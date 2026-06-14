from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, func, and_, text

from app.core.dependencies import get_db, require_analyst
from app.models.user import User
from app.models.client import Client
from app.models.client_query import ClientQuery
from app.models.operational_event import OperationalEvent
from app.models.anomaly import Anomaly
from app.models.audit_log import AuditLog
from app.models.scheduler_status import SchedulerStatus
from app.models.event_issue import EventIssue
from app.schemas.events import (
    PeriodFilter, RaiseIssueRequest,PaginatedAnomalies,
    EventIssueRow, ResolveIssueRequest, DeleteIssueRequest,PaginatedEvents
)
from app.schemas.analyst import (
    AnalystEventRow, AnomalyRow, AcknowledgeRequest,
    DashboardStats, SchedulerStatusRow,
)
from app.utils.excel_formatter import ExcelFormatter

router = APIRouter(prefix="/analyst", tags=["Analyst Portal"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _period_start(period: PeriodFilter, start: Optional[datetime]) -> datetime:
    now = datetime.now(timezone.utc)
    if period == PeriodFilter.last_24h:
        return now - timedelta(hours=24)
    if period == PeriodFilter.last_7d:
        return now - timedelta(days=7)
    if period == PeriodFilter.last_30d:
        return now - timedelta(days=30)
    if start is None:
        raise HTTPException(
            status_code=400, detail="start required for custom period"
        )
    return start


async def _audit(db, request, event_type, user, details):
    try:
        entry = AuditLog(
            user_id=user.id, role=user.role,
            event_type=event_type,
            ip_address=request.client.host if request.client else "127.0.0.1",
            user_agent=request.headers.get("user-agent"),
            details=details,
        )
        db.add(entry)
        await db.commit()
    except Exception as e:
        print(f"AUDIT FAILURE: {e}")
        await db.rollback()


# ---------------------------------------------------------------------------
# GET /analyst/dashboard-stats
# ---------------------------------------------------------------------------

@router.get("/dashboard-stats", response_model=DashboardStats)
async def dashboard_stats(
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    today_start = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    )

    total_clients = (await db.execute(
        select(func.count(Client.id)).where(Client.active == True)
    )).scalar()

    total_events_today = (await db.execute(
        select(func.count(OperationalEvent.id)).where(
            OperationalEvent.timestamp >= today_start
        )
    )).scalar()

    unacknowledged_anomalies = (await db.execute(
        select(func.count(Anomaly.id)).where(
            Anomaly.acknowledged_by == None
        )
    )).scalar()

    open_issues = (await db.execute(
        select(func.count(EventIssue.id)).where(
            and_(EventIssue.resolved_at == None, EventIssue.deleted == False)
        )
    )).scalar()

    # Latest row per process_name
    scheduler_rows = (await db.execute(
        text("""
            SELECT DISTINCT ON (process_name) *
            FROM scheduler_status
            ORDER BY process_name, last_run_at DESC
        """)
    )).mappings().all()

    return DashboardStats(
        total_clients=total_clients,
        total_events_today=total_events_today,
        unacknowledged_anomalies=unacknowledged_anomalies,
        open_issues=open_issues,
        scheduler_status=[SchedulerStatusRow(**r) for r in scheduler_rows],
    )


# ---------------------------------------------------------------------------
# GET /analyst/events
# ---------------------------------------------------------------------------

@router.get("/events", response_model=PaginatedEvents)
async def get_events(
    request: Request,
    client_id:  Optional[int] = Query(None),
    query_name: Optional[str] = Query(None),
    period: PeriodFilter = Query(PeriodFilter.last_7d),
    start: Optional[datetime] = Query(None),
    end: Optional[datetime] = Query(None),
    confirmed: Optional[bool] = Query(None),
    has_issue: Optional[bool] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    user:User = Depends(require_analyst),
    db:AsyncSession = Depends(get_db),
    ):
    since = _period_start(period, start)
    until = end if period == PeriodFilter.custom else None

    oe = OperationalEvent.__table__
    cl = Client.__table__
    confirmer = User.__table__.alias("confirmer")
    issuer = User.__table__.alias("issuer")

    stmt =( select(
        oe,
        cl.c.name.label("client_name"),
        confirmer.c.username.label("confirmed_by_username"),
        issuer.c.username.label("issue_raised_by_username")
    )
    .select_from(oe)
    .join(cl, oe.c.client_id==cl.c.id)
    .outerjoin(confirmer,oe.c.confirmed_by==confirmer.c.id)
    .outerjoin(issuer, oe.c.issue_raised_by==issuer.c.id)
    .where(oe.c.timestamp >= since)
    .order_by(oe.c.timestamp.desc())
    )
    if until:
        stmt= stmt.where(oe.c.timestamp <= until)
    if client_id is not None:
        stmt = stmt.where(oe.c.client_id == client_id)
    if query_name is not None:
        stmt = stmt.where(oe.c.query_name == query_name)
    if confirmed is True:
        stmt = stmt.where(oe.c.confirmed_by != None)
    elif confirmed is False:
        stmt = stmt.where(oe.c.confirmed_by == None)
    if has_issue is True:
        stmt = stmt.where(oe.c.issue_text != None)
    elif has_issue is False:
        stmt = stmt.where(oe.c.issue_text == None)
    total = (await db.execute(
        select(func.count()).select_from(stmt.subquery())
    )).scalar()
    stmt = stmt.offset((page-1) * page_size).limit(page_size)
    rows = (await db.execute(stmt)).mappings().all()

    return PaginatedEvents(
        total = total,
        page=page,
        page_size = page_size,
        items=[AnalystEventRow(**r) for  r in rows]
    )


# ---------------------------------------------------------------------------
# GET /analyst/events/{event_id}/issues — full thread for one event
# (must be declared BEFORE /events/download to avoid route collision)
# ---------------------------------------------------------------------------

@router.get("/events/{event_id}/issues", response_model=list[EventIssueRow])
async def get_event_issues_analyst(
    event_id: int,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    ei = EventIssue.__table__
    raiser = User.__table__.alias("raiser")
    resolver = User.__table__.alias("resolver")

    stmt = (
        select(
            ei,
            raiser.c.username.label("raised_by_username"),
            resolver.c.username.label("resolved_by_username"),
        )
        .select_from(ei)
        .outerjoin(raiser, ei.c.raised_by == raiser.c.id)
        .outerjoin(resolver, ei.c.resolved_by == resolver.c.id)
        .where(and_(ei.c.event_id == event_id, ei.c.deleted == False))
        .order_by(ei.c.created_at.asc())
    )
    rows = (await db.execute(stmt)).mappings().all()
    return [EventIssueRow(**r) for r in rows]


# ---------------------------------------------------------------------------
# GET /analyst/events/download
# ---------------------------------------------------------------------------

@router.get("/events/download")
async def download_events(
    request: Request,
    client_id: Optional[int] = Query(None),
    query_name: Optional[str] = Query(None),
    period: PeriodFilter = Query(PeriodFilter.last_7d),
    start: Optional[datetime] = Query(None),
    end: Optional[datetime] = Query(None),
    confirmed: Optional[bool] = Query(None),
    has_issue: Optional[bool] = Query(None),
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    since = _period_start(period, start)
    until = end if period == PeriodFilter.custom else None

    oe = OperationalEvent.__table__
    cl = Client.__table__
    confirmer = User.__table__.alias("confirmer")
    issuer = User.__table__.alias("issuer")

    stmt = (
        select(
            oe,
            cl.c.name.label("client_name"),
            confirmer.c.username.label("confirmed_by_username"),
            issuer.c.username.label("issue_raised_by_username"),
        )
        .select_from(oe)
        .join(cl, oe.c.client_id == cl.c.id)
        .outerjoin(confirmer, oe.c.confirmed_by == confirmer.c.id)
        .outerjoin(issuer, oe.c.issue_raised_by == issuer.c.id)
        .where(oe.c.timestamp >= since)
        .order_by(oe.c.timestamp.desc())
    )

    if until:
        stmt = stmt.where(oe.c.timestamp <= until)
    if client_id is not None:
        stmt = stmt.where(oe.c.client_id == client_id)
    if query_name is not None:
        stmt = stmt.where(oe.c.query_name == query_name)
    if confirmed is True:
        stmt = stmt.where(oe.c.confirmed_by != None)
    elif confirmed is False:
        stmt = stmt.where(oe.c.confirmed_by == None)
    if has_issue is True:
        stmt = stmt.where(oe.c.issue_text != None)
    elif has_issue is False:
        stmt = stmt.where(oe.c.issue_text == None)

    rows = (await db.execute(stmt)).mappings().all()
    events = [dict(r) for r in rows]

    buf = ExcelFormatter.format_events(events, include_client_name=True)
    await _audit(db, request, "FILE_DOWNLOADED", user, {
        "type": "analyst_events",
        "filters": {
            "client_id": client_id, "query_name": query_name,
            "period": period.value,
        },
        "row_count": len(events),
    })

    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=analyst_events.xlsx"},
    )


# ---------------------------------------------------------------------------
# GET /analyst/anomalies
# ---------------------------------------------------------------------------

@router.get("/anomalies", response_model=PaginatedAnomalies)
async def get_anomalies(
    request: Request,
    client_id: Optional[int] = Query(None),
    category: Optional[str] = Query(None),
    layer: Optional[int] = Query(None),
    period: PeriodFilter = Query(PeriodFilter.last_7d),
    start: Optional[datetime] = Query(None),
    acknowledged: Optional[bool]= Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    user:User = Depends(require_analyst),
    db:AsyncSession = Depends(get_db),
):
    since = _period_start(period, start)
    
    an= Anomaly.__table__
    cl=Client.__table__
    oe=OperationalEvent.__table__
    acker=User.__table__.alias("acker")

    stmt = (select(
        an, 
        cl.c.name.label("client_name"),
        oe.c.fields.label("event_fields"),
        oe.c.query_name.label("event_query_name"),
        acker.c.username.label("acknowledged_by_username")
    )
    .select_from(an)
    .join(cl,an.c.client_id== cl.c.id)
    .outerjoin(oe, an.c.operational_event_id==oe.c.id)
    .outerjoin(acker, an.c.acknowledged_by == acker.c.id)
    .where(an.c.detected_at >= since)
    .order_by(an.c.detected_at.desc())
    )
    if client_id is not None:
        stmt = stmt.where(an.c.client_id == client_id)
    if category is not None:
        stmt = stmt.where(an.c.category == category)
    if layer is not None:
        stmt = stmt.where(an.c.layer == layer)
    if acknowledged is False:
        stmt = stmt.where(an.c.acknowledged_by == None)
    elif acknowledged is True:
        stmt = stmt.where(an.c.acknowledged_by != None)
    
    total = (await db.execute(
        select(func.count()).select_from(stmt.subquery())
    )).scalar()
    stmt = stmt.offset((page-1) * page_size).limit(page_size)
    rows = (await db.execute(stmt)).mappings().all()
    return PaginatedAnomalies(
        total=total,
        page=page,
        page_size=page_size,
        items=[AnomalyRow(**r) for r in rows]
    )


# ---------------------------------------------------------------------------
# POST /analyst/anomalies/acknowledge
# ---------------------------------------------------------------------------

@router.post("/anomalies/acknowledge")
async def acknowledge_anomaly(
    request: Request,
    payload: AcknowledgeRequest,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Anomaly).where(Anomaly.id == payload.anomaly_id)
    )
    anomaly = result.scalar_one_or_none()

    if not anomaly:
        raise HTTPException(status_code=404, detail="Anomaly not found")

    if anomaly.acknowledged_by is not None:
        return {"detail": "Anomaly already acknowledged"}

    new_details = dict(anomaly.details or {})
    if payload.notes:
        new_details["analyst_notes"] = payload.notes

    await db.execute(
        update(Anomaly)
        .where(Anomaly.id == anomaly.id)
        .values(
            acknowledged_by=user.id,
            acknowledged_at=datetime.now(timezone.utc),
            details=new_details,
        )
    )
    await db.commit()

    await _audit(db, request, "ANOMALY_ACKNOWLEDGED", user, {
        "anomaly_id": anomaly.id,
        "category": anomaly.category,
        "layer": anomaly.layer,
        "client_id": anomaly.client_id,
        "notes": payload.notes,
    })

    return {"detail": "Anomaly acknowledged"}


# ---------------------------------------------------------------------------
# GET /analyst/anomalies/download
# ---------------------------------------------------------------------------

@router.get("/anomalies/download")
async def download_anomalies(
    request: Request,
    client_id: Optional[int] = Query(None),
    category: Optional[str] = Query(None),
    layer: Optional[int] = Query(None),
    period: PeriodFilter = Query(PeriodFilter.last_7d),
    start: Optional[datetime] = Query(None),
    acknowledged: Optional[bool] = Query(None),
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    since = _period_start(period, start)

    an = Anomaly.__table__
    cl = Client.__table__
    oe = OperationalEvent.__table__
    acker = User.__table__.alias("acker")

    stmt = (
        select(
            an,
            cl.c.name.label("client_name"),
            oe.c.fields.label("event_fields"),
            oe.c.query_name.label("event_query_name"),
            acker.c.username.label("acknowledged_by_username"),
        )
        .select_from(an)
        .join(cl, an.c.client_id == cl.c.id)
        .outerjoin(oe, an.c.operational_event_id == oe.c.id)
        .outerjoin(acker, an.c.acknowledged_by == acker.c.id)
        .where(an.c.detected_at >= since)
        .order_by(an.c.detected_at.desc())
    )

    if client_id is not None:
        stmt = stmt.where(an.c.client_id == client_id)
    if category is not None:
        stmt = stmt.where(an.c.category == category)
    if layer is not None:
        stmt = stmt.where(an.c.layer == layer)
    if acknowledged is False:
        stmt = stmt.where(an.c.acknowledged_by == None)
    elif acknowledged is True:
        stmt = stmt.where(an.c.acknowledged_by != None)

    rows = (await db.execute(stmt)).mappings().all()

    # Build flat dicts for Excel
    events = []
    for r in rows:
        d = dict(r)
        d["fields"] = d.pop("event_fields") or {}
        d["time_summary"] = (
            f"{d['category']} | Layer {d['layer']} | {d['anomaly_type']}"
        )
        events.append(d)

    buf = ExcelFormatter.format_events(events, include_client_name=True)
    await _audit(db, request, "FILE_DOWNLOADED", user, {
        "type": "analyst_anomalies", "row_count": len(events),
    })

    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=anomalies.xlsx"},
    )

# ---------------------------------------------------------------------------
# GET /analyst/issues  — all issues across all clients, thread model
# ---------------------------------------------------------------------------

@router.get("/issues", response_model=list[EventIssueRow])
async def get_issues(
    request: Request,
    show_resolved: bool = Query(False),
    client_id: Optional[int] = Query(None),
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    ei = EventIssue.__table__
    raiser = User.__table__.alias("raiser")
    resolver = User.__table__.alias("resolver")

    stmt = (
        select(
            ei,
            raiser.c.username.label("raised_by_username"),
            resolver.c.username.label("resolved_by_username"),
        )
        .select_from(ei)
        .outerjoin(raiser, ei.c.raised_by == raiser.c.id)
        .outerjoin(resolver, ei.c.resolved_by == resolver.c.id)
        .where(ei.c.deleted == False)
        .order_by(ei.c.created_at.desc())
        .limit(500)
    )

    if not show_resolved:
        stmt = stmt.where(ei.c.resolved_at == None)
    if client_id is not None:
        stmt = stmt.where(ei.c.client_id == client_id)

    rows = (await db.execute(stmt)).mappings().all()
    return [EventIssueRow(**r) for r in rows]


# ---------------------------------------------------------------------------
# POST /analyst/issues/resolve
# analyst_comment is optional — analyst can resolve with or without a reply.
# ---------------------------------------------------------------------------

@router.post("/issues/resolve")
async def resolve_issue(
    request: Request,
    payload: ResolveIssueRequest,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(EventIssue).where(and_(
            EventIssue.id == payload.issue_id,
            EventIssue.deleted == False,
        ))
    )
    issue = result.scalar_one_or_none()
    if not issue:
        raise HTTPException(status_code=404, detail="Issue not found")
    if issue.resolved_at is not None:
        raise HTTPException(status_code=400, detail="Issue already resolved")

    await db.execute(
        update(EventIssue)
        .where(EventIssue.id == payload.issue_id)
        .values(
            resolved_by=user.id,
            resolved_at=datetime.now(timezone.utc),
            # None is a valid value here — means resolved without comment
            analyst_comment=payload.analyst_comment,
        )
    )
    await db.commit()
    await _audit(db, request, "EVENT_ISSUE_RESOLVED", user, {
        "action": "resolved",
        "issue_id": payload.issue_id,
        "has_comment": payload.analyst_comment is not None,
        "comment_preview": (payload.analyst_comment or "")[:100],
    })
    return {"detail": "Issue resolved"}

# ---------------------------------------------------------------------------
# PATCH /analyst/issues/{issue_id}/comment  — update analyst comment on a
# resolved issue (correction or addendum after the fact)
# ---------------------------------------------------------------------------

@router.patch("/issues/{issue_id}/comment")
async def update_issue_comment(
    issue_id: int,
    request: Request,
    payload: ResolveIssueRequest,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(EventIssue).where(and_(
            EventIssue.id == issue_id,
            EventIssue.deleted == False,
        ))
    )
    issue = result.scalar_one_or_none()
    if not issue:
        raise HTTPException(status_code=404, detail="Issue not found")
    if issue.resolved_at is None:
        raise HTTPException(
            status_code=400,
            detail="Issue is not yet resolved. Use /issues/resolve first.",
        )

    old_comment = issue.analyst_comment or ""
    await db.execute(
        update(EventIssue)
        .where(EventIssue.id == issue_id)
        .values(
            analyst_comment=payload.analyst_comment,
            resolved_by=user.id,
            resolved_at=issue.resolved_at,  # preserve original resolution time
        )
    )
    await db.commit()
    await _audit(db, request, "EVENT_ISSUE_RESOLVED", user, {
        "action": "comment_updated",
        "issue_id": issue_id,
        "old_comment_preview": old_comment[:100],
        "new_comment_preview": (payload.analyst_comment or "")[:100],
    })
    return {"detail": "Comment updated"}

# ---------------------------------------------------------------------------
# POST /analyst/issues/delete  (permanent soft-delete)
# ---------------------------------------------------------------------------

@router.post("/issues/delete")
async def delete_issue(
    request: Request,
    payload: DeleteIssueRequest,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(EventIssue).where(EventIssue.id == payload.issue_id)
    )
    issue = result.scalar_one_or_none()
    if not issue:
        raise HTTPException(status_code=404, detail="Issue not found")

    await db.execute(
        update(EventIssue)
        .where(EventIssue.id == payload.issue_id)
        .values(deleted=True)
    )
    await db.commit()
    await _audit(db, request, "EVENT_ISSUE_DELETED", user, {
        "action": "deleted",
        "issue_id": payload.issue_id,
    })
    return {"detail": "Issue deleted"}

# GET /analyst/threat-intel
# ---------------------------------------------------------------------------
# POST /analyst/events/raise-issue
# ---------------------------------------------------------------------------

@router.post("/events/raise-issue")
async def analyst_raise_issue_deprecated():
    raise HTTPException(
        status_code=410,
        detail=(
            "This endpoint is deprecated. Analysts cannot raise issues. "
            "Issues are raised by client users via POST /client/events/raise-issue. "
            "Analysts resolve issues via POST /analyst/issues/resolve."
        ),
    )


# ---------------------------------------------------------------------------
# GET /analyst/clients  — list all active clients (for filter dropdowns)
# ---------------------------------------------------------------------------

@router.get("/clients")
async def list_clients_for_analyst(
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Client.id, Client.name)
        .where(Client.active == True)
        .order_by(Client.name)
    )
    return [{"id": r.id, "name": r.name} for r in result.all()]


# ---------------------------------------------------------------------------
# GET /analyst/clients/{client_id}/queries
# — list distinct query names for a client (populates query_name dropdown)
# ---------------------------------------------------------------------------

@router.get("/clients/{client_id}/queries")
async def list_client_queries_for_analyst(
    client_id: int,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ClientQuery.query_name, ClientQuery.display_order)
        .where(
            ClientQuery.client_id == client_id,
            ClientQuery.enabled == True,
            ClientQuery.is_ml_category == False,
        )
        .order_by(ClientQuery.display_order)
    )
    return [{"query_name": r.query_name} for r in result.all()]


@router.get("/threat-intel")
async def get_threat_intel(
    request: Request,
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    from app.models.threat_intel import ThreatIntel
    stmt = (
        select(ThreatIntel)
        .order_by(ThreatIntel.published_at.desc())
        .limit(200)
    )
    rows = (await db.execute(stmt)).scalars().all()
    return rows


# GET /analyst/audit-log
@router.get("/audit-log")
async def get_audit_log(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    # Analysts cannot see superadmin actions
    stmt = (
        select(AuditLog)
        .where(AuditLog.role != "superadmin")
        .order_by(AuditLog.performed_at.desc())
        .limit(limit)
        .offset(offset)
    )
    rows = (await db.execute(stmt)).scalars().all()
    return rows
