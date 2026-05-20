from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, func, and_
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.core.dependencies import get_db, require_client
from app.models.user import User
from app.models.client_query import ClientQuery
from app.models.operational_event import OperationalEvent
from app.models.event_view import EventView
from app.models.audit_log import AuditLog
from app.models.event_issue import EventIssue  
from app.schemas.events import (
    QueryTabInfo, EventRow, ConfirmEventRequest,
    RaiseIssueRequest, PeriodFilter,
    RaiseIssueV2Request, EventIssueRow,                # ADD THESE
)
from app.utils.excel_formatter import ExcelFormatter

router = APIRouter(prefix="/client", tags=["Client Portal"])


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
        raise HTTPException(status_code=400, detail="start required for custom period")
    return start


async def _fetch_events(
    db: AsyncSession,
    client_id: int,
    query_name: str,
    since: datetime,
    until: Optional[datetime] = None,
    user_id: Optional[int] = None,
) -> list[dict]:
    confirmer = User.__table__.alias("confirmer")
    issuer = User.__table__.alias("issuer")
    oe = OperationalEvent.__table__
    ei = EventIssue.__table__

    # Subquery: open issues (no resolved_at, not deleted) per event
    open_sq = (
        select(func.count())
        .select_from(ei)
        .where(and_(
            ei.c.event_id == oe.c.id,
            ei.c.deleted == False,
            ei.c.resolved_at == None,
        ))
        .correlate(oe)
        .scalar_subquery()
    )

    # Subquery: resolved issues per event
    resolved_sq = (
        select(func.count())
        .select_from(ei)
        .where(and_(
            ei.c.event_id == oe.c.id,
            ei.c.deleted == False,
            ei.c.resolved_at != None,
        ))
        .correlate(oe)
        .scalar_subquery()
    )

    # Subquery: analyst replies unseen by this user
    unread_sq = (
        select(func.count())
        .select_from(ei)
        .where(and_(
            ei.c.event_id == oe.c.id,
            ei.c.deleted == False,
            ei.c.analyst_comment != None,
            ei.c.reply_seen_at == None,
        ))
        .correlate(oe)
        .scalar_subquery()
    )

    stmt = (
        select(
            oe,
            confirmer.c.username.label("confirmed_by_username"),
            issuer.c.username.label("issue_raised_by_username"),
            open_sq.label("open_issue_count"),
            resolved_sq.label("resolved_issue_count"),
            unread_sq.label("unread_reply_count"),
        )
        .select_from(oe)
        .outerjoin(confirmer, oe.c.confirmed_by == confirmer.c.id)
        .outerjoin(issuer, oe.c.issue_raised_by == issuer.c.id)
        .where(and_(
            oe.c.client_id == client_id,
            oe.c.query_name == query_name,
            oe.c.timestamp >= since,
        ))
        .order_by(oe.c.timestamp.desc())
    )
    if until is not None:
        stmt = stmt.where(oe.c.timestamp <= until)

    rows = (await db.execute(stmt)).mappings().all()
    return [dict(r) for r in rows]


async def _mark_viewed(db: AsyncSession, event_ids: list[int], user_id: int):
    if not event_ids:
        return
    stmt = pg_insert(EventView).values(
        [{"event_id": eid, "user_id": user_id} for eid in event_ids]
    ).on_conflict_do_nothing(index_elements=["event_id", "user_id"])
    await db.execute(stmt)
    await db.commit()


async def _audit(db, request, event_type, user, details):
    try:
        entry = AuditLog(
            user_id=user.id, role=user.role, client_id=user.client_id,
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
# GET /client/queries
# ---------------------------------------------------------------------------

@router.get("/queries", response_model=list[QueryTabInfo])
async def get_queries(
    request: Request,
    user: User = Depends(require_client),
    db: AsyncSession = Depends(get_db),
):
    cq = ClientQuery.__table__
    oe = OperationalEvent.__table__
    ev = EventView.__table__

    unviewed_subq = (
        select(func.count(oe.c.id))
        .where(and_(
            oe.c.client_id == user.client_id,
            oe.c.query_name == cq.c.query_name,
            ~oe.c.id.in_(
                select(ev.c.event_id).where(ev.c.user_id == user.id)
            ),
        ))
        .correlate(cq)
        .scalar_subquery()
    )

    stmt = (
        select(
            cq.c.query_name,
            cq.c.display_order,
            unviewed_subq.label("unviewed_count"),
        )
        .where(and_(
            cq.c.client_id == user.client_id,
            cq.c.enabled == True,
            cq.c.is_ml_category == False,
        ))
        .order_by(cq.c.display_order)
    )

    rows = (await db.execute(stmt)).mappings().all()
    return [QueryTabInfo(**r) for r in rows]


# ---------------------------------------------------------------------------
# GET /client/events
# ---------------------------------------------------------------------------

@router.get("/events", response_model=list[EventRow])
async def get_events(
    request: Request,
    query_name: str = Query(...),
    period: PeriodFilter = Query(PeriodFilter.last_7d),
    start: Optional[datetime] = Query(None),
    end: Optional[datetime] = Query(None),
    user: User = Depends(require_client),
    db: AsyncSession = Depends(get_db),
):
    since = _period_start(period, start)
    until = end if period == PeriodFilter.custom else None
    events = await _fetch_events(db, user.client_id, query_name, since, until, user_id=user.id)
    await _mark_viewed(db, [e["id"] for e in events], user.id)
    return [EventRow(**e) for e in events]


# ---------------------------------------------------------------------------
# POST /client/events/confirm
# ---------------------------------------------------------------------------

@router.post("/events/confirm")
async def confirm_event(
    request: Request,
    payload: ConfirmEventRequest,
    user: User = Depends(require_client),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(OperationalEvent).where(and_(
            OperationalEvent.id == payload.event_id,
            OperationalEvent.client_id == user.client_id,
        ))
    )
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    if event.confirmed_by is not None:
        return {"detail": "Event already confirmed"}

    await db.execute(
        update(OperationalEvent)
        .where(OperationalEvent.id == event.id)
        .values(confirmed_by=user.id, confirmed_at=datetime.now(timezone.utc))
    )
    await db.commit()
    await _audit(db, request, "EVENT_CONFIRMED", user, {
        "event_id": event.id,
        "query_name": event.query_name,
        "event_fingerprint": event.event_fingerprint,
    })
    return {"detail": "Event confirmed"}


# ---------------------------------------------------------------------------
# GET /client/anomalies
# ---------------------------------------------------------------------------

@router.get("/anomalies")
async def get_anomalies(
    request: Request,
    user: User = Depends(require_client),
    db: AsyncSession = Depends(get_db),
):
    # Check visibility flag
    from app.models.client import Client
    result = await db.execute(
        select(Client).where(Client.id == user.client_id)
    )
    client = result.scalar_one_or_none()
    
    if not client or not client.anomaly_visibility_enabled:
        raise HTTPException(
            status_code=403,
            detail="Anomaly monitoring is not enabled for your organization."
        )

    # Fetch anomalies for this client
    from app.models.anomaly import Anomaly
    stmt = (
        select(Anomaly)
        .where(Anomaly.client_id == user.client_id)
        .order_by(Anomaly.detected_at.desc())
        .limit(500)
    )
    rows = (await db.execute(stmt)).scalars().all()
    return rows

# ---------------------------------------------------------------------------
# POST /client/events/raise-issue  (v2 — appends to event_issues thread)
# ---------------------------------------------------------------------------

@router.post("/events/raise-issue")
async def raise_issue(
    request: Request,
    payload: RaiseIssueV2Request,
    user: User = Depends(require_client),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(OperationalEvent).where(and_(
            OperationalEvent.id == payload.event_id,
            OperationalEvent.client_id == user.client_id,
        ))
    )
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    new_issue = EventIssue(
        event_id=event.id,
        client_id=user.client_id,
        raised_by=user.id,
        issue_text=payload.issue_text,
    )
    db.add(new_issue)
    await db.commit()
    await db.refresh(new_issue)

    await _audit(db, request, "EVENT_ISSUE_RAISED", user, {
        "event_id": event.id,
        "query_name": event.query_name,
        "issue_preview": payload.issue_text[:100],
        "issue_id": new_issue.id,
    })
    return {"detail": "Issue raised", "issue_id": new_issue.id}

# GET /client/issues/unread-replies  — badge count for the client nav
# ---------------------------------------------------------------------------

@router.get("/issues/unread-replies")
async def unread_reply_count(
    user: User = Depends(require_client),
    db: AsyncSession = Depends(get_db),
):
    ei = EventIssue.__table__
    result = await db.execute(
        select(func.count())
        .select_from(ei)
        .where(and_(
            ei.c.client_id == user.client_id,
            ei.c.deleted == False,
            ei.c.analyst_comment != None,
            ei.c.reply_seen_at == None,
        ))
    )
    count = result.scalar() or 0
    return {"unread_replies": count}


# ---------------------------------------------------------------------------
# GET /client/issues/unread-by-event  — per-event unread counts for row badges
# ---------------------------------------------------------------------------

@router.get("/issues/unread-by-event")
async def unread_replies_by_event(
    user: User = Depends(require_client),
    db: AsyncSession = Depends(get_db),
):
    """Returns {event_id: unread_reply_count} for all events of this client
    that have unseen analyst replies. Used to refresh row badges without
    reloading the full events list."""
    ei = EventIssue.__table__
    stmt = (
        select(ei.c.event_id, func.count().label("cnt"))
        .where(and_(
            ei.c.client_id == user.client_id,
            ei.c.deleted == False,
            ei.c.analyst_comment != None,
            ei.c.reply_seen_at == None,
        ))
        .group_by(ei.c.event_id)
    )
    rows = (await db.execute(stmt)).all()
    return {row.event_id: row.cnt for row in rows}


# ---------------------------------------------------------------------------
# POST /client/issues/mark-seen  — called when client opens a thread

@router.post("/issues/mark-seen")
async def mark_replies_seen(
    payload: ConfirmEventRequest,   # reuses {event_id: int}
    user: User = Depends(require_client),
    db: AsyncSession = Depends(get_db),
):
    await db.execute(
        update(EventIssue)
        .where(and_(
            EventIssue.event_id == payload.event_id,
            EventIssue.client_id == user.client_id,
            EventIssue.deleted == False,
            EventIssue.analyst_comment != None,
            EventIssue.reply_seen_at == None,
        ))
        .values(reply_seen_at=datetime.now(timezone.utc))
    )
    await db.commit()
    return {"detail": "Marked seen"}



# ---------------------------------------------------------------------------
# GET /client/events/{event_id}/issues  — thread for one event (same client)
# ---------------------------------------------------------------------------

@router.get("/events/{event_id}/issues", response_model=list[EventIssueRow])
async def get_event_issues(
    event_id: int,
    user: User = Depends(require_client),
    db: AsyncSession = Depends(get_db),
):
    event = (await db.execute(
        select(OperationalEvent).where(and_(
            OperationalEvent.id == event_id,
            OperationalEvent.client_id == user.client_id,
        ))
    )).scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

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
        .where(and_(
            ei.c.event_id == event_id,
            ei.c.deleted == False,
        ))
        .order_by(ei.c.created_at.asc())
    )
    rows = (await db.execute(stmt)).mappings().all()
    return [EventIssueRow(**r) for r in rows]


# ---------------------------------------------------------------------------
# GET /client/events/download
# ---------------------------------------------------------------------------

@router.get("/events/download")
async def download_events(
    request: Request,
    query_name: str = Query(...),
    period: PeriodFilter = Query(PeriodFilter.last_7d),
    start: Optional[datetime] = Query(None),
    end: Optional[datetime] = Query(None),
    user: User = Depends(require_client),
    db: AsyncSession = Depends(get_db),
):
    since = _period_start(period, start)
    until = end if period == PeriodFilter.custom else None
    events = await _fetch_events(db, user.client_id, query_name, since, until)
    buf = ExcelFormatter.format_events(events, include_client_name=False)
    await _audit(db, request, "FILE_DOWNLOADED", user, {
        "query_name": query_name, "period": period.value, "row_count": len(events),
    })
    filename = f"events_{query_name.replace(' ', '_')}_{period.value}.xlsx"
    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )