# from datetime import datetime, timezone, timedelta
# from typing import Optional
# from fastapi import APIRouter, Depends, HTTPException, Query, Request
# from fastapi.responses import StreamingResponse
# from sqlalchemy.ext.asyncio import AsyncSession
# from sqlalchemy import select, func, update, and_
# from sqlalchemy.dialects.postgresql import inser as pg_insert
# from app.core.dependencies import get_db, require_client
# from app.models.user import User
# from app.models.client_query import ClientQuery
# from app.models.operational_event import OperationalEvent
# from app.models.event_view import EventView
# from app.models.audit_log import AuditLog
# from app.models.event_issue import EventIssue
# from app.schemas.events import (
#     QueryTabInfo,EventRow, ConfirmEventRequest,
#     RaiseIssueRequest, PeriodFilter, RaiseIssueV2Request, EventIssueRow,
# )

# router = APIRouter(prefix="/client", tags=["Client Portal"])

# def _period_start(period: PeriodFilter, start: Optional[datetime]) -> datetime:
#     now = datetime.now(timezone.utc)
#     if period == PeriodFilter.last_24h:
#         return now - timedelta(hours=24)
#     if period == PeriodFilter.last_30d:
#         return now - timedelta(days=30)
#     if period == PeriodFilter.last_7d:
#         return now - timedelta(days=7)
#     if start is None:
#         raise HTTPException(status_code=400, detail="Start required for custom period")
#     return start

# async def _fetch_events(
#         db: AsyncSession,
#         client_id : int,
#         query_name : str,
#         since: datetime,
#         until: Optional[datetime] = None,
#         user_id : Optional[int] = None,
# ) -> list[dict]:
#     confirmer = User.__table__.alias("confirmer")
#     issuer = User.__table__.alias("issuer")
#     oe = OperationalEvent.__table__
#     ei = EventIssue.__table__

#     open_sq = (
#         select(func.count())
#         .select_from(ei)
#         .where(and_(
#             ei.c.event_id == oe.c.id,
#             ei.c.deleted == False,
#             ei.c.resolved_at == None,
#         ))
#         .correlate(oe)
#         .scalar_subquery())
#     resolved_sq = (
#         select(func.count())
#         .select_from(ei)
#         .where(and_(
#             ei.c.event_id == oe.c.id,
#             ei.c.deleted == False,
#             ei.c.resolved_at != None,
#         ))
#         .correlate(oe)
#         .scalar_subquery()
#     )

#     # Subquery: analyst replies unseen by this user
#     unread_sq = (
#         select(func.count())
#         .select_from(ei)
#         .where(and_(
#             ei.c.event_id == oe.c.id,
#             ei.c.deleted == False,
#             ei.c.analyst_comment != None,
#             ei.c.reply_seen_at == None,
#         ))
#         .correlate(oe)
#         .scalar_subquery()
#     )
#     stmt = (
#         select(
#             oe,
#             confirmer.c.username.label("confimer_by_username"),
#             issuer.c.username.label("issue_raised_by_username"),
#             open_sq.label("open_issue_count"),
#             resolved_sq.label("resolved_issue_count"),
#             unread_sq.label("unread_reply_count"),
#         )
#         .select_from(oe)
#         .outerjoin(confirmer, oe.c.confirmed_by == confirmer.c.id)
#         .outerjoin(issuer, oe.c.raised_by == issuer.c.id)
#         .where(and_(
#             oe.c.client_id == client_id,
#             oe.c.query_name == query_name,
#             oe.c.timestamp >=since,
#         ))
#         .order_by(oe.c.timestamp.desc())

#     )
#     if until is not None:
#         stmt = stmt.where(oe.c.timestamp <= until)
#     rows = (await db.execute(stmt)).mappings().all()
#     return [dict(r) for r in rows]

# async def _marked_viewed(db: AsyncSession, event_ids: list[int], user_id:int):
#     if not event_ids:
#         return
#     stmt = pg_insert(EventView).values(
#         [{"event_id":eid, "user_id": user_id} for eid in event_ids]
#         ).on_conflict_do_nothing(index_elements=["event_id", "user_id"])
#     await db.execute(stmt)
#     await db.commit()

# async def _audit(db, request, event_type, user, details):
#     try:
#         entry = AuditLog(
#             user_id = user.id, role = user.role, client_id = user.client_id,
#             event_type = event_type,
#             ip_address = request.client.host if request.client else "127.0.0.1",
#             user_agent = request.headers.get("user-agent"),
#             details=details,
#         )
#         db.add(entry)
#         await db.commit()
#     except Exception as e:
#         print(f"AUDIT FAILURE: {e}")
#         await db.rollback()

# @router.get("/queries", response_model=list[QueryTabInfo])
# async def get_queries(
#     request : Request,
#     user : User = Depends(require_client),
#     db : AsyncSession = Depends(get_db),
# ):
#     cq = ClientQuery.__table__
#     oe = OperationalEvent.__table__
#     ev = EventView.__table__

#     unviewed_subquery = (
#         select(func.count(oe.c.id))
#         .where(and_(
#             oe.c.clientid ==user.client_id,
#             oe.c.query_name == cq.c.query_name,
#             ~oe.c.id.in_(
#                 select(ev.c.event_id).where(ev.c.user_id == user.id)
#             ),
            
#         ))
#         .correlate(cq)
#         .scalar_subquery()
#     )
#     stmt = (
#         select(
#             cq.c.query_name,
#             cq.c.display_order,
#             unviewed_subquery.label("unviewed_count"),
#         )
#         .where(and_(
#             cq.c.client_id == user.client_id,
#             cq.c.enabled == True,
#             cq.c.ml_category == False,
#         ))
#         .order_by(cq.c.display_order)
#     )
#     rows = (await db.execute(stmt)).mappings().all()
#     return [QueryTabInfo(**r) for r in rows]

# @router.get("/events", response_model=list[EventRow])
# async def get_events(
#     request: Request,
#     query_name :str = Query(...),
#     period: PeriodFilter = Query(PeriodFilter.last_7d),
#     start: Optional[datetime] = Query(None),
#     end: Optional[datetime] = Query(None),
#     user: User = Depends(require_client), 
#     db : AsyncSession = Depends(get_db),
# ):
#     since = _period_start(period, start)
#     until = end if period == PeriodFilter.custom else None
#     events = await _fetch_events(db, user.client_id, query_name, since, until, user_id = user.id)
#     await _marked_viewed(db, [e["id"] for e in events], user.id)
#     return [EventRow(**e) for e in events]
# @router.post("/events/clients")
# async def confirm_event(
#     request: Request,
#     payload: ConfirmEventRequest,
#     user:User = Depends(require_client),
#     db: AsyncSession = Depends(get_db),
# ):
#     result = await db.execute(
#         select(OperationalEvent).where(and_(
#             OperationalEvent.id == payload.event_id,
#             OperationalEvent.client_id == user.client_id,
#         ))
#     )
#     event = result.scalar_one_or_none()
#     if not event:
#         raise HTTPException(status_code=404, detail="event not found")
#     if event.confirmed_by is not None:
#         return {"detail":"Event already confirmed"}
#     await db.execute(
#         update (OperationalEvent)
#         .where(OperationalEvent.id ==event.id)
#         .values(confirmed_by=user.id, confirmed_at = datetime.now(timezone.utc))
#     )
#     await db.commit()
#     await _audit(db, request, "EVENT CONFIRMED", user, {
#         "event_id" :event.id,
#         "query_name": event.query_name,
#         "event_fingerprint":event.event_fingerprint,
#     })
#     return {"detail":"event confirmed"}

# @router.post("/events/raise-issue")
# async def raise_issue(
#     request : Request, 
#     payload: RaiseIssueV2Request,
#     user: User = Depends(require_client),
#     db: AsyncSession = Depends(get_db),
# ):
#     result = await db.execute(
#         select(OperationalEvent).where(and_(
#             OperationalEvent.id == payload.event_id,
#             OperationalEvent.client_id == user.client_id,
#         ))
#     )
#     event = result.scalar_one_or_none()
#     if not event:
#         raise HTTPException(status_code=404, detail="Event not found")
#     new_issue = EventIssue(
#         event_id = event.id,
#         client_id = user.client_id,
#         raised_by = user.id,
#         issue_text = payload.issue_text,
#     )
#     db.add(new_issue)
#     await db.commit()
#     await db.refresh(new_issue)
#     await _audit(db, request, "EVENT_ISSUE_RAISED", user, {
#         "event_id": event.id,
#         "query_name": event.query_name,
#         "issue_preview": payload.issue_text[:100],
#         "issue_id": new_issue.id,
#     })
#     return {"detail": "Issue raised", "issue_id": new_issue.id}

# @router.get("/anomalies")
# async def get_anomalies(
#     request: Request,
#     user:User = Depends(require_client),
#     db: AsyncSession = Depends(get_db)
# ):
#     from app.models.client import Client
#     result = await db.execute(
#         select(Client).where(Client.id ==user.client_id)
#     )
#     client = result.scalar_one_or_none()
#     if not client or not client.anomaly_visibility_enabled:
#         raise HTTPException(
#             status_code = 403, 
#             detail= " Anomaly monitoring not enabled for your organization"
#         )
#     from app.models.anomaly import Anomaly
#     stmt = (
#         select(Anomaly)
#         .where(Anomaly.client_id == user.client_id)
#         .order_by(Anomaly.detected_at.desc())
#         .limit(500)
#     )
#     rows = (await db.execute(stmt)).scalars().all()
#     return rows
