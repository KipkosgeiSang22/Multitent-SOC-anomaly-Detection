"""
app/routers/graylog.py — Session 12: Graylog Management
Registered in main.py: prefix="/graylog", tags=["graylog"]

Permission gate (same pattern as rules.py and retrain.py):
  Superadmin: always allowed
  Analyst: needs can_manage_graylog=True AND client_id in scope

All actions logged to:
  1. graylog_audit table (every proxied call)
  2. audit_log table (via log_action — GRAYLOG_ACTION event type)

Destructive actions (delete_user, restart_input) require a
two-step confirmation:
  POST /graylog/{client_id}/confirm-intent  → confirm_token (60s TTL)
  Then re-submit with confirm_token + password in body

Route order (static before dynamic — learned from sessions 10/11):
  /health, /confirm-intent registered as sub-paths of /{client_id}/
  which is fine since client_id is always an int and these are
  under /{client_id}/ prefix, not ambiguous with each other.
"""
from __future__ import annotations

import json
import logging
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_action
from app.core.dependencies import get_current_user, get_db
from app.core.security import verify_password
from app.models.analyst_permission import AnalystPermission
from app.models.client import Client
from app.models.graylog_audit import GraylogAudit
from app.models.user import User
from app.schemas.graylog import (
    ConfirmIntentRequest,
    ConfirmIntentResponse,
    DashboardCreate,
    DestructiveRequest,
    GraylogProxyResponse,
    GraylogUserCreate,
    GraylogUserDeleteRequest,
    InputRestartRequest,
)
from app.siem.factory import get_adapter

log = logging.getLogger(__name__)
router = APIRouter()

# ── In-memory confirm token store {token: {client_id, action, target, expires}} 
_confirm_tokens: Dict[str, Dict[str, Any]] = {}
_TOKEN_TTL = 60  # seconds


# ── Permission helper ─────────────────────────────────────────────────────────
async def _check_graylog_permission(
    db: AsyncSession, current_user: User, client_id: int
) -> None:
    if current_user.role == "superadmin":
        return
    if current_user.role != "analyst":
        raise HTTPException(status_code=403, detail="Access denied")

    result = await db.execute(
        select(AnalystPermission).where(
            AnalystPermission.analyst_id == current_user.id,
            AnalystPermission.revoked_at.is_(None),
            AnalystPermission.can_manage_graylog.is_(True),
        )
    )
    perm = result.scalar_one_or_none()
    if not perm:
        raise HTTPException(status_code=403, detail="can_manage_graylog permission required")

    scope = perm.client_scope or []
    if scope != ["ALL"] and client_id not in scope:
        raise HTTPException(status_code=403, detail="Client not in your scope")


# ── Fetch client + build adapter ──────────────────────────────────────────────
async def _get_adapter(db: AsyncSession, client_id: int):
    result = await db.execute(select(Client).where(Client.id == client_id, Client.active.is_(True)))
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found or inactive")
    if client.siem_type != "graylog":
        raise HTTPException(status_code=400, detail=f"Client SIEM type is '{client.siem_type}', not graylog")
    try:
        return get_adapter({
            "id": client.id,
            "siem_type": client.siem_type,
            "siem_base_url": client.siem_base_url,
            "siem_credentials": client.siem_credentials,
        })
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Adapter init failed: {exc}")


# ── Audit helpers ─────────────────────────────────────────────────────────────
async def _write_graylog_audit(
    db: AsyncSession,
    analyst_id: int,
    client_id: int,
    action_type: str,
    payload: dict,
    response_status: int,
) -> None:
    entry = GraylogAudit(
        analyst_id=analyst_id,
        client_id=client_id,
        action_type=action_type,
        payload=payload,
        response_status=response_status,
    )
    db.add(entry)
    # caller is responsible for flush/commit


async def _proxy_call(
    db: AsyncSession,
    request: Request,
    current_user: User,
    client_id: int,
    action_type: str,
    payload: dict,
    coro,  # awaitable that calls the adapter, coroutine
) -> Any:
    """
    Execute an adapter coroutine, write to graylog_audit + audit_log,
    handle httpx errors cleanly.
    """
    response_status = 200
    result = None
    try:
        result = await coro
    except httpx.HTTPStatusError as exc:
        response_status = exc.response.status_code
        await _write_graylog_audit(db, current_user.id, client_id,
                                   action_type, payload, response_status)
        await log_action(db, request, "GRAYLOG_ACTION", user_id=current_user.id,
                         client_id=client_id,
                         details={"action": action_type, "status": response_status,
                                  "error": str(exc)},
                         flush_only=True)
        await db.commit()
        raise HTTPException(status_code=response_status,
                            detail=f"Graylog returned {response_status}: {exc.response.text[:200]}")
    except httpx.RequestError as exc:
        response_status = 503
        await _write_graylog_audit(db, current_user.id, client_id,
                                   action_type, payload, response_status)
        await log_action(db, request, "GRAYLOG_ACTION", user_id=current_user.id,
                         client_id=client_id,
                         details={"action": action_type, "status": 503, "error": str(exc)},
                         flush_only=True)
        await db.commit()
        raise HTTPException(status_code=503, detail=f"Cannot reach Graylog: {exc}")

    await _write_graylog_audit(db, current_user.id, client_id,
                               action_type, payload, response_status)
    await log_action(db, request, "GRAYLOG_ACTION", user_id=current_user.id,
                     client_id=client_id,
                     details={"action": action_type, "status": response_status},
                     flush_only=True)
    await db.commit()
    return result


# ── Confirm token helpers ─────────────────────────────────────────────────────
def _issue_confirm_token(client_id: int, action: str, target: str) -> str:
    token = secrets.token_urlsafe(32)
    _confirm_tokens[token] = {
        "client_id": client_id,
        "action": action,
        "target": target,
        "expires": time.time() + _TOKEN_TTL,
    }
    return token


def _consume_confirm_token(token: str, client_id: int, action: str) -> dict:
    """Validate and consume (delete) a confirm token. Raises HTTPException on failure."""
    entry = _confirm_tokens.get(token)
    if not entry:
        raise HTTPException(status_code=400, detail="Invalid or already-used confirmation token")
    if time.time() > entry["expires"]:
        _confirm_tokens.pop(token, None)
        raise HTTPException(status_code=400, detail="Confirmation token expired (60s window)")
    if entry["client_id"] != client_id or entry["action"] != action:
        raise HTTPException(status_code=400, detail="Confirmation token mismatch")
    _confirm_tokens.pop(token)
    return entry


async def _verify_user_password(db: AsyncSession, user: User, password: str) -> None:
    if not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Password incorrect")


# ══════════════════════════════════════════════════════════════════════════════
# ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

# ── Step 1 for destructive actions: issue confirm token ───────────────────────
@router.post("/{client_id}/confirm-intent", response_model=ConfirmIntentResponse)
async def confirm_intent(
    client_id: int,
    body: ConfirmIntentRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _check_graylog_permission(db, current_user, client_id)
    token = _issue_confirm_token(client_id, body.action, body.target)
    log.info("Confirm token issued: user=%s client=%s action=%s target=%s",
             current_user.id, client_id, body.action, body.target)
    return ConfirmIntentResponse(
        confirm_token=token,
        expires_in_seconds=_TOKEN_TTL,
        message=f"Re-submit within {_TOKEN_TTL}s with this token and your password to confirm.",
    )


# ── Health ────────────────────────────────────────────────────────────────────
@router.get("/{client_id}/health", response_model=GraylogProxyResponse)
async def get_health(
    client_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _check_graylog_permission(db, current_user, client_id)
    adapter = await _get_adapter(db, client_id)
    data = await _proxy_call(db, request, current_user, client_id,
                             "get_health", {},
                             adapter.get_system_health())
    return GraylogProxyResponse(success=True, data=data)


# ── Inputs ────────────────────────────────────────────────────────────────────
@router.get("/{client_id}/inputs", response_model=GraylogProxyResponse)
async def list_inputs(
    client_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _check_graylog_permission(db, current_user, client_id)
    adapter = await _get_adapter(db, client_id)
    data = await _proxy_call(db, request, current_user, client_id,
                             "get_inputs", {},
                             adapter.get_inputs())
    return GraylogProxyResponse(success=True, data=data)


@router.post("/{client_id}/inputs/{input_id}/restart", response_model=GraylogProxyResponse)
async def restart_input(
    client_id: int,
    input_id: str,
    body: InputRestartRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _check_graylog_permission(db, current_user, client_id)
    _consume_confirm_token(body.confirm_token, client_id, "restart_input")
    await _verify_user_password(db, current_user, body.password)

    adapter = await _get_adapter(db, client_id)
    data = await _proxy_call(db, request, current_user, client_id,
                             "restart_input", {"input_id": input_id},
                             adapter.restart_input(input_id))
    return GraylogProxyResponse(success=True, data=data,
                                message=f"Input {input_id} restarted")


# ── Users ─────────────────────────────────────────────────────────────────────
@router.get("/{client_id}/users", response_model=GraylogProxyResponse)
async def list_users(
    client_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _check_graylog_permission(db, current_user, client_id)
    adapter = await _get_adapter(db, client_id)
    # Graylog GET /api/users
    data = await _proxy_call(db, request, current_user, client_id,
                             "list_users", {},
                             adapter._get("/api/users"))
    return GraylogProxyResponse(success=True, data=data)


@router.post("/{client_id}/users", response_model=GraylogProxyResponse)
async def create_user(
    client_id: int,
    body: GraylogUserCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _check_graylog_permission(db, current_user, client_id)
    adapter = await _get_adapter(db, client_id)
    payload = body.model_dump()
    # Never log the password
    audit_payload = {k: v for k, v in payload.items() if k != "password"}
    data = await _proxy_call(db, request, current_user, client_id,
                             "create_user", audit_payload,
                             adapter.create_user(payload))
    return GraylogProxyResponse(success=True, data=data,
                                message=f"User '{body.username}' created in Graylog")


@router.delete("/{client_id}/users/{username}", response_model=GraylogProxyResponse)
async def delete_user(
    client_id: int,
    username: str,
    body: GraylogUserDeleteRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _check_graylog_permission(db, current_user, client_id)
    _consume_confirm_token(body.confirm_token, client_id, "delete_user")
    await _verify_user_password(db, current_user, body.password)

    adapter = await _get_adapter(db, client_id)
    data = await _proxy_call(db, request, current_user, client_id,
                             "delete_user", {"username": username},
                             adapter.delete_user(username))
    return GraylogProxyResponse(success=True, data=data,
                                message=f"User '{username}' deleted from Graylog")


# ── Dashboards ────────────────────────────────────────────────────────────────
@router.get("/{client_id}/dashboards", response_model=GraylogProxyResponse)
async def list_dashboards(
    client_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _check_graylog_permission(db, current_user, client_id)
    adapter = await _get_adapter(db, client_id)
    data = await _proxy_call(db, request, current_user, client_id,
                             "get_dashboards", {},
                             adapter.get_dashboards())
    return GraylogProxyResponse(success=True, data=data)


@router.post("/{client_id}/dashboards", response_model=GraylogProxyResponse)
async def create_dashboard(
    client_id: int,
    body: DashboardCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _check_graylog_permission(db, current_user, client_id)
    adapter = await _get_adapter(db, client_id)
    payload = body.model_dump()
    data = await _proxy_call(db, request, current_user, client_id,
                             "create_dashboard", payload,
                             adapter.create_dashboard(payload))
    return GraylogProxyResponse(success=True, data=data,
                                message=f"Dashboard '{body.title}' created")


# ── Streams ───────────────────────────────────────────────────────────────────
@router.get("/{client_id}/streams", response_model=GraylogProxyResponse)
async def list_streams(
    client_id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _check_graylog_permission(db, current_user, client_id)
    adapter = await _get_adapter(db, client_id)
    data = await _proxy_call(db, request, current_user, client_id,
                             "get_streams", {},
                             adapter.get_streams())
    return GraylogProxyResponse(success=True, data=data)
#adapter looks like this:adapter = GraylogAdapter("https://graylog.example.com", {"username": "admin", "password": "secret"})

# ── Graylog audit log (internal — what actions were taken via this proxy) ─────
@router.get("/{client_id}/audit", response_model=List[dict])
async def graylog_audit_log(
    client_id: int,
    limit: int = 50,
    request: Request = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await _check_graylog_permission(db, current_user, client_id)
    result = await db.execute(
        select(GraylogAudit)
        .where(GraylogAudit.client_id == client_id)
        .order_by(GraylogAudit.performed_at.desc())
        .limit(limit)
    )
    rows = result.scalars().all()
    return [
        {
            "id": r.id,
            "analyst_id": r.analyst_id,
            "client_id": r.client_id,
            "action_type": r.action_type,
            "payload": r.payload,
            "response_status": r.response_status,
            "performed_at": r.performed_at.isoformat() if r.performed_at else None,
        }
        for r in rows
    ]
