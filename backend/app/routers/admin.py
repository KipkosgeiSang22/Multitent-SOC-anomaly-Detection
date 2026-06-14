"""
Superadmin API — Session 6
All routes require require_superadmin dependency.
Every write operation logs to audit_log.
"""
import json
import os
from datetime import datetime, timezone
from io import BytesIO
from typing import Optional

from cryptography.fernet import Fernet
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import select, update, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_action
from app.core.config import settings
from app.core.dependencies import get_db, require_superadmin
from app.core.security import hash_password, generate_temp_password
from app.db.init_db import seed_default_rules_for_client
from app.models.analyst_permission import AnalystPermission
from app.models.anomaly import Anomaly
from app.models.audit_log import AuditLog
from app.models.client import Client
from app.models.client_anomaly_visibility import ClientAnomalyVisibility
from app.models.client_query import ClientQuery
from app.models.operational_event import OperationalEvent
from app.models.scheduler_status import SchedulerStatus
from app.models.user import User
from app.schemas.admin import (
    AuditLogResponse,
    ClientQueryResponse,
    ClientResponse,
    CreateAnalystRequest,
    CreateClientRequest,
    CreateClientUserRequest,
    CreateQueryRequest,
    GrantPermissionRequest,
    PermissionResponse,
    ToggleVisibilityRequest,
    UpdateClientRequest,
    UpdateQueryRequest,
    UpdateUserRequest,
    UserResponse,
    VisibilityResponse,
    VALID_ML_CATEGORIES,
)
from app.utils.excel_formatter import ExcelFormatter

router = APIRouter(prefix="/admin", tags=["admin"])


def _fernet_encrypt(credentials: dict) -> str:
    """Fernet-encrypt a credentials dict and return as string."""
    f = Fernet(settings.FERNET_KEY.encode())
    return f.encrypt(json.dumps(credentials).encode()).decode()


# ===========================================================================
# USER MANAGEMENT
# ===========================================================================

@router.get("/users", response_model=list[UserResponse])
async def list_users(
    role: Optional[str] = Query(None),
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(User).order_by(User.created_at.desc())
    if role:
        stmt = stmt.where(User.role == role)
    result = await db.execute(stmt)
    return result.scalars().all()


@router.get("/users/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int,
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.post("/analysts", response_model=UserResponse, status_code=201)
async def create_analyst(
    request: Request,
    body: CreateAnalystRequest,
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    dup = await db.execute(
        select(User).where(
            (User.username == body.username) | (User.email == body.email)
        )
    )
    if dup.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Username or email already taken")

    new_user = User(
        username=body.username,
        email=body.email,
        password_hash=hash_password(body.password),
        role="analyst",
        is_active=True,
        force_password_change=True,
        mfa_enabled=False,
        failed_login_attempts=0,
    )
    db.add(new_user)
    await db.flush()

    await log_action(
        db=db,
        request=request,
        event_type="ANALYST_CREATED",
        user_id=current_user.id,
        target_id=new_user.id,
        details={"username": body.username, "email": body.email, "target_id": new_user.id},
        flush_only=True,
    )
    await db.commit()
    await db.refresh(new_user)
    return new_user


@router.post("/client-users", response_model=UserResponse, status_code=201)
async def create_client_user(
    request: Request,
    body: CreateClientUserRequest,
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    client_result = await db.execute(
        select(Client).where(Client.id == body.client_id, Client.active == True)
    )
    if not client_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Client not found or inactive")

    dup = await db.execute(
        select(User).where(
            (User.username == body.username) | (User.email == body.email)
        )
    )
    if dup.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Username or email already taken")

    new_user = User(
        username=body.username,
        email=body.email,
        password_hash=hash_password(body.password),
        role="client",
        client_id=body.client_id,
        is_active=True,
        force_password_change=True,
        mfa_enabled=False,
        failed_login_attempts=0,
    )
    db.add(new_user)
    await db.flush()

    await log_action(
        db=db,
        request=request,
        event_type="CLIENT_USER_CREATED",
        user_id=current_user.id,
        client_id=body.client_id,
        target_id=new_user.id,
        details={
            "username": body.username,
            "email": body.email,
            "role": "client",
            "client_id": body.client_id,
            "target_id": new_user.id,
        },
        flush_only=True,
    )
    await db.commit()
    await db.refresh(new_user)
    return new_user


@router.patch("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    request: Request,
    body: UpdateUserRequest,
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if body.is_active is False and user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")

    before = {
        "email": user.email,
        "is_active": user.is_active,
        "force_password_change": user.force_password_change,
    }

    if body.email is not None:
        user.email = body.email
    if body.is_active is not None:
        user.is_active = body.is_active
    if body.force_password_change is not None:
        user.force_password_change = body.force_password_change

    after = {
        "email": user.email,
        "is_active": user.is_active,
        "force_password_change": user.force_password_change,
    }

    event_type = "ANALYST_UPDATED" if user.role == "analyst" else "CLIENT_UPDATED"
    await log_action(
        db=db,
        request=request,
        event_type=event_type,
        user_id=current_user.id,
        target_id=user.id,
        details={"before": before, "after": after},
        flush_only=True,
    )
    await db.commit()
    await db.refresh(user)
    return user


@router.post("/users/{user_id}/deactivate")
async def deactivate_user(
    user_id: int,
    request: Request,
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_active = False
    await log_action(
        db=db,
        request=request,
        event_type="USER_DEACTIVATED",
        user_id=current_user.id,
        target_id=user.id,
        details={"username": user.username, "role": user.role},
        flush_only=True,
    )
    await db.commit()
    return {"detail": "User deactivated"}


@router.post("/users/{user_id}/reset-password")
async def reset_user_password(
    user_id: int,
    request: Request,
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    temp_password = generate_temp_password()
    user.password_hash = hash_password(temp_password)
    user.force_password_change = True

    await log_action(
        db=db,
        request=request,
        event_type="PASSWORD_RESET_BY_ADMIN",
        user_id=current_user.id,
        target_id=user.id,
        details={"target_user_id": user.id, "target_username": user.username},
        flush_only=True,
    )
    await db.commit()
    # await _send_reset_email(user.email, temp_password)

    response: dict = {"detail": "Password reset"}
    if settings.ENVIRONMENT == "development":
        response["temp_password"] = temp_password
    return response


@router.delete("/users/{user_id}", status_code=204)
async def delete_user(
    user_id: int,
    request: Request,
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.role == "superadmin":
        raise HTTPException(status_code=400, detail="Cannot delete superadmin accounts")

    await log_action(
        db=db,
        request=request,
        event_type="USER_DELETED",
        user_id=current_user.id,
        target_id=user.id,
        details={"username": user.username, "role": user.role, "email": user.email},
        flush_only=True,
    )
    await db.delete(user)
    await db.commit()


# ===========================================================================
# CLIENT MANAGEMENT
# ===========================================================================

@router.get("/clients", response_model=list[ClientResponse])
async def list_clients(
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Client).order_by(Client.created_at.desc()))
    return result.scalars().all()


@router.get("/clients/{client_id}", response_model=ClientResponse)
async def get_client(
    client_id: int,
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Client).where(Client.id == client_id))
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    return client


@router.post("/clients", response_model=ClientResponse, status_code=201)
async def create_client(
    request: Request,
    body: CreateClientRequest,
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    dup = await db.execute(select(Client).where(Client.name == body.name))
    if dup.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Client name already taken")

    encrypted_creds = None
    if body.siem_credentials:
        encrypted_creds = _fernet_encrypt(body.siem_credentials)

    new_client = Client(
        name=body.name,
        siem_type=body.siem_type,
        siem_base_url=body.siem_base_url,
        siem_credentials=encrypted_creds,
        subscription_plan=body.subscription_plan,
        subscription_status=body.subscription_status,
        anomaly_visibility_enabled=False,
        active=True,
    )
    db.add(new_client)
    await db.flush()

    

    await seed_default_rules_for_client(db, new_client.id, current_user.id)

    visibility = ClientAnomalyVisibility(
        client_id=new_client.id,
        visible=False,
        toggled_by=current_user.id,
        toggled_at=datetime.now(timezone.utc),
    )
    db.add(visibility)

    await log_action(
        db=db,
        request=request,
        event_type="CLIENT_CREATED",
        user_id=current_user.id,
        client_id=new_client.id,
        details={"name": body.name, "siem_type": body.siem_type},
        flush_only=True,
    )
    await db.commit()
    await db.refresh(new_client)
    os.makedirs(f"{settings.MODEL_BASE_PATH}/{new_client.id}", exist_ok=True)
    return new_client


@router.patch("/clients/{client_id}", response_model=ClientResponse)
async def update_client(
    client_id: int,
    request: Request,
    body: UpdateClientRequest,
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Client).where(Client.id == client_id))
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    before = {
        "name": client.name,
        "siem_type": client.siem_type,
        "siem_base_url": client.siem_base_url,
        "subscription_plan": client.subscription_plan,
        "subscription_status": client.subscription_status,
        "active": client.active,
    }

    if body.name is not None:
        client.name = body.name
    if body.siem_type is not None:
        client.siem_type = body.siem_type
    if body.siem_base_url is not None:
        client.siem_base_url = body.siem_base_url
    if body.siem_credentials is not None:
        client.siem_credentials = _fernet_encrypt(body.siem_credentials)
    if body.subscription_plan is not None:
        client.subscription_plan = body.subscription_plan
    if body.subscription_status is not None:
        client.subscription_status = body.subscription_status
    if body.active is not None:
        client.active = body.active

    after = {
        "name": client.name,
        "siem_type": client.siem_type,
        "siem_base_url": client.siem_base_url,
        "subscription_plan": client.subscription_plan,
        "subscription_status": client.subscription_status,
        "active": client.active,
    }

    await log_action(
        db=db,
        request=request,
        event_type="CLIENT_UPDATED",
        user_id=current_user.id,
        client_id=client_id,
        details={"before": before, "after": after},
        flush_only=True,
    )
    await db.commit()
    await db.refresh(client)
    return client


@router.post("/clients/{client_id}/deactivate")
async def deactivate_client(
    client_id: int,
    request: Request,
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Client).where(Client.id == client_id))
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    client.active = False
    await log_action(
        db=db,
        request=request,
        event_type="CLIENT_DEACTIVATED",
        user_id=current_user.id,
        client_id=client_id,
        details={"name": client.name},
        flush_only=True,
    )
    await db.commit()
    return {"detail": "Client deactivated"}


# ===========================================================================
# CLIENT QUERY MANAGEMENT
# ===========================================================================

@router.get("/clients/{client_id}/queries", response_model=list[ClientQueryResponse])
async def list_queries(
    client_id: int,
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ClientQuery)
        .where(ClientQuery.client_id == client_id)
        .order_by(ClientQuery.display_order)
    )
    return result.scalars().all()


@router.post("/queries", response_model=ClientQueryResponse, status_code=201)
async def create_query(
    request: Request,
    body: CreateQueryRequest,
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    client_result = await db.execute(select(Client).where(Client.id == body.client_id))
    if not client_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Client not found")

    if body.is_ml_category:
        if not body.ml_category:
            raise HTTPException(
                status_code=400,
                detail="ml_category is required when is_ml_category is True",
            )
        if body.ml_category not in VALID_ML_CATEGORIES:
            raise HTTPException(
                status_code=400,
                detail=f"ml_category must be one of: {', '.join(VALID_ML_CATEGORIES)}",
            )

    dup = await db.execute(
        select(ClientQuery).where(
            ClientQuery.client_id == body.client_id,
            ClientQuery.query_name == body.query_name,
        )
    )
    if dup.scalar_one_or_none():
        raise HTTPException(
            status_code=409, detail="Query name already exists for this client"
        )

    new_query = ClientQuery(
        client_id=body.client_id,
        query_name=body.query_name,
        graylog_query=body.graylog_query,
        is_ml_category=body.is_ml_category,
        ml_category=body.ml_category if body.is_ml_category else None,
        enabled=True,
        display_order=body.display_order,
    )
    db.add(new_query)
    await db.flush()

    await log_action(
        db=db,
        request=request,
        event_type="QUERY_CREATED",
        user_id=current_user.id,
        client_id=body.client_id,
        target_id=new_query.id,
        details={"query_name": body.query_name, "client_id": body.client_id},
        flush_only=True,
    )
    await db.commit()
    await db.refresh(new_query)
    return new_query


@router.patch("/queries/{query_id}", response_model=ClientQueryResponse)
async def update_query(
    query_id: int,
    request: Request,
    body: UpdateQueryRequest,
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(ClientQuery).where(ClientQuery.id == query_id))
    query = result.scalar_one_or_none()
    if not query:
        raise HTTPException(status_code=404, detail="Query not found")

    before = {
        "query_name": query.query_name,
        "graylog_query": query.graylog_query,
        "enabled": query.enabled,
        "display_order": query.display_order,
    }

    if body.query_name is not None:
        query.query_name = body.query_name
    if body.graylog_query is not None:
        query.graylog_query = body.graylog_query
    if body.enabled is not None:
        query.enabled = body.enabled
    if body.display_order is not None:
        query.display_order = body.display_order

    await log_action(
        db=db,
        request=request,
        event_type="QUERY_UPDATED",
        user_id=current_user.id,
        client_id=query.client_id,
        target_id=query.id,
        details={
            "before": before,
            "after": {
                "query_name": query.query_name,
                "graylog_query": query.graylog_query,
                "enabled": query.enabled,
                "display_order": query.display_order,
            },
        },
        flush_only=True,
    )
    await db.commit()
    await db.refresh(query)
    return query


@router.post("/queries/{query_id}/disable")
async def disable_query(
    query_id: int,
    request: Request,
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(ClientQuery).where(ClientQuery.id == query_id))
    query = result.scalar_one_or_none()
    if not query:
        raise HTTPException(status_code=404, detail="Query not found")

    query.enabled = False
    await log_action(
        db=db,
        request=request,
        event_type="QUERY_DISABLED",
        user_id=current_user.id,
        client_id=query.client_id,
        target_id=query.id,
        details={"query_name": query.query_name},
        flush_only=True,
    )
    await db.commit()
    return {"detail": "Query disabled"}


# ===========================================================================
# PERMISSION MANAGEMENT
# ===========================================================================

async def _build_permission_response(
    perm: AnalystPermission, db: AsyncSession
) -> PermissionResponse:
    analyst_result = await db.execute(select(User).where(User.id == perm.analyst_id))
    analyst = analyst_result.scalar_one_or_none()
    granter_result = await db.execute(select(User).where(User.id == perm.granted_by))
    granter = granter_result.scalar_one_or_none()
    return PermissionResponse(
        id=perm.id,
        analyst_id=perm.analyst_id,
        analyst_username=analyst.username if analyst else "unknown",
        granted_by=perm.granted_by,
        granted_by_username=granter.username if granter else "unknown",
        can_retrain_models=perm.can_retrain_models,
        can_edit_layer1_rules=perm.can_edit_layer1_rules,
        can_manage_graylog=perm.can_manage_graylog,
        client_scope=perm.client_scope,
        granted_at=perm.granted_at,
        revoked_at=perm.revoked_at,
        reason=perm.reason,
    )


@router.get("/permissions", response_model=list[PermissionResponse])
async def list_permissions(
    analyst_id: Optional[int] = Query(None),
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(AnalystPermission).where(AnalystPermission.revoked_at.is_(None))
    if analyst_id:
        stmt = stmt.where(AnalystPermission.analyst_id == analyst_id)
    result = await db.execute(stmt)
    perms = result.scalars().all()
    return [await _build_permission_response(p, db) for p in perms]

@router.post("/permissions/grant", response_model=PermissionResponse, status_code=201)
async def grant_permission(
    request: Request,
    body: GrantPermissionRequest,
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    analyst_result = await db.execute(select(User).where(User.id == body.analyst_id))
    analyst = analyst_result.scalar_one_or_none()
    if not analyst:
        raise HTTPException(status_code=404, detail="Analyst not found")
    if analyst.role != "analyst":
        raise HTTPException(status_code=400, detail="Target user is not an analyst")
    old_perm_result =await db.execute(
        select(AnalystPermission).where(AnalystPermission.analyst_id == body.analyst_id,
                                        AnalystPermission.revoked_at.is_(None))
    )
    old_perm = old_perm_result.scalar_one_or_none()
    before = {
        "can_retrain_models":old_perm.can_retrain_models,
        "can_edit_layer1_rules":old_perm.can_edit_layer1_rules,
        "can_manage_graylog":old_perm.can_manage_graylog,
        "client_scope":old_perm.client_scope,
        "reason":old_perm.reason,
     } if old_perm else None
    await db.execute(
        update(AnalystPermission)
        .where(
            AnalystPermission.analyst_id == body.analyst_id,
            AnalystPermission.revoked_at.is_(None),
        )
        .values(revoked_at=datetime.now(timezone.utc))
    )

    new_perm = AnalystPermission(
        analyst_id=body.analyst_id,
        granted_by=current_user.id,
        can_retrain_models=body.can_retrain_models,
        can_edit_layer1_rules=body.can_edit_layer1_rules,
        can_manage_graylog=body.can_manage_graylog,
        client_scope=body.client_scope,
        reason=body.reason,
    )
    db.add(new_perm)
    await db.flush()

    await log_action(
        db=db,
        request=request,
        event_type="PERMISSION_GRANTED",
        user_id=current_user.id,
        target_id=body.analyst_id,
        before_update=before,
        after_update={
            "analyst_id": body.analyst_id,
            "analyst_username": analyst.username,
            "can_retrain_models": body.can_retrain_models,
            "can_edit_layer1_rules": body.can_edit_layer1_rules,
            "can_manage_graylog": body.can_manage_graylog,
            "client_scope": body.client_scope,
            "reason": body.reason,
        },
        flush_only=True,
    )
    await db.commit()
    await db.refresh(new_perm)
    return await _build_permission_response(new_perm, db)


@router.post("/permissions/{permission_id}/revoke")
async def revoke_permission(
    permission_id: int,
    request: Request,
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(AnalystPermission).where(AnalystPermission.id == permission_id)
    )
    perm = result.scalar_one_or_none()
    if not perm:
        raise HTTPException(status_code=404, detail="Permission not found")
    if perm.revoked_at:
        raise HTTPException(status_code=400, detail="Permission already revoked")

    perm.revoked_at = datetime.now(timezone.utc)
    await log_action(
        db=db,
        request=request,
        event_type="PERMISSION_REVOKED",
        user_id=current_user.id,
        target_id=perm.analyst_id,
        details={"permission_id": permission_id, "analyst_id": perm.analyst_id},
        flush_only=True,
    )
    await db.commit()
    return {"detail": "Permission revoked"}


# ===========================================================================
# ANOMALY VISIBILITY
# ===========================================================================

@router.post("/visibility/toggle")
async def toggle_visibility(
    request: Request,
    body: ToggleVisibilityRequest,
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    client_result = await db.execute(select(Client).where(Client.id == body.client_id))
    client = client_result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    now = datetime.now(timezone.utc)

    existing = await db.execute(
        select(ClientAnomalyVisibility).where(
            ClientAnomalyVisibility.client_id == body.client_id
        )
    )
    vis = existing.scalar_one_or_none()

    if vis:
        vis.visible = body.visible
        vis.toggled_by = current_user.id
        vis.toggled_at = now
    else:
        vis = ClientAnomalyVisibility(
            client_id=body.client_id,
            visible=body.visible,
            toggled_by=current_user.id,
            toggled_at=now,
        )
        db.add(vis)

    client.anomaly_visibility_enabled = body.visible

    await log_action(
        db=db,
        request=request,
        event_type="VISIBILITY_TOGGLED",
        user_id=current_user.id,
        client_id=body.client_id,
        details={"client_id": body.client_id, "visible": body.visible},
        flush_only=True,
    )
    await db.commit()
    return {"detail": f"Visibility set to {body.visible} for client {body.client_id}"}


@router.get("/visibility", response_model=list[VisibilityResponse])
async def list_visibility(
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(ClientAnomalyVisibility))
    rows = result.scalars().all()
    responses = []
    for row in rows:
        client_result = await db.execute(select(Client).where(Client.id == row.client_id))
        client = client_result.scalar_one_or_none()
        responses.append(
            VisibilityResponse(
                client_id=row.client_id,
                client_name=client.name if client else "Unknown",
                visible=row.visible,
                toggled_by=row.toggled_by,
                toggled_at=row.toggled_at,
            )
        )
    return responses


# ===========================================================================
# PLATFORM HEALTH
# ===========================================================================

@router.get("/platform-stats")
async def platform_stats(
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    total_clients = (await db.execute(select(func.count()).select_from(Client))).scalar()
    active_clients = (
        await db.execute(
            select(func.count()).select_from(Client).where(Client.active == True)
        )
    ).scalar()
    total_users = (await db.execute(select(func.count()).select_from(User))).scalar()
    total_events = (
        await db.execute(select(func.count()).select_from(OperationalEvent))
    ).scalar()
    total_anomalies = (
        await db.execute(select(func.count()).select_from(Anomaly))
    ).scalar()
    unacknowledged_anomalies = (
        await db.execute(
            select(func.count())
            .select_from(Anomaly)
            .where(Anomaly.acknowledged_by.is_(None))
        )
    ).scalar()

    scheduler_result = await db.execute(
        select(SchedulerStatus).order_by(SchedulerStatus.last_run_at.desc())
    )
    scheduler_rows = scheduler_result.scalars().all()
    scheduler_status = [
        {
            "process_name": s.process_name,
            "last_run_at": s.last_run_at.isoformat() if s.last_run_at else None,
            "last_run_status": s.last_run_status,
            "last_error": s.last_error,
            "clients_processed": s.clients_processed,
            "events_inserted": s.events_inserted,
            "anomalies_detected": s.anomalies_detected,
            "duration_seconds": s.duration_seconds,
        }
        for s in scheduler_rows
    ]

    return {
        "total_clients": total_clients,
        "active_clients": active_clients,
        "total_users": total_users,
        "total_events": total_events,
        "total_anomalies": total_anomalies,
        "unacknowledged_anomalies": unacknowledged_anomalies,
        "scheduler_status": scheduler_status,
    }


# ===========================================================================
# AUDIT LOG
# ===========================================================================

@router.get("/audit-log", response_model=list[AuditLogResponse])
async def get_audit_log(
    user_id: Optional[int] = Query(None),
    client_id: Optional[int] = Query(None),
    event_type: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(AuditLog).order_by(AuditLog.performed_at.desc()).limit(limit)
    if user_id:
        stmt = stmt.where(AuditLog.user_id == user_id)
    if client_id:
        stmt = stmt.where(AuditLog.client_id == client_id)
    if event_type:
        stmt = stmt.where(AuditLog.event_type == event_type)

    result = await db.execute(stmt)
    logs = result.scalars().all()

    responses = []
    for log_row in logs:
        username = None
        if log_row.user_id:
            u_result = await db.execute(select(User).where(User.id == log_row.user_id))
            u = u_result.scalar_one_or_none()
            username = u.username if u else None

        responses.append(
            AuditLogResponse(
                id=log_row.id,
                user_id=log_row.user_id,
                username=username,
                role=log_row.role,
                event_type=log_row.event_type,
                client_id=log_row.client_id,
                target_id=log_row.target_id,
                details=log_row.details,
                ip_address=log_row.ip_address,
                user_agent=log_row.user_agent,
                performed_at=log_row.performed_at,
            )
        )
    return responses


@router.get("/audit-log/download")
async def download_audit_log(
    request: Request,
    user_id: Optional[int] = Query(None),
    client_id: Optional[int] = Query(None),
    event_type: Optional[str] = Query(None),
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(AuditLog).order_by(AuditLog.performed_at.desc())
    if user_id:
        stmt = stmt.where(AuditLog.user_id == user_id)
    if client_id:
        stmt = stmt.where(AuditLog.client_id == client_id)
    if event_type:
        stmt = stmt.where(AuditLog.event_type == event_type)

    result = await db.execute(stmt)
    logs = result.scalars().all()

    rows = []
    for log_row in logs:
        username = None
        if log_row.user_id:
            u_result = await db.execute(select(User).where(User.id == log_row.user_id))
            u = u_result.scalar_one_or_none()
            username = u.username if u else None

        rows.append({
            "id": log_row.id,
            "username": username,
            "role": log_row.role,
            "event_type": log_row.event_type,
            "client_id": log_row.client_id,
            "target_id": log_row.target_id,
            "details": json.dumps(log_row.details) if log_row.details else "",
            "ip_address": log_row.ip_address,
            "user_agent": log_row.user_agent,
            "performed_at": log_row.performed_at,
        })

    formatter = ExcelFormatter()
    buffer: BytesIO = formatter.write_audit_log(rows)

    await log_action(
        db=db,
        request=request,
        event_type="FILE_DOWNLOADED",
        user_id=current_user.id,
        details={
            "file": "audit_log",
            "filters": {
                "user_id": user_id,
                "client_id": client_id,
                "event_type": event_type,
            },
            "row_count": len(rows),
        },
        flush_only=True,
    )
    await db.commit()

    return StreamingResponse(
        buffer,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=audit_log.xlsx"},
    )


# ---------------------------------------------------------------------------
# GET /admin/payments  — all payments across all clients
# ---------------------------------------------------------------------------

from app.models.payment import Payment
from app.schemas.payments import PaymentResponse


@router.get("/payments", response_model=list[PaymentResponse])
async def get_all_payments(
    client_id: Optional[int] = Query(None),
    status: Optional[str] = Query(None),
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    """
    Return all payments across all clients, newest first.
    Optional filters: ?client_id=&status=
    """
    stmt = select(Payment).order_by(Payment.initiated_at.desc())
    if client_id:
        stmt = stmt.where(Payment.client_id == client_id)
    if status:
        stmt = stmt.where(Payment.status == status)

    result = await db.execute(stmt)
    payments = result.scalars().all()

    responses = []
    for payment in payments:
        c_result = await db.execute(select(Client).where(Client.id == payment.client_id))
        c = c_result.scalar_one_or_none()
        client_name = c.name if c else f"client_{payment.client_id}"

        responses.append(PaymentResponse(
            id=payment.id,
            client_id=payment.client_id,
            client_name=client_name,
            phone_number=payment.phone_number,
            amount=float(payment.amount) if payment.amount is not None else None,
            mpesa_receipt_number=payment.mpesa_receipt_number,
            checkout_request_id=payment.checkout_request_id,
            status=payment.status,
            payment_type=payment.payment_type,
            period_covered_start=payment.period_covered_start,
            period_covered_end=payment.period_covered_end,
            initiated_at=payment.initiated_at,
            completed_at=payment.completed_at,
            callback_received_at=payment.callback_received_at,
        ))

    return responses
