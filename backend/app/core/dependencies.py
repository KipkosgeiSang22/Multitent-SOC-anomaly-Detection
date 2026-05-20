from typing import AsyncGenerator, Optional, List
from fastapi import Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text
from datetime import datetime, timezone
from app.db.session import AsyncSessionLocal
from app.core.security import decode_token
from app.models.user import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login", auto_error=False)

VALID_ROLES = {"superadmin", "analyst", "client", "none"}


async def get_db(request: Request) -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        await session.execute(text("SET LOCAL \"app.current_client_id\" = ''"))
        await session.execute(text("SET LOCAL \"app.current_role\" = 'none'"))
        try:
            yield session
        finally:
            await session.close()


async def get_current_user(
    request: Request,
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> User:
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    payload = decode_token(token)
    if not payload or payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user_id = payload.get("sub")
    result = await db.execute(select(User).where(User.id == int(user_id)))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User inactive or not found")

    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        raise HTTPException(status_code=423, detail="Account is locked")

    # Sanitize role against whitelist before injecting into SET LOCAL
    role = user.role if user.role in VALID_ROLES else "none"
    client_id = str(user.client_id) if user.client_id else ""
    # Block access everywhere except /auth/change-password if password change is forced
    if user.force_password_change and request.url.path != "/auth/change-password":
        raise HTTPException(
            status_code=403,
            detail={"code": "password_change_required", "message": "Password change required"}
        )
    await db.execute(text(f"SET LOCAL \"app.current_role\" = '{role}'"))
    await db.execute(text(f"SET LOCAL \"app.current_client_id\" = '{client_id}'"))

    return user


def require_role(roles: List[str]):
    def role_checker(user: User = Depends(get_current_user)):
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return role_checker


require_superadmin = require_role(["superadmin"])
require_analyst = require_role(["superadmin", "analyst"])


async def _require_client_user(
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Extended client dependency that:
    1. Verifies role == 'client'
    2. Checks that the client organisation's subscription is not suspended
    """
    if user.role != "client":
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    # Import here to avoid circular imports at module load time
    from app.models.client import Client
    if user.client_id:
        result = await db.execute(select(Client).where(Client.id == user.client_id))
        client = result.scalar_one_or_none()
        if client and client.subscription_status == "suspended":
            raise HTTPException(
                status_code=403,
                detail="Account suspended. Contact your administrator."
            )

    return user


# require_client now enforces subscription_status in addition to role
require_client = _require_client_user
