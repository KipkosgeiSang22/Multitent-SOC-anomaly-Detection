import secrets
import hashlib
import aiosmtplib
from email.message import EmailMessage
from datetime import datetime, timezone, timedelta
from fastapi.security import OAuth2PasswordRequestForm
from fastapi import APIRouter, Depends, HTTPException, Response, Request, Cookie
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.core import security, dependencies
from app.schemas import auth as schemas
from app.models.user import User 
from app.models.audit_log import AuditLog
from app.models.client import Client
from app.core.config import settings

router = APIRouter(prefix="/auth", tags=["Authentication"])


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

async def _log_event(
    db: AsyncSession,
    request: Request,
    event_type: str,
    user_id: int = None,
    client_id: int = None,
    details: dict = None,
    role: str = None,
):
    """Write to audit_log; never raises — failures are printed only."""
    try:
        audit = AuditLog(
            user_id=user_id,
            event_type=event_type,
            client_id=client_id,
            role=role,
            ip_address=request.client.host if request.client else "127.0.0.1",
            user_agent=request.headers.get("user-agent"),
            details=details or {},
        )
        db.add(audit)
        await db.commit()
    except Exception as e:
        print(f"AUDIT LOG FAILURE: {e}")
        await db.rollback()


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def _send_reset_email(to_email: str, reset_link: str):
    """Send password-reset email via SMTP. Swallows errors in development."""
    if not settings.SMTP_HOST:
        print(f"[DEV] Password reset link for {to_email}: {reset_link}")
        return
    try:
        msg = EmailMessage()
        msg["From"] = settings.SMTP_FROM
        msg["To"] = to_email
        msg["Subject"] = "SOC Platform — Password Reset"
        msg.set_content(
            f"Click the link below to reset your password (valid 30 minutes):\n\n{reset_link}\n\n"
            "If you did not request this, ignore this email."
        )
        await aiosmtplib.send(
            msg,
            hostname=settings.SMTP_HOST,
            port=settings.SMTP_PORT,
            username=settings.SMTP_USER,
            password=settings.SMTP_PASSWORD,
            start_tls=True, 
        )
    except Exception as e:
        print(f"EMAIL SEND FAILURE: {e}")


# ---------------------------------------------------------------------------
# POST /auth/login
# ---------------------------------------------------------------------------

@router.post("/login", response_model=schemas.LoginResponse)
async def login(
    request: Request,
    response: Response,
    # OAuth2PasswordRequestForm allows Swagger UI to work with the lock icon.
    payload: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(dependencies.get_db)
):
    # Fetch user by username from the form
    result = await db.execute(select(User).where(User.username == payload.username))
    user = result.scalar_one_or_none()

    # 1. Check if user exists
    if not user or not user.is_active:
        await _log_event(db, request, "LOGIN_FAILED", details={"reason": "User not found", "user": payload.username})
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # 2. Check if locked
    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        raise HTTPException(status_code=423, detail="Account is locked")

    # 3. Verify Password
    if not security.verify_password(payload.password, user.password_hash):
        new_attempts = user.failed_login_attempts + 1
        lock_until = datetime.now(timezone.utc) + timedelta(minutes=15) if new_attempts >= 5 else None
        await db.execute(
            update(User).where(User.id == user.id).values(
                failed_login_attempts=new_attempts, locked_until=lock_until
            )
        )
        await db.commit()
        await _log_event(db, request, "LOGIN_FAILED", user_id=user.id, details={"reason": "Wrong password"})
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # 4. Success - Clear failures and issue token
    await db.execute(update(User).where(User.id == user.id).values(failed_login_attempts=0, locked_until=None))
    await db.commit()

    # 4a. For client users, check subscription_status before issuing a token
    if user.role == "client" and user.client_id:
        client_result = await db.execute(select(Client).where(Client.id == user.client_id))
        client_obj = client_result.scalar_one_or_none()
        if client_obj and client_obj.subscription_status == "suspended":
            raise HTTPException(
                status_code=403,
                detail="Your organisation\'s subscription is suspended. Contact your administrator."
            )
    if user.mfa_enabled:
        temp_token = security.create_mfa_temp_token(user.id)
        return {
            "mfa_required": True,
            "temp_token": temp_token,
            "access_token": None,
            "token_type": "bearer"
        }
    access_token = security.create_access_token({
        "sub": str(user.id), 
        "role": user.role,
        "client_id": user.client_id
    })
    
    await _log_event(db, request, f"{user.role.upper()}_LOGIN", user_id=user.id)

    # BUG FIX: login must set the refresh cookie so that bootstrap() on page
    # reload can call POST /auth/refresh and silently restore the session.
    # Previously only mfa-verify set this cookie, so non-MFA logins were
    # always kicked out on reload.
    refresh_token = security.create_refresh_token({"sub": str(user.id), "version":user.refresh_token_version})
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        samesite="lax",
        secure=settings.ENVIRONMENT != "development",
        max_age=60 * 60 * 24 * 7,  # 7 days, matches token expiry
    )

    return {
        "mfa_required": False,
        "access_token": access_token,
        "token_type": "bearer"
    }


# ---------------------------------------------------------------------------
# POST /auth/mfa-verify
# ---------------------------------------------------------------------------



@router.post("/mfa-verify", response_model=schemas.TokenResponse)
async def mfa_verify(
    request: Request,
    response: Response,
    payload: schemas.MFARequest,
    db: AsyncSession = Depends(dependencies.get_db),
):
    data = security.decode_token(payload.temp_token)
    if not data or data.get("type") != "mfa_temp" or not data.get("mfa_pending"):
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    user_id = int(data["sub"])
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found")
    if user.mfa_locked_until and user.mfa_locked_until > datetime.now(timezone.utc):
        raise HTTPException(status_code=423, detail="account temporarily out")

    if not security.verify_totp(user.mfa_secret, payload.totp_code):
        new_attempts = user.mfa_failed_attempts + 1
        lock_until = datetime.now(timezone.utc) + timedelta(minutes=15) if new_attempts >= 5 else None
        await db.execute(
            update(User).where(User.id == user.id).values(
                mfa_failed_attempts = new_attempts, mfa_locked_until = lock_until
            )
        )
        await db.commit()
        await _log_event(db, request, "LOGIN_FAILED", user_id=user.id, details={"reason": "bad_totp"})
        raise HTTPException(status_code=401, detail="Invalid MFA code")

    access_token = security.create_access_token(
        {"sub": str(user.id), "role": user.role, "client_id": user.client_id}
    )
    refresh_token = security.create_refresh_token({"sub": str(user.id), "version":user.refresh_token_version})

    response.set_cookie(
        key="refresh_token", value=refresh_token,
        httponly=True, samesite="lax", secure=settings.ENVIRONMENT != "development"
    )
    event = f"{user.role.upper()}_LOGIN"
    await db.execute(update(User).where(User.id == user.id).values(mfa_failed_attempts=0, mfa_locked_until = None))

    await _log_event(db, request, event, user_id=user.id, role=user.role)
    await db.commit()
    return {"access_token": access_token, "token_type": "bearer"}


# ---------------------------------------------------------------------------
# POST /auth/refresh
# ---------------------------------------------------------------------------

@router.post("/refresh", response_model=schemas.RefreshResponse)
async def refresh(
    request: Request,
    response: Response,
    refresh_token: str = Cookie(default=None),
    db: AsyncSession = Depends(dependencies.get_db),
):
    if not refresh_token:
        raise HTTPException(status_code=401, detail="No refresh token")

    data = security.decode_token(refresh_token)
    if not data or data.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    user_id = int(data["sub"])
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()


    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found")
    if data.get("version") != user.refresh_token_version:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    
    

    # Rotate: issue new tokens, old one is implicitly invalidated by expiry
    new_access = security.create_access_token(
        {"sub": str(user.id), "role": user.role, "client_id": user.client_id}
    )
    new_refresh = security.create_refresh_token({"sub": str(user.id), "version":user.refresh_token_version})

    response.set_cookie(
        key="refresh_token", value=new_refresh,
        httponly=True, samesite="lax", secure=settings.ENVIRONMENT != "development"
    )
    return {"access_token": new_access, "token_type": "bearer"}


# ---------------------------------------------------------------------------
# POST /auth/logout
# ---------------------------------------------------------------------------

@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    user: User = Depends(dependencies.get_current_user),
    db: AsyncSession = Depends(dependencies.get_db),
):
    response.delete_cookie("refresh_token")
    await _log_event(db, request, "LOGOUT", user_id=user.id, role=user.role)
    await db.execute(update(User).where(User.id == user.id).values(
        refresh_token_version = user.refresh_token_version + 1))
    await db.commit()

    return {"detail": "Logged out"}


# ---------------------------------------------------------------------------
# POST /auth/forgot-password
# ---------------------------------------------------------------------------

@router.post("/forgot-password")
async def forgot_password(
    request: Request,
    payload: schemas.ForgotPasswordRequest,
    db: AsyncSession = Depends(dependencies.get_db),
):
    # Always return 200 — never reveal if email exists
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if user and user.is_active:
        raw_token = secrets.token_urlsafe(32)
        token_hash = _hash_token(raw_token)
        expiry = datetime.now(timezone.utc) + timedelta(minutes=30)

        await db.execute(
            update(User).where(User.id == user.id).values(
                password_reset_token=token_hash,
                password_reset_expires=expiry,
            )
        )
        await db.commit()

        reset_link = f"{settings.FRONTEND_ORIGIN}/reset-password?token={raw_token}"
        await _send_reset_email(user.email, reset_link)
        await _log_event(db, request, "PASSWORD_RESET_SELF", user_id=user.id, details={"step": "requested"})

    return {"detail": "If that email exists, a reset link has been sent"}


# ---------------------------------------------------------------------------
# POST /auth/reset-password
# ---------------------------------------------------------------------------

@router.post("/reset-password")
async def reset_password(
    request: Request,
    payload: schemas.ResetPasswordRequest,
    db: AsyncSession = Depends(dependencies.get_db),
):
    token_hash = _hash_token(payload.token)
    result = await db.execute(
        select(User).where(User.password_reset_token == token_hash)
    )
    user = result.scalar_one_or_none()

    if not user or not user.password_reset_expires:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    if user.password_reset_expires < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    new_hash = security.hash_password(payload.new_password)
    await db.execute(
        update(User).where(User.id == user.id).values(
            password_hash=new_hash,
            password_reset_token=None,
            password_reset_expires=None,
            force_password_change=False,
            refresh_token_version = user.refresh_token_version + 1,
        )
    )
    
    await db.commit()
    await _log_event(db, request, "PASSWORD_RESET_SELF", user_id=user.id, details={"step": "completed"})

    return {"detail": "Password reset successfully"}


# ---------------------------------------------------------------------------
# POST /auth/change-password  (works even when force_password_change=True)
# ---------------------------------------------------------------------------

@router.post("/change-password")
async def change_password(
    request: Request,
    payload: schemas.ChangePasswordRequest,
    db: AsyncSession = Depends(dependencies.get_db),
    token: str = Depends(dependencies.oauth2_scheme),
):
    # Re-use get_current_user but pass the SAME db session to avoid the two-session bug
    user = await dependencies.get_current_user(request=request, token=token, db=db)

    if not security.verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    await db.execute(
        update(User).where(User.id == user.id).values(
            password_hash=security.hash_password(payload.new_password),
            force_password_change=False,
            refresh_token_version = User.refresh_token_version + 1,
        )
    )
    await db.commit()
    await _log_event(db, request, "PASSWORD_RESET_SELF", user_id=user.id)
    return {"detail": "Password updated successfully, login again"}


# ---------------------------------------------------------------------------
# GET /auth/mfa-setup
# ---------------------------------------------------------------------------

@router.get("/mfa-setup", response_model=schemas.SetupMFAResponse)
async def mfa_setup(
    request: Request,
    db: AsyncSession = Depends(dependencies.get_db),
    user: User = Depends(dependencies.require_analyst),
):
    secret = security.generate_totp_secret()
    await db.execute(
        update(User).where(User.id == user.id).values(mfa_secret=secret)
    )
    await db.commit()

    totp = __import__("pyotp").TOTP(secret)
    qr_url = totp.provisioning_uri(name=user.email, issuer_name="SOC Platform")
    return {"secret": secret, "qr_code_url": qr_url}


# ---------------------------------------------------------------------------
# POST /auth/mfa-setup/verify
# ---------------------------------------------------------------------------

@router.post("/mfa-setup/verify")
async def mfa_setup_verify(
    request: Request,
    payload: schemas.VerifyMFASetupRequest,
    db: AsyncSession = Depends(dependencies.get_db),
    user: User = Depends(dependencies.get_current_user),
):
    if not user.mfa_secret:
        raise HTTPException(status_code=400, detail="MFA setup not initiated. Call GET /auth/mfa-setup first.")

    if not security.verify_totp(user.mfa_secret, payload.totp_code):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")

    await db.execute(
        update(User).where(User.id == user.id).values(mfa_enabled=True)
    )
    await db.commit()
    return {"detail": "MFA enabled successfully"}


# ---------------------------------------------------------------------------
# GET /auth/me
# ---------------------------------------------------------------------------

@router.get("/me", response_model=schemas.UserMe)
async def get_me(user: User = Depends(dependencies.get_current_user)):
    return user
