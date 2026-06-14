# import secrets
# import hashlib
# import aiosmtplib
# from email.message import EmailMessage
# from datetime import datetime, timezone, timedelta
# from fastapi.security import OAuth2PasswordRequestForm
# from fastapi import APIRouter, Depends, HTTPException, Response, Request, Cookie
# from sqlalchemy.ext.asyncio import AsyncSession
# from sqlalchemy import select, update

# from app.core import security, dependencies
# from app.schemas import auth as schemas
# from app.models.user import User 
# from app.models.audit_log import AuditLog
# from app.models.client import Client
# from app.core.config import settings
# router = APIRouter(prefix="/auth", tags=["Authentication"])
# @router.post("/login", response_model=schemas.LoginResponse)
# async def mfa_verify(
#     request:Request,
#     response:Response,
#     payload:schemas.MFARequest,
#     db:AsyncSession=Depends(dependencies.get_db)
# ):
#     data=security.decode_token(payload.temp_token)
#     user_id = int(data["sub"])
#     result = await db.execute(select(User).where(User.id==user_id))
#     user = result.scalar_one_or_none()
#     if result.mfa_locked_until and result.mfa_locked_until > datetime.now(timezone.utc):
#         pass
#     if not security.verify_totp(user.mfa_secret, payload.totp_code):
#         new_attempts = user.mfa_failed_attempts + 1
#         lock_until = datetime.now(timezone.utc) + timedelta(minutes=15) if new_attempts> 5 else None
#         await db.execute(select(User).where(User.id == user.id).values(
#             mfa_failed_attemps = new_attempts, mfa_locked_until = lock_until
#         ))
#         await db.commit()
#         raise HTTPException(status_code=401, detail="Invalid MFA code")
#     access_token = security.create_access_token(
#         {"sub":user.id, "role":user.role, "client_id": user.client_id}
#     )
#     refresh_token = security.create_refresh_token({"sub":str(user.id), "version":user.refresh_token_version})
#     response.set_cookie(
#         key="refresh token", value=refresh_token
#     )
#     event = f"{user.role.upper()}"
#     return {"access_token": access_token,"token_type":"bearer"}
# @router.post("/refresh", response_model=schemas.RefreshResponse)
# async def refresh(
#     request:Request,
#     response:Response,
#     refresh_token: str = Cookie(default=None),
#     db:AsyncSession=Depends(dependencies.get_db)
# ):
#     if not refresh_token:
#         raise HTTPException(status_code=401, detail="No refresh token")
#     data = security.decode_token(refresh_token)
#     new_access = security.create_access_token({"sub": str(user.id), "role":user.role, "client_id":user.client_id})
#     new_refresh = security.create_refresh_token({"sub":str(user.id), "version":user.refresh_token_version})
#     response.set_cookie(
#         key="refresh_token", value=new_refresh,
#         httponl
#     )