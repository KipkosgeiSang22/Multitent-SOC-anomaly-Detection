from pydantic import BaseModel, EmailStr, ConfigDict
from typing import Optional, List

class LoginRequest(BaseModel):
    username: str
    password: str

class MFARequest(BaseModel):
    temp_token: str
    totp_code: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    mfa_required: bool = False

class LoginResponse(BaseModel):
    mfa_required: bool
    temp_token: Optional[str] = None
    access_token: Optional[str] = None
    token_type: Optional[str] = "bearer"

class RefreshResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

class SetupMFAResponse(BaseModel):
    secret: str
    qr_code_url: str

class VerifyMFASetupRequest(BaseModel):
    totp_code: str

class UserMe(BaseModel):
    id: int
    username: str
    email: str
    role: str
    client_id: Optional[int]
    mfa_enabled: bool
    force_password_change: bool

    model_config = ConfigDict(from_attributes=True)