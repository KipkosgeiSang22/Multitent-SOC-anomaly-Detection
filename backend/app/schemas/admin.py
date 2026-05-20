from datetime import datetime
from typing import Optional, List, Any
from pydantic import BaseModel, EmailStr, ConfigDict, field_validator


# ---------------------------------------------------------------------------
# USER MANAGEMENT
# ---------------------------------------------------------------------------

class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str
    role: str
    client_id: Optional[int]
    is_active: bool
    mfa_enabled: bool
    force_password_change: bool
    last_login: Optional[datetime]
    created_at: Optional[datetime] = None
    locked_until: Optional[datetime]


class CreateAnalystRequest(BaseModel):
    username: str
    email: EmailStr
    password: str

    @field_validator("username")
    @classmethod
    def username_length(cls, v: str) -> str:
        if not (3 <= len(v) <= 50):
            raise ValueError("username must be 3–50 characters")
        return v

    @field_validator("password")
    @classmethod
    def password_min(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("password must be at least 8 characters")
        return v


class CreateClientUserRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    client_id: int

    @field_validator("username")
    @classmethod
    def username_length(cls, v: str) -> str:
        if not (3 <= len(v) <= 50):
            raise ValueError("username must be 3–50 characters")
        return v

    @field_validator("password")
    @classmethod
    def password_min(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("password must be at least 8 characters")
        return v


class UpdateUserRequest(BaseModel):
    email: Optional[EmailStr] = None
    is_active: Optional[bool] = None
    force_password_change: Optional[bool] = None


# ---------------------------------------------------------------------------
# CLIENT MANAGEMENT
# ---------------------------------------------------------------------------

VALID_SIEM_TYPES = {"graylog", "elastic", "wazuh", "splunk"}


class ClientResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    siem_type: Optional[str]
    siem_base_url: Optional[str]
    subscription_plan: Optional[str]
    subscription_status: Optional[str]
    anomaly_visibility_enabled: bool = False
    active: bool
    created_at: Optional[datetime] = None


class CreateClientRequest(BaseModel):
    name: str
    siem_type: str
    siem_base_url: Optional[str] = None
    siem_credentials: Optional[dict] = None
    subscription_plan: Optional[str] = None
    subscription_status: str = "trial"

    @field_validator("name")
    @classmethod
    def name_min(cls, v: str) -> str:
        if len(v) < 2:
            raise ValueError("name must be at least 2 characters")
        return v

    @field_validator("siem_type")
    @classmethod
    def siem_type_valid(cls, v: str) -> str:
        if v not in VALID_SIEM_TYPES:
            raise ValueError(f"siem_type must be one of: {', '.join(VALID_SIEM_TYPES)}")
        return v


class UpdateClientRequest(BaseModel):
    name: Optional[str] = None
    siem_type: Optional[str] = None
    siem_base_url: Optional[str] = None
    siem_credentials: Optional[dict] = None
    subscription_plan: Optional[str] = None
    subscription_status: Optional[str] = None
    active: Optional[bool] = None

    @field_validator("siem_type")
    @classmethod
    def siem_type_valid(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in VALID_SIEM_TYPES:
            raise ValueError(f"siem_type must be one of: {', '.join(VALID_SIEM_TYPES)}")
        return v


# ---------------------------------------------------------------------------
# CLIENT QUERY MANAGEMENT
# ---------------------------------------------------------------------------

VALID_ML_CATEGORIES = {
    "AuthenticationEvents",
    "AccountManagementEvents",
    "ProcessCreationEvents",
}


class ClientQueryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    client_id: int
    query_name: str
    graylog_query: str
    is_ml_category: bool
    ml_category: Optional[str]
    enabled: bool
    display_order: int
    created_at: Optional[datetime] = None


class CreateQueryRequest(BaseModel):
    client_id: int
    query_name: str
    graylog_query: str
    is_ml_category: bool = False
    ml_category: Optional[str] = None
    display_order: int = 0

    @field_validator("ml_category")
    @classmethod
    def ml_category_valid(cls, v: Optional[str], info) -> Optional[str]:
        # Validation that ml_category is required when is_ml_category=True
        # is enforced in the router (Pydantic v2 model_validator would need
        # access to other fields which requires @model_validator)
        if v is not None and v not in VALID_ML_CATEGORIES:
            raise ValueError(
                f"ml_category must be one of: {', '.join(VALID_ML_CATEGORIES)}"
            )
        return v


class UpdateQueryRequest(BaseModel):
    query_name: Optional[str] = None
    graylog_query: Optional[str] = None
    enabled: Optional[bool] = None
    display_order: Optional[int] = None


# ---------------------------------------------------------------------------
# PERMISSION MANAGEMENT
# ---------------------------------------------------------------------------

class PermissionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    analyst_id: int
    analyst_username: str  # joined field — populated manually in router
    granted_by: int
    granted_by_username: str  # joined field — populated manually in router
    can_retrain_models: bool
    can_edit_layer1_rules: bool
    can_manage_graylog: bool
    client_scope: Any  # JSONB list
    granted_at: datetime
    revoked_at: Optional[datetime]
    reason: str


class GrantPermissionRequest(BaseModel):
    analyst_id: int
    can_retrain_models: bool = False
    can_edit_layer1_rules: bool = False
    can_manage_graylog: bool = False
    client_scope: List[Any] = ["ALL"]
    reason: str

    @field_validator("reason")
    @classmethod
    def reason_min(cls, v: str) -> str:
        if len(v) < 5:
            raise ValueError("reason must be at least 5 characters")
        return v


# ---------------------------------------------------------------------------
# ANOMALY VISIBILITY
# ---------------------------------------------------------------------------

class ToggleVisibilityRequest(BaseModel):
    client_id: int
    visible: bool


class VisibilityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    client_id: int
    client_name: str  # joined — populated in router
    visible: bool
    toggled_by: Optional[int]
    toggled_at: Optional[datetime]


# ---------------------------------------------------------------------------
# AUDIT LOG
# ---------------------------------------------------------------------------

class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: Optional[int]
    username: Optional[str]  # joined — populated in router
    role: Optional[str]
    event_type: str
    client_id: Optional[int]
    target_id: Optional[int]
    details: Optional[Any]
    ip_address: Optional[str]
    user_agent: Optional[str]
    performed_at: datetime