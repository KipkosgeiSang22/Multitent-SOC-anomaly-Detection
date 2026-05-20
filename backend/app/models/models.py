"""
SQLAlchemy async ORM models — users and clients tables.
SOC Platform · Multi-Tenant MSSP · Session 3

Place this file at: backend/app/models/models.py
Then add to backend/app/db/base.py:
    from app.models.models import User, Client
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    """Shared declarative base — import this in db/base.py."""
    pass


# ---------------------------------------------------------------------------
# Enums  (stored as plain TEXT in Postgres — avoids ALTER TYPE migrations)
# ---------------------------------------------------------------------------

class RoleEnum(str, enum.Enum):
    superadmin = "superadmin"
    analyst    = "analyst"
    client     = "client"


class SiemTypeEnum(str, enum.Enum):
    graylog  = "graylog"
    elastic  = "elastic"
    wazuh    = "wazuh"
    splunk   = "splunk"


class SubscriptionStatusEnum(str, enum.Enum):
    active    = "active"
    suspended = "suspended"
    trial     = "trial"


# ---------------------------------------------------------------------------
# TABLE: clients
# (declared before users so the FK on users.client_id resolves cleanly)
# ---------------------------------------------------------------------------

class Client(Base):
    """
    One row per managed organisation (bank, SACCO, company, …).
    Adding a new client = one INSERT here — zero schema changes.
    """

    __tablename__ = "clients"

    # ------------------------------------------------------------------
    # Primary key
    # ------------------------------------------------------------------
    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Surrogate PK — also used as the filesystem folder name for ML models.",
    )

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------
    name: Mapped[str] = mapped_column(
        String,
        nullable=False,
        unique=True,
        comment="Human-readable client name, e.g. 'Equity Bank'.",
    )

    # ------------------------------------------------------------------
    # SIEM integration
    # ------------------------------------------------------------------
    siem_type: Mapped[Optional[str]] = mapped_column(
        String,
        nullable=True,
        comment="Adapter key: graylog | elastic | wazuh | splunk.",
    )
    siem_base_url: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Base URL of the client's SIEM instance.",
    )
    siem_credentials: Mapped[Optional[dict]] = mapped_column(
        JSONB,
        nullable=True,
        comment=(
            "Fernet-encrypted credentials blob. "
            "Encrypt BEFORE writing; decrypt AFTER reading — "
            "never store plaintext here."
        ),
    )

    # ------------------------------------------------------------------
    # Subscription
    # ------------------------------------------------------------------
    subscription_plan: Mapped[Optional[str]] = mapped_column(
        String,
        nullable=True,
        comment="e.g. 'starter', 'professional', 'enterprise'.",
    )
    subscription_status: Mapped[str] = mapped_column(
        String,
        nullable=False,
        default=SubscriptionStatusEnum.trial.value,
        server_default="trial",
        comment="active | suspended | trial.",
    )

    # ------------------------------------------------------------------
    # Feature flags
    # ------------------------------------------------------------------
    anomaly_visibility_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
        comment=(
            "When False, client-role users cannot see the Anomalies page. "
            "Toggled by superadmin only; written to client_anomaly_visibility table too."
        ),
    )
    active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
        comment="Soft-delete flag. Deactivated clients cannot log in.",
    )

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="Row creation timestamp (UTC).",
    )

    # ------------------------------------------------------------------
    # Relationships (back-populated by child models)
    # ------------------------------------------------------------------
    users: Mapped[list["User"]] = relationship(
        "User",
        back_populates="client",
        lazy="select",
    )

    # ------------------------------------------------------------------
    # Repr
    # ------------------------------------------------------------------
    def __repr__(self) -> str:  # pragma: no cover
        return f"<Client id={self.id} name={self.name!r} status={self.subscription_status!r}>"


# ---------------------------------------------------------------------------
# TABLE: users
# ---------------------------------------------------------------------------

class User(Base):
    """
    All three roles (superadmin, analyst, client) share this table.
    client_id is NULL for superadmin and analyst rows.
    client_id is always read from the JWT server-side — never from
    user-supplied request data.
    """

    __tablename__ = "users"

    # ------------------------------------------------------------------
    # Primary key
    # ------------------------------------------------------------------
    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    # ------------------------------------------------------------------
    # Identity & credentials
    # ------------------------------------------------------------------
    username: Mapped[str] = mapped_column(
        String,
        nullable=False,
        unique=True,
        index=True,
        comment="Login handle — uniqueness enforced at DB level.",
    )
    email: Mapped[str] = mapped_column(
        String,
        nullable=False,
        unique=True,
        index=True,
        comment="Used for password-reset emails and temp-password delivery.",
    )
    password_hash: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="bcrypt hash, cost=12. NEVER log or return in API responses.",
    )

    # ------------------------------------------------------------------
    # Role & client association
    # ------------------------------------------------------------------
    role: Mapped[str] = mapped_column(
        String,
        nullable=False,
        comment="superadmin | analyst | client.",
    )
    client_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("clients.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment=(
            "NULL for superadmin and analyst rows. "
            "Populated at INSERT for client-role users. "
            "Embedded in JWT at login — user never supplies this value."
        ),
    )

    # ------------------------------------------------------------------
    # Account state
    # ------------------------------------------------------------------
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
        comment="False = soft-deleted / deactivated. Login blocked.",
    )
    force_password_change: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
        comment=(
            "Set to True by superadmin reset. "
            "User is redirected to /force-change-password on every "
            "request until they set a new password."
        ),
    )

    # ------------------------------------------------------------------
    # MFA  (TOTP — mandatory for analyst and superadmin roles)
    # ------------------------------------------------------------------
    mfa_secret: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment=(
            "Base32-encoded TOTP secret (pyotp). "
            "NULL until MFA is enrolled. "
            "Client-role users never enrol MFA."
        ),
    )
    mfa_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
        comment=(
            "True once the analyst/superadmin has completed TOTP setup "
            "and verified their first OTP code."
        ),
    )

    # ------------------------------------------------------------------
    # Brute-force protection
    # ------------------------------------------------------------------
    failed_login_attempts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
        comment="Incremented on every failed login. Reset to 0 on success.",
    )
    locked_until: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment=(
            "Non-NULL means account is temporarily locked. "
            "Set to NOW() + 15 min after 5 consecutive failures. "
            "Auth endpoint checks this before bcrypt verification."
        ),
    )

    # ------------------------------------------------------------------
    # Timestamps
    # ------------------------------------------------------------------
    last_login: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Written on every successful authentication (after MFA).",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
        comment="Updated automatically on any column change.",
    )

    # ------------------------------------------------------------------
    # Password reset (self-service forgot-password flow)
    # ------------------------------------------------------------------
    password_reset_token: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment=(
            "Hashed single-use token sent via email. "
            "Stored as bcrypt hash — plaintext only exists in the email link. "
            "Invalidated on use or expiry."
        ),
    )
    password_reset_expires: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Token is rejected after this timestamp (30-minute window).",
    )

    # ------------------------------------------------------------------
    # Constraints
    # ------------------------------------------------------------------
    __table_args__ = (
        # A client-role user MUST have a client_id.
        # Enforced in application logic (Pydantic + router) rather than
        # a check constraint because SQLAlchemy async doesn't easily
        # express cross-column conditional checks in DDL.
        # See: POST /admin/client-users router — always sets client_id.
        UniqueConstraint("username", name="uq_users_username"),
        UniqueConstraint("email",    name="uq_users_email"),
    )

    # ------------------------------------------------------------------
    # Relationships
    # ------------------------------------------------------------------
    client: Mapped[Optional["Client"]] = relationship(
        "Client",
        back_populates="users",
        lazy="select",
    )

    # ------------------------------------------------------------------
    # Repr
    # ------------------------------------------------------------------
    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<User id={self.id} username={self.username!r} "
            f"role={self.role!r} active={self.is_active}>"
        )


# ---------------------------------------------------------------------------
# db/base.py — add these lines so Alembic detects both tables
# ---------------------------------------------------------------------------
# from app.models.models import User, Client
#
# Then run:
#   alembic revision --autogenerate -m "add_users_and_clients"
#   alembic upgrade head
# ---------------------------------------------------------------------------

