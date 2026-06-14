from datetime import date, datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, field_validator


# ── Client-facing ─────────────────────────────────────────────────────────────

class ClientInitiatePaymentRequest(BaseModel):
    """
    Client user initiates their own subscription payment.
    Only needs a phone number — amount comes from clients.subscription_amount,
    payment_type is always 'subscription', client_id comes from JWT.
    """
    phone_number: str


# ── Superadmin-facing ─────────────────────────────────────────────────────────

class AdminInitiatePaymentRequest(BaseModel):
    """
    Superadmin triggers an STK Push on behalf of a client.
    Amount is optional — if not provided, falls back to clients.subscription_amount.
    Superadmin can override amount for onboarding fees or manual renewals.
    """
    client_id: int
    phone_number: str
    amount: Optional[int] = None      # KES whole number — Daraja requires int, no decimals
                                      # if None, system reads from clients.subscription_amount
    payment_type: str                 # subscription | onboarding
    period_start: Optional[date] = None
    period_end: Optional[date] = None

    @field_validator("payment_type")
    @classmethod
    def validate_payment_type(cls, v: str) -> str:
        if v not in ("subscription", "onboarding"):
            raise ValueError("payment_type must be 'subscription' or 'onboarding'")
        return v

    @field_validator("amount")
    @classmethod
    def validate_amount(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and v <= 0:
            raise ValueError("amount must be a positive integer")
        return v


# ── Shared response ───────────────────────────────────────────────────────────

class PaymentResponse(BaseModel):
    id: int
    client_id: int
    client_name: str
    phone_number: Optional[str]
    amount: Optional[float]
    mpesa_receipt_number: Optional[str]
    checkout_request_id: Optional[str]
    status: str
    payment_type: Optional[str]
    period_covered_start: Optional[date]
    period_covered_end: Optional[date]
    initiated_at: datetime
    completed_at: Optional[datetime]
    callback_received_at: Optional[datetime]

    model_config = ConfigDict(from_attributes=True)


# ── Daraja callback ───────────────────────────────────────────────────────────

class DarajaCallbackBody(BaseModel):
    """
    Daraja posts a nested structure. We accept the outer Body as a raw dict
    and unpack it manually in the route handler — this avoids fragility from
    Daraja changing minor field names or adding extras.
    """
    Body: dict