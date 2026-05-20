from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class InitiatePaymentRequest(BaseModel):
    client_id: int
    phone_number: str
    amount: int           # KES whole number — Daraja requires int, no decimals
    payment_type: str     # subscription | onboarding
    period_start: Optional[datetime] = None
    period_end: Optional[datetime] = None


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
    period_covered_start: Optional[datetime]
    period_covered_end: Optional[datetime]
    initiated_at: datetime
    completed_at: Optional[datetime]
    callback_received_at: Optional[datetime]

    model_config = ConfigDict(from_attributes=True)


class DarajaCallbackBody(BaseModel):
    """
    Daraja posts a nested structure. We accept the outer Body as a raw dict
    and unpack it manually in the route handler — this avoids fragility from
    Daraja changing minor field names or adding extras.
    """
    Body: dict
