"""
Payments router — /payments/*

POST /payments/initiate        superadmin only
POST /payments/callback        PUBLIC — Daraja posts here after STK completes
GET  /payments/{client_id}/history   superadmin only
"""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.dependencies import get_db, require_superadmin
from app.core.audit import log_action
from app.models.user import User
from app.models.client import Client
from app.models.payment import Payment
from app.schemas.payments import InitiatePaymentRequest, PaymentResponse, DarajaCallbackBody
from app.services.daraja import daraja_service, _normalise_phone

router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_daraja_transaction_date(value) -> datetime | None:
    """
    Daraja sends TransactionDate as an integer YYYYMMDDHHmmss.
    Parse it into a timezone-aware UTC datetime.
    """
    try:
        s = str(int(value))
        # Format: 20260518120000
        dt = datetime.strptime(s, "%Y%m%d%H%M%S")
        # Daraja timestamps are EAT (UTC+3); store as UTC
        from datetime import timedelta
        dt_utc = dt - timedelta(hours=3)
        return dt_utc.replace(tzinfo=timezone.utc)
    except Exception:
        return None


async def _build_payment_response(db: AsyncSession, payment: Payment) -> PaymentResponse:
    """Fetch client name and build a PaymentResponse."""
    client_result = await db.execute(select(Client).where(Client.id == payment.client_id))
    client = client_result.scalar_one_or_none()
    client_name = client.name if client else f"client_{payment.client_id}"

    return PaymentResponse(
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
    )


# ---------------------------------------------------------------------------
# POST /payments/initiate
# ---------------------------------------------------------------------------

@router.post("/initiate")
async def initiate_payment(
    request: Request,
    body: InitiatePaymentRequest,
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    """
    Superadmin triggers an M-Pesa STK Push to a client's phone number.
    A pending Payment row is written before the Daraja call so we always
    have a record even if the callback never arrives.
    """
    # Validate client exists
    client_result = await db.execute(select(Client).where(Client.id == body.client_id))
    client = client_result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    # Normalise phone — raise 400 on bad format
    try:
        normalised_phone = _normalise_phone(body.phone_number)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Validate payment_type
    if body.payment_type not in ("subscription", "onboarding"):
        raise HTTPException(
            status_code=400,
            detail="payment_type must be 'subscription' or 'onboarding'"
        )

    # Initiate STK Push via Daraja
    try:
        daraja_resp = await daraja_service.stk_push(
            phone=normalised_phone,
            amount=body.amount,
            client_id=body.client_id,
            payment_type=body.payment_type,
            account_ref=client.name[:12],  # Daraja limits AccountReference to 12 chars
        )
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Daraja STK Push failed: {exc}"
        )

    # Persist pending payment row
    payment = Payment(
        client_id=body.client_id,
        phone_number=normalised_phone,
        amount=body.amount,
        checkout_request_id=daraja_resp["checkout_request_id"],
        merchant_request_id=daraja_resp["merchant_request_id"],
        status="pending",
        payment_type=body.payment_type,
        period_covered_start=body.period_start,
        period_covered_end=body.period_end,
    )
    db.add(payment)
    await db.flush()

    await log_action(
        db=db,
        request=request,
        event_type="PAYMENT_RECEIVED",
        user_id=current_user.id,
        client_id=body.client_id,
        target_id=payment.id,
        details={
            "stage": "initiated",
            "phone": normalised_phone,
            "amount": body.amount,
            "payment_type": body.payment_type,
            "checkout_request_id": daraja_resp["checkout_request_id"],
        },
        flush_only=True,
    )
    await db.commit()

    return {
        "checkout_request_id": daraja_resp["checkout_request_id"],
        "message": (
            f"STK Push sent to {normalised_phone}. "
            "Ask the client to enter their M-Pesa PIN."
        ),
    }


# ---------------------------------------------------------------------------
# POST /payments/callback  — PUBLIC, no JWT
# ---------------------------------------------------------------------------

@router.post("/callback")
async def daraja_callback(
    request: Request,
    body: DarajaCallbackBody,
    db: AsyncSession = Depends(get_db),
):
    """
    Daraja posts here when an STK Push transaction completes or fails.
    We ALWAYS return HTTP 200 — Daraja retries on any non-200 response.
    Internal errors are logged and swallowed.
    """
    try:
        stk = body.Body.get("stkCallback", {})
        checkout_request_id = stk.get("CheckoutRequestID")
        merchant_request_id = stk.get("MerchantRequestID")
        result_code = stk.get("ResultCode")
        result_desc = stk.get("ResultDesc", "")

        if not checkout_request_id:
            print(f"DARAJA CALLBACK: missing CheckoutRequestID — body={body.Body}")
            return {"ResultCode": 0, "ResultDesc": "Accepted"}

        # Locate the pending payment row
        result = await db.execute(
            select(Payment).where(Payment.checkout_request_id == checkout_request_id)
        )
        payment = result.scalar_one_or_none()

        if not payment:
            print(
                f"DARAJA CALLBACK: unknown CheckoutRequestID {checkout_request_id!r} — ignoring"
            )
            return {"ResultCode": 0, "ResultDesc": "Accepted"}

        now_utc = datetime.now(timezone.utc)

        if result_code == 0:
            # ---- Success path ----
            # Extract metadata from CallbackMetadata Items
            items = stk.get("CallbackMetadata", {}).get("Item", [])
            meta = {item["Name"]: item.get("Value") for item in items}

            receipt = meta.get("MpesaReceiptNumber")
            amount = meta.get("Amount")
            txn_date = _parse_daraja_transaction_date(meta.get("TransactionDate"))

            payment.status = "completed"
            payment.mpesa_receipt_number = receipt
            payment.amount = amount
            payment.completed_at = txn_date or now_utc
            payment.callback_received_at = now_utc

            # If it's a subscription payment, activate the client
            if payment.payment_type == "subscription":
                client_result = await db.execute(
                    select(Client).where(Client.id == payment.client_id)
                )
                client = client_result.scalar_one_or_none()
                if client:
                    client.subscription_status = "active"

            await log_action(
                db=db,
                request=request,
                event_type="PAYMENT_RECEIVED",
                client_id=payment.client_id,
                target_id=payment.id,
                details={
                    "stage": "completed",
                    "receipt": receipt,
                    "amount": str(amount),
                    "checkout_request_id": checkout_request_id,
                },
                flush_only=True,
            )

        else:
            # ---- Failure path ----
            payment.status = "failed"
            payment.callback_received_at = now_utc

            await log_action(
                db=db,
                request=request,
                event_type="PAYMENT_RECEIVED",
                client_id=payment.client_id,
                target_id=payment.id,
                details={
                    "stage": "failed",
                    "result_code": result_code,
                    "result_desc": result_desc,
                    "checkout_request_id": checkout_request_id,
                },
                flush_only=True,
            )

        await db.commit()

    except Exception as exc:
        # Never let an internal error return non-200 — Daraja would retry endlessly
        print(f"DARAJA CALLBACK ERROR: {exc}")
        try:
            await db.rollback()
        except Exception:
            pass

    # Daraja expects this exact shape on success
    return {"ResultCode": 0, "ResultDesc": "Accepted"}


# ---------------------------------------------------------------------------
# GET /payments/{client_id}/history
# ---------------------------------------------------------------------------

@router.get("/{client_id}/history", response_model=list[PaymentResponse])
async def get_payment_history(
    client_id: int,
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    """Return all payments for a specific client, newest first."""
    # Verify client exists
    client_result = await db.execute(select(Client).where(Client.id == client_id))
    client = client_result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    result = await db.execute(
        select(Payment)
        .where(Payment.client_id == client_id)
        .order_by(Payment.initiated_at.desc())
    )
    payments = result.scalars().all()

    return [
        await _build_payment_response(db, p) for p in payments
    ]
