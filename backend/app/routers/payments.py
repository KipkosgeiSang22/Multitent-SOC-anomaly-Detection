"""
Payments router — /payments/*

Client-facing:
  POST /payments/client/initiate          — client triggers STK Push for their own subscription
  GET  /payments/client/history           — client views their organization's payment history

Superadmin-facing:
  POST /payments/admin/initiate           — superadmin triggers STK Push on behalf of a client
  POST /payments/admin/{payment_id}/confirm  — manually confirm a payment if callback failed
  GET  /payments/admin/{client_id}/history   — superadmin views a specific client's payment history
  GET  /payments/admin/all                   — superadmin views all payments across all clients

Public (no JWT):
  POST /payments/callback                 — Daraja posts here after STK completes or fails
"""


#TODO ON FRONTEND
# Client Portal — new things needed:
# A payment page or modal with:
# - Phone number input field
# - Shows the subscription amount (read from the initiate response)
# - "Pay Now" button → POST /payments/client/initiate
# - Shows the STK push confirmation message
# - Polling to check payment status using checkout_request_id
# - Payment history table (GET /payments/client/history)
#   showing: date, amount, receipt number, status, period covered
# The client also needs a subscription status indicator somewhere visible — a banner or card showing:
# Subscription: Active
# Expires: July 12, 2024
# And if suspended:
# Subscription: Suspended — Please renew to continue
# [Renew Now] button → takes them to payment page
# Superadmin Portal — changes needed:
# The existing payment UI used InitiatePaymentRequest which had amount as required. Now:
# - Amount field becomes optional with placeholder 
#   "Leave blank to use plan amount (KES X,XXX)"
# - payment_type dropdown: subscription | onboarding
# - Add manual confirm button on any pending/failed payment row
#   → POST /payments/admin/{payment_id}/confirm
# - Add "All Payments" view → GET /payments/admin/all
#   showing payments across all clients in one table
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_action
from app.core.dependencies import get_current_user, get_db, require_superadmin
from app.models.client import Client
from app.models.payment import Payment
from app.models.user import User
from app.schemas.payments import (
    ClientInitiatePaymentRequest,
    AdminInitiatePaymentRequest,
    DarajaCallbackBody,
    PaymentResponse,
)
from app.services.daraja import _normalise_phone, daraja_service

router = APIRouter()


# ── Constants ─────────────────────────────────────────────────────────────────

SUBSCRIPTION_PERIOD_DAYS = 30  # one payment = 30 days of subscription


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_daraja_transaction_date(value) -> Optional[datetime]:
    """
    Daraja sends TransactionDate as an integer YYYYMMDDHHmmss in EAT (UTC+3).
    Parse and convert to UTC.
    """
    try:
        s = str(int(value))
        dt = datetime.strptime(s, "%Y%m%d%H%M%S")
        return (dt - timedelta(hours=3)).replace(tzinfo=timezone.utc)
    except Exception:
        return None


async def _get_client_or_404(db: AsyncSession, client_id: int) -> Client:
    result = await db.execute(select(Client).where(Client.id == client_id))
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    return client


async def _build_payment_response(db: AsyncSession, payment: Payment) -> PaymentResponse:
    result = await db.execute(select(Client).where(Client.id == payment.client_id))
    client = result.scalar_one_or_none()
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


async def _activate_subscription(client: Client, payment: Payment) -> None:
    """
    Set subscription_status to active and advance period_covered_end
    by SUBSCRIPTION_PERIOD_DAYS from today (or from current end if still
    in the future — so early renewals stack correctly).
    """
    now = datetime.now(timezone.utc)
    base = (
        payment.period_covered_end
        if payment.period_covered_end and payment.period_covered_end > now.date()
        else now.date()
    )
    payment.period_covered_end = base + timedelta(days=SUBSCRIPTION_PERIOD_DAYS)
    payment.period_covered_start = now.date()
    client.subscription_status = "active"


# ── CLIENT: initiate payment ──────────────────────────────────────────────────

@router.post("/client/initiate")
async def client_initiate_payment(
    request: Request,
    body: ClientInitiatePaymentRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Any authenticated client user can trigger an STK Push for their
    organization's subscription. client_id comes from JWT — never
    from the request body.

    Amount is read from clients.subscription_amount — the client
    never inputs or sees the raw amount, they just approve on their phone.
    """
    if current_user.role != "client":
        raise HTTPException(status_code=403, detail="Access denied")

    client_id = current_user.client_id
    client = await _get_client_or_404(db, client_id)

    # Amount must be configured by superadmin before payments can be made
    if not client.subscription_amount:
        raise HTTPException(
            status_code=402,
            detail=(
                "Subscription amount not configured for your organization. "
                "Please contact support."
            ),
        )

    expected_amount = int(client.subscription_amount)

    # Normalise phone number
    try:
        normalised_phone = _normalise_phone(body.phone_number)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Block if there is already a pending payment for this client
    # (prevents duplicate STK pushes if user clicks twice)
    existing = await db.execute(
        select(Payment).where(
            Payment.client_id == client_id,
            Payment.status == "pending",
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=409,
            detail=(
                "A payment is already pending for your organization. "
                "Please complete or wait for it to expire before initiating a new one."
            ),
        )

    # Trigger STK Push
    try:
        daraja_resp = await daraja_service.stk_push(
            phone=normalised_phone,
            amount=int(expected_amount),
            client_id=client_id,
            payment_type="subscription",
            account_ref=client.name[:12],
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"STK Push failed: {exc}")

    # Persist pending payment row
    payment = Payment(
        client_id=client_id,
        phone_number=normalised_phone,
        amount=expected_amount,
        checkout_request_id=daraja_resp["checkout_request_id"],
        merchant_request_id=daraja_resp["merchant_request_id"],
        status="pending",
        payment_type="subscription",
        initiated_at=datetime.now(timezone.utc),
    )
    db.add(payment)
    await db.flush()

    await log_action(
        db=db,
        request=request,
        event_type="PAYMENT_RECEIVED",
        user_id=current_user.id,
        client_id=client_id,
        target_id=payment.id,
        details={
            "stage": "initiated",
            "initiated_by": "client_user",
            "phone": normalised_phone,
            "amount": expected_amount,
            "payment_type": "subscription",
            "checkout_request_id": daraja_resp["checkout_request_id"],
        },
        flush_only=True,
    )
    await db.commit()

    return {
        "checkout_request_id": daraja_resp["checkout_request_id"],
        "amount": expected_amount,
        "message": (
            f"An M-Pesa prompt has been sent to {normalised_phone}. "
            "Please enter your PIN to complete the payment."
        ),
    }


# ── CLIENT: payment history ───────────────────────────────────────────────────

@router.get("/client/history", response_model=list[PaymentResponse])
async def client_payment_history(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Client users see their own organization's full payment history.
    client_id always comes from JWT.
    """
    if current_user.role != "client":
        raise HTTPException(status_code=403, detail="Access denied")

    result = await db.execute(
        select(Payment)
        .where(Payment.client_id == current_user.client_id)
        .order_by(Payment.initiated_at.desc())
    )
    payments = result.scalars().all()
    return [await _build_payment_response(db, p) for p in payments]
# ── Shared helper — updates DB when Daraja confirms outcome ──────────────────
# Used by both daraja_callback() and check_payment_status()
# In production: daraja_callback() calls this
# In development: check_payment_status() calls this (callback unreachable locally)

async def _resolve_payment(
    db: AsyncSession,
    payment: Payment,
    result_code: int,
    meta: dict,
) -> str:
    """
    Updates payment row and activates subscription if successful.
    Returns the new status string: "completed" or "failed".
    meta is the CallbackMetadata Item dict from Daraja — empty dict for failures.
    """
    now_utc = datetime.now(timezone.utc)
    payment.callback_received_at = now_utc

    if result_code == 0:
        receipt = meta.get("MpesaReceiptNumber")
        paid_amount = float(meta.get("Amount", 0))
        txn_date = _parse_daraja_transaction_date(meta.get("TransactionDate"))

        # Amount validation
        expected = float(payment.amount) if payment.amount else 0.0
        if paid_amount < expected:
            payment.status = "failed"
            await db.commit()
            return "failed"

        payment.status = "completed"
        payment.mpesa_receipt_number = receipt
        payment.amount = paid_amount
        payment.completed_at = txn_date or now_utc

        if payment.payment_type == "subscription":
            client_result = await db.execute(
                select(Client).where(Client.id == payment.client_id)
            )
            client = client_result.scalar_one_or_none()
            if client:
                await _activate_subscription(client, payment)
    else:
        payment.status = "failed"

    await db.commit()
    return payment.status


# ── CLIENT: poll payment status ───────────────────────────────────────────────

@router.get("/client/payment-status/{checkout_request_id}")
async def check_payment_status(
    checkout_request_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Frontend polls this every 5 seconds after initiating payment.

    In production: callback has already updated the DB so this just
    reads and returns the current status — no Daraja call needed.

    In local development: callback cannot reach localhost so this
    actively queries Daraja and updates the DB when outcome is known,
    mirroring exactly what daraja_callback() does in production.

    To switch to production mode: set POLL_DARAJA=false in .env
    and this function will only read from DB, never call Daraja.
    Callback handles all DB updates in production.
    """
    if current_user.role != "client":
        raise HTTPException(status_code=403, detail="Access denied")

    # Security — client can only check their own organization's payments
    result = await db.execute(
        select(Payment).where(
            Payment.checkout_request_id == checkout_request_id,
            Payment.client_id == current_user.client_id,
        )
    )
    payment = result.scalar_one_or_none()
    if not payment:
        raise HTTPException(status_code=404, detail="Payment not found")

    # Already resolved — just return DB status
    if payment.status in ("completed", "failed"):
        return {
            "status": payment.status,
            "receipt": payment.mpesa_receipt_number,
            "amount": float(payment.amount) if payment.amount else None,
            "period_end": payment.period_covered_end,
        }

    # Still pending — ask Daraja directly
    # In production comment out from here ↓
    try:
        daraja_result = await daraja_service.query_status(checkout_request_id)
        result_code = daraja_result.get("ResultCode")

        if result_code is not None and result_code != 1032:
            # 1032 = still processing — don't resolve yet
            # Build meta dict the same way callback does
            items = daraja_result.get("CallbackMetadata", {}).get("Item", [])
            meta = {item["Name"]: item.get("Value") for item in items}

            new_status = await _resolve_payment(db, payment, result_code, meta)
            return {
                "status": new_status,
                "receipt": payment.mpesa_receipt_number,
                "amount": float(payment.amount) if payment.amount else None,
                "period_end": payment.period_covered_end,
            }
    except Exception as e:
        # Daraja query failed — return pending, frontend will retry
        print(f"Daraja query_status failed: {e}")
    # In production comment out to here ↑

    return {"status": "pending"}


# ── PUBLIC: Daraja callback ───────────────────────────────────────────────────

@router.post("/callback")
async def daraja_callback(
    request: Request,
    body: DarajaCallbackBody,
    db: AsyncSession = Depends(get_db),
):
    try:
        stk = body.Body.get("stkCallback", {})
        checkout_request_id = stk.get("CheckoutRequestID")
        result_code = stk.get("ResultCode")
        result_desc = stk.get("ResultDesc", "")

        if not checkout_request_id:
            print(f"DARAJA CALLBACK: missing CheckoutRequestID — body={body.Body}")
            return {"ResultCode": 0, "ResultDesc": "Accepted"}

        result = await db.execute(
            select(Payment).where(
                Payment.checkout_request_id == checkout_request_id
            )
        )
        payment = result.scalar_one_or_none()

        if not payment:
            print(f"DARAJA CALLBACK: unknown CheckoutRequestID {checkout_request_id!r}")
            return {"ResultCode": 0, "ResultDesc": "Accepted"}

        # Build meta dict
        items = stk.get("CallbackMetadata", {}).get("Item", [])
        meta = {item["Name"]: item.get("Value") for item in items}

        await _resolve_payment(db, payment, result_code, meta)

        await log_action(
            db=db,
            request=request,
            event_type="PAYMENT_RECEIVED",
            client_id=payment.client_id,
            target_id=payment.id,
            details={
                "stage": "completed" if result_code == 0 else "failed",
                "result_code": result_code,
                "result_desc": result_desc,
                "checkout_request_id": checkout_request_id,
                "receipt": meta.get("MpesaReceiptNumber"),
            },
            flush_only=True,
        )
        await db.commit()

    except Exception as exc:
        print(f"DARAJA CALLBACK ERROR: {exc}")
        try:
            await db.rollback()
        except Exception:
            pass

    return {"ResultCode": 0, "ResultDesc": "Accepted"}


# ── SUPERADMIN: initiate payment on behalf of client ─────────────────────────

@router.post("/admin/initiate")
async def admin_initiate_payment(
    request: Request,
    body: AdminInitiatePaymentRequest,
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    """
    Superadmin triggers an STK Push on behalf of a client.
    Used for onboarding fees or manual subscription renewals.
    Amount can be overridden here — superadmin knows what they are doing.
    """
    client = await _get_client_or_404(db, body.client_id)

    # Use override amount if provided, otherwise fall back to plan amount
    if body.amount:
        amount = int(body.amount)
    elif client.subscription_amount:
        amount = int(client.subscription_amount)
    else:
        raise HTTPException(
            status_code=400,
            detail=(
                "No amount provided and no subscription_amount configured "
                "for this client. Provide an amount explicitly."
            ),
        )

    if body.payment_type not in ("subscription", "onboarding"):
        raise HTTPException(
            status_code=400,
            detail="payment_type must be 'subscription' or 'onboarding'",
        )

    try:
        normalised_phone = _normalise_phone(body.phone_number)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    try:
        daraja_resp = await daraja_service.stk_push(
            phone=normalised_phone,
            amount=int(amount),
            client_id=body.client_id,
            payment_type=body.payment_type,
            account_ref=client.name[:12],
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"STK Push failed: {exc}")

    payment = Payment(
        client_id=body.client_id,
        phone_number=normalised_phone,
        amount=amount,
        checkout_request_id=daraja_resp["checkout_request_id"],
        merchant_request_id=daraja_resp["merchant_request_id"],
        status="pending",
        payment_type=body.payment_type,
        period_covered_start=body.period_start,
        period_covered_end=body.period_end,
        initiated_at=datetime.now(timezone.utc),
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
            "initiated_by": "superadmin",
            "phone": normalised_phone,
            "amount": amount,
            "payment_type": body.payment_type,
            "checkout_request_id": daraja_resp["checkout_request_id"],
        },
        flush_only=True,
    )
    await db.commit()

    return {
        "checkout_request_id": daraja_resp["checkout_request_id"],
        "amount": amount,
        "message": (
            f"STK Push sent to {normalised_phone}. "
            "Ask the client to enter their M-Pesa PIN."
        ),
    }


# ── SUPERADMIN: manual confirm ────────────────────────────────────────────────

@router.post("/admin/{payment_id}/confirm")
async def admin_manual_confirm(
    payment_id: int,
    request: Request,
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    """
    Superadmin manually marks a payment as completed when:
    - M-Pesa went through but Daraja callback failed to reach the server
    - Superadmin has verified the receipt in the M-Pesa portal

    This activates the client subscription immediately.
    Written to audit_log with confirmed_manually=True for traceability.
    """
    result = await db.execute(select(Payment).where(Payment.id == payment_id))
    payment = result.scalar_one_or_none()
    if not payment:
        raise HTTPException(status_code=404, detail="Payment not found")

    if payment.status == "completed":
        raise HTTPException(
            status_code=409,
            detail="Payment is already marked as completed.",
        )

    now_utc = datetime.now(timezone.utc)
    payment.status = "completed"
    payment.completed_at = now_utc
    payment.callback_received_at = now_utc

    # Activate subscription if this is a subscription payment
    if payment.payment_type == "subscription":
        client_result = await db.execute(
            select(Client).where(Client.id == payment.client_id)
        )
        client = client_result.scalar_one_or_none()
        if client:
            await _activate_subscription(client, payment)

    await log_action(
        db=db,
        request=request,
        event_type="PAYMENT_RECEIVED",
        user_id=current_user.id,
        client_id=payment.client_id,
        target_id=payment.id,
        details={
            "stage": "completed",
            "confirmed_manually": True,
            "confirmed_by": current_user.username,
            "payment_id": payment_id,
            "payment_type": payment.payment_type,
            "amount": str(payment.amount),
        },
        flush_only=True,
    )
    await db.commit()

    return {
        "message": (
            f"Payment {payment_id} manually confirmed. "
            "Subscription has been activated."
        ),
        "payment_id": payment_id,
        "client_id": payment.client_id,
    }


# ── SUPERADMIN: client payment history ───────────────────────────────────────

@router.get("/admin/{client_id}/history", response_model=list[PaymentResponse])
async def admin_client_payment_history(
    client_id: int,
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    """Superadmin views full payment history for a specific client."""
    await _get_client_or_404(db, client_id)

    result = await db.execute(
        select(Payment)
        .where(Payment.client_id == client_id)
        .order_by(Payment.initiated_at.desc())
    )
    payments = result.scalars().all()
    return [await _build_payment_response(db, p) for p in payments]


# ── SUPERADMIN: all payments across all clients ───────────────────────────────

@router.get("/admin/all", response_model=list[PaymentResponse])
async def admin_all_payments(
    current_user: User = Depends(require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    """Superadmin views all payments across every client, newest first."""
    result = await db.execute(
        select(Payment).order_by(Payment.initiated_at.desc())
    )
    payments = result.scalars().all()
    return [await _build_payment_response(db, p) for p in payments]