"""
DarajaService — Safaricom M-Pesa Daraja API integration.
Handles OAuth token caching, STK Push initiation, and status queries.
"""

import base64
import time
import httpx
from datetime import datetime
import pytz

from app.core.config import settings


EAT = pytz.timezone("Africa/Nairobi")


def _normalise_phone(raw: str) -> str:
    """
    Normalise a Kenyan phone number to the 254XXXXXXXXX format Daraja expects.
    Accepts:  0712345678  →  254712345678
              +254712345678 → 254712345678
              254712345678  → 254712345678
    Raises ValueError if the result is not exactly 12 digits.
    """
    phone = raw.strip().replace(" ", "").replace("-", "")
    # Strip leading +
    if phone.startswith("+"):
        phone = phone[1:]
    # Strip leading 0
    if phone.startswith("0"):
        phone = "254" + phone[1:]
    # If it already starts with 254 leave it alone
    if not phone.startswith("254"):
        raise ValueError(f"Non-Kenyan phone number: {raw!r}")
    if len(phone) != 12 or not phone.isdigit():
        raise ValueError(f"Invalid phone number after normalisation: {phone!r}")
    return phone


def _make_password(shortcode: str, passkey: str) -> tuple[str, str]:
    """
    Generate the Daraja STK Push password and timestamp.
    Password = base64(shortcode + passkey + timestamp)
    Timestamp = YYYYMMDDHHmmss in Africa/Nairobi time.
    Returns (password_b64, timestamp_str).
    """
    now_eat = datetime.now(EAT)
    timestamp = now_eat.strftime("%Y%m%d%H%M%S")
    raw = shortcode + passkey + timestamp
    password = base64.b64encode(raw.encode()).decode()
    return password, timestamp


class DarajaService:
    BASE_URL = "https://sandbox.safaricom.co.ke"  # swap to prod URL when ready

    def __init__(self):
        self._token: str | None = None
        self._token_expires_at: float = 0.0  # Unix timestamp

    # ------------------------------------------------------------------
    # OAuth
    # ------------------------------------------------------------------

    async def get_oauth_token(self) -> str:
        """Fetch (and in-memory-cache) the Daraja OAuth bearer token."""
        now = time.monotonic()
        if self._token and now < self._token_expires_at - 60:
            return self._token

        consumer_key = settings.DARAJA_CONSUMER_KEY
        consumer_secret = settings.DARAJA_CONSUMER_SECRET
        credentials = base64.b64encode(
            f"{consumer_key}:{consumer_secret}".encode()
        ).decode()

        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.BASE_URL}/oauth/v1/generate",
                params={"grant_type": "client_credentials"},
                headers={"Authorization": f"Basic {credentials}"},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()

        self._token = data["access_token"]
        expires_in = int(data.get("expires_in", 3600))
        self._token_expires_at = time.monotonic() + expires_in
        return self._token

    # ------------------------------------------------------------------
    # STK Push
    # ------------------------------------------------------------------

    async def stk_push(
        self,
        phone: str,
        amount: int,
        client_id: int,
        payment_type: str,
        account_ref: str,
    ) -> dict:
        """
        Initiate an M-Pesa STK Push (Lipa Na M-Pesa Online).

        Args:
            phone:        Kenyan phone number (any accepted format — normalised here).
            amount:       Amount in KES (whole integer — Daraja requirement).
            client_id:    Internal client DB id (stored on the Payment row).
            payment_type: "subscription" | "onboarding"
            account_ref:  Shown to the customer on their M-Pesa prompt.

        Returns:
            {"checkout_request_id": str, "merchant_request_id": str}
        """
        normalised_phone = _normalise_phone(phone)
        token = await self.get_oauth_token()
        shortcode = settings.DARAJA_SHORTCODE
        passkey = settings.DARAJA_PASSKEY
        password, timestamp = _make_password(shortcode, passkey)

        payload = {
            "BusinessShortCode": shortcode,
            "Password": password,
            "Timestamp": timestamp,
            "TransactionType": "CustomerPayBillOnline",
            "Amount": amount,
            "PartyA": normalised_phone,
            "PartyB": shortcode,
            "PhoneNumber": normalised_phone,
            "CallBackURL": settings.DARAJA_CALLBACK_URL,
            "AccountReference": account_ref,
            "TransactionDesc": f"{payment_type} payment for client {client_id}",
        }

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.BASE_URL}/mpesa/stkpush/v1/processrequest",
                json=payload,
                headers={"Authorization": f"Bearer {token}"},
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()

        # Daraja returns ResponseCode "0" on success
        if data.get("ResponseCode") != "0":
            raise ValueError(
                f"Daraja STK Push failed: {data.get('ResponseDescription', data)}"
            )

        return {
            "checkout_request_id": data["CheckoutRequestID"],
            "merchant_request_id": data["MerchantRequestID"],
            "normalised_phone": normalised_phone,
        }

    # ------------------------------------------------------------------
    # STK Push Status Query
    # ------------------------------------------------------------------

    async def query_status(self, checkout_request_id: str) -> dict:
        """
        Query the current status of an STK Push transaction from Daraja.

        Returns the raw Daraja response dict.
        ResultCode 0 = success; anything else = failure/pending.
        """
        token = await self.get_oauth_token()
        shortcode = settings.DARAJA_SHORTCODE
        passkey = settings.DARAJA_PASSKEY
        password, timestamp = _make_password(shortcode, passkey)

        payload = {
            "BusinessShortCode": shortcode,
            "Password": password,
            "Timestamp": timestamp,
            "CheckoutRequestID": checkout_request_id,
        }

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.BASE_URL}/mpesa/stkpushquery/v1/query",
                json=payload,
                headers={"Authorization": f"Bearer {token}"},
                timeout=15,
            )
            resp.raise_for_status()
            return resp.json()


# Module-level singleton — import this in routers
daraja_service = DarajaService()
