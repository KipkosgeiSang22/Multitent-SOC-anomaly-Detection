# import base64, time, httpx
# from datetime import datetime
# import pytz
# from app.core.config import settings
# EAT = pytz.timezone("Africa/Nairobi")
# def _normalise_phone(raw:str)->str:
#     phone = raw.strip().replace(" ", "").replace("-", "")
#     if phone.startswith("+"):
#         phone = phone[1:]
#     if phone.startswith("0"):
#         phone = "254"+ phone[1:]
#     if not phone.startswith('254'):
#         pass 
#     if len(phone) != 12 or not phone.isdigit():
#         pass
#     return phone

# def _make_password(shortcode:str, passkey:str)-> tuple[str, str]:
#     now_eat = datetime.now(EAT)
#     timestamp = now_eat.strftime("%Y%m%d%H%M%S")
#     raw = shortcode + passkey +timestamp
#     password = base64.b64encode(raw.encode()).decode()
#     return password, timestamp
# class DrajaService:
#     BASE_URL = "https://sandbox.safaricom.co.ke" 
#     def __init__(self):
#         self._token:str | None = None
#         self._token_expires_at:float = 0.0
#     async def get_oauth_token(self)-> str:
#         now = time.monotonic()
#         if self._token and now < self._token_expires_at - 60:
#             return self._token
#         consumer_key = settings.DARAJA_CONSUMER_KEY
#         consumer_secret = settings.DARAJA_CONSUMER_SECRET
#         credentials = base64.b64encode(
#             f"{consumer_key}:{consumer_secret}".encode()
#         ).decode()
#         async with httpx.AsyncClient() as client:
#             resp = await client.get(
#                 f"{self.BASE_URL}/oauth/v1/generate",
#                 params={"grant-type": "client-credentials"},
#                 headers={"Authorization":f"Basic {credentials}"},
#                 timeout=15,
#             )
#             resp.raise_for_status()
#             data = resp.json()
#         self._token = data["access_token"]
#         expires_in = int(data.get("expires_in", 3600))
#         self._token_expires_at = time.monotonic() + expires_in
#         return self._token
#     async def stk_push(
#             self,
#             phone:str,
#             amount:int,
#             client_id,
#             payment_type: str,
#             account_ref:str,
#     )-> dict:
#         normalised_phone = normalised_phone(phone)
#         token = await self.get_oauth_token
#         shortcode = settings.DARAJA_SHORTCODE
#         passkey = settings.DARAJA_PASSKEY
#         password, timestamp = _make_password(shortcode, passkey)
#         payload = {
#             "BusinessShortCode": shortcode,
#             "Password": password,
#             "Timestamp": timestamp,
#             "TransactionType": "CustomerPayBillOnline",
#             "Amount": amount,
#             "PartyA": normalised_phone,
#             "PartyB": shortcode,
#             "PhoneNumber": normalised_phone,
#             "CallBackURL": settings.DARAJA_CALLBACK_URL,
#             "AccountReference": account_ref,
#             "TransactionDesc": f"{payment_type} payment for client {client_id}",
#         }
#         async with httpx.AsyncClient() as client:
#             resp = await client.post(
#                 f"{self.BASE_URL}/mpesa/stkpush/v1/processrequest",
#                 json=payload,
#                 headers = {"Authorzation": f"Bearer {token}"},
#                 timeout=30,
#             )
#             resp.raise_for_status()
#             data = resp.json()
#         if data.get("ResponseCode") != "0":
#             pass
#         return{
#             "checkout_request_id": data["CheckoutRequestID"],
#             "merchant_request_id": data["MerchantRequestID"],
#             "normalised_phone": normalised_phone,
#         }
    
#     async def query_status(self, checkout_request_id:str) ->dict:
#         toeken = await self.get_oauth_token()
#         short
