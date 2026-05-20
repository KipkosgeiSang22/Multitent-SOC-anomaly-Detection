import time
import logging
from starlette.middleware.base import  BaseHTTPMiddleware
from fastapi import Request, Response
from app.core.security import decode_token 

logger = logging.getLogger("audit")
class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        user_id = None
        try:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer"):
                token = auth_header[len("Bearer "):].strip()
                payload = decode_token(token)
                user_id = payload.get("sub")
        except Exception as e:
            logger.warning(f"failed to extract user ID: {e}")
        response : Response = await call_next(request)
        duration = time.time() - start_time
        try:
            logger.info(
                f"{request.method} {request.url.path} "
                f"status={response.status_code} "
                f"ip={request.client.host if request.client else 'unknown'} "
                f"user_agent={request.headers.get('user-agent', 'unknown')} " 
                f"user_id={user_id or 'unknown'} "
                f"duration ={duration:.4f}s" 
            )
        except Exception as e:
            logger.error(f"failed to log audit info: {e}")
        return response