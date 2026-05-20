from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from app.routers import auth, analyst, client, admin, rules, retrain, graylog, payments, bootstrap_train
from app.core.config import settings
from app.core.middleware import AuditMiddleware
import traceback

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="MSSP SOC Platform")

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(AuditMiddleware)
from fastapi.responses import PlainTextResponse, JSONResponse

@app.exception_handler(Exception)
async def debug_exception_handler(request, exc):
    if settings.ENVIRONMENT == "development":
        return PlainTextResponse(traceback.format_exc(), status_code=500)
    else:
        return JSONResponse({"error": "Internal server error"}, status_code=500)

    
    
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.FRONTEND_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(analyst.router)
app.include_router(client.router)
app.include_router(admin.router)
app.include_router(rules.router, prefix="/rules", tags=["rules"])
app.include_router(retrain.router, prefix="/retrain", tags=["retrain"])
app.include_router(graylog.router, prefix="/graylog", tags=["graylog"])
app.include_router(bootstrap_train.router, prefix="/admin/bootstrap-train", tags=["bootstrap"])
app.include_router(payments.router, prefix="/payments", tags=["payments"])


@app.get("/health")
async def health():
    return {"status": "operational"}
