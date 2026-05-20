from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


# Import all models here so Alembic can detect them
from app.models import (  # noqa: F401, E402
    user,
    client,
    client_query,
    operational_event,
    event_view,
    auth_event,
    account_event,
    process_event,
    anomaly,
    layer1_rule,
    ml_model,
    analyst_permission,
    scheduler_status,
    audit_log,
    event_issue,
    threat_intel,
    graylog_audit,
    payment,
    client_anomaly_visibility,
)