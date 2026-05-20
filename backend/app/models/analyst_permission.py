from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime,
    ForeignKey, func
)
from sqlalchemy.dialects.postgresql import JSONB
from app.db.base import Base


class AnalystPermission(Base):
    __tablename__ = "analyst_permissions"

    id = Column(Integer, primary_key=True)
    analyst_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    granted_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    can_retrain_models = Column(Boolean, default=False)
    can_edit_layer1_rules = Column(Boolean, default=False)
    can_manage_graylog = Column(Boolean, default=False)
    client_scope = Column(JSONB, nullable=False)  # ["ALL"] or [1,3,7]
    granted_at = Column(DateTime(timezone=True), server_default=func.now())
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    reason = Column(String, nullable=False)