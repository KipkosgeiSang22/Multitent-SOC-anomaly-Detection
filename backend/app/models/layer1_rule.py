from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime,
    ForeignKey, func
)
from sqlalchemy.dialects.postgresql import JSONB
from app.db.base import Base


class Layer1Rule(Base):
    __tablename__ = "layer1_rules"

    id = Column(Integer, primary_key=True)
    client_id = Column(Integer, ForeignKey("clients.id"), nullable=False)
    rule_name = Column(String, nullable=False)
    description = Column(String, nullable=True)
    category = Column(String, nullable=False)
    conditions = Column(JSONB, nullable=False)
    severity = Column(String, default="medium")
    enabled = Column(Boolean, default=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    updated_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(),
                        onupdate=func.now())