from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime,
    ForeignKey, func, UniqueConstraint, Index
)
from sqlalchemy.dialects.postgresql import JSONB
from app.db.base import Base


class MLModel(Base):
    __tablename__ = "ml_models"

    id = Column(Integer, primary_key=True)
    client_id = Column(Integer, ForeignKey("clients.id"), nullable=False)
    category = Column(String, nullable=False)
    model_path = Column(String, nullable=False)
    backup_path = Column(String, nullable=False)
    trained_at = Column(DateTime(timezone=True), nullable=True)
    trained_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    training_rows = Column(Integer, nullable=True)
    feature_columns = Column(JSONB, nullable=True)
    excluded_event_ids = Column(JSONB, nullable=True)
    notes = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)

    __table_args__ = (
        Index(
            "ix_ml_models_active",
            "client_id", "category",
            unique=True,
            postgresql_where=Column("is_active").is_(True)
        ),
    )