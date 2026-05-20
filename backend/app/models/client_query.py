from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime,
    ForeignKey, func, UniqueConstraint
)
from app.db.base import Base


class ClientQuery(Base):
    __tablename__ = "client_queries"

    id = Column(Integer, primary_key=True)
    client_id = Column(Integer, ForeignKey("clients.id"), nullable=False)
    query_name = Column(String, nullable=False)
    graylog_query = Column(String, nullable=False)
    is_ml_category = Column(Boolean, default=False)
    ml_category = Column(String, nullable=True)
    enabled = Column(Boolean, default=True)
    display_order = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint("client_id", "query_name", name="uq_client_query_name"),
    )