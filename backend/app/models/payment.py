from sqlalchemy import (
    Column, Integer, String, DateTime, ForeignKey,
    func, Numeric
)
from app.db.base import Base


class Payment(Base):
    __tablename__ = "payments"

    id = Column(Integer, primary_key=True)
    client_id = Column(Integer, ForeignKey("clients.id"), nullable=False)
    phone_number = Column(String, nullable=True)
    amount = Column(Numeric(10, 2), nullable=True)
    mpesa_receipt_number = Column(String, unique=True, nullable=True)
    checkout_request_id = Column(String, unique=True, nullable=True)
    merchant_request_id = Column(String, nullable=True)
    status = Column(String, default="pending")
    payment_type = Column(String, nullable=True)
    period_covered_start = Column(DateTime(timezone=True), nullable=True)
    period_covered_end = Column(DateTime(timezone=True), nullable=True)
    initiated_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
    callback_received_at = Column(DateTime(timezone=True), nullable=True)