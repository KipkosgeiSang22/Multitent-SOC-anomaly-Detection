from sqlalchemy import Column, Integer, String, Boolean, DateTime, Numeric, func
from app.db.base import Base


class Client(Base):
    __tablename__ = "clients"

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    siem_type = Column(String, nullable=True)
    siem_base_url = Column(String, nullable=True)
    siem_credentials = Column(String, nullable=True)  # Fernet-encrypted JSON
    subscription_plan = Column(String, nullable=True)
    subscription_status = Column(String, default="trial")
    subscription_amount = Column(Numeric(10, 2), nullable=True)  # e.g. 5000.00
    anomaly_visibility_enabled = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    active = Column(Boolean, default=True)