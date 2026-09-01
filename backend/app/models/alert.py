from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database.base import Base


def utc_now():
    return datetime.now(timezone.utc)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    security_event_id = Column(Integer, ForeignKey("security_events.id", ondelete="CASCADE"), nullable=True, index=True)
    application = Column(String(50), nullable=False, index=True)
    alert_type = Column(String(100), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(String(20), default="MEDIUM", nullable=False, index=True)  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    status = Column(String(20), default="OPEN", nullable=False, index=True)  # "OPEN", "ACKNOWLEDGED", "RESOLVED"
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)

    # Relationships
    user = relationship("User", back_populates="alerts")
    security_event = relationship("SecurityEvent", back_populates="alerts")
