from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database.base import Base


def utc_now():
    return datetime.now(timezone.utc)


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    session_id = Column(String(64), ForeignKey("sessions.id", ondelete="SET NULL"), nullable=True, index=True)
    application = Column(String(50), nullable=False, index=True)
    event_type = Column(String(100), nullable=False)  # e.g., "BEHAVIORAL_ANOMALY", "NEW_DEVICE", "POLICY_VIOLATION", "STEP_UP_CHALLENGE"
    severity = Column(String(20), default="LOW", nullable=False, index=True)  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    anomaly_score = Column(Float, default=0.0, nullable=False)
    risk_score = Column(Float, default=0.0, nullable=False)
    decision = Column(String(50), default="ALLOW", nullable=False)  # "ALLOW", "STEP_UP_VERIFICATION", "RESTRICT", "BLOCK", "TERMINATE_SESSION"
    details = Column(Text, nullable=True)  # JSON-encoded contextual details
    timestamp = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)

    # Relationships
    user = relationship("User", back_populates="security_events")
    session = relationship("Session", back_populates="security_events")
    alerts = relationship("Alert", back_populates="security_event", cascade="all, delete-orphan")
