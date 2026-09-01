from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.database.base import Base


def utc_now():
    return datetime.now(timezone.utc)


class Session(Base):
    __tablename__ = "sessions"

    id = Column(String(64), primary_key=True, index=True)  # Unique session UUID / token id
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    application = Column(String(50), nullable=False, index=True)  # "college", "ecommerce", "healthcare", "platform"
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="SET NULL"), nullable=True)
    ip_address = Column(String(45), nullable=True)
    login_time = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    logout_time = Column(DateTime(timezone=True), nullable=True)
    status = Column(String(25), default="ACTIVE", nullable=False)  # "ACTIVE", "TERMINATED", "RESTRICTED", "STEP_UP_REQUIRED"
    current_risk_level = Column(String(20), default="LOW", nullable=False)  # "LOW", "MEDIUM", "HIGH", "CRITICAL"

    # Relationships
    user = relationship("User", back_populates="sessions")
    device = relationship("Device", back_populates="sessions")
    behavior_logs = relationship("BehaviorLog", back_populates="session", cascade="all, delete-orphan")
    security_events = relationship("SecurityEvent", back_populates="session")
