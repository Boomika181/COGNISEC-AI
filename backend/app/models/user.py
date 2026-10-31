from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.orm import relationship
from app.database.base import Base


def utc_now():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="USER", nullable=False)  # "USER" or "ADMIN"
    account_status = Column(String(20), default="ACTIVE", nullable=False)  # "ACTIVE", "LOCKED", "SUSPENDED"
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Relationships
    devices = relationship("Device", back_populates="user", cascade="all, delete-orphan")
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    behavior_logs = relationship("BehaviorLog", back_populates="user", cascade="all, delete-orphan")
    behavior_profile = relationship("BehaviorProfile", back_populates="user", uselist=False, cascade="all, delete-orphan")
    security_events = relationship("SecurityEvent", back_populates="user", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="user", cascade="all, delete-orphan")
    adaptive_factors = relationship("AdaptiveFactor", back_populates="user", cascade="all, delete-orphan")
    notifications = relationship("DeviceNotification", back_populates="user", cascade="all, delete-orphan")
