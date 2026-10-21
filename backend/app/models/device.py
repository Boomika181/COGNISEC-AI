from datetime import datetime, timezone
import secrets
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float, ForeignKey
from sqlalchemy.orm import relationship
from app.database.base import Base


def utc_now():
    return datetime.now(timezone.utc)


def generate_device_id():
    return f"dev_{secrets.token_hex(12)}"


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    device_id = Column(String(64), unique=True, index=True, nullable=False, default=generate_device_id)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    device_fingerprint = Column(String(255), index=True, nullable=False)
    nickname = Column(String(100), nullable=True)  # User-provided nickname e.g. "My MacBook Pro"
    browser = Column(String(500), nullable=True)  # Raw browser summary/UA
    browser_name = Column(String(100), nullable=True)  # e.g. "Chrome"
    browser_version = Column(String(50), nullable=True)  # e.g. "122.0.0.0"
    os = Column(String(500), nullable=True)  # Raw OS string
    os_name = Column(String(100), nullable=True)  # e.g. "macOS"
    os_version = Column(String(50), nullable=True)  # e.g. "14.2"
    device_type = Column(String(50), default="Desktop", nullable=False)  # "Desktop", "Mobile", "Tablet", "Unknown"
    trust_state = Column(String(30), default="PENDING_CONFIRMATION", nullable=False)  # "TRUSTED", "PENDING_CONFIRMATION", "UNKNOWN", "REVOKED"
    is_trusted = Column(Boolean, default=False, nullable=False)  # Kept in sync with trust_state == 'TRUSTED'
    last_ip = Column(String(45), nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    city = Column(String(100), nullable=True)
    region = Column(String(100), nullable=True)
    country = Column(String(100), nullable=True)
    location_source = Column(String(50), default="UNKNOWN", nullable=False)  # "GPS", "IP_APPROXIMATE", "DENIED", "UNAVAILABLE", "UNKNOWN"
    location_accuracy = Column(Float, nullable=True)
    location_updated_at = Column(DateTime(timezone=True), nullable=True)
    first_seen = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_seen = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    # Relationships
    user = relationship("User", back_populates="devices")
    sessions = relationship("Session", back_populates="device")
    notifications = relationship("DeviceNotification", back_populates="device", cascade="all, delete-orphan")
