from datetime import datetime, timezone
import secrets
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.database.base import Base


def utc_now():
    return datetime.now(timezone.utc)


def generate_notification_id():
    return f"notif_{secrets.token_hex(12)}"


class DeviceNotification(Base):
    __tablename__ = "device_notifications"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    notification_id = Column(String(64), unique=True, index=True, nullable=False, default=generate_notification_id)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="SET NULL"), nullable=True, index=True)
    notification_type = Column(String(50), default="NEW_DEVICE_LOGIN", nullable=False)  # "NEW_DEVICE_LOGIN", "SUSPICIOUS_LOGIN_FAILED", "DEVICE_REVOKED", "DEVICE_CONFIRMED"
    title = Column(String(255), default="New Login Detected", nullable=False)
    message = Column(Text, nullable=False)
    device_summary = Column(String(255), nullable=True)  # e.g. "Chrome 122 on macOS (Desktop)"
    ip_address = Column(String(45), nullable=True)
    location_summary = Column(String(255), nullable=True)  # e.g. "Bengaluru, IN (GPS)" or "Approximate: California, US (IP)"
    status = Column(String(50), default="PENDING_CONFIRMATION", nullable=False)  # "PENDING_CONFIRMATION", "CONFIRMED_TRUSTED", "CONFIRMED_DENIED", "DEVICE_REVOKED", "READ"
    email_delivery_status = Column(String(50), default="SKIPPED_UNCONFIGURED", nullable=False)  # "SENT", "FAILED", "SKIPPED_UNCONFIGURED"
    email_error = Column(String(500), nullable=True)
    is_read = Column(Boolean, default=False, nullable=False)
    confirmation_token = Column(String(64), nullable=True, index=True)
    confirmed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)

    # Relationships
    user = relationship("User", back_populates="notifications")
    device = relationship("Device", back_populates="notifications")
