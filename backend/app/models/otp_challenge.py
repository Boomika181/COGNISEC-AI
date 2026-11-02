from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean, Text
from sqlalchemy.orm import relationship
from app.database.base import Base


def utc_now():
    return datetime.now(timezone.utc)


class OTPChallenge(Base):
    __tablename__ = "otp_challenges"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    challenge_id = Column(String(64), unique=True, index=True, nullable=False)
    session_id = Column(String(64), index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    purpose = Column(String(50), nullable=False, default="APPOINTMENT_OTP", index=True)  # "APPOINTMENT_OTP", "LOGIN_OTP", "PAYMENT_OTP"
    recipient_email = Column(String(255), nullable=False)
    otp_hash = Column(String(128), nullable=False)
    appointment_data = Column(Text, nullable=True)  # JSON-encoded appointment details
    attempts = Column(Integer, default=0, nullable=False)
    max_attempts = Column(Integer, default=3, nullable=False)
    is_consumed = Column(Boolean, default=False, nullable=False)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    cooldown_until = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    user = relationship("User", backref="otp_challenges", foreign_keys=[user_id])

