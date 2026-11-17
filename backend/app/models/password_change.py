from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean, Float
from sqlalchemy.orm import relationship
from app.database.base import Base


def utc_now():
    return datetime.now(timezone.utc)


class PasswordChangeTransaction(Base):
    """
    Server-authoritative transaction state for cognitive-verified password changes.
    Tracks session/user/portal binding, sequential cognitive challenge completion,
    single-use replay prevention, expiry, and attempt lockouts.
    Never stores raw passwords, sequence answers, or private security answers.
    """
    __tablename__ = "password_change_transactions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    transaction_id = Column(String(64), unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    session_id = Column(String(64), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    application = Column(String(50), nullable=False, default="platform", index=True)  # shopping, college, healthcare, platform
    status = Column(String(40), nullable=False, default="PENDING_IMAGE", index=True)

    current_password_verified = Column(Boolean, default=True, nullable=False)
    risk_level_at_init = Column(String(20), nullable=False, default="LOW")
    risk_score_at_init = Column(Float, nullable=False, default=0.0)
    bound_stepup_challenge_id = Column(String(64), nullable=True)

    image_challenge_id = Column(String(64), unique=True, index=True, nullable=False)
    image_verified = Column(Boolean, default=False, nullable=False)
    image_verified_at = Column(DateTime(timezone=True), nullable=True)

    private_challenge_id = Column(String(64), unique=True, index=True, nullable=False)
    private_verified = Column(Boolean, default=False, nullable=False)
    private_verified_at = Column(DateTime(timezone=True), nullable=True)

    attempts = Column(Integer, default=0, nullable=False)
    max_attempts = Column(Integer, default=2, nullable=False)
    image_attempts = Column(Integer, default=0, nullable=False)
    image_max_attempts = Column(Integer, default=2, nullable=False)
    private_attempts = Column(Integer, default=0, nullable=False)
    private_max_attempts = Column(Integer, default=2, nullable=False)
    is_consumed = Column(Boolean, default=False, nullable=False)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    user = relationship("User", backref="password_change_transactions")
    session = relationship("Session", backref="password_change_transactions")

