from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    ForeignKey,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship
from app.database.base import Base


def utc_now():
    return datetime.now(timezone.utc)


class PortalSecurityLock(Base):
    """
    Persistent portal-scoped security lock record created when verification
    failures exceed the portal's authoritative attempt threshold (or security ejection).
    Distinct from full session logout: locks ONLY the affected (user_id, application)
    portal while preserving user identity investigation state and cross-portal isolation.
    Never stores OTP codes, passwords, cognitive answers, or internal risk scores.
    """
    __tablename__ = "portal_security_locks"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    application = Column(String(50), nullable=False, index=True)  # "shopping", "college", "healthcare", "platform"
    lock_reason = Column(String(255), nullable=False)
    verification_purpose = Column(String(64), nullable=False, index=True)  # "LOGIN_OTP", "CONFIDENTIAL_RESOURCE", "PASSWORD_CHANGE", "COGNITIVE_STEP_UP"
    failed_attempt_count = Column(Integer, default=1, nullable=False)
    max_attempts = Column(Integer, default=1, nullable=False)
    challenge_reference = Column(String(128), nullable=True)
    security_reference_id = Column(String(64), unique=True, index=True, nullable=False)
    audit_correlation_id = Column(String(64), index=True, nullable=False)
    session_id = Column(String(64), index=True, nullable=True)
    device_context = Column(Text, nullable=True)  # JSON metadata: device_summary, ip_address, location_summary, device_id

    lock_status = Column(String(32), default="ACTIVE", nullable=False, index=True)  # "ACTIVE", "RECOVERED"
    recovery_status = Column(String(48), default="PENDING_ADMIN_RECOVERY", nullable=False, index=True)
    recovery_otp_verified_at = Column(DateTime(timezone=True), nullable=True)
    unlocked_by = Column(String(120), nullable=True)
    unlocked_by_user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    recovery_notes = Column(String(500), nullable=True)

    locked_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    unlocked_at = Column(DateTime(timezone=True), nullable=True)

    reentry_attempts = Column(Integer, default=0, nullable=False)
    last_reentry_at = Column(DateTime(timezone=True), nullable=True)
    last_reentry_corr_id = Column(String(128), nullable=True)
    last_reentry_notif_at = Column(DateTime(timezone=True), nullable=True)

    user = relationship("User", foreign_keys=[user_id], backref="portal_security_locks")
    unlocked_by_admin = relationship("User", foreign_keys=[unlocked_by_user_id])


class VerificationAttemptCounter(Base):
    """
    Persistent backend-enforced verification attempt counter scoped to
    (user_id, session_id, application, verification_purpose, factor_key).
    Survives browser refreshes, modal reopening, challenge expiry, and repeated challenge requests.
    """
    __tablename__ = "verification_attempt_counters"
    __table_args__ = (
        UniqueConstraint(
            "user_id",
            "session_id",
            "application",
            "verification_purpose",
            "factor_key",
            name="uq_verification_attempt_session_scope",
        ),
    )

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    session_id = Column(String(64), nullable=False, default="", index=True)
    application = Column(String(50), nullable=False, index=True)
    verification_purpose = Column(String(64), nullable=False, index=True)
    factor_key = Column(String(64), nullable=False, index=True)
    attempts = Column(Integer, default=0, nullable=False)
    max_attempts = Column(Integer, default=3, nullable=False)
    last_challenge_id = Column(String(128), nullable=True)
    locked_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    user = relationship("User", backref="verification_attempt_counters")

