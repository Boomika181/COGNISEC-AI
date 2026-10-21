from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, UniqueConstraint
from sqlalchemy.orm import relationship
from app.database.base import Base


def utc_now():
    return datetime.now(timezone.utc)


class AdaptiveFactor(Base):
    """
    Cryptographically protected Multi-Factor Authentication factor enrollment.
    Stores salted, hashed verifiers (bcrypt) for:
    - GESTURE_PATTERN (3x3 grid sequence)
    - COGNITIVE_IMAGE_SEQUENCE (ordered symbols from catalogue)
    - PRIVATE_RESPONSE (custom security question/answer)
    Never stores raw patterns, secret answers, or plaintext inputs.
    """
    __tablename__ = "adaptive_factors"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    factor_type = Column(String(50), nullable=False, index=True)  # "GESTURE_PATTERN", "COGNITIVE_IMAGE_SEQUENCE", "PRIVATE_RESPONSE"
    verifier_hash = Column(String(255), nullable=False)           # Salted bcrypt hash of canonical representation
    metadata_json = Column(Text, nullable=True)                   # Non-sensitive metadata (e.g. question prompt)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_used_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint("user_id", "factor_type", name="uq_user_factor_type"),
    )

    # Relationships
    user = relationship("User", back_populates="adaptive_factors")
