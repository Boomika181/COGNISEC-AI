from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from app.database.base import Base


def utc_now():
    return datetime.now(timezone.utc)


class ApplicationGrant(Base):
    """
    Authoritative server-side record of an application-scoped and resource-scoped
    step-up verification grant (e.g., NeuralTrace / GESTURE_PATTERN).
    Enforces that a verification in one demo portal (e.g. College) NEVER satisfies
    confidential access requirements in another portal (e.g. Shopping or Healthcare).
    """
    __tablename__ = "application_grants"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    session_id = Column(String(64), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    application = Column(String(50), nullable=False, index=True)  # "college", "shopping", "healthcare"
    resource = Column(String(50), nullable=False, index=True)     # "academic_vault", "financial_vault", "ehr_vault"
    factor = Column(String(50), nullable=False, default="GESTURE_PATTERN")
    granted_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked = Column(Boolean, default=False, nullable=False)

    # Relationships
    session = relationship("Session", backref="application_grants")
    user = relationship("User", backref="application_grants")
