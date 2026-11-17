from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text, UniqueConstraint
from sqlalchemy.orm import relationship
from app.database.base import Base


def utc_now():
    return datetime.now(timezone.utc)


class BehaviorLog(Base):
    __tablename__ = "behavior_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    session_id = Column(String(64), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    application = Column(String(50), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Passive Behavioral Biometric Features
    typing_speed_wpm = Column(Float, default=0.0, nullable=False)
    avg_flight_time_ms = Column(Float, default=0.0, nullable=False)
    avg_dwell_time_ms = Column(Float, default=0.0, nullable=False)
    mouse_velocity_avg = Column(Float, default=0.0, nullable=False)
    mouse_acceleration_avg = Column(Float, default=0.0, nullable=False)
    mouse_curvature_entropy = Column(Float, default=0.0, nullable=False)
    click_frequency = Column(Float, default=0.0, nullable=False)
    scroll_speed_avg = Column(Float, default=0.0, nullable=False)
    idle_duration_sec = Column(Float, default=0.0, nullable=False)
    navigation_entropy = Column(Float, default=0.0, nullable=False)

    # Structured features in JSON string (privacy-safe, NO password/sensitive content)
    raw_feature_json = Column(Text, nullable=True)

    # Relationships
    user = relationship("User", back_populates="behavior_logs")
    session = relationship("Session", back_populates="behavior_logs")


class BehaviorProfile(Base):
    __tablename__ = "behavior_profiles"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    sample_count = Column(Integer, default=0, nullable=False)
    profile_version = Column(Integer, default=1, nullable=False)
    last_updated = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    # Baseline Feature Averages & Standard Deviations (Stored as JSON string)
    baseline_features = Column(Text, nullable=True)

    # Relationships
    user = relationship("User", back_populates="behavior_profile")


class BehavioralTrainingEvent(Base):
    """
    Durable, database-backed behavioral ML training-event ledger.
    Enforces a strict state machine (PENDING -> ELIGIBLE -> PROCESSED, or REJECTED)
    and database-level uniqueness on event_id across retries, restarts, and workers.
    """
    __tablename__ = "behavioral_training_events"
    __table_args__ = (
        UniqueConstraint("event_id", name="uq_behavioral_training_events_event_id"),
    )

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    event_id = Column(String(128), nullable=False, unique=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    session_id = Column(String(64), nullable=True, index=True)
    behavior_log_id = Column(Integer, ForeignKey("behavior_logs.id", ondelete="SET NULL"), nullable=True, index=True)
    lifecycle_state = Column(String(32), default="PENDING", nullable=False, index=True)
    eligibility_status = Column(String(32), default="PENDING", nullable=False)
    is_trusted = Column(Integer, default=0, nullable=False, index=True)
    profile_version = Column(Integer, nullable=True, index=True)
    raw_vector_json = Column(Text, nullable=False)
    training_vector_json = Column(Text, nullable=True)
    observed_features_json = Column(Text, nullable=True)
    rejection_reason = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)
