from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.database.base import Base


def utc_now():
    return datetime.now(timezone.utc)


class HealthcareAppointment(Base):
    __tablename__ = "healthcare_appointments"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    reference_id = Column(String(32), unique=True, index=True, nullable=False)
    patient_name = Column(String(100), nullable=False)
    patient_age = Column(Integer, nullable=True)
    patient_gender = Column(String(20), nullable=True)
    patient_phone = Column(String(20), nullable=False)
    patient_email = Column(String(255), nullable=False, index=True)
    reason_for_visit = Column(String(500), nullable=True)
    department = Column(String(100), nullable=False)
    doctor_id = Column(String(50), nullable=False, index=True)
    doctor_name = Column(String(100), nullable=False)
    appointment_date = Column(String(20), nullable=False, index=True)  # YYYY-MM-DD
    time_slot = Column(String(20), nullable=False)
    consultation_mode = Column(String(50), nullable=False)  # "In-Person Hospital Visit", "Video Teleconsultation"
    consultation_fee = Column(String(30), nullable=True)
    room = Column(String(50), nullable=True)
    status = Column(String(30), default="CONFIRMED", nullable=False)  # "PENDING_VERIFICATION", "CONFIRMED", "CANCELLED", "FAILED", "EXPIRED"
    otp_challenge_id = Column(String(64), nullable=True, index=True)
    verified_at = Column(DateTime(timezone=True), nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Optional relationship to user
    user = relationship("User", backref="healthcare_appointments", foreign_keys=[user_id])
