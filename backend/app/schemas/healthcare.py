from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field, field_validator


class DoctorResponse(BaseModel):
    id: str
    name: str
    degrees: str
    dept: str
    dept_label: str
    room: str
    experience: str
    reg: str
    fee: str
    availability: str
    opd_hours: str
    avatar: str
    bio: str
    is_active: bool = True
    available_days: List[str] = []
    available_slots: List[str] = []


class DepartmentResponse(BaseModel):
    id: str
    name: str
    code: str
    icon: str
    description: str
    doctor_count: int


class AppointmentCreateRequest(BaseModel):
    patient_name: str = Field(..., min_length=2, max_length=100)
    patient_phone: str = Field(..., min_length=7, max_length=20)
    patient_email: EmailStr
    department: str = Field(..., min_length=2, max_length=100)
    doctor_id: str = Field(..., min_length=2, max_length=50)
    appointment_date: str = Field(..., min_length=10, max_length=10)  # YYYY-MM-DD
    time_slot: str = Field(..., min_length=2, max_length=30)
    consultation_mode: str = Field(default="In-Person OPD Visit")

    @field_validator("patient_name")
    def validate_name(cls, v: str) -> str:
        clean = v.strip()
        if len(clean) < 2:
            raise ValueError("Patient name must be at least 2 characters.")
        return clean

    @field_validator("patient_phone")
    def validate_phone(cls, v: str) -> str:
        clean = v.strip()
        digits = "".join(ch for ch in clean if ch.isdigit())
        if len(digits) < 7 or len(digits) > 15:
            raise ValueError("Phone number must contain between 7 and 15 digits.")
        return clean

    @field_validator("patient_email")
    def validate_email_lower(cls, v: EmailStr) -> str:
        return str(v).strip().lower()

    @field_validator("appointment_date")
    def validate_date(cls, v: str) -> str:
        clean = v.strip()
        try:
            parsed = datetime.strptime(clean, "%Y-%m-%d").date()
            today = datetime.now().date()
            if parsed < today:
                raise ValueError("Appointment date cannot be in the past.")
        except ValueError as e:
            if "past" in str(e):
                raise e
            raise ValueError("Invalid date format. Expected YYYY-MM-DD.")
        return clean


class AppointmentResponse(BaseModel):
    id: int
    reference_id: str
    patient_name: str
    patient_age: Optional[int] = None
    patient_gender: Optional[str] = None
    patient_phone: str
    patient_email: str
    reason_for_visit: Optional[str] = None
    department: str
    doctor_id: str
    doctor_name: str
    appointment_date: str
    time_slot: str
    consultation_mode: str
    consultation_fee: Optional[str] = None
    room: Optional[str] = None
    status: str
    verified_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True


class DoctorLoginRequest(BaseModel):
    email: EmailStr
    password: str
    device_fingerprint: Optional[str] = None
    browser: Optional[str] = None
    os: Optional[str] = None


class DoctorProfileResponse(BaseModel):
    id: int
    name: str
    email: str
    role: str
    department: str
    license_no: str
    opd_room: str
    session_id: Optional[str] = None
    session_status: Optional[str] = None


class AppointmentOtpRequest(BaseModel):
    session_id: Optional[str] = Field(None, description="Optional active session ID")
    patient_name: str = Field(..., min_length=2, max_length=100)
    patient_age: Optional[int] = Field(None, ge=1, le=110)
    patient_gender: Optional[str] = Field(None, max_length=20)
    patient_phone: str = Field(..., min_length=7, max_length=20)
    patient_email: EmailStr
    reason_for_visit: Optional[str] = Field(None, max_length=500)
    department: str = Field(..., min_length=2, max_length=100)
    doctor_id: str = Field(..., min_length=2, max_length=50)
    doctor_name: Optional[str] = None
    appointment_date: str = Field(..., min_length=10, max_length=10)
    time_slot: str = Field(..., min_length=2, max_length=30)
    consultation_mode: str = Field(default="In-Person Hospital Visit")
    room: Optional[str] = None

    @field_validator("patient_name")
    def validate_otp_patient_name(cls, v: str) -> str:
        clean = v.strip()
        if len(clean) < 2:
            raise ValueError("Patient name must be at least 2 characters.")
        return clean

    @field_validator("patient_phone")
    def validate_otp_patient_phone(cls, v: str) -> str:
        clean = v.strip()
        digits = "".join(ch for ch in clean if ch.isdigit())
        if len(digits) < 7 or len(digits) > 15:
            raise ValueError("Phone number must contain between 7 and 15 digits.")
        return clean

    @field_validator("patient_email")
    def validate_otp_patient_email(cls, v: EmailStr) -> str:
        return str(v).strip().lower()

    @field_validator("time_slot")
    def validate_otp_time_slot(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("Time slot is required.")
        return clean

    @field_validator("appointment_date")
    def validate_otp_appointment_date(cls, v: str) -> str:
        clean = v.strip()
        try:
            parsed = datetime.strptime(clean, "%Y-%m-%d").date()
            today = datetime.now().date()
            if parsed < today:
                raise ValueError("Appointment date cannot be in the past.")
        except ValueError as e:
            if "past" in str(e):
                raise e
            raise ValueError("Invalid date format. Expected YYYY-MM-DD.")
        return clean


class AppointmentOtpResponse(BaseModel):
    challenge_id: str
    challenge_type: str = "HEALTHCARE_APPOINTMENT"
    pending_appointment_id: Optional[int] = None
    pending_reference_id: Optional[str] = None
    delivery_status: str = "SENT"
    masked_email: str
    expires_in_seconds: int = 300
    resend_cooldown_seconds: int = 15
    message: str
    doctor_id: Optional[str] = None
    doctor_name: Optional[str] = None
    department: Optional[str] = None
    consultation_fee: Optional[str] = None
    appointment_date: Optional[str] = None
    time_slot: Optional[str] = None


class AppointmentOtpVerifyRequest(BaseModel):
    session_id: Optional[str] = Field(None, description="Optional active session ID")
    challenge_id: str = Field(..., description="Challenge identifier")
    otp_code: str = Field(..., min_length=6, max_length=6, description="6-digit verification code")


class AppointmentOtpVerifyResponse(BaseModel):
    success: bool = True
    reference_id: str
    status: str = "CONFIRMED"
    message: str
    appointment: AppointmentResponse


class AppointmentOtpResendRequest(BaseModel):
    session_id: Optional[str] = Field(None, description="Optional active session ID")
    challenge_id: str = Field(..., description="Challenge identifier to resend")
