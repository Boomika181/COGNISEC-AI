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
        if not clean:
            raise ValueError("Patient name cannot be empty.")
        return clean

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
    patient_phone: str
    patient_email: str
    department: str
    doctor_id: str
    doctor_name: str
    appointment_date: str
    time_slot: str
    consultation_mode: str
    room: Optional[str] = None
    status: str
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
