import re
from typing import Optional, List
from pydantic import BaseModel, EmailStr, field_validator, model_validator


def validate_password_strength(v: str) -> str:
    if not isinstance(v, str):
        raise ValueError("Password must be a valid string.")
    if len(v) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    if not re.search(r"[A-Z]", v):
        raise ValueError("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", v):
        raise ValueError("Password must contain at least one lowercase letter.")
    if not re.search(r"\d", v):
        raise ValueError("Password must contain at least one digit.")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>\-_=+[\]\\/;~`']", v):
        raise ValueError("Password must contain at least one special character.")
    return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    application: Optional[str] = "platform"
    device_fingerprint: Optional[str] = "unknown"
    browser: Optional[str] = None
    os: Optional[str] = None
    device_type: Optional[str] = "Desktop"
    nickname: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    location_accuracy: Optional[float] = None
    location_source: Optional[str] = None
    doctor_required: Optional[bool] = False


class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: Optional[str] = "USER"  # "USER" or "ADMIN"
    gesture_pattern: Optional[List[int]] = None
    confirm_gesture_pattern: Optional[List[int]] = None
    image_sequence: Optional[List[str]] = None
    confirm_image_sequence: Optional[List[str]] = None
    private_question: Optional[str] = None
    private_response: Optional[str] = None
    confirm_private_response: Optional[str] = None
    enrollment_telemetry: Optional[dict] = None

    @field_validator("password")
    @classmethod
    def check_password_strength(cls, v: str) -> str:
        return validate_password_strength(v)


class BootstrapAdminRequest(BaseModel):
    name: str
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def check_password_strength(cls, v: str) -> str:
        return validate_password_strength(v)


import datetime


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    user_id: int
    name: str
    email: str
    session_id: Optional[str] = None
    session_status: Optional[str] = "PENDING_OBSERVATION"
    observation_seconds_remaining: Optional[int] = 60
    is_new_device: bool = False
    device_id: Optional[str] = None
    trust_state: Optional[str] = None


class ObservationStatusResponse(BaseModel):
    session_id: str
    status: str
    observation_seconds_remaining: int
    is_completed: bool
    telemetry_samples_count: int
    observation_started_at: Optional[datetime.datetime] = None


class LoginOtpRequest(BaseModel):
    session_id: str


class LoginOtpResponse(BaseModel):
    challenge_id: str
    session_id: str
    challenge_type: str = "LOGIN_OTP"
    masked_email: str
    expires_in_seconds: int = 300
    message: str
    otp: str = ""


class LoginOtpVerifyRequest(BaseModel):
    session_id: str
    otp_code: str
    challenge_id: Optional[str] = None


class LoginOtpVerifyResponse(BaseModel):
    success: bool
    decision: str = "ALLOW"
    session_status: str = "ACTIVE"
    message: str


class TokenData(BaseModel):
    user_id: Optional[int] = None
    role: Optional[str] = None
    session_id: Optional[str] = None


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetResponse(BaseModel):
    success: bool
    masked_email: str
    message: str
    email_delivered: bool = False
    delivery_status: str = "UNKNOWN"


class PasswordResetResendRequest(BaseModel):
    email: EmailStr


class PasswordResetVerifyRequest(BaseModel):
    email: EmailStr
    otp_code: str
    new_password: str
    confirm_password: Optional[str] = None

    @field_validator("new_password")
    @classmethod
    def check_password_strength(cls, v: str) -> str:
        return validate_password_strength(v)

    @model_validator(mode="after")
    def check_password_match(self) -> "PasswordResetVerifyRequest":
        if self.confirm_password is not None and self.confirm_password != self.new_password:
            raise ValueError("Passwords do not match. Please verify both fields.")
        return self


class PasswordResetVerifyResponse(BaseModel):
    success: bool
    message: str


class RecoverAccountRequest(BaseModel):
    email: EmailStr
    new_password: str

    @field_validator("new_password")
    @classmethod
    def check_password_strength(cls, v: str) -> str:
        return validate_password_strength(v)
