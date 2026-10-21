import datetime
from typing import Optional
from pydantic import BaseModel


class SessionStartRequest(BaseModel):
    application: str  # "college", "ecommerce", "healthcare", "platform"
    device_fingerprint: Optional[str] = "unknown"
    browser: Optional[str] = None
    os: Optional[str] = None
    ip_address: Optional[str] = None


class SessionResponse(BaseModel):
    id: str
    user_id: int
    application: str
    device_id: Optional[int]
    ip_address: Optional[str]
    login_time: datetime.datetime
    logout_time: Optional[datetime.datetime]
    status: str
    current_risk_level: str
    step_up_verified_at: Optional[datetime.datetime] = None
    step_up_valid_until: Optional[datetime.datetime] = None
    step_up_factor: Optional[str] = None
    step_up_risk_cleared: Optional[float] = None
    observation_started_at: Optional[datetime.datetime] = None
    observation_ends_at: Optional[datetime.datetime] = None
    observation_completed_at: Optional[datetime.datetime] = None
    login_outcome: Optional[str] = None
    login_otp_challenge_id: Optional[str] = None

    class Config:
        from_attributes = True


class SessionTerminateRequest(BaseModel):
    reason: Optional[str] = "User signed out"
