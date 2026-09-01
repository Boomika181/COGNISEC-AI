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

    class Config:
        from_attributes = True


class SessionTerminateRequest(BaseModel):
    reason: Optional[str] = "User signed out"
