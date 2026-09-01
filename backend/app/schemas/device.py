import datetime
from typing import Optional
from pydantic import BaseModel


class DeviceCreate(BaseModel):
    device_fingerprint: str
    browser: Optional[str] = "Unknown"
    os: Optional[str] = "Unknown"
    device_type: Optional[str] = "Desktop"


class DeviceResponse(BaseModel):
    id: int
    user_id: int
    device_fingerprint: str
    browser: Optional[str]
    os: Optional[str]
    device_type: Optional[str]
    is_trusted: bool
    first_seen: datetime.datetime
    last_seen: datetime.datetime

    class Config:
        from_attributes = True
