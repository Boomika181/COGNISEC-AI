import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class DeviceCreate(BaseModel):
    device_fingerprint: str
    browser: Optional[str] = "Unknown"
    os: Optional[str] = "Unknown"
    device_type: Optional[str] = "Desktop"
    nickname: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    location_accuracy: Optional[float] = None
    location_source: Optional[str] = "UNKNOWN"


class DeviceUpdateNickname(BaseModel):
    nickname: str


class DeviceResponse(BaseModel):
    id: int
    device_id: Optional[str] = None
    user_id: int
    device_fingerprint: str
    nickname: Optional[str] = None
    browser: Optional[str] = None
    browser_name: Optional[str] = None
    browser_version: Optional[str] = None
    os: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    device_type: Optional[str] = "Desktop"
    trust_state: Optional[str] = "PENDING_CONFIRMATION"  # TRUSTED, PENDING_CONFIRMATION, UNKNOWN, REVOKED
    is_trusted: bool = False
    last_ip: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    city: Optional[str] = None
    region: Optional[str] = None
    country: Optional[str] = None
    location_source: Optional[str] = "UNKNOWN"
    location_accuracy: Optional[float] = None
    location_updated_at: Optional[datetime.datetime] = None
    first_seen: datetime.datetime
    last_seen: datetime.datetime
    active_session_count: Optional[int] = 0
    active_session_ids: Optional[list[str]] = []
    user_name: Optional[str] = None
    user_email: Optional[str] = None
    is_active: bool = False
    provenance: str = "HISTORICAL_RECORD"  # "GENUINE_ACTIVE", "KNOWN_TEST", "HISTORICAL_RECORD"
    is_physical_device_confirmed: bool = False
    hardware_evidence_summary: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

