import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict


class NotificationActionRequest(BaseModel):
    decision: str  # "yes", "no", "confirm", "deny"


class DeviceNotificationResponse(BaseModel):
    id: int
    notification_id: str
    user_id: int
    device_id: Optional[int] = None
    notification_type: str
    title: str
    message: str
    device_summary: Optional[str] = None
    ip_address: Optional[str] = None
    location_summary: Optional[str] = None
    status: str  # "PENDING_CONFIRMATION", "CONFIRMED_TRUSTED", "CONFIRMED_DENIED", "DEVICE_REVOKED", "READ"
    email_delivery_status: str  # "SENT", "FAILED", "SKIPPED_UNCONFIGURED"
    email_error: Optional[str] = None
    is_read: bool = False
    confirmed_at: Optional[datetime.datetime] = None
    created_at: datetime.datetime

    model_config = ConfigDict(from_attributes=True)


class NotificationListResponse(BaseModel):
    notifications: List[DeviceNotificationResponse]
    unread_count: int
    total_count: int = 0
    total: Optional[int] = None


class NotificationActionResponse(BaseModel):
    status: str
    message: str
    notification_status: str
    device_trust_state: str
