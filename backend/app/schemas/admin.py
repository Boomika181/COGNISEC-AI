import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel


class AdminMetricsResponse(BaseModel):
    live_sessions_count: int
    trusted_users_count: int
    blocked_sessions_count: int
    total_devices_count: int
    active_alerts_count: int
    anomaly_rate_percent: float


class AlertResponse(BaseModel):
    id: int
    user_id: int
    user_name: Optional[str] = None
    user_email: Optional[str] = None
    security_event_id: Optional[int]
    application: str
    alert_type: str
    message: str
    severity: str
    status: str
    created_at: datetime.datetime

    class Config:
        from_attributes = True


class AlertResolveRequest(BaseModel):
    status: str = "RESOLVED"  # "RESOLVED" or "ACKNOWLEDGED"
    resolution_notes: Optional[str] = None


class SecurityEventResponse(BaseModel):
    id: int
    user_id: int
    user_name: Optional[str] = None
    session_id: Optional[str]
    application: str
    event_type: str
    severity: str
    anomaly_score: float
    risk_score: float
    decision: str
    details: Optional[str] = None
    timestamp: datetime.datetime

    class Config:
        from_attributes = True


class AttackSimulationRequest(BaseModel):
    scenario: str  # "NEW_DEVICE", "ABNORMAL_TYPING", "ABNORMAL_MOUSE", "IMPOSSIBLE_TRAVEL", "CREDENTIAL_MISUSE", "REQUEST_FLOOD", "SESSION_HIJACKING"
    application: Optional[str] = "ecommerce"
    target_user_id: Optional[int] = None
    custom_parameters: Optional[Dict[str, Any]] = None


class AttackSimulationResponse(BaseModel):
    scenario: str
    application: str
    target_user_id: int
    simulated_session_id: str
    anomaly_score: float
    risk_score: float
    risk_level: str
    security_decision: str
    alert_created: bool
    alert_id: Optional[int]
    message: str


class EmailDiagnosticsResponse(BaseModel):
    smtp_enabled: bool
    smtp_host: str
    smtp_port: int
    smtp_tls: bool
    smtp_timeout_seconds: int
    smtp_user_configured: bool
    smtp_password_configured: bool
    sender_configured: bool
    sender_email: str
    delivery_status: str
    app_base_url: str
    exhibition_mode: bool


class EmailTestRequest(BaseModel):
    recipient_email: str


class EmailTestResponse(BaseModel):
    success: bool
    message: str
