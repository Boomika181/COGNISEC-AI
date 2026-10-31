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
    total_users_count: int = 0
    trusted_devices_count: int = 0
    pending_devices_count: int = 0
    revoked_devices_count: int = 0
    high_risk_sessions_count: int = 0
    step_up_count: int = 0
    # Authoritative breakdown fields for transparent data provenance
    active_devices_count: int = 0
    persisted_devices_count: int = 0
    active_users_count: int = 0
    persisted_users_count: int = 0
    known_test_accounts_count: int = 0
    unknown_provenance_accounts_count: int = 0
    seeded_demo_accounts_count: int = 0
    genuine_active_accounts_count: int = 0
    restricted_sessions_count: int = 0
    terminated_sessions_count: int = 0
    revoked_sessions_count: int = 0
    active_enforcements_count: int = 0
    verified_metadata_devices_count: int = 0
    unverified_identity_devices_count: int = 0
    open_alerts_count: int = 0
    reopened_alerts_count: int = 0
    resolved_alerts_count: int = 0
    total_alerts_count: int = 0
    anomaly_rate_observations: int = 0
    anomaly_rate_window: str = "24h"
    anomaly_rate_label: str = "0.0%"


class AdminSessionResponse(BaseModel):
    id: str
    user_id: int
    user_name: Optional[str] = "Unknown"
    user_email: Optional[str] = "unknown@cognisec.ai"
    application: str
    device_id: Optional[int] = None
    device_nickname: Optional[str] = None
    ip_address: Optional[str] = "127.0.0.1"
    login_time: datetime.datetime
    logout_time: Optional[datetime.datetime] = None
    status: str
    current_risk_level: str = "LOW"
    step_up_factor: Optional[str] = None
    login_outcome: Optional[str] = None
    is_simulated: bool = False
    provenance: str = "GENUINE_DEV"  # "GENUINE_DEV", "SIMULATED_TEST", "AUTOMATED_TEST", "HISTORICAL_RECORD"

    class Config:
        from_attributes = True


class AdminUserResponse(BaseModel):
    id: int
    name: str
    email: str
    role: str
    account_status: str
    failed_login_attempts: int = 0
    created_at: datetime.datetime
    active_sessions_count: int = 0
    registered_devices_count: int = 0
    baseline_status: Optional[str] = "COLD_START"
    sample_count: int = 0
    is_active: bool = False
    provenance: str = "UNKNOWN_PROVENANCE"  # "GENUINE_ACTIVE", "SEEDED_DEMO", "KNOWN_TEST", "UNKNOWN_PROVENANCE"

    class Config:
        from_attributes = True


class RiskDistributionResponse(BaseModel):
    low_risk_sessions: int = 0
    medium_risk_sessions: int = 0
    high_risk_sessions: int = 0
    critical_risk_sessions: int = 0
    step_up_verified_count: int = 0
    active_threats_count: int = 0


class AlertResponse(BaseModel):
    id: int
    user_id: int
    user_name: Optional[str] = None
    user_email: Optional[str] = None
    security_event_id: Optional[int] = None
    application: str
    alert_type: str
    message: str
    severity: str
    status: str
    assigned_to: Optional[str] = None
    notes: Optional[str] = None
    resolution_reason: Optional[str] = None
    resolved_at: Optional[datetime.datetime] = None
    resolved_by: Optional[str] = None
    created_at: datetime.datetime
    is_simulated: bool = False
    provenance: str = "HISTORICAL_RECORD"  # "GENUINE_INCIDENT", "SIMULATED_ATTACK", "TEST_ALERT", "HISTORICAL_RECORD"

    class Config:
        from_attributes = True


class AlertResolveRequest(BaseModel):
    status: str = "RESOLVED"  # "OPEN", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "REOPENED"
    assigned_to: Optional[str] = None
    notes: Optional[str] = None
    resolution_reason: Optional[str] = None


class IncidentInvestigationResponse(BaseModel):
    incident_id: int
    alert_id: Optional[int] = None
    security_event_id: Optional[int] = None
    timestamp: datetime.datetime
    severity: str
    status: str
    event_type: str
    application: str
    message: str
    user: Optional[Dict[str, Any]] = None
    device: Optional[Dict[str, Any]] = None
    session: Optional[Dict[str, Any]] = None
    risk_assessment: Dict[str, Any]
    behavioral_signals: Optional[Dict[str, Any]] = None
    step_up_history: List[Dict[str, Any]] = []
    related_timeline: List[Dict[str, Any]] = []
    enforcement_outcome: str
    admin_actions: List[Dict[str, Any]] = []
    investigation_notes: Optional[str] = None
    assigned_to: Optional[str] = None
    resolution_reason: Optional[str] = None


class AuditLogResponse(BaseModel):
    id: int
    operator_email: str
    action: str
    target_resource: str
    timestamp: datetime.datetime
    outcome: str
    reason_or_notes: Optional[str] = None
    correlation_id: Optional[str] = None


class HistoricalAnalyticsResponse(BaseModel):
    time_window: str
    total_auth_attempts: int
    successful_logins: int
    failed_logins: int
    risk_decisions: Dict[str, int]
    step_up_challenges: int
    step_up_verified: int
    step_up_failed: int
    sessions_restricted: int
    sessions_terminated: int
    devices_registered: int
    devices_revoked: int
    alerts_opened: int
    alerts_resolved: int
    activity_timeline: List[Dict[str, Any]] = []


class SystemHealthResponse(BaseModel):
    database_connected: bool
    database_engine: str
    database_latency_ms: float
    last_event_ingested_at: Optional[datetime.datetime] = None
    telemetry_pipeline_status: str
    active_sessions_count: int
    server_timestamp: datetime.datetime


class RescanResponse(BaseModel):
    status: str
    timestamp: datetime.datetime
    evaluated_sessions: int
    evaluated_devices: int
    evaluated_alerts: int
    findings: List[Dict[str, Any]]
    summary: str


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
    is_simulated: bool = False
    provenance: str = "HISTORICAL_RECORD"  # "GENUINE_EVENT", "SIMULATED_EVENT", "TEST_EVENT", "HISTORICAL_RECORD"

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


class DevResetLockoutRequest(BaseModel):
    email: str


class DevResetLockoutResponse(BaseModel):
    success: bool
    message: str
    account_status: str
    failed_login_attempts: int
    target_email: str

