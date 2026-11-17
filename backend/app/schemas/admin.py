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
    suspended_accounts_count: int = 0
    untrusted_devices_count: int = 0
    pending_recovery_count: int = 0
    # Genuine human vs admin/test/demo user separation
    registered_users_count: int = 0
    email_verified_users_count: int = 0
    admin_accounts_count: int = 0
    test_and_demo_accounts_count: int = 0
    unverified_provenance_accounts_count: int = 0
    logged_in_users_count: int = 0
    scope: str = "all"


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
    last_activity: Optional[datetime.datetime] = None
    browser_os: Optional[str] = None
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
    last_login: Optional[datetime.datetime] = None
    total_sessions_count: int = 0
    last_risk_level: Optional[str] = None
    last_risk_score: Optional[float] = None
    is_test_account: bool = False
    email_verified: bool = False
    email_verified_at: Optional[datetime.datetime] = None
    registration_source: Optional[str] = None
    portal_activity: Optional[str] = None
    last_device_name: Optional[str] = None
    last_device_type: Optional[str] = None
    last_location: Optional[str] = None

    class Config:
        from_attributes = True


class AdminUserDirectoryResponse(BaseModel):
    items: List[AdminUserResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


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
    incident_category: Optional[str] = None
    timestamp: datetime.datetime
    updated_at: Optional[datetime.datetime] = None
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
    step_up_challenges: List[Dict[str, Any]] = []
    related_timeline: List[Dict[str, Any]] = []
    enforcement_outcome: str
    admin_actions: List[Dict[str, Any]] = []
    investigation_notes: Optional[str] = None
    notes: Optional[str] = None
    assigned_to: Optional[str] = None
    resolution_reason: Optional[str] = None
    containment_status: Optional[str] = None
    containment_actions: List[str] = []
    ai_analysis: Optional[Dict[str, Any]] = None
    resolved_at: Optional[datetime.datetime] = None
    resolved_by: Optional[str] = None


class AuditLogResponse(BaseModel):
    id: int
    operator_email: str
    action: str
    target_resource: str
    timestamp: datetime.datetime
    outcome: str
    reason_or_notes: Optional[str] = None
    correlation_id: Optional[str] = None


class AuditTrailItem(BaseModel):
    id: int
    timestamp: datetime.datetime
    category: str = "Authentication"
    actor_type: str  # "ADMIN", "SYSTEM", "AGENT", "USER"
    actor_label: str
    action_code: str
    action_label: str
    target_resource: str
    target_user_id: Optional[int] = None
    target_user_name: Optional[str] = None
    target_user_email: Optional[str] = None
    application: str
    session_id: Optional[str] = None
    result: str  # "Successful", "Denied", "Failed", "Pending", "Enforced", "Advisory Completed", "Fallback (Timeout)", "Escalated by Arbiter"
    risk_level: Optional[str] = None
    previous_risk_level: Optional[str] = None
    risk_score: Optional[float] = None
    anomaly_score: Optional[float] = None
    has_behavioral_telemetry: bool = False
    has_agent_analysis: bool = False
    related_incident_id: Optional[int] = None
    summary: str = ""
    reason: Optional[str] = None
    technical_details: Optional[Dict[str, Any]] = None
    repeat_count: int = 1
    correlation_id: Optional[str] = None
    integrity_status: str = "Verified"


class AuditTrailResponse(BaseModel):
    items: List[AuditTrailItem]
    total: int
    page: int
    page_size: int
    total_pages: int


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


class LLMProviderHealth(BaseModel):
    configured_provider: str
    configured_model: str
    provider_configured: bool
    credentials_present: bool
    connectivity_verified: bool
    agent_request_succeeded: bool
    connectivity_status: str
    last_successful_check: Optional[str] = None
    last_failure_category: Optional[str] = None


class SystemHealthResponse(BaseModel):
    database_connected: bool
    database_engine: str
    database_latency_ms: float
    last_event_ingested_at: Optional[datetime.datetime] = None
    telemetry_pipeline_status: str
    active_sessions_count: int
    server_timestamp: datetime.datetime
    llm_provider_health: Optional[LLMProviderHealth] = None


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


# -------------------------------------------------------------------------
# SOC Monitoring Agent Response Schemas
# -------------------------------------------------------------------------
class SOCIncidentSummary(BaseModel):
    incident_id: int
    alert_id: Optional[int] = None
    security_event_id: Optional[int] = None
    severity: str
    status: str
    application: str
    message: str
    user_id: int
    user_name: str
    user_email: str
    created_at: datetime.datetime
    ai_analysis: Optional[Dict[str, Any]] = None
    session_id: Optional[str] = None
    device_id: Optional[int] = None
    risk_score: Optional[float] = None
    incident_category: Optional[str] = None
    containment_status: Optional[str] = None
    containment_actions: List[str] = []
    timeline_event_count: Optional[int] = None
    updated_at: Optional[datetime.datetime] = None


class SOCPostureResponse(BaseModel):
    active_sessions: int
    open_incidents: int
    risk_distribution: Dict[str, int]
    critical_events: int
    failed_auth_attempts: int
    device_trust_distribution: Dict[str, int]
    portal_incident_counts: Dict[str, int]
    behavioral_anomaly_trends: Dict[str, Any]
    modality_maturity_distribution: Dict[str, int]
    contained_incidents: int = 0
    resolved_incidents: int = 0
    total_incidents: int = 0
    incidents_by_severity: Dict[str, int] = {}
    portal_activity_counts: Dict[str, int] = {}
    recent_containment_actions_count: int = 0


class SOCContainmentActionItem(BaseModel):
    id: int
    timestamp: datetime.datetime
    action_type: str
    target_user_id: int
    target_session_id: Optional[str] = None
    application: str
    details: Optional[str] = None
    severity: str = "HIGH"
    status: str = "CONTAINED"


class SOCContainmentActionsResponse(BaseModel):
    total: int
    actions: List[SOCContainmentActionItem] = []


class SOCSummaryResponse(BaseModel):
    executive_summary: str
    threat_assessment: str
    incident_priority: str
    suspicious_patterns: List[str] = []
    attack_correlations: List[Dict[str, Any]] = []
    observed_facts: List[str] = []
    inferred_threats: List[str] = []
    investigation_steps: List[str] = []
    timestamp: str
    provenance: str = "AI_ASSISTED_ADVISORY"


class SOCRecommendationsResponse(BaseModel):
    recommendations: List[str]
    priority: str
    generated_at: str
    disclaimer: str = "AI-generated recommendations are advisory and require human SOC analyst verification."


# -------------------------------------------------------------------------
# Security Intelligence & Event Timeline Schemas
# -------------------------------------------------------------------------
class SecurityIntelligenceOverviewResponse(BaseModel):
    authentication_events_count: int = 0
    behavioral_anomalies_count: int = 0
    risk_transitions_count: int = 0
    step_up_challenges_count: int = 0
    successful_verifications_count: int = 0
    failed_verifications_count: int = 0
    session_terminations_count: int = 0
    portal_locks_count: int = 0
    security_response_actions_count: int = 0
    agentic_executions_count: int = 0
    total_events_count: int = 0
    total_registered_users: int = 0
    active_users_count: int = 0
    successful_logins_count: int = 0
    failed_logins_count: int = 0
    step_up_verifications_count: int = 0
    security_incidents_count: int = 0
    portal_locks_and_terminations_count: int = 0
    data_limitations: List[str] = []


class BehaviouralFeatureComparison(BaseModel):
    key: str
    label: str
    unit: str
    observed: Optional[float] = None
    baseline_mean: Optional[float] = None
    baseline_std: Optional[float] = None
    deviation_z: Optional[float] = None
    status: str = "Not recorded"


class BehaviouralIntelligencePayload(BaseModel):
    telemetry_available: bool = False
    baseline_available: bool = False
    sample_count: int = 0
    modality_maturity: str = "COLD_START"
    maturity_progress: float = 0.0
    model_version: Optional[str] = None
    anomaly_score: Optional[float] = None
    risk_score: Optional[float] = None
    observed_at: Optional[datetime.datetime] = None
    note: Optional[str] = None
    features: List[BehaviouralFeatureComparison] = []


class AdaptiveAuthHistoryItem(BaseModel):
    id: int
    timestamp: datetime.datetime
    user_id: Optional[int] = None
    user_name: Optional[str] = None
    user_email: Optional[str] = None
    session_id: Optional[str] = None
    application: str
    risk_level: Optional[str] = None
    risk_score: Optional[float] = None
    requested_factor: str
    challenge_status: str  # "ISSUED", "VERIFIED", "FAILED", "LOCKED", "TERMINATED"
    actual_result: str
    reason: str


class AgentExecutionDetail(BaseModel):
    agent_key: str
    agent_name: str
    trigger_event: str
    analysis_status: str  # "COMPLETED", "TIMEOUT_FALLBACK", "FALLBACK", "FAILED", "NOT_EXECUTED"
    main_finding: str
    recommendation: Optional[str] = None
    confidence: Optional[float] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    provider_status: str
    execution_time_ms: Optional[float] = None
    timestamp: Optional[datetime.datetime] = None


class DeterministicArbiterDecision(BaseModel):
    decision: str
    risk_level: str
    risk_score: Optional[float] = None
    enforced_outcome: str
    authoritative_source: str = "Deterministic Security Engine"


class SecurityEventDetailResponse(BaseModel):
    event: AuditTrailItem
    user: Dict[str, Any] = {}
    session: Optional[Dict[str, Any]] = None
    device: Optional[Dict[str, Any]] = None
    behavioural_intelligence: BehaviouralIntelligencePayload
    adaptive_auth_history: List[AdaptiveAuthHistoryItem] = []
    agent_executions: List[AgentExecutionDetail] = []
    arbiter_decision: Optional[DeterministicArbiterDecision] = None
    related_incidents: List[Dict[str, Any]] = []
    portal_locks: List[Dict[str, Any]] = []
    related_session_events: List[AuditTrailItem] = []



