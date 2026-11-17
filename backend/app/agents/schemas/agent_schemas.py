"""
Strict Pydantic v2 Schemas for Multi-Agent Inputs, Outputs, and Assessments.
"""
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import secrets
from pydantic import BaseModel, Field, field_validator


# -------------------------------------------------------------------------
# 1. Security Context Agent Schemas
# -------------------------------------------------------------------------
class SecurityContextInput(BaseModel):
    user_id: int
    session_id: Optional[str] = None
    application: Optional[str] = "SYSTEM"
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    device_id: Optional[str] = None
    requesting_user_id: Optional[int] = None
    is_admin: bool = False
    context_signals: Optional[Dict[str, Any]] = None


class SecurityContextOutput(BaseModel):
    collection_timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    user_id: int
    application_context: Dict[str, Any] = Field(default_factory=dict)
    session_summary: Dict[str, Any] = Field(default_factory=dict)
    device_summary: Dict[str, Any] = Field(default_factory=dict)
    behavioural_summary: Dict[str, Any] = Field(default_factory=dict)
    modality_maturity_breakdown: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    security_event_summary: Dict[str, Any] = Field(default_factory=dict)
    missing_data_indicators: List[str] = Field(default_factory=list)
    data_provenance: Dict[str, str] = Field(default_factory=dict)
    context_summary: str = "Security context evaluated."
    sanitized_context: Dict[str, Any] = Field(default_factory=dict)
    known_device: bool = False
    profile_status: str = "COLD_START"
    active_modalities: List[str] = Field(default_factory=list)
    risk_signals: List[str] = Field(default_factory=list)


# -------------------------------------------------------------------------
# 2. Risk Analysis Agent Schemas
# -------------------------------------------------------------------------
class RiskAnalysisInput(BaseModel):
    user_id: int
    deterministic_score: float = Field(ge=0.0, le=1.0)
    deterministic_level: str
    anomaly_score: float = Field(default=0.0, ge=0.0, le=1.0)
    is_anomaly: bool = False
    sanitized_context: Dict[str, Any] = Field(default_factory=dict)
    modality_maturity: Optional[Dict[str, Any]] = None
    feature_deviations: Optional[Dict[str, float]] = None

    @field_validator("deterministic_level")
    @classmethod
    def validate_deterministic_level(cls, v: str) -> str:
        clean = v.strip().upper()
        if clean not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            raise ValueError(f"Invalid deterministic_level: '{v}'. Must be LOW, MEDIUM, HIGH, or CRITICAL.")
        return clean


class RiskAnalysisOutput(BaseModel):
    deterministic_risk_level: str = "LOW"
    deterministic_risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    threat_category: str = "BENIGN_BASELINE"  # CREDENTIAL_COMPROMISE, SESSION_HIJACKING, BOT_AUTOMATION, INSIDER_THREAT, SUSPICIOUS_ANOMALY, BENIGN_BASELINE, INSUFFICIENT_EVIDENCE
    identified_risk_indicators: List[str] = Field(default_factory=list)
    supporting_evidence: Dict[str, Any] = Field(default_factory=dict)
    evidence_provenance: Dict[str, str] = Field(default_factory=dict)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    missing_or_insufficient_evidence: List[str] = Field(default_factory=list)
    recommended_escalation: bool = False
    recommended_risk_level: str = "LOW"
    recommended_risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    recommended_action: str = "ALLOW"  # ALLOW, STEP_UP_REQUIRED, RESTRICT, TERMINATE_SESSION
    human_readable_explanation: str = "Risk evaluated."
    analysis_timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Backward-compatibility fields
    risk_level: str = "LOW"
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    primary_risk_factors: List[str] = Field(default_factory=list)
    rationale: str = "Risk evaluated."
    cross_modal_anomaly_detected: bool = False

    @field_validator("risk_level", "recommended_risk_level", "deterministic_risk_level")
    @classmethod
    def validate_risk_level(cls, v: str) -> str:
        clean = v.strip().upper()
        if clean not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            raise ValueError(f"Invalid risk_level: '{v}'. Must be LOW, MEDIUM, HIGH, or CRITICAL.")
        return clean

    @field_validator("recommended_action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        clean = v.strip().upper()
        valid = ("ALLOW", "STEP_UP_REQUIRED", "RESTRICT", "TERMINATE_SESSION")
        if clean not in valid:
            raise ValueError(f"Invalid recommended_action '{v}'. Must be one of {valid}.")
        return clean


# -------------------------------------------------------------------------
# 3. Adaptive Authentication Agent Schemas
# -------------------------------------------------------------------------
class AdaptiveAuthInput(BaseModel):
    user_id: int
    effective_risk_level: str
    effective_risk_score: float = Field(ge=0.0, le=1.0)
    enrolled_factors: Dict[str, bool] = Field(default_factory=dict)
    application: str = "SYSTEM"
    session_status: str = "ACTIVE"
    session_id: Optional[str] = None
    protected_resource: Optional[str] = None
    active_challenge: Optional[Dict[str, Any]] = None
    risk_indicators: List[str] = Field(default_factory=list)
    request_step_up: bool = False

    @field_validator("effective_risk_level")
    @classmethod
    def validate_risk_level(cls, v: str) -> str:
        clean = v.strip().upper()
        if clean not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            raise ValueError(f"Invalid effective_risk_level '{v}'. Must be LOW, MEDIUM, HIGH, or CRITICAL.")
        return clean


class AdaptiveAuthOutput(BaseModel):
    action: str  # ALLOW, STEP_UP_REQUIRED, DENY, TERMINATE
    recommended_factor: str  # NONE, EMAIL_OTP, NEURAL_TRACE, COGNITIVE_DUAL, TERMINATE
    rationale: str
    step_up_required: bool = False
    effective_risk_level: str = "LOW"
    effective_risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    user_enrolled: bool = True
    active_challenge_detected: bool = False
    weaker_factors_rejected: List[str] = Field(default_factory=list)
    fallback_strategy: Optional[str] = None
    observed_facts: List[str] = Field(default_factory=list)
    policy_decision: str = "ALLOW"
    agent_recommendation: str = "Frictionless access permitted."
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @field_validator("action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        clean = v.strip().upper()
        if clean not in ("ALLOW", "STEP_UP_REQUIRED", "DENY", "TERMINATE"):
            raise ValueError(f"Invalid action '{v}'. Must be ALLOW, STEP_UP_REQUIRED, DENY, or TERMINATE.")
        return clean

    @field_validator("recommended_factor")
    @classmethod
    def validate_factor(cls, v: str) -> str:
        clean = v.strip().upper()
        valid = ("NONE", "EMAIL_OTP", "NEURAL_TRACE", "COGNITIVE_DUAL", "TERMINATE")
        if clean not in valid:
            raise ValueError(f"Invalid recommended_factor '{v}'. Must be one of {valid}.")
        return clean


# -------------------------------------------------------------------------
# 4. Security Response Agent Schemas
# -------------------------------------------------------------------------
def generate_incident_id() -> str:
    return f"inc_{secrets.token_hex(8)}"


class SecurityResponseInput(BaseModel):
    user_id: int
    event_id: str
    effective_risk_level: str
    effective_risk_score: float = Field(ge=0.0, le=1.0)
    reasons: List[str] = Field(default_factory=list)
    session_id: Optional[str] = None
    application: str = "platform"
    protected_resource: Optional[str] = None
    device_id: Optional[int] = None
    device_trust: Optional[str] = None
    threat_category: Optional[str] = None
    risk_analysis_summary: Optional[str] = None
    adaptive_auth_recommendation: Optional[Dict[str, Any]] = None
    active_challenges: List[Dict[str, Any]] = Field(default_factory=list)
    recent_security_events: List[Dict[str, Any]] = Field(default_factory=list)
    idempotency_key: Optional[str] = None
    auto_execute_containment: bool = False


class SecurityResponseOutput(BaseModel):
    incident_id: str = Field(default_factory=generate_incident_id)
    incident_category: str = "ROUTINE"
    severity: str = "LOW"
    affected_session_reference: Optional[str] = None
    application_portal: str = "platform"
    observed_facts: List[str] = Field(default_factory=list)
    supporting_evidence: List[str] = Field(default_factory=list)
    risk_analysis_summary: str = ""
    recommended_response: str = "Continue baseline monitoring."
    required_backend_operation: str = "NONE"
    notification_recommendation: Dict[str, Any] = Field(default_factory=dict)
    audit_metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    lifecycle_status: str = "RESPONSE_RECOMMENDED"
    execution_result: Optional[Dict[str, Any]] = None

    # Backward compatibility fields
    alert_required: bool = False
    alert_severity: str = "LOW"
    alert_summary: str = ""
    containment_action: str = "NONE"
    user_notification_recommended: bool = False

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        clean = v.strip().upper()
        if clean not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            raise ValueError(f"Invalid severity '{v}'.")
        return clean

    @field_validator("alert_severity")
    @classmethod
    def validate_alert_severity(cls, v: str) -> str:
        clean = v.strip().upper()
        if clean not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            raise ValueError(f"Invalid alert_severity '{v}'.")
        return clean

    @field_validator("required_backend_operation")
    @classmethod
    def validate_backend_op(cls, v: str) -> str:
        clean = v.strip().upper()
        valid = ("TERMINATE_SESSION", "REVOKE_GRANTS", "ENFORCE_STEP_UP", "NOTIFY_USER", "LOG_AUDIT_ONLY", "RECORD_AUDIT", "LOCK_PORTAL", "NONE")
        if clean not in valid:
            raise ValueError(f"Invalid required_backend_operation '{v}'.")
        return clean

    @field_validator("lifecycle_status")
    @classmethod
    def validate_lifecycle(cls, v: str) -> str:
        clean = v.strip().upper()
        valid = ("DETECTED", "ANALYZING", "RESPONSE_RECOMMENDED", "RESPONSE_EXECUTED", "NOTIFICATION_PENDING", "NOTIFIED", "CLOSED", "FAILED", "CONTAINED")
        if clean not in valid:
            raise ValueError(f"Invalid lifecycle_status '{v}'.")
        return clean


# -------------------------------------------------------------------------
# 5. SOC Monitoring Agent Schemas
# -------------------------------------------------------------------------
class SOCMonitoringInput(BaseModel):
    event_id: Optional[str] = None
    user_id: Optional[int] = None
    application: Optional[str] = None
    time_window_minutes: int = 60
    risk_events: List[Dict[str, Any]] = Field(default_factory=list)
    incidents: List[Dict[str, Any]] = Field(default_factory=list)
    active_sessions: List[Dict[str, Any]] = Field(default_factory=list)
    device_events: List[Dict[str, Any]] = Field(default_factory=list)
    security_response: Optional[Dict[str, Any]] = None
    containment_status: Optional[str] = None
    containment_actions_taken: List[str] = Field(default_factory=list)


class SOCMonitoringOutput(BaseModel):
    executive_summary: str
    threat_assessment: str
    suspicious_patterns: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    incident_priority: str = "P3"
    observed_facts: List[str] = Field(default_factory=list)
    inferred_threats: List[str] = Field(default_factory=list)
    attack_correlations: List[Dict[str, Any]] = Field(default_factory=list)
    posture_summary: Optional[Dict[str, Any]] = None
    investigation_steps: List[str] = Field(default_factory=list)
    containment_assessment: Optional[Dict[str, Any]] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @field_validator("incident_priority")
    @classmethod
    def validate_priority(cls, v: str) -> str:
        clean = v.strip().upper()
        if clean not in ("P1", "P2", "P3", "P4"):
            raise ValueError(f"Invalid incident_priority '{v}'. Must be P1, P2, P3, or P4.")
        return clean

