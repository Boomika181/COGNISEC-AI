import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict


class RiskEvaluationRequest(BaseModel):
    session_id: str
    application: str
    behavior_event_id: Optional[int] = None
    contextual_signals: Optional[Dict[str, Any]] = None


class UserSecurityOutcome(BaseModel):
    decision: str  # "ALLOW", "STEP_UP_VERIFICATION", "RESTRICT", "TERMINATE_SESSION"
    message: str   # Clean user-facing text
    session_status: Optional[str] = "ACTIVE"
    verification_required: bool = False
    confidential_access_granted: bool = False
    step_up_fresh: bool = False
    step_up_factor: Optional[str] = None
    application: Optional[str] = None
    resource: Optional[str] = None
    stage: Optional[int] = None
    stage_1_passed: Optional[bool] = None
    prompt: Optional[str] = None
    challenge_id: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class UserBehaviorEventResponse(BaseModel):
    """Sanitized Zero-Trust security outcome response returned to standard user clients."""
    decision: str
    user_message: str
    session_status: str
    verification_required: bool = False
    timestamp: datetime.datetime

    model_config = ConfigDict(from_attributes=True)


class AdminSecurityDecisionResponse(BaseModel):
    """Privileged security intelligence response for SOC/Admin command center inspection."""
    decision: str
    user_message: str
    session_status: str
    verification_required: bool = False
    risk_level: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    risk_score: float
    anomaly_score: float
    is_anomaly: bool = False
    ml_status: str = "ML_READY"
    contributing_factors: List[str]
    event_id: Optional[int] = None
    timestamp: datetime.datetime

    model_config = ConfigDict(from_attributes=True)


# Backward-compatibility alias
SecurityDecisionResponse = AdminSecurityDecisionResponse


class CatalogueItem(BaseModel):
    id: str
    label: str
    icon: str
    category: str


class MfaEnrollmentStatusResponse(BaseModel):
    user_id: int
    has_gesture_pattern: bool
    has_cognitive_image_sequence: bool
    has_private_response: bool
    private_question: Optional[str] = None


class GestureEnrollRequest(BaseModel):
    pattern: List[int]
    confirm_pattern: List[int]


class ImageSequenceEnrollRequest(BaseModel):
    image_sequence: List[str]
    confirm_image_sequence: List[str]


class PrivateResponseEnrollRequest(BaseModel):
    question: str
    response: str
    confirm_response: str


class MfaEnrollResponse(BaseModel):
    success: bool
    factor_type: str
    message: str


class GestureVerifyRequest(BaseModel):
    gesture_pattern: List[int]


class FactorVerifyResponse(BaseModel):
    success: bool
    factor_type: str
    message: str


class StepUpChallengeRequest(BaseModel):
    session_id: str
    preferred_factor: Optional[str] = None  # Optional user factor preference (if permitted by policy)
    application: Optional[str] = None
    resource: Optional[str] = None


class StepUpChallengeResponse(BaseModel):
    challenge_id: str
    session_id: str
    otp: str = ""  # Present for OTP challenges only if exhibition/demo mode is enabled
    challenge_type: str = "OTP"  # "OTP", "GESTURE_PATTERN", "COGNITIVE_IMAGE_SEQUENCE", "PRIVATE_RESPONSE", "HIGH_RISK_DUAL"
    expires_in_seconds: int = 300
    message: str = "Step-up challenge generated. Complete verification to restore session access."
    masked_email: Optional[str] = None  # Privacy-masked recipient email for OTP challenges
    prompt: Optional[str] = None  # For private response questions
    catalogue: Optional[List[CatalogueItem]] = None  # For cognitive image sequences
    min_length: Optional[int] = None
    delivery_status: Optional[str] = "SENT"
    is_demo_otp: bool = False  # Clearly separates exhibition OTP delivery from production email OTP
    application: Optional[str] = None
    resource: Optional[str] = None
    stage: Optional[int] = 1
    stage_1_passed: Optional[bool] = False


class StepUpVerifyRequest(BaseModel):
    session_id: str
    challenge_code: Optional[str] = None
    challenge_id: Optional[str] = None
    challenge_type: Optional[str] = "OTP"  # "OTP", "GESTURE_PATTERN", "COGNITIVE_IMAGE_SEQUENCE", "PRIVATE_RESPONSE", "HIGH_RISK_DUAL"
    gesture_pattern: Optional[List[int]] = None
    image_sequence: Optional[List[str]] = None
    private_response: Optional[str] = None
    application: Optional[str] = None
    resource: Optional[str] = None
    stage: Optional[int] = 1


class NeuralTraceResetRequestResponse(BaseModel):
    success: bool
    reset_challenge_id: str
    message: str
    masked_email: str


class NeuralTraceResetVerifyRequest(BaseModel):
    reset_challenge_id: Optional[str] = None
    challenge_id: Optional[str] = None
    otp: str


class NeuralTraceResetVerifyResponse(BaseModel):
    success: bool
    reset_ticket: str
    message: str


class NeuralTraceResetConfirmRequest(BaseModel):
    reset_ticket: str
    pattern: List[int]
    confirm_pattern: List[int]


class NeuralTraceResetConfirmResponse(BaseModel):
    success: bool
    factor_type: str = "GESTURE_PATTERN"
    message: str


class AccessDecisionRequest(BaseModel):
    session_id: str
    resource: str  # e.g., "academic_vault", "financial_vault", "ehr_vault"
    application: Optional[str] = None


class AccessDecisionResponse(BaseModel):
    decision: str  # "ALLOW", "STEP_UP_VERIFICATION", "RESTRICT", "TERMINATE_SESSION"
    access_granted: bool
    session_status: str
    risk_level: str
    step_up_fresh: bool
    step_up_factor: Optional[str] = None
    message: str
    verification_required: bool = False
    required_factor: Optional[str] = None
    resource: str
    application: Optional[str] = None


class VaultRelockRequest(BaseModel):
    session_id: str
    resource: str  # e.g., "academic_vault", "financial_vault", "ehr_vault"
    application: Optional[str] = None


class VaultRelockResponse(BaseModel):
    success: bool
    message: str
    resource: str
    application: str
    revoked_count: int
    vault_status: str = "LOCKED"

