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


class SecurityDecisionResponse(BaseModel):
    # Public outcome (shown to normal user)
    decision: str
    user_message: str
    session_status: str

    # Administrative & internal audit fields (for SOC dashboard and engine inspection)
    risk_level: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    risk_score: float
    anomaly_score: float
    is_anomaly: bool = False
    ml_status: str = "ML_READY"
    contributing_factors: List[str]
    event_id: Optional[int] = None
    timestamp: datetime.datetime

    model_config = ConfigDict(from_attributes=True)


class StepUpVerifyRequest(BaseModel):
    session_id: str
    challenge_code: str
