"""
Authoritative Deterministic Security Arbiter.
Enforces Zero-Trust policy invariants:
- Agents CANNOT lower deterministic risk scores or levels.
- Agents CANNOT independently authenticate users or bypass MFA.
- Agents CANNOT prevent CRITICAL session termination or grant revocation.
- All agent recommendations are validated against backend security policy.
"""
import logging
from typing import Dict, Any, Tuple, Optional
from pydantic import BaseModel

from app.core.config import settings

logger = logging.getLogger("cognisec.arbiter")

RISK_LEVEL_RANKS = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}


class ArbitrationResult(BaseModel):
    effective_risk_score: float
    effective_risk_level: str
    action: str  # ALLOW, STEP_UP_REQUIRED, DENY, TERMINATE
    recommended_factor: str  # NONE, EMAIL_OTP, NEURAL_TRACE, COGNITIVE_DUAL, TERMINATE
    is_agent_accepted: bool
    override_reason: Optional[str] = None
    step_up_required: bool = False


class DeterministicSecurityArbiter:
    """
    Authoritative decision gate between deterministic security components
    and the cognitive agent fabric.
    """

    @classmethod
    def arbitrate_risk(
        cls,
        deterministic_score: float,
        deterministic_level: str,
        agent_score: Optional[float] = None,
        agent_level: Optional[str] = None,
    ) -> Tuple[float, str, bool, Optional[str]]:
        """
        Enforces Monotonic Risk Invariant:
        effective_score = max(deterministic_score, agent_score)
        effective_level = max(deterministic_level, agent_level)
        Returns: (effective_score, effective_level, is_agent_accepted, override_reason)
        """
        det_score = round(max(0.0, min(1.0, float(deterministic_score))), 4)
        det_lvl = deterministic_level.strip().upper()
        det_rank = RISK_LEVEL_RANKS.get(det_lvl, 1)

        if agent_score is None or agent_level is None:
            return det_score, det_lvl, False, "No agent recommendation provided; using deterministic baseline."

        ag_score = round(max(0.0, min(1.0, float(agent_score))), 4)
        ag_lvl = agent_level.strip().upper()
        ag_rank = RISK_LEVEL_RANKS.get(ag_lvl, 1)

        # 1. Check for Attempted Risk Downgrade
        if ag_rank < det_rank or ag_score < det_score:
            msg = (
                f"OVERRIDDEN_DOWNGRADE: Agent attempted to reduce risk "
                f"from {det_lvl} ({det_score:.2f}) to {ag_lvl} ({ag_score:.2f}). "
                f"Enforcing deterministic security floor."
            )
            logger.warning(msg)
            # Take the maximum of both to guarantee monotonic hardening
            effective_score = max(det_score, ag_score)
            effective_level = det_lvl if det_rank >= ag_rank else ag_lvl
            return effective_score, effective_level, False, msg

        # 2. Agent Escalation Accepted
        if ag_rank > det_rank or ag_score > det_score:
            msg = f"ACCEPTED_ESCALATION: Agent escalated risk from {det_lvl} ({det_score:.2f}) to {ag_lvl} ({ag_score:.2f})."
            logger.info(msg)
            return ag_score, ag_lvl, True, msg

        # 3. Agent and Deterministic Engine Agree
        return det_score, det_lvl, True, None

    @classmethod
    def arbitrate_decision(
        cls,
        effective_risk_score: float,
        effective_risk_level: str,
        enrolled_factors: Optional[Dict[str, bool]] = None,
        agent_action: Optional[str] = None,
        agent_factor: Optional[str] = None,
    ) -> ArbitrationResult:
        """
        Maps the arbitrated risk score and level to an authoritative enforcement action.
        Validates agent factor recommendations against backend policy.
        """
        lvl = effective_risk_level.upper()
        enrolled = enrolled_factors or {}

        # 1. CRITICAL Risk: Immediate Deterministic Session Termination
        if lvl == "CRITICAL" or effective_risk_score >= settings.RISK_THRESHOLD_HIGH:
            return ArbitrationResult(
                effective_risk_score=effective_risk_score,
                effective_risk_level="CRITICAL",
                action="TERMINATE",
                recommended_factor="TERMINATE",
                is_agent_accepted=(agent_action == "TERMINATE"),
                override_reason="CRITICAL risk requires immediate deterministic session termination.",
                step_up_required=False
            )

        # 2. HIGH Risk: Compound Cognitive Dual Factor
        if lvl == "HIGH" or effective_risk_score >= settings.RISK_THRESHOLD_MEDIUM:
            # Policy strictly mandates COGNITIVE_DUAL for HIGH risk
            return ArbitrationResult(
                effective_risk_score=effective_risk_score,
                effective_risk_level="HIGH",
                action="STEP_UP_REQUIRED",
                recommended_factor="COGNITIVE_DUAL",
                is_agent_accepted=(agent_factor == "COGNITIVE_DUAL"),
                override_reason=None if agent_factor == "COGNITIVE_DUAL" else "Policy mandates COGNITIVE_DUAL for HIGH risk.",
                step_up_required=True
            )

        # 3. MEDIUM Risk: NeuralTrace Gesture Auth (fallback to OTP if unenrolled)
        if lvl == "MEDIUM" or effective_risk_score >= settings.RISK_THRESHOLD_LOW:
            has_gesture = enrolled.get("has_gesture_pattern", False)
            chosen_factor = "NEURAL_TRACE" if has_gesture else "EMAIL_OTP"
            return ArbitrationResult(
                effective_risk_score=effective_risk_score,
                effective_risk_level="MEDIUM",
                action="STEP_UP_REQUIRED",
                recommended_factor=chosen_factor,
                is_agent_accepted=(agent_factor == chosen_factor),
                override_reason=None if agent_factor == chosen_factor else f"Policy assigned {chosen_factor} for MEDIUM risk.",
                step_up_required=True
            )

        # 4. LOW Risk: Frictionless or Email OTP depending on threshold
        if effective_risk_score < 0.15:
            return ArbitrationResult(
                effective_risk_score=effective_risk_score,
                effective_risk_level="LOW",
                action="ALLOW",
                recommended_factor="NONE",
                is_agent_accepted=True,
                override_reason=None,
                step_up_required=False
            )
        else:
            return ArbitrationResult(
                effective_risk_score=effective_risk_score,
                effective_risk_level="LOW",
                action="STEP_UP_REQUIRED",
                recommended_factor="EMAIL_OTP",
                is_agent_accepted=True,
                override_reason=None,
                step_up_required=True
            )

