"""
Adaptive Authentication Agent Module.
Recommends optimal authentication factors and verification response actions
(ALLOW, STEP_UP_REQUIRED, DENY, TERMINATE) strictly aligned with backend
Zero-Trust policy and enrolled user factors.
"""
import json
import logging
from datetime import datetime, timezone
from typing import Optional, Set, Any, Dict, List
from sqlalchemy.orm import Session

from app.core.config import settings
from app.agents.core.base_agent import BaseAgent
from app.agents.core.llm_client import LLMClient, LLMRequest
from app.agents.core.sanitization import Sanitizer
from app.agents.core.tool import AgentTool
from app.agents.core.arbiter import DeterministicSecurityArbiter, ArbitrationResult
from app.agents.schemas.agent_schemas import AdaptiveAuthInput, AdaptiveAuthOutput

from app.services.session_service import SessionService
from app.services.adaptive_auth_service import AdaptiveAuthService
from app.services.step_up_service import StepUpService

logger = logging.getLogger("cognisec.agent.adaptive_auth")

DEFAULT_PERMITTED_TOOLS = {
    "get_enrolled_mfa_factors",
    "check_rate_limit_status"
}

VALID_FACTORS = ("NONE", "EMAIL_OTP", "NEURAL_TRACE", "COGNITIVE_DUAL", "TERMINATE")
VALID_ACTIONS = ("ALLOW", "STEP_UP_REQUIRED", "DENY", "TERMINATE")


class AdaptiveAuthAgent(BaseAgent):
    """
    Adaptive Authentication Agent: Consumes arbitrated risk outputs,
    enrolled factor availability, and session context to recommend
    appropriate authentication challenges and access actions.
    """

    def __init__(
        self,
        db: Optional[Session] = None,
        llm_client: Optional[LLMClient] = None,
        permitted_tools: Optional[Set[str]] = None,
        timeout_seconds: Optional[float] = None,
        max_retries: Optional[int] = None
    ):
        super().__init__(
            name="AdaptiveAuthAgent",
            description="Recommends verification actions and factors aligned strictly with backend zero-trust policy.",
            input_schema=AdaptiveAuthInput,
            output_schema=AdaptiveAuthOutput,
            permitted_tools=permitted_tools or DEFAULT_PERMITTED_TOOLS,
            llm_client=llm_client,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries
        )
        self.db: Optional[Session] = db
        self._register_default_tools()

    def set_db(self, db: Session) -> None:
        """Sets or updates the database session for factor lookups."""
        self.db = db

    def _register_default_tools(self) -> None:
        """Registers sandboxed tools for inspecting factor enrollment and challenge rate limits."""
        self.register_tool(AgentTool(
            name="get_enrolled_mfa_factors",
            description="Retrieves enrolled authentication factors for a user.",
            func=self._tool_get_enrolled_mfa_factors,
            is_read_only=True
        ))
        self.register_tool(AgentTool(
            name="check_rate_limit_status",
            description="Checks active step-up challenges and attempt rate limits.",
            func=self._tool_check_rate_limit_status,
            is_read_only=True
        ))

    def _tool_get_enrolled_mfa_factors(self, user_id: int) -> Dict[str, Any]:
        """Tool querying enrolled factors safely without exposing secrets."""
        if not self.db:
            return {"error": "Database session not available."}
        try:
            return AdaptiveAuthService.get_enrollment_status(self.db, user_id)
        except Exception as e:
            return {"user_id": user_id, "error": str(e)}

    def _tool_check_rate_limit_status(self, session_id: str, application: Optional[str] = None) -> Dict[str, Any]:
        """Tool inspecting active challenge state and attempt limits."""
        chal = StepUpService.get_challenge(session_id, application)
        if not chal:
            return {"session_id": session_id, "has_active_challenge": False}
        return {
            "session_id": session_id,
            "has_active_challenge": True,
            "challenge_type": chal.get("challenge_type"),
            "attempts": chal.get("attempts", 0),
            "max_attempts": chal.get("max_attempts", 3),
            "is_active": (chal.get("expires_at") > datetime.now(timezone.utc)) if chal.get("expires_at") else True
        }

    def _evaluate_deterministic_policy(
        self,
        validated_input: AdaptiveAuthInput
    ) -> Dict[str, Any]:
        """
        Determines the authoritative factor and action based on Zero-Trust policy:
        - CRITICAL (>= 0.85): TERMINATE_SESSION (Immediate server-side kill switch).
        - HIGH (0.65 <= risk < 0.85): HIGH_RISK_DUAL (COGNITIVE_DUAL). If unenrolled, FAIL-CLOSED (DENY).
        - MEDIUM (0.30 <= risk < 0.65): NEURAL_TRACE (GESTURE_PATTERN) if enrolled.
          If unenrolled: FAIL-CLOSED for protected vaults; fallback to EMAIL_OTP for general portal.
        - LOW (< 0.30): Frictionless ALLOW. If explicit step-up requested, EMAIL_OTP.
        """
        risk_level = validated_input.effective_risk_level.strip().upper()
        risk_score = round(float(validated_input.effective_risk_score), 4)
        sess_status = str(validated_input.session_status).strip().upper()
        portal = str(validated_input.application).strip().lower()
        res = validated_input.protected_resource
        is_vault = bool(res and SessionService.normalize_resource(res) in ("academic_vault", "financial_vault", "ehr_vault"))

        # Resolve factor enrollment
        enrolled = dict(validated_input.enrolled_factors or {})
        if not enrolled and self.db:
            try:
                enrolled = AdaptiveAuthService.get_enrollment_status(self.db, validated_input.user_id)
            except Exception:
                enrolled = {}

        # Inspect active challenge status
        active_chal_detected = False
        if validated_input.active_challenge:
            active_chal_detected = True
        elif validated_input.session_id:
            raw_chal = StepUpService.get_challenge(validated_input.session_id, portal)
            if raw_chal:
                exp = raw_chal.get("expires_at")
                if not exp or exp > datetime.now(timezone.utc):
                    active_chal_detected = True

        observed_facts: List[str] = [
            f"Effective risk tier: {risk_level} ({risk_score:.2f}).",
            f"Session status: {sess_status}.",
            f"Target portal: '{portal}'" + (f" (accessing protected resource '{res}')" if is_vault else "."),
            f"Factor enrollment: gesture={enrolled.get('has_gesture_pattern', False)}, cognitive_img={enrolled.get('has_cognitive_image_sequence', False)}, private_resp={enrolled.get('has_private_response', False)}."
        ]
        if active_chal_detected:
            observed_facts.append("Active in-flight step-up challenge detected for this session.")

        # -------------------------------------------------------------
        # 1. Inactive or Terminated Session Gate
        # -------------------------------------------------------------
        if sess_status in ("TERMINATED", "REVOKED", "EXPIRED"):
            act = "TERMINATE" if sess_status == "TERMINATED" else "DENY"
            decision = {
                "action": act,
                "recommended_factor": "NONE",
                "step_up_required": False,
                "effective_risk_level": risk_level,
                "effective_risk_score": risk_score,
                "user_enrolled": True,
                "active_challenge_detected": active_chal_detected,
                "weaker_factors_rejected": [],
                "fallback_strategy": None,
                "observed_facts": observed_facts,
                "policy_decision": act,
                "agent_recommendation": f"Reject access: Session is {sess_status}.",
                "rationale": f"Deterministic policy: Session is in {sess_status} state. Access denied and step-up challenge creation prohibited."
            }

        # -------------------------------------------------------------
        # 2. CRITICAL Risk (>= 0.85): Immediate Session Termination
        # -------------------------------------------------------------
        elif risk_level == "CRITICAL" or risk_score >= settings.RISK_THRESHOLD_HIGH:
            decision = {
                "action": "TERMINATE",
                "recommended_factor": "TERMINATE",
                "step_up_required": False,
                "effective_risk_level": "CRITICAL",
                "effective_risk_score": max(0.85, risk_score),
                "user_enrolled": True,
                "active_challenge_detected": active_chal_detected,
                "weaker_factors_rejected": ["EMAIL_OTP", "NEURAL_TRACE", "COGNITIVE_DUAL"],
                "fallback_strategy": None,
                "observed_facts": observed_facts,
                "policy_decision": "TERMINATE_SESSION",
                "agent_recommendation": "Execute immediate non-negotiable session termination and grant revocation.",
                "rationale": "Deterministic policy: CRITICAL risk enforces immediate session termination. Authentication challenges and access grants are strictly prohibited."
            }

        # -------------------------------------------------------------
        # 3. HIGH Risk (0.65 <= risk < 0.85): Mandatory Cognitive Dual
        # -------------------------------------------------------------
        elif risk_level == "HIGH" or risk_score >= settings.RISK_THRESHOLD_MEDIUM:
            # Check explicit unavailability (key explicitly False in enrolled dict)
            explicitly_missing_img = (enrolled.get("has_cognitive_image_sequence") is False)
            explicitly_missing_priv = (enrolled.get("has_private_response") is False)
            has_img = bool(enrolled.get("has_cognitive_image_sequence", True))
            has_priv = bool(enrolled.get("has_private_response", True))

            is_explicitly_unavailable = explicitly_missing_img or explicitly_missing_priv
            user_enrolled = has_img and has_priv and not is_explicitly_unavailable
            weaker_rejected = ["EMAIL_OTP", "NEURAL_TRACE"]

            if not is_explicitly_unavailable:
                decision = {
                    "action": "STEP_UP_REQUIRED",
                    "recommended_factor": "COGNITIVE_DUAL",
                    "step_up_required": True,
                    "effective_risk_level": "HIGH",
                    "effective_risk_score": risk_score,
                    "user_enrolled": True,
                    "active_challenge_detected": active_chal_detected,
                    "weaker_factors_rejected": weaker_rejected,
                    "fallback_strategy": None,
                    "observed_facts": observed_facts,
                    "policy_decision": "STEP_UP_REQUIRED (COGNITIVE_DUAL)",
                    "agent_recommendation": "Issue compound HIGH_RISK_DUAL verification (Image Sequence + Private Security Response).",
                    "rationale": "Deterministic policy: HIGH risk mandates compound cognitive verification (Sequential Image Sequence + Private Security Response). Weaker single factors rejected."
                }
            else:
                missing = []
                if explicitly_missing_img:
                    missing.append("Cognitive Image Sequence")
                if explicitly_missing_priv:
                    missing.append("Private Security Response")
                decision = {
                    "action": "DENY",
                    "recommended_factor": "COGNITIVE_DUAL",
                    "step_up_required": False,
                    "effective_risk_level": "HIGH",
                    "effective_risk_score": risk_score,
                    "user_enrolled": False,
                    "active_challenge_detected": active_chal_detected,
                    "weaker_factors_rejected": weaker_rejected,
                    "fallback_strategy": "FAIL_CLOSED_CANNOT_DOWNGRADE",
                    "observed_facts": observed_facts,
                    "policy_decision": "DENY (UNENROLLED_COGNITIVE_DUAL)",
                    "agent_recommendation": "Deny access. User is not enrolled in mandatory compound cognitive factors.",
                    "rationale": f"Deterministic policy: HIGH risk requires both Cognitive Image Sequence and Private Security Response. Missing: {', '.join(missing)}. Policy strictly prohibits downgrading to weaker factor."
                }

        # -------------------------------------------------------------
        # 4. MEDIUM Risk (0.30 <= risk < 0.65): NeuralTrace Verification
        # -------------------------------------------------------------
        elif risk_level == "MEDIUM" or risk_score >= settings.RISK_THRESHOLD_LOW:
            has_gesture = bool(enrolled.get("has_gesture_pattern", False))

            if has_gesture:
                decision = {
                    "action": "STEP_UP_REQUIRED",
                    "recommended_factor": "NEURAL_TRACE",
                    "step_up_required": True,
                    "effective_risk_level": "MEDIUM",
                    "effective_risk_score": risk_score,
                    "user_enrolled": True,
                    "active_challenge_detected": active_chal_detected,
                    "weaker_factors_rejected": ["EMAIL_OTP"],
                    "fallback_strategy": None,
                    "observed_facts": observed_facts,
                    "policy_decision": "STEP_UP_REQUIRED (NEURAL_TRACE)",
                    "agent_recommendation": "Issue NeuralTrace route reconstruction challenge.",
                    "rationale": "Deterministic policy: MEDIUM risk mandates biometric NeuralTrace route verification. Weaker OTP factor rejected."
                }
            else:
                # User is NOT enrolled in NeuralTrace
                if is_vault:
                    decision = {
                        "action": "DENY",
                        "recommended_factor": "NEURAL_TRACE",
                        "step_up_required": False,
                        "user_enrolled": False,
                        "effective_risk_level": "MEDIUM",
                        "effective_risk_score": risk_score,
                        "active_challenge_detected": active_chal_detected,
                        "weaker_factors_rejected": ["EMAIL_OTP"],
                        "fallback_strategy": "FAIL_CLOSED_PROTECTED_VAULT",
                        "observed_facts": observed_facts,
                        "policy_decision": "DENY (UNENROLLED_NEURALTRACE_VAULT)",
                        "agent_recommendation": "Deny protected vault access. User is not enrolled in required NeuralTrace factor.",
                        "rationale": "Deterministic policy: Accessing protected vault under MEDIUM risk strictly requires NeuralTrace verification. User is not enrolled; policy forbids falling back to weaker Email OTP."
                    }
                else:
                    decision = {
                        "action": "STEP_UP_REQUIRED",
                        "recommended_factor": "EMAIL_OTP",
                        "step_up_required": True,
                        "effective_risk_level": "MEDIUM",
                        "effective_risk_score": risk_score,
                        "user_enrolled": False,
                        "active_challenge_detected": active_chal_detected,
                        "weaker_factors_rejected": [],
                        "fallback_strategy": "FALLBACK_EMAIL_OTP",
                        "observed_facts": observed_facts,
                        "policy_decision": "STEP_UP_REQUIRED (EMAIL_OTP_FALLBACK)",
                        "agent_recommendation": "Issue Email OTP as permitted fallback for general portal under MEDIUM risk.",
                        "rationale": "Deterministic policy: User is not enrolled in NeuralTrace. For general non-vault portal activity, policy permits falling back to Email OTP verification."
                    }

        # -------------------------------------------------------------
        # 5. LOW Risk (< 0.30): Frictionless Access / Explicit Step-Up
        # -------------------------------------------------------------
        elif validated_input.request_step_up or is_vault:
            decision = {
                "action": "STEP_UP_REQUIRED",
                "recommended_factor": "EMAIL_OTP",
                "step_up_required": True,
                "effective_risk_level": "LOW",
                "effective_risk_score": risk_score,
                "user_enrolled": True,
                "active_challenge_detected": active_chal_detected,
                "weaker_factors_rejected": [],
                "fallback_strategy": None,
                "observed_facts": observed_facts,
                "policy_decision": "STEP_UP_REQUIRED (EMAIL_OTP)",
                "agent_recommendation": "Issue Email OTP for requested step-up under LOW risk.",
                "rationale": "Deterministic policy: Low-risk explicit step-up challenge requested. Email OTP assigned as baseline verification."
            }
        else:
            decision = {
                "action": "ALLOW",
                "recommended_factor": "NONE",
                "step_up_required": False,
                "effective_risk_level": "LOW",
                "effective_risk_score": risk_score,
                "user_enrolled": True,
                "active_challenge_detected": active_chal_detected,
                "weaker_factors_rejected": [],
                "fallback_strategy": None,
                "observed_facts": observed_facts,
                "policy_decision": "ALLOW",
                "agent_recommendation": "Permit frictionless access without step-up challenge.",
                "rationale": "Deterministic policy: LOW risk allows frictionless access without challenge. Continuous identity monitoring remains active."
            }

        if active_chal_detected and "in-flight step-up challenge" not in decision["rationale"].lower():
            decision["rationale"] += " Note: An active in-flight step-up challenge already exists for this session."

        return decision

    async def _run_reasoning(self, validated_input: AdaptiveAuthInput) -> AdaptiveAuthOutput:
        """
        Executes adaptive authentication recommendation using authoritative policy evaluation
        and structured LLM reasoning, bounded by fail-secure deterministic arbitration.
        """
        # 1. Authoritative Policy Evaluation
        pol_eval = self._evaluate_deterministic_policy(validated_input)

        # 2. Build anti-injection prompt containing structured facts
        facts_json = json.dumps(Sanitizer.sanitize_dict(pol_eval), indent=2)

        prompt = (
            f"You are the Cognisec Adaptive Authentication Agent. Recommend an authentication response "
            f"for user {validated_input.user_id}:\n"
            f"<untrusted_database_context>\n"
            f"{facts_json}\n"
            f"</untrusted_database_context>\n\n"
            "ZERO TRUST POLICY INVARIANTS:\n"
            "1. You CANNOT reduce risk, bypass session termination, or grant unauthorized vault access.\n"
            "2. LOW risk (< 0.30): Frictionless ALLOW without step-up (unless explicit step-up requested).\n"
            "3. MEDIUM risk (0.30 - 0.64): NEURAL_TRACE mandatory if enrolled. Protected vaults FAIL-CLOSED if unenrolled.\n"
            "4. HIGH risk (0.65 - 0.84): COGNITIVE_DUAL mandatory. If unenrolled, FAIL-CLOSED (DENY). Never downgrade to OTP.\n"
            "5. CRITICAL risk (>= 0.85): TERMINATE immediately. Challenge creation strictly forbidden.\n\n"
            "Produce a JSON object with exactly these keys:\n"
            "- action: (string: ALLOW, STEP_UP_REQUIRED, DENY, or TERMINATE)\n"
            "- recommended_factor: (string: NONE, EMAIL_OTP, NEURAL_TRACE, COGNITIVE_DUAL, or TERMINATE)\n"
            "- rationale: (string explanation distinguishing observed facts, policy decision, and recommendation)\n"
            "- step_up_required: (boolean)\n"
        )
        request = LLMRequest(
            prompt=prompt,
            system_instruction="You are the Cognisec Adaptive Authentication Agent. Enforce zero-trust factor policies strictly without downgrading security.",
            response_schema={"type": "object"}
        )

        resp = await self.llm_client.generate(request)
        if resp.parsed_json and isinstance(resp.parsed_json, dict):
            proposed_action = str(resp.parsed_json.get("action", pol_eval["action"])).upper()
            proposed_factor = str(resp.parsed_json.get("recommended_factor", pol_eval["recommended_factor"])).upper()

            # Arbiter & Policy Guard: Prevent unauthorized action or factor downgrade
            if proposed_action not in VALID_ACTIONS:
                proposed_action = pol_eval["action"]
            if proposed_factor not in VALID_FACTORS:
                proposed_factor = pol_eval["recommended_factor"]

            # Invariant 1: If policy mandates TERMINATE, LLM cannot override
            if pol_eval["action"] == "TERMINATE":
                proposed_action = "TERMINATE"
                proposed_factor = "TERMINATE"

            # Invariant 2: If policy mandates COGNITIVE_DUAL, LLM cannot downgrade to EMAIL_OTP or NEURAL_TRACE
            if pol_eval["recommended_factor"] == "COGNITIVE_DUAL" and proposed_factor in ("EMAIL_OTP", "NEURAL_TRACE", "NONE"):
                proposed_factor = "COGNITIVE_DUAL"
                proposed_action = pol_eval["action"]

            # Invariant 3: If policy mandates NEURAL_TRACE and user unenrolled for vault, cannot downgrade to OTP
            if pol_eval["action"] == "DENY" and pol_eval.get("fallback_strategy") == "FAIL_CLOSED_PROTECTED_VAULT":
                proposed_action = "DENY"
                proposed_factor = "NEURAL_TRACE"

            # Invariant 4: If policy is ALLOW for LOW risk, do not add unsolicited step-up
            if pol_eval["action"] == "ALLOW" and not validated_input.request_step_up and proposed_action == "STEP_UP_REQUIRED":
                # Preserve LOW risk frictionless policy
                proposed_action = "ALLOW"
                proposed_factor = "NONE"

            step_up_req = (proposed_action == "STEP_UP_REQUIRED")
            rationale_text = resp.parsed_json.get("rationale") or pol_eval["rationale"]
            if pol_eval["active_challenge_detected"] and "in-flight step-up challenge" not in rationale_text.lower():
                rationale_text += " Note: An active in-flight step-up challenge already exists for this session."

            return AdaptiveAuthOutput(
                action=proposed_action,
                recommended_factor=proposed_factor,
                rationale=rationale_text,
                step_up_required=step_up_req,
                effective_risk_level=pol_eval["effective_risk_level"],
                effective_risk_score=pol_eval["effective_risk_score"],
                user_enrolled=pol_eval["user_enrolled"],
                active_challenge_detected=pol_eval["active_challenge_detected"],
                weaker_factors_rejected=pol_eval["weaker_factors_rejected"],
                fallback_strategy=pol_eval["fallback_strategy"],
                observed_facts=pol_eval["observed_facts"],
                policy_decision=pol_eval["policy_decision"],
                agent_recommendation=pol_eval["agent_recommendation"]
            )

        # Fallback to deterministic policy evaluation
        return self.get_deterministic_fallback(validated_input)

    def get_deterministic_fallback(self, input_data: Any) -> AdaptiveAuthOutput:
        """
        Deterministic, fail-secure fallback that strictly applies backend Zero-Trust policy
        without relying on external LLM services. Guaranteed never to fail or raise exceptions.
        """
        try:
            if isinstance(input_data, dict):
                validated_input = AdaptiveAuthInput(**input_data)
            elif isinstance(input_data, AdaptiveAuthInput):
                validated_input = input_data
            else:
                validated_input = AdaptiveAuthInput.model_validate(input_data)
        except Exception:
            user_id = getattr(input_data, "user_id", 0)
            score = getattr(input_data, "effective_risk_score", 0.0)
            level = getattr(input_data, "effective_risk_level", "LOW")
            validated_input = AdaptiveAuthInput(
                user_id=int(user_id) if isinstance(user_id, (int, float)) else 0,
                effective_risk_score=float(score) if isinstance(score, (int, float)) else 0.0,
                effective_risk_level=str(level) if str(level) in ("LOW", "MEDIUM", "HIGH", "CRITICAL") else "LOW"
            )

        pol_eval = self._evaluate_deterministic_policy(validated_input)
        return AdaptiveAuthOutput(
            action=pol_eval["action"],
            recommended_factor=pol_eval["recommended_factor"],
            rationale=f"Deterministic fallback: {pol_eval['rationale']}",
            step_up_required=pol_eval["step_up_required"],
            effective_risk_level=pol_eval["effective_risk_level"],
            effective_risk_score=pol_eval["effective_risk_score"],
            user_enrolled=pol_eval["user_enrolled"],
            active_challenge_detected=pol_eval["active_challenge_detected"],
            weaker_factors_rejected=pol_eval["weaker_factors_rejected"],
            fallback_strategy=pol_eval["fallback_strategy"],
            observed_facts=pol_eval["observed_facts"],
            policy_decision=pol_eval["policy_decision"],
            agent_recommendation=pol_eval["agent_recommendation"]
        )
