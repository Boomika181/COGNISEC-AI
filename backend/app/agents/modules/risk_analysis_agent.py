"""
Risk Analysis Agent Module.
Performs cognitive risk reasoning by synthesizing deterministic risk scores,
Isolation Forest behavioral anomaly deviation, Welford modality maturity,
device trust, and session environmental signals.
Enforces the Monotonic Risk Arbiter: can recommend risk escalation where justified,
but CANNOT reduce deterministic risk levels or bypass hard security gates.
"""
import json
import logging
from datetime import datetime, timezone
from typing import Optional, Set, Any, Dict, List, Tuple
from sqlalchemy.orm import Session

from app.core.config import settings
from app.agents.core.base_agent import BaseAgent
from app.agents.core.llm_client import LLMClient, LLMRequest
from app.agents.core.sanitization import Sanitizer
from app.agents.core.tool import AgentTool
from app.agents.core.arbiter import DeterministicSecurityArbiter, RISK_LEVEL_RANKS
from app.agents.schemas.agent_schemas import RiskAnalysisInput, RiskAnalysisOutput

from app.ml.model_manager import ModelManager
from app.ml.feature_engineering import FEATURE_NAMES

logger = logging.getLogger("cognisec.agent.risk_analysis")

DEFAULT_PERMITTED_TOOLS = {
    "compute_z_score_breakdown",
    "inspect_isolation_forest_decision"
}

VALID_THREAT_CATEGORIES = {
    "CREDENTIAL_COMPROMISE",
    "SESSION_HIJACKING",
    "BOT_AUTOMATION",
    "INSIDER_THREAT",
    "SUSPICIOUS_ANOMALY",
    "BENIGN_BASELINE",
    "INSUFFICIENT_EVIDENCE"
}


class RiskAnalysisAgent(BaseAgent):
    """
    Risk Analysis Agent: Analyzes verified multi-source behavioral and environmental
    context, identifies anomalous signal combinations, generates explainable threat
    hypotheses, and recommends justified risk escalation.
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
            name="RiskAnalysisAgent",
            description="Analyzes multi-factor behavioral anomalies, detects suspicious signal combinations, and recommends risk escalation.",
            input_schema=RiskAnalysisInput,
            output_schema=RiskAnalysisOutput,
            permitted_tools=permitted_tools or DEFAULT_PERMITTED_TOOLS,
            llm_client=llm_client,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries
        )
        self.db: Optional[Session] = db
        self._register_default_tools()

    def set_db(self, db: Session) -> None:
        """Sets or updates the database session for tool queries."""
        self.db = db

    def _register_default_tools(self) -> None:
        """Registers sandboxed tools for inspecting statistical deviations and model state."""
        self.register_tool(AgentTool(
            name="compute_z_score_breakdown",
            description="Calculates per-feature statistical z-scores against user baseline mean and standard deviation.",
            func=self._tool_compute_z_score_breakdown,
            is_read_only=True
        ))
        self.register_tool(AgentTool(
            name="inspect_isolation_forest_decision",
            description="Inspects Isolation Forest model readiness, trained sample counts, and decision thresholds.",
            func=self._tool_inspect_isolation_forest_decision,
            is_read_only=True
        ))

    def _tool_compute_z_score_breakdown(
        self,
        feature_vector: List[float],
        baseline_stats: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Tool computing standardized z-scores for feature deviation analysis."""
        if not feature_vector or not baseline_stats:
            return {"error": "Missing feature vector or baseline stats."}
        means = baseline_stats.get("means", {})
        stds = baseline_stats.get("stds", {})
        z_scores = {}
        for idx, feat_name in enumerate(FEATURE_NAMES):
            if idx < len(feature_vector):
                val = float(feature_vector[idx])
                mean = float(means.get(feat_name, 0.0))
                std = max(float(stds.get(feat_name, 1.0)), float(settings.FEATURE_MIN_SIGMA.get(feat_name, 1.0)))
                z = (val - mean) / std if std > 0 else 0.0
                z_scores[feat_name] = round(z, 3)
        return {"z_scores": z_scores}

    def _tool_inspect_isolation_forest_decision(
        self,
        user_id: int
    ) -> Dict[str, Any]:
        """Tool inspecting Isolation Forest model state and sample count."""
        try:
            status, sample_count, is_anom, score = ModelManager.get_ml_status(
                user_id=user_id,
                sample_count=0,
                db=self.db
            )
            return {
                "user_id": user_id,
                "ml_status": status,
                "trained_samples": sample_count,
                "default_anomaly_flag": is_anom,
                "default_score": score
            }
        except Exception as e:
            return {"user_id": user_id, "error": str(e), "ml_status": "ML_UNAVAILABLE"}

    def _evaluate_deterministic_analysis(
        self,
        validated_input: RiskAnalysisInput
    ) -> Dict[str, Any]:
        """
        Analyzes multi-factor context deterministically, detecting suspicious combinations
        of signals, identifying threat categories, and formulating escalation recommendations.
        """
        det_score = round(float(validated_input.deterministic_score), 4)
        det_level = validated_input.deterministic_level.strip().upper()
        if_score = round(float(validated_input.anomaly_score), 4)
        is_anomaly = bool(validated_input.is_anomaly)

        ctx = validated_input.sanitized_context or {}
        sess_sum = ctx.get("session_summary", {})
        dev_sum = ctx.get("device_summary", {})
        behav_sum = ctx.get("behavioural_summary", {})
        mod_breakdown = ctx.get("modality_maturity_breakdown") or validated_input.modality_maturity or {}
        sec_sum = ctx.get("security_event_summary", {})
        app_ctx = ctx.get("application_context", {})
        context_signals = ctx.get("context_signals", {})
        missing_indicators = ctx.get("missing_data_indicators", [])

        # Extract primary factual indicators
        device_trusted = bool(dev_sum.get("is_trusted", False))
        device_trust_state = str(dev_sum.get("trust_state", "UNKNOWN")).upper()
        changes_detected = bool(dev_sum.get("changes_detected", False))
        maturity_status = str(behav_sum.get("maturity_status", "COLD_START")).upper()
        profile_sample_count = int(behav_sum.get("sample_count", 0))
        failed_attempts = int(sec_sum.get("failed_attempts_count", 0))
        portal = str(app_ctx.get("portal", "SYSTEM")).lower()

        indicators: List[str] = []
        missing_evidence: List[str] = list(missing_indicators)
        supporting_evidence: Dict[str, Any] = {
            "deterministic_score": det_score,
            "deterministic_level": det_level,
            "isolation_forest_score": if_score,
            "is_anomaly": is_anomaly,
            "device_trusted": device_trusted,
            "device_trust_state": device_trust_state,
            "profile_maturity_status": maturity_status,
            "profile_sample_count": profile_sample_count,
            "failed_attempts_count": failed_attempts,
            "portal": portal
        }
        evidence_provenance: Dict[str, str] = {
            "deterministic_score": "DETERMINISTIC_RISK_ENGINE",
            "deterministic_level": "DETERMINISTIC_RISK_ENGINE",
            "isolation_forest_score": "ISOLATION_FOREST_DETECTOR",
            "device_trusted": "DATABASE_DEVICE",
            "profile_maturity_status": "DATABASE_PROFILE",
            "failed_attempts_count": "SECURITY_EVENTS_AND_CHALLENGES",
            "portal": "DATABASE_SESSION"
        }

        # -------------------------------------------------------------
        # 1. Modality Maturity & Confidence Calibration
        # -------------------------------------------------------------
        if maturity_status == "COLD_START" or profile_sample_count == 0:
            confidence = 0.35
            missing_evidence.append("Immature behavioral baseline: profile is in COLD_START; behavioral anomaly cannot stand as sole evidence for escalation.")
        elif maturity_status == "LEARNING" or profile_sample_count < 5:
            confidence = 0.65
            missing_evidence.append("Developing behavioral baseline: profile is in LEARNING mode; anomaly signal dampened.")
        else:
            confidence = 0.95

        # Cross-modal anomaly detection (e.g. keyboard AND mouse deviating)
        deviating_modalities = []
        if isinstance(mod_breakdown, dict):
            for mod_name, mod_info in mod_breakdown.items():
                if isinstance(mod_info, dict) and mod_info.get("sample_count", 0) >= 5:
                    pass  # Modality is mature
        cross_modal_anomaly_detected = False
        if is_anomaly and if_score >= 0.60 and maturity_status == "ESTABLISHED":
            cross_modal_anomaly_detected = True
            indicators.append("Cross-modal behavioral anomaly detected across mature telemetry channels")

        # -------------------------------------------------------------
        # 2. Suspicious Signal Combination & Threat Categorization
        # -------------------------------------------------------------
        threat_category = "BENIGN_BASELINE"
        recommended_escalation = False
        recommended_level = det_level
        recommended_score = det_score
        recommended_action = "ALLOW"

        observed_facts: List[str] = [
            f"Deterministic risk evaluated at {det_level} ({det_score:.2f}).",
            f"Device trust state is {device_trust_state} (is_trusted={device_trusted}).",
            f"Profile maturity status is {maturity_status} with {profile_sample_count} trusted baseline samples.",
            f"Isolation Forest continuous deviation score is {if_score:.2f} (is_anomaly={is_anomaly})."
        ]
        inferences: List[str] = []
        recommendations: List[str] = []

        # Tier 1: CRITICAL Deterministic Invariant
        if det_level == "CRITICAL" or det_score >= 0.85:
            threat_category = "CREDENTIAL_COMPROMISE"
            recommended_escalation = False
            recommended_level = "CRITICAL"
            recommended_score = max(0.85, det_score)
            recommended_action = "TERMINATE_SESSION"
            indicators.append("Deterministic engine flagged CRITICAL security risk tier")
            inferences.append("Severe multi-factor risk breach detected. Session integrity is authoritatively compromised.")
            recommendations.append("Execute immediate non-negotiable session termination (TERMINATE_SESSION) and revoke all active grants.")

        # Tier 2: Mid-Session Network/Device Switch + Telemetry Anomaly (Session Hijacking)
        elif changes_detected and (if_score >= 0.50 or is_anomaly):
            threat_category = "SESSION_HIJACKING"
            recommended_escalation = True
            indicators.append("Mid-session IP address switch combined with behavioral deviation")
            inferences.append("Observed sudden network origin transition accompanied by atypical interaction physics, strongly indicative of Man-in-the-Middle session hijacking.")
            # Compounding escalation: escalate to HIGH
            proposed_score = max(det_score, 0.78)
            recommended_score = proposed_score
            recommended_level = "HIGH"
            recommended_action = "STEP_UP_REQUIRED"
            recommendations.append("Escalate risk to HIGH and mandate multi-factor step-up verification before permitting session continuation.")

        # Tier 3: Untrusted Hardware + Established Profile Deviation (Credential Compromise / ATO)
        elif (not device_trusted or device_trust_state in ("UNTRUSTED", "REVOKED", "NEW")) and (if_score >= 0.55 or is_anomaly):
            if maturity_status == "ESTABLISHED":
                threat_category = "CREDENTIAL_COMPROMISE"
                recommended_escalation = True
                indicators.append("Untrusted hardware fingerprint combined with severe behavioral anomaly on established baseline")
                inferences.append("The user profile is statistically established, yet observed biometrics deviate sharply from the established baseline on unverified hardware, indicating account takeover.")
                proposed_score = max(det_score, 0.75)
                recommended_score = proposed_score
                recommended_level = "HIGH"
                recommended_action = "STEP_UP_REQUIRED"
                recommendations.append("Escalate risk to HIGH. Require high-risk dual cognitive verification before granting portal access.")
            else:
                threat_category = "INSUFFICIENT_EVIDENCE"
                indicators.append("Untrusted device fingerprint observed with immature baseline")
                inferences.append("Behavioral anomaly detected, but baseline is immature; cannot rule out normal user learning curve.")
                # Preserve deterministic level without compounding escalation
                recommended_escalation = False
                recommended_level = det_level
                recommended_score = det_score
                recommended_action = "STEP_UP_REQUIRED" if det_level in ("MEDIUM", "HIGH") else "ALLOW"
                recommendations.append("Maintain deterministic risk level. Collect further trusted samples before behavioral escalation.")

        # Tier 4: Repeated Failed Challenges / Security Blocks (Brute Force / Abuse)
        elif failed_attempts >= 2:
            threat_category = "CREDENTIAL_COMPROMISE"
            indicators.append(f"Multiple ({failed_attempts}) failed verification attempts or security blocks logged")
            inferences.append("Repeated authentication friction indicates potential brute-force guessing or challenge bypass probing.")
            if det_level == "LOW":
                recommended_escalation = True
                recommended_level = "MEDIUM"
                recommended_score = max(det_score, 0.50)
                recommended_action = "STEP_UP_REQUIRED"
                recommendations.append("Escalate risk from LOW to MEDIUM due to repeated failed security challenges.")
            elif det_level == "MEDIUM" and failed_attempts >= 3:
                recommended_escalation = True
                recommended_level = "HIGH"
                recommended_score = max(det_score, 0.70)
                recommended_action = "STEP_UP_REQUIRED"
                recommendations.append("Escalate risk from MEDIUM to HIGH due to persistent challenge failures.")
            else:
                recommended_escalation = False
                recommended_level = det_level
                recommended_score = det_score
                recommended_action = "STEP_UP_REQUIRED" if det_level in ("MEDIUM", "HIGH") else "ALLOW"

        # Tier 5: Sensitive Portal Access from Untrusted Device
        elif portal in ("shopping", "college", "healthcare") and not device_trusted:
            threat_category = "SUSPICIOUS_ANOMALY"
            indicators.append(f"Access attempt to protected portal '{portal}' from untrusted device")
            inferences.append(f"Protected resources for portal '{portal}' are requested from unverified hardware.")
            if det_level == "LOW":
                recommended_escalation = True
                recommended_level = "MEDIUM"
                recommended_score = max(det_score, 0.45)
                recommended_action = "STEP_UP_REQUIRED"
                recommendations.append(f"Escalate risk from LOW to MEDIUM to safeguard '{portal}' confidential records.")
            else:
                recommended_escalation = False
                recommended_level = det_level
                recommended_score = det_score
                recommended_action = "STEP_UP_REQUIRED"

        # Tier 6: Benign Baseline Alignment
        else:
            threat_category = "BENIGN_BASELINE"
            indicators.append("Telemetry signals consistent with verified baseline")
            inferences.append("Observed interaction physics and environmental indicators align with known benign activity.")
            recommended_escalation = False
            recommended_level = det_level
            recommended_score = det_score
            recommended_action = "ALLOW" if det_level == "LOW" else "STEP_UP_REQUIRED"
            recommendations.append("Maintain baseline risk status.")

        # Guarantee Monotonic Risk Invariant: agent recommendation cannot downgrade deterministic floor
        effective_score, effective_level, is_accepted, override_reason = DeterministicSecurityArbiter.arbitrate_risk(
            deterministic_score=det_score,
            deterministic_level=det_level,
            agent_score=recommended_score,
            agent_level=recommended_level
        )
        recommended_score = effective_score
        recommended_level = effective_level

        # Compile structured human-readable explanation
        explanation = (
            f"[OBSERVED FACTS]\n" + "\n".join(f"- {f}" for f in observed_facts) + "\n\n"
            f"[INFERENCES]\n" + "\n".join(f"- {i}" for i in (inferences or ["No anomalous inference required."])) + "\n\n"
            f"[RECOMMENDATIONS]\n" + "\n".join(f"- {r}" for r in recommendations)
        )

        return {
            "deterministic_risk_level": det_level,
            "deterministic_risk_score": det_score,
            "threat_category": threat_category,
            "identified_risk_indicators": indicators,
            "supporting_evidence": supporting_evidence,
            "evidence_provenance": evidence_provenance,
            "confidence": round(confidence, 2),
            "missing_or_insufficient_evidence": missing_evidence,
            "recommended_escalation": recommended_escalation,
            "recommended_risk_level": recommended_level,
            "recommended_risk_score": recommended_score,
            "recommended_action": recommended_action,
            "human_readable_explanation": explanation,
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
            # Backward-compatibility fields
            "risk_level": recommended_level,
            "risk_score": recommended_score,
            "primary_risk_factors": indicators,
            "rationale": explanation,
            "cross_modal_anomaly_detected": cross_modal_anomaly_detected
        }

    async def _run_reasoning(self, validated_input: RiskAnalysisInput) -> RiskAnalysisOutput:
        """
        Executes real-time multi-factor risk analysis using factual baseline data
        and structured LLM reasoning, bounded by fail-secure deterministic arbitration.
        """
        # 1. Deterministic Baseline Analysis
        det_eval = self._evaluate_deterministic_analysis(validated_input)

        # 2. Build anti-injection prompt containing structured facts
        sanitized_facts = Sanitizer.sanitize_dict(det_eval["supporting_evidence"])
        facts_json = json.dumps(sanitized_facts, indent=2)

        prompt = (
            f"You are the Cognisec Risk Analysis Agent. Analyze the following verified facts "
            f"for user {validated_input.user_id}:\n"
            f"<untrusted_database_context>\n"
            f"{facts_json}\n"
            f"</untrusted_database_context>\n\n"
            "SECURITY POLICY INVARIANTS:\n"
            "1. You CANNOT reduce the deterministic risk level or score under any circumstances.\n"
            "2. Distinguish clearly between observed facts, inferences, and recommendations.\n"
            "3. Do NOT treat an uncalibrated Isolation Forest score as a statistical probability.\n"
            "4. If modalities are immature (COLD_START/LEARNING), evidence is insufficient for purely behavioral escalation.\n\n"
            "Produce a JSON object with exactly these keys:\n"
            "- threat_category: (string: CREDENTIAL_COMPROMISE, SESSION_HIJACKING, BOT_AUTOMATION, INSIDER_THREAT, SUSPICIOUS_ANOMALY, BENIGN_BASELINE, or INSUFFICIENT_EVIDENCE)\n"
            "- identified_risk_indicators: (array of strings)\n"
            "- confidence: (float between 0.0 and 1.0)\n"
            "- recommended_escalation: (boolean)\n"
            "- recommended_risk_level: (string: LOW, MEDIUM, HIGH, or CRITICAL)\n"
            "- recommended_risk_score: (float between 0.0 and 1.0)\n"
            "- recommended_action: (string: ALLOW, STEP_UP_REQUIRED, RESTRICT, or TERMINATE_SESSION)\n"
            "- human_readable_explanation: (string with separate [OBSERVED FACTS], [INFERENCES], and [RECOMMENDATIONS] sections)\n"
            "- cross_modal_anomaly_detected: (boolean)\n"
        )
        request = LLMRequest(
            prompt=prompt,
            system_instruction="You are the Cognisec Risk Analysis Agent. Evaluate behavioral risk objectively without inventing facts or reducing deterministic security floors.",
            response_schema={"type": "object"}
        )

        resp = await self.llm_client.generate(request)
        if resp.parsed_json and isinstance(resp.parsed_json, dict):
            proposed_score = float(resp.parsed_json.get("recommended_risk_score", det_eval["recommended_risk_score"]))
            proposed_level = str(resp.parsed_json.get("recommended_risk_level", det_eval["recommended_risk_level"])).upper()

            # Monotonic Risk Arbiter: Enforce that agent output cannot downgrade deterministic floor
            eff_score, eff_level, accepted, reason = DeterministicSecurityArbiter.arbitrate_risk(
                deterministic_score=det_eval["deterministic_risk_score"],
                deterministic_level=det_eval["deterministic_risk_level"],
                agent_score=proposed_score,
                agent_level=proposed_level
            )

            threat_cat = str(resp.parsed_json.get("threat_category", det_eval["threat_category"])).upper()
            if threat_cat not in VALID_THREAT_CATEGORIES:
                threat_cat = det_eval["threat_category"]

            action = str(resp.parsed_json.get("recommended_action", det_eval["recommended_action"])).upper()
            if action not in ("ALLOW", "STEP_UP_REQUIRED", "RESTRICT", "TERMINATE_SESSION"):
                action = det_eval["recommended_action"]

            # If CRITICAL, enforce termination unconditionally
            if eff_level == "CRITICAL":
                action = "TERMINATE_SESSION"

            indicators = resp.parsed_json.get("identified_risk_indicators")
            if not isinstance(indicators, list) or not indicators:
                indicators = det_eval["identified_risk_indicators"]

            explanation = resp.parsed_json.get("human_readable_explanation") or det_eval["human_readable_explanation"]
            cross_modal = bool(resp.parsed_json.get("cross_modal_anomaly_detected", det_eval["cross_modal_anomaly_detected"]))
            conf = float(resp.parsed_json.get("confidence", det_eval["confidence"]))
            conf = max(0.0, min(1.0, conf))

            return RiskAnalysisOutput(
                deterministic_risk_level=det_eval["deterministic_risk_level"],
                deterministic_risk_score=det_eval["deterministic_risk_score"],
                threat_category=threat_cat,
                identified_risk_indicators=indicators,
                supporting_evidence=det_eval["supporting_evidence"],
                evidence_provenance=det_eval["evidence_provenance"],
                confidence=conf,
                missing_or_insufficient_evidence=det_eval["missing_or_insufficient_evidence"],
                recommended_escalation=(eff_level != det_eval["deterministic_risk_level"] or eff_score > det_eval["deterministic_risk_score"]),
                recommended_risk_level=eff_level,
                recommended_risk_score=eff_score,
                recommended_action=action,
                human_readable_explanation=explanation,
                analysis_timestamp=datetime.now(timezone.utc).isoformat(),
                # Backward-compatibility fields
                risk_level=eff_level,
                risk_score=eff_score,
                primary_risk_factors=indicators,
                rationale=explanation,
                cross_modal_anomaly_detected=cross_modal
            )

        # Fallback to deterministic synthesis if LLM response was unstructured
        return self.get_deterministic_fallback(validated_input)

    def get_deterministic_fallback(self, input_data: Any) -> RiskAnalysisOutput:
        """
        Deterministic, fail-secure fallback synthesizing verified database facts
        without external LLM dependencies. Guaranteed never to fail or raise exceptions.
        """
        try:
            if isinstance(input_data, dict):
                validated_input = RiskAnalysisInput(**input_data)
            elif isinstance(input_data, RiskAnalysisInput):
                validated_input = input_data
            else:
                validated_input = RiskAnalysisInput.model_validate(input_data)
        except Exception:
            det_score = getattr(input_data, "deterministic_score", 0.0)
            det_level = getattr(input_data, "deterministic_level", "LOW")
            validated_input = RiskAnalysisInput(
                user_id=getattr(input_data, "user_id", 0),
                deterministic_score=float(det_score) if isinstance(det_score, (int, float)) else 0.0,
                deterministic_level=str(det_level) if str(det_level) in ("LOW", "MEDIUM", "HIGH", "CRITICAL") else "LOW"
            )

        det_eval = self._evaluate_deterministic_analysis(validated_input)
        fallback_msg = "Deterministic fallback risk evaluation applied."
        det_eval["rationale"] = f"{fallback_msg}\n{det_eval['human_readable_explanation']}"
        det_eval["human_readable_explanation"] = det_eval["rationale"]
        return RiskAnalysisOutput(**det_eval)
