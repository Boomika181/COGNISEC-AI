"""
Multi-Agent Orchestrator Module.
Provides structured event-driven coordination across all 5 specialized security agents
with strict fail-secure boundaries, zero circular calls, and monotonic risk preservation.
"""
import time
import json
import uuid
import asyncio
import logging
import threading
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Callable
from sqlalchemy.orm import Session

from app.core.config import settings
from app.agents.core.llm_client import LLMClient
from app.agents.core.factory import get_llm_client
from app.agents.core.sanitization import Sanitizer
from app.agents.core.arbiter import DeterministicSecurityArbiter
from app.agents.modules.security_context_agent import SecurityContextAgent
from app.agents.modules.risk_analysis_agent import RiskAnalysisAgent
from app.agents.modules.adaptive_auth_agent import AdaptiveAuthAgent
from app.agents.modules.security_response_agent import SecurityResponseAgent
from app.agents.modules.soc_monitoring_agent import SOCMonitoringAgent
from app.agents.schemas.agent_schemas import (
    SecurityContextInput,
    RiskAnalysisInput,
    AdaptiveAuthInput,
    SecurityResponseInput,
    SOCMonitoringInput
)
from app.models.security_event import SecurityEvent
from app.services.session_service import SessionService
from app.services.step_up_service import StepUpService

logger = logging.getLogger(__name__)


class SecurityOrchestrator:
    """
    Coordinates end-to-end multi-agent evaluation for telemetry events,
    session transitions, and administrative security assessments.
    """

    _lock = threading.RLock()
    _idempotency_cache: Dict[str, Dict[str, Any]] = {}
    _inflight_keys: set = set()
    _background_threads: List[threading.Thread] = []

    def __init__(
        self,
        db: Optional[Session] = None,
        llm_client: Optional[LLMClient] = None
    ):
        self.db = db
        self.llm_client = llm_client if llm_client is not None else get_llm_client()
        self.context_agent = SecurityContextAgent(llm_client=self.llm_client, db=db)
        self.risk_agent = RiskAnalysisAgent(llm_client=self.llm_client)
        self.auth_agent = AdaptiveAuthAgent(llm_client=self.llm_client, db=db)
        self.response_agent = SecurityResponseAgent(llm_client=self.llm_client, db=db)
        self.soc_agent = SOCMonitoringAgent(llm_client=self.llm_client, db=db)

    async def evaluate_session_security(
        self,
        user_id: int,
        session_id: Optional[str] = None,
        application: str = "platform",
        telemetry_features: Optional[List[float]] = None,
        raw_anomaly_score: float = 0.0,
        deterministic_risk_score: float = 0.0,
        deterministic_risk_level: str = "LOW",
        contributing_reasons: Optional[List[str]] = None,
        protected_resource: Optional[str] = None,
        auto_containment: bool = False,
        correlation_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        trigger_event: str = "SECURITY_EVALUATION",
        skip_containment: bool = False,
        threat_category: Optional[str] = None,
        event_id: Optional[int] = None,
        device_id: Optional[int] = None,
        **kwargs: Any
    ) -> Dict[str, Any]:
        """
        Executes the canonical multi-agent pipeline:
        1. Non-negotiable Synchronous Kill Switch (CRITICAL risk).
        2. SecurityContextAgent: Gathers session, device, and behavioral context.
        3. RiskAnalysisAgent: Reasons over behavioral anomalies and compounding factors.
        4. DeterministicSecurityArbiter: Enforces monotonic risk arbiter.
        5. AdaptiveAuthAgent: Determines factor recommendation and step-up necessity.
        6. SecurityResponseAgent: Formulates incident response & executes authorized containment if elevated.
        7. SOCMonitoringAgent: Updates SOC metrics & correlations.
        """
        start_t = time.monotonic()
        corr_id = correlation_id or f"corr_{uuid.uuid4().hex[:12]}"
        cache_key = idempotency_key or f"{user_id}:{session_id or 'anon'}:{corr_id}"

        with self._lock:
            if cache_key in self._idempotency_cache:
                return self._idempotency_cache[cache_key]

        reasons = list(contributing_reasons or [])
        portal = SessionService.normalize_application(application) or "platform"

        # -------------------------------------------------------------
        # Non-negotiable Zero-Trust Invariant:
        # Synchronous Session Termination for CRITICAL risk (>= 0.85)
        # MUST execute immediately before waiting for LLMs, background tasks, or agents
        # -------------------------------------------------------------
        sync_term_executed = False
        is_crit = (deterministic_risk_level == "CRITICAL" or deterministic_risk_score >= settings.RISK_THRESHOLD_HIGH)
        if is_crit and session_id and self.db:
            try:
                cur_sess = SessionService.get_session(self.db, session_id)
                if (
                    cur_sess
                    and cur_sess.user_id == user_id
                    and (SessionService.normalize_application(cur_sess.application) or "platform") == portal
                ):
                    SessionService.terminate_session(self.db, session_id, risk_level="CRITICAL")
                    sync_term_executed = True
                else:
                    logger.warning(f"Synchronous critical termination skipped: BOLA or portal mismatch for session {session_id}")
            except Exception as e:
                logger.error(f"Synchronous critical termination failure for session {session_id}: {e}")

        agents_executed: List[str] = []
        fallback_errors: List[Dict[str, str]] = []
        agent_timings_ms: Dict[str, float] = {}

        # -------------------------------------------------------------
        # Step 1: SecurityContextAgent
        # -------------------------------------------------------------
        ctx_inp = SecurityContextInput(
            user_id=user_id,
            session_id=session_id,
            application=portal
        )
        _t0 = time.monotonic()
        try:
            ctx_out = await self.context_agent.execute(ctx_inp)
            ctx_meta = getattr(self.context_agent, "last_execution_meta", None) or {}
            if ctx_meta.get("status") in ("FALLBACK", "TIMEOUT"):
                agents_executed.append("SecurityContextAgent:fallback")
                fallback_errors.append({"agent": "SecurityContextAgent", "error": ctx_meta.get("error") or ctx_meta.get("status"), "retry_attempts": ctx_meta.get("attempts", 1)})
            else:
                agents_executed.append("SecurityContextAgent")
        except Exception as e:
            logger.warning(f"SecurityContextAgent error, using fallback: {e}")
            fallback_errors.append({"agent": "SecurityContextAgent", "error": str(e)[:200]})
            ctx_out = self.context_agent.get_deterministic_fallback(ctx_inp)
            agents_executed.append("SecurityContextAgent:fallback")
        agent_timings_ms["SecurityContextAgent"] = round((time.monotonic() - _t0) * 1000, 2)

        # -------------------------------------------------------------
        # Step 2: Risk Analysis Agent
        # -------------------------------------------------------------
        feature_deviations = None
        if telemetry_features and len(telemetry_features) == 10 and self.db:
            try:
                import numpy as np
                from app.services.profile_service import ProfileService
                from app.ml.feature_engineering import FeatureEngineering
                prof = ProfileService.get_or_create_profile(self.db, user_id)
                b_stats = ProfileService.get_profile_dict(prof) if prof else {}
                if b_stats:
                    feature_deviations = FeatureEngineering.compute_statistical_deviations(
                        np.array(telemetry_features, dtype=float), b_stats
                    )
            except Exception as dev_err:
                logger.debug(f"Could not compute Welford deviations for RiskAnalysisAgent: {dev_err}")

        risk_inp = RiskAnalysisInput(
            user_id=user_id,
            deterministic_score=deterministic_risk_score,
            deterministic_level=deterministic_risk_level,
            anomaly_score=raw_anomaly_score,
            is_anomaly=(raw_anomaly_score > 0.45),
            sanitized_context=ctx_out.model_dump(),
            modality_maturity=getattr(ctx_out, "modality_maturity_breakdown", None),
            feature_deviations=feature_deviations,
        )
        _t0 = time.monotonic()
        try:
            risk_out = await self.risk_agent.execute(risk_inp)
            risk_meta = getattr(self.risk_agent, "last_execution_meta", None) or {}
            if risk_meta.get("status") in ("FALLBACK", "TIMEOUT"):
                agents_executed.append("RiskAnalysisAgent:fallback")
                fallback_errors.append({"agent": "RiskAnalysisAgent", "error": risk_meta.get("error") or risk_meta.get("status"), "retry_attempts": risk_meta.get("attempts", 1)})
            else:
                agents_executed.append("RiskAnalysisAgent")
        except Exception as e:
            logger.warning(f"RiskAnalysisAgent error, using fallback: {e}")
            fallback_errors.append({"agent": "RiskAnalysisAgent", "error": str(e)[:200]})
            risk_out = self.risk_agent.get_deterministic_fallback(risk_inp)
            agents_executed.append("RiskAnalysisAgent:fallback")
        agent_timings_ms["RiskAnalysisAgent"] = round((time.monotonic() - _t0) * 1000, 2)

        # -------------------------------------------------------------
        # Step 3: Deterministic Security Arbiter (Monotonic Floor)
        # -------------------------------------------------------------
        effective_score, effective_level, is_accepted, override_reason = DeterministicSecurityArbiter.arbitrate_risk(
            deterministic_score=deterministic_risk_score,
            deterministic_level=deterministic_risk_level,
            agent_score=risk_out.deterministic_risk_score,
            agent_level=risk_out.deterministic_risk_level
        )
        agents_executed.append("DeterministicSecurityArbiter")
        arb_res = {
            "effective_risk_score": effective_score,
            "effective_risk_level": effective_level,
            "is_agent_accepted": is_accepted,
            "override_reason": override_reason,
            "reasons": reasons + risk_out.identified_risk_indicators
        }

        # -------------------------------------------------------------
        # Step 4: Adaptive Authentication Agent
        # -------------------------------------------------------------
        sess_ctx_status = "ACTIVE" if sync_term_executed else (
            ctx_out.session_summary.get("status") if isinstance(getattr(ctx_out, "session_summary", None), dict) else None
        )
        auth_inp = AdaptiveAuthInput(
            user_id=user_id,
            session_id=session_id,
            application=portal,
            protected_resource=protected_resource,
            effective_risk_level=effective_level,
            effective_risk_score=effective_score,
            risk_indicators=arb_res["reasons"],
            session_status=(sess_ctx_status or "ACTIVE"),
            request_step_up=(trigger_event == "STEP_UP_CHALLENGE_REQUEST" or protected_resource is not None),
        )
        _t0 = time.monotonic()
        try:
            auth_out = await self.auth_agent.execute(auth_inp)
            auth_meta = getattr(self.auth_agent, "last_execution_meta", None) or {}
            if auth_meta.get("status") in ("FALLBACK", "TIMEOUT"):
                agents_executed.append("AdaptiveAuthAgent:fallback")
                fallback_errors.append({"agent": "AdaptiveAuthAgent", "error": auth_meta.get("error") or auth_meta.get("status"), "retry_attempts": auth_meta.get("attempts", 1)})
            else:
                agents_executed.append("AdaptiveAuthAgent")
        except Exception as e:
            logger.warning(f"AdaptiveAuthAgent error, using fallback: {e}")
            fallback_errors.append({"agent": "AdaptiveAuthAgent", "error": str(e)[:200]})
            auth_out = self.auth_agent.get_deterministic_fallback(auth_inp)
            agents_executed.append("AdaptiveAuthAgent:fallback")
        agent_timings_ms["AdaptiveAuthAgent"] = round((time.monotonic() - _t0) * 1000, 2)

        # -------------------------------------------------------------
        # Step 5: Security Response Agent
        # -------------------------------------------------------------
        threat_cat = threat_category or kwargs.get("threat_category")
        if not threat_cat:
            r_str = " ".join(arb_res.get("reasons") or []).lower()
            t_str = str(trigger_event).lower()
            if "hijack" in r_str or "hijack" in t_str or "session transfer" in r_str:
                threat_cat = "SESSION_HIJACKING"
            elif "takeover" in r_str or "takeover" in t_str or "credential stuffing" in r_str:
                threat_cat = "ACCOUNT_TAKEOVER"
            elif "lockout" in t_str or "locked portal" in r_str or "portal lock" in r_str:
                threat_cat = "PORTAL_LOCKOUT"
            elif "recovery" in t_str:
                threat_cat = "PORTAL_RECOVERY"
            elif getattr(ctx_out, "device_trust_status", None) == "REVOKED":
                threat_cat = "DEVICE_TRUST_VIOLATION"
            elif "failed" in t_str or "brute force" in r_str or "auth failure" in r_str:
                threat_cat = "REPEATED_AUTH_FAILURES"
            elif protected_resource or "vault" in r_str:
                if portal == "shopping" and ("payment" in r_str or "fraud" in r_str or "card" in r_str):
                    threat_cat = "PAYMENT_FRAUD"
                elif portal == "college" and ("exam" in r_str or "proctor" in r_str):
                    threat_cat = "EXAM_AUTHORIZATION_VIOLATION"
                elif portal == "healthcare" and ("ehr" in r_str or "clinical" in r_str or "patient" in r_str):
                    threat_cat = "SUSPICIOUS_EHR_ACCESS"
                else:
                    threat_cat = "UNAUTHORIZED_VAULT_ACCESS"
            elif effective_level == "CRITICAL":
                threat_cat = "CRITICAL_SECURITY_EVENT"
            elif effective_level in ("HIGH", "MEDIUM"):
                threat_cat = "BEHAVIORAL_ANOMALY"
            else:
                threat_cat = "ROUTINE"

        active_chals = []
        if session_id and portal:
            chal = StepUpService.get_challenge(session_id, portal)
            if chal:
                active_chals.append(chal)

        resp_inp = SecurityResponseInput(
            user_id=user_id,
            event_id=str(event_id or kwargs.get("event_id") or f"ev_{session_id or 'anon'}"),
            session_id=session_id,
            application=portal,
            protected_resource=protected_resource,
            device_id=(device_id or kwargs.get("device_id")),
            device_trust=getattr(ctx_out, "device_trust_status", None),
            threat_category=threat_cat,
            risk_analysis_summary=getattr(risk_out, "summary", "") or getattr(risk_out, "human_readable_explanation", "") or getattr(risk_out, "rationale", ""),
            adaptive_auth_recommendation=(auth_out.model_dump() if hasattr(auth_out, "model_dump") else None),
            active_challenges=active_chals,
            recent_security_events=list(getattr(ctx_out, "recent_security_events", []) or []),
            effective_risk_level=effective_level,
            effective_risk_score=effective_score,
            reasons=arb_res["reasons"],
            auto_execute_containment=(not skip_containment) and (auto_containment or (effective_level == "CRITICAL")),
            idempotency_key=cache_key
        )
        _t0 = time.monotonic()
        try:
            resp_out = await self.response_agent.execute(resp_inp)
            resp_meta = getattr(self.response_agent, "last_execution_meta", None) or {}
            if resp_meta.get("status") in ("FALLBACK", "TIMEOUT"):
                agents_executed.append("SecurityResponseAgent:fallback")
                fallback_errors.append({"agent": "SecurityResponseAgent", "error": resp_meta.get("error") or resp_meta.get("status"), "retry_attempts": resp_meta.get("attempts", 1)})
            else:
                agents_executed.append("SecurityResponseAgent")
        except Exception as e:
            logger.warning(f"SecurityResponseAgent error, using fallback: {e}")
            fallback_errors.append({"agent": "SecurityResponseAgent", "error": str(e)[:200]})
            resp_out = self.response_agent.get_deterministic_fallback(resp_inp)
            agents_executed.append("SecurityResponseAgent:fallback")
        agent_timings_ms["SecurityResponseAgent"] = round((time.monotonic() - _t0) * 1000, 2)

        # -------------------------------------------------------------
        # Step 6: SOC Monitoring Agent
        # -------------------------------------------------------------
        contain_status = "CONTAINED" if (effective_level == "CRITICAL" or sync_term_executed) else (
            getattr(resp_out, "lifecycle_status", "OPEN")
        )
        contain_actions = []
        if sync_term_executed or getattr(resp_out, "required_backend_operation", "") == "TERMINATE_SESSION":
            contain_actions.append("TERMINATE_SESSION")
        if getattr(resp_out, "containment_action", "") in ("GRANTS_REVOKED", "SESSION_REVOKED"):
            contain_actions.append("REVOKE_GRANTS")
        if getattr(resp_out, "required_backend_operation", "") == "LOCK_PORTAL":
            contain_actions.append("LOCK_PORTAL")

        soc_inp = SOCMonitoringInput(
            event_id=str(event_id or f"ev_{session_id or 'anon'}"),
            user_id=user_id,
            application=portal,
            time_window_minutes=60,
            risk_events=[{
                "id": event_id,
                "user_id": user_id,
                "session_id": session_id,
                "application": portal,
                "risk_level": effective_level,
                "risk_score": effective_score,
                "reasons": arb_res["reasons"],
                "trigger_event": trigger_event
            }],
            security_response=(resp_out.model_dump() if hasattr(resp_out, "model_dump") else None),
            containment_status=contain_status,
            containment_actions_taken=contain_actions
        )
        _t0 = time.monotonic()
        try:
            soc_out = await self.soc_agent.execute(soc_inp)
            soc_meta = getattr(self.soc_agent, "last_execution_meta", None) or {}
            if soc_meta.get("status") in ("FALLBACK", "TIMEOUT"):
                agents_executed.append("SOCMonitoringAgent:fallback")
                fallback_errors.append({"agent": "SOCMonitoringAgent", "error": soc_meta.get("error") or soc_meta.get("status"), "retry_attempts": soc_meta.get("attempts", 1)})
            else:
                agents_executed.append("SOCMonitoringAgent")
        except Exception as e:
            logger.warning(f"SOCMonitoringAgent error, using fallback: {e}")
            fallback_errors.append({"agent": "SOCMonitoringAgent", "error": str(e)[:200]})
            soc_out = self.soc_agent.get_deterministic_fallback(soc_inp)
            agents_executed.append("SOCMonitoringAgent:fallback")
        agent_timings_ms["SOCMonitoringAgent"] = round((time.monotonic() - _t0) * 1000, 2)

        duration_ms = round((time.monotonic() - start_t) * 1000, 2)
        exec_status = "CONTAINED" if (effective_level == "CRITICAL" or sync_term_executed) else ("CHALLENGED" if auth_out.step_up_required else "PERMITTED")
        llm_provider = getattr(self.llm_client, "provider_name", None) or settings.LLM_PROVIDER
        llm_model = (
            getattr(self.llm_client, "model_name", None)
            or getattr(settings, "GEMINI_MODEL", None)
            or settings.LLM_MODEL
        )

        observability = Sanitizer.sanitize_dict({
            "trigger_event": trigger_event,
            "correlation_id": corr_id,
            "idempotency_key": cache_key,
            "agents_executed": agents_executed,
            "agent_timings_ms": agent_timings_ms,
            "execution_status": exec_status,
            "duration_ms": duration_ms,
            "llm_provider": llm_provider,
            "llm_model": llm_model,
            "synchronous_kill_executed": sync_term_executed,
            "input_summary": {
                "portal": portal,
                "trigger_event": trigger_event,
                "deterministic_risk_score": round(float(deterministic_risk_score or 0.0), 4),
                "deterministic_risk_level": deterministic_risk_level,
                "raw_anomaly_score": round(float(raw_anomaly_score or 0.0), 4),
                "contributing_reasons": list(reasons[:6]),
                "protected_resource": protected_resource,
            },
            "deterministic_assessment": {
                "risk_score": round(float(deterministic_risk_score or 0.0), 4),
                "risk_level": deterministic_risk_level,
            },
            "agent_recommendation": {
                "recommended_risk_score": round(float(getattr(risk_out, "deterministic_risk_score", 0.0) or 0.0), 4),
                "recommended_risk_level": getattr(risk_out, "deterministic_risk_level", None),
                "threat_category": threat_cat,
                "recommended_factor": getattr(auth_out, "recommended_factor", None),
                "recommended_response": getattr(resp_out, "recommended_response", None),
            },
            "arbiter_decision": {
                "effective_risk_score": effective_score,
                "effective_risk_level": effective_level,
                "is_agent_accepted": is_accepted,
                "override_reason": override_reason,
                "policy_decision": auth_out.policy_decision,
                "recommended_factor": auth_out.recommended_factor,
            },
            "sanitized_outputs": {
                "context_summary": getattr(ctx_out, "context_summary", None),
                "risk_summary": getattr(risk_out, "human_readable_explanation", None) or getattr(risk_out, "rationale", None),
                "adaptive_auth_action": getattr(auth_out, "action", None),
                "adaptive_auth_factor": getattr(auth_out, "recommended_factor", None),
                "security_response": getattr(resp_out, "recommended_response", None),
                "soc_priority": getattr(soc_out, "incident_priority", None),
                "soc_summary": getattr(soc_out, "executive_summary", None),
            },
            "tool_calls": {
                "context_risk_signals": list(getattr(ctx_out, "risk_signals", []) or [])[:5],
                "auth_observed_facts": list(getattr(auth_out, "observed_facts", []) or [])[:5],
                "executed_backend_operations": getattr(resp_out, "execution_result", None),
            },
            "fallback_or_error": fallback_errors if fallback_errors else None,
        })

        result_payload = {
            "correlation_id": corr_id,
            "execution_status": exec_status,
            "execution_metadata": {
                "duration_ms": duration_ms,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "synchronous_kill_executed": sync_term_executed,
                "effective_risk_level": effective_level,
                "effective_risk_score": effective_score,
                "llm_provider": llm_provider,
                "llm_model": llm_model,
            },
            "observability": observability,
            "context": ctx_out,
            "risk_analysis": risk_out,
            "arbitrated_risk": arb_res,
            "adaptive_auth": auth_out,
            "security_response": resp_out,
            "soc_monitoring": soc_out
        }

        with self._lock:
            self._idempotency_cache[cache_key] = result_payload

        return result_payload

    @classmethod
    def persist_observability(
        cls,
        db: Optional[Session],
        event_id: Optional[int],
        user_id: int,
        session_id: Optional[str],
        application: str,
        trigger_event: str,
        orch_result: Optional[Dict[str, Any]]
    ) -> Optional[int]:
        """
        Persists sanitized orchestration observability into the existing SecurityEvent.details
        JSON column (or creates a SecurityEvent if no parent event_id exists).
        Never persists sensitive raw context or secrets, and fails soft.
        """
        if not db or not orch_result:
            return event_id
        obs = orch_result.get("observability")
        if not obs:
            return event_id
        sanitized_obs = Sanitizer.sanitize_dict(obs)
        try:
            if event_id is not None:
                ev = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
                if ev:
                    existing_details: Dict[str, Any] = {}
                    if ev.details:
                        try:
                            parsed = json.loads(ev.details)
                            if isinstance(parsed, dict):
                                existing_details = parsed
                            else:
                                existing_details = {"message": str(ev.details)}
                        except Exception:
                            existing_details = {"message": str(ev.details)}
                    existing_details["agentic_orchestration"] = sanitized_obs
                    ev.details = json.dumps(existing_details)
                    db.commit()
                    return ev.id

            arb = orch_result.get("arbitrated_risk") or {}
            ev_type = f"AGENTIC_{trigger_event}"
            ev_sev = str(arb.get("effective_risk_level") or "LOW").upper()
            ev_dec = str(orch_result.get("execution_status") or "PERMITTED")

            # Deduplicate identical noisy agentic audit events for the same session within 60s
            if session_id:
                recent_cutoff = datetime.now(timezone.utc) - timedelta(seconds=60)
                recent_same = (
                    db.query(SecurityEvent)
                    .filter(
                        SecurityEvent.session_id == session_id,
                        SecurityEvent.event_type == ev_type,
                        SecurityEvent.severity == ev_sev,
                        SecurityEvent.decision == ev_dec,
                        SecurityEvent.timestamp >= recent_cutoff,
                    )
                    .order_by(SecurityEvent.timestamp.desc())
                    .first()
                )
                if recent_same:
                    return recent_same.id

            ev = SecurityEvent(
                user_id=user_id,
                session_id=session_id,
                application=(SessionService.normalize_application(application) or "platform"),
                event_type=ev_type,
                severity=ev_sev,
                risk_score=float(arb.get("effective_risk_score") or 0.0),
                decision=ev_dec,
                details=json.dumps({"agentic_orchestration": sanitized_obs}),
            )
            db.add(ev)
            db.commit()
            db.refresh(ev)
            return ev.id
        except Exception as e:
            logger.warning(f"Failed to persist orchestration observability: {e}")
            try:
                db.rollback()
            except Exception:
                pass
            return event_id

    def run_bounded_sync(
        self,
        timeout_seconds: Optional[float] = None,
        **kwargs: Any
    ) -> Optional[Dict[str, Any]]:
        """
        Executes evaluate_session_security synchronously from a sync FastAPI route
        with a strict timeout budget. Returns None on timeout or error so
        deterministic enforcement is never delayed or weakened.
        """
        if not settings.AGENTIC_AI_ENABLED:
            return None

        budget = float(timeout_seconds or settings.AGENT_EXECUTION_TIMEOUT_SECONDS or 0.8)

        async def _runner():
            return await asyncio.wait_for(
                self.evaluate_session_security(**kwargs),
                timeout=budget
            )

        try:
            try:
                asyncio.get_running_loop()
                # Already inside a running loop: run in a helper thread to avoid RuntimeError
                holder: Dict[str, Any] = {}

                def _thread_target():
                    try:
                        holder["result"] = asyncio.run(_runner())
                    except Exception as exc:
                        holder["error"] = exc

                t = threading.Thread(target=_thread_target, daemon=True)
                t.start()
                t.join(timeout=budget + 0.1)
                if "error" in holder:
                    raise holder["error"]
                return holder.get("result")
            except RuntimeError:
                return asyncio.run(_runner())
        except asyncio.TimeoutError:
            logger.warning(f"SecurityOrchestrator bounded execution exceeded {budget}s timeout.")
            return None
        except Exception as e:
            logger.warning(f"SecurityOrchestrator bounded execution failed: {e}")
            return None

    @classmethod
    def dispatch_background(
        cls,
        db_session_factory: Optional[Callable[[], Session]] = None,
        db_bind: Any = None,
        llm_client: Optional[LLMClient] = None,
        event_id: Optional[int] = None,
        timeout_seconds: Optional[float] = None,
        **kwargs: Any
    ) -> Optional[threading.Thread]:
        """
        Best-effort, non-blocking in-process background orchestration for security events.
        - Opens an isolated DB session inside the daemon thread (never shares request DB sessions).
        - Bounded by strict execution timeout and safe cleanup.
        - Deduplicates duplicate / in-flight idempotency keys to avoid duplicate incidents.
        - Routes any arbiter-accepted risk escalation through deterministic DecisionService.
        - Records failures/timeouts in observability without affecting authentication.
        - Note: Best-effort in-process execution; does not guarantee delivery across process restarts.
        """
        if not settings.AGENTIC_AI_ENABLED:
            return None

        default_bg_budget = max(25.0, float(getattr(settings, "LLM_TIMEOUT_SECONDS", 2.0) or 2.0) * 10.0)
        budget = float(timeout_seconds) if timeout_seconds is not None else default_bg_budget
        user_id = kwargs.get("user_id")
        session_id = kwargs.get("session_id")
        application = kwargs.get("application", "platform")
        trigger_event = kwargs.get("trigger_event", "BACKGROUND_INCIDENT")
        idem_key = kwargs.get("idempotency_key")
        det_level = str(kwargs.get("deterministic_risk_level") or "LOW").upper()

        if idem_key:
            with cls._lock:
                if idem_key in cls._idempotency_cache or idem_key in cls._inflight_keys:
                    return None
                cls._inflight_keys.add(idem_key)

        def _bg_worker():
            bg_start = time.monotonic()
            from sqlalchemy.orm import sessionmaker
            from app.database.connection import SessionLocal
            if db_session_factory is not None:
                factory = db_session_factory
            elif db_bind is not None:
                factory = sessionmaker(autocommit=False, autoflush=False, bind=db_bind)
            else:
                factory = SessionLocal
            bg_db: Optional[Session] = None
            try:
                bg_db = factory()
                orch = cls(db=bg_db, llm_client=llm_client)

                async def _runner():
                    return await asyncio.wait_for(
                        orch.evaluate_session_security(**kwargs),
                        timeout=budget
                    )

                res = asyncio.run(_runner())
                if res and user_id is not None:
                    # If arbiter accepted an upward risk escalation, pass through deterministic DecisionService
                    arb = res.get("arbitrated_risk") or {}
                    eff_lvl = str(arb.get("effective_risk_level") or det_level).upper()
                    eff_score = float(arb.get("effective_risk_score") or kwargs.get("deterministic_risk_score") or 0.0)
                    tier_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
                    if session_id and tier_rank.get(eff_lvl, 0) > tier_rank.get(det_level, 0):
                        try:
                            from app.services.decision_service import DecisionService
                            DecisionService.enforce_zero_trust_decision(
                                db=bg_db,
                                user_id=user_id,
                                session_id=session_id,
                                application=application,
                                risk_score=eff_score,
                                anomaly_score=float(kwargs.get("raw_anomaly_score") or 0.0),
                                risk_level=eff_lvl,
                                contributing_factors=list(arb.get("reasons") or ["agent_escalated_scrutiny"]),
                            )
                        except Exception as esc_err:
                            logger.warning(f"Background deterministic escalation failed softly: {esc_err}")

                    # Route AdaptiveAuthAgent STEP_UP_REQUIRED recommendation through deterministic StepUpService
                    # after revalidating session ownership, portal isolation, active status, and non-duplication.
                    auth_out = res.get("adaptive_auth")
                    step_up_outcome = "NONE"
                    if (
                        auth_out is not None
                        and str(getattr(auth_out, "action", "")).upper() == "STEP_UP_REQUIRED"
                        and session_id
                        and (eff_lvl in ("MEDIUM", "HIGH") or kwargs.get("protected_resource") is not None)
                    ):
                        try:
                            from app.services.portal_lock_service import PortalLockService
                            norm_app = SessionService.normalize_application(application) or "platform"
                            cur_sess = SessionService.get_session(bg_db, session_id)
                            now_utc = datetime.now(timezone.utc)
                            is_valid_session = (
                                cur_sess is not None
                                and cur_sess.user_id == user_id
                                and (SessionService.normalize_application(cur_sess.application) or "platform") == norm_app
                                and cur_sess.status in ("ACTIVE", "STEP_UP_REQUIRED", "RESTRICTED")
                                and cur_sess.current_risk_level != "CRITICAL"
                                and not SessionService.is_session_expired(cur_sess)
                                and PortalLockService.get_active_lock(bg_db, user_id, norm_app) is None
                            )
                            if not is_valid_session:
                                step_up_outcome = "SKIPPED_INVALID_OR_LOCKED_SESSION"
                            else:
                                factor_map = {
                                    "COGNITIVE_DUAL": "HIGH_RISK_DUAL",
                                    "NEURAL_TRACE": "GESTURE_PATTERN",
                                    "COGNITIVE_IMAGE_SEQUENCE": "COGNITIVE_IMAGE_SEQUENCE",
                                    "PRIVATE_RESPONSE": "PRIVATE_RESPONSE",
                                    "EMAIL_OTP": "OTP",
                                }
                                factor_rank = {
                                    "OTP": 1,
                                    "PRIVATE_RESPONSE": 2,
                                    "COGNITIVE_IMAGE_SEQUENCE": 2,
                                    "GESTURE_PATTERN": 2,
                                    "HIGH_RISK_DUAL": 3,
                                }
                                prot_res = kwargs.get("protected_resource")
                                norm_prot_res = SessionService.normalize_resource(prot_res) if prot_res else None
                                if eff_lvl == "HIGH":
                                    min_det_factor = "HIGH_RISK_DUAL"
                                elif eff_lvl == "MEDIUM" or norm_prot_res in ("academic_vault", "financial_vault", "ehr_vault"):
                                    min_det_factor = "GESTURE_PATTERN"
                                else:
                                    min_det_factor = "OTP"

                                rec_factor = factor_map.get(str(getattr(auth_out, "recommended_factor", "")).upper())
                                min_det_rank = factor_rank[min_det_factor]
                                rec_rank = factor_rank.get(rec_factor or "", 0)
                                effective_required_rank = max(min_det_rank, rec_rank)
                                # Never pass a weaker factor than the deterministic tier/resource policy requires
                                safe_preferred_factor = rec_factor if (rec_factor and rec_rank >= min_det_rank) else None

                                existing_chal = StepUpService.get_challenge(session_id, norm_app)
                                existing_valid = bool(
                                    existing_chal
                                    and (existing_chal.get("expires_at") is None or existing_chal["expires_at"] > now_utc)
                                )
                                existing_rank = factor_rank.get(str(existing_chal.get("challenge_type", "")).upper(), 0) if existing_valid else 0
                                if existing_valid and existing_rank >= effective_required_rank:
                                    step_up_outcome = "EXISTING_ACTIVE_CHALLENGE_PRESERVED"
                                else:
                                    chal_purpose = "CONFIDENTIAL_RESOURCE" if norm_prot_res in ("academic_vault", "financial_vault", "ehr_vault") else "SESSION_STEP_UP"
                                    chal = StepUpService.create_adaptive_challenge(
                                        session_id=session_id,
                                        user_id=user_id,
                                        db=bg_db,
                                        risk_score=eff_score,
                                        risk_level=eff_lvl,
                                        preferred_factor=safe_preferred_factor,
                                        ttl_seconds=300,
                                        application=norm_app,
                                        resource=prot_res,
                                        challenge_purpose=chal_purpose,
                                    )
                                    step_up_outcome = f"CHALLENGE_CREATED:{chal.get('challenge_type')}"
                        except Exception as su_err:
                            logger.warning(f"Background StepUpService dispatch failed softly: {su_err}")
                            step_up_outcome = f"STEP_UP_REJECTED:{type(su_err).__name__}"

                    if isinstance(res.get("observability"), dict):
                        res["observability"]["step_up_service_outcome"] = step_up_outcome

                    # Route SecurityResponseAgent containment and alert recommendations through authorized backend services
                    resp_out = res.get("security_response")
                    sec_resp_outcome = "NONE"
                    if resp_out is not None and user_id is not None:
                        try:
                            from app.services.portal_lock_service import PortalLockService
                            from app.models.alert import Alert
                            norm_app = SessionService.normalize_application(application) or "platform"
                            req_op = str(getattr(resp_out, "required_backend_operation", "NONE")).upper().strip()
                            sec_resp_details = {}

                            # Unauthorized operation guard: agent must never unlock portal, grant access, or reduce risk
                            UNAUTHORIZED_OPS = {"UNLOCK_PORTAL", "GRANT_ACCESS", "VERIFY_FACTOR", "REDUCE_RISK", "BYPASS_AUTH"}
                            if req_op in UNAUTHORIZED_OPS:
                                logger.warning(f"Unauthorized security response operation rejected: {req_op}")
                                sec_resp_outcome = f"REJECTED_UNAUTHORIZED_OPERATION:{req_op}"
                            else:
                                skip_contain = bool(kwargs.get("skip_containment", False))
                                if skip_contain:
                                    sec_resp_details["containment"] = "SKIPPED_DUE_TO_FLAG"
                                else:
                                    # 1. Session Termination: enforce session ownership, portal match, and non-duplicate containment
                                    if req_op == "TERMINATE_SESSION" and session_id:
                                        cur_sess = SessionService.get_session(bg_db, session_id)
                                        if not cur_sess:
                                            sec_resp_details["session_termination"] = "SESSION_NOT_FOUND"
                                        elif cur_sess.user_id != user_id:
                                            sec_resp_details["session_termination"] = "REJECTED_BOLA_MISMATCH"
                                        elif (SessionService.normalize_application(cur_sess.application) or "platform") != norm_app:
                                            sec_resp_details["session_termination"] = "REJECTED_PORTAL_MISMATCH"
                                        elif cur_sess.status in ("TERMINATED", "REVOKED", "EXPIRED") or cur_sess.logout_time is not None:
                                            sec_resp_details["session_termination"] = "ALREADY_TERMINATED"
                                        else:
                                            SessionService.terminate_session(bg_db, session_id, risk_level=eff_lvl)
                                            sec_resp_details["session_termination"] = "TERMINATED"

                                    # 2. Grant Revocation: portal-isolated grant cleanup
                                    if req_op in ("TERMINATE_SESSION", "REVOKE_GRANTS") and session_id:
                                        cur_sess = SessionService.get_session(bg_db, session_id)
                                        if cur_sess and cur_sess.user_id == user_id:
                                            prot_res = kwargs.get("protected_resource")
                                            rev_count = SessionService.revoke_application_grants(
                                                bg_db,
                                                session_id=session_id,
                                                user_id=user_id,
                                                application=norm_app,
                                                resource=prot_res
                                            )
                                            sec_resp_details["grants_revoked_count"] = rev_count

                                    # 3. Portal Lockout: portal-scoped isolation
                                    if req_op == "LOCK_PORTAL" or str(getattr(resp_out, "containment_action", "")).upper() == "PORTAL_LOCKED":
                                        existing_lock = PortalLockService.get_active_lock(bg_db, user_id, norm_app)
                                        if existing_lock:
                                            sec_resp_details["portal_lock"] = "ALREADY_LOCKED"
                                        else:
                                            rec_reason = str(getattr(resp_out, "recommended_response", "Security incident automated lock"))
                                            lock_obj = PortalLockService.lock_portal(
                                                db=bg_db,
                                                user_id=user_id,
                                                application=norm_app,
                                                verification_purpose="SECURITY_INCIDENT",
                                                lock_reason=rec_reason[:255],
                                                failed_attempt_count=1,
                                                max_attempts=1,
                                                session_id=session_id
                                            )
                                            sec_resp_details["portal_lock"] = f"LOCKED:{lock_obj.id}"

                                # 4. SOC Alert Escalation (idempotent / deduplicated)
                                if getattr(resp_out, "alert_required", False) or eff_lvl in ("HIGH", "CRITICAL"):
                                    cat = str(getattr(resp_out, "incident_category", "INCIDENT")).upper()
                                    alert_type = f"{cat}_{eff_lvl}"
                                    existing_alert = bg_db.query(Alert).filter(
                                        Alert.user_id == user_id,
                                        Alert.application == norm_app.lower(),
                                        Alert.status.in_(["OPEN", "ACKNOWLEDGED", "INVESTIGATING"])
                                    ).first()
                                    if existing_alert:
                                        sec_resp_details["soc_alert"] = f"ALREADY_EXISTS:{existing_alert.id}"
                                        if (sec_resp_details.get("session_termination") == "TERMINATED" or sec_resp_details.get("portal_lock")) and existing_alert.status == "OPEN":
                                            existing_alert.status = "CONTAINED"
                                            bg_db.commit()
                                    else:
                                        is_contained = bool(sec_resp_details.get("session_termination") == "TERMINATED" or sec_resp_details.get("portal_lock"))
                                        new_alert = Alert(
                                            user_id=user_id,
                                            security_event_id=event_id,
                                            application=norm_app.lower(),
                                            alert_type=alert_type,
                                            message=f"[{eff_lvl}] {str(getattr(resp_out, 'recommended_response', 'Security response alert'))[:250]}",
                                            severity=eff_lvl,
                                            status="CONTAINED" if is_contained else "OPEN"
                                        )
                                        bg_db.add(new_alert)
                                        bg_db.commit()
                                        bg_db.refresh(new_alert)
                                        sec_resp_details["soc_alert"] = f"CREATED:{new_alert.id}"

                                # 5. Security Notification Delivery (fails soft: never undoes containment)
                                if getattr(resp_out, "user_notification_recommended", False):
                                    try:
                                        from app.models.user import User
                                        from app.services.email_service import EmailService
                                        user_record = bg_db.query(User).filter(User.id == user_id).first()
                                        if user_record and user_record.email:
                                            notif_info = getattr(resp_out, "notification_recommendation", {}) or {}
                                            notif_msg = notif_info.get("message") or f"A security event was detected on portal {norm_app}."
                                            email_ok, email_err = EmailService.send_email(
                                                recipient_email=user_record.email,
                                                subject=f"[COGNISEC-AI] Security Notice: {norm_app.upper()}",
                                                plain_text=f"Hello {user_record.name},\n\n{notif_msg}\n\nSeverity: {eff_lvl}\nStatus: Enforced."
                                            )
                                            sec_resp_details["notification"] = "SENT" if email_ok else f"DELIVERY_FAILED:{email_err}"
                                    except Exception as notif_err:
                                        logger.warning(f"Background notification dispatch failed softly: {notif_err}")
                                        sec_resp_details["notification"] = f"ERROR:{type(notif_err).__name__}"

                                sec_resp_outcome = "EXECUTED" if sec_resp_details else "NOOP"
                                if getattr(resp_out, "lifecycle_status", None):
                                    resp_out.lifecycle_status = "CONTAINED" if (
                                        sec_resp_details.get("session_termination") == "TERMINATED"
                                        or sec_resp_details.get("portal_lock")
                                    ) else ("EXECUTED" if sec_resp_details else "RESPONSE_RECOMMENDED")
                                resp_out.execution_result = sec_resp_details
                        except Exception as resp_err:
                            logger.warning(f"Background SecurityResponse coordination failed softly: {resp_err}")
                            sec_resp_outcome = f"ERROR:{type(resp_err).__name__}"

                    if isinstance(res.get("observability"), dict):
                        res["observability"]["security_response_service_outcome"] = sec_resp_outcome
                        res["observability"]["security_response_details"] = getattr(resp_out, "execution_result", None)

                    cls.persist_observability(
                        db=bg_db,
                        event_id=event_id,
                        user_id=user_id,
                        session_id=session_id,
                        application=application,
                        trigger_event=trigger_event,
                        orch_result=res,
                    )
            except Exception as e:
                err_kind = "TIMEOUT_FALLBACK" if isinstance(e, asyncio.TimeoutError) else "ERROR_FALLBACK"
                logger.warning(f"Background SecurityOrchestrator execution {err_kind}: {e}")
                if bg_db is not None and user_id is not None:
                    try:
                        bg_db.rollback()
                        cls.persist_observability(
                            db=bg_db,
                            event_id=event_id,
                            user_id=user_id,
                            session_id=session_id,
                            application=application,
                            trigger_event=trigger_event,
                            orch_result={
                                "execution_status": err_kind,
                                "arbitrated_risk": {
                                    "effective_risk_level": det_level,
                                    "effective_risk_score": float(kwargs.get("deterministic_risk_score") or 0.0),
                                },
                                "observability": {
                                    "correlation_id": kwargs.get("correlation_id"),
                                    "trigger_event": trigger_event,
                                    "agents_executed": [],
                                    "execution_status": err_kind,
                                    "duration_ms": round((time.monotonic() - bg_start) * 1000, 2),
                                    "llm_provider": settings.LLM_PROVIDER,
                                    "llm_model": getattr(settings, "GEMINI_MODEL", None) or settings.LLM_MODEL,
                                    "fallback_or_error": str(e)[:200] or type(e).__name__,
                                },
                            },
                        )
                    except Exception:
                        pass
            finally:
                if idem_key:
                    with cls._lock:
                        cls._inflight_keys.discard(idem_key)
                if bg_db is not None:
                    try:
                        bg_db.close()
                    except Exception:
                        pass

        t = threading.Thread(target=_bg_worker, daemon=True)
        t.start()
        with cls._lock:
            cls._background_threads = [th for th in cls._background_threads if th.is_alive()][-10:]
            cls._background_threads.append(t)
        return t
