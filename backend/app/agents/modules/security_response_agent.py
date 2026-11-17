"""
Security Response Agent Module.
Coordinates alerts, containment, and notification policies using verified outputs
from the Zero-Trust security engine and agent pipeline.
"""
import asyncio
import json
import logging
import secrets
import threading
from datetime import datetime, timezone
from typing import Optional, Set, Any, Dict, List
from sqlalchemy.orm import Session

from app.core.config import settings
from app.agents.core.base_agent import BaseAgent
from app.agents.core.llm_client import LLMClient, LLMRequest
from app.agents.core.tool import AgentTool, UnauthorizedToolError, ToolExecutionError
from app.agents.core.sanitization import Sanitizer
from app.agents.schemas.agent_schemas import (
    SecurityResponseInput,
    SecurityResponseOutput,
    generate_incident_id
)
from app.services.session_service import SessionService
from app.services.email_service import EmailService
from app.models.security_event import SecurityEvent
from app.models.alert import Alert
from app.models.application_grant import ApplicationGrant

logger = logging.getLogger(__name__)

DEFAULT_PERMITTED_TOOLS = {
    "terminate_session",
    "revoke_session_grants",
    "lock_portal",
    "send_security_alert_email",
    "create_security_alert",
    "record_security_event",
    "queue_security_notification_email"
}


class SecurityResponseAgent(BaseAgent):
    """
    Security Response Agent: Coordinates alerts, security notifications,
    containment plans, and incident tracking for detected security anomalies.
    """

    _lock = threading.RLock()
    _idempotency_cache: Dict[str, SecurityResponseOutput] = {}

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        permitted_tools: Optional[Set[str]] = None,
        timeout_seconds: Optional[float] = None,
        db: Optional[Session] = None
    ):
        super().__init__(
            name="SecurityResponseAgent",
            description="Coordinates alerts, containment, and notification policies for security incidents.",
            input_schema=SecurityResponseInput,
            output_schema=SecurityResponseOutput,
            permitted_tools=permitted_tools or DEFAULT_PERMITTED_TOOLS,
            llm_client=llm_client,
            timeout_seconds=timeout_seconds
        )
        self.db = db
        self._register_backend_tools()

    def _register_backend_tools(self) -> None:
        """Registers authorized, narrowly scoped backend execution tools with BOLA protections."""
        def tool_terminate_session(session_id: str, user_id: int, application: Optional[str] = None) -> Dict[str, Any]:
            if not self.db:
                return {"success": False, "reason": "No database session available"}
            sess = SessionService.get_session(self.db, session_id)
            if not sess:
                return {"success": False, "reason": f"Session {session_id} not found"}
            # BOLA ownership validation
            if sess.user_id != user_id:
                raise PermissionError(f"Session {session_id} does not belong to user {user_id}. Termination rejected.")
            # Portal isolation validation
            if application:
                norm_app = SessionService.normalize_application(application) or "platform"
                sess_app = SessionService.normalize_application(sess.application) or "platform"
                if norm_app != "platform" and sess_app != norm_app:
                    raise PermissionError(f"Session {session_id} belongs to portal '{sess_app}', not '{norm_app}'. Portal mismatch rejected.")
            # Idempotency check: avoid redundant termination if already terminated/revoked/expired
            if str(sess.status or "").upper() in ("TERMINATED", "REVOKED", "EXPIRED") or sess.logout_time is not None:
                return {"success": True, "session_id": session_id, "action": "ALREADY_TERMINATED", "status": sess.status}
            SessionService.terminate_session(self.db, session_id, risk_level="CRITICAL")
            return {"success": True, "session_id": session_id, "action": "TERMINATED"}

        def tool_revoke_session_grants(session_id: str, user_id: int, application: Optional[str] = None) -> Dict[str, Any]:
            if not self.db:
                return {"success": False, "reason": "No database session available"}
            sess = SessionService.get_session(self.db, session_id)
            if sess and sess.user_id != user_id:
                raise PermissionError(f"Session {session_id} does not belong to user {user_id}. Grant revocation rejected.")
            norm_app = SessionService.normalize_application(application) if application else None
            query = self.db.query(ApplicationGrant).filter(
                ApplicationGrant.session_id == session_id,
                ApplicationGrant.user_id == user_id,
                ApplicationGrant.revoked == False
            )
            if norm_app and norm_app != "platform":
                query = query.filter(ApplicationGrant.application == norm_app)
            revoked_count = query.update({"revoked": True})
            self.db.commit()
            return {"success": True, "session_id": session_id, "revoked_grants_count": revoked_count}

        def tool_lock_portal(user_id: int, application: str, reason: str, session_id: Optional[str] = None) -> Dict[str, Any]:
            if not self.db:
                return {"success": False, "reason": "No database session available"}
            norm_app = SessionService.normalize_application(application) or "platform"
            from app.services.portal_lock_service import PortalLockService
            existing = PortalLockService.get_active_lock(self.db, user_id, norm_app)
            if existing:
                return {"success": True, "action": "ALREADY_LOCKED", "lock_id": existing.id, "application": norm_app}
            lock_obj = PortalLockService.lock_portal(
                db=self.db,
                user_id=user_id,
                application=norm_app,
                verification_purpose="SECURITY_INCIDENT",
                lock_reason=(reason[:255] if reason else "Security Incident Automated Lock"),
                failed_attempt_count=1,
                max_attempts=1,
                session_id=session_id
            )
            return {"success": True, "action": "PORTAL_LOCKED", "lock_id": lock_obj.id, "application": norm_app}

        def tool_send_alert_email(recipient_email: str, subject: str, message: str) -> Dict[str, Any]:
            try:
                success, msg = EmailService.send_email(
                    recipient_email=recipient_email,
                    subject=subject,
                    plain_text=message
                )
                return {"success": success, "message": msg}
            except Exception as e:
                logger.warning(f"Notification email delivery failed: {e}")
                return {"success": False, "error": str(e)}

        def tool_create_alert(user_id: int, application: str, alert_type: str, message: str, severity: str, security_event_id: Optional[int] = None) -> Dict[str, Any]:
            if not self.db:
                return {"success": False, "reason": "No database session available"}
            norm_app = SessionService.normalize_application(application) or "platform"
            # Deduplication: prevent duplicate open alerts for same user, app, and type
            existing_alert = self.db.query(Alert).filter(
                Alert.user_id == user_id,
                Alert.application == norm_app.lower(),
                Alert.alert_type == alert_type,
                Alert.status == "OPEN"
            ).first()
            if existing_alert:
                return {"success": True, "action": "ALERT_REUSED", "alert_id": existing_alert.id}

            al = Alert(
                user_id=user_id,
                security_event_id=security_event_id,
                application=norm_app.lower(),
                alert_type=alert_type,
                message=message,
                severity=severity.upper(),
                status="OPEN"
            )
            self.db.add(al)
            self.db.commit()
            self.db.refresh(al)
            return {"success": True, "action": "ALERT_CREATED", "alert_id": al.id}

        def tool_record_sec_event(user_id: int, session_id: Optional[str], application: str, event_type: str, severity: str, details: str) -> Dict[str, Any]:
            if not self.db:
                return {"success": False, "reason": "No database session available"}
            ev = SecurityEvent(
                user_id=user_id,
                session_id=session_id,
                application=application.lower(),
                event_type=event_type,
                severity=severity.upper(),
                details=details
            )
            self.db.add(ev)
            self.db.commit()
            self.db.refresh(ev)
            return {"success": True, "event_id": ev.id}

        self.tools["terminate_session"] = AgentTool(
            name="terminate_session",
            description="Authoritatively terminates a user's session in the backend database.",
            func=tool_terminate_session,
            is_read_only=False
        )
        self.tools["revoke_session_grants"] = AgentTool(
            name="revoke_session_grants",
            description="Revokes all active application grants bound to a session.",
            func=tool_revoke_session_grants,
            is_read_only=False
        )
        self.tools["lock_portal"] = AgentTool(
            name="lock_portal",
            description="Authoritatively locks a portal for an account in the backend database.",
            func=tool_lock_portal,
            is_read_only=False
        )
        self.tools["send_security_alert_email"] = AgentTool(
            name="send_security_alert_email",
            description="Sends an email security notification via EmailService.",
            func=tool_send_alert_email,
            is_read_only=False
        )
        self.tools["queue_security_notification_email"] = self.tools["send_security_alert_email"]
        self.tools["create_security_alert"] = AgentTool(
            name="create_security_alert",
            description="Creates an administrative SOC Alert record in database.",
            func=tool_create_alert,
            is_read_only=False
        )
        self.tools["record_security_event"] = AgentTool(
            name="record_security_event",
            description="Logs an immutable SecurityEvent in the audit database.",
            func=tool_record_sec_event,
            is_read_only=False
        )

    def _evaluate_deterministic_policy(self, validated_input: SecurityResponseInput) -> Dict[str, Any]:
        """
        Computes authoritative zero-trust policy decision for the security incident.
        Consumes the authoritative deterministic risk level via RiskService.classify_risk_level
        and prevents any agent-driven downgrade below the deterministic floor.
        """
        from app.services.risk_service import RiskService

        score = float(validated_input.effective_risk_score)
        passed_level = (validated_input.effective_risk_level or "").upper().strip()

        # Authoritative canonical Zero Trust risk classifier:
        # LOW: score < 0.30
        # MEDIUM: 0.30 <= score < 0.65
        # HIGH: 0.65 <= score < 0.85
        # CRITICAL: score >= 0.85
        det_level = RiskService.classify_risk_level(score)

        # Monotonic Risk Floor:
        # Agent recommendation cannot downgrade below the authoritative deterministic risk level
        tier_ranks = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        if passed_level in tier_ranks and tier_ranks[passed_level] > tier_ranks[det_level]:
            effective_tier = passed_level
        else:
            effective_tier = det_level

        reasons = list(validated_input.reasons or [])
        portal = (validated_input.application or "platform").lower().strip()
        category = validated_input.threat_category

        # Classify threat category if not explicitly provided
        if not category:
            reasons_str = " ".join(reasons).lower()
            if "hijack" in reasons_str or "stolen token" in reasons_str or "session transfer" in reasons_str:
                category = "SESSION_HIJACKING"
            elif "takeover" in reasons_str or "credential stuffing" in reasons_str or "password spray" in reasons_str:
                category = "ACCOUNT_TAKEOVER"
            elif "lockout" in reasons_str or "locked portal" in reasons_str or "portal lock" in reasons_str:
                category = "PORTAL_LOCKOUT"
            elif "recovery" in reasons_str:
                category = "PORTAL_RECOVERY"
            elif "untrusted device" in reasons_str or "device trust" in reasons_str or (validated_input.device_trust and validated_input.device_trust.upper() == "REVOKED"):
                category = "DEVICE_TRUST_VIOLATION"
            elif "brute force" in reasons_str or "repeated" in reasons_str or "failed auth" in reasons_str:
                category = "REPEATED_AUTH_FAILURES"
            elif validated_input.protected_resource or "vault" in reasons_str:
                if portal == "shopping" and ("payment" in reasons_str or "fraud" in reasons_str or "card" in reasons_str):
                    category = "PAYMENT_FRAUD"
                elif portal == "college" and ("exam" in reasons_str or "proctor" in reasons_str):
                    category = "EXAM_AUTHORIZATION_VIOLATION"
                elif portal == "healthcare" and ("ehr" in reasons_str or "clinical" in reasons_str or "patient" in reasons_str):
                    category = "SUSPICIOUS_EHR_ACCESS"
                else:
                    category = "UNAUTHORIZED_VAULT_ACCESS"
            elif effective_tier == "CRITICAL":
                category = "CRITICAL_SECURITY_EVENT"
            elif effective_tier in ("MEDIUM", "HIGH"):
                category = "BEHAVIORAL_ANOMALY"
            else:
                category = "ROUTINE"

        observed_facts = [
            f"Risk Level: {effective_tier} (Score: {score:.4f}).",
            f"User ID: {validated_input.user_id}, Event Reference: '{validated_input.event_id}'.",
            f"Application Portal: '{portal}'.",
            f"Threat Category: '{category}'."
        ]
        if validated_input.session_id:
            observed_facts.append(f"Affected Session: '{validated_input.session_id}'.")
        if validated_input.protected_resource:
            observed_facts.append(f"Target Protected Resource: '{validated_input.protected_resource}'.")
        if validated_input.device_trust:
            observed_facts.append(f"Device Trust State: '{validated_input.device_trust}'.")
        if validated_input.active_challenges:
            observed_facts.append(f"Active Challenge Count: {len(validated_input.active_challenges)}.")

        # 1. CRITICAL Risk (effective_tier == "CRITICAL", score >= 0.85)
        if effective_tier == "CRITICAL":
            return {
                "severity": "CRITICAL",
                "incident_category": category if category != "ROUTINE" else "CRITICAL_SECURITY_EVENT",
                "required_backend_operation": "TERMINATE_SESSION",
                "containment_action": "SESSION_REVOKED",
                "alert_required": True,
                "user_notification_recommended": True,
                "recommended_response": f"CRITICAL incident ({category}): Immediate session termination and grant revocation enforced.",
                "risk_analysis_summary": f"Critical security threat ({category}) confirmed. Deterministic policy enforces immediate session kill.",
                "observed_facts": observed_facts,
                "supporting_evidence": reasons,
                "notification_recommendation": {
                    "user_alert_required": True,
                    "admin_alert_required": True,
                    "notification_type": "CRITICAL_SECURITY_ALERT",
                    "message": f"A critical security threat ({category}) occurred on your account. The affected session has been securely terminated."
                }
            }

        # 2. HIGH Risk (effective_tier == "HIGH", 0.65 <= score < 0.85)
        elif effective_tier == "HIGH":
            if category == "PORTAL_LOCKOUT":
                req_op = "LOCK_PORTAL"
                cont_act = "PORTAL_LOCKED"
            elif validated_input.protected_resource or category in ("PAYMENT_FRAUD", "EXAM_AUTHORIZATION_VIOLATION", "SUSPICIOUS_EHR_ACCESS", "UNAUTHORIZED_VAULT_ACCESS"):
                req_op = "REVOKE_GRANTS"
                cont_act = "GRANTS_REVOKED" if validated_input.protected_resource else "STEP_UP_ENFORCED"
            else:
                req_op = "ENFORCE_STEP_UP"
                cont_act = "STEP_UP_ENFORCED"

            return {
                "severity": "HIGH",
                "incident_category": category if category != "ROUTINE" else "BEHAVIORAL_ANOMALY",
                "required_backend_operation": req_op,
                "containment_action": cont_act,
                "alert_required": True,
                "user_notification_recommended": True,
                "recommended_response": f"HIGH risk ({category}): Enforce mandatory compound cognitive verification and isolate sensitive access.",
                "risk_analysis_summary": f"High behavioral risk detected ({category}). Step-up verification required.",
                "observed_facts": observed_facts,
                "supporting_evidence": reasons,
                "notification_recommendation": {
                    "user_alert_required": True,
                    "admin_alert_required": True,
                    "notification_type": "HIGH_RISK_ALERT",
                    "message": f"Unusual patterns ({category}) were detected during your session. Additional verification is required."
                }
            }

        # 3. MEDIUM Risk (effective_tier == "MEDIUM", 0.30 <= score < 0.65)
        elif effective_tier == "MEDIUM":
            if category == "PORTAL_LOCKOUT":
                req_op = "LOCK_PORTAL"
                cont_act = "PORTAL_LOCKED"
            elif validated_input.protected_resource:
                req_op = "REVOKE_GRANTS"
                cont_act = "GRANTS_REVOKED"
            else:
                req_op = "ENFORCE_STEP_UP"
                cont_act = "STEP_UP_ENFORCED"

            return {
                "severity": "MEDIUM",
                "incident_category": category if category != "ROUTINE" else "BEHAVIORAL_ANOMALY",
                "required_backend_operation": req_op,
                "containment_action": cont_act,
                "alert_required": True,
                "user_notification_recommended": False,
                "recommended_response": f"MEDIUM risk ({category}): Enforce biometric NeuralTrace route verification for protected activities.",
                "risk_analysis_summary": f"Moderate behavioral deviation flagged ({category}). Step-up challenge initiated.",
                "observed_facts": observed_facts,
                "supporting_evidence": reasons,
                "notification_recommendation": {
                    "user_alert_required": False,
                    "admin_alert_required": True,
                    "notification_type": "MEDIUM_RISK_WARNING",
                    "message": "Moderate behavioral anomaly recorded in security telemetry."
                }
            }

        # 4. LOW Risk (< 0.30 and level LOW)
        else:
            if category == "PORTAL_LOCKOUT":
                return {
                    "severity": "HIGH",
                    "incident_category": "PORTAL_LOCKOUT",
                    "required_backend_operation": "LOCK_PORTAL",
                    "containment_action": "PORTAL_LOCKED",
                    "alert_required": True,
                    "user_notification_recommended": True,
                    "recommended_response": f"Portal lockout enforced for {portal}.",
                    "risk_analysis_summary": f"Portal lockout triggered on {portal}.",
                    "observed_facts": observed_facts,
                    "supporting_evidence": reasons,
                    "notification_recommendation": {
                        "user_alert_required": True,
                        "admin_alert_required": True,
                        "notification_type": "PORTAL_LOCKED_ALERT",
                        "message": f"Access to portal {portal} has been locked following security violations."
                    }
                }
            elif category == "PORTAL_RECOVERY":
                return {
                    "severity": "LOW",
                    "incident_category": "PORTAL_RECOVERY",
                    "required_backend_operation": "RECORD_AUDIT",
                    "containment_action": "NONE",
                    "alert_required": False,
                    "user_notification_recommended": True,
                    "recommended_response": f"Portal recovery successfully verified for {portal}. Session restored.",
                    "risk_analysis_summary": f"Portal recovery completed via verified OTP on {portal}.",
                    "observed_facts": observed_facts,
                    "supporting_evidence": reasons or ["Recovery OTP verified"],
                    "notification_recommendation": {
                        "user_alert_required": True,
                        "admin_alert_required": False,
                        "notification_type": "PORTAL_RECOVERY_COMPLETED",
                        "message": f"Your access to portal {portal} has been successfully restored."
                    }
                }
            else:
                return {
                    "severity": "LOW",
                    "incident_category": "ROUTINE",
                    "required_backend_operation": "NONE",
                    "containment_action": "NONE",
                    "alert_required": False,
                    "user_notification_recommended": False,
                    "recommended_response": "Normal baseline activity: Continuous Zero-Trust monitoring remains active without interruption.",
                    "risk_analysis_summary": "Nominal behavioral signals observed within baseline boundaries.",
                    "observed_facts": observed_facts,
                    "supporting_evidence": reasons or ["Normal telemetry"],
                    "notification_recommendation": {
                        "user_alert_required": False,
                        "admin_alert_required": False,
                        "notification_type": "NONE",
                        "message": "Nominal telemetry verified."
                    }
                }

    def _execute_containment_operations(
        self,
        validated_input: SecurityResponseInput,
        pol_eval: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Executes authorized backend operations through registered sandboxed tools.
        Guarantees that notification delivery failures do not roll back or impede session termination.
        """
        results: Dict[str, Any] = {"terminated": False, "grants_revoked": False, "portal_locked": False, "alert_created": False, "email_sent": False}
        req_op = pol_eval["required_backend_operation"]
        sess_id = validated_input.session_id
        uid = validated_input.user_id

        # Unauthorized operations are strictly blocked
        UNAUTHORIZED_OPS = {"UNLOCK_PORTAL", "GRANT_ACCESS", "VERIFY_FACTOR", "REDUCE_RISK", "BYPASS_AUTH"}
        if req_op in UNAUTHORIZED_OPS:
            logger.warning(f"Unauthorized security operation rejected: {req_op}")
            results["unauthorized_operation_rejected"] = req_op
            return results

        # 1. Session Termination
        if req_op == "TERMINATE_SESSION" and sess_id:
            try:
                term_res = self.execute_tool("terminate_session", session_id=sess_id, user_id=uid, application=validated_input.application)
                results["terminated"] = term_res.get("success", False)
                if term_res.get("action"):
                    results["termination_action"] = term_res["action"]
            except Exception as e:
                logger.error(f"Error terminating session {sess_id}: {e}")
                results["termination_error"] = str(e)

        # 2. Grant Revocation (portal-isolated)
        if req_op in ("TERMINATE_SESSION", "REVOKE_GRANTS") and sess_id:
            try:
                grant_res = self.execute_tool("revoke_session_grants", session_id=sess_id, user_id=uid, application=validated_input.application)
                results["grants_revoked"] = grant_res.get("success", False)
                results["grants_revoked_count"] = grant_res.get("revoked_grants_count", 0)
            except Exception as e:
                logger.error(f"Error revoking grants for session {sess_id}: {e}")
                results["grant_revocation_error"] = str(e)

        # 3. Portal Lockout
        if req_op == "LOCK_PORTAL" and uid:
            try:
                lock_res = self.execute_tool(
                    "lock_portal",
                    user_id=uid,
                    application=validated_input.application,
                    reason=pol_eval.get("recommended_response", "Security Incident Lock"),
                    session_id=sess_id
                )
                results["portal_locked"] = lock_res.get("success", False)
                if lock_res.get("lock_id"):
                    results["lock_id"] = lock_res["lock_id"]
                if lock_res.get("action"):
                    results["portal_lock_action"] = lock_res["action"]
            except Exception as e:
                logger.error(f"Error locking portal: {e}")
                results["portal_lock_error"] = str(e)

        # 4. Administrative Alert Creation
        if pol_eval.get("alert_required", False) and self.db:
            try:
                al_res = self.execute_tool(
                    "create_security_alert",
                    user_id=uid,
                    application=validated_input.application,
                    alert_type=f"{pol_eval['incident_category']}_{pol_eval['severity']}",
                    message=f"[{pol_eval['severity']}] {pol_eval['recommended_response']} (Event {validated_input.event_id})",
                    severity=pol_eval["severity"]
                )
                results["alert_created"] = al_res.get("success", False)
                if al_res.get("alert_id"):
                    results["alert_id"] = al_res["alert_id"]
                if al_res.get("action"):
                    results["alert_action"] = al_res["action"]
            except Exception as e:
                logger.warning(f"Error creating administrative alert: {e}")

        # 5. Security Notification Delivery (fails soft so containment remains intact)
        notif_rec = pol_eval.get("notification_recommendation", {})
        if notif_rec.get("user_alert_required", False) and self.db:
            try:
                from app.models.user import User
                user = self.db.query(User).filter(User.id == uid).first()
                if user and user.email:
                    email_res = self.execute_tool(
                        "send_security_alert_email",
                        recipient_email=user.email,
                        subject=f"[COGNISEC-AI] Security Alert: {pol_eval['incident_category']}",
                        message=f"Hello {user.name},\n\n{notif_rec.get('message', 'A security incident was detected.')}\n\nEvent Reference: {validated_input.event_id}\nSeverity: {pol_eval['severity']}\nTime (UTC): {datetime.now(timezone.utc).isoformat()}"
                    )
                    results["email_sent"] = email_res.get("success", False)
                    if not email_res.get("success", False):
                        results["email_error"] = email_res.get("error") or "Failed to deliver email"
            except Exception as e:
                logger.warning(f"Notification email dispatch error: {e}")
                results["email_error"] = str(e)

        return results

    async def _run_reasoning(self, validated_input: SecurityResponseInput) -> SecurityResponseOutput:
        """
        Executes reasoning using authoritative zero-trust policy evaluation,
        LLM contextual enrichment, output arbitration, and idempotent execution.
        """
        # Idempotency check
        cache_key = validated_input.idempotency_key or f"{validated_input.user_id}:{validated_input.event_id}:{validated_input.effective_risk_level}"
        with self._lock:
            if cache_key in self._idempotency_cache:
                return self._idempotency_cache[cache_key]

        pol_eval = self._evaluate_deterministic_policy(validated_input)

        # Build prompt with sanitized ground truth
        facts_clean = Sanitizer.sanitize_dict(pol_eval)
        prompt = (
            f"Formulate a structured Security Incident Response Plan based strictly on the verified facts below.\n\n"
            f"<SECURITY_CONTEXT>\n{json.dumps(facts_clean, indent=2)}\n</SECURITY_CONTEXT>\n\n"
            f"Instructions:\n"
            f"1. You must NOT downgrade severity ({pol_eval['severity']}) or the required backend operation ({pol_eval['required_backend_operation']}).\n"
            f"2. Separate observed facts from inferred threat narrative.\n"
            f"3. Return a JSON object with keys: incident_category, severity, risk_analysis_summary, recommended_response, required_backend_operation, containment_action, user_notification_recommended."
        )

        request = LLMRequest(
            prompt=prompt,
            system_instruction="You are the Cognisec Security Response Agent. Coordinate containment and incident response strictly bounded by Zero-Trust policy.",
            response_schema={"type": "object"}
        )

        resp = await self.llm_client.generate(request)
        proposed_severity = pol_eval["severity"]
        proposed_backend_op = pol_eval["required_backend_operation"]
        proposed_category = pol_eval["incident_category"]
        proposed_response = pol_eval["recommended_response"]
        proposed_summary = pol_eval["risk_analysis_summary"]

        if resp.parsed_json and isinstance(resp.parsed_json, dict):
            # Enforce Monotonic Output Arbiter: LLM cannot downgrade severity or backend operation
            llm_sev = str(resp.parsed_json.get("severity", "")).upper().strip()
            tier_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
            if llm_sev in tier_rank and tier_rank[llm_sev] >= tier_rank[pol_eval["severity"]]:
                proposed_severity = llm_sev

            llm_op = str(resp.parsed_json.get("required_backend_operation", "")).upper().strip()
            # Block any unauthorized operations
            UNAUTHORIZED_OPS = {"UNLOCK_PORTAL", "GRANT_ACCESS", "VERIFY_FACTOR", "REDUCE_RISK", "BYPASS_AUTH"}
            if llm_op in UNAUTHORIZED_OPS:
                llm_op = pol_eval["required_backend_operation"]

            # If policy requires termination, LLM cannot propose anything weaker
            if pol_eval["required_backend_operation"] == "TERMINATE_SESSION":
                proposed_backend_op = "TERMINATE_SESSION"
            elif pol_eval["required_backend_operation"] == "LOCK_PORTAL":
                proposed_backend_op = "TERMINATE_SESSION" if llm_op == "TERMINATE_SESSION" else "LOCK_PORTAL"
            elif pol_eval["required_backend_operation"] in ("ENFORCE_STEP_UP", "REVOKE_GRANTS") and llm_op in ("ENFORCE_STEP_UP", "REVOKE_GRANTS", "LOCK_PORTAL", "TERMINATE_SESSION"):
                proposed_backend_op = llm_op
            
            if resp.parsed_json.get("recommended_response"):
                proposed_response = str(resp.parsed_json["recommended_response"])
            if resp.parsed_json.get("risk_analysis_summary"):
                proposed_summary = str(resp.parsed_json["risk_analysis_summary"])

        # Containment execution if requested
        exec_res = None
        status = "RESPONSE_RECOMMENDED"
        if validated_input.auto_execute_containment or pol_eval["severity"] == "CRITICAL":
            exec_res = self._execute_containment_operations(validated_input, pol_eval)
            status = "RESPONSE_EXECUTED" if exec_res.get("terminated") or exec_res.get("grants_revoked") or exec_res.get("portal_locked") or exec_res.get("alert_created") else "RESPONSE_RECOMMENDED"
            if exec_res.get("email_sent"):
                status = "NOTIFIED"

        out = SecurityResponseOutput(
            incident_id=generate_incident_id(),
            incident_category=proposed_category,
            severity=proposed_severity,
            affected_session_reference=validated_input.session_id,
            application_portal=validated_input.application,
            observed_facts=pol_eval["observed_facts"],
            supporting_evidence=pol_eval["supporting_evidence"],
            risk_analysis_summary=proposed_summary,
            recommended_response=proposed_response,
            required_backend_operation=proposed_backend_op,
            notification_recommendation=pol_eval["notification_recommendation"],
            audit_metadata={"idempotency_key": cache_key, "event_id": validated_input.event_id},
            lifecycle_status=status,
            execution_result=exec_res,
            alert_required=pol_eval["alert_required"],
            alert_severity=proposed_severity,
            alert_summary=proposed_response,
            containment_action=pol_eval["containment_action"],
            user_notification_recommended=pol_eval["user_notification_recommended"]
        )

        with self._lock:
            self._idempotency_cache[cache_key] = out

        return out

    def get_deterministic_fallback(self, input_data: Any) -> SecurityResponseOutput:
        """
        Deterministic, fail-secure fallback that strictly applies backend Zero-Trust policy
        without relying on external LLM services. Guaranteed never to fail or raise exceptions.
        """
        try:
            if isinstance(input_data, dict):
                validated_input = SecurityResponseInput(**input_data)
            elif isinstance(input_data, SecurityResponseInput):
                validated_input = input_data
            else:
                validated_input = SecurityResponseInput.model_validate(input_data)
        except Exception:
            uid = getattr(input_data, "user_id", 0)
            score = getattr(input_data, "effective_risk_score", 0.0)
            level = getattr(input_data, "effective_risk_level", "LOW")
            ev_id = getattr(input_data, "event_id", "unknown_event")
            validated_input = SecurityResponseInput(
                user_id=int(uid) if isinstance(uid, (int, float)) else 0,
                event_id=str(ev_id),
                effective_risk_score=float(score) if isinstance(score, (int, float)) else 0.0,
                effective_risk_level=str(level) if str(level) in ("LOW", "MEDIUM", "HIGH", "CRITICAL") else "LOW"
            )

        cache_key = validated_input.idempotency_key or f"{validated_input.user_id}:{validated_input.event_id}:{validated_input.effective_risk_level}"
        with self._lock:
            if cache_key in self._idempotency_cache:
                return self._idempotency_cache[cache_key]

        pol_eval = self._evaluate_deterministic_policy(validated_input)

        exec_res = None
        status = "RESPONSE_RECOMMENDED"
        if validated_input.auto_execute_containment or pol_eval["severity"] == "CRITICAL":
            exec_res = self._execute_containment_operations(validated_input, pol_eval)
            status = "RESPONSE_EXECUTED" if exec_res.get("terminated") or exec_res.get("grants_revoked") or exec_res.get("portal_locked") or exec_res.get("alert_created") else "RESPONSE_RECOMMENDED"
            if exec_res.get("email_sent"):
                status = "NOTIFIED"

        out = SecurityResponseOutput(
            incident_id=generate_incident_id(),
            incident_category=pol_eval["incident_category"],
            severity=pol_eval["severity"],
            affected_session_reference=validated_input.session_id,
            application_portal=validated_input.application,
            observed_facts=pol_eval["observed_facts"],
            supporting_evidence=pol_eval["supporting_evidence"],
            risk_analysis_summary=pol_eval["risk_analysis_summary"],
            recommended_response=f"Deterministic fallback: {pol_eval['recommended_response']}",
            required_backend_operation=pol_eval["required_backend_operation"],
            notification_recommendation=pol_eval["notification_recommendation"],
            audit_metadata={"idempotency_key": cache_key, "event_id": validated_input.event_id, "fallback": True},
            lifecycle_status=status,
            execution_result=exec_res,
            alert_required=pol_eval["alert_required"],
            alert_severity=pol_eval["severity"],
            alert_summary=pol_eval["recommended_response"],
            containment_action=pol_eval["containment_action"],
            user_notification_recommended=pol_eval["user_notification_recommended"]
        )

        with self._lock:
            self._idempotency_cache[cache_key] = out

        return out
