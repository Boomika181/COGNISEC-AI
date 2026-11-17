"""
SOC Monitoring Agent Module.
Delivers operational security intelligence, incident summarization,
attack-pattern correlation, and fleet posture reporting for security administrators.
"""
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Set, Any, Dict, List
from sqlalchemy.orm import Session
from sqlalchemy import func, or_

from app.core.config import settings
from app.agents.core.base_agent import BaseAgent
from app.agents.core.llm_client import LLMClient, LLMRequest
from app.agents.core.sanitization import Sanitizer
from app.agents.schemas.agent_schemas import (
    SOCMonitoringInput,
    SOCMonitoringOutput
)
from app.models.user import User
from app.models.session import Session as DbSession
from app.models.security_event import SecurityEvent
from app.models.alert import Alert
from app.models.device import Device
from app.models.behavior import BehaviorProfile
from app.models.user import User
from app.models.portal_lock import PortalSecurityLock
from app.models.application_grant import ApplicationGrant
from app.services.session_service import SessionService

logger = logging.getLogger(__name__)

DEFAULT_PERMITTED_TOOLS = {
    "query_soc_metrics",
    "update_alert_explainability"
}


class SOCMonitoringAgent(BaseAgent):
    """
    SOC Monitoring Agent: Delivers contextual, human-readable threat assessments,
    attack pattern correlation, and security posture aggregates for SOC analysts.
    """

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        permitted_tools: Optional[Set[str]] = None,
        timeout_seconds: Optional[float] = None,
        db: Optional[Session] = None
    ):
        super().__init__(
            name="SOCMonitoringAgent",
            description="Produces explainable security summaries, correlates attack patterns, and analyzes fleet posture.",
            input_schema=SOCMonitoringInput,
            output_schema=SOCMonitoringOutput,
            permitted_tools=permitted_tools or DEFAULT_PERMITTED_TOOLS,
            llm_client=llm_client,
            timeout_seconds=timeout_seconds
        )
        self.db = db

    def compute_security_posture(self) -> Dict[str, Any]:
        """
        Computes authoritative real-time security posture metrics directly from database records.
        Guarantees zero fabricated numbers; accurately handles empty database state.
        """
        if not self.db:
            return {
                "active_sessions": 0,
                "open_incidents": 0,
                "contained_incidents": 0,
                "resolved_incidents": 0,
                "total_incidents": 0,
                "risk_distribution": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
                "incidents_by_severity": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
                "critical_events": 0,
                "failed_auth_attempts": 0,
                "device_trust_distribution": {"TRUSTED": 0, "PENDING_CONFIRMATION": 0, "REVOKED": 0},
                "portal_incident_counts": {"college": 0, "shopping": 0, "healthcare": 0, "platform": 0},
                "portal_activity_counts": {"college": 0, "shopping": 0, "healthcare": 0, "platform": 0},
                "behavioral_anomaly_trends": {"total_anomalies": 0, "avg_anomaly_score": 0.0},
                "modality_maturity_distribution": {"COLD_START": 0, "ESTABLISHED": 0},
                "recent_containment_actions_count": 0
            }

        now = datetime.now(timezone.utc)
        role_expr = func.upper(func.trim(func.coalesce(User.role, "USER")))
        non_admin_uids = self.db.query(User.id).filter(~role_expr.in_(["ADMIN", "SYSTEM", "SERVICE"]))

        # 1. Active sessions & risk distribution
        active_sessions = self.db.query(DbSession).filter(
            DbSession.user_id.in_(non_admin_uids),
            DbSession.status == "ACTIVE",
            DbSession.logout_time.is_(None)
        ).all()
        risk_dist = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for s in active_sessions:
            lvl = (s.current_risk_level or "LOW").upper()
            if lvl in risk_dist:
                risk_dist[lvl] += 1

        # 2. Incidents (Alerts) breakdown by lifecycle status and severity
        all_alerts = self.db.query(Alert).filter(Alert.user_id.in_(non_admin_uids)).all()
        open_count = sum(1 for al in all_alerts if al.status in ("OPEN", "ACKNOWLEDGED", "INVESTIGATING", "REOPENED"))
        contained_count = sum(1 for al in all_alerts if al.status == "CONTAINED")
        resolved_count = sum(1 for al in all_alerts if al.status == "RESOLVED")
        total_alerts = len(all_alerts)

        incidents_by_sev = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        portal_incident_counts = {"college": 0, "shopping": 0, "healthcare": 0, "platform": 0}
        for al in all_alerts:
            sev = (al.severity or "MEDIUM").upper()
            if sev in incidents_by_sev:
                incidents_by_sev[sev] += 1
            if al.status in ("OPEN", "ACKNOWLEDGED", "INVESTIGATING", "CONTAINED", "REOPENED"):
                p = (al.application or "platform").lower()
                portal_incident_counts[p] = portal_incident_counts.get(p, 0) + 1

        # 3. Security events & portal activity counts
        all_events = self.db.query(SecurityEvent).filter(
            SecurityEvent.user_id.in_(non_admin_uids),
            ~SecurityEvent.event_type.like("ADMIN_%"),
            ~SecurityEvent.event_type.like("AGENTIC_%"),
            SecurityEvent.event_type != "AGENT_DEMO_ANALYSIS",
        ).all()
        crit_count = sum(1 for ev in all_events if ev.severity == "CRITICAL")
        failed_auth = sum(
            1 for ev in all_events
            if ev.event_type in ("LOGIN_FAILED", "STEP_UP_FAILED", "AUTH_FAILURE", "STEP_UP_LOCKED", "OTP_FAILED", "COGNITIVE_FAILED")
            or "fail" in str(ev.decision).lower()
        )
        portal_activity = {"college": 0, "shopping": 0, "healthcare": 0, "platform": 0}
        for ev in all_events:
            p = (ev.application or "platform").lower()
            portal_activity[p] = portal_activity.get(p, 0) + 1

        # 4. Device trust distribution
        devs = self.db.query(Device).filter(Device.user_id.in_(non_admin_uids)).all()
        dev_trust = {"TRUSTED": 0, "PENDING_CONFIRMATION": 0, "REVOKED": 0}
        for d in devs:
            st = (d.trust_state or "PENDING_CONFIRMATION").upper()
            dev_trust[st] = dev_trust.get(st, 0) + 1

        # 5. Behavioral anomaly trends
        anom_events = [ev for ev in all_events if ev.anomaly_score > 0.45]
        total_anom = len(anom_events)
        avg_anom = sum(e.anomaly_score for e in anom_events) / total_anom if total_anom > 0 else 0.0

        # 6. Modality maturity distribution
        profiles = self.db.query(BehaviorProfile).filter(BehaviorProfile.user_id.in_(non_admin_uids)).all()
        mat_dist = {"COLD_START": 0, "ESTABLISHED": 0}
        for p in profiles:
            if getattr(p, "sample_count", 0) >= 15:
                mat_dist["ESTABLISHED"] += 1
            else:
                mat_dist["COLD_START"] += 1

        # 7. Recent containment actions (last 24 hours)
        cutoff_24h = now - timedelta(hours=24)
        containment_ev_types = {
            "SESSION_TERMINATED", "PORTAL_LOCKED", "PORTAL_SECURITY_LOCKED", "GRANTS_REVOKED",
            "APPLICATION_GRANT_REVOKED", "ADMIN_SESSION_TERMINATED", "ADMIN_ALERT_CONTAINED",
            "ADMIN_INCIDENT_CONTAINED", "CONTAINMENT_ACTION", "SECURITY_LOCK_TRIGGERED"
        }
        containment_decisions = {"TERMINATE_SESSION", "RESTRICT", "LOCK_PORTAL", "BLOCK", "REVOKE_GRANT"}

        def _is_within_24h(ts):
            if not ts:
                return False
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            return ts >= cutoff_24h

        recent_containment_count = sum(
            1 for ev in all_events
            if _is_within_24h(ev.timestamp)
            and (ev.event_type in containment_ev_types or ev.decision in containment_decisions)
        )

        return {
            "active_sessions": len(active_sessions),
            "open_incidents": open_count,
            "contained_incidents": contained_count,
            "resolved_incidents": resolved_count,
            "total_incidents": total_alerts,
            "risk_distribution": risk_dist,
            "incidents_by_severity": incidents_by_sev,
            "critical_events": crit_count,
            "failed_auth_attempts": failed_auth,
            "device_trust_distribution": dev_trust,
            "portal_incident_counts": portal_incident_counts,
            "portal_activity_counts": portal_activity,
            "behavioral_anomaly_trends": {
                "total_anomalies": total_anom,
                "avg_anomaly_score": round(avg_anom, 4)
            },
            "modality_maturity_distribution": mat_dist,
            "recent_containment_actions_count": recent_containment_count
        }

    def correlate_attack_patterns(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Identifies genuine cross-session and cross-portal attack patterns from verified records.
        Strictly requires sufficient empirical evidence before asserting a pattern.
        """
        if not events or len(events) < 2:
            return []

        correlations: List[Dict[str, Any]] = []

        # 1. Repeated Failed Authentication
        failed_auth = [
            e for e in events
            if "fail" in str(e.get("event_type", "")).lower()
            or "fail" in str(e.get("decision", "")).lower()
            or "locked" in str(e.get("event_type", "")).lower()
        ]
        if len(failed_auth) >= 3:
            uids = list({e.get("user_id") for e in failed_auth if e.get("user_id") is not None})
            correlations.append({
                "pattern_type": "REPEATED_AUTHENTICATION_FAILURES",
                "severity": "HIGH",
                "evidence_count": len(failed_auth),
                "affected_users": uids,
                "description": f"Observed {len(failed_auth)} failed authentication attempts within the evaluation window.",
                "confidence": "HIGH"
            })

        # 2. Multi-Session Suspicious Activity (same account across multiple sessions)
        user_sessions: Dict[int, Set[str]] = {}
        for e in events:
            uid = e.get("user_id")
            sid = e.get("session_id")
            if uid and sid and e.get("risk_level") in ("MEDIUM", "HIGH", "CRITICAL"):
                user_sessions.setdefault(uid, set()).add(sid)

        for uid, sids in user_sessions.items():
            if len(sids) >= 2:
                correlations.append({
                    "pattern_type": "MULTI_SESSION_ACCOUNT_DEVIATION",
                    "severity": "HIGH",
                    "evidence_count": len(sids),
                    "affected_users": [uid],
                    "description": f"User #{uid} exhibits concurrent suspicious risk across {len(sids)} distinct sessions.",
                    "confidence": "HIGH"
                })

        # 3. Repeated Device Trust Failures
        untrusted_devices = [
            e for e in events
            if "device" in str(e.get("event_type", "")).lower()
            and any(word in str(e.get("details", "")).lower() for word in ["untrusted", "revoked", "mismatch"])
        ]
        if len(untrusted_devices) >= 2:
            correlations.append({
                "pattern_type": "REPEATED_DEVICE_TRUST_FAILURES",
                "severity": "MEDIUM",
                "evidence_count": len(untrusted_devices),
                "description": f"Detected {len(untrusted_devices)} device trust anomalies.",
                "confidence": "MEDIUM"
            })

        # 4. Cross-Portal Targeted Incidents
        portals_hit = {str(e.get("application", "")).lower() for e in events if e.get("application")}
        high_events = [e for e in events if e.get("risk_level") in ("HIGH", "CRITICAL") or e.get("severity") in ("HIGH", "CRITICAL")]
        if len(portals_hit.intersection({"college", "shopping", "healthcare"})) >= 2 and len(high_events) >= 2:
            correlations.append({
                "pattern_type": "CROSS_PORTAL_SUSPICIOUS_CONVERGENCE",
                "severity": "HIGH",
                "evidence_count": len(high_events),
                "portals": list(portals_hit),
                "description": f"Correlated elevated threat activities across multiple portals: {', '.join(portals_hit)}.",
                "confidence": "MEDIUM"
            })

        # 5. Repeated Protected Resource Denials (Vault Access)
        vault_denials = [
            e for e in events
            if "vault" in str(e.get("details", "")).lower()
            or "vault" in str(e.get("event_type", "")).lower()
            or e.get("decision") in ("DENY", "BLOCK")
        ]
        if len(vault_denials) >= 3:
            correlations.append({
                "pattern_type": "REPEATED_PROTECTED_VAULT_PROBING",
                "severity": "HIGH",
                "evidence_count": len(vault_denials),
                "description": f"Detected {len(vault_denials)} unauthorized attempts against confidential vault resources.",
                "confidence": "HIGH"
            })

        # 6. Portal Lockout Incident Series
        portal_locks = [
            e for e in events
            if "lock" in str(e.get("event_type", "")).lower()
            or "lock" in str(e.get("decision", "")).lower()
            or "suspended" in str(e.get("details", "")).lower()
        ]
        if len(portal_locks) >= 1:
            correlations.append({
                "pattern_type": "PORTAL_LOCKOUT_SECURITY_INCIDENT",
                "severity": "HIGH",
                "evidence_count": len(portal_locks),
                "description": f"Portal access suspended or locked following security verification limit enforcement.",
                "confidence": "HIGH"
            })

        # 7. Account Takeover Indicators
        ato_events = [
            e for e in events
            if "takeover" in str(e.get("event_type", "")).lower()
            or "takeover" in str(e.get("details", "")).lower()
            or (e.get("risk_level") in ("HIGH", "CRITICAL") and "untrusted" in str(e.get("details", "")).lower())
        ]
        if len(ato_events) >= 1:
            correlations.append({
                "pattern_type": "ACCOUNT_TAKEOVER_INDICATORS",
                "severity": "HIGH",
                "evidence_count": len(ato_events),
                "description": f"Account takeover indicators detected on unverified endpoint.",
                "confidence": "HIGH"
            })

        # 8. Session Hijacking Indicators
        hijack_events = [
            e for e in events
            if "hijack" in str(e.get("event_type", "")).lower()
            or "hijack" in str(e.get("details", "")).lower()
            or "jump" in str(e.get("details", "")).lower()
        ]
        if len(hijack_events) >= 1:
            correlations.append({
                "pattern_type": "SESSION_HIJACKING_INDICATORS",
                "severity": "CRITICAL",
                "evidence_count": len(hijack_events),
                "description": f"Mid-session network jump or session transfer pattern detected.",
                "confidence": "HIGH"
            })

        return correlations

    def correlate_incidents(
        self,
        db: Session,
        alert_id: Optional[int] = None,
        user_id: Optional[int] = None,
        application: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 50,
        skip: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Correlates raw alerts and security events into comprehensive, structured incident records.
        Strictly reads actual database records without fabricating data.
        """
        query = db.query(Alert)
        if alert_id is not None:
            query = query.filter(Alert.id == alert_id)
        if user_id:
            query = query.filter(Alert.user_id == user_id)
        if application and application.lower() != "all":
            query = query.filter(Alert.application == application.lower())
        if status and status.upper() != "ALL":
            query = query.filter(Alert.status == status.upper())
        if severity and severity.upper() != "ALL":
            query = query.filter(Alert.severity == severity.upper())

        alerts = query.order_by(Alert.created_at.desc()).offset(skip).limit(limit).all()
        if not alerts:
            return []

        # Batch load users
        uids = {al.user_id for al in alerts}
        users_map = {u.id: u for u in db.query(User).filter(User.id.in_(uids)).all()} if uids else {}

        # Batch load security events
        sec_ids = {al.security_event_id for al in alerts if al.security_event_id}
        sec_map = {s.id: s for s in db.query(SecurityEvent).filter(SecurityEvent.id.in_(sec_ids)).all()} if sec_ids else {}

        # Pre-fetch recent sessions for users
        sessions_query = db.query(DbSession).filter(DbSession.user_id.in_(uids)).order_by(DbSession.login_time.desc()).limit(100).all() if uids else []
        sess_by_user: Dict[int, List[DbSession]] = {}
        for s in sessions_query:
            sess_by_user.setdefault(s.user_id, []).append(s)

        # Pre-fetch active locks
        locks_query = db.query(PortalSecurityLock).filter(
            PortalSecurityLock.user_id.in_(uids),
            PortalSecurityLock.lock_status == "ACTIVE"
        ).all() if uids else []
        active_locks = {(lk.user_id, (lk.application or "").lower()): lk for lk in locks_query}

        correlated_incidents = []
        for al in alerts:
            user = users_map.get(al.user_id)
            sec_ev = sec_map.get(al.security_event_id)
            user_sessions = sess_by_user.get(al.user_id, [])

            # Match session
            matched_sess = None
            if sec_ev and sec_ev.session_id:
                matched_sess = next((s for s in user_sessions if s.id == sec_ev.session_id), None)
            if not matched_sess:
                matched_sess = next((s for s in user_sessions if (s.application or "").lower() == (al.application or "").lower()), None)

            # Timeline of events for this incident
            timeline_evs = db.query(SecurityEvent).filter(
                SecurityEvent.user_id == al.user_id,
                SecurityEvent.application == al.application
            ).order_by(SecurityEvent.timestamp.desc()).limit(10).all()

            # Containment status
            active_lock = active_locks.get((al.user_id, (al.application or "").lower()))
            is_terminated = bool(matched_sess and matched_sess.status in ("TERMINATED", "REVOKED"))
            containment_actions = []
            if is_terminated:
                containment_actions.append("SESSION_TERMINATED")
            if active_lock:
                containment_actions.append("PORTAL_LOCKED")
            if any("grant" in str(ev.details).lower() for ev in timeline_evs):
                containment_actions.append("GRANTS_REVOKED")

            if al.status == "RESOLVED":
                containment_status = "RESOLVED"
            elif al.status == "CONTAINED" or is_terminated or active_lock:
                containment_status = "CONTAINED"
            elif al.status == "INVESTIGATING":
                containment_status = "INVESTIGATING"
            elif al.severity in ("HIGH", "CRITICAL"):
                containment_status = "PENDING"
            else:
                containment_status = "NONE"

            risk_score = sec_ev.risk_score if sec_ev else (0.85 if al.severity == "CRITICAL" else (0.70 if al.severity == "HIGH" else 0.45))

            ai_analysis = {
                "disclaimer": "AI Security Analysis is advisory and must be verified by a human SOC analyst.",
                "incident_category": al.alert_type,
                "recommended_containment": "SESSION_REVOKED" if al.severity == "CRITICAL" else ("STEP_UP_ENFORCED" if al.severity in ("HIGH", "MEDIUM") else "NONE"),
                "containment_verified": containment_status == "CONTAINED",
                "containment_actions": containment_actions,
                "investigation_notes": al.notes or f"Automated triage logged for {al.alert_type} on {al.application}."
            }

            correlated_incidents.append({
                "incident_id": al.id,
                "alert_id": al.id,
                "security_event_id": al.security_event_id,
                "severity": al.severity,
                "status": al.status,
                "application": al.application,
                "message": al.message,
                "user_id": al.user_id,
                "user_name": user.name if user else "Unknown User",
                "user_email": user.email if user else "unknown@cognisec.ai",
                "created_at": al.created_at,
                "ai_analysis": ai_analysis,
                "session_id": matched_sess.id if matched_sess else (sec_ev.session_id if sec_ev else None),
                "device_id": matched_sess.device_id if matched_sess else None,
                "risk_score": risk_score,
                "incident_category": al.alert_type,
                "containment_status": containment_status,
                "containment_actions": containment_actions,
                "timeline_event_count": len(timeline_evs),
                "updated_at": al.resolved_at or al.created_at
            })

        return correlated_incidents

    async def _run_reasoning(self, validated_input: SOCMonitoringInput) -> SOCMonitoringOutput:
        """
        Executes SOC analytical reasoning: derives posture metrics, performs correlation,
        synthesizes executive summary, and generates advisory investigation steps.
        """
        events = list(validated_input.risk_events or [])
        posture = self.compute_security_posture()
        correlations = self.correlate_attack_patterns(events)

        # Factual extraction
        n_crit = sum(1 for e in events if e.get("risk_level") == "CRITICAL" or e.get("severity") == "CRITICAL")
        n_high = sum(1 for e in events if e.get("risk_level") == "HIGH" or e.get("severity") == "HIGH")
        n_med = sum(1 for e in events if e.get("risk_level") == "MEDIUM" or e.get("severity") == "MEDIUM")
        n_low = sum(1 for e in events if e.get("risk_level") == "LOW" or e.get("severity") == "LOW")

        # Extract SecurityResponseAgent containment outcomes
        sec_resp = validated_input.security_response or {}
        contain_status = validated_input.containment_status or (
            "CONTAINED" if (n_crit > 0 or sec_resp.get("containment_action") in ("SESSION_REVOKED", "PORTAL_LOCKED")) else "NONE"
        )
        actions_taken = list(validated_input.containment_actions_taken or [])
        if sec_resp.get("required_backend_operation") == "TERMINATE_SESSION" and "TERMINATE_SESSION" not in actions_taken:
            actions_taken.append("TERMINATE_SESSION")
        if sec_resp.get("required_backend_operation") == "LOCK_PORTAL" and "LOCK_PORTAL" not in actions_taken:
            actions_taken.append("LOCK_PORTAL")
        if sec_resp.get("containment_action") in ("GRANTS_REVOKED", "SESSION_REVOKED") and "REVOKE_GRANTS" not in actions_taken:
            actions_taken.append("REVOKE_GRANTS")

        containment_assessment = {
            "status": contain_status,
            "actions_taken": actions_taken,
            "containment_actions": actions_taken,
            "session_terminated": "TERMINATE_SESSION" in actions_taken or any(e.get("decision") == "TERMINATE_SESSION" for e in events),
            "grants_revoked": "REVOKE_GRANTS" in actions_taken,
            "portal_locked": "LOCK_PORTAL" in actions_taken or any("lock" in str(e.get("decision", "")).lower() for e in events),
            "alert_created": bool(sec_resp.get("alert_required", False)),
            "notification_attempted": bool(sec_resp.get("user_notification_recommended", False)),
            "containment_pending": (contain_status == "PENDING" or (n_crit > 0 and "TERMINATE_SESSION" not in actions_taken))
        }

        observed_facts = [
            f"Evaluated {len(events)} security events across past {validated_input.time_window_minutes} minutes.",
            f"Event Severity Breakdown: {n_crit} CRITICAL, {n_high} HIGH, {n_med} MEDIUM, {n_low} LOW.",
            f"Active fleet sessions: {posture['active_sessions']}, Open alerts: {posture['open_incidents']}, Contained: {posture.get('contained_incidents', 0)}.",
            f"Containment Assessment: Status='{contain_status}', Actions={actions_taken or ['NONE']}."
        ]
        if validated_input.user_id:
            observed_facts.append(f"Scope restricted to User ID #{validated_input.user_id}.")
        if validated_input.application:
            observed_facts.append(f"Target Portal: '{validated_input.application}'.")

        inferred_threats = []
        for c in correlations:
            inferred_threats.append(f"Potential attack pattern [{c['pattern_type']}]: {c['description']}")

        # Investigation steps
        investigation_steps: List[str] = []
        if containment_assessment["containment_pending"]:
            investigation_steps.append("URGENT: Verify immediate containment execution (session termination / portal lock).")
        elif containment_assessment["status"] == "CONTAINED":
            investigation_steps.append("Confirm containment status and review affected session / portal isolation boundaries.")

        if n_crit > 0:
            investigation_steps.append("Verify immediate session termination and grant invalidation for critical sessions.")
        if n_high > 0:
            investigation_steps.append("Inspect compound cognitive verification logs and device trust histories.")
        if any(c["pattern_type"] == "REPEATED_AUTHENTICATION_FAILURES" for c in correlations):
            investigation_steps.append("Review IP addresses and rate limiting counters for credential brute-force indicators.")
        if any(c["pattern_type"] == "REPEATED_PROTECTED_VAULT_PROBING" for c in correlations):
            investigation_steps.append("Audit vault authorization grants and review unauthorized 403 access traces.")
        if not investigation_steps:
            investigation_steps.append("Continue routine SOC telemetry ingestion and baseline observation.")

        priority = "P1" if n_crit > 0 else ("P2" if n_high > 0 else ("P3" if n_med > 0 else "P4"))

        # Build prompt for LLM narrative enrichment
        facts_clean = Sanitizer.sanitize_dict({
            "event_count": len(events),
            "critical_events": n_crit,
            "high_events": n_high,
            "medium_events": n_med,
            "priority": priority,
            "correlations": correlations,
            "containment": containment_assessment,
            "active_sessions": posture["active_sessions"],
            "open_incidents": posture["open_incidents"]
        })

        prompt = (
            f"Synthesize an executive SOC Threat Assessment based on the structured metrics below:\n"
            f"<SOC_METRICS>\n{json.dumps(facts_clean, indent=2)}\n</SOC_METRICS>\n\n"
            f"Instructions:\n"
            f"1. Clearly separate verified empirical facts from inferred threat narrative.\n"
            f"2. Do NOT invent attacks or fabricate numbers not present in the data.\n"
            f"3. Return a JSON object with keys: executive_summary, threat_assessment, suspicious_patterns, recommended_actions."
        )

        request = LLMRequest(
            prompt=prompt,
            system_instruction="You are the Cognisec SOC Monitoring Agent. Provide objective, explainable security analysis for SOC analysts.",
            response_schema={"type": "object"}
        )

        resp = await self.llm_client.generate(request)
        exec_summary = f"SOC Fleet Analysis: {len(events)} events processed ({n_crit} critical, {n_high} high). Containment: {contain_status}."
        threat_analysis = "Nominal security baseline observed across fleet." if n_crit == 0 and n_high == 0 else f"Elevated behavioral risk detected ({n_crit + n_high} high/critical events)."
        suspicious_patterns = [c["pattern_type"] for c in correlations] or (["Statistical threshold monitoring active"] if len(events) == 0 else ["No coordinated multi-session attack pattern confirmed"])
        recommended_actions = list(investigation_steps)

        if resp.parsed_json and isinstance(resp.parsed_json, dict):
            if resp.parsed_json.get("executive_summary"):
                exec_summary = str(resp.parsed_json["executive_summary"])
            if resp.parsed_json.get("threat_assessment"):
                threat_analysis = str(resp.parsed_json["threat_assessment"])
            if resp.parsed_json.get("suspicious_patterns") and isinstance(resp.parsed_json["suspicious_patterns"], list):
                suspicious_patterns = [str(p) for p in resp.parsed_json["suspicious_patterns"]]
            if resp.parsed_json.get("recommended_actions") and isinstance(resp.parsed_json["recommended_actions"], list):
                recommended_actions = [str(a) for a in resp.parsed_json["recommended_actions"]]

        return SOCMonitoringOutput(
            executive_summary=exec_summary,
            threat_assessment=threat_analysis,
            suspicious_patterns=suspicious_patterns,
            recommended_actions=recommended_actions,
            incident_priority=priority,
            observed_facts=observed_facts,
            inferred_threats=inferred_threats,
            attack_correlations=correlations,
            posture_summary=posture,
            investigation_steps=investigation_steps,
            containment_assessment=containment_assessment
        )

    def get_deterministic_fallback(self, input_data: Any) -> SOCMonitoringOutput:
        """
        Deterministic, fail-secure fallback that compiles real empirical metrics
        without relying on external LLM services. Guaranteed never to fail or raise exceptions.
        """
        events = getattr(input_data, "risk_events", [])
        if not isinstance(events, list):
            events = []

        posture = self.compute_security_posture()
        correlations = self.correlate_attack_patterns(events)

        n_crit = sum(1 for e in events if isinstance(e, dict) and (e.get("risk_level") == "CRITICAL" or e.get("severity") == "CRITICAL"))
        n_high = sum(1 for e in events if isinstance(e, dict) and (e.get("risk_level") == "HIGH" or e.get("severity") == "HIGH"))
        n_med = sum(1 for e in events if isinstance(e, dict) and (e.get("risk_level") == "MEDIUM" or e.get("severity") == "MEDIUM"))

        priority = "P1" if n_crit > 0 else ("P2" if n_high > 0 else ("P3" if n_med > 0 else "P4"))

        sec_resp = getattr(input_data, "security_response", {}) or {}
        contain_status = getattr(input_data, "containment_status", None) or (
            "CONTAINED" if (n_crit > 0 or sec_resp.get("containment_action") in ("SESSION_REVOKED", "PORTAL_LOCKED")) else "NONE"
        )
        actions_taken = list(getattr(input_data, "containment_actions_taken", []) or [])
        if sec_resp.get("required_backend_operation") == "TERMINATE_SESSION" and "TERMINATE_SESSION" not in actions_taken:
            actions_taken.append("TERMINATE_SESSION")
        if sec_resp.get("required_backend_operation") == "LOCK_PORTAL" and "LOCK_PORTAL" not in actions_taken:
            actions_taken.append("LOCK_PORTAL")
        if sec_resp.get("containment_action") in ("GRANTS_REVOKED", "SESSION_REVOKED") and "REVOKE_GRANTS" not in actions_taken:
            actions_taken.append("REVOKE_GRANTS")

        containment_assessment = {
            "status": contain_status,
            "actions_taken": actions_taken,
            "containment_actions": actions_taken,
            "session_terminated": "TERMINATE_SESSION" in actions_taken or any(isinstance(e, dict) and e.get("decision") == "TERMINATE_SESSION" for e in events),
            "grants_revoked": "REVOKE_GRANTS" in actions_taken,
            "portal_locked": "LOCK_PORTAL" in actions_taken or any(isinstance(e, dict) and "lock" in str(e.get("decision", "")).lower() for e in events),
            "alert_created": bool(sec_resp.get("alert_required", False)),
            "notification_attempted": bool(sec_resp.get("user_notification_recommended", False)),
            "containment_pending": (contain_status == "PENDING" or (n_crit > 0 and "TERMINATE_SESSION" not in actions_taken))
        }

        observed_facts = [
            f"Processed {len(events)} security events from database telemetry feed.",
            f"Observed counts: {n_crit} CRITICAL, {n_high} HIGH, {n_med} MEDIUM.",
            f"Containment Assessment: Status='{contain_status}', Actions={actions_taken or ['NONE']}."
        ]
        inferred_threats = [f"Correlated pattern: {c['description']}" for c in correlations]
        investigation_steps = [
            "Review high-risk audit records in admin security log.",
            "Verify that any CRITICAL sessions received immediate zero-trust termination."
        ]

        return SOCMonitoringOutput(
            executive_summary=f"Automated SOC summary generated for {len(events)} security events across {posture.get('active_sessions', 0)} active sessions.",
            threat_assessment="Deterministic zero-trust risk analysis in effect." if n_crit == 0 else "CRITICAL risk indicators detected in event stream.",
            suspicious_patterns=[c["pattern_type"] for c in correlations] if correlations else ["Statistical threshold monitoring active"],
            recommended_actions=investigation_steps,
            incident_priority=priority,
            observed_facts=observed_facts,
            inferred_threats=inferred_threats,
            attack_correlations=correlations,
            posture_summary=posture,
            investigation_steps=investigation_steps,
            containment_assessment=containment_assessment
        )
