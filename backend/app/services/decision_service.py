import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple, Optional
from sqlalchemy.orm import Session
from app.models.session import Session as DbSession
from app.models.security_event import SecurityEvent
from app.models.alert import Alert
from app.services.session_service import SessionService


class DecisionService:
    @staticmethod
    def enforce_zero_trust_decision(
        db: Session,
        user_id: int,
        session_id: str,
        application: str,
        risk_score: float,
        anomaly_score: float,
        risk_level: str,
        contributing_factors: List[str]
    ) -> Tuple[str, str, str, Optional[int]]:
        """
        Enforces policy decision based on multi-factor risk level.
        Returns: (decision, user_facing_message, session_status, security_event_id)
        """
        now_utc = datetime.now(timezone.utc)

        if risk_level == "LOW":
            decision = "ALLOW"
            user_message = "Access allowed. Continuous identity verification active."
            session_status = "ACTIVE"
            event_id = None

        elif risk_level == "MEDIUM":
            decision = "STEP_UP_VERIFICATION"
            user_message = "Additional security verification required to proceed."
            session_status = "STEP_UP_REQUIRED"
            SessionService.update_session_status(db, session_id, status=session_status, risk_level=risk_level)
            
            # Log security event
            sec_event = SecurityEvent(
                user_id=user_id,
                session_id=session_id,
                application=application.lower(),
                event_type="STEP_UP_CHALLENGE",
                severity="MEDIUM",
                anomaly_score=anomaly_score,
                risk_score=risk_score,
                decision=decision,
                details=json.dumps({"factors": contributing_factors}),
                timestamp=now_utc
            )
            db.add(sec_event)
            db.commit()
            db.refresh(sec_event)
            event_id = sec_event.id

            # Create SOC alert
            alert = Alert(
                user_id=user_id,
                security_event_id=sec_event.id,
                application=application.lower(),
                alert_type="STEP_UP_CHALLENGE_TRIGGERED",
                message=f"Step-up verification required in {application.upper()} portal. Factors: {', '.join(contributing_factors) if contributing_factors else 'Moderate risk'}",
                severity="MEDIUM",
                status="OPEN",
                created_at=now_utc
            )
            db.add(alert)
            db.commit()

        elif risk_level == "HIGH":
            decision = "RESTRICT"
            user_message = "Access temporarily restricted. Sensitive operations are locked."
            session_status = "RESTRICTED"
            SessionService.update_session_status(db, session_id, status=session_status, risk_level=risk_level)

            sec_event = SecurityEvent(
                user_id=user_id,
                session_id=session_id,
                application=application.lower(),
                event_type="SESSION_RESTRICTED",
                severity="HIGH",
                anomaly_score=anomaly_score,
                risk_score=risk_score,
                decision=decision,
                details=json.dumps({"factors": contributing_factors}),
                timestamp=now_utc
            )
            db.add(sec_event)
            db.commit()
            db.refresh(sec_event)
            event_id = sec_event.id

            alert = Alert(
                user_id=user_id,
                security_event_id=sec_event.id,
                application=application.lower(),
                alert_type="HIGH_RISK_SESSION_RESTRICTION",
                message=f"Session restricted for user #{user_id} in {application.upper()}. Factors: {', '.join(contributing_factors)}",
                severity="HIGH",
                status="OPEN",
                created_at=now_utc
            )
            db.add(alert)
            db.commit()

        else:  # CRITICAL
            decision = "TERMINATE_SESSION"
            user_message = "Your session has been securely terminated due to critical security risk."
            session_status = "TERMINATED"
            SessionService.terminate_session(db, session_id)

            sec_event = SecurityEvent(
                user_id=user_id,
                session_id=session_id,
                application=application.lower(),
                event_type="ZERO_TRUST_KILL_SWITCH",
                severity="CRITICAL",
                anomaly_score=anomaly_score,
                risk_score=risk_score,
                decision=decision,
                details=json.dumps({"factors": contributing_factors}),
                timestamp=now_utc
            )
            db.add(sec_event)
            db.commit()
            db.refresh(sec_event)
            event_id = sec_event.id

            alert = Alert(
                user_id=user_id,
                security_event_id=sec_event.id,
                application=application.lower(),
                alert_type="KILL_SWITCH_EXECUTED",
                message=f"CRITICAL: Zero-Trust Kill Switch terminated session {session_id} in {application.upper()}. High anomaly & threat vectors detected.",
                severity="CRITICAL",
                status="OPEN",
                created_at=now_utc
            )
            db.add(alert)
            db.commit()

        return decision, user_message, session_status, event_id
