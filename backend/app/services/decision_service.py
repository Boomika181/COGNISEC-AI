import json
from datetime import datetime, timezone, timedelta
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
        db_session = SessionService.get_session(db, session_id)
        is_fresh = SessionService.is_step_up_fresh(db_session, current_risk_score=risk_score, current_risk_level=risk_level)

        # A RESTRICTED session can be relaxed by normal risk telemetry unless a brute-force
        # lockout (STEP_UP_LOCKED), admin action, or termination is in force.
        if db_session and db_session.status == "RESTRICTED" and risk_level in ("LOW", "MEDIUM"):
            active_hard_lock = db.query(SecurityEvent).filter(
                SecurityEvent.session_id == session_id,
                SecurityEvent.event_type.in_(["STEP_UP_LOCKED", "ADMIN_REVOCATION", "SESSION_TERMINATED"])
            ).first()
            if active_hard_lock:
                return (
                    "RESTRICT",
                    "Access temporarily restricted. Sensitive operations are locked.",
                    "RESTRICTED",
                    None,
                )


        if risk_level == "LOW":
            decision = "ALLOW"
            user_message = "Access allowed. Continuous identity verification active."
            session_status = "ACTIVE"
            event_id = None
            if db_session and db_session.status != "TERMINATED":
                db_session.current_risk_level = "LOW"
                if db_session.status not in ("PENDING_OBSERVATION", "PENDING_OTP", "TERMINATED"):
                    db_session.status = "ACTIVE"
                db.commit()

        elif risk_level == "MEDIUM":
            if is_fresh:
                # Session has active, fresh Step-Up verification. Allow continuous access without re-triggering challenge.
                decision = "ALLOW"
                user_message = "Access allowed. Continuous identity verified via active step-up authentication."
                session_status = "ACTIVE"
                event_id = None
                if db_session and db_session.status != "TERMINATED":
                    db_session.current_risk_level = "MEDIUM"
                    db.commit()
            else:
                decision = "STEP_UP_VERIFICATION"
                user_message = "Additional security verification required to proceed."
                session_status = "STEP_UP_REQUIRED"
                SessionService.update_session_status(db, session_id, status=session_status, risk_level=risk_level)

                # Cooldown check: avoid duplicate event emission on every rapid telemetry packet
                recent_step_event = db.query(SecurityEvent).filter(
                    SecurityEvent.session_id == session_id,
                    SecurityEvent.event_type == "STEP_UP_CHALLENGE",
                    SecurityEvent.timestamp >= now_utc - timedelta(seconds=60)
                ).order_by(SecurityEvent.timestamp.desc()).first()

                if not recent_step_event:
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
                        details=json.dumps({"factors": contributing_factors, "enforcement_outcome": "STEP_UP_ENFORCED"}),
                        timestamp=now_utc
                    )
                    db.add(sec_event)
                    db.commit()
                    db.refresh(sec_event)
                    event_id = sec_event.id

                    # Create or update active SOC alert
                    existing_open_alert = db.query(Alert).filter(
                        Alert.user_id == user_id,
                        Alert.alert_type == "STEP_UP_CHALLENGE_TRIGGERED",
                        Alert.status.in_(["OPEN", "ACKNOWLEDGED", "INVESTIGATING"])
                    ).first()

                    if not existing_open_alert:
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
                else:
                    event_id = recent_step_event.id

        elif risk_level == "HIGH":
            decision = "RESTRICT"
            user_message = "Access temporarily restricted. Sensitive operations are locked."
            session_status = "RESTRICTED"
            SessionService.update_session_status(db, session_id, status=session_status, risk_level=risk_level)

            # Cooldown check: avoid logging identical restriction events every 2 seconds
            recent_restricted_event = db.query(SecurityEvent).filter(
                SecurityEvent.session_id == session_id,
                SecurityEvent.event_type == "SESSION_RESTRICTED",
                SecurityEvent.timestamp >= now_utc - timedelta(seconds=60)
            ).order_by(SecurityEvent.timestamp.desc()).first()

            if not recent_restricted_event:
                sec_event = SecurityEvent(
                    user_id=user_id,
                    session_id=session_id,
                    application=application.lower(),
                    event_type="SESSION_RESTRICTED",
                    severity="HIGH",
                    anomaly_score=anomaly_score,
                    risk_score=risk_score,
                    decision=decision,
                    details=json.dumps({"factors": contributing_factors, "enforcement_outcome": "RESTRICTED"}),
                    timestamp=now_utc
                )
                db.add(sec_event)
                db.commit()
                db.refresh(sec_event)
                event_id = sec_event.id

                # Deduplicate open alert
                existing_high_alert = db.query(Alert).filter(
                    Alert.user_id == user_id,
                    Alert.alert_type == "HIGH_RISK_SESSION_RESTRICTION",
                    Alert.status.in_(["OPEN", "ACKNOWLEDGED", "INVESTIGATING"])
                ).first()

                if not existing_high_alert:
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
            else:
                event_id = recent_restricted_event.id

        else:  # CRITICAL
            decision = "TERMINATE_SESSION"
            user_message = "Your session has been securely terminated due to critical security risk."
            session_status = "TERMINATED"
            SessionService.terminate_session(db, session_id, risk_level="CRITICAL")

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
