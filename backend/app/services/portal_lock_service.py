"""
Authoritative Portal-Scoped Verification Attempt Counter, Security Lock,
Re-Entry Monitoring, and Authorized Recovery Service.
"""

import json
import logging
import secrets
import threading
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.application_grant import ApplicationGrant
from app.models.device import Device
from app.models.portal_lock import PortalSecurityLock, VerificationAttemptCounter
from app.models.security_event import SecurityEvent
from app.models.session import Session as DbSession
from app.models.user import User
from app.services.notification_service import NotificationService

logger = logging.getLogger("cognisec.portal_lock")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _norm_app(application: Optional[str]) -> str:
    raw = (application or "platform").strip().lower()
    mapping = {
        "ecommerce": "shopping",
        "shopping_portal": "shopping",
        "nyraa": "shopping",
        "shopping": "shopping",
        "college_portal": "college",
        "bits_college": "college",
        "college": "college",
        "healthcare_portal": "healthcare",
        "ayusync": "healthcare",
        "healthcare": "healthcare",
        "platform": "platform",
    }
    return mapping.get(raw, raw or "platform")


def _portal_display_name(app: str) -> str:
    return {
        "shopping": "Shopping Portal (Nyraa Retail)",
        "college": "College Portal (BITS Pilani)",
        "healthcare": "Healthcare Portal (AyuSync MedCare)",
        "platform": "COGNISEC-AI Platform",
    }.get(_norm_app(app), f"{_norm_app(app).capitalize()} Portal")


def _safe_utc_iso(dt: Optional[datetime]) -> Optional[str]:
    if not dt:
        return None
    aware = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return aware.isoformat()


class PortalLockService:
    MAX_VERIFICATION_ATTEMPTS = 3
    LIMIT_LOGIN_OTP = 1
    LIMIT_RECOVERY_OTP = 1
    LIMIT_EXAM_OTP = 1
    LIMIT_OTHER_OTP = 1
    LIMIT_GESTURE = 3
    LIMIT_COGNITIVE_IMAGE = 2
    LIMIT_COGNITIVE_PRIVATE = 2
    SESSION_TERMINATED_MESSAGE = (
        "Your session has been terminated due to critical security risk policy. Please sign in again."
    )

    RECOVERY_INSTRUCTIONS = (
        "1. Verify your identity via registered-email recovery OTP if prompted. "
        "2. Contact your Security Administrator / SOC to authorize portal clearance using Security Reference ID. "
        "3. After clearance, return to the portal and complete fresh 20-second behavioral observation and Email OTP."
    )

    _op_lock = threading.RLock()

    @classmethod
    def get_max_attempts_for(cls, verification_purpose: str, factor_key: str) -> int:
        purpose = (verification_purpose or "").strip().upper()
        factor = (factor_key or "").strip().upper()
        if purpose == "RECOVERY_OTP" or factor == "RECOVERY_EMAIL_OTP":
            return cls.LIMIT_RECOVERY_OTP
        if (
            factor in ("EMAIL_OTP", "OTP", "LOGIN_OTP", "EXAM_OTP", "PAYMENT_OTP", "APPOINTMENT_OTP")
            or purpose in ("LOGIN_OTP", "EXAM_OTP", "PAYMENT_OTP", "APPOINTMENT_OTP", "RECOVERY_OTP")
        ):
            return cls.LIMIT_OTHER_OTP
        if factor == "GESTURE_PATTERN":
            return cls.LIMIT_GESTURE
        if factor == "COGNITIVE_IMAGE_SEQUENCE":
            return cls.LIMIT_COGNITIVE_IMAGE
        if factor == "PRIVATE_RESPONSE":
            return cls.LIMIT_COGNITIVE_PRIVATE
        return cls.MAX_VERIFICATION_ATTEMPTS

    @classmethod
    def extract_device_context(
        cls,
        db: Session,
        user_id: int,
        session_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Dict[str, Any]:
        sess = None
        dev = None
        if session_id:
            sess = db.query(DbSession).filter(DbSession.id == session_id).first()
            if sess and sess.device_id:
                dev = db.query(Device).filter(Device.id == sess.device_id).first()
        if not dev and user_id:
            dev = (
                db.query(Device)
                .filter(Device.user_id == user_id)
                .order_by(Device.last_seen.desc())
                .first()
            )
        ip = client_ip or (sess.ip_address if sess and sess.ip_address else None) or (dev.last_ip if dev else None) or "unknown"
        if dev:
            env = (
                f"{dev.browser_name} on {dev.os_name}"
                if dev.browser_name and dev.os_name and dev.browser_name != "Unknown" and dev.os_name != "Unknown"
                else (dev.browser or dev.nickname or dev.device_type or "Registered Client")
            )
            loc = f"{dev.city}, {dev.country}" if dev.city and dev.country else f"IP {ip}"
            summary = f"{env} ({loc})"
        elif user_agent:
            summary = f"{user_agent[:100]} (IP {ip})"
        else:
            summary = f"IP {ip}"

        return {
            "device_id": dev.id if dev else None,
            "device_identifier": dev.device_id if dev else None,
            "device_summary": summary,
            "ip_address": ip,
            "location_summary": (f"{dev.city}, {dev.country}" if dev and dev.city and dev.country else None),
            "user_agent": (user_agent[:180] if user_agent else None),
        }

    @classmethod
    def get_active_lock(
        cls,
        db: Session,
        user_id: int,
        application: Optional[str],
    ) -> Optional[PortalSecurityLock]:
        norm_app = _norm_app(application)
        return (
            db.query(PortalSecurityLock)
            .filter(
                PortalSecurityLock.user_id == user_id,
                PortalSecurityLock.application == norm_app,
                PortalSecurityLock.lock_status == "ACTIVE",
            )
            .order_by(PortalSecurityLock.id.desc())
            .first()
        )

    @classmethod
    def serialize_lock(cls, lock: PortalSecurityLock) -> Dict[str, Any]:
        dev_ctx = {}
        if lock.device_context:
            try:
                dev_ctx = json.loads(lock.device_context)
            except Exception:
                dev_ctx = {}
        return {
            "locked": lock.lock_status == "ACTIVE",
            "portal": lock.application,
            "portal_display_name": _portal_display_name(lock.application),
            "lock_reason": lock.lock_reason,
            "verification_purpose": lock.verification_purpose,
            "failed_attempt_count": lock.failed_attempt_count,
            "max_attempts": lock.max_attempts,
            "security_reference_id": lock.security_reference_id,
            "audit_correlation_id": lock.audit_correlation_id,
            "lock_status": lock.lock_status,
            "recovery_status": lock.recovery_status,
            "recovery_otp_verified": lock.recovery_otp_verified_at is not None,
            "recovery_otp_verified_at": _safe_utc_iso(lock.recovery_otp_verified_at),
            "locked_at": _safe_utc_iso(lock.locked_at),
            "unlocked_at": _safe_utc_iso(lock.unlocked_at),
            "unlocked_by": lock.unlocked_by,
            "recovery_notes": lock.recovery_notes,
            "reentry_attempts": lock.reentry_attempts or 0,
            "device_summary": dev_ctx.get("device_summary"),
            "recovery_instructions": cls.RECOVERY_INSTRUCTIONS,
        }

    @classmethod
    def build_lock_detail(cls, lock: PortalSecurityLock, detail_prefix: Optional[str] = None) -> Dict[str, Any]:
        payload = cls.serialize_lock(lock)
        base_msg = (
            f"SECURITY ACCESS SUSPENDED: Your access to {_portal_display_name(lock.application)} "
            f"has been temporarily suspended ({lock.lock_reason}). Reference ID: {lock.security_reference_id}."
        )
        payload["error"] = "PORTAL_SECURITY_LOCKED"
        payload["portal_locked"] = True
        payload["message"] = f"{detail_prefix} {base_msg}".strip() if detail_prefix else base_msg
        return payload

    @classmethod
    def raise_locked_http_exception(
        cls,
        lock: PortalSecurityLock,
        status_code: int = status.HTTP_423_LOCKED,
        detail_prefix: Optional[str] = None,
    ) -> None:
        info = cls.build_lock_detail(lock, detail_prefix=detail_prefix)
        raise HTTPException(
            status_code=status_code,
            detail=info["message"],
            headers={
                "X-Cognisec-Portal-Locked": "true",
                "X-Cognisec-Locked-Portal": lock.application,
                "X-Cognisec-Security-Ref": lock.security_reference_id,
            },
        )

    @classmethod
    def raise_terminated_http_exception(
        cls,
        status_code: int = status.HTTP_403_FORBIDDEN,
        detail: Optional[str] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        hdrs = {
            "X-Cognisec-Session-Terminated": "true",
            "X-Cognisec-Attempts-Remaining": "0",
            "X-Cognisec-Redirect": "login",
        }
        if extra_headers:
            hdrs.update(extra_headers)
        raise HTTPException(
            status_code=status_code,
            detail=detail or cls.SESSION_TERMINATED_MESSAGE,
            headers=hdrs,
        )

    @classmethod
    def enforce_not_locked(
        cls,
        db: Session,
        user_id: int,
        application: Optional[str],
        detail_prefix: Optional[str] = None,
    ) -> None:
        lock = cls.get_active_lock(db, user_id, application)
        if lock:
            cls.raise_locked_http_exception(lock, status_code=status.HTTP_423_LOCKED, detail_prefix=detail_prefix)

    @classmethod
    def get_attempt_counter_status(
        cls,
        db: Session,
        user_id: int,
        application: Optional[str],
        verification_purpose: str,
        factor_key: str,
        session_id: Optional[str] = "",
        max_attempts_override: Optional[int] = None,
    ) -> Dict[str, Any]:
        norm_app = _norm_app(application)
        purpose = (verification_purpose or "STEP_UP").strip().upper()
        factor = (factor_key or "UNKNOWN").strip().upper()
        sess_scope = (session_id or "").strip()
        configured_max = max_attempts_override or cls.get_max_attempts_for(purpose, factor)
        row = (
            db.query(VerificationAttemptCounter)
            .filter(
                VerificationAttemptCounter.user_id == user_id,
                VerificationAttemptCounter.session_id == sess_scope,
                VerificationAttemptCounter.application == norm_app,
                VerificationAttemptCounter.verification_purpose == purpose,
                VerificationAttemptCounter.factor_key == factor,
            )
            .first()
        )
        used = int(row.attempts) if row else 0
        max_att = int(row.max_attempts) if row and row.max_attempts else configured_max
        exhausted = bool(row and (row.locked_at is not None or used >= max_att))
        remaining = 0 if exhausted else max(0, max_att - used)
        return {
            "attempts_used": used,
            "max_attempts": max_att,
            "attempts_remaining": remaining,
            "exhausted": exhausted,
        }

    @classmethod
    def reset_factor_counter_on_success(
        cls,
        db: Session,
        user_id: int,
        application: Optional[str],
        verification_purpose: str,
        factor_key: str,
        session_id: Optional[str] = "",
    ) -> None:
        norm_app = _norm_app(application)
        purpose = (verification_purpose or "STEP_UP").strip().upper()
        factor = (factor_key or "UNKNOWN").strip().upper()
        sess_scope = (session_id or "").strip()
        with cls._op_lock:
            row = (
                db.query(VerificationAttemptCounter)
                .filter(
                    VerificationAttemptCounter.user_id == user_id,
                    VerificationAttemptCounter.session_id == sess_scope,
                    VerificationAttemptCounter.application == norm_app,
                    VerificationAttemptCounter.verification_purpose == purpose,
                    VerificationAttemptCounter.factor_key == factor,
                )
                .first()
            )
            if row and row.locked_at is None:
                row.attempts = 0
                row.updated_at = utc_now()
                db.commit()

    @classmethod
    def is_counter_exhausted(
        cls,
        db: Session,
        user_id: int,
        application: Optional[str],
        verification_purpose: str,
        factor_key: str,
        session_id: Optional[str] = "",
    ) -> bool:
        norm_app = _norm_app(application)
        purpose = (verification_purpose or "STEP_UP").strip().upper()
        factor = (factor_key or "UNKNOWN").strip().upper()
        sess_scope = (session_id or "").strip()
        row = (
            db.query(VerificationAttemptCounter)
            .filter(
                VerificationAttemptCounter.user_id == user_id,
                VerificationAttemptCounter.session_id == sess_scope,
                VerificationAttemptCounter.application == norm_app,
                VerificationAttemptCounter.verification_purpose == purpose,
                VerificationAttemptCounter.factor_key == factor,
            )
            .first()
        )
        return bool(row and (row.locked_at is not None or row.attempts >= row.max_attempts))

    @classmethod
    def lock_portal(
        cls,
        db: Session,
        user_id: int,
        application: Optional[str],
        verification_purpose: str,
        lock_reason: str,
        failed_attempt_count: int,
        max_attempts: int,
        session_id: Optional[str] = None,
        challenge_reference: Optional[str] = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        emit_step_up_locked_event: bool = False,
    ) -> PortalSecurityLock:
        """
        Atomically creates/returns a persistent portal-scoped security lock,
        revokes portal ApplicationGrants, restricts portal sessions while preserving
        user identity & cross-portal state, logs SecurityEvent, and dispatches alerts.
        """
        norm_app = _norm_app(application)
        now = utc_now()
        user = db.query(User).filter(User.id == user_id).first()
        dev_ctx = cls.extract_device_context(
            db, user_id=user_id, session_id=session_id, client_ip=client_ip, user_agent=user_agent
        )

        with cls._op_lock:
            existing = cls.get_active_lock(db, user_id, norm_app)
            if existing:
                return existing

            sec_ref = f"SEC-LOCK-{secrets.token_hex(5).upper()}"
            corr_id = f"CORR-{secrets.token_hex(6).upper()}"
            lock = PortalSecurityLock(
                user_id=user_id,
                application=norm_app,
                lock_reason=lock_reason[:255],
                verification_purpose=(verification_purpose or "STEP_UP").upper()[:64],
                failed_attempt_count=failed_attempt_count,
                max_attempts=max_attempts,
                challenge_reference=(challenge_reference[:128] if challenge_reference else None),
                security_reference_id=sec_ref,
                audit_correlation_id=corr_id,
                session_id=session_id,
                device_context=json.dumps(dev_ctx),
                lock_status="ACTIVE",
                recovery_status="PENDING_ADMIN_RECOVERY",
                locked_at=now,
                reentry_attempts=0,
            )
            db.add(lock)

            # 1. Revoke portal-scoped ApplicationGrants (cross-portal grants remain untouched)
            db.query(ApplicationGrant).filter(
                ApplicationGrant.user_id == user_id,
                ApplicationGrant.application == norm_app,
                ApplicationGrant.revoked == False,
            ).update({"revoked": True}, synchronize_session=False)

            # 2. Restrict active/pending sessions ONLY for this locked portal (preserve global identity & other portals)
            sess_updates = {
                "status": "RESTRICTED",
                "step_up_verified_at": None,
                "step_up_valid_until": None,
                "step_up_factor": None,
            }
            if (verification_purpose or "").strip().upper() == "LOGIN_OTP":
                sess_updates["login_outcome"] = "rejected"
            db.query(DbSession).filter(
                DbSession.user_id == user_id,
                DbSession.application == norm_app,
                DbSession.status.in_(["ACTIVE", "PENDING_OBSERVATION", "PENDING_OTP", "STEP_UP_REQUIRED"]),
            ).update(sess_updates, synchronize_session=False)

            # Cancel pending PasswordChangeTransactions ONLY for this locked portal
            try:
                from app.models.password_change import PasswordChangeTransaction
                db.query(PasswordChangeTransaction).filter(
                    PasswordChangeTransaction.user_id == user_id,
                    PasswordChangeTransaction.application == norm_app,
                    PasswordChangeTransaction.is_consumed == False,
                ).update(
                    {"status": "LOCKED", "is_consumed": True, "consumed_at": now},
                    synchronize_session=False,
                )
            except Exception:
                pass

            # Purge portal-scoped challenges & drift tracker ONLY for this locked portal
            try:
                from app.services.step_up_service import StepUpService
                StepUpService.purge_portal_challenges(user_id=user_id, application=norm_app, session_id=session_id)
            except Exception:
                pass

            if session_id:
                try:
                    target_sess = db.query(DbSession).filter(DbSession.id == session_id).first()
                    if target_sess and _norm_app(target_sess.application) == norm_app:
                        from app.services.behavior_drift_service import BehavioralDriftTracker
                        BehavioralDriftTracker.clear_session(session_id)
                except Exception:
                    pass

            # 3. Record authoritative SecurityEvent(s)
            lock_event = SecurityEvent(
                user_id=user_id,
                session_id=session_id,
                application=norm_app,
                event_type="PORTAL_SECURITY_LOCKED",
                severity="HIGH",
                decision="LOCK_PORTAL",
                details=json.dumps({
                    "security_reference_id": sec_ref,
                    "audit_correlation_id": corr_id,
                    "portal": norm_app,
                    "verification_purpose": lock.verification_purpose,
                    "failed_attempt_count": failed_attempt_count,
                    "max_attempts": max_attempts,
                    "lock_reason": lock_reason,
                    "device_summary": dev_ctx.get("device_summary"),
                    "ip_address": dev_ctx.get("ip_address"),
                }),
                timestamp=now,
            )
            db.add(lock_event)
            if emit_step_up_locked_event:
                db.add(SecurityEvent(
                    user_id=user_id,
                    session_id=session_id,
                    application=norm_app,
                    event_type="STEP_UP_LOCKED",
                    severity="HIGH",
                    decision="RESTRICT",
                    details=f"Session restricted after exceeding maximum verification attempts ({sec_ref}).",
                    timestamp=now,
                ))

            db.commit()
            db.refresh(lock)
            db.refresh(lock_event)

        # Count active portal locks across portals for repeated cross-portal SOC escalation
        active_locks = (
            db.query(PortalSecurityLock)
            .filter(
                PortalSecurityLock.user_id == user_id,
                PortalSecurityLock.lock_status == "ACTIVE",
            )
            .all()
        )
        cross_portal_escalate = len(active_locks) >= 2
        alert_type = "CROSS_PORTAL_LOCKOUT_ESCALATION" if cross_portal_escalate else "PORTAL_SECURITY_LOCKOUT"
        alert_sev = "CRITICAL" if cross_portal_escalate else "HIGH"
        msg = (
            f"Access to {_portal_display_name(norm_app)} was suspended after {failed_attempt_count}/{max_attempts} "
            f"unsuccessful verification attempt(s) ({lock.verification_purpose}). Reference ID: {sec_ref}."
        )
        if cross_portal_escalate:
            portals_str = ", ".join(sorted({lk.application for lk in active_locks}))
            msg += f" Repeated lockouts detected across portals: {portals_str}."

        if user:
            NotificationService.notify_portal_security_event(
                db=db,
                user=user,
                application=norm_app,
                notification_type="PORTAL_ACCESS_SUSPENDED",
                title=f"Portal Access Suspended — {_portal_display_name(norm_app)}",
                message=msg,
                security_reference_id=sec_ref,
                lock_reason=lock_reason,
                alert_type=alert_type,
                alert_severity=alert_sev,
                device_summary=dev_ctx.get("device_summary") or "Unknown Device Context",
                ip_address=dev_ctx.get("ip_address"),
                device_id=dev_ctx.get("device_id"),
                security_event_id=lock_event.id,
                create_admin_alert=True,
            )
        return lock

    @classmethod
    def terminate_session_and_revoke_grants(
        cls,
        db: Session,
        user_id: int,
        session_id: Optional[str],
        application: Optional[str],
        verification_purpose: str,
        factor_key: str,
        reason: Optional[str] = None,
        challenge_reference: Optional[str] = None,
        emit_step_up_locked_event: bool = True,
    ) -> Optional[DbSession]:
        """
        Deterministic, idempotent enforcement executed after reaching the maximum failed
        verification attempts (3):
        - Terminates the session server-side (status='TERMINATED', logout_time=utc_now).
        - Clears step-up freshness & sets login_outcome='rejected' for LOGIN_OTP.
        - Revokes all applicable active ApplicationGrant records.
        - Cancels/locks pending PasswordChangeTransaction rows and OTPChallenge rows.
        - Purges in-memory StepUpService challenges and stops BehavioralDriftTracker.
        - Emits sanitized SecurityEvent without leaking OTPs/answers/passwords/tokens.
        Never bypassable by LLM/agent/notification failures.
        """
        from app.services.session_service import SessionService

        norm_app = _norm_app(application)
        purpose = (verification_purpose or "STEP_UP").strip().upper()
        factor = (factor_key or "UNKNOWN").strip().upper()
        now = utc_now()

        with cls._op_lock:
            db_session = (
                db.query(DbSession).filter(DbSession.id == session_id).first()
                if session_id else None
            )
            already_terminated = bool(db_session and db_session.status == "TERMINATED")

            if session_id:
                try:
                    db_session = SessionService.terminate_session(db, session_id)
                except Exception:
                    if db_session:
                        db_session.status = "TERMINATED"
                        db_session.logout_time = db_session.logout_time or now
                        db_session.step_up_valid_until = None
                        db_session.step_up_factor = None
                        db_session.step_up_verified_at = None
                        db_session.step_up_risk_cleared = None
                        db.commit()
                if db_session:
                    if purpose == "LOGIN_OTP":
                        db_session.login_outcome = "rejected"
                    db_session.logout_time = db_session.logout_time or now
                    db_session.step_up_valid_until = None
                    db_session.step_up_factor = None
                    db_session.step_up_verified_at = None
                    db_session.step_up_risk_cleared = None

                # Revoke ALL active grants bound to this session OR this user/application
                db.query(ApplicationGrant).filter(
                    ApplicationGrant.session_id == session_id,
                    ApplicationGrant.revoked == False,
                ).update({"revoked": True}, synchronize_session=False)

                if norm_app and norm_app != "platform":
                    db.query(ApplicationGrant).filter(
                        ApplicationGrant.user_id == user_id,
                        ApplicationGrant.application == norm_app,
                        ApplicationGrant.revoked == False,
                    ).update({"revoked": True}, synchronize_session=False)

                # Invalidate any unconsumed PasswordChangeTransaction rows on this session
                try:
                    from app.models.password_change import PasswordChangeTransaction
                    db.query(PasswordChangeTransaction).filter(
                        PasswordChangeTransaction.session_id == session_id,
                        PasswordChangeTransaction.is_consumed == False,
                    ).update(
                        {"status": "LOCKED", "is_consumed": True, "consumed_at": now},
                        synchronize_session=False,
                    )
                except Exception:
                    pass

                # Purge in-memory StepUpService challenges and consume OTPChallenge rows
                try:
                    from app.services.step_up_service import StepUpService
                    StepUpService.purge_session_challenges(session_id)
                except Exception:
                    pass

                try:
                    from app.models.otp_challenge import OTPChallenge
                    db.query(OTPChallenge).filter(
                        OTPChallenge.session_id == session_id,
                        OTPChallenge.is_consumed == False,
                    ).update({"is_consumed": True, "consumed_at": now}, synchronize_session=False)
                except Exception:
                    pass

                try:
                    from app.services.behavior_drift_service import BehavioralDriftTracker
                    BehavioralDriftTracker.clear_session(session_id)
                except Exception:
                    pass

            if not already_terminated:
                safe_reason = reason or f"Session terminated after 3 failed {factor} verification attempts ({purpose})."
                db.add(SecurityEvent(
                    user_id=user_id,
                    session_id=session_id,
                    application=norm_app,
                    event_type="SESSION_TERMINATED",
                    severity="HIGH",
                    decision="TERMINATE_SESSION",
                    details=json.dumps({
                        "portal": norm_app,
                        "verification_purpose": purpose,
                        "factor": factor,
                        "reason": safe_reason,
                        "challenge_reference": challenge_reference,
                        "max_attempts": cls.MAX_VERIFICATION_ATTEMPTS,
                    }),
                    timestamp=now,
                ))
                if emit_step_up_locked_event:
                    db.add(SecurityEvent(
                        user_id=user_id,
                        session_id=session_id,
                        application=norm_app,
                        event_type="STEP_UP_LOCKED",
                        severity="HIGH",
                        decision="TERMINATE_SESSION",
                        details=f"Session terminated after exceeding maximum verification attempts ({purpose}/{factor}).",
                        timestamp=now,
                    ))

            db.commit()
            if db_session:
                db.refresh(db_session)
            return db_session

    @classmethod
    def get_user_portal_locks_summary(
        cls,
        db: Session,
        user_id: int,
        current_session: Optional[DbSession] = None,
    ) -> Dict[str, Any]:
        """
        Returns authoritative separation between global session identity state and
        per-portal lock / authorization state for the central index.html dashboard.
        """
        locks = (
            db.query(PortalSecurityLock)
            .filter(
                PortalSecurityLock.user_id == user_id,
                PortalSecurityLock.lock_status == "ACTIVE",
            )
            .order_by(PortalSecurityLock.id.desc())
            .all()
        )
        lock_by_app: Dict[str, PortalSecurityLock] = {}
        serialized_locks: List[Dict[str, Any]] = []
        for lk in locks:
            norm = _norm_app(lk.application)
            if norm not in lock_by_app:
                lock_by_app[norm] = lk
                serialized_locks.append(cls.serialize_lock(lk))

        active_grants = (
            db.query(ApplicationGrant)
            .filter(
                ApplicationGrant.user_id == user_id,
                ApplicationGrant.revoked == False,
            )
            .all()
        )
        now = utc_now()
        granted_apps = set()
        for g in active_grants:
            exp = g.expires_at
            if exp:
                aware_exp = exp if exp.tzinfo else exp.replace(tzinfo=timezone.utc)
                if now <= aware_exp:
                    granted_apps.add(_norm_app(g.application))
            else:
                granted_apps.add(_norm_app(g.application))

        portals_out: Dict[str, Any] = {}
        for portal_key in ("college", "shopping", "healthcare"):
            lk = lock_by_app.get(portal_key)
            if lk:
                portals_out[portal_key] = {
                    "portal": portal_key,
                    "portal_display_name": _portal_display_name(portal_key),
                    "locked": True,
                    "status": "SUSPENDED",
                    "grant_active": False,
                    "lock": cls.serialize_lock(lk),
                }
            else:
                has_grant = portal_key in granted_apps
                portals_out[portal_key] = {
                    "portal": portal_key,
                    "portal_display_name": _portal_display_name(portal_key),
                    "locked": False,
                    "status": "AUTHORIZED" if has_grant else "AVAILABLE",
                    "grant_active": has_grant,
                    "lock": None,
                }

        sess_status = (current_session.status if current_session else None) or "ACTIVE"
        sess_app = _norm_app(current_session.application) if current_session else "platform"
        sess_valid = bool(current_session is None or sess_status not in ("TERMINATED", "EXPIRED"))
        portal_auth_completed = bool(
            current_session
            and sess_status == "ACTIVE"
            and (current_session.login_outcome in (None, "verified", "active"))
        )

        return {
            "authenticated": sess_valid,
            "global_session": {
                "session_id": current_session.id if current_session else None,
                "session_status": sess_status,
                "application": sess_app,
                "valid": sess_valid,
                "portal_auth_completed": portal_auth_completed,
                "has_suspended_portals": len(serialized_locks) > 0,
            },
            "locks": serialized_locks,
            "portals": portals_out,
        }

    @classmethod
    def record_verification_failure(
        cls,
        db: Session,
        user_id: int,
        application: Optional[str],
        verification_purpose: str,
        factor_key: str,
        session_id: Optional[str] = None,
        challenge_reference: Optional[str] = None,
        lock_reason: Optional[str] = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        emit_step_up_locked_event: bool = False,
        max_attempts_override: Optional[int] = None,
    ) -> Tuple[bool, int, int, int, Optional[PortalSecurityLock]]:
        """
        Atomically records a verification failure in VerificationAttemptCounter scoped to
        (user_id, session_id, application, verification_purpose, factor_key).
        On reaching the factor's maximum failure limit, performs portal-scoped ejection via
        lock_portal(): suspends ONLY that portal, revokes ONLY that portal's grants, and
        preserves global authenticated identity/session and unrelated portals.
        Returns: (is_locked, attempts_used, max_attempts, remaining_attempts, active_lock_or_None).
        """
        norm_app = _norm_app(application)
        purpose = (verification_purpose or "STEP_UP").strip().upper()
        factor = (factor_key or "UNKNOWN").strip().upper()
        sess_scope = (session_id or "").strip()
        configured_max = max_attempts_override or cls.get_max_attempts_for(purpose, factor)
        now = utc_now()

        with cls._op_lock:
            existing_lock = cls.get_active_lock(db, user_id, norm_app)
            if existing_lock:
                used_cnt = existing_lock.failed_attempt_count or configured_max
                max_cnt = existing_lock.max_attempts or configured_max
                return (True, used_cnt, max_cnt, 0, existing_lock)

            q = db.query(VerificationAttemptCounter).filter(
                VerificationAttemptCounter.user_id == user_id,
                VerificationAttemptCounter.session_id == sess_scope,
                VerificationAttemptCounter.application == norm_app,
                VerificationAttemptCounter.verification_purpose == purpose,
                VerificationAttemptCounter.factor_key == factor,
            )
            if db.bind and db.bind.dialect and db.bind.dialect.name != "sqlite":
                q = q.with_for_update()
            counter = q.first()

            if not counter:
                counter = VerificationAttemptCounter(
                    user_id=user_id,
                    session_id=sess_scope,
                    application=norm_app,
                    verification_purpose=purpose,
                    factor_key=factor,
                    attempts=0,
                    max_attempts=configured_max,
                    last_challenge_id=challenge_reference,
                    created_at=now,
                    updated_at=now,
                )
                db.add(counter)
                db.flush()
            else:
                counter.max_attempts = configured_max

            if counter.locked_at is not None or counter.attempts >= counter.max_attempts:
                counter.locked_at = counter.locked_at or now
                attempts_used = counter.attempts
                max_att = counter.max_attempts
                db.commit()
                lock = cls.lock_portal(
                    db=db,
                    user_id=user_id,
                    application=norm_app,
                    verification_purpose=purpose,
                    lock_reason=lock_reason or f"Maximum verification attempts ({max_att}) exceeded for {factor}.",
                    failed_attempt_count=attempts_used,
                    max_attempts=max_att,
                    session_id=sess_scope or None,
                    challenge_reference=challenge_reference or counter.last_challenge_id,
                    client_ip=client_ip,
                    user_agent=user_agent,
                    emit_step_up_locked_event=emit_step_up_locked_event,
                )
                return (True, attempts_used, max_att, 0, lock)

            counter.attempts += 1
            counter.last_challenge_id = challenge_reference or counter.last_challenge_id
            counter.updated_at = now

            if counter.attempts >= counter.max_attempts:
                counter.locked_at = now
                attempts_used = counter.attempts
                max_att = counter.max_attempts
                db.commit()
                lock = cls.lock_portal(
                    db=db,
                    user_id=user_id,
                    application=norm_app,
                    verification_purpose=purpose,
                    lock_reason=lock_reason or f"Maximum verification attempts ({max_att}) exceeded for {factor}.",
                    failed_attempt_count=attempts_used,
                    max_attempts=max_att,
                    session_id=sess_scope or None,
                    challenge_reference=challenge_reference or counter.last_challenge_id,
                    client_ip=client_ip,
                    user_agent=user_agent,
                    emit_step_up_locked_event=emit_step_up_locked_event,
                )
                return (True, attempts_used, max_att, 0, lock)

            attempts_used = counter.attempts
            max_att = counter.max_attempts
            remaining = max(0, max_att - attempts_used)
            db.commit()
            return (False, attempts_used, max_att, remaining, None)

    @classmethod
    def record_reentry_attempt(
        cls,
        db: Session,
        user: User,
        application: Optional[str],
        session_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        reentry_correlation_id: Optional[str] = None,
        is_auto_poll: bool = False,
        source: str = "PORTAL_REOPEN",
    ) -> Optional[Dict[str, Any]]:
        """
        Detects & records user-initiated re-entry attempts against an active portal lock.
        - Passive polling (`is_auto_poll=True`) NEVER triggers duplicate events/emails.
        - Exact correlation-ID retries of the same HTTP event are deduplicated cleanly.
        - Genuinely distinct re-entry attempts (refresh/new tab/direct URL/re-login) each
          record a SecurityEvent and send owner + Admin/SOC notifications.
        """
        norm_app = _norm_app(application)
        now = utc_now()
        dev_ctx = cls.extract_device_context(
            db, user_id=user.id, session_id=session_id, client_ip=client_ip, user_agent=user_agent
        )

        with cls._op_lock:
            lock = cls.get_active_lock(db, user.id, norm_app)
            if not lock:
                return None

            corr_clean = (reentry_correlation_id or "").strip()[:120]
            if is_auto_poll:
                out = cls.serialize_lock(lock)
                out["reentry_recorded"] = False
                return out

            # Deduplicate retries of the exact same event correlation ID
            if corr_clean and lock.last_reentry_corr_id == corr_clean:
                out = cls.serialize_lock(lock)
                out["reentry_recorded"] = False
                return out

            # Short burst deduplication ONLY when no explicit distinct correlation ID is supplied
            if not corr_clean and lock.last_reentry_notif_at:
                last_dt = lock.last_reentry_notif_at
                aware_last = last_dt if last_dt.tzinfo else last_dt.replace(tzinfo=timezone.utc)
                if (now - aware_last) < timedelta(seconds=3):
                    out = cls.serialize_lock(lock)
                    out["reentry_recorded"] = False
                    return out

            new_corr = corr_clean or f"REENTRY-{secrets.token_hex(6).upper()}"
            lock.reentry_attempts = (lock.reentry_attempts or 0) + 1
            lock.last_reentry_at = now
            lock.last_reentry_corr_id = new_corr
            lock.last_reentry_notif_at = now

            evt_details = {
                "portal": norm_app,
                "security_reference_id": lock.security_reference_id,
                "audit_correlation_id": lock.audit_correlation_id,
                "reentry_correlation_id": new_corr,
                "reentry_attempt_number": lock.reentry_attempts,
                "source": source,
                "event_type": "PORTAL_REENTRY_BLOCKED",
                "timestamp": now.isoformat(),
                "device_context": {
                    "device_summary": dev_ctx.get("device_summary"),
                    "ip_address": dev_ctx.get("ip_address"),
                    "location_summary": dev_ctx.get("location_summary"),
                },
            }
            sec_evt = SecurityEvent(
                user_id=user.id,
                session_id=session_id,
                application=norm_app,
                event_type="PORTAL_REENTRY_BLOCKED",
                severity="HIGH",
                decision="DENY",
                details=json.dumps(evt_details),
                timestamp=now,
            )
            db.add(sec_evt)
            db.commit()
            db.refresh(sec_evt)
            db.refresh(lock)

        msg = (
            f"Blocked attempt #{lock.reentry_attempts} to reopen locked {_portal_display_name(norm_app)} "
            f"({source}). Device: {dev_ctx.get('device_summary')}. Security Ref: {lock.security_reference_id}."
        )
        NotificationService.notify_portal_security_event(
            db=db,
            user=user,
            application=norm_app,
            notification_type="PORTAL_REENTRY_ATTEMPT",
            title=f"Blocked Re-Entry Attempt — {_portal_display_name(norm_app)}",
            message=msg,
            security_reference_id=lock.security_reference_id,
            lock_reason=lock.lock_reason,
            alert_type="PORTAL_REENTRY_ATTEMPT",
            alert_severity="HIGH",
            device_summary=dev_ctx.get("device_summary") or "Unknown Device Context",
            ip_address=dev_ctx.get("ip_address"),
            device_id=dev_ctx.get("device_id"),
            security_event_id=sec_evt.id,
            create_admin_alert=True,
        )
        out = cls.serialize_lock(lock)
        out["reentry_recorded"] = True
        out["reentry_correlation_id"] = new_corr
        return out

    @classmethod
    def record_recovery_otp_failure(
        cls,
        db: Session,
        user_id: int,
        application: Optional[str],
        security_reference_id: str,
        challenge_reference: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Tuple[int, int]:
        """
        Records a failed Recovery Email OTP attempt in its own purpose-specific
        VerificationAttemptCounter without resetting other counters or weakening/modifying
        the active PortalSecurityLock.
        """
        norm_app = _norm_app(application)
        now = utc_now()
        scope_sid = f"recov:{security_reference_id}"[:64]
        valid_sid = None
        if session_id:
            if db.query(DbSession.id).filter(DbSession.id == session_id).first():
                valid_sid = session_id

        with cls._op_lock:
            row = (
                db.query(VerificationAttemptCounter)
                .filter(
                    VerificationAttemptCounter.user_id == user_id,
                    VerificationAttemptCounter.session_id == scope_sid,
                    VerificationAttemptCounter.application == norm_app,
                    VerificationAttemptCounter.verification_purpose == "RECOVERY_OTP",
                    VerificationAttemptCounter.factor_key == "RECOVERY_EMAIL_OTP",
                )
                .first()
            )
            if not row:
                row = VerificationAttemptCounter(
                    user_id=user_id,
                    session_id=scope_sid,
                    application=norm_app,
                    verification_purpose="RECOVERY_OTP",
                    factor_key="RECOVERY_EMAIL_OTP",
                    attempts=0,
                    max_attempts=cls.LIMIT_RECOVERY_OTP,
                    created_at=now,
                    updated_at=now,
                )
                db.add(row)
            row.max_attempts = cls.LIMIT_RECOVERY_OTP
            row.attempts = int(row.attempts or 0) + 1
            row.last_challenge_id = challenge_reference
            row.updated_at = now
            if row.attempts >= row.max_attempts and not row.locked_at:
                row.locked_at = now

            sec_evt = SecurityEvent(
                user_id=user_id,
                session_id=valid_sid,
                application=norm_app,
                event_type="PORTAL_RECOVERY_OTP_FAILED",
                severity="MEDIUM",
                decision="DENY",
                details=json.dumps({
                    "portal": norm_app,
                    "security_reference_id": security_reference_id,
                    "challenge_id": challenge_reference,
                    "attempts": row.attempts,
                    "max_attempts": cls.LIMIT_RECOVERY_OTP,
                    "lock_remains_active": True,
                }),
                timestamp=now,
            )
            db.add(sec_evt)
            db.commit()
            return int(row.attempts), cls.LIMIT_RECOVERY_OTP

    @classmethod
    def mark_recovery_otp_verified(
        cls,
        db: Session,
        user: User,
        application: Optional[str],
        session_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        security_reference_id: Optional[str] = None,
    ) -> PortalSecurityLock:
        """
        Records step 2 of the security recovery gate (registered email OTP verification).
        Explicitly does NOT unlock the portal — administrator clearance remains mandatory.
        """
        norm_app = _norm_app(application)
        lock = cls.get_active_lock(db, user.id, norm_app)
        if not lock:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No active portal security lock found for '{norm_app}'."
            )
        if security_reference_id and lock.security_reference_id != security_reference_id.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Recovery OTP challenge does not match the active Security Reference ID."
            )
        valid_sid = None
        if session_id:
            if db.query(DbSession.id).filter(DbSession.id == session_id).first():
                valid_sid = session_id

        now = utc_now()
        dev_ctx = cls.extract_device_context(
            db, user_id=user.id, session_id=valid_sid, client_ip=client_ip, user_agent=user_agent
        )
        lock.recovery_otp_verified_at = now
        lock.recovery_status = "OTP_VERIFIED_AWAITING_ADMIN"

        sec_evt = SecurityEvent(
            user_id=user.id,
            session_id=valid_sid,
            application=norm_app,
            event_type="PORTAL_RECOVERY_OTP_VERIFIED",
            severity="MEDIUM",
            decision="PENDING_ADMIN_RECOVERY",
            details=json.dumps({
                "portal": norm_app,
                "security_reference_id": lock.security_reference_id,
                "recovery_status": lock.recovery_status,
                "lock_status": lock.lock_status,
                "note": "Owner verified recovery OTP; portal remains suspended awaiting authorized SOC/Admin clearance.",
            }),
            timestamp=now,
        )
        db.add(sec_evt)
        db.commit()
        db.refresh(sec_evt)
        db.refresh(lock)

        try:
            NotificationService.notify_portal_security_event(
                db=db,
                user=user,
                application=norm_app,
                notification_type="PORTAL_RECOVERY_REQUESTED",
                title=f"Recovery Clearance Requested — {_portal_display_name(norm_app)}",
                message=(
                    f"Account owner verified registered-email OTP for suspended {_portal_display_name(norm_app)} "
                    f"(Ref: {lock.security_reference_id}). Awaiting authorized Security Administrator clearance."
                ),
                security_reference_id=lock.security_reference_id,
                lock_reason=lock.lock_reason,
                alert_type="PORTAL_RECOVERY_REQUESTED",
                alert_severity="MEDIUM",
                device_summary=dev_ctx.get("device_summary") or "Unknown Device Context",
                ip_address=dev_ctx.get("ip_address"),
                device_id=dev_ctx.get("device_id"),
                security_event_id=sec_evt.id,
                create_admin_alert=True,
            )
        except Exception as exc:
            logger.warning(f"[COGNISEC-AI] Recovery OTP verification notification failure (state preserved): {exc}")
        return lock

    @classmethod
    def admin_recover_portal_lock(
        cls,
        db: Session,
        security_reference_id: str,
        admin_user: User,
        notes: Optional[str] = None,
        client_ip: Optional[str] = None,
    ) -> PortalSecurityLock:
        """
        Authorized administrator / SOC clearance of a persistent portal security lock.
        - Enforces ADMIN role and blocks self-approval.
        - Clears PortalSecurityLock and portal attempt counters.
        - Terminates restricted portal sessions so user must start fresh login + 20s observation + Email OTP.
        - Notifies both Account Owner and Admin/SOC.
        """
        if not admin_user or (admin_user.role or "").upper() != "ADMIN":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access restricted: Security Administrator privileges required to clear portal security locks."
            )

        with cls._op_lock:
            lock = (
                db.query(PortalSecurityLock)
                .filter(PortalSecurityLock.security_reference_id == security_reference_id)
                .first()
            )
            if not lock:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Portal security lock '{security_reference_id}' not found."
                )
            if lock.user_id == admin_user.id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Self-approval prohibited: an administrator cannot approve their own portal recovery."
                )
            if lock.lock_status != "ACTIVE":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Portal security lock '{security_reference_id}' has already been recovered."
                )

            now = utc_now()
            lock.lock_status = "RECOVERED"
            lock.recovery_status = "RECOVERED"
            lock.unlocked_by = admin_user.email
            lock.unlocked_by_user_id = admin_user.id
            lock.unlocked_at = now
            lock.recovery_notes = (notes or "Cleared by Security Administrator recovery gate.")[:500]

            # Clear verification attempt counters ONLY for this cleared portal
            db.query(VerificationAttemptCounter).filter(
                VerificationAttemptCounter.user_id == lock.user_id,
                VerificationAttemptCounter.application == lock.application,
            ).delete(synchronize_session=False)

            # Expire restricted sessions on this portal so next re-entry enforces fresh 20s observation + Email OTP
            portal_sessions = (
                db.query(DbSession)
                .filter(
                    DbSession.user_id == lock.user_id,
                    DbSession.application == lock.application,
                    DbSession.status.in_(["RESTRICTED", "PENDING_OBSERVATION", "PENDING_OTP", "STEP_UP_REQUIRED"]),
                )
                .all()
            )
            restricted_sids = [s.id for s in portal_sessions]
            for s in portal_sessions:
                s.status = "TERMINATED"
                s.logout_time = now
                s.step_up_verified_at = None
                s.step_up_valid_until = None
                s.step_up_factor = None

            # Ensure all prior ApplicationGrants for this portal remain revoked
            db.query(ApplicationGrant).filter(
                ApplicationGrant.user_id == lock.user_id,
                ApplicationGrant.application == lock.application,
                ApplicationGrant.revoked == False,
            ).update({"revoked": True}, synchronize_session=False)

            # Resolve open portal lockout alerts for this user & application
            db.query(Alert).filter(
                Alert.user_id == lock.user_id,
                Alert.application == lock.application,
                Alert.alert_type.in_([
                    "PORTAL_SECURITY_LOCKOUT",
                    "CROSS_PORTAL_LOCKOUT_ESCALATION",
                    "PORTAL_REENTRY_ATTEMPT",
                    "PORTAL_RECOVERY_REQUESTED",
                ]),
                Alert.status != "RESOLVED",
            ).update(
                {
                    "status": "RESOLVED",
                    "resolved_at": now,
                    "resolved_by": admin_user.email,
                    "resolution_reason": f"Portal lock {lock.security_reference_id} recovered by {admin_user.email}",
                },
                synchronize_session=False,
            )

            # Remove session-level STEP_UP_LOCKED markers on cleared sessions
            if restricted_sids:
                db.query(SecurityEvent).filter(
                    SecurityEvent.session_id.in_(restricted_sids),
                    SecurityEvent.event_type == "STEP_UP_LOCKED",
                ).delete(synchronize_session=False)

            sec_evt = SecurityEvent(
                user_id=lock.user_id,
                session_id=lock.session_id,
                application=lock.application,
                event_type="PORTAL_LOCK_RECOVERED",
                severity="LOW",
                decision="ALLOW",
                details=json.dumps({
                    "portal": lock.application,
                    "security_reference_id": lock.security_reference_id,
                    "unlocked_by": admin_user.email,
                    "admin_user_id": admin_user.id,
                    "clearance_decision": "APPROVED",
                    "recovery_notes": lock.recovery_notes,
                    "requires_fresh_observation_and_otp": True,
                }),
                timestamp=now,
            )
            db.add(sec_evt)
            db.commit()
            db.refresh(sec_evt)
            db.refresh(lock)

        owner = db.query(User).filter(User.id == lock.user_id).first()
        if owner:
            try:
                NotificationService.notify_portal_security_event(
                    db=db,
                    user=owner,
                    application=lock.application,
                    notification_type="PORTAL_ACCESS_RESTORED",
                    title=f"Portal Access Restored — {_portal_display_name(lock.application)}",
                    message=(
                        f"Authorized administrator clearance approved for {_portal_display_name(lock.application)} "
                        f"(Ref: {lock.security_reference_id}). Please sign in and complete a fresh 20-second "
                        f"behavioral observation and Email OTP."
                    ),
                    security_reference_id=lock.security_reference_id,
                    lock_reason="Authorized administrator recovery approved",
                    alert_type="PORTAL_ACCESS_RESTORED",
                    alert_severity="LOW",
                    device_summary=f"Approved by {admin_user.email}",
                    ip_address=client_ip,
                    security_event_id=sec_evt.id,
                    create_admin_alert=False,
                )
            except Exception as exc:
                logger.warning(f"[COGNISEC-AI] Admin recovery notification failure (state preserved): {exc}")
        return lock

    @classmethod
    def admin_reject_portal_lock(
        cls,
        db: Session,
        security_reference_id: str,
        admin_user: User,
        notes: Optional[str] = None,
        client_ip: Optional[str] = None,
    ) -> PortalSecurityLock:
        """
        Records explicit Security Administrator / SOC rejection of a portal recovery request.
        Keeps PortalSecurityLock.lock_status == "ACTIVE" and portal access blocked.
        """
        if not admin_user or (admin_user.role or "").upper() != "ADMIN":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access restricted: Security Administrator privileges required to review portal recovery."
            )

        with cls._op_lock:
            lock = (
                db.query(PortalSecurityLock)
                .filter(PortalSecurityLock.security_reference_id == security_reference_id)
                .first()
            )
            if not lock:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Portal security lock '{security_reference_id}' not found."
                )
            if lock.user_id == admin_user.id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Self-review prohibited: an administrator cannot adjudicate their own portal recovery."
                )
            if lock.lock_status != "ACTIVE":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Portal security lock '{security_reference_id}' is already recovered and cannot be rejected."
                )

            now = utc_now()
            lock.lock_status = "ACTIVE"
            lock.recovery_status = "REJECTED_BY_ADMIN"
            lock.unlocked_by = admin_user.email
            lock.unlocked_by_user_id = admin_user.id
            lock.unlocked_at = None
            lock.recovery_notes = (notes or "Recovery clearance rejected by Security Administrator.")[:500]

            sec_evt = SecurityEvent(
                user_id=lock.user_id,
                session_id=lock.session_id,
                application=lock.application,
                event_type="PORTAL_LOCK_RECOVERY_REJECTED",
                severity="HIGH",
                decision="DENY",
                details=json.dumps({
                    "portal": lock.application,
                    "security_reference_id": lock.security_reference_id,
                    "reviewed_by": admin_user.email,
                    "admin_user_id": admin_user.id,
                    "clearance_decision": "REJECTED",
                    "recovery_notes": lock.recovery_notes,
                    "timestamp": now.isoformat(),
                }),
                timestamp=now,
            )
            db.add(sec_evt)
            db.commit()
            db.refresh(sec_evt)
            db.refresh(lock)

        owner = db.query(User).filter(User.id == lock.user_id).first()
        if owner:
            try:
                NotificationService.notify_portal_security_event(
                    db=db,
                    user=owner,
                    application=lock.application,
                    notification_type="PORTAL_LOCK_RECOVERY_REJECTED",
                    title=f"Portal Recovery Rejected — {_portal_display_name(lock.application)}",
                    message=(
                        f"Security Administrator clearance for {_portal_display_name(lock.application)} "
                        f"(Ref: {lock.security_reference_id}) was rejected ({lock.recovery_notes}). Portal remains suspended."
                    ),
                    security_reference_id=lock.security_reference_id,
                    lock_reason=lock.recovery_notes or lock.lock_reason,
                    alert_type="PORTAL_LOCK_RECOVERY_REJECTED",
                    alert_severity="HIGH",
                    device_summary=f"Rejected by {admin_user.email}",
                    ip_address=client_ip,
                    security_event_id=sec_evt.id,
                    create_admin_alert=True,
                )
            except Exception as exc:
                logger.warning(f"[COGNISEC-AI] Admin rejection notification failure (state preserved): {exc}")
        return lock

