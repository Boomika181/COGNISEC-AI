"""
Shared Cognitive-Verified Password Change Service across all COGNISEC-AI portals
(Shopping, College, Healthcare, Platform).

Enforces:
- Server-side identity & session binding (never trusts client-supplied user IDs)
- Authoritative deterministic risk policy & arbiter enforcement (LOW/MEDIUM/HIGH/CRITICAL)
- Current password verification via existing bcrypt hashing helpers
- Mandatory action-specific two-part cognitive verification:
  1) COGNITIVE_IMAGE_SEQUENCE
  2) PRIVATE_RESPONSE
- Single-use atomic transaction consumption, expiry, attempt limits, and replay prevention
- SecurityEvent audit trail, email confirmation notification, and post-change session revocation
"""

import logging
import secrets
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.agents.core.arbiter import DeterministicSecurityArbiter
from app.core.security import get_password_hash, verify_password
from app.models.password_change import PasswordChangeTransaction
from app.models.security_event import SecurityEvent
from app.models.session import Session as DbSession
from app.models.user import User
from app.schemas.auth import validate_password_strength
from app.services.adaptive_auth_service import AdaptiveAuthService
from app.services.email_service import EmailService
from app.services.risk_service import RiskService
from app.services.session_service import SessionService
from app.services.step_up_service import StepUpService

logger = logging.getLogger("cognisec.password_change")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


ALLOWED_PORTALS = {"shopping", "college", "healthcare", "platform"}


class PasswordChangeService:
    DEFAULT_TTL_SECONDS = 300
    MAX_COGNITIVE_ATTEMPTS = 2
    MAX_IMAGE_ATTEMPTS = 2
    MAX_PRIVATE_ATTEMPTS = 2
    _confirm_locks_guard = threading.Lock()
    _confirm_locks: Dict[int, threading.RLock] = {}

    @classmethod
    def _get_user_lock(cls, user_id: int) -> threading.RLock:
        with cls._confirm_locks_guard:
            lock = cls._confirm_locks.get(user_id)
            if lock is None:
                lock = threading.RLock()
                cls._confirm_locks[user_id] = lock
            return lock

    @classmethod
    def normalize_portal(cls, application: Optional[str]) -> str:
        norm = SessionService.normalize_application(application) or "platform"
        if norm not in ALLOWED_PORTALS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported portal application '{application}'."
            )
        return norm

    @classmethod
    def resolve_and_validate_session(
        cls,
        db: Session,
        current_user: User,
        requested_session_id: Optional[str] = None,
        token_session_id: Optional[str] = None,
    ) -> DbSession:
        """Resolves session ID authoritatively and prevents session spoofing or unverified access."""
        if requested_session_id and token_session_id and requested_session_id != token_session_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Session identifier mismatch against authenticated token."
            )
        sid = requested_session_id or token_session_id
        if not sid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Active session identifier is required for password change."
            )

        db_session = SessionService.get_session(db, sid)
        if not db_session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found."
            )
        if db_session.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Unauthorized: Session does not belong to authenticated user."
            )
        if db_session.status in ("TERMINATED", "EXPIRED"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session has been terminated or expired. Please sign in again."
            )
        if db_session.status in ("PENDING_OBSERVATION", "PENDING_OTP"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Password change requires an active verified session (current status: {db_session.status})."
            )
        return db_session

    @classmethod
    def _resolve_deterministic_risk(cls, db: Session, db_session: DbSession) -> Tuple[float, str]:
        """Resolves authoritative deterministic risk score and tier from session + latest SecurityEvent."""
        tier_defaults = {"LOW": 0.15, "MEDIUM": 0.45, "HIGH": 0.75, "CRITICAL": 0.90}
        sess_level = (db_session.current_risk_level or "LOW").strip().upper()
        if sess_level not in tier_defaults:
            sess_level = "LOW"

        latest_event = (
            db.query(SecurityEvent)
            .filter(SecurityEvent.session_id == db_session.id)
            .order_by(SecurityEvent.id.desc())
            .first()
        )
        det_score = tier_defaults[sess_level]
        if latest_event and latest_event.risk_score is not None:
            event_score = float(latest_event.risk_score)
            event_level = RiskService.classify_risk_level(event_score)
            # Never let a lower historical event score downgrade a higher active session risk tier
            eff_score, eff_level, _, _ = DeterministicSecurityArbiter.arbitrate_risk(
                deterministic_score=max(event_score, tier_defaults[sess_level]) if sess_level != "LOW" else event_score,
                deterministic_level=sess_level if tier_defaults[sess_level] >= tier_defaults.get(event_level, 0.15) else event_level,
            )
            return eff_score, eff_level

        eff_score, eff_level, _, _ = DeterministicSecurityArbiter.arbitrate_risk(
            deterministic_score=det_score,
            deterministic_level=sess_level,
        )
        return eff_score, eff_level

    @classmethod
    def _terminate_on_critical(
        cls,
        db: Session,
        user: User,
        db_session: DbSession,
        application: str,
        reason: str,
    ) -> None:
        """Immediately terminates session, revokes grants, and invalidates active password-change tx."""
        db.query(PasswordChangeTransaction).filter(
            PasswordChangeTransaction.session_id == db_session.id,
            PasswordChangeTransaction.is_consumed == False,
        ).update({"status": "REVOKED", "is_consumed": True, "consumed_at": utc_now()})

        SessionService.revoke_application_grants(db, session_id=db_session.id, user_id=user.id)
        SessionService.terminate_session(db, db_session.id, risk_level="CRITICAL")

        sec_event = SecurityEvent(
            user_id=user.id,
            session_id=db_session.id,
            application=application,
            event_type="PASSWORD_CHANGE_BLOCKED_CRITICAL",
            severity="CRITICAL",
            risk_score=0.95,
            decision="TERMINATE_SESSION",
            details=reason,
        )
        db.add(sec_event)
        db.commit()

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Critical security risk detected. Session terminated and grants revoked; password change denied.",
            headers={"X-Cognisec-Decision": "TERMINATE_SESSION"},
        )

    @classmethod
    def _enforce_risk_gate(
        cls,
        db: Session,
        user: User,
        db_session: DbSession,
        application: str,
    ) -> Tuple[float, str]:
        """
        Enforces exact Zero Trust behavioral risk rules before password-change progression:
        - CRITICAL (>=0.85): terminate session, revoke grants, deny unconditionally.
        - Hard lockout (STEP_UP_LOCKED / ADMIN_REVOCATION / SESSION_TERMINATED): deny.
        - MEDIUM (0.30-<0.65) or STEP_UP_REQUIRED with MEDIUM: requires fresh GESTURE_PATTERN.
        - LOW STEP_UP_REQUIRED: requires OTP step-up verification first.
        - HIGH (0.65-<0.85): allowed to proceed ONLY via action-specific two-part cognitive checks.
        """
        from app.services.portal_lock_service import PortalLockService
        PortalLockService.enforce_not_locked(db, user.id, application)
        if db_session.status == "TERMINATED":
            PortalLockService.terminate_session_and_revoke_grants(
                db=db,
                user_id=user.id,
                session_id=db_session.id,
                application=application,
                verification_purpose="PASSWORD_CHANGE",
                factor_key="COGNITIVE",
            )
            PortalLockService.raise_terminated_http_exception(status_code=status.HTTP_401_UNAUTHORIZED)

        risk_score, risk_level = cls._resolve_deterministic_risk(db, db_session)

        if risk_level == "CRITICAL" or risk_score >= 0.85:
            cls._terminate_on_critical(
                db, user, db_session, application,
                f"Password change denied and session terminated due to CRITICAL risk (score={risk_score:.2f})."
            )

        from sqlalchemy import or_, and_
        hard_lock = (
            db.query(SecurityEvent)
            .filter(
                SecurityEvent.session_id == db_session.id,
                or_(
                    SecurityEvent.event_type.in_(["ADMIN_REVOCATION", "SESSION_TERMINATED"]),
                    and_(
                        SecurityEvent.event_type == "STEP_UP_LOCKED",
                        SecurityEvent.application == application,
                    ),
                ),
            )
            .first()
        )
        if hard_lock:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Session is security-restricted due to excessive failed attempts or revocation. Sign out and sign in again.",
            )

        # MEDIUM risk behavioral gate: NeuralTrace (GESTURE_PATTERN) must already be verified on session
        if risk_level == "MEDIUM":
            has_fresh_gesture = SessionService.is_step_up_fresh(
                db_session,
                current_risk_score=risk_score,
                current_risk_level="MEDIUM",
                required_factor="GESTURE_PATTERN",
            )
            if not has_fresh_gesture:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Behavioral step-up verification required: complete NeuralTrace GESTURE_PATTERN before password change cognitive verification.",
                    headers={"X-Cognisec-Required-Factor": "GESTURE_PATTERN"},
                )

        # LOW risk with active STEP_UP_REQUIRED: must satisfy LOW-risk Email OTP first
        if risk_level == "LOW" and db_session.status == "STEP_UP_REQUIRED":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Behavioral step-up verification required: complete Email OTP verification before changing password.",
                headers={"X-Cognisec-Required-Factor": "OTP"},
            )

        return risk_score, risk_level

    @classmethod
    def _get_required_enrollment(cls, db: Session, user_id: int) -> Tuple[Dict[str, Any], Optional[str]]:
        enrollment = AdaptiveAuthService.get_enrollment_status(db, user_id)
        has_img = bool(enrollment.get("has_cognitive_image_sequence", False))
        has_priv = bool(enrollment.get("has_private_response", False))
        if not (has_img and has_priv):
            missing = []
            if not has_img:
                missing.append("Cognitive Image Sequence")
            if not has_priv:
                missing.append("Private Security Response")
            return enrollment, " and ".join(missing)
        return enrollment, None

    @classmethod
    def get_policy(
        cls,
        db: Session,
        current_user: User,
        db_session: DbSession,
        application: str,
    ) -> Dict[str, Any]:
        norm_app = cls.normalize_portal(application)
        from app.services.portal_lock_service import PortalLockService
        PortalLockService.enforce_not_locked(db, current_user.id, norm_app)
        from app.services.portal_lock_service import PortalLockService
        PortalLockService.enforce_not_locked(db, current_user.id, norm_app)
        if db_session.status == "TERMINATED":
            PortalLockService.terminate_session_and_revoke_grants(
                db=db,
                user_id=current_user.id,
                session_id=db_session.id,
                application=application,
                verification_purpose="PASSWORD_CHANGE",
                factor_key="COGNITIVE",
            )
            PortalLockService.raise_terminated_http_exception(status_code=status.HTTP_401_UNAUTHORIZED)

        risk_score, risk_level = cls._resolve_deterministic_risk(db, db_session)
        enrollment = AdaptiveAuthService.get_enrollment_status(db, current_user.id)

        requires_behavioral = False
        req_factor = None
        can_proceed = True
        msg = "Enter your current password and complete both cognitive verifications to change your password."

        if risk_level == "CRITICAL" or risk_score >= 0.85:
            cls._terminate_on_critical(
                db, current_user, db_session, norm_app,
                "Critical risk detected while inspecting password change policy."
            )

        if risk_level == "MEDIUM":
            if not SessionService.is_step_up_fresh(
                db_session,
                current_risk_score=risk_score,
                current_risk_level="MEDIUM",
                required_factor="GESTURE_PATTERN",
            ):
                requires_behavioral = True
                req_factor = "GESTURE_PATTERN"
                msg = "Moderate behavioral risk detected. Complete NeuralTrace gesture verification before password change."
        elif risk_level == "LOW" and db_session.status == "STEP_UP_REQUIRED":
            requires_behavioral = True
            req_factor = "OTP"
            msg = "Complete Email OTP step-up verification before initiating password change."

        if not (enrollment.get("has_cognitive_image_sequence") and enrollment.get("has_private_response")):
            can_proceed = False
            msg = "Both Cognitive Image Sequence and Private Security Response must be enrolled in MFA Setup before changing your password."

        return {
            "has_cognitive_image_sequence": bool(enrollment.get("has_cognitive_image_sequence", False)),
            "has_private_response": bool(enrollment.get("has_private_response", False)),
            "has_gesture_pattern": bool(enrollment.get("has_gesture_pattern", False)),
            "private_question": enrollment.get("private_question"),
            "catalogue": AdaptiveAuthService.get_catalogue(),
            "risk_level": risk_level,
            "session_status": db_session.status,
            "requires_behavioral_step_up": requires_behavioral,
            "required_behavioral_factor": req_factor,
            "can_proceed": can_proceed,
            "message": msg,
        }

    @classmethod
    def initiate_change(
        cls,
        db: Session,
        current_user: User,
        db_session: DbSession,
        application: str,
        current_password: str,
        bound_high_risk_challenge_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        norm_app = cls.normalize_portal(application)
        from app.services.portal_lock_service import PortalLockService
        PortalLockService.enforce_not_locked(db, current_user.id, norm_app)
        risk_score, risk_level = cls._enforce_risk_gate(db, current_user, db_session, norm_app)

        from app.services.portal_lock_service import PortalLockService
        img_cnt = PortalLockService.get_attempt_counter_status(
            db, current_user.id, norm_app, "PASSWORD_CHANGE", "COGNITIVE_IMAGE_SEQUENCE",
            session_id=db_session.id, max_attempts_override=cls.MAX_COGNITIVE_ATTEMPTS,
        )
        priv_cnt = PortalLockService.get_attempt_counter_status(
            db, current_user.id, norm_app, "PASSWORD_CHANGE", "PRIVATE_RESPONSE",
            session_id=db_session.id, max_attempts_override=cls.MAX_COGNITIVE_ATTEMPTS,
        )
        if img_cnt["exhausted"] or priv_cnt["exhausted"]:
            failing_factor = "COGNITIVE_IMAGE_SEQUENCE" if img_cnt["exhausted"] else "PRIVATE_RESPONSE"
            lock_obj = PortalLockService.lock_portal(
                db=db,
                user_id=current_user.id,
                application=norm_app,
                verification_purpose="PASSWORD_CHANGE",
                lock_reason=f"Maximum {failing_factor} verification attempts exceeded during password change.",
                failed_attempt_count=img_cnt["attempts_used"] if img_cnt["exhausted"] else priv_cnt["attempts_used"],
                max_attempts=cls.MAX_COGNITIVE_ATTEMPTS,
                session_id=db_session.id,
                emit_step_up_locked_event=True,
            )
            PortalLockService.raise_locked_http_exception(lock_obj, status_code=status.HTTP_423_LOCKED)

        if not current_password or not isinstance(current_password, str):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is required."
            )

        if not verify_password(current_password, current_user.password_hash):
            sec_fail = SecurityEvent(
                user_id=current_user.id,
                session_id=db_session.id,
                application=norm_app,
                event_type="PASSWORD_CHANGE_AUTH_FAILED",
                severity="MEDIUM",
                decision="BLOCK",
                details=f"Incorrect current password provided during password change initiation on '{norm_app}'."
            )
            db.add(sec_fail)
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Current password is incorrect."
            )

        enrollment, missing_str = cls._get_required_enrollment(db, current_user.id)
        if missing_str:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Two-part cognitive verification is mandatory for password changes. Please enroll {missing_str} in MFA Setup first."
            )

        # Invalidate any prior active password-change transactions for this session
        now = utc_now()
        db.query(PasswordChangeTransaction).filter(
            PasswordChangeTransaction.user_id == current_user.id,
            PasswordChangeTransaction.session_id == db_session.id,
            PasswordChangeTransaction.is_consumed == False,
        ).update({"status": "CANCELLED", "is_consumed": True, "consumed_at": now})

        # Optional explicit HIGH_RISK_DUAL step-up binding ONLY if resource == 'password_change'
        already_completed_dual = False
        bound_cid = None
        if bound_high_risk_challenge_id:
            ok_bound, bound_msg = StepUpService.consume_bound_password_change_challenge(
                challenge_id=bound_high_risk_challenge_id,
                user_id=current_user.id,
                session_id=db_session.id,
                application=norm_app,
            )
            if not ok_bound:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=bound_msg,
                )
            already_completed_dual = True
            bound_cid = bound_high_risk_challenge_id

        tx_id = f"pwdchg_{secrets.token_hex(8)}"
        img_cid = f"chal_pcimg_{secrets.token_hex(8)}"
        priv_cid = f"chal_pcpriv_{secrets.token_hex(8)}"

        tx = PasswordChangeTransaction(
            transaction_id=tx_id,
            user_id=current_user.id,
            session_id=db_session.id,
            application=norm_app,
            status="READY_TO_COMMIT" if already_completed_dual else "PENDING_IMAGE",
            current_password_verified=True,
            risk_level_at_init=risk_level,
            risk_score_at_init=risk_score,
            bound_stepup_challenge_id=bound_cid,
            image_challenge_id=img_cid,
            image_verified=already_completed_dual,
            image_verified_at=now if already_completed_dual else None,
            private_challenge_id=priv_cid,
            private_verified=already_completed_dual,
            private_verified_at=now if already_completed_dual else None,
            attempts=0,
            max_attempts=cls.MAX_COGNITIVE_ATTEMPTS,
            image_attempts=0,
            image_max_attempts=cls.MAX_COGNITIVE_ATTEMPTS,
            private_attempts=0,
            private_max_attempts=cls.MAX_COGNITIVE_ATTEMPTS,
            is_consumed=False,
            expires_at=now + timedelta(seconds=cls.DEFAULT_TTL_SECONDS),
            created_at=now,
        )
        db.add(tx)
        db.add(SecurityEvent(
            user_id=current_user.id,
            session_id=db_session.id,
            application=norm_app,
            event_type="PASSWORD_CHANGE_INITIATED",
            severity="LOW" if risk_level == "LOW" else risk_level,
            decision="STEP_UP_VERIFICATION",
            details=f"Password change transaction initialized in '{norm_app}' portal; action-bound cognitive challenges issued."
        ))
        db.commit()
        db.refresh(tx)

        return {
            "success": True,
            "transaction_id": tx.transaction_id,
            "image_challenge_id": tx.image_challenge_id,
            "private_challenge_id": tx.private_challenge_id,
            "application": norm_app,
            "risk_level": risk_level,
            "current_stage": 3 if already_completed_dual else 1,
            "expires_in_seconds": cls.DEFAULT_TTL_SECONDS,
            "private_question": enrollment.get("private_question") or "Security Verification Question",
            "catalogue": AdaptiveAuthService.get_catalogue(),
            "already_completed_high_risk_dual": already_completed_dual,
            "image_attempts_remaining": img_cnt["attempts_remaining"],
            "private_attempts_remaining": priv_cnt["attempts_remaining"],
            "max_attempts": cls.MAX_COGNITIVE_ATTEMPTS,
            "message": (
                "Bound HIGH_RISK_DUAL verification confirmed. Set your new password."
                if already_completed_dual
                else "Current password verified. Complete Cognitive Step 1: Image Sequence."
            ),
        }

    @classmethod
    def _load_bound_transaction(
        cls,
        db: Session,
        transaction_id: str,
        current_user: User,
        db_session: DbSession,
        norm_app: str,
    ) -> PasswordChangeTransaction:
        tx = (
            db.query(PasswordChangeTransaction)
            .populate_existing()
            .filter(PasswordChangeTransaction.transaction_id == transaction_id)
            .first()
        )
        if not tx:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Password change transaction not found."
            )
        if tx.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Unauthorized: Password change transaction does not belong to authenticated user."
            )
        if tx.session_id != db_session.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Unauthorized: Password change transaction does not belong to the active session."
            )
        if tx.application != norm_app:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Portal mismatch: Transaction belongs to '{tx.application}' and cannot be used from '{norm_app}'."
            )
        if tx.is_consumed or tx.status in ("COMPLETED", "CANCELLED", "LOCKED", "REVOKED"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Password change transaction is no longer active (status: {tx.status}). Please restart."
            )
        if utc_now() > _as_utc(tx.expires_at):
            tx.status = "EXPIRED"
            tx.is_consumed = True
            tx.consumed_at = utc_now()
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password change verification challenges have expired. Please restart password change."
            )
        return tx

    @classmethod
    def _record_cognitive_failure(
        cls,
        db: Session,
        tx: PasswordChangeTransaction,
        current_user: User,
        db_session: DbSession,
        norm_app: str,
        step_label: str,
        factor_key: str,
    ) -> None:
        from app.services.portal_lock_service import PortalLockService

        if factor_key == "COGNITIVE_IMAGE_SEQUENCE":
            tx.image_attempts = (tx.image_attempts or 0) + 1
        else:
            tx.private_attempts = (tx.private_attempts or 0) + 1
        tx.attempts = (tx.image_attempts or 0) + (tx.private_attempts or 0)

        is_locked, used, max_att, remaining, lock_obj = PortalLockService.record_verification_failure(
            db=db,
            user_id=current_user.id,
            application=norm_app,
            verification_purpose="PASSWORD_CHANGE",
            factor_key=factor_key,
            session_id=db_session.id,
            challenge_reference=tx.transaction_id,
            lock_reason=f"Password change {step_label} verification failed ({cls.MAX_COGNITIVE_ATTEMPTS} attempts maximum).",
            emit_step_up_locked_event=True,
            max_attempts_override=cls.MAX_COGNITIVE_ATTEMPTS,
        )

        if is_locked:
            tx.status = "LOCKED"
            tx.is_consumed = True
            tx.consumed_at = utc_now()
            db.add(SecurityEvent(
                user_id=current_user.id,
                session_id=db_session.id,
                application=norm_app,
                event_type="PASSWORD_CHANGE_COGNITIVE_LOCKED",
                severity="HIGH",
                decision="LOCK_PORTAL",
                details=f"Portal '{norm_app}' suspended after exceeding max {step_label} verification attempts ({used}/{max_att})."
            ))
            db.commit()
            if lock_obj:
                PortalLockService.raise_locked_http_exception(lock_obj, status_code=status.HTTP_423_LOCKED)
            PortalLockService.enforce_not_locked(db, current_user.id, norm_app)

        db.add(SecurityEvent(
            user_id=current_user.id,
            session_id=db_session.id,
            application=norm_app,
            event_type="PASSWORD_CHANGE_COGNITIVE_FAILED",
            severity="MEDIUM",
            decision="STEP_UP_VERIFICATION",
            details=f"Failed {step_label} verification during password change ({remaining} attempts remaining)."
        ))
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid {step_label} verification. {remaining} attempt{'s' if remaining != 1 else ''} remaining.",
            headers={"X-Cognisec-Attempts-Remaining": str(remaining)},
        )

    @classmethod
    def verify_image_challenge(
        cls,
        db: Session,
        current_user: User,
        db_session: DbSession,
        application: str,
        transaction_id: str,
        image_challenge_id: str,
        image_sequence: List[str],
    ) -> Dict[str, Any]:
        norm_app = cls.normalize_portal(application)
        from app.services.portal_lock_service import PortalLockService
        PortalLockService.enforce_not_locked(db, current_user.id, norm_app)
        cls._enforce_risk_gate(db, current_user, db_session, norm_app)
        tx = cls._load_bound_transaction(db, transaction_id, current_user, db_session, norm_app)

        if tx.image_challenge_id != image_challenge_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Image challenge ID does not match active password change transaction."
            )
        if tx.image_verified or tx.status != "PENDING_IMAGE":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Image sequence challenge has already been verified or is out of sequence."
            )
        if not image_sequence or len(image_sequence) < 3:
            cls._record_cognitive_failure(db, tx, current_user, db_session, norm_app, "cognitive image sequence", "COGNITIVE_IMAGE_SEQUENCE")

        is_valid = AdaptiveAuthService.verify_enrolled_factor(
            db=db,
            user_id=current_user.id,
            factor_type="COGNITIVE_IMAGE_SEQUENCE",
            image_sequence=image_sequence,
        )
        if not is_valid:
            cls._record_cognitive_failure(db, tx, current_user, db_session, norm_app, "cognitive image sequence", "COGNITIVE_IMAGE_SEQUENCE")

        from app.services.portal_lock_service import PortalLockService
        PortalLockService.reset_factor_counter_on_success(
            db, current_user.id, norm_app, "PASSWORD_CHANGE", "COGNITIVE_IMAGE_SEQUENCE", session_id=db_session.id
        )

        now = utc_now()
        tx.image_verified = True
        tx.image_verified_at = now
        tx.status = "PENDING_PRIVATE"
        db.add(SecurityEvent(
            user_id=current_user.id,
            session_id=db_session.id,
            application=norm_app,
            event_type="PASSWORD_CHANGE_IMAGE_VERIFIED",
            severity="LOW",
            decision="STEP_UP_VERIFICATION",
            details=f"Stage 1 cognitive image sequence verified for password change in '{norm_app}'."
        ))
        db.commit()

        enrollment = AdaptiveAuthService.get_enrollment_status(db, current_user.id)
        return {
            "success": True,
            "transaction_id": tx.transaction_id,
            "image_challenge_id": tx.image_challenge_id,
            "image_verified": True,
            "current_stage": 2,
            "private_challenge_id": tx.private_challenge_id,
            "private_question": enrollment.get("private_question") or "Security Verification Question",
            "message": "Cognitive image sequence verified. Complete Stage 2: Private Security Response.",
        }

    @classmethod
    def verify_private_challenge(
        cls,
        db: Session,
        current_user: User,
        db_session: DbSession,
        application: str,
        transaction_id: str,
        private_challenge_id: str,
        private_response: str,
    ) -> Dict[str, Any]:
        norm_app = cls.normalize_portal(application)
        from app.services.portal_lock_service import PortalLockService
        PortalLockService.enforce_not_locked(db, current_user.id, norm_app)
        cls._enforce_risk_gate(db, current_user, db_session, norm_app)
        tx = cls._load_bound_transaction(db, transaction_id, current_user, db_session, norm_app)

        if tx.private_challenge_id != private_challenge_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Private security challenge ID does not match active password change transaction."
            )
        if not tx.image_verified or tx.status == "PENDING_IMAGE":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cognitive image sequence (Step 1) must be verified before private security response."
            )
        if tx.private_verified or tx.status != "PENDING_PRIVATE":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Private security challenge has already been verified or consumed."
            )
        if not private_response or not str(private_response).strip():
            cls._record_cognitive_failure(db, tx, current_user, db_session, norm_app, "private security response", "PRIVATE_RESPONSE")

        is_valid = AdaptiveAuthService.verify_enrolled_factor(
            db=db,
            user_id=current_user.id,
            factor_type="PRIVATE_RESPONSE",
            private_response=str(private_response).strip(),
        )
        if not is_valid:
            cls._record_cognitive_failure(db, tx, current_user, db_session, norm_app, "private security response", "PRIVATE_RESPONSE")

        from app.services.portal_lock_service import PortalLockService
        PortalLockService.reset_factor_counter_on_success(
            db, current_user.id, norm_app, "PASSWORD_CHANGE", "PRIVATE_RESPONSE", session_id=db_session.id
        )

        now = utc_now()
        tx.private_verified = True
        tx.private_verified_at = now
        tx.status = "READY_TO_COMMIT"
        db.add(SecurityEvent(
            user_id=current_user.id,
            session_id=db_session.id,
            application=norm_app,
            event_type="PASSWORD_CHANGE_PRIVATE_VERIFIED",
            severity="LOW",
            decision="STEP_UP_VERIFICATION",
            details=f"Stage 2 private security response verified for password change in '{norm_app}'."
        ))
        db.commit()

        return {
            "success": True,
            "transaction_id": tx.transaction_id,
            "private_challenge_id": tx.private_challenge_id,
            "private_verified": True,
            "ready_to_commit": True,
            "current_stage": 3,
            "message": "Both cognitive factors verified. Enter your new password to confirm.",
        }

    @classmethod
    def confirm_password_change(
        cls,
        db: Session,
        current_user: User,
        db_session: DbSession,
        application: str,
        transaction_id: str,
        new_password: str,
        confirm_password: str,
        client_ip: str = "127.0.0.1",
        bound_high_risk_challenge_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        norm_app = cls.normalize_portal(application)
        from app.services.portal_lock_service import PortalLockService
        PortalLockService.enforce_not_locked(db, current_user.id, norm_app)

        if confirm_password != new_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New password and confirmation do not match."
            )
        try:
            validate_password_strength(new_password)
        except ValueError as ve:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(ve)
            )

        with cls._get_user_lock(current_user.id):
            current_user = db.query(User).populate_existing().filter(User.id == current_user.id).first() or current_user
            db_session = db.query(DbSession).populate_existing().filter(DbSession.id == db_session.id).first() or db_session
            if db_session.status in ("TERMINATED", "EXPIRED"):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Session has been terminated or expired. Please sign in again."
                )

            if verify_password(new_password, current_user.password_hash):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="New password must be different from your current password."
                )

            # Re-evaluate authoritative behavioral risk immediately before committing
            cls._enforce_risk_gate(db, current_user, db_session, norm_app)

            tx = cls._load_bound_transaction(db, transaction_id, current_user, db_session, norm_app)
            if not tx.current_password_verified:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Current password verification is required."
                )

            # Allow optional late HIGH_RISK_DUAL binding ONLY if bound explicitly to resource=='password_change'
            if not (tx.image_verified and tx.private_verified) and bound_high_risk_challenge_id:
                ok_bound, bound_msg = StepUpService.consume_bound_password_change_challenge(
                    challenge_id=bound_high_risk_challenge_id,
                    user_id=current_user.id,
                    session_id=db_session.id,
                    application=norm_app,
                )
                if not ok_bound:
                    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=bound_msg)
                tx.image_verified = True
                tx.image_verified_at = utc_now()
                tx.private_verified = True
                tx.private_verified_at = utc_now()
                tx.bound_stepup_challenge_id = bound_high_risk_challenge_id
                tx.status = "READY_TO_COMMIT"
                db.flush()

            if not (tx.image_verified and tx.private_verified and tx.status == "READY_TO_COMMIT"):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Both cognitive challenges (Image Sequence and Private Security Response) must be verified before updating password."
                )

            now = utc_now()
            # Atomic single-use compare-and-set to defeat concurrent duplicate password-change commits
            updated_rows = (
                db.query(PasswordChangeTransaction)
                .filter(
                    PasswordChangeTransaction.id == tx.id,
                    PasswordChangeTransaction.is_consumed == False,
                    PasswordChangeTransaction.status == "READY_TO_COMMIT",
                )
                .update({
                    "is_consumed": True,
                    "consumed_at": now,
                    "status": "COMPLETED",
                })
            )
            if updated_rows == 0:
                db.rollback()
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Password change transaction has already been completed or invalidated."
                )

            # Update password securely and invalidate any remaining pending transactions for this user
            current_user.password_hash = get_password_hash(new_password)
            current_user.account_status = "ACTIVE"
            current_user.failed_login_attempts = 0

            db.query(PasswordChangeTransaction).filter(
                PasswordChangeTransaction.user_id == current_user.id,
                PasswordChangeTransaction.id != tx.id,
                PasswordChangeTransaction.is_consumed == False,
            ).update({
                "is_consumed": True,
                "consumed_at": now,
                "status": "CANCELLED",
            })

            sec_event = SecurityEvent(
                user_id=current_user.id,
                session_id=db_session.id,
                application=norm_app,
                event_type="PASSWORD_CHANGED",
                severity="MEDIUM",
                decision="ALLOW",
                details=(
                    f"Account password updated via cognitive-verified transaction in '{norm_app}' portal. "
                    f"Client IP: {client_ip}."
                ),
            )
            db.add(sec_event)
            db.commit()
            db.refresh(current_user)

            # Invalidate all user sessions and application grants AFTER password commit succeeded
            sessions_revoked = SessionService.terminate_all_user_sessions(db, current_user.id)
            try:
                StepUpService.purge_session_challenges(db_session.id)
            except Exception:
                pass

        # Send registered email security notification (non-fatal if SMTP disabled in test)
        email_sent = False
        try:
            ok_email, _ = EmailService.send_password_changed_notification(
                recipient_email=current_user.email,
                user_name=current_user.name,
                application=norm_app,
                timestamp_str=now.strftime("%Y-%m-%d %H:%M:%S UTC"),
                ip_address=client_ip,
            )
            email_sent = bool(ok_email)
        except Exception as exc:
            logger.warning(f"[COGNISEC-AI] [PASSWORD_CHANGE_NOTIFY] Non-fatal notification dispatch error: {exc}")

        logger.info(
            f"[COGNISEC-AI] [PASSWORD_CHANGED] user_id={current_user.id} portal={norm_app} "
            f"sessions_revoked={sessions_revoked} email_sent={email_sent}"
        )

        return {
            "success": True,
            "message": "Your password has been updated. All active sessions have been invalidated—please sign in with your new password.",
            "application": norm_app,
            "sessions_revoked": sessions_revoked,
            "email_notification_sent": email_sent,
            "security_event_recorded": True,
            "requires_reauth": True,
        }
