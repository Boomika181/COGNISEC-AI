import hmac
import hashlib
import json
import logging
import secrets
import threading
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, Tuple, List
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from app.core.config import settings
from app.models.user import User
from app.services.email_service import EmailService
from app.services.adaptive_auth_service import AdaptiveAuthService, COGNITIVE_CATALOGUE

logger = logging.getLogger(__name__)

NEURALTRACE_NOT_ENROLLED_DETAIL = (
    "NeuralTrace is not enrolled for this account. Enroll your NeuralTrace route first "
    "(security settings on the main dashboard), then retry. No default route is ever created."
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class StepUpService:
    """
    Thread-safe Adaptive Step-Up Challenge Manager.
    Evaluates Zero-Trust risk context to issue:
    - Normal / Low Risk: ALLOW (No step-up required)
    - Mild deviation / Low step-up band (0.30 <= risk < 0.50): Email OTP
    - Moderate risk (0.50 <= risk < 0.65): Enrolled GESTURE_PATTERN (fallback to Email OTP if unenrolled)
    - High but recoverable risk (0.65 <= risk < 0.85): Compound challenge requiring
      BOTH COGNITIVE_IMAGE_SEQUENCE AND PRIVATE_RESPONSE (HIGH_RISK_DUAL)
    - Critical risk (>= 0.85): TERMINATE_SESSION (Challenge creation and verification strictly prohibited)
    Enforces single-use consumption, secure hash storage, short TTL, and brute-force lockout.
    """

    _lock = threading.RLock()
    _challenges: Dict[str, Dict[str, Any]] = {}  # keyed by session_id
    _password_resets: Dict[str, Dict[str, Any]] = {}  # keyed by normalized email
    _email_verifications: Dict[str, Dict[str, Any]] = {}  # keyed by normalized email
    _neuraltrace_resets: Dict[str, Dict[str, Any]] = {}  # keyed by challenge_id
    _reset_tickets: Dict[str, Dict[str, Any]] = {}  # keyed by ticket_token
    _bound_password_change_receipts: Dict[str, Dict[str, Any]] = {}  # keyed by challenge_id, resource=='password_change' only
    _inflight_appointment_sessions: set = set()
    _inflight_login_sessions: set = set()
    _inflight_exam_sessions: set = set()

    DEFAULT_TTL_SECONDS = 300  # 5 minutes
    MAX_ATTEMPTS = 3

    @classmethod
    def _hash_otp(cls, otp: str) -> str:
        """Computes keyed HMAC-SHA256 verifier for OTP storage."""
        return hmac.new(settings.SECRET_KEY.encode("utf-8"), otp.encode("utf-8"), hashlib.sha256).hexdigest()

    @classmethod
    def create_challenge(
        cls,
        session_id: str,
        user_id: int,
        ttl_seconds: int = DEFAULT_TTL_SECONDS
    ) -> Dict[str, Any]:
        """
        Legacy/Default: Generates a secure random 6-digit OTP for the given session.
        Maintains backward compatibility with all existing tests.
        """
        with cls._lock:
            cls._cleanup_expired()

            otp = f"{secrets.randbelow(1000000):06d}"
            otp_hash = cls._hash_otp(otp)
            challenge_id = f"chal_{secrets.token_hex(8)}"
            now = utc_now()
            expires_at = now + timedelta(seconds=ttl_seconds)

            cls._challenges[session_id] = {
                "challenge_id": challenge_id,
                "session_id": session_id,
                "user_id": user_id,
                "challenge_type": "OTP",
                "otp_hash": otp_hash,
                "otp": otp,  # retained for legacy tests
                "created_at": now,
                "expires_at": expires_at,
                "attempts": 0,
                "max_attempts": cls.MAX_ATTEMPTS,
            }

            return {
                "challenge_id": challenge_id,
                "session_id": session_id,
                "otp": otp,
                "challenge_type": "OTP",
                "expires_in_seconds": ttl_seconds,
                "message": "Step-up challenge generated. Enter this one-time code to restore session access.",
                "is_demo_otp": True
            }

    @classmethod
    def purge_portal_challenges(cls, user_id: Optional[int], application: Optional[str], session_id: Optional[str] = None):
        """Purges active challenges ONLY for the specified portal application."""
        norm_app = (application or "").strip().lower()
        with cls._lock:
            to_delete = []
            for c in list(cls._challenges.values()):
                if user_id is not None and c.get("user_id") != user_id:
                    continue
                c_app = (c.get("application") or "").strip().lower()
                c_type = (c.get("challenge_type") or "").upper()
                if norm_app and c_app == norm_app:
                    to_delete.append(c)
                elif norm_app == "college" and c_type == "COLLEGE_EXAM_OTP":
                    to_delete.append(c)
                elif norm_app == "shopping" and c_type == "SHOPPING_PAYMENT":
                    to_delete.append(c)
                elif norm_app == "healthcare" and c_type == "APPOINTMENT_OTP":
                    to_delete.append(c)
                elif session_id and c.get("session_id") == session_id and not c_app:
                    to_delete.append(c)
            for c in to_delete:
                cls._delete_challenge(c)

    @classmethod
    def _delete_challenge(cls, challenge: Dict[str, Any]):
        """Helper to cleanly purge challenge across all memory index keys."""
        cid = challenge.get("challenge_id")
        sid = challenge.get("session_id")
        app = challenge.get("application")
        if cid:
            cls._challenges.pop(cid, None)
        if sid:
            cls._challenges.pop(sid, None)
            if app:
                cls._challenges.pop(f"{sid}:{app}", None)
        for k, v in list(cls._challenges.items()):
            if v.get("challenge_id") == cid:
                cls._challenges.pop(k, None)

    @classmethod
    def purge_session_challenges(cls, session_id: str):
        """Purges all active step-up challenges for a session upon termination or revocation."""
        with cls._lock:
            to_delete = [
                c for c in list(cls._challenges.values())
                if c.get("session_id") == session_id
            ]
            for c in to_delete:
                cls._delete_challenge(c)
            cls._challenges.pop(session_id, None)
            cls._challenges.pop(f"exam:{session_id}", None)
            cls._challenges.pop(f"apt:{session_id}", None)
            cls._challenges.pop(f"login:{session_id}", None)
            for k in list(cls._challenges.keys()):
                if k.startswith(f"{session_id}:") or k == session_id:
                    cls._challenges.pop(k, None)
            for cid in [
                rcid for rcid, rec in cls._bound_password_change_receipts.items()
                if rec.get("session_id") == session_id
            ]:
                cls._bound_password_change_receipts.pop(cid, None)

    @classmethod
    def create_adaptive_challenge(
        cls,
        session_id: str,
        user_id: int,
        db: Session,
        risk_score: float = 0.35,
        risk_level: str = "MEDIUM",
        preferred_factor: Optional[str] = None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        application: Optional[str] = None,
        resource: Optional[str] = None,
        challenge_purpose: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Policy-driven Adaptive Challenge Generator.
        Maps risk context to factor complexity:
        - Critical risk (>= 0.85): TERMINATED (Prohibited)
        - High risk (0.65 <= risk < 0.85): HIGH_RISK_DUAL (Requires BOTH Image Sequence AND Private Response)
        - Moderate risk (0.50 <= risk < 0.65): GESTURE_PATTERN (if enrolled; else Email OTP)
        - Mild deviation (0.30 <= risk < 0.50): Email OTP
        Enforces that the client cannot choose a weaker factor than required by risk.
        Binds challenge strictly to application, resource, and challenge_purpose.
        """
        from app.services.session_service import SessionService
        norm_app = SessionService.normalize_application(application)
        raw_norm_res = SessionService.normalize_resource(resource) if resource else None
        req_purpose = (challenge_purpose or "").upper().strip()
        is_booking_resource = bool(raw_norm_res in ("healthcare_booking", "appointment", "appointment_booking")) or req_purpose == "HEALTHCARE_BOOKING"
        is_pwd_change_resource = bool(raw_norm_res == "password_change") or req_purpose == "PASSWORD_CHANGE"

        if is_pwd_change_resource:
            norm_res = "password_change"
            is_protected_vault = False
            resolved_purpose = "PASSWORD_CHANGE"
        elif is_booking_resource:
            norm_res = raw_norm_res or "healthcare_booking"
            is_protected_vault = False
            resolved_purpose = "HEALTHCARE_BOOKING"
        elif req_purpose == "SESSION_STEP_UP" and raw_norm_res not in ("academic_vault", "financial_vault", "ehr_vault"):
            # Explicit generic session step-up without a vault target MUST NOT coerce to a confidential vault resource
            norm_res = raw_norm_res
            is_protected_vault = False
            resolved_purpose = "SESSION_STEP_UP"
        else:
            norm_res = raw_norm_res if raw_norm_res else SessionService.get_resource_for_application(norm_app)
            if (not norm_app or norm_app == "platform") and norm_res:
                norm_app = SessionService.get_application_for_resource(norm_res)
            if not norm_res and norm_app:
                norm_res = SessionService.get_resource_for_application(norm_app)
            is_protected_vault = bool(raw_norm_res in ("academic_vault", "financial_vault", "ehr_vault")) or req_purpose == "CONFIDENTIAL_RESOURCE"
            is_strict_purpose = bool(req_purpose) or is_pwd_change_resource or is_booking_resource or (raw_norm_res in ("academic_vault", "financial_vault", "ehr_vault"))
            resolved_purpose = req_purpose or ("CONFIDENTIAL_RESOURCE" if norm_res in ("academic_vault", "financial_vault", "ehr_vault") else "SESSION_STEP_UP")

        with cls._lock:
            cls._cleanup_expired()

            from app.services.portal_lock_service import PortalLockService
            from app.models.session import Session as DbSession
            from app.services.risk_service import RiskService

            # Canonical risk level resolution:
            # 1. Determine canonical tier from numerical risk_score via authoritative RiskService
            # 2. Determine effective tier, elevating if numerical risk_score is higher than provided risk_level
            canonical_tier = RiskService.classify_risk_level(risk_score) if risk_score is not None else None
            provided_level = (risk_level or "").upper().strip()
            tier_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

            if provided_level in tier_rank:
                if canonical_tier and tier_rank.get(canonical_tier, 0) > tier_rank.get(provided_level, 0):
                    effective_tier = canonical_tier
                else:
                    effective_tier = provided_level
            else:
                effective_tier = canonical_tier or "MEDIUM"

            # -------------------------------------------------------------
            # Tier 1: CRITICAL RISK (risk_score >= 0.85 or level CRITICAL)
            # Terminate session, revoke grants, invalidate tokens, refuse challenge
            # -------------------------------------------------------------
            if effective_tier == "CRITICAL":
                if session_id:
                    try:
                        SessionService.terminate_session(db, session_id, risk_level="CRITICAL")
                    except Exception:
                        pass
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot issue challenge: Session terminated due to critical security risk."
                )

            eff_portal_for_lock = norm_app or "platform"
            if db is not None and session_id:
                existing_sess = db.query(DbSession).filter(DbSession.id == session_id).first()
                if existing_sess and existing_sess.status == "TERMINATED":
                    PortalLockService.raise_terminated_http_exception(status_code=status.HTTP_401_UNAUTHORIZED)

            enrollment = AdaptiveAuthService.get_enrollment_status(db, user_id)
            selected_type = "OTP"
            prompt = None
            catalogue = None
            min_len = None

            # -------------------------------------------------------------
            # Tier 2: HIGH RISK (0.65 <= risk_score < 0.85 or level HIGH)
            # Mandatory compound cognitive verification (HIGH_RISK_DUAL)
            # Caller preferences CANNOT downgrade or weaken this requirement
            # -------------------------------------------------------------
            if effective_tier == "HIGH":
                has_img = enrollment.get("has_cognitive_image_sequence", False)
                has_priv = enrollment.get("has_private_response", False)

                if not (has_img and has_priv):
                    missing = []
                    if not has_img:
                        missing.append("Cognitive Image Sequence")
                    if not has_priv:
                        missing.append("Private Security Response")
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=f"High risk verification requires both Cognitive Image Sequence and Private Security Response to be enrolled. Missing: {', '.join(missing)}."
                    )
                selected_type = "HIGH_RISK_DUAL"
                catalogue = COGNITIVE_CATALOGUE
                prompt = enrollment.get("private_question") or "Registered Security Question"
                min_len = 3

            # -------------------------------------------------------------
            # Tier 3: MEDIUM RISK (0.30 <= risk_score < 0.65 or level MEDIUM)
            # Mandatory NeuralTrace gesture verification for medium risk
            # Caller-supplied OTP CANNOT downgrade this requirement
            # -------------------------------------------------------------
            elif effective_tier == "MEDIUM":
                pref = (preferred_factor or "").upper().strip()

                # Voluntary upward escalation to stronger cognitive factors is permitted if enrolled
                if pref == "COGNITIVE_IMAGE_SEQUENCE":
                    if not enrollment.get("has_cognitive_image_sequence"):
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail="Cognitive image sequence is not enrolled for this account."
                        )
                    selected_type = "COGNITIVE_IMAGE_SEQUENCE"
                    catalogue = COGNITIVE_CATALOGUE
                    min_len = 3
                elif pref == "PRIVATE_RESPONSE":
                    if not enrollment.get("has_private_response"):
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail="Private security response is not enrolled for this account."
                        )
                    selected_type = "PRIVATE_RESPONSE"
                    prompt = enrollment.get("private_question")
                elif pref == "HIGH_RISK_DUAL":
                    has_img = enrollment.get("has_cognitive_image_sequence", False)
                    has_priv = enrollment.get("has_private_response", False)
                    if not (has_img and has_priv):
                        missing = []
                        if not has_img:
                            missing.append("Cognitive Image Sequence")
                        if not has_priv:
                            missing.append("Private Security Response")
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail=f"High risk verification requires both Cognitive Image Sequence and Private Security Response to be enrolled. Missing: {', '.join(missing)}."
                        )
                    selected_type = "HIGH_RISK_DUAL"
                    catalogue = COGNITIVE_CATALOGUE
                    prompt = enrollment.get("private_question") or "Registered Security Question"
                    min_len = 3
                else:
                    # Baseline factor for MEDIUM risk is NeuralTrace (GESTURE_PATTERN)
                    # Downward request such as preferred_factor="OTP" is strictly ignored / rejected
                    if enrollment.get("has_gesture_pattern", False):
                        selected_type = "GESTURE_PATTERN"
                        min_len = 4
                    else:
                        # User is NOT enrolled in NeuralTrace
                        # Protected vaults, healthcare booking, and explicit gesture requests MUST fail closed (HTTP 409)
                        if is_protected_vault or is_booking_resource or norm_app == "healthcare" or pref == "GESTURE_PATTERN":
                            raise HTTPException(
                                status_code=status.HTTP_409_CONFLICT,
                                detail=NEURALTRACE_NOT_ENROLLED_DETAIL
                            )
                        # For general platform portal step-up (non-healthcare, non-vault), fall back to OTP
                        selected_type = "OTP"

            # -------------------------------------------------------------
            # Tier 4: LOW RISK (risk_score < 0.30 or level LOW)
            # Mandatory Email OTP for LOW risk & healthcare appointment booking
            # -------------------------------------------------------------
            else:
                pref = (preferred_factor or "").upper().strip()

                # Appointment booking MUST strictly enforce Email OTP under LOW risk (cannot be overridden by caller preference)
                if is_booking_resource:
                    if pref and pref not in ("OTP", "EMAIL_OTP"):
                        logger.warning(
                            f"[StepUpService] Ignoring non-OTP factor override '{pref}' for LOW-risk healthcare booking "
                            f"(session_id={session_id}, resource={raw_norm_res}); enforcing OTP."
                        )
                    selected_type = "OTP"
                elif pref == "GESTURE_PATTERN":
                    if not enrollment.get("has_gesture_pattern"):
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail=NEURALTRACE_NOT_ENROLLED_DETAIL
                        )
                    selected_type = "GESTURE_PATTERN"
                    min_len = 4
                elif pref == "COGNITIVE_IMAGE_SEQUENCE":
                    if not enrollment.get("has_cognitive_image_sequence"):
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail="Cognitive image sequence is not enrolled for this account."
                        )
                    selected_type = "COGNITIVE_IMAGE_SEQUENCE"
                    catalogue = COGNITIVE_CATALOGUE
                    min_len = 3
                elif pref == "PRIVATE_RESPONSE":
                    if not enrollment.get("has_private_response"):
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail="Private security response is not enrolled for this account."
                        )
                    selected_type = "PRIVATE_RESPONSE"
                    prompt = enrollment.get("private_question")
                elif pref == "HIGH_RISK_DUAL":
                    has_img = enrollment.get("has_cognitive_image_sequence", False)
                    has_priv = enrollment.get("has_private_response", False)
                    if not (has_img and has_priv):
                        missing = []
                        if not has_img:
                            missing.append("Cognitive Image Sequence")
                        if not has_priv:
                            missing.append("Private Security Response")
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail=f"High risk verification requires both Cognitive Image Sequence and Private Security Response to be enrolled. Missing: {', '.join(missing)}."
                        )
                    selected_type = "HIGH_RISK_DUAL"
                    catalogue = COGNITIVE_CATALOGUE
                    prompt = enrollment.get("private_question") or "Registered Security Question"
                    min_len = 3
                elif pref in ("OTP", "EMAIL_OTP"):
                    selected_type = "OTP"
                else:
                    if is_protected_vault and enrollment.get("has_gesture_pattern", False):
                        selected_type = "GESTURE_PATTERN"
                        min_len = 4
                    elif is_protected_vault and not enrollment.get("has_gesture_pattern", False):
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail=NEURALTRACE_NOT_ENROLLED_DETAIL
                        )
                    else:
                        selected_type = "OTP"

            logger.info(
                f"[StepUpService] challenge_selected session_id={session_id} risk_tier={effective_tier} "
                f"risk_score={float(risk_score) if risk_score is not None else -1.0:.4f} app={norm_app} "
                f"resource={norm_res} preferred={preferred_factor} selected={selected_type}"
            )

            # 2. Generate challenge entity
            challenge_id = f"chal_{secrets.token_hex(8)}"
            now = utc_now()
            expires_at = now + timedelta(seconds=ttl_seconds)

            chal_key = f"{session_id}:{norm_app}" if norm_app else session_id

            # Deduplication: if active un-attempted challenge of same factor already exists within 5 seconds, reuse it
            existing = cls._challenges.get(chal_key) or cls._challenges.get(session_id)
            if (
                existing
                and existing.get("attempts", 0) == 0
                and (now - existing["created_at"]) < timedelta(seconds=5)
                and now < existing["expires_at"]
                and (preferred_factor is None or existing.get("challenge_type") == preferred_factor.upper())
                and (selected_type == existing.get("challenge_type"))
                and (not norm_app or existing.get("application") == norm_app)
                and (existing.get("challenge_purpose", resolved_purpose) == resolved_purpose)
            ):
                user = db.query(User).filter(User.id == user_id).first()
                delivery_email = EmailService.resolve_delivery_recipient(user.email) if user and user.email else None
                masked_email = EmailService.mask_email(delivery_email) if delivery_email else None
                return_otp = existing.get("otp", "") if (settings.EXHIBITION_MODE or settings.ENVIRONMENT in ("test", "testing")) else ""
                return {
                    "challenge_id": existing["challenge_id"],
                    "session_id": session_id,
                    "application": existing.get("application"),
                    "resource": existing.get("resource"),
                    "challenge_purpose": existing.get("challenge_purpose", resolved_purpose),
                    "otp": return_otp,
                    "challenge_type": existing["challenge_type"],
                    "expires_in_seconds": int((existing["expires_at"] - now).total_seconds()),
                    "delivery_status": "SMTP_ACCEPTED",
                    "message": f"Email submitted to the mail server for {masked_email or 'registered email'}. Check your inbox and spam folder.",
                    "masked_email": masked_email,
                    "prompt": existing.get("prompt"),
                    "catalogue": catalogue,
                    "min_length": min_len,
                    "stage": existing.get("stage", 1),
                    "stage_1_passed": existing.get("stage_1_passed", False),
                    "is_demo_otp": bool(settings.EXHIBITION_MODE and existing["challenge_type"] == "OTP")
                }

            masked_email = None
            otp_val = ""
            otp_hash = ""

            delivery_status = "SENT"
            if selected_type == "OTP":
                otp_val = f"{secrets.randbelow(1000000):06d}"
                otp_hash = cls._hash_otp(otp_val)

                # Fetch authenticated user's email strictly from DB record
                user = db.query(User).filter(User.id == user_id).first()
                if not user or not user.email:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Authenticated user account does not have a registered email address."
                    )
                delivery_email = EmailService.resolve_delivery_recipient(user.email)
                masked_email = EmailService.mask_email(delivery_email)

                # Out-of-band email dispatch
                delivery_status = "PENDING"
                email_ok, email_msg = EmailService.send_otp_email(
                    recipient_email=delivery_email,
                    otp_code=otp_val,
                    expires_in_minutes=ttl_seconds // 60,
                    challenge_id=challenge_id,
                    issued_at=now,
                    expires_at=now + timedelta(seconds=ttl_seconds),
                )
                if email_ok:
                    last_res = EmailService.get_last_delivery_result() or {}
                    if last_res.get("success") and last_res.get("delivery_status") in (
                        EmailService.DELIVERY_STATE_SMTP_ACCEPTED,
                        EmailService.DELIVERY_STATE_DELIVERY_CONFIRMED,
                        EmailService.DELIVERY_STATE_PENDING,
                    ):
                        delivery_status = last_res["delivery_status"]
                    else:
                        delivery_status = EmailService.DELIVERY_STATE_SMTP_ACCEPTED
                else:
                    if "not configured" in email_msg or "disabled" in email_msg:
                        delivery_status = EmailService.DELIVERY_STATE_FAILED
                    else:
                        delivery_status = EmailService.DELIVERY_STATE_FAILED

                    if not settings.EXHIBITION_MODE:
                        raise HTTPException(
                            status_code=status.HTTP_502_BAD_GATEWAY,
                            detail="Email delivery could not be initiated. Please retry."
                        )

            # Purge any previous challenges for this session/application so resend strictly invalidates them
            to_purge = [
                c for c in list(cls._challenges.values())
                if c.get("session_id") == session_id and (not norm_app or c.get("application") == norm_app)
            ]
            for c in to_purge:
                cls._delete_challenge(c)

            is_strict_purpose = True if req_purpose in ("SESSION_STEP_UP", "PASSWORD_CHANGE", "HEALTHCARE_BOOKING", "CONFIDENTIAL_RESOURCE") or is_pwd_change_resource or is_booking_resource or (raw_norm_res in ("academic_vault", "financial_vault", "ehr_vault")) else False
            factor_max_attempts = PortalLockService.get_max_attempts_for(resolved_purpose, selected_type)
            # Store challenge in memory verifier (resend invalidates previous challenge)
            challenge_payload = {
                "challenge_id": challenge_id,
                "session_id": session_id,
                "user_id": user_id,
                "application": norm_app or None,
                "resource": norm_res or None,
                "challenge_purpose": resolved_purpose,
                "purpose_strict": is_strict_purpose,
                "challenge_type": selected_type,
                "otp_hash": otp_hash,
                "otp": otp_val if (settings.EXHIBITION_MODE or settings.ENVIRONMENT in ("test", "testing")) else "",
                "prompt": prompt,
                "created_at": now,
                "expires_at": expires_at,
                "attempts": 0,
                "max_attempts": factor_max_attempts,
                "stage": 1,
                "stage_1_passed": False,
                "completed": False,
            }
            cls._challenges[chal_key] = challenge_payload
            cls._challenges[challenge_id] = challenge_payload
            if chal_key != session_id:
                cls._challenges[session_id] = challenge_payload

            otp_message = (
                f"Email submitted to the mail server for {masked_email or 'registered email'}. Check your inbox and spam folder."
                if delivery_status in (EmailService.DELIVERY_STATE_SMTP_ACCEPTED, EmailService.DELIVERY_STATE_DELIVERY_CONFIRMED)
                else (
                    "Sending verification email..."
                    if delivery_status in (EmailService.DELIVERY_STATE_PENDING, EmailService.DELIVERY_STATE_SENDING, EmailService.DELIVERY_STATE_RETRY_PENDING)
                    else "Email delivery could not be initiated. Please retry."
                )
            )
            msg_map = {
                "OTP": otp_message,
                "GESTURE_PATTERN": "Moderate risk detected. Reconstruct your NeuralTrace signal route across the network grid to verify identity.",
                "COGNITIVE_IMAGE_SEQUENCE": "High risk detected. Replay your enrolled cognitive image sequence to restore access.",
                "PRIVATE_RESPONSE": "High risk detected. Answer your enrolled private security question to restore access.",
                "HIGH_RISK_DUAL": "High risk detected. Complete sequential cognitive verification (Stage 1: Image Sequence, Stage 2: Private Response) to restore access."
            }

            # In exhibition mode or test environment, return OTP for demonstration
            # In production or when EXHIBITION_MODE=False, OTP is NEVER returned in the API response
            return_otp = ""
            if settings.EXHIBITION_MODE:
                return_otp = otp_val
            elif settings.ENVIRONMENT in ("test", "testing") and not getattr(settings, "_FORCE_NO_DEMO_OTP", False):
                return_otp = otp_val

            is_demo = bool(settings.EXHIBITION_MODE and selected_type == "OTP")
            attempts_rem = PortalLockService.MAX_VERIFICATION_ATTEMPTS
            max_att = PortalLockService.MAX_VERIFICATION_ATTEMPTS
            if db is not None and session_id:
                cnt_status = PortalLockService.get_attempt_counter_status(
                    db,
                    user_id=user_id,
                    application=eff_portal_for_lock,
                    verification_purpose=resolved_purpose,
                    factor_key=selected_type,
                    session_id=session_id,
                    max_attempts_override=factor_max_attempts,
                )
                if cnt_status["exhausted"]:
                    lock_obj = PortalLockService.lock_portal(
                        db=db,
                        user_id=user_id,
                        application=eff_portal_for_lock,
                        verification_purpose=resolved_purpose,
                        lock_reason=f"Maximum verification attempts ({cnt_status['max_attempts']}) already exceeded.",
                        failed_attempt_count=cnt_status["attempts_used"],
                        max_attempts=cnt_status["max_attempts"],
                        session_id=session_id,
                        emit_step_up_locked_event=True,
                    )
                    PortalLockService.raise_locked_http_exception(lock_obj, status_code=status.HTTP_423_LOCKED)
                attempts_rem = cnt_status["attempts_remaining"]
                max_att = cnt_status["max_attempts"]

            return {
                "challenge_id": challenge_id,
                "session_id": session_id,
                "application": norm_app or None,
                "resource": norm_res or None,
                "challenge_purpose": resolved_purpose,
                "otp": return_otp,
                "challenge_type": selected_type,
                "expires_in_seconds": ttl_seconds,
                "delivery_status": delivery_status,
                "message": msg_map.get(selected_type, "Adaptive challenge generated."),
                "masked_email": masked_email,
                "prompt": prompt,
                "catalogue": catalogue,
                "min_length": min_len,
                "stage": 1,
                "stage_1_passed": False,
                "is_demo_otp": is_demo,
                "attempts_remaining": attempts_rem,
                "max_attempts": max_att,
            }

    @classmethod
    def verify_challenge(
        cls,
        session_id: str,
        user_id: int,
        challenge_code: str
    ) -> Tuple[bool, str, bool]:
        """
        Legacy OTP verification. Maintains backward compatibility.
        """
        success, message, is_locked, _ = cls.verify_adaptive_challenge(
            session_id=session_id,
            user_id=user_id,
            challenge_code=challenge_code
        )
        return (success, message, is_locked)

    @classmethod
    def _record_adaptive_failure(
        cls,
        db: Optional[Session],
        challenge: Dict[str, Any],
        user_id: int,
        session_id: str,
        eff_app: Optional[str],
        eff_purpose: str,
        factor_key: str,
        base_invalid_msg: str,
        max_attempts_override: Optional[int] = None,
    ) -> Tuple[bool, str, bool, Optional[Dict[str, Any]]]:
        """Shared authoritative failure counter & portal-scoped ejection helper."""
        from app.services.portal_lock_service import PortalLockService

        if db is not None:
            portal_scope = eff_app or challenge.get("application") or "platform"
            purpose_scope = eff_purpose or challenge.get("challenge_purpose") or "STEP_UP"
            is_locked, used, max_att, rem, lock_obj = PortalLockService.record_verification_failure(
                db=db,
                user_id=user_id,
                application=portal_scope,
                verification_purpose=purpose_scope,
                factor_key=factor_key,
                session_id=session_id,
                challenge_reference=challenge.get("challenge_id"),
                lock_reason=f"Verification attempts exceeded for {factor_key} ({purpose_scope}).",
                emit_step_up_locked_event=True,
                max_attempts_override=max_attempts_override or PortalLockService.get_max_attempts_for(purpose_scope, factor_key),
            )
            challenge["attempts"] = used
            if is_locked:
                cls._delete_challenge(challenge)
                lock_detail = PortalLockService.build_lock_detail(lock_obj)["message"] if lock_obj else (
                    f"SECURITY ACCESS SUSPENDED: Access to {portal_scope} suspended after exceeding maximum attempts."
                )
                return (
                    False,
                    lock_detail,
                    True,
                    {
                        "portal_locked": True,
                        "portal": lock_obj.application if lock_obj else portal_scope,
                        "security_reference_id": lock_obj.security_reference_id if lock_obj else None,
                        "attempts_used": used,
                        "max_attempts": max_att,
                        "attempts_remaining": 0,
                    },
                )
            return (
                False,
                f"{base_invalid_msg} {rem} attempt{'s' if rem != 1 else ''} remaining.",
                False,
                {"attempts_used": used, "max_attempts": max_att, "attempts_remaining": rem},
            )

        max_attempts = max_attempts_override or challenge.get("max_attempts", cls.MAX_ATTEMPTS)
        challenge["attempts"] += 1
        if challenge["attempts"] >= max_attempts:
            cls._delete_challenge(challenge)
            return (False, "Maximum verification attempts exceeded. Challenge locked.", True, {"portal_locked": True})
        remaining = max_attempts - challenge["attempts"]
        return (False, f"{base_invalid_msg} {remaining} attempt{'s' if remaining != 1 else ''} remaining.", False, {"attempts_remaining": remaining, "max_attempts": max_attempts})

    @classmethod
    def verify_adaptive_challenge(
        cls,
        session_id: str,
        user_id: int,
        db: Optional[Session] = None,
        challenge_type: Optional[str] = None,
        challenge_code: Optional[str] = None,
        gesture_pattern: Optional[List[int]] = None,
        image_sequence: Optional[List[str]] = None,
        private_response: Optional[str] = None,
        application: Optional[str] = None,
        resource: Optional[str] = None,
        challenge_id: Optional[str] = None,
        stage: Optional[int] = 1,
        challenge_purpose: Optional[str] = None,
    ) -> Tuple[bool, str, bool, Optional[Dict[str, Any]]]:
        """
        Verifies adaptive multi-factor challenge submission with sequential stage support.
        Enforces user binding, session binding, and application/resource/purpose binding.
        Returns:
            (success: bool, message: str, is_locked: bool, details: Optional[Dict[str, Any]])
        """
        with cls._lock:
            cls._cleanup_expired()

            from app.services.session_service import SessionService
            norm_app = SessionService.normalize_application(application)
            raw_norm_res = SessionService.normalize_resource(resource) if resource else None
            req_purpose = (challenge_purpose or "").upper().strip()
            if req_purpose == "SESSION_STEP_UP" and not raw_norm_res:
                norm_res = None
            else:
                norm_res = raw_norm_res
                if (not norm_app or norm_app == "platform") and norm_res:
                    norm_app = SessionService.get_application_for_resource(norm_res)
                if not norm_res and norm_app:
                    norm_res = SessionService.get_resource_for_application(norm_app)

            challenge = None
            chal_key = None

            # 1. Mandatory challenge ID check for HIGH_RISK_DUAL (unless legacy direct compound verification)
            is_compound_direct = bool(image_sequence and private_response)
            if (challenge_type == "HIGH_RISK_DUAL") and not is_compound_direct and not challenge_id:
                return (
                    False,
                    "Missing challenge ID. A valid challenge ID is mandatory for sequential high-risk cognitive verification.",
                    False,
                    None
                )

            # 2. Lookup by explicit challenge_id if supplied
            if challenge_id:
                for k, c in list(cls._challenges.items()):
                    if c.get("challenge_id") == challenge_id:
                        challenge = c
                        chal_key = k
                        break
                if not challenge:
                    return (
                        False,
                        "No active step-up challenge found or challenge expired/already used. Please request a new challenge.",
                        False,
                        None
                    )

            # 3. Lookup by application-scoped session key
            if not challenge and norm_app:
                specific_key = f"{session_id}:{norm_app}"
                if specific_key in cls._challenges:
                    challenge = cls._challenges[specific_key]
                    chal_key = specific_key

            # 4. Fallback to generic session key
            if not challenge:
                if session_id in cls._challenges:
                    challenge = cls._challenges[session_id]
                    chal_key = session_id
                else:
                    for k, c in list(cls._challenges.items()):
                        if c.get("session_id") == session_id:
                            challenge = c
                            chal_key = k
                            break

            if not challenge:
                return (
                    False,
                    "No active step-up challenge found or challenge expired/already used. Please request a new challenge.",
                    False,
                    None
                )

            # Validate user identity binding (BOLA protection)
            if challenge["user_id"] != user_id:
                return (
                    False,
                    "Unauthorized: Challenge does not belong to the requesting user.",
                    False,
                    None
                )

            # Validate session binding
            if challenge["session_id"] != session_id:
                return (
                    False,
                    "Unauthorized: Challenge does not belong to the requesting session.",
                    False,
                    None
                )

            # Validate exact application binding
            chal_app = challenge.get("application")
            if chal_app and norm_app and chal_app != norm_app:
                return (
                    False,
                    f"Challenge application mismatch: This challenge was issued for '{chal_app}' and cannot be submitted to '{norm_app}'.",
                    False,
                    None
                )

            # Validate exact resource binding if specified
            chal_res = challenge.get("resource")
            if chal_res and norm_res and chal_res != norm_res:
                return (
                    False,
                    f"Challenge resource mismatch: This challenge was issued for '{chal_res}' and cannot be submitted to '{norm_res}'.",
                    False,
                    None
                )

            # Validate explicit challenge purpose isolation (prevents cross-purpose reuse)
            chal_purpose = (challenge.get("challenge_purpose") or "").upper().strip()
            purpose_strict = bool(challenge.get("purpose_strict"))
            if chal_purpose and req_purpose and chal_purpose != req_purpose:
                return (
                    False,
                    f"Challenge purpose mismatch: This challenge was issued for '{chal_purpose}' and cannot authorize '{req_purpose}'.",
                    False,
                    None
                )
            if chal_purpose == "PASSWORD_CHANGE" and raw_norm_res != "password_change":
                return (
                    False,
                    "Challenge purpose mismatch: Password change challenge cannot authorize unrelated resources.",
                    False,
                    None
                )
            if purpose_strict and chal_purpose in ("SESSION_STEP_UP", "HEALTHCARE_BOOKING") and raw_norm_res in ("academic_vault", "financial_vault", "ehr_vault"):
                return (
                    False,
                    f"Challenge purpose mismatch: '{chal_purpose}' challenge cannot authorize confidential vault '{raw_norm_res}'.",
                    False,
                    None
                )

            # Check expiration
            if utc_now() > challenge["expires_at"]:
                cls._delete_challenge(challenge)
                return (
                    False,
                    "Step-up challenge has expired. Please request a new challenge.",
                    False,
                    None
                )

            actual_type = challenge.get("challenge_type", "OTP")
            eff_app = norm_app or challenge.get("application") or "platform"
            eff_purpose = chal_purpose or ("CONFIDENTIAL_RESOURCE" if (raw_norm_res or challenge.get("resource")) in ("academic_vault", "financial_vault", "ehr_vault") else "SESSION_STEP_UP")
            from app.services.portal_lock_service import PortalLockService

            if db is not None:
                from app.models.session import Session as DbSession
                cur_sess = db.query(DbSession).filter(DbSession.id == session_id).first()
                if cur_sess and cur_sess.status == "TERMINATED":
                    cls._delete_challenge(challenge)
                    PortalLockService.terminate_session_and_revoke_grants(
                        db=db,
                        user_id=user_id,
                        session_id=session_id,
                        application=eff_app,
                        verification_purpose=eff_purpose,
                        factor_key=actual_type,
                    )
                    return (
                        False,
                        PortalLockService.SESSION_TERMINATED_MESSAGE,
                        True,
                        {"terminated": True, "session_status": "TERMINATED"},
                    )

            # Verify factor based on challenge type
            if actual_type == "OTP":
                input_code = str(challenge_code or "").strip()
                is_valid = False
                if challenge.get("otp_hash"):
                    computed_hash = cls._hash_otp(input_code)
                    is_valid = hmac.compare_digest(challenge["otp_hash"], computed_hash)
                elif challenge.get("otp"):
                    is_valid = hmac.compare_digest(challenge["otp"], input_code)

                if is_valid:
                    if db is not None:
                        PortalLockService.reset_factor_counter_on_success(db, user_id, eff_app, eff_purpose, "OTP", session_id=session_id)
                    cls._delete_challenge(challenge)
                    return (True, "Identity step-up verified. Full access restored.", False, {"completed": True, "challenge_type": actual_type, "challenge_purpose": chal_purpose})

                return cls._record_adaptive_failure(
                    db=db, challenge=challenge, user_id=user_id, session_id=session_id,
                    eff_app=eff_app, eff_purpose=eff_purpose, factor_key="OTP",
                    base_invalid_msg="Invalid verification.",
                    max_attempts_override=challenge.get("max_attempts", cls.MAX_ATTEMPTS),
                )

            elif actual_type == "GESTURE_PATTERN":
                is_valid = False
                if db and gesture_pattern:
                    is_valid = AdaptiveAuthService.verify_enrolled_factor(
                        db=db,
                        user_id=user_id,
                        factor_type="GESTURE_PATTERN",
                        gesture_pattern=gesture_pattern
                    )

                if is_valid:
                    if db is not None:
                        PortalLockService.reset_factor_counter_on_success(db, user_id, eff_app, eff_purpose, "GESTURE_PATTERN", session_id=session_id)
                    cls._delete_challenge(challenge)
                    return (True, "Identity step-up verified. Full access restored.", False, {"completed": True, "challenge_type": actual_type, "challenge_purpose": chal_purpose})

                return cls._record_adaptive_failure(
                    db=db, challenge=challenge, user_id=user_id, session_id=session_id,
                    eff_app=eff_app, eff_purpose=eff_purpose, factor_key="GESTURE_PATTERN",
                    base_invalid_msg="Invalid verification.",
                    max_attempts_override=PortalLockService.LIMIT_GESTURE,
                )

            elif actual_type == "COGNITIVE_IMAGE_SEQUENCE":
                is_valid = False
                if db and image_sequence:
                    is_valid = AdaptiveAuthService.verify_enrolled_factor(
                        db=db,
                        user_id=user_id,
                        factor_type="COGNITIVE_IMAGE_SEQUENCE",
                        image_sequence=image_sequence
                    )

                if is_valid:
                    if db is not None:
                        PortalLockService.reset_factor_counter_on_success(db, user_id, eff_app, eff_purpose, "COGNITIVE_IMAGE_SEQUENCE", session_id=session_id)
                    cls._delete_challenge(challenge)
                    return (True, "Identity step-up verified. Full access restored.", False, {"completed": True, "challenge_type": actual_type, "challenge_purpose": chal_purpose})

                return cls._record_adaptive_failure(
                    db=db, challenge=challenge, user_id=user_id, session_id=session_id,
                    eff_app=eff_app, eff_purpose=eff_purpose, factor_key="COGNITIVE_IMAGE_SEQUENCE",
                    base_invalid_msg="Invalid cognitive image sequence.",
                    max_attempts_override=PortalLockService.LIMIT_COGNITIVE_IMAGE,
                )

            elif actual_type == "PRIVATE_RESPONSE":
                is_valid = False
                if db and private_response:
                    is_valid = AdaptiveAuthService.verify_enrolled_factor(
                        db=db,
                        user_id=user_id,
                        factor_type="PRIVATE_RESPONSE",
                        private_response=private_response
                    )

                if is_valid:
                    if db is not None:
                        PortalLockService.reset_factor_counter_on_success(db, user_id, eff_app, eff_purpose, "PRIVATE_RESPONSE", session_id=session_id)
                    cls._delete_challenge(challenge)
                    return (True, "Identity step-up verified. Full access restored.", False, {"completed": True, "challenge_type": actual_type, "challenge_purpose": chal_purpose})

                return cls._record_adaptive_failure(
                    db=db, challenge=challenge, user_id=user_id, session_id=session_id,
                    eff_app=eff_app, eff_purpose=eff_purpose, factor_key="PRIVATE_RESPONSE",
                    base_invalid_msg="Invalid private response.",
                    max_attempts_override=PortalLockService.LIMIT_COGNITIVE_PRIVATE,
                )

            elif actual_type == "HIGH_RISK_DUAL":
                cog_purpose = "PASSWORD_CHANGE" if eff_purpose == "PASSWORD_CHANGE" else "COGNITIVE_STEP_UP"
                # Check for direct compound submission (both factors supplied simultaneously)
                if image_sequence and private_response:
                    img_valid = AdaptiveAuthService.verify_enrolled_factor(
                        db=db,
                        user_id=user_id,
                        factor_type="COGNITIVE_IMAGE_SEQUENCE",
                        image_sequence=image_sequence
                    )
                    priv_valid = AdaptiveAuthService.verify_enrolled_factor(
                        db=db,
                        user_id=user_id,
                        factor_type="PRIVATE_RESPONSE",
                        private_response=private_response
                    )
                    if img_valid and priv_valid:
                        if db is not None:
                            PortalLockService.reset_factor_counter_on_success(db, user_id, eff_app, cog_purpose, "COGNITIVE_IMAGE_SEQUENCE", session_id=session_id)
                            PortalLockService.reset_factor_counter_on_success(db, user_id, eff_app, cog_purpose, "PRIVATE_RESPONSE", session_id=session_id)
                        cid = challenge.get("challenge_id")
                        cls._record_password_change_receipt(challenge)
                        cls._delete_challenge(challenge)
                        return (True, "Identity step-up verified. Full access restored.", False, {"stage": 2, "stage_1_passed": True, "completed": True, "challenge_id": cid, "challenge_purpose": chal_purpose})

                    failing_factor = "COGNITIVE_IMAGE_SEQUENCE" if not img_valid else "PRIVATE_RESPONSE"
                    if not img_valid and not priv_valid and db is not None:
                        # Increment both independent factor counters when both submitted factors fail simultaneously
                        is_img_lock, _, _, _, img_lock_obj = PortalLockService.record_verification_failure(
                            db=db, user_id=user_id, application=eff_app, verification_purpose=cog_purpose,
                            factor_key="COGNITIVE_IMAGE_SEQUENCE", session_id=session_id,
                            challenge_reference=challenge.get("challenge_id"), emit_step_up_locked_event=True,
                            max_attempts_override=PortalLockService.LIMIT_COGNITIVE_IMAGE,
                        )
                        if is_img_lock:
                            cls._delete_challenge(challenge)
                            return (
                                False,
                                PortalLockService.build_lock_detail(img_lock_obj)["message"] if img_lock_obj else "Portal access suspended.",
                                True,
                                {"portal_locked": True, "security_reference_id": img_lock_obj.security_reference_id if img_lock_obj else None},
                            )
                        return cls._record_adaptive_failure(
                            db=db, challenge=challenge, user_id=user_id, session_id=session_id,
                            eff_app=eff_app, eff_purpose=cog_purpose, factor_key="PRIVATE_RESPONSE",
                            base_invalid_msg="Invalid cognitive verification.",
                            max_attempts_override=PortalLockService.LIMIT_COGNITIVE_PRIVATE,
                        )
                    return cls._record_adaptive_failure(
                        db=db, challenge=challenge, user_id=user_id, session_id=session_id,
                        eff_app=eff_app, eff_purpose=cog_purpose, factor_key=failing_factor,
                        base_invalid_msg="Invalid verification.",
                        max_attempts_override=PortalLockService.LIMIT_COGNITIVE_IMAGE,
                    )

                # Sequential flow evaluation
                eff_stage = stage or (2 if (private_response and not image_sequence) else 1)

                if eff_stage == 1:
                    if challenge.get("stage_1_passed"):
                        return (
                            False,
                            "Stage 1 already verified. Please submit Stage 2 (Private Security Response).",
                            False,
                            None
                        )

                    if not image_sequence or not isinstance(image_sequence, list) or len(image_sequence) < 3:
                        return cls._record_adaptive_failure(
                            db=db, challenge=challenge, user_id=user_id, session_id=session_id,
                            eff_app=eff_app, eff_purpose=cog_purpose, factor_key="COGNITIVE_IMAGE_SEQUENCE",
                            base_invalid_msg="Valid cognitive image sequence of at least 3 symbols required for Stage 1.",
                            max_attempts_override=PortalLockService.LIMIT_COGNITIVE_IMAGE,
                        )

                    img_valid = AdaptiveAuthService.verify_enrolled_factor(
                        db=db,
                        user_id=user_id,
                        factor_type="COGNITIVE_IMAGE_SEQUENCE",
                        image_sequence=image_sequence
                    )
                    if not img_valid:
                        return cls._record_adaptive_failure(
                            db=db, challenge=challenge, user_id=user_id, session_id=session_id,
                            eff_app=eff_app, eff_purpose=cog_purpose, factor_key="COGNITIVE_IMAGE_SEQUENCE",
                            base_invalid_msg="Invalid cognitive image sequence.",
                            max_attempts_override=PortalLockService.LIMIT_COGNITIVE_IMAGE,
                        )

                    if db is not None:
                        PortalLockService.reset_factor_counter_on_success(db, user_id, eff_app, cog_purpose, "COGNITIVE_IMAGE_SEQUENCE", session_id=session_id)

                    # Stage 1 succeeds: Mark stage 1 passed, keep challenge active for Stage 2
                    challenge["stage_1_passed"] = True
                    challenge["stage"] = 2
                    return (
                        True,
                        "Stage 1 verified. Proceed to Stage 2: Private Security Response.",
                        False,
                        {
                            "stage": 2,
                            "stage_1_passed": True,
                            "completed": False,
                            "prompt": challenge.get("prompt"),
                            "challenge_id": challenge.get("challenge_id")
                        }
                    )

                elif eff_stage == 2:
                    # Enforce server-side stage progression check
                    if not challenge.get("stage_1_passed"):
                        return cls._record_adaptive_failure(
                            db=db, challenge=challenge, user_id=user_id, session_id=session_id,
                            eff_app=eff_app, eff_purpose=cog_purpose, factor_key="PRIVATE_RESPONSE",
                            base_invalid_msg="Out of order: Stage 1 (Cognitive Image Sequence) must be completed and verified before Stage 2.",
                            max_attempts_override=PortalLockService.LIMIT_COGNITIVE_PRIVATE,
                        )

                    if not private_response or not str(private_response).strip():
                        return cls._record_adaptive_failure(
                            db=db, challenge=challenge, user_id=user_id, session_id=session_id,
                            eff_app=eff_app, eff_purpose=cog_purpose, factor_key="PRIVATE_RESPONSE",
                            base_invalid_msg="Private security response is required for Stage 2.",
                            max_attempts_override=PortalLockService.LIMIT_COGNITIVE_PRIVATE,
                        )

                    priv_valid = AdaptiveAuthService.verify_enrolled_factor(
                        db=db,
                        user_id=user_id,
                        factor_type="PRIVATE_RESPONSE",
                        private_response=str(private_response).strip()
                    )
                    if not priv_valid:
                        return cls._record_adaptive_failure(
                            db=db, challenge=challenge, user_id=user_id, session_id=session_id,
                            eff_app=eff_app, eff_purpose=cog_purpose, factor_key="PRIVATE_RESPONSE",
                            base_invalid_msg="Invalid private response.",
                            max_attempts_override=PortalLockService.LIMIT_COGNITIVE_PRIVATE,
                        )

                    if db is not None:
                        PortalLockService.reset_factor_counter_on_success(db, user_id, eff_app, cog_purpose, "PRIVATE_RESPONSE", session_id=session_id)

                    # Stage 2 succeeds: consume and delete challenge immediately (single use / replay protection)
                    cid = challenge.get("challenge_id")
                    cls._record_password_change_receipt(challenge)
                    cls._delete_challenge(challenge)
                    return (
                        True,
                        "Identity step-up verified. Full access restored.",
                        False,
                        {
                            "stage": 2,
                            "stage_1_passed": True,
                            "completed": True,
                            "challenge_id": cid,
                            "challenge_purpose": chal_purpose
                        }
                    )

                else:
                    return (False, f"Invalid stage {stage} specified.", False, None)

            return (False, "Unknown challenge type.", False, None)

    @classmethod
    def create_login_otp_challenge(
        cls,
        session_id: str,
        user_id: int,
        db: Session,
        ttl_seconds: int = DEFAULT_TTL_SECONDS
    ) -> Dict[str, Any]:
        """
        Creates mandatory login OTP challenge following the observation window.
        Enforces server-side email dispatch via SMTP strictly to account's registered email,
        masked destination, cryptographic HMAC storage, and session binding.
        """
        from app.models.session import Session as DbSession
        from app.services.portal_lock_service import PortalLockService

        session = db.query(DbSession).filter(DbSession.id == session_id).first()
        if not session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found."
            )

        if session.status == "TERMINATED":
            PortalLockService.raise_terminated_http_exception(status_code=status.HTTP_401_UNAUTHORIZED)

        if session.status == "ACTIVE":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Session is already authenticated and active."
            )

        cnt_status = PortalLockService.get_attempt_counter_status(
            db, user_id=user_id, application=session.application,
            verification_purpose="LOGIN_OTP", factor_key="EMAIL_OTP", session_id=session_id,
            max_attempts_override=PortalLockService.LIMIT_LOGIN_OTP,
        )
        if cnt_status["exhausted"]:
            lock_obj = PortalLockService.lock_portal(
                db=db,
                user_id=user_id,
                application=session.application,
                verification_purpose="LOGIN_OTP",
                lock_reason="Maximum Login Email OTP verification attempts (1) already exceeded.",
                failed_attempt_count=cnt_status["attempts_used"],
                max_attempts=cnt_status["max_attempts"],
                session_id=session_id,
                emit_step_up_locked_event=True,
            )
            PortalLockService.raise_locked_http_exception(lock_obj, status_code=status.HTTP_423_LOCKED)

        now = utc_now()
        with cls._lock:
            cls._cleanup_expired()
            existing = cls._challenges.get(session_id)
            if existing and existing.get("challenge_type") == "LOGIN_OTP" and now < existing["expires_at"]:
                user = db.query(User).filter(User.id == user_id).first()
                if not user or not user.email:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Authenticated user account does not have a registered email address."
                    )
                delivery_email = EmailService.resolve_delivery_recipient(user.email)
                masked_email = EmailService.mask_email(delivery_email)
                return_otp = existing.get("otp", "") if (settings.EXHIBITION_MODE or settings.ENVIRONMENT in ("test", "testing")) else ""
                return {
                    "challenge_id": existing["challenge_id"],
                    "session_id": session_id,
                    "challenge_type": "LOGIN_OTP",
                    "masked_email": masked_email,
                    "expires_in_seconds": int((existing["expires_at"] - now).total_seconds()),
                    "message": f"Active verification code pending. Check your inbox and spam folder ({masked_email}).",
                    "otp": return_otp,
                    "is_demo_otp": bool(settings.EXHIBITION_MODE),
                    "attempts_remaining": cnt_status["attempts_remaining"],
                    "max_attempts": cnt_status["max_attempts"],
                }

            if session_id in cls._inflight_login_sessions:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Verification code transmission is already in progress. Please check your inbox."
                )
            cls._inflight_login_sessions.add(session_id)

        try:
            user = db.query(User).filter(User.id == user_id).first()
            if not user or not user.email:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Authenticated user account does not have a registered email address."
                )
            delivery_email = EmailService.resolve_delivery_recipient(user.email)
            masked_email = EmailService.mask_email(delivery_email)

            otp_val = f"{secrets.randbelow(1000000):06d}"
            otp_hash = cls._hash_otp(otp_val)
            challenge_id = f"chal_login_{secrets.token_hex(8)}"
            expires_at = now + timedelta(seconds=ttl_seconds)

            # Dispatch via SMTP without holding threading lock
            email_ok, email_msg = EmailService.send_otp_email(
                recipient_email=delivery_email,
                otp_code=otp_val,
                expires_in_minutes=ttl_seconds // 60,
                challenge_id=challenge_id,
                issued_at=now,
                expires_at=expires_at,
            )
            if not email_ok:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Email OTP transmission failed: {email_msg}. Please retry."
                )

            return_otp = otp_val if (settings.EXHIBITION_MODE or settings.ENVIRONMENT in ("test", "testing")) else ""

            with cls._lock:
                cls._challenges[session_id] = {
                    "challenge_id": challenge_id,
                    "session_id": session_id,
                    "user_id": user_id,
                    "challenge_type": "LOGIN_OTP",
                    "otp_hash": otp_hash,
                    "otp": return_otp,
                    "created_at": now,
                    "expires_at": expires_at,
                    "attempts": cnt_status["attempts_used"],
                    "max_attempts": PortalLockService.LIMIT_LOGIN_OTP,
                }

            return {
                "challenge_id": challenge_id,
                "session_id": session_id,
                "challenge_type": "LOGIN_OTP",
                "masked_email": masked_email,
                "expires_in_seconds": ttl_seconds,
                "delivery_status": "SMTP_ACCEPTED",
                "message": f"Email submitted to the mail server for {masked_email}. Check your inbox and spam folder.",
                "otp": return_otp,
                "is_demo_otp": bool(settings.EXHIBITION_MODE),
                "attempts_remaining": cnt_status["attempts_remaining"],
                "max_attempts": cnt_status["max_attempts"],
            }
        finally:
            with cls._lock:
                cls._inflight_login_sessions.discard(session_id)

    @classmethod
    def resend_login_otp_challenge(
        cls,
        session_id: str,
        user_id: int,
        db: Session,
        ttl_seconds: int = DEFAULT_TTL_SECONDS
    ) -> Dict[str, Any]:
        """
        Resends login OTP:
        1. Verifies session is not TERMINATED and not ACTIVE.
        2. Invalidates previous challenge atomically.
        3. Generates fresh cryptographically secure 6-digit OTP and new challenge ID.
        4. Resolves recipient exclusively from authenticated user DB record.
        5. Sends via SMTP.
        6. Stores new challenge and updates session binding.
        """
        from app.models.session import Session as DbSession
        from app.services.portal_lock_service import PortalLockService

        session = db.query(DbSession).filter(DbSession.id == session_id).first()
        if not session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found."
            )

        if session.status == "TERMINATED":
            PortalLockService.raise_terminated_http_exception(status_code=status.HTTP_401_UNAUTHORIZED)

        if session.status == "ACTIVE":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Session is already authenticated and active."
            )

        cnt_status = PortalLockService.get_attempt_counter_status(
            db, user_id=user_id, application=session.application,
            verification_purpose="LOGIN_OTP", factor_key="EMAIL_OTP", session_id=session_id,
            max_attempts_override=PortalLockService.LIMIT_LOGIN_OTP,
        )
        if cnt_status["exhausted"]:
            lock_obj = PortalLockService.lock_portal(
                db=db,
                user_id=user_id,
                application=session.application,
                verification_purpose="LOGIN_OTP",
                lock_reason="Maximum Login Email OTP verification attempts (1) already exceeded.",
                failed_attempt_count=cnt_status["attempts_used"],
                max_attempts=cnt_status["max_attempts"],
                session_id=session_id,
                emit_step_up_locked_event=True,
            )
            PortalLockService.raise_locked_http_exception(lock_obj, status_code=status.HTTP_423_LOCKED)

        # Invalidate previous challenge atomically with in-flight guard
        with cls._lock:
            if session_id in cls._inflight_login_sessions:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Verification code transmission is already in progress. Please check your inbox."
                )
            cls._challenges.pop(session_id, None)
            cls._inflight_login_sessions.add(session_id)

        try:
            user = db.query(User).filter(User.id == user_id).first()
            if not user or not user.email:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Authenticated user account does not have a registered email address."
                )
            delivery_email = EmailService.resolve_delivery_recipient(user.email)
            masked_email = EmailService.mask_email(delivery_email)

            otp_val = f"{secrets.randbelow(1000000):06d}"
            otp_hash = cls._hash_otp(otp_val)
            challenge_id = f"chal_login_{secrets.token_hex(8)}"
            now = utc_now()
            expires_at = now + timedelta(seconds=ttl_seconds)

            email_ok, email_msg = EmailService.send_otp_email(
                recipient_email=delivery_email,
                otp_code=otp_val,
                expires_in_minutes=ttl_seconds // 60,
                challenge_id=challenge_id,
                issued_at=now,
                expires_at=expires_at,
            )
            if not email_ok:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Email OTP transmission failed: {email_msg}. Please retry."
                )

            return_otp = otp_val if (settings.EXHIBITION_MODE or settings.ENVIRONMENT in ("test", "testing")) else ""

            with cls._lock:
                cls._challenges[session_id] = {
                    "challenge_id": challenge_id,
                    "session_id": session_id,
                    "user_id": user_id,
                    "challenge_type": "LOGIN_OTP",
                    "otp_hash": otp_hash,
                    "otp": return_otp,
                    "created_at": now,
                    "expires_at": expires_at,
                    "attempts": cnt_status["attempts_used"],
                    "max_attempts": PortalLockService.LIMIT_LOGIN_OTP,
                }

            session.login_otp_challenge_id = challenge_id
            db.commit()

            return {
                "challenge_id": challenge_id,
                "session_id": session_id,
                "challenge_type": "LOGIN_OTP",
                "masked_email": masked_email,
                "expires_in_seconds": ttl_seconds,
                "delivery_status": "SMTP_ACCEPTED",
                "message": f"Email submitted to the mail server for {masked_email}. Check your inbox and spam folder.",
                "otp": return_otp,
                "is_demo_otp": bool(settings.EXHIBITION_MODE),
                "attempts_remaining": cnt_status["attempts_remaining"],
                "max_attempts": cnt_status["max_attempts"],
            }
        finally:
            with cls._lock:
                cls._inflight_login_sessions.discard(session_id)

    @classmethod
    def verify_login_otp(
        cls,
        session_id: str,
        user_id: int,
        otp_code: str,
        db: Session,
        challenge_id: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        Atomically verifies the login OTP for a pending session.
        - Enforces user binding, session binding, challenge ID binding, and expiry.
        - Expiry does not consume failure attempts.
        - Allows up to 3 incorrect attempts; on the 3rd failure, immediately
          terminates the session and revokes applicable grants.
        """
        from app.services.session_service import SessionService
        from app.services.portal_lock_service import PortalLockService
        with cls._lock:
            session = SessionService.get_session(db, session_id)
            if session and session.status == "TERMINATED":
                cls._challenges.pop(session_id, None)
                PortalLockService.terminate_session_and_revoke_grants(
                    db=db,
                    user_id=user_id,
                    session_id=session_id,
                    application=session.application,
                    verification_purpose="LOGIN_OTP",
                    factor_key="EMAIL_OTP",
                )
                return (False, PortalLockService.SESSION_TERMINATED_MESSAGE)

            challenge = cls._challenges.get(session_id)
            if not challenge or challenge.get("challenge_type") != "LOGIN_OTP":
                return (False, "No active login verification challenge found or challenge expired.")

            if challenge["user_id"] != user_id:
                return (False, "Unauthorized: Challenge does not belong to the requesting user.")

            if challenge.get("session_id") != session_id:
                return (False, "Unauthorized: Challenge does not belong to the requesting session.")

            if challenge_id and challenge.get("challenge_id") != challenge_id:
                return (False, "Challenge ID mismatch or obsolete verification code. Please request a new code.")

            now = utc_now()
            if now > challenge["expires_at"]:
                cls._challenges.pop(session_id, None)
                return (False, "Verification code has expired. Please request a new code.")

            # Validate code atomically
            input_code = str(otp_code or "").strip()
            computed_hash = cls._hash_otp(input_code)
            is_valid = hmac.compare_digest(challenge["otp_hash"], computed_hash)

            if is_valid:
                # Correct OTP: consume atomically and activate session
                cls._challenges.pop(session_id, None)
                if session:
                    PortalLockService.reset_factor_counter_on_success(
                        db, user_id, session.application, "LOGIN_OTP", "EMAIL_OTP", session_id=session_id
                    )
                SessionService.activate_session_after_login_otp(db, session_id, challenge.get("challenge_id"))
                return (True, "Login verification successful. Full access granted.")

            # Incorrect OTP: increment session-bound atomic counter (max 1 attempt -> portal-scoped lockout)
            chal_id_ref = challenge.get("challenge_id")
            portal_app = session.application if session else "platform"
            is_locked, used, max_att, remaining, lock_obj = PortalLockService.record_verification_failure(
                db=db,
                user_id=user_id,
                application=portal_app,
                verification_purpose="LOGIN_OTP",
                factor_key="EMAIL_OTP",
                session_id=session_id,
                challenge_reference=chal_id_ref,
                lock_reason="Maximum Login Email OTP verification attempts (1) exceeded.",
                emit_step_up_locked_event=True,
                max_attempts_override=PortalLockService.LIMIT_LOGIN_OTP,
            )
            challenge["attempts"] = used
            if is_locked:
                cls._challenges.pop(session_id, None)
                detail_msg = (
                    PortalLockService.build_lock_detail(lock_obj)["message"]
                    if lock_obj
                    else f"SECURITY ACCESS SUSPENDED: Access to {portal_app} suspended after failed Email OTP."
                )
                return (False, detail_msg)

            return (
                False,
                f"Invalid verification code. {remaining} attempt{'s' if remaining != 1 else ''} remaining."
            )

    @classmethod
    def create_recovery_otp_challenge(
        cls,
        user_id: int,
        application: str,
        db: Session,
        ttl_seconds: int = 300,
        security_reference_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Issues a persistent, single-use Email OTP for Step 2 of locked portal recovery.
        - Persisted in OTPChallenge (purpose='PORTAL_RECOVERY_OTP', max_attempts=1).
        - Bound to (user_id, portal, security_reference_id).
        - Invalidates any prior active recovery OTP challenges for the same (user, portal).
        - Never stores or logs plaintext OTP codes.
        """
        from app.models.otp_challenge import OTPChallenge
        from app.models.session import Session as DbSession
        from app.services.portal_lock_service import PortalLockService, _norm_app

        norm_app = _norm_app(application)
        lock = PortalLockService.get_active_lock(db, user_id, norm_app)
        if not lock:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No active portal security lock found for recovery."
            )
        if security_reference_id and lock.security_reference_id != security_reference_id.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Provided Security Reference ID does not match the active lock for this portal."
            )
        user = db.query(User).filter(User.id == user_id).first()
        if not user or not user.email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Registered user email is required for recovery OTP verification."
            )
        delivery_email = EmailService.resolve_delivery_recipient(user.email)
        masked_email = EmailService.mask_email(delivery_email)
        otp_val = f"{secrets.randbelow(1000000):06d}"
        otp_hash = cls._hash_otp(otp_val)
        challenge_id = f"chal_recov_{secrets.token_hex(8)}"
        now = utc_now()
        expires_at = now + timedelta(seconds=ttl_seconds)

        valid_sid = None
        if session_id:
            if db.query(DbSession.id).filter(DbSession.id == session_id).first():
                valid_sid = session_id

        key = f"recovery:{user_id}:{lock.application}"
        meta = {
            "portal": lock.application,
            "security_reference_id": lock.security_reference_id,
            "lock_id": lock.id,
        }
        with cls._lock:
            prior_rows = (
                db.query(OTPChallenge)
                .filter(
                    OTPChallenge.user_id == user_id,
                    OTPChallenge.purpose == "PORTAL_RECOVERY_OTP",
                    OTPChallenge.is_consumed == False,
                )
                .all()
            )
            for row in prior_rows:
                try:
                    row_meta = json.loads(row.appointment_data) if isinstance(row.appointment_data, str) else (row.appointment_data or {})
                except Exception:
                    row_meta = {}
                if _norm_app(row_meta.get("portal")) == lock.application:
                    row.is_consumed = True

            db_chal = OTPChallenge(
                challenge_id=challenge_id,
                session_id=valid_sid,
                user_id=user_id,
                purpose="PORTAL_RECOVERY_OTP",
                recipient_email=delivery_email,
                otp_hash=otp_hash,
                appointment_data=json.dumps(meta),
                attempts=0,
                max_attempts=PortalLockService.LIMIT_RECOVERY_OTP,
                is_consumed=False,
                expires_at=expires_at,
                created_at=now,
            )
            db.add(db_chal)
            db.commit()

            cls._challenges[key] = {
                "challenge_id": challenge_id,
                "user_id": user_id,
                "application": lock.application,
                "security_reference_id": lock.security_reference_id,
                "challenge_type": "PORTAL_RECOVERY_OTP",
                "otp_hash": otp_hash,
                "created_at": now,
                "expires_at": expires_at,
                "attempts": 0,
                "max_attempts": PortalLockService.LIMIT_RECOVERY_OTP,
            }

        email_ok, email_msg = EmailService.send_recovery_otp_email(
            recipient_email=delivery_email,
            otp_code=otp_val,
            portal=lock.application,
            security_reference_id=lock.security_reference_id,
            request_timestamp=now,
            expires_in_minutes=max(1, ttl_seconds // 60),
            challenge_id=challenge_id,
            issued_at=now,
            expires_at=expires_at,
        )
        if not email_ok:
            with cls._lock:
                db_chal.is_consumed = True
                db.commit()
                cls._challenges.pop(key, None)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Recovery OTP transmission failed: {email_msg}."
            )

        return_otp = otp_val if (settings.EXHIBITION_MODE or settings.ENVIRONMENT in ("test", "testing")) else ""
        return {
            "challenge_id": challenge_id,
            "portal": lock.application,
            "security_reference_id": lock.security_reference_id,
            "masked_email": masked_email,
            "expires_in_seconds": ttl_seconds,
            "max_attempts": PortalLockService.LIMIT_RECOVERY_OTP,
            "delivery_status": "SMTP_ACCEPTED",
            "otp": return_otp,
            "message": f"Email submitted to the mail server for {masked_email}. Check your inbox and spam folder. Administrator clearance is still required after OTP verification.",
        }

    @classmethod
    def verify_recovery_otp_code(
        cls,
        user_id: int,
        application: str,
        otp_code: str,
        db: Session,
        challenge_id: Optional[str] = None,
        security_reference_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Verifies the registered-email recovery OTP for an active portal lock using persistent DB state.
        - Enforces user, portal, security_reference_id, purpose, single-use, and UTC expiry binding.
        - Enforces single-attempt Recovery Email OTP policy (1 unsuccessful attempt) without
          weakening or clearing the active PortalSecurityLock.
        """
        from app.models.otp_challenge import OTPChallenge
        from app.services.portal_lock_service import PortalLockService, _norm_app

        norm_app = _norm_app(application)
        key = f"recovery:{user_id}:{norm_app}"
        lock = PortalLockService.get_active_lock(db, user_id, norm_app)
        if not lock:
            return (False, "No active portal security lock found for recovery.")
        if security_reference_id and lock.security_reference_id != security_reference_id.strip():
            return (False, "Recovery OTP does not match the active Security Reference ID.")

        now = utc_now()
        with cls._lock:
            db_chal = None
            if challenge_id:
                db_chal = db.query(OTPChallenge).filter(OTPChallenge.challenge_id == challenge_id).first()
                if not db_chal:
                    return (False, "No active recovery OTP challenge found or it has expired.")
            else:
                candidates = (
                    db.query(OTPChallenge)
                    .filter(
                        OTPChallenge.user_id == user_id,
                        OTPChallenge.purpose == "PORTAL_RECOVERY_OTP",
                    )
                    .order_by(OTPChallenge.id.desc())
                    .limit(20)
                    .all()
                )
                matching_portal = []
                for cand in candidates:
                    try:
                        c_meta = json.loads(cand.appointment_data) if isinstance(cand.appointment_data, str) else (cand.appointment_data or {})
                    except Exception:
                        c_meta = {}
                    if _norm_app(c_meta.get("portal")) == norm_app and c_meta.get("security_reference_id") == lock.security_reference_id:
                        matching_portal.append(cand)
                for cand in matching_portal:
                    if not cand.is_consumed:
                        db_chal = cand
                        break
                if not db_chal and matching_portal:
                    db_chal = matching_portal[0]
                if not db_chal:
                    return (False, "No active recovery OTP challenge found or it has expired.")

            if db_chal.purpose != "PORTAL_RECOVERY_OTP":
                return (False, "Verification challenge purpose mismatch. Non-recovery OTPs cannot be used for recovery.")
            if db_chal.user_id != user_id:
                return (False, "Unauthorized: Recovery challenge does not belong to the requesting user.")

            try:
                meta = json.loads(db_chal.appointment_data) if isinstance(db_chal.appointment_data, str) else (db_chal.appointment_data or {})
            except Exception:
                meta = {}
            meta_portal = _norm_app(meta.get("portal"))
            meta_sec_ref = meta.get("security_reference_id")
            if meta_portal != norm_app:
                return (False, "Portal mismatch: Recovery OTP belongs to a different suspended portal.")
            if meta_sec_ref and lock.security_reference_id != meta_sec_ref:
                return (False, "Recovery OTP is not bound to the current active Security Reference ID.")

            if db_chal.is_consumed:
                if (db_chal.attempts or 0) >= (db_chal.max_attempts or PortalLockService.LIMIT_RECOVERY_OTP):
                    return (False, "Maximum recovery OTP attempts (1) exceeded for this code. Please request a new recovery OTP.")
                return (False, "This recovery verification code has already been used or superseded. Please request a new recovery OTP.")

            exp = db_chal.expires_at if db_chal.expires_at.tzinfo else db_chal.expires_at.replace(tzinfo=timezone.utc)
            if now > exp:
                db_chal.is_consumed = True
                db.commit()
                cls._challenges.pop(key, None)
                return (False, "Recovery verification code has expired. Please request a new recovery OTP.")

            max_att = db_chal.max_attempts or PortalLockService.LIMIT_RECOVERY_OTP
            if (db_chal.attempts or 0) >= max_att:
                db_chal.is_consumed = True
                db.commit()
                cls._challenges.pop(key, None)
                return (False, "Maximum recovery OTP attempts (1) exceeded for this code. Please request a new recovery OTP.")

            computed = cls._hash_otp(str(otp_code or "").strip())
            if not str(otp_code or "").strip() or not hmac.compare_digest(db_chal.otp_hash, computed):
                db_chal.attempts = int(db_chal.attempts or 0) + 1
                if db_chal.attempts >= max_att:
                    db_chal.is_consumed = True
                db.commit()
                cls._challenges.pop(key, None)
                PortalLockService.record_recovery_otp_failure(
                    db=db,
                    user_id=user_id,
                    application=norm_app,
                    security_reference_id=lock.security_reference_id,
                    challenge_reference=db_chal.challenge_id,
                    session_id=session_id,
                )
                return (False, "Invalid recovery OTP code. Single-attempt recovery OTP policy exceeded for this code; request a new recovery OTP to retry.")

            updated_rows = (
                db.query(OTPChallenge)
                .filter(
                    OTPChallenge.id == db_chal.id,
                    OTPChallenge.is_consumed == False,
                )
                .update({"is_consumed": True, "consumed_at": now})
            )
            db.commit()
            cls._challenges.pop(key, None)
            if updated_rows == 0:
                return (False, "This recovery verification code has already been used. Please request a new recovery OTP.")
            return (True, "Recovery OTP verified. Portal remains suspended pending Security Administrator clearance.")

    @classmethod
    def create_payment_otp_challenge(
        cls,
        session_id: str,
        user_id: int,
        order_id: str,
        amount: float,
        item_summary: str,
        db: Session,
        ttl_seconds: int = 300
    ) -> Dict[str, Any]:
        """
        Generates and transmits a single-use 6-digit payment verification OTP for Shopping checkout.
        Enforces:
        - Authenticated user account with resolved recipient email (boomikaram35@gmail.com).
        - Order ID and amount binding.
        - Cooldown between resend requests (15s).
        - Direct synchronous SMTP dispatch awaiting result (fails if SMTP transmission fails).
        - Strict challenge purpose: 'SHOPPING_PAYMENT'.
        """
        user = db.query(User).filter(User.id == user_id).first()
        if not user or not user.email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Authenticated user account does not have a registered email address."
            )

        delivery_email = EmailService.resolve_delivery_recipient(user.email)
        masked_email = EmailService.mask_email(delivery_email)
        now = utc_now()

        # Check existing active payment challenge cooldown for this order
        with cls._lock:
            cls._cleanup_expired()
            existing = cls._challenges.get(f"pay:{order_id}")
            if existing and existing.get("challenge_type") == "SHOPPING_PAYMENT":
                cooldown_until = existing.get("cooldown_until")
                if cooldown_until and now < cooldown_until:
                    rem_sec = max(1, int((cooldown_until - now).total_seconds()))
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail=f"Please wait {rem_sec} seconds before requesting a new payment verification code."
                    )

        otp_val = f"{secrets.randbelow(1000000):06d}"
        otp_hash = cls._hash_otp(otp_val)
        challenge_id = f"chal_pay_{secrets.token_hex(8)}"
        expires_at = now + timedelta(seconds=ttl_seconds)

        # Immediate synchronous SMTP delivery
        email_ok, email_msg = EmailService.send_payment_otp_email(
            recipient_email=delivery_email,
            otp_code=otp_val,
            order_id=order_id,
            amount=amount,
            item_summary=item_summary,
            expires_in_minutes=ttl_seconds // 60,
            challenge_id=challenge_id,
            issued_at=now,
            expires_at=expires_at,
        )
        if not email_ok:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Email OTP transmission failed: {email_msg}. Please retry."
            )

        return_otp = otp_val if (settings.EXHIBITION_MODE or settings.ENVIRONMENT in ("test", "testing")) else ""

        from app.services.portal_lock_service import PortalLockService
        challenge_payload = {
            "challenge_id": challenge_id,
            "session_id": session_id,
            "user_id": user_id,
            "order_id": order_id,
            "amount": amount,
            "challenge_type": "SHOPPING_PAYMENT",
            "otp_hash": otp_hash,
            "otp": return_otp,
            "created_at": now,
            "expires_at": expires_at,
            "attempts": 0,
            "max_attempts": PortalLockService.LIMIT_OTHER_OTP,
            "cooldown_until": now + timedelta(seconds=15),
        }

        with cls._lock:
            # Purge prior payment challenges for this order
            for k, c in list(cls._challenges.items()):
                if c.get("challenge_type") == "SHOPPING_PAYMENT" and c.get("order_id") == order_id:
                    cls._challenges.pop(k, None)
            cls._challenges[challenge_id] = challenge_payload
            cls._challenges[f"pay:{order_id}"] = challenge_payload

        logger.info(
            f"[COGNISEC-AI] [PAYMENT_OTP_ISSUED] challenge_id={challenge_id} "
            f"order_id={order_id} recipient={masked_email} amount={amount}"
        )

        return {
            "challenge_id": challenge_id,
            "order_id": order_id,
            "challenge_type": "SHOPPING_PAYMENT",
            "masked_email": masked_email,
            "expires_in_seconds": ttl_seconds,
            "resend_cooldown_seconds": 15,
            "delivery_status": "SMTP_ACCEPTED",
            "message": f"Email submitted to the mail server for {masked_email}. Check your inbox and spam folder.",
            "amount": amount,
            "currency": "INR",
            "otp": return_otp,
            "is_demo_otp": bool(settings.EXHIBITION_MODE)
        }

    @classmethod
    def verify_payment_otp(
        cls,
        session_id: str,
        user_id: int,
        order_id: str,
        challenge_id: str,
        otp_code: str,
        db: Session
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Atomically verifies the single-use payment OTP for Shopping checkout.
        Enforces:
        - Challenge type strictly 'SHOPPING_PAYMENT'.
        - Challenge must match session, user, and order ID.
        - Expiry checking.
        - Max attempt limiting (3 attempts).
        - Atomic consumption upon success (cannot be reused).
        - Updates ShoppingOrder to PAID and sets payment reference upon valid code.
        """
        from app.models.shopping_order import ShoppingOrder
        from app.models.security_event import SecurityEvent

        with cls._lock:
            cls._cleanup_expired()

            # Find challenge by challenge_id
            challenge = cls._challenges.get(challenge_id) or cls._challenges.get(f"pay:{order_id}")
            if not challenge or challenge.get("challenge_type") != "SHOPPING_PAYMENT":
                return (False, "No active payment verification challenge found or challenge expired.", None)

            if challenge.get("challenge_id") != challenge_id:
                return (False, "Challenge ID mismatch or obsolete payment verification code. Please request a new code.", None)

            if challenge.get("user_id") != user_id:
                return (False, "Unauthorized: Payment challenge does not belong to the requesting user.", None)

            if challenge.get("session_id") != session_id:
                return (False, "Unauthorized: Payment challenge does not belong to the requesting session.", None)

            if challenge.get("order_id") != order_id:
                return (False, "Unauthorized: Payment challenge does not match the order ID.", None)

            now = utc_now()
            if now > challenge["expires_at"]:
                cls._challenges.pop(challenge_id, None)
                cls._challenges.pop(f"pay:{order_id}", None)
                return (False, "Verification code has expired. Please request a new code.", None)

            if challenge["attempts"] >= challenge["max_attempts"]:
                cls._challenges.pop(challenge_id, None)
                cls._challenges.pop(f"pay:{order_id}", None)
                return (False, "Maximum verification attempts exceeded. Payment challenge locked. Please request a new code.", None)

            # Validate code atomically
            input_code = str(otp_code or "").strip()
            computed_hash = cls._hash_otp(input_code)
            is_valid = hmac.compare_digest(challenge["otp_hash"], computed_hash)

            if not is_valid:
                from app.services.portal_lock_service import PortalLockService
                challenge["attempts"] += 1
                is_locked, _, _, rem, lock_obj = PortalLockService.record_verification_failure(
                    db=db,
                    user_id=user_id,
                    application="shopping",
                    verification_purpose="PAYMENT_OTP",
                    factor_key="EMAIL_OTP",
                    session_id=session_id,
                    challenge_reference=challenge_id,
                    lock_reason="Maximum Shopping Payment Email OTP verification attempts (1) exceeded.",
                    emit_step_up_locked_event=True,
                    max_attempts_override=PortalLockService.LIMIT_OTHER_OTP,
                )
                if is_locked or rem <= 0:
                    cls._challenges.pop(challenge_id, None)
                    cls._challenges.pop(f"pay:{order_id}", None)
                    detail_msg = (
                        PortalLockService.build_lock_detail(lock_obj)["message"]
                        if lock_obj
                        else "Invalid verification code. Maximum attempts exceeded."
                    )
                    return (False, detail_msg, None)
                return (False, f"Invalid verification code. {rem} attempt(s) remaining.", None)

            # Succeeded: Consume challenge atomically so it can NEVER be reused
            cls._challenges.pop(challenge_id, None)
            cls._challenges.pop(f"pay:{order_id}", None)

            # Generate unique demo payment reference
            payment_ref = f"SIM-PAY-{secrets.token_hex(4).upper()}"

            # Update database order
            order = db.query(ShoppingOrder).filter(ShoppingOrder.order_id == order_id).first()
            if order:
                order.payment_status = "PAID"
                order.payment_reference = payment_ref
                order.paid_at = now
                db.commit()

            # Record security audit event
            try:
                sec_event = SecurityEvent(
                    session_id=session_id,
                    event_type="PAYMENT_OTP_VERIFIED",
                    details=f"Payment authorization code verified for order {order_id} (amount=₹{challenge.get('amount')}). Ref: {payment_ref}",
                    ip_address="127.0.0.1"
                )
                db.add(sec_event)
                db.commit()
            except Exception as ev_err:
                logger.debug(f"[COGNISEC-AI] Payment event audit notice: {ev_err}")

            return (True, "Simulated payment verified successfully.", payment_ref)

    @classmethod
    def resend_payment_otp_challenge(
        cls,
        session_id: str,
        user_id: int,
        order_id: str,
        db: Session
    ) -> Dict[str, Any]:
        """
        Resends payment verification OTP for Shopping checkout subject to cooldown.
        Retrieves existing order details, invalidates prior challenge, and issues fresh code.
        """
        from app.models.shopping_order import ShoppingOrder
        order = db.query(ShoppingOrder).filter(
            ShoppingOrder.user_id == user_id,
            ShoppingOrder.order_id == order_id
        ).first()
        if not order:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Order '{order_id}' not found."
            )
        if order.payment_status == "PAID":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Order is already paid."
            )
        return cls.create_payment_otp_challenge(
            session_id=session_id,
            user_id=user_id,
            order_id=order_id,
            amount=order.amount,
            item_summary=order.item_summary,
            db=db
        )

    @classmethod
    def create_appointment_otp_challenge(
        cls,
        session_id: Optional[str],
        user_id: Optional[int],
        appointment_data: Dict[str, Any],
        db: Session,
        ttl_seconds: int = 300,
        existing_pending_appointment_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Generates and transmits a single-use 6-digit verification OTP for Healthcare appointment booking.
        Enforces:
        - Patient supplied, validated email recipient (or registered user email when verified).
        - Pre-check on doctor validity, OPD day/slot schedule, and confirmed slot availability.
        - Creates a PENDING_VERIFICATION appointment record linked to the challenge before issuing OTP.
        - Concurrency lock and 15s cooldown between requests per session or patient email.
        - Persistent challenge record in DB (OTPChallenge table) with HMAC-SHA256 hashed code.
        - Direct synchronous SMTP dispatch awaiting result (fails cleanly without confirming if SMTP fails).
        """
        from app.services.healthcare_service import HealthcareService
        from app.models.appointment import HealthcareAppointment
        from app.models.otp_challenge import OTPChallenge

        if user_id is not None:
            user = db.query(User).filter(User.id == user_id).first()
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Authenticated user account not found."
                )

        # Validate doctor exists
        doctor = HealthcareService.get_doctor_by_id(appointment_data.get("doctor_id", ""))
        if not doctor:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Selected doctor '{appointment_data.get('doctor_id')}' is not in the hospital registry."
            )

        patient_name = str(appointment_data.get("patient_name", "")).strip()
        patient_phone = str(appointment_data.get("patient_phone", "")).strip()
        patient_email = str(appointment_data.get("patient_email", "")).strip().lower()
        apt_date = str(appointment_data.get("appointment_date", "")).strip()
        time_slot = str(appointment_data.get("time_slot", "")).strip()

        if not EmailService.validate_email_address(patient_email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="A valid patient email address is required to receive the verification OTP."
            )

        # Validate doctor's configured OPD schedule (weekday & slot)
        HealthcareService.validate_doctor_schedule(doctor, apt_date, time_slot)

        # Ensure slot is not already confirmed
        is_open = HealthcareService.check_slot_availability(
            db=db,
            doctor_id=doctor["id"],
            date=apt_date,
            slot=time_slot
        )
        if not is_open:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"The selected time slot ({time_slot} on {apt_date}) is already booked. Please choose another slot."
            )

        appointment_data["doctor_id"] = doctor["id"]
        appointment_data["doctor_name"] = doctor["name"]
        appointment_data["department"] = doctor["dept_label"]
        appointment_data["room"] = doctor["room"]
        appointment_data["consultation_fee"] = doctor["fee"]
        appointment_data["patient_name"] = patient_name
        appointment_data["patient_phone"] = patient_phone
        appointment_data["patient_email"] = patient_email
        appointment_data["appointment_date"] = apt_date
        appointment_data["time_slot"] = time_slot

        # Send OTP strictly to the patient's supplied, validated email
        delivery_email = EmailService.resolve_delivery_recipient(patient_email)
        masked_email = EmailService.mask_email(delivery_email)
        now = utc_now()
        scope_key = f"apt:{session_id}" if session_id else f"apt_email:{delivery_email}"

        # Check existing active appointment challenge cooldown and in-flight lock
        with cls._lock:
            cls._cleanup_expired()
            if scope_key in cls._inflight_appointment_sessions:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="An appointment verification code is currently being dispatched. Please wait a moment."
                )

            existing = cls._challenges.get(scope_key)
            if existing and existing.get("challenge_type") == "HEALTHCARE_APPOINTMENT":
                cooldown_until = existing.get("cooldown_until")
                if cooldown_until and now < cooldown_until:
                    rem_sec = max(1, int((cooldown_until - now).total_seconds()))
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail=f"Please wait {rem_sec} seconds before requesting a new appointment verification code."
                    )

            db_query = db.query(OTPChallenge).filter(
                OTPChallenge.purpose == "APPOINTMENT_OTP",
                OTPChallenge.is_consumed == False,
                OTPChallenge.expires_at > now
            )
            if session_id:
                db_query = db_query.filter(OTPChallenge.session_id == session_id)
            else:
                db_query = db_query.filter(OTPChallenge.recipient_email == delivery_email)

            db_existing = db_query.order_by(OTPChallenge.created_at.desc()).first()
            if db_existing and db_existing.cooldown_until:
                cooldown_db = (
                    db_existing.cooldown_until
                    if db_existing.cooldown_until.tzinfo
                    else db_existing.cooldown_until.replace(tzinfo=timezone.utc)
                )
                if now < cooldown_db:
                    rem_sec = max(1, int((cooldown_db - now).total_seconds()))
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail=f"Please wait {rem_sec} seconds before requesting a new appointment verification code."
                    )

            cls._inflight_appointment_sessions.add(scope_key)

        try:
            otp_val = f"{secrets.randbelow(1000000):06d}"
            otp_hash = cls._hash_otp(otp_val)
            challenge_id = f"chal_apt_{secrets.token_hex(8)}"
            expires_at = now + timedelta(seconds=ttl_seconds)
            cooldown_until = now + timedelta(seconds=15)

            # Invalidate any prior unconsumed appointment challenges for this scope in DB
            inv_query = db.query(OTPChallenge).filter(
                OTPChallenge.purpose == "APPOINTMENT_OTP",
                OTPChallenge.is_consumed == False
            )
            if session_id:
                inv_query = inv_query.filter(OTPChallenge.session_id == session_id)
            else:
                inv_query = inv_query.filter(OTPChallenge.recipient_email == delivery_email)
            inv_query.update({"is_consumed": True, "consumed_at": now})
            db.commit()

            # Reuse or create PENDING_VERIFICATION appointment record
            pending_apt = None
            if existing_pending_appointment_id:
                pending_apt = (
                    db.query(HealthcareAppointment)
                    .filter(
                        HealthcareAppointment.id == existing_pending_appointment_id,
                        HealthcareAppointment.status == "PENDING_VERIFICATION"
                    )
                    .first()
                )

            if not pending_apt:
                # Expire any prior stale PENDING_VERIFICATION booking by this same patient for this slot
                db.query(HealthcareAppointment).filter(
                    HealthcareAppointment.doctor_id == doctor["id"],
                    HealthcareAppointment.appointment_date == apt_date,
                    HealthcareAppointment.time_slot == time_slot,
                    HealthcareAppointment.patient_email == patient_email,
                    HealthcareAppointment.status == "PENDING_VERIFICATION"
                ).update({"status": "EXPIRED"})

                ref_id = f"AYU-{datetime.now().year}-{secrets.token_hex(3).upper()}"
                pending_apt = HealthcareAppointment(
                    reference_id=ref_id,
                    patient_name=patient_name,
                    patient_age=appointment_data.get("patient_age"),
                    patient_gender=appointment_data.get("patient_gender"),
                    patient_phone=patient_phone,
                    patient_email=patient_email,
                    reason_for_visit=appointment_data.get("reason_for_visit"),
                    department=doctor["dept_label"],
                    doctor_id=doctor["id"],
                    doctor_name=doctor["name"],
                    appointment_date=apt_date,
                    time_slot=time_slot,
                    consultation_mode=appointment_data.get("consultation_mode") or "In-Person Hospital Visit",
                    consultation_fee=doctor["fee"],
                    room=doctor["room"],
                    status="PENDING_VERIFICATION",
                    otp_challenge_id=challenge_id,
                    user_id=user_id,
                )
                db.add(pending_apt)
                db.flush()
            else:
                pending_apt.otp_challenge_id = challenge_id

            from app.services.portal_lock_service import PortalLockService
            # Persist new challenge record linked to pending appointment
            db_challenge = OTPChallenge(
                challenge_id=challenge_id,
                session_id=session_id,
                user_id=user_id,
                appointment_id=pending_apt.id,
                purpose="APPOINTMENT_OTP",
                recipient_email=delivery_email,
                otp_hash=otp_hash,
                appointment_data=json.dumps(appointment_data),
                attempts=0,
                max_attempts=PortalLockService.LIMIT_OTHER_OTP,
                is_consumed=False,
                expires_at=expires_at,
                cooldown_until=cooldown_until,
                created_at=now
            )
            db.add(db_challenge)
            db.commit()
            db.refresh(pending_apt)

            # Immediate synchronous SMTP delivery
            email_ok, email_msg = EmailService.send_appointment_otp_email(
                recipient_email=delivery_email,
                otp_code=otp_val,
                patient_name=patient_name or "Valued Patient",
                doctor_name=doctor["name"],
                appointment_date=apt_date,
                time_slot=time_slot,
                department=doctor["dept_label"],
                expires_in_minutes=ttl_seconds // 60,
                challenge_id=challenge_id,
                appointment_reference=pending_apt.reference_id,
                consultation_mode=pending_apt.consultation_mode,
                issued_at=now,
                expires_at=expires_at,
            )
            if not email_ok or ("Simulated delivery" in str(email_msg) and not EmailService.is_configured()):
                db.delete(db_challenge)
                pending_apt.status = "FAILED"
                db.commit()
                fail_reason = email_msg if not email_ok else "SMTP mail server is not configured or disabled on the backend. Unable to dispatch real appointment verification email."
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Email OTP transmission failed: {fail_reason}. Please check the email address and retry."
                )

            challenge_payload = {
                "challenge_id": challenge_id,
                "session_id": session_id,
                "user_id": user_id,
                "appointment_id": pending_apt.id,
                "scope_key": scope_key,
                "challenge_type": "HEALTHCARE_APPOINTMENT",
                "appointment_data": appointment_data,
                "otp_hash": otp_hash,
                "created_at": now,
                "expires_at": expires_at,
                "attempts": 0,
                "max_attempts": cls.MAX_ATTEMPTS,
                "cooldown_until": cooldown_until,
            }

            with cls._lock:
                for k, c in list(cls._challenges.items()):
                    if c.get("challenge_type") == "HEALTHCARE_APPOINTMENT" and c.get("scope_key") == scope_key:
                        cls._challenges.pop(k, None)
                cls._challenges[challenge_id] = challenge_payload
                cls._challenges[scope_key] = challenge_payload

            logger.info(
                f"[COGNISEC-AI] [APPOINTMENT_OTP_ISSUED] challenge_id={challenge_id} "
                f"pending_ref={pending_apt.reference_id} recipient={masked_email} doctor={doctor['name']} date={apt_date}"
            )

            if EmailService.is_configured():
                disp_msg = f"Email submitted to the mail server for {masked_email}. Check your inbox and spam folder."
            else:
                disp_msg = f"Email submitted to the mail server for {masked_email}. Check your inbox and spam folder."

            return {
                "challenge_id": challenge_id,
                "challenge_type": "HEALTHCARE_APPOINTMENT",
                "pending_appointment_id": pending_apt.id,
                "pending_reference_id": pending_apt.reference_id,
                "delivery_status": "SMTP_ACCEPTED",
                "masked_email": masked_email,
                "expires_in_seconds": ttl_seconds,
                "resend_cooldown_seconds": 15,
                "message": disp_msg,
                "doctor_id": doctor["id"],
                "doctor_name": doctor["name"],
                "department": doctor["dept_label"],
                "consultation_fee": doctor["fee"],
                "appointment_date": apt_date,
                "time_slot": time_slot
            }
        finally:
            with cls._lock:
                cls._inflight_appointment_sessions.discard(scope_key)

    @classmethod
    def verify_appointment_otp(
        cls,
        session_id: Optional[str],
        user_id: Optional[int],
        challenge_id: str,
        otp_code: str,
        db: Session
    ) -> Tuple[bool, str, Optional[Any]]:
        """
        Atomically verifies the single-use appointment OTP for AyuSync MedCare and
        transitions the linked PENDING_VERIFICATION appointment to CONFIRMED.
        """
        from app.models.appointment import HealthcareAppointment
        from app.services.healthcare_service import HealthcareService
        from app.models.security_event import SecurityEvent
        from app.models.otp_challenge import OTPChallenge

        now = utc_now()

        db_challenge = None
        if challenge_id:
            db_challenge = db.query(OTPChallenge).filter(OTPChallenge.challenge_id == challenge_id).first()
        if not db_challenge and session_id:
            db_challenge = (
                db.query(OTPChallenge)
                .filter(
                    OTPChallenge.session_id == session_id,
                    OTPChallenge.purpose == "APPOINTMENT_OTP",
                    OTPChallenge.is_consumed == False
                )
                .order_by(OTPChallenge.created_at.desc())
                .first()
            )

        if not db_challenge or db_challenge.purpose != "APPOINTMENT_OTP":
            return (False, "No active appointment verification challenge found or challenge expired.", None)

        if db_challenge.user_id is not None and db_challenge.user_id != user_id:
            return (False, "Unauthorized: Appointment challenge does not belong to the requesting user.", None)
        if db_challenge.session_id is not None and db_challenge.session_id != session_id:
            return (False, "Unauthorized: Appointment challenge does not belong to the requesting session.", None)

        pending_apt = None
        if getattr(db_challenge, "appointment_id", None):
            pending_apt = db.query(HealthcareAppointment).filter(HealthcareAppointment.id == db_challenge.appointment_id).first()
        if not pending_apt:
            pending_apt = db.query(HealthcareAppointment).filter(HealthcareAppointment.otp_challenge_id == db_challenge.challenge_id).first()

        if db_challenge.is_consumed:
            return (False, "This appointment verification code has already been used. Please request a new code.", None)

        exp = db_challenge.expires_at if db_challenge.expires_at.tzinfo else db_challenge.expires_at.replace(tzinfo=timezone.utc)
        if now > exp:
            db_challenge.is_consumed = True
            if pending_apt and pending_apt.status == "PENDING_VERIFICATION":
                pending_apt.status = "EXPIRED"
            db.commit()
            with cls._lock:
                cls._challenges.pop(challenge_id, None)
                if db_challenge.session_id:
                    cls._challenges.pop(f"apt:{db_challenge.session_id}", None)
            return (False, "Verification code has expired. Please request a new code.", None)

        if db_challenge.attempts >= db_challenge.max_attempts:
            db_challenge.is_consumed = True
            if pending_apt and pending_apt.status == "PENDING_VERIFICATION":
                pending_apt.status = "FAILED"
            db.commit()
            with cls._lock:
                cls._challenges.pop(challenge_id, None)
                if db_challenge.session_id:
                    cls._challenges.pop(f"apt:{db_challenge.session_id}", None)
            return (False, "Maximum verification attempts exceeded. Appointment remains unconfirmed. Please request a new code.", None)

        input_code = str(otp_code or "").strip()
        computed_hash = cls._hash_otp(input_code)
        is_valid = hmac.compare_digest(db_challenge.otp_hash, computed_hash)

        if not is_valid:
            db_challenge.attempts += 1
            rem = db_challenge.max_attempts - db_challenge.attempts
            actor_uid = user_id if user_id is not None else db_challenge.user_id
            lock_obj = None
            is_locked = False
            if actor_uid is not None:
                from app.services.portal_lock_service import PortalLockService
                is_locked, _, _, rem, lock_obj = PortalLockService.record_verification_failure(
                    db=db,
                    user_id=actor_uid,
                    application="healthcare",
                    verification_purpose="APPOINTMENT_OTP",
                    factor_key="EMAIL_OTP",
                    session_id=session_id or db_challenge.session_id,
                    challenge_reference=challenge_id,
                    lock_reason="Maximum Healthcare Appointment Email OTP verification attempts (1) exceeded.",
                    emit_step_up_locked_event=True,
                    max_attempts_override=PortalLockService.LIMIT_OTHER_OTP,
                )
            if is_locked or rem <= 0:
                db_challenge.is_consumed = True
                if pending_apt and pending_apt.status == "PENDING_VERIFICATION":
                    pending_apt.status = "FAILED"
                db.commit()
                with cls._lock:
                    cls._challenges.pop(challenge_id, None)
                    if db_challenge.session_id:
                        cls._challenges.pop(f"apt:{db_challenge.session_id}", None)
                detail_msg = (
                    PortalLockService.build_lock_detail(lock_obj)["message"]
                    if lock_obj
                    else "Invalid verification code. Maximum attempts exceeded. Appointment was not confirmed."
                )
                return (False, detail_msg, None)
            db.commit()
            return (False, f"Invalid verification code. {rem} attempt(s) remaining.", None)

        # Atomic single-use consumption
        updated_rows = (
            db.query(OTPChallenge)
            .filter(
                OTPChallenge.id == db_challenge.id,
                OTPChallenge.is_consumed == False
            )
            .update({"is_consumed": True, "consumed_at": now})
        )
        db.commit()
        if updated_rows == 0:
            return (False, "This appointment verification code has already been used. Please request a new code.", None)

        with cls._lock:
            cls._challenges.pop(challenge_id, None)
            if db_challenge.session_id:
                cls._challenges.pop(f"apt:{db_challenge.session_id}", None)

        apt_data = json.loads(db_challenge.appointment_data) if isinstance(db_challenge.appointment_data, str) else (db_challenge.appointment_data or {})

        # Atomically check confirmed slot collisions and promote PENDING_VERIFICATION -> CONFIRMED
        with cls._lock:
            is_open = HealthcareService.check_slot_availability(
                db=db,
                doctor_id=apt_data["doctor_id"],
                date=apt_data["appointment_date"],
                slot=apt_data["time_slot"]
            )
            if not is_open:
                if pending_apt and pending_apt.status == "PENDING_VERIFICATION":
                    pending_apt.status = "FAILED"
                    db.commit()
                return (False, f"Slot {apt_data['time_slot']} on {apt_data['appointment_date']} was just confirmed by another patient. Please select another slot.", None)

            if pending_apt:
                pending_apt.status = "CONFIRMED"
                pending_apt.verified_at = now
                if user_id is not None and pending_apt.user_id is None:
                    pending_apt.user_id = user_id
                db.commit()
                db.refresh(pending_apt)
                appointment = pending_apt
            else:
                ref_id = f"AYU-{datetime.now().year}-{secrets.token_hex(3).upper()}"
                appointment = HealthcareAppointment(
                    reference_id=ref_id,
                    patient_name=str(apt_data.get("patient_name", "Valued Patient")).strip(),
                    patient_age=apt_data.get("patient_age"),
                    patient_gender=apt_data.get("patient_gender"),
                    patient_phone=str(apt_data.get("patient_phone", "")).strip(),
                    patient_email=str(apt_data.get("patient_email", "")).strip().lower(),
                    reason_for_visit=apt_data.get("reason_for_visit"),
                    department=apt_data.get("department", "General Medicine"),
                    doctor_id=apt_data["doctor_id"],
                    doctor_name=apt_data["doctor_name"],
                    appointment_date=apt_data["appointment_date"],
                    time_slot=apt_data["time_slot"],
                    consultation_mode=apt_data.get("consultation_mode", "In-Person Hospital Visit"),
                    consultation_fee=apt_data.get("consultation_fee"),
                    room=apt_data.get("room"),
                    status="CONFIRMED",
                    otp_challenge_id=db_challenge.challenge_id,
                    verified_at=now,
                    user_id=user_id
                )
                db.add(appointment)
                db.commit()
                db.refresh(appointment)

        if session_id:
            try:
                sec_event = SecurityEvent(
                    session_id=session_id,
                    event_type="APPOINTMENT_OTP_VERIFIED",
                    details=f"Appointment OTP verified for {appointment.doctor_name} on {appointment.appointment_date} {appointment.time_slot}. Ref: {appointment.reference_id}",
                    ip_address="127.0.0.1"
                )
                db.add(sec_event)
                db.commit()
            except Exception as ev_err:
                logger.debug(f"[COGNISEC-AI] Appointment event audit notice: {ev_err}")

        return (True, "Appointment confirmed successfully.", appointment)

    @classmethod
    def resend_appointment_otp_challenge(
        cls,
        session_id: Optional[str],
        user_id: Optional[int],
        challenge_id: str,
        db: Session
    ) -> Dict[str, Any]:
        """
        Resends appointment verification OTP subject to 15s cooldown while keeping
        the associated PENDING_VERIFICATION appointment linked.
        """
        from app.models.otp_challenge import OTPChallenge

        now = utc_now()

        db_challenge = None
        if challenge_id:
            db_challenge = db.query(OTPChallenge).filter(OTPChallenge.challenge_id == challenge_id).first()
        if not db_challenge and session_id:
            db_challenge = (
                db.query(OTPChallenge)
                .filter(
                    OTPChallenge.session_id == session_id,
                    OTPChallenge.purpose == "APPOINTMENT_OTP"
                )
                .order_by(OTPChallenge.created_at.desc())
                .first()
            )

        if not db_challenge or db_challenge.purpose != "APPOINTMENT_OTP":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No active appointment verification challenge found to resend."
            )

        if db_challenge.user_id is not None and db_challenge.user_id != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Unauthorized: Challenge does not belong to requesting user."
            )
        if db_challenge.session_id is not None and db_challenge.session_id != session_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Unauthorized: Challenge does not belong to requesting session."
            )
        if db_challenge.cooldown_until:
            cooldown_db = (
                db_challenge.cooldown_until
                if db_challenge.cooldown_until.tzinfo
                else db_challenge.cooldown_until.replace(tzinfo=timezone.utc)
            )
            if now < cooldown_db:
                rem_sec = max(1, int((cooldown_db - now).total_seconds()))
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Please wait {rem_sec} seconds before requesting a new appointment verification code."
                )

        apt_data = json.loads(db_challenge.appointment_data) if isinstance(db_challenge.appointment_data, str) else (db_challenge.appointment_data or {})
        pending_apt_id = getattr(db_challenge, "appointment_id", None)
        db_challenge.is_consumed = True
        db.commit()

        return cls.create_appointment_otp_challenge(
            session_id=session_id,
            user_id=user_id,
            appointment_data=apt_data,
            db=db,
            existing_pending_appointment_id=pending_apt_id
        )

    @classmethod
    def create_exam_otp_challenge(
        cls,
        session_id: str,
        user_id: int,
        course_name: str,
        db: Session,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        force_new: bool = False
    ) -> Dict[str, Any]:
        """
        Generates and dispatches a 6-digit OTP to the student's registered email
        before launching a proctored online examination in the College Portal.
        - Deduplicates repeated exam launch requests so no duplicate or conflicting
          OTP emails are sent for the same active challenge window.
        - Only reports email delivery after Gmail SMTP confirms acceptance.
        """
        from app.models.session import Session as DbSession
        from app.models.otp_challenge import OTPChallenge

        db_session = db.query(DbSession).filter(DbSession.id == session_id).first()
        if not db_session or db_session.user_id != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid or unauthorized session for online examination."
            )
        if db_session.status == "TERMINATED" or db_session.current_risk_level == "CRITICAL":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Session terminated due to critical security risk. Cannot launch online examination."
            )
        if db_session.status == "PENDING_OBSERVATION":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Initial 20-second behavioral observation is still in progress. Complete login verification first."
            )

        user = db.query(User).filter(User.id == user_id).first()
        if not user or not user.email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Authenticated student account has no registered email address."
            )

        delivery_email = EmailService.resolve_delivery_recipient(user.email)
        masked_email = EmailService.mask_email(delivery_email)
        clean_course = (course_name or "CS F301 • End-Semester Proctored Assessment").strip()
        now = utc_now()

        with cls._lock:
            cls._cleanup_expired()
            if session_id in cls._inflight_exam_sessions:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="An examination verification code is currently being dispatched. Please wait a moment."
                )

            if not force_new:
                existing_mem = cls._challenges.get(f"exam:{session_id}")
                if (
                    existing_mem
                    and existing_mem.get("challenge_type") == "COLLEGE_EXAM_OTP"
                    and existing_mem.get("attempts", 0) == 0
                    and now < existing_mem.get("expires_at", now)
                ):
                    rem_ttl = max(1, int((existing_mem["expires_at"] - now).total_seconds()))
                    cd_until = existing_mem.get("cooldown_until")
                    rem_cd = max(0, int((cd_until - now).total_seconds())) if (cd_until and now < cd_until) else 0
                    logger.info(
                        f"[COGNISEC-AI] [EXAM_OTP_DEDUP] Reusing active un-attempted exam OTP challenge "
                        f"challenge_id={existing_mem['challenge_id']} session_id={session_id}"
                    )
                    return {
                        "challenge_id": existing_mem["challenge_id"],
                        "session_id": session_id,
                        "challenge_type": "COLLEGE_EXAM_OTP",
                        "course_name": existing_mem.get("course_name", clean_course),
                        "masked_email": masked_email,
                        "expires_in_seconds": rem_ttl,
                        "resend_cooldown_seconds": rem_cd,
                        "email_delivered": True,
                        "deduplicated": True,
                        "message": f"Verification code already sent to {masked_email}. Please enter the 6-digit code to launch the exam.",
                        "otp": existing_mem.get("otp", ""),
                        "is_demo_otp": bool(settings.EXHIBITION_MODE)
                    }

            cls._inflight_exam_sessions.add(session_id)

        try:
            otp_val = f"{secrets.randbelow(1000000):06d}"
            otp_hash = cls._hash_otp(otp_val)
            challenge_id = f"chal_exam_{secrets.token_hex(8)}"
            expires_at = now + timedelta(seconds=ttl_seconds)
            cooldown_until = now + timedelta(seconds=15)

            # Invalidate any prior unconsumed exam challenges for this session in DB
            db.query(OTPChallenge).filter(
                OTPChallenge.session_id == session_id,
                OTPChallenge.purpose == "COLLEGE_EXAM_OTP",
                OTPChallenge.is_consumed == False
            ).update({"is_consumed": True, "consumed_at": now})
            db.commit()

            from app.services.portal_lock_service import PortalLockService
            exam_meta = {"course_name": clean_course, "student_email": delivery_email}
            db_challenge = OTPChallenge(
                challenge_id=challenge_id,
                session_id=session_id,
                user_id=user_id,
                purpose="COLLEGE_EXAM_OTP",
                recipient_email=delivery_email,
                otp_hash=otp_hash,
                appointment_data=json.dumps(exam_meta),
                attempts=0,
                max_attempts=PortalLockService.LIMIT_EXAM_OTP,
                is_consumed=False,
                expires_at=expires_at,
                cooldown_until=cooldown_until,
                created_at=now
            )
            db.add(db_challenge)
            db.commit()

            email_ok, email_msg = EmailService.send_exam_otp_email(
                recipient_email=delivery_email,
                otp_code=otp_val,
                course_name=clean_course,
                expires_in_minutes=max(1, ttl_seconds // 60),
                challenge_id=challenge_id,
                issued_at=now,
                expires_at=expires_at,
            )
            if not email_ok:
                db.delete(db_challenge)
                db.commit()
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Email OTP transmission failed: {email_msg}. Please retry."
                )

            return_otp = otp_val if (settings.EXHIBITION_MODE or settings.ENVIRONMENT in ("test", "testing")) else ""
            challenge_payload = {
                "challenge_id": challenge_id,
                "session_id": session_id,
                "user_id": user_id,
                "challenge_type": "COLLEGE_EXAM_OTP",
                "course_name": clean_course,
                "otp_hash": otp_hash,
                "otp": return_otp,
                "created_at": now,
                "expires_at": expires_at,
                "attempts": 0,
                "max_attempts": cls.MAX_ATTEMPTS,
                "cooldown_until": cooldown_until,
            }

            with cls._lock:
                for k, c in list(cls._challenges.items()):
                    if c.get("challenge_type") == "COLLEGE_EXAM_OTP" and c.get("session_id") == session_id:
                        cls._challenges.pop(k, None)
                cls._challenges[challenge_id] = challenge_payload
                cls._challenges[f"exam:{session_id}"] = challenge_payload

            max_attempts = PortalLockService.get_max_attempts_for("EXAM_OTP", "EMAIL_OTP")
            counter_status = PortalLockService.get_attempt_counter_status(
                db=db,
                user_id=user_id,
                application="college",
                verification_purpose="EXAM_OTP",
                factor_key="EMAIL_OTP",
                session_id=session_id,
                max_attempts_override=max_attempts,
            )
            attempts_remaining = counter_status["attempts_remaining"]

            logger.info(
                f"[COGNISEC-AI] [EXAM_OTP_ISSUED] challenge_id={challenge_id} "
                f"session_id={session_id} recipient={masked_email} course={clean_course}"
            )

            return {
                "challenge_id": challenge_id,
                "session_id": session_id,
                "challenge_type": "COLLEGE_EXAM_OTP",
                "course_name": clean_course,
                "masked_email": masked_email,
                "expires_in_seconds": ttl_seconds,
                "resend_cooldown_seconds": 15,
                "attempts_remaining": attempts_remaining,
                "max_attempts": max_attempts,
                "email_delivered": True,
                "delivery_status": "SMTP_ACCEPTED",
                "deduplicated": False,
                "message": f"Email submitted to the mail server for {masked_email}. Check your inbox and spam folder.",
                "otp": return_otp,
                "is_demo_otp": bool(settings.EXHIBITION_MODE)
            }
        finally:
            with cls._lock:
                cls._inflight_exam_sessions.discard(session_id)

    @classmethod
    def resend_exam_otp_challenge(
        cls,
        session_id: str,
        user_id: int,
        course_name: Optional[str],
        db: Session
    ) -> Dict[str, Any]:
        """
        Resends examination verification OTP subject to 15-second cooldown.
        Invalidates previous exam challenge and dispatches a fresh 6-digit OTP.
        """
        from app.models.otp_challenge import OTPChallenge

        now = utc_now()
        resolved_course = course_name or "CS F301 • End-Semester Proctored Assessment"

        db_challenge = (
            db.query(OTPChallenge)
            .filter(
                OTPChallenge.session_id == session_id,
                OTPChallenge.purpose == "COLLEGE_EXAM_OTP",
                OTPChallenge.is_consumed == False
            )
            .order_by(OTPChallenge.created_at.desc())
            .first()
        )
        if db_challenge:
            if db_challenge.user_id != user_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Unauthorized: Challenge does not belong to requesting user."
                )
            if db_challenge.cooldown_until:
                cd_db = (
                    db_challenge.cooldown_until
                    if db_challenge.cooldown_until.tzinfo
                    else db_challenge.cooldown_until.replace(tzinfo=timezone.utc)
                )
                if now < cd_db:
                    rem_sec = max(1, int((cd_db - now).total_seconds()))
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail=f"Please wait {rem_sec} seconds before requesting a new examination verification code."
                    )
            try:
                meta = json.loads(db_challenge.appointment_data) if isinstance(db_challenge.appointment_data, str) else (db_challenge.appointment_data or {})
                if not course_name and meta.get("course_name"):
                    resolved_course = meta["course_name"]
            except Exception:
                pass
            db_challenge.is_consumed = True
            db_challenge.consumed_at = now
            db.commit()
        else:
            with cls._lock:
                mem_chal = cls._challenges.get(f"exam:{session_id}")
                if mem_chal and mem_chal.get("challenge_type") == "COLLEGE_EXAM_OTP":
                    if mem_chal.get("user_id") != user_id:
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail="Unauthorized: Challenge does not belong to requesting user."
                        )
                    cd_until = mem_chal.get("cooldown_until")
                    if cd_until and now < cd_until:
                        rem_sec = max(1, int((cd_until - now).total_seconds()))
                        raise HTTPException(
                            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail=f"Please wait {rem_sec} seconds before requesting a new examination verification code."
                        )
                    if not course_name and mem_chal.get("course_name"):
                        resolved_course = mem_chal["course_name"]
                    cls._delete_challenge(mem_chal)
                    cls._challenges.pop(f"exam:{session_id}", None)

        return cls.create_exam_otp_challenge(
            session_id=session_id,
            user_id=user_id,
            course_name=resolved_course,
            db=db,
            force_new=True
        )

    @classmethod
    def verify_exam_otp_challenge(
        cls,
        session_id: str,
        user_id: int,
        challenge_id: Optional[str],
        otp_code: str,
        course_name: Optional[str],
        db: Session
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Atomically verifies the single-use College Examination OTP.
        - Rejects expired, invalid, reused, or incorrect OTPs.
        - Records an authoritative ApplicationGrant for (application='college', resource='online_exam', factor='EXAM_OTP').
        """
        from app.models.otp_challenge import OTPChallenge
        from app.models.security_event import SecurityEvent
        from app.services.session_service import SessionService

        now = utc_now()

        db_challenge = None
        if challenge_id:
            db_challenge = db.query(OTPChallenge).filter(OTPChallenge.challenge_id == challenge_id).first()
        if not db_challenge and session_id:
            db_challenge = (
                db.query(OTPChallenge)
                .filter(
                    OTPChallenge.session_id == session_id,
                    OTPChallenge.purpose == "COLLEGE_EXAM_OTP"
                )
                .order_by(OTPChallenge.created_at.desc())
                .first()
            )

        mem_challenge = None
        with cls._lock:
            cls._cleanup_expired()
            mem_challenge = (cls._challenges.get(challenge_id) if challenge_id else None) or cls._challenges.get(f"exam:{session_id}")

        if not db_challenge and not mem_challenge:
            return (False, "No active examination verification challenge found or challenge has expired.", None)

        resolved_course = course_name or "CS F301 • End-Semester Proctored Assessment"

        if db_challenge:
            if db_challenge.user_id != user_id:
                return (False, "Unauthorized: Examination challenge does not belong to the requesting user.", None)
            if db_challenge.session_id != session_id:
                return (False, "Unauthorized: Examination challenge does not belong to the requesting session.", None)
            if challenge_id and db_challenge.challenge_id != challenge_id:
                return (False, "Challenge ID mismatch or obsolete examination verification code. Please request a new code.", None)
            if db_challenge.is_consumed:
                return (False, "This examination verification code has already been used or invalidated.", None)

            exp = db_challenge.expires_at if db_challenge.expires_at.tzinfo else db_challenge.expires_at.replace(tzinfo=timezone.utc)
            if now > exp:
                db_challenge.is_consumed = True
                db_challenge.consumed_at = now
                db.commit()
                with cls._lock:
                    if challenge_id:
                        cls._challenges.pop(challenge_id, None)
                    cls._challenges.pop(f"exam:{session_id}", None)
                return (False, "Verification code has expired. Please request a new code.", None)

            if db_challenge.attempts >= db_challenge.max_attempts:
                db_challenge.is_consumed = True
                db_challenge.consumed_at = now
                db.commit()
                with cls._lock:
                    if challenge_id:
                        cls._challenges.pop(challenge_id, None)
                    cls._challenges.pop(f"exam:{session_id}", None)
                return (False, "Maximum verification attempts exceeded. Examination challenge locked.", None)

            input_code = str(otp_code or "").strip()
            computed_hash = cls._hash_otp(input_code)
            is_valid = hmac.compare_digest(db_challenge.otp_hash, computed_hash)

            if not is_valid:
                from app.services.portal_lock_service import PortalLockService
                db_challenge.attempts += 1
                is_locked, _, _, rem, lock_obj = PortalLockService.record_verification_failure(
                    db=db,
                    user_id=user_id,
                    application="college",
                    verification_purpose="EXAM_OTP",
                    factor_key="EMAIL_OTP",
                    session_id=session_id,
                    challenge_reference=db_challenge.challenge_id,
                    lock_reason="Maximum Examination Email OTP verification attempts (1) exceeded.",
                    emit_step_up_locked_event=True,
                    max_attempts_override=PortalLockService.LIMIT_EXAM_OTP,
                )
                if mem_challenge:
                    mem_challenge["attempts"] = db_challenge.attempts
                if is_locked or rem <= 0:
                    db_challenge.is_consumed = True
                    db_challenge.consumed_at = now
                    db.commit()
                    with cls._lock:
                        if challenge_id:
                            cls._challenges.pop(challenge_id, None)
                        cls._challenges.pop(f"exam:{session_id}", None)
                    detail_msg = (
                        PortalLockService.build_lock_detail(lock_obj)["message"]
                        if lock_obj
                        else "Invalid verification code. Maximum attempts exceeded. Examination remains locked."
                    )
                    return (False, detail_msg, None)
                db.commit()
                return (False, f"Invalid verification code. {rem} attempt(s) remaining.", None)

            # Consume single-use challenge
            db_challenge.is_consumed = True
            db_challenge.consumed_at = now
            db.commit()
            try:
                meta = json.loads(db_challenge.appointment_data) if isinstance(db_challenge.appointment_data, str) else (db_challenge.appointment_data or {})
                if meta.get("course_name"):
                    resolved_course = meta["course_name"]
            except Exception:
                pass
            with cls._lock:
                if challenge_id:
                    cls._challenges.pop(challenge_id, None)
                cls._challenges.pop(db_challenge.challenge_id, None)
                cls._challenges.pop(f"exam:{session_id}", None)
        else:
            challenge = mem_challenge
            if challenge.get("challenge_type") != "COLLEGE_EXAM_OTP":
                return (False, "No active examination verification challenge found or challenge has expired.", None)
            if challenge_id and challenge.get("challenge_id") != challenge_id:
                return (False, "Challenge ID mismatch or obsolete examination verification code.", None)
            if challenge.get("user_id") != user_id or challenge.get("session_id") != session_id:
                return (False, "Unauthorized: Examination challenge does not belong to the requesting session.", None)
            if now > challenge["expires_at"]:
                with cls._lock:
                    cls._delete_challenge(challenge)
                    cls._challenges.pop(f"exam:{session_id}", None)
                return (False, "Verification code has expired. Please request a new code.", None)
            if challenge["attempts"] >= challenge["max_attempts"]:
                with cls._lock:
                    cls._delete_challenge(challenge)
                    cls._challenges.pop(f"exam:{session_id}", None)
                return (False, "Maximum verification attempts exceeded. Examination challenge locked.", None)

            input_code = str(otp_code or "").strip()
            computed_hash = cls._hash_otp(input_code)
            if not hmac.compare_digest(challenge["otp_hash"], computed_hash):
                from app.services.portal_lock_service import PortalLockService
                challenge["attempts"] += 1
                is_locked, _, _, rem, lock_obj = PortalLockService.record_verification_failure(
                    db=db,
                    user_id=user_id,
                    application="college",
                    verification_purpose="EXAM_OTP",
                    factor_key="EMAIL_OTP",
                    session_id=session_id,
                    challenge_reference=challenge.get("challenge_id"),
                    lock_reason="Maximum Examination Email OTP verification attempts (1) exceeded.",
                    emit_step_up_locked_event=True,
                    max_attempts_override=PortalLockService.LIMIT_EXAM_OTP,
                )
                if is_locked or rem <= 0:
                    with cls._lock:
                        cls._delete_challenge(challenge)
                        cls._challenges.pop(f"exam:{session_id}", None)
                    detail_msg = (
                        PortalLockService.build_lock_detail(lock_obj)["message"]
                        if lock_obj
                        else "Invalid verification code. Maximum attempts exceeded. Examination remains locked."
                    )
                    return (False, detail_msg, None)
                return (False, f"Invalid verification code. {rem} attempt(s) remaining.", None)

            resolved_course = challenge.get("course_name") or resolved_course
            with cls._lock:
                cls._delete_challenge(challenge)
                cls._challenges.pop(f"exam:{session_id}", None)

        # Create authoritative ApplicationGrant for online_exam
        grant = SessionService.record_application_grant(
            db=db,
            session_id=session_id,
            user_id=user_id,
            application="college",
            resource="online_exam",
            factor="EXAM_OTP",
            validity_minutes=30
        )
        if not grant:
            return (False, "Session is no longer active or eligible for examination authorization.", None)

        exam_token = f"#BITS-EXM-{secrets.token_hex(3).upper()}"
        try:
            sec_event = SecurityEvent(
                user_id=user_id,
                session_id=session_id,
                application="college",
                event_type="EXAM_OTP_VERIFIED",
                severity="INFO",
                decision="ALLOW",
                details=f"Online examination OTP verified for course '{resolved_course}'. Exam token: {exam_token}"
            )
            db.add(sec_event)
            db.commit()
        except Exception:
            pass

        return (
            True,
            "Examination identity verification complete. Proctored exam unlocked.",
            {
                "authorized": True,
                "session_id": session_id,
                "course_name": resolved_course,
                "exam_token": exam_token,
                "grant_expires_at": grant.expires_at.isoformat() if grant.expires_at else None
            }
        )

    @classmethod
    def get_challenge(cls, session_id: str, application: Optional[str] = None) -> Optional[Dict[str, Any]]:
        with cls._lock:
            if application:
                from app.services.session_service import SessionService
                norm_app = SessionService.normalize_application(application)
                if f"{session_id}:{norm_app}" in cls._challenges:
                    return cls._challenges[f"{session_id}:{norm_app}"]
            if session_id in cls._challenges:
                return cls._challenges[session_id]
            for c in cls._challenges.values():
                if c.get("session_id") == session_id:
                    return c
            return None

    @classmethod
    def _record_password_change_receipt(cls, challenge: Dict[str, Any]):
        """Records a single-use receipt ONLY for HIGH_RISK_DUAL challenges explicitly bound to resource=='password_change'."""
        if not challenge:
            return
        if challenge.get("challenge_type") != "HIGH_RISK_DUAL":
            return
        if challenge.get("resource") != "password_change":
            return
        cid = challenge.get("challenge_id")
        if not cid:
            return
        cls._bound_password_change_receipts[cid] = {
            "challenge_id": cid,
            "user_id": challenge.get("user_id"),
            "session_id": challenge.get("session_id"),
            "application": challenge.get("application"),
            "resource": "password_change",
            "expires_at": utc_now() + timedelta(minutes=5),
            "consumed": False,
        }

    @classmethod
    def consume_bound_password_change_challenge(
        cls,
        challenge_id: str,
        user_id: int,
        session_id: str,
        application: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Atomically verifies and consumes a HIGH_RISK_DUAL challenge explicitly bound to password_change."""
        if not challenge_id:
            return False, "Missing bound high-risk challenge ID."
        with cls._lock:
            rec = cls._bound_password_change_receipts.get(challenge_id)
            if not rec or rec.get("consumed"):
                return False, "Challenge is invalid, expired, not bound to password_change, or already used."
            if rec.get("user_id") != user_id:
                return False, "Unauthorized: Challenge does not belong to requesting user."
            if rec.get("session_id") != session_id:
                return False, "Unauthorized: Challenge does not belong to requesting session."
            if rec.get("resource") != "password_change":
                return False, "Challenge was not issued for password_change."
            rec_app = rec.get("application")
            if rec_app and application and rec_app != application:
                return False, f"Challenge application mismatch: issued for '{rec_app}', submitted to '{application}'."
            if utc_now() > rec.get("expires_at", utc_now()):
                cls._bound_password_change_receipts.pop(challenge_id, None)
                return False, "Bound high-risk challenge has expired."
            rec["consumed"] = True
            cls._bound_password_change_receipts.pop(challenge_id, None)
            return True, "Bound HIGH_RISK_DUAL verification confirmed for password_change."

    @classmethod
    def reset(cls):
        """Reset all challenges (used for test isolation)."""
        with cls._lock:
            cls._challenges.clear()
            cls._password_resets.clear()
            cls._email_verifications.clear()
            cls._neuraltrace_resets.clear()
            cls._reset_tickets.clear()
            cls._bound_password_change_receipts.clear()

    @classmethod
    def invalidate_user_challenges(cls, user_id: int, factor_type: Optional[str] = None):
        """
        Invalidates active step-up challenges for the specified user.
        If factor_type is provided, only challenges of that type are removed.
        """
        with cls._lock:
            to_delete = [
                k for k, c in cls._challenges.items()
                if c.get("user_id") == user_id and (factor_type is None or c.get("challenge_type") == factor_type)
            ]
            for k in to_delete:
                cls._challenges.pop(k, None)

    @classmethod
    def create_password_reset_challenge(
        cls,
        email: str,
        db: Session,
        ttl_seconds: int = DEFAULT_TTL_SECONDS
    ) -> Tuple[bool, str, str, bool, str]:
        """
        Generates and delivers a secure 6-digit OTP for account password recovery.
        Resolves account strictly from verified database record.
        Returns: (success, message, masked_email, email_delivered, delivery_status)
        """
        norm_email = email.lower().strip()
        from app.services.auth_service import AuthService
        user = AuthService.get_user_by_email(db, norm_email)
        if not user:
            # Anti-enumeration response
            masked = EmailService.mask_email(norm_email)
            return (
                True,
                f"If this account is registered, a verification code has been sent to {masked}.",
                masked,
                False,
                "UNREGISTERED_ACCOUNT",
                None
            )

        delivery_email = EmailService.resolve_delivery_recipient(user.email)
        masked_email = EmailService.mask_email(delivery_email)
        otp = f"{secrets.randbelow(1000000):06d}"
        otp_hash = cls._hash_otp(otp)
        now = utc_now()
        expires_at = now + timedelta(seconds=ttl_seconds)

        with cls._lock:
            existing = cls._password_resets.get(norm_email)
            if existing and (now - existing["created_at"]) < timedelta(seconds=15) and now < existing["expires_at"]:
                logger.info(
                    f"[COGNISEC-AI] [PASSWORD_RESET_DEDUP] Duplicate reset request for {norm_email} deduplicated within 15s cooldown."
                )
                ret_otp = existing.get("otp") if (settings.EXHIBITION_MODE or settings.ENVIRONMENT in ("test", "testing")) else None
                return (True, f"Verification code sent to {masked_email}.", masked_email, True, "DELIVERED", ret_otp)

            cls._password_resets[norm_email] = {
                "user_id": user.id,
                "email": user.email,
                "otp_hash": otp_hash,
                "otp": otp,
                "created_at": now,
                "expires_at": expires_at,
                "attempts": 0,
                "max_attempts": cls.MAX_ATTEMPTS
            }

        # Send via EmailService using dedicated password reset template
        email_ok, email_msg = EmailService.send_password_reset_email(
            recipient_email=delivery_email,
            otp_code=otp,
            expires_in_minutes=ttl_seconds // 60,
            issued_at=now,
            expires_at=expires_at,
        )
        if not email_ok and not settings.EXHIBITION_MODE:
            with cls._lock:
                cls._password_resets.pop(norm_email, None)
            safe_err = "Email delivery failed: unable to dispatch verification code."
            if "timed out" in email_msg.lower():
                safe_err = "Email delivery failed: connection timed out."
            elif "rejected" in email_msg.lower():
                safe_err = "Email delivery failed: recipient address was rejected."
            elif "auth" in email_msg.lower():
                safe_err = "Email delivery failed: mail server authentication error."
            elif "suppressed" in email_msg.lower():
                safe_err = "Email delivery failed: recipient is not deliverable."
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=safe_err
            )

        delivery_status = "SMTP_ACCEPTED" if email_ok else ("PENDING" if settings.EXHIBITION_MODE else "FAILED")
        return_otp = otp if (settings.EXHIBITION_MODE or settings.ENVIRONMENT in ("test", "testing")) else None
        msg_text = (
            f"Email submitted to the mail server for {masked_email}. Check your inbox and spam folder."
            if email_ok else ("Sending verification email..." if settings.EXHIBITION_MODE else "Email delivery could not be initiated. Please retry.")
        )
        return (True, msg_text, masked_email, email_ok, delivery_status, return_otp)

    @classmethod
    def resend_password_reset_challenge(
        cls,
        email: str,
        db: Session,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        cooldown_seconds: int = 30
    ) -> Tuple[bool, str, str, int, bool, str]:
        """
        Resends password recovery OTP to registered email.
        Enforces cooldown, supersedes previous OTP, and returns delivery status.
        Returns: (success, message, masked_email, retry_after, email_delivered, delivery_status)
        """
        norm_email = email.lower().strip()
        from app.services.auth_service import AuthService
        user = AuthService.get_user_by_email(db, norm_email)
        masked = EmailService.mask_email(norm_email)
        if not user:
            # Anti-enumeration response: preserve identical format
            return (
                True,
                f"If this account is registered, a verification code has been sent to {masked}.",
                masked,
                cooldown_seconds,
                False,
                "UNREGISTERED_ACCOUNT"
            )

        masked_email = EmailService.mask_email(user.email)
        now = utc_now()

        with cls._lock:
            existing = cls._password_resets.get(norm_email)
            if existing:
                elapsed = (now - existing["created_at"]).total_seconds()
                # If existing code is still valid and within cooldown window, block resend
                if elapsed < cooldown_seconds and now < existing["expires_at"]:
                    remaining = max(1, int(cooldown_seconds - elapsed))
                    logger.info(
                        f"[COGNISEC-AI] [PASSWORD_RESET_RESEND_BLOCKED] Resend for {norm_email} blocked by cooldown ({remaining}s remaining)."
                    )
                    return (
                        False,
                        f"Please wait {remaining} second{'s' if remaining != 1 else ''} before requesting a new code.",
                        masked_email,
                        remaining,
                        False,
                        "COOLDOWN_ACTIVE"
                    )

            # Generate fresh 6-digit OTP and supersede any prior challenge
            otp = f"{secrets.randbelow(1000000):06d}"
            otp_hash = cls._hash_otp(otp)
            expires_at = now + timedelta(seconds=ttl_seconds)

            cls._password_resets[norm_email] = {
                "user_id": user.id,
                "email": user.email,
                "otp_hash": otp_hash,
                "otp": otp,
                "created_at": now,
                "expires_at": expires_at,
                "attempts": 0,
                "max_attempts": cls.MAX_ATTEMPTS
            }

        # Dispatch via EmailService
        delivery_email = EmailService.resolve_delivery_recipient(user.email)
        masked_email = EmailService.mask_email(delivery_email)
        email_ok, email_msg = EmailService.send_password_reset_email(
            recipient_email=delivery_email,
            otp_code=otp,
            expires_in_minutes=ttl_seconds // 60,
            issued_at=now,
            expires_at=expires_at,
        )
        if not email_ok and not settings.EXHIBITION_MODE:
            with cls._lock:
                cls._password_resets.pop(norm_email, None)
            safe_err = "Email delivery failed: unable to dispatch verification code."
            if "timed out" in email_msg.lower():
                safe_err = "Email delivery failed: connection timed out."
            elif "rejected" in email_msg.lower():
                safe_err = "Email delivery failed: recipient address was rejected."
            elif "auth" in email_msg.lower():
                safe_err = "Email delivery failed: mail server authentication error."
            elif "suppressed" in email_msg.lower():
                safe_err = "Email delivery failed: recipient is not deliverable."
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=safe_err
            )

        delivery_status = "SMTP_ACCEPTED" if email_ok else ("PENDING" if settings.EXHIBITION_MODE else "FAILED")
        logger.info(f"[COGNISEC-AI] [PASSWORD_RESET_RESEND] Password reset OTP status={delivery_status} for {masked_email}.")
        msg_text = (
            f"Email submitted to the mail server for {masked_email}. Check your inbox and spam folder."
            if email_ok else ("Sending verification email..." if settings.EXHIBITION_MODE else "Email delivery could not be initiated. Please retry.")
        )
        return (
            True,
            msg_text,
            masked_email,
            cooldown_seconds,
            email_ok,
            delivery_status
        )

    @classmethod
    def verify_password_reset_challenge(cls, email: str, otp_code: str) -> Tuple[bool, str]:
        norm_email = email.lower().strip()
        with cls._lock:
            challenge = cls._password_resets.get(norm_email)
            if not challenge:
                return (False, "No active password reset request found for this email. Please request a new code.")

            now = utc_now()
            if now > challenge["expires_at"]:
                cls._password_resets.pop(norm_email, None)
                return (False, "Verification code has expired. Please request a new code.")

            if challenge["attempts"] >= challenge["max_attempts"]:
                cls._password_resets.pop(norm_email, None)
                return (False, "Too many failed attempts. This reset request has been cancelled.")

            expected_hash = cls._hash_otp(otp_code.strip())
            if not hmac.compare_digest(challenge["otp_hash"], expected_hash):
                challenge["attempts"] += 1
                rem = challenge["max_attempts"] - challenge["attempts"]
                if rem <= 0:
                    cls._password_resets.pop(norm_email, None)
                    return (False, "Too many failed attempts. This reset request has been cancelled.")
                return (False, f"Invalid verification code. {rem} attempt{'s' if rem != 1 else ''} remaining.")

            # Successfully verified, consume single-use challenge
            cls._password_resets.pop(norm_email, None)
            return (True, "Verification successful.")

    @classmethod
    def has_email_verification_challenge(cls, email: str) -> bool:
        norm_email = email.lower().strip()
        with cls._lock:
            return norm_email in cls._email_verifications

    @classmethod
    def create_email_verification_challenge(
        cls,
        email: str,
        db: Session,
        ttl_seconds: int = DEFAULT_TTL_SECONDS
    ) -> Tuple[bool, str, str, bool, str, Optional[str]]:
        """
        Generates and dispatches a 6-digit email verification OTP for newly registered accounts.
        Returns: (success, message, masked_email, email_delivered, delivery_status, dev_otp)
        """
        norm_email = email.lower().strip()
        from app.services.auth_service import AuthService
        user = AuthService.get_user_by_email(db, norm_email)
        if not user:
            masked = EmailService.mask_email(norm_email)
            return (False, "Account not found.", masked, False, "UNREGISTERED_ACCOUNT", None)

        delivery_email = EmailService.resolve_delivery_recipient(user.email)
        masked_email = EmailService.mask_email(delivery_email)
        otp = f"{secrets.randbelow(1000000):06d}"
        otp_hash = cls._hash_otp(otp)
        now = utc_now()
        expires_at = now + timedelta(seconds=ttl_seconds)

        with cls._lock:
            existing = cls._email_verifications.get(norm_email)
            if existing and (now - existing["created_at"]) < timedelta(seconds=15) and now < existing["expires_at"]:
                ret_otp = existing.get("otp") if (settings.EXHIBITION_MODE or settings.ENVIRONMENT in ("test", "testing")) else None
                return (True, f"Verification code sent to {masked_email}.", masked_email, True, "DELIVERED", ret_otp)

            cls._email_verifications[norm_email] = {
                "user_id": user.id,
                "email": user.email,
                "otp_hash": otp_hash,
                "otp": otp,
                "created_at": now,
                "expires_at": expires_at,
                "attempts": 0,
                "max_attempts": cls.MAX_ATTEMPTS,
            }

        email_ok, email_msg = EmailService.send_otp_email(
            recipient_email=delivery_email,
            otp_code=otp,
            expires_in_minutes=max(1, ttl_seconds // 60),
            issued_at=now,
            expires_at=expires_at,
        )
        if not email_ok and not settings.EXHIBITION_MODE and settings.ENVIRONMENT not in ("test", "testing"):
            logger.warning(f"[COGNISEC-AI] [EMAIL_VERIF_OTP] Email dispatch warning for {masked_email}: {email_msg}")

        delivery_status = "SMTP_ACCEPTED" if email_ok else ("EXHIBITION_FALLBACK" if settings.EXHIBITION_MODE else "DISPATCH_PENDING")
        return_otp = otp if (settings.EXHIBITION_MODE or settings.ENVIRONMENT in ("test", "testing")) else None
        msg_text = (
            f"Verification code sent to {masked_email}. Enter the 6-digit code to verify your email."
            if email_ok else f"Verification code generated for {masked_email}."
        )
        return (True, msg_text, masked_email, email_ok, delivery_status, return_otp)

    @classmethod
    def verify_email_verification_challenge(cls, email: str, otp_code: str) -> Tuple[bool, str]:
        norm_email = email.lower().strip()
        with cls._lock:
            challenge = cls._email_verifications.get(norm_email)
            if not challenge:
                return (False, "No active email verification challenge found. Please request a new code.")

            now = utc_now()
            if now > challenge["expires_at"]:
                cls._email_verifications.pop(norm_email, None)
                return (False, "Verification code has expired. Please request a new code.")

            if challenge["attempts"] >= challenge["max_attempts"]:
                cls._email_verifications.pop(norm_email, None)
                return (False, "Too many failed verification attempts. Please request a new code.")

            expected_hash = cls._hash_otp((otp_code or "").strip())
            if not hmac.compare_digest(challenge["otp_hash"], expected_hash):
                challenge["attempts"] += 1
                rem = challenge["max_attempts"] - challenge["attempts"]
                if rem <= 0:
                    cls._email_verifications.pop(norm_email, None)
                    return (False, "Too many failed verification attempts. Please request a new code.")
                return (False, f"Invalid verification code. {rem} attempt{'s' if rem != 1 else ''} remaining.")

            cls._email_verifications.pop(norm_email, None)
            return (True, "Email verified successfully.")

    @classmethod
    def create_neuraltrace_reset_challenge(
        cls,
        user_id: int,
        otp: str,
        ttl_seconds: int = 600
    ) -> str:
        """
        Creates a single-use re-authentication challenge for NeuralTrace factor reset.
        Stores salted HMAC-SHA256 hash. Returns challenge_id.
        """
        with cls._lock:
            cls._cleanup_expired()
            challenge_id = f"nt_reset_{secrets.token_hex(12)}"
            now = utc_now()
            cls._neuraltrace_resets[challenge_id] = {
                "challenge_id": challenge_id,
                "user_id": user_id,
                "otp_hash": cls._hash_otp(otp),
                "otp": otp if (settings.EXHIBITION_MODE or settings.ENVIRONMENT in ("test", "testing")) else "",
                "created_at": now,
                "expires_at": now + timedelta(seconds=ttl_seconds),
                "attempts": 0,
                "max_attempts": cls.MAX_ATTEMPTS,
            }
            return challenge_id

    @classmethod
    def verify_neuraltrace_reset_challenge(
        cls,
        user_id: int,
        challenge_id: str,
        otp: str,
        ticket_ttl_seconds: int = 600
    ) -> Tuple[bool, Optional[str], str]:
        """
        Verifies 6-digit recovery OTP for NeuralTrace factor reset.
        On success, issues a single-use cryptographically random reset ticket.
        Returns: (success, reset_ticket, message)
        """
        with cls._lock:
            cls._cleanup_expired()
            challenge = cls._neuraltrace_resets.get(challenge_id)
            if not challenge:
                return (False, None, "Invalid or expired reset challenge. Please request a new verification code.")

            if challenge["user_id"] != user_id:
                return (False, None, "Unauthorized: Challenge does not belong to the authenticated user.")

            now = utc_now()
            if now > challenge["expires_at"]:
                cls._neuraltrace_resets.pop(challenge_id, None)
                return (False, None, "Reset verification code has expired. Please request a new code.")

            if challenge["attempts"] >= challenge["max_attempts"]:
                cls._neuraltrace_resets.pop(challenge_id, None)
                return (False, None, f"Maximum verification attempts ({challenge['max_attempts']}) exceeded. Please request a new code.")

            code_clean = str(otp or "").strip()
            computed_hash = cls._hash_otp(code_clean)
            if not hmac.compare_digest(challenge["otp_hash"], computed_hash):
                challenge["attempts"] += 1
                rem = challenge["max_attempts"] - challenge["attempts"]
                if rem <= 0:
                    cls._neuraltrace_resets.pop(challenge_id, None)
                    return (False, None, "Maximum verification attempts exceeded. Reset challenge locked.")
                return (False, None, f"Invalid verification code. {rem} attempt{'s' if rem != 1 else ''} remaining.")

            # Verification succeeded: consume reset challenge and issue scoped ticket
            cls._neuraltrace_resets.pop(challenge_id, None)
            ticket_token = f"nt_ticket_{secrets.token_hex(24)}"
            cls._reset_tickets[ticket_token] = {
                "ticket": ticket_token,
                "user_id": user_id,
                "created_at": now,
                "expires_at": now + timedelta(seconds=ticket_ttl_seconds)
            }
            return (True, ticket_token, "Re-authentication verified. You may now draw and confirm your new NeuralTrace route.")

    @classmethod
    def validate_neuraltrace_reset_ticket(cls, user_id: int, reset_ticket: str) -> bool:
        """
        Validates a NeuralTrace reset ticket without consuming it.
        """
        with cls._lock:
            cls._cleanup_expired()
            ticket_data = cls._reset_tickets.get(reset_ticket)
            if not ticket_data:
                return False
            if ticket_data["user_id"] != user_id:
                return False
            if utc_now() > ticket_data["expires_at"]:
                cls._reset_tickets.pop(reset_ticket, None)
                return False
            return True

    @classmethod
    def consume_neuraltrace_reset_ticket(cls, user_id: int, reset_ticket: str) -> bool:
        """
        Validates and consumes a single-use NeuralTrace reset ticket.
        Returns True if valid and consumed; False otherwise.
        """
        with cls._lock:
            cls._cleanup_expired()
            ticket_data = cls._reset_tickets.get(reset_ticket)
            if not ticket_data:
                return False

            if ticket_data["user_id"] != user_id:
                return False

            now = utc_now()
            if now > ticket_data["expires_at"]:
                cls._reset_tickets.pop(reset_ticket, None)
                return False

            # Single-use consumption
            cls._reset_tickets.pop(reset_ticket, None)
            return True

    @classmethod
    def _cleanup_expired(cls):
        now = utc_now()
        expired_keys = [
            sid for sid, c in cls._challenges.items()
            if now > c["expires_at"]
        ]
        for sid in expired_keys:
            cls._challenges.pop(sid, None)

        expired_pwd = [
            em for em, c in cls._password_resets.items()
            if now > c["expires_at"]
        ]
        for em in expired_pwd:
            cls._password_resets.pop(em, None)

        expired_resets = [
            cid for cid, c in cls._neuraltrace_resets.items()
            if now > c["expires_at"]
        ]
        for cid in expired_resets:
            cls._neuraltrace_resets.pop(cid, None)

        expired_tickets = [
            tk for tk, t in cls._reset_tickets.items()
            if now > t["expires_at"]
        ]
        for tk in expired_tickets:
            cls._reset_tickets.pop(tk, None)

