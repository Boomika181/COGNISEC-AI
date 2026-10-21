import hmac
import hashlib
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

    _lock = threading.Lock()
    _challenges: Dict[str, Dict[str, Any]] = {}  # keyed by session_id
    _password_resets: Dict[str, Dict[str, Any]] = {}  # keyed by normalized email
    _neuraltrace_resets: Dict[str, Dict[str, Any]] = {}  # keyed by challenge_id
    _reset_tickets: Dict[str, Dict[str, Any]] = {}  # keyed by ticket_token

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
            for k in list(cls._challenges.keys()):
                if k.startswith(f"{session_id}:") or k == session_id:
                    cls._challenges.pop(k, None)

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
        resource: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Policy-driven Adaptive Challenge Generator.
        Maps risk context to factor complexity:
        - Critical risk (>= 0.85): TERMINATED (Prohibited)
        - High risk (0.65 <= risk < 0.85): HIGH_RISK_DUAL (Requires BOTH Image Sequence AND Private Response)
        - Moderate risk (0.50 <= risk < 0.65): GESTURE_PATTERN (if enrolled; else Email OTP)
        - Mild deviation (0.30 <= risk < 0.50): Email OTP
        Enforces that the client cannot choose a weaker factor than required by risk.
        Binds challenge strictly to application and resource.
        """
        from app.services.session_service import SessionService
        norm_app = SessionService.normalize_application(application)
        norm_res = SessionService.normalize_resource(resource) if resource else SessionService.get_resource_for_application(norm_app)
        if not norm_app and norm_res:
            norm_app = SessionService.get_application_for_resource(norm_res)
        if not norm_res and norm_app:
            norm_res = SessionService.get_resource_for_application(norm_app)

        with cls._lock:
            cls._cleanup_expired()

            # Guard against challenge creation on Critical risk
            if risk_level == "CRITICAL" or risk_score >= settings.RISK_THRESHOLD_HIGH:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot issue challenge: Session terminated due to critical security risk."
                )

            enrollment = AdaptiveAuthService.get_enrollment_status(db, user_id)
            selected_type = "OTP"
            prompt = None
            catalogue = None
            min_len = None

            # 1. Determine factor type based on authoritative policy mapping
            if risk_level == "HIGH" or risk_score >= settings.RISK_THRESHOLD_MEDIUM:
                # High risk: Strong compound cognitive verification required
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

            elif risk_level == "MEDIUM" or risk_score >= 0.50:
                # Moderate risk (0.50 <= risk < 0.65): Gesture pattern preferred (fallback to Email OTP if unenrolled)
                if preferred_factor and preferred_factor.upper() == "GESTURE_PATTERN":
                    if not enrollment.get("has_gesture_pattern"):
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail=NEURALTRACE_NOT_ENROLLED_DETAIL
                        )
                    selected_type = "GESTURE_PATTERN"
                    min_len = 4
                elif enrollment.get("has_gesture_pattern", False):
                    selected_type = "GESTURE_PATTERN"
                    min_len = 4
                else:
                    selected_type = "OTP"

            else:
                # Mild deviation (risk < 0.50) or user-initiated step-up
                if preferred_factor and preferred_factor.upper() in [
                    "GESTURE_PATTERN", "COGNITIVE_IMAGE_SEQUENCE", "PRIVATE_RESPONSE", "HIGH_RISK_DUAL"
                ]:
                    pref = preferred_factor.upper()
                    if pref == "GESTURE_PATTERN":
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
            ):
                user = db.query(User).filter(User.id == user_id).first()
                masked_email = EmailService.mask_email(user.email) if user and user.email else None
                return_otp = existing.get("otp", "") if (settings.EXHIBITION_MODE or settings.ENVIRONMENT in ("test", "testing")) else ""
                return {
                    "challenge_id": existing["challenge_id"],
                    "session_id": session_id,
                    "application": existing.get("application"),
                    "resource": existing.get("resource"),
                    "otp": return_otp,
                    "challenge_type": existing["challenge_type"],
                    "expires_in_seconds": int((existing["expires_at"] - now).total_seconds()),
                    "delivery_status": "SENT",
                    "message": f"Step-up verification code sent to {masked_email or 'registered email'}.",
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
                user_email = user.email
                masked_email = EmailService.mask_email(user_email)

                # Out-of-band email dispatch
                delivery_status = "PENDING"
                email_ok, email_msg = EmailService.send_otp_email(
                    recipient_email=user_email,
                    otp_code=otp_val,
                    expires_in_minutes=ttl_seconds // 60,
                    challenge_id=challenge_id
                )
                if email_ok:
                    delivery_status = "SENT"
                else:
                    if "not configured" in email_msg or "disabled" in email_msg:
                        delivery_status = "SKIPPED_UNCONFIGURED"
                    else:
                        delivery_status = "FAILED"

                    if not settings.EXHIBITION_MODE:
                        raise HTTPException(
                            status_code=status.HTTP_502_BAD_GATEWAY,
                            detail=f"Email OTP transmission failed: {email_msg}"
                        )

            # Purge any previous challenges for this session/application so resend strictly invalidates them
            to_purge = [
                c for c in list(cls._challenges.values())
                if c.get("session_id") == session_id and (not norm_app or c.get("application") == norm_app)
            ]
            for c in to_purge:
                cls._delete_challenge(c)

            # Store challenge in memory verifier (resend invalidates previous challenge)
            challenge_payload = {
                "challenge_id": challenge_id,
                "session_id": session_id,
                "user_id": user_id,
                "application": norm_app or None,
                "resource": norm_res or None,
                "challenge_type": selected_type,
                "otp_hash": otp_hash,
                "otp": otp_val if settings.EXHIBITION_MODE else "",  # Only stored if exhibition mode
                "prompt": prompt,
                "created_at": now,
                "expires_at": expires_at,
                "attempts": 0,
                "max_attempts": cls.MAX_ATTEMPTS,
                "stage": 1,
                "stage_1_passed": False,
                "completed": False,
            }
            cls._challenges[chal_key] = challenge_payload
            cls._challenges[challenge_id] = challenge_payload
            if chal_key != session_id:
                cls._challenges[session_id] = challenge_payload

            msg_map = {
                "OTP": f"Step-up verification code sent to {masked_email or 'registered email'}.",
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

            return {
                "challenge_id": challenge_id,
                "session_id": session_id,
                "application": norm_app or None,
                "resource": norm_res or None,
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
                "is_demo_otp": is_demo
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
        stage: Optional[int] = 1
    ) -> Tuple[bool, str, bool, Optional[Dict[str, Any]]]:
        """
        Verifies adaptive multi-factor challenge submission with sequential stage support.
        Enforces user binding, session binding, and application-specific challenge binding.
        Returns:
            (success: bool, message: str, is_locked: bool, details: Optional[Dict[str, Any]])
        """
        with cls._lock:
            cls._cleanup_expired()

            from app.services.session_service import SessionService
            norm_app = SessionService.normalize_application(application)
            norm_res = SessionService.normalize_resource(resource) if resource else None

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
            max_attempts = challenge.get("max_attempts", cls.MAX_ATTEMPTS)

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
                    cls._delete_challenge(challenge)
                    return (True, "Identity step-up verified. Full access restored.", False, {"completed": True})

                challenge["attempts"] += 1
                if challenge["attempts"] >= max_attempts:
                    cls._delete_challenge(challenge)
                    return (False, f"Maximum challenge attempts ({max_attempts}) exceeded. Session locked.", True, None)
                remaining = max_attempts - challenge["attempts"]
                return (False, f"Invalid verification. {remaining} attempt{'s' if remaining != 1 else ''} remaining.", False, None)

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
                    cls._delete_challenge(challenge)
                    return (True, "Identity step-up verified. Full access restored.", False, {"completed": True})

                challenge["attempts"] += 1
                if challenge["attempts"] >= max_attempts:
                    cls._delete_challenge(challenge)
                    return (False, f"Maximum challenge attempts ({max_attempts}) exceeded. Session locked.", True, None)
                remaining = max_attempts - challenge["attempts"]
                return (False, f"Invalid verification. {remaining} attempt{'s' if remaining != 1 else ''} remaining.", False, None)

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
                    cls._delete_challenge(challenge)
                    return (True, "Identity step-up verified. Full access restored.", False, {"completed": True})

                challenge["attempts"] += 1
                if challenge["attempts"] >= max_attempts:
                    cls._delete_challenge(challenge)
                    return (False, f"Maximum challenge attempts ({max_attempts}) exceeded. Session locked.", True, None)
                remaining = max_attempts - challenge["attempts"]
                return (False, f"Invalid verification. {remaining} attempt{'s' if remaining != 1 else ''} remaining.", False, None)

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
                    cls._delete_challenge(challenge)
                    return (True, "Identity step-up verified. Full access restored.", False, {"completed": True})

                challenge["attempts"] += 1
                if challenge["attempts"] >= max_attempts:
                    cls._delete_challenge(challenge)
                    return (False, f"Maximum challenge attempts ({max_attempts}) exceeded. Session locked.", True, None)
                remaining = max_attempts - challenge["attempts"]
                return (False, f"Invalid verification. {remaining} attempt{'s' if remaining != 1 else ''} remaining.", False, None)

            elif actual_type == "HIGH_RISK_DUAL":
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
                        cid = challenge.get("challenge_id")
                        cls._delete_challenge(challenge)
                        return (True, "Identity step-up verified. Full access restored.", False, {"stage": 2, "stage_1_passed": True, "completed": True, "challenge_id": cid})
                    else:
                        challenge["attempts"] += 1
                        if challenge["attempts"] >= max_attempts:
                            cls._delete_challenge(challenge)
                            return (False, f"Maximum challenge attempts ({max_attempts}) exceeded. Session locked.", True, None)
                        remaining = max_attempts - challenge["attempts"]
                        return (False, f"Invalid verification. {remaining} attempt{'s' if remaining != 1 else ''} remaining.", False, None)

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
                        challenge["attempts"] += 1
                        if challenge["attempts"] >= max_attempts:
                            cls._delete_challenge(challenge)
                            return (False, f"Maximum challenge attempts ({max_attempts}) exceeded. Session locked.", True, None)
                        return (False, "Valid cognitive image sequence of at least 3 symbols required for Stage 1.", False, None)

                    img_valid = AdaptiveAuthService.verify_enrolled_factor(
                        db=db,
                        user_id=user_id,
                        factor_type="COGNITIVE_IMAGE_SEQUENCE",
                        image_sequence=image_sequence
                    )
                    if not img_valid:
                        challenge["attempts"] += 1
                        if challenge["attempts"] >= max_attempts:
                            cls._delete_challenge(challenge)
                            return (False, f"Maximum challenge attempts ({max_attempts}) exceeded. Session locked.", True, None)
                        remaining = max_attempts - challenge["attempts"]
                        return (False, f"Invalid cognitive image sequence. {remaining} attempt{'s' if remaining != 1 else ''} remaining.", False, None)

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
                        challenge["attempts"] += 1
                        if challenge["attempts"] >= max_attempts:
                            cls._delete_challenge(challenge)
                            return (False, f"Maximum challenge attempts ({max_attempts}) exceeded. Session locked.", True, None)
                        return (
                            False,
                            "Out of order: Stage 1 (Cognitive Image Sequence) must be completed and verified before Stage 2.",
                            False,
                            None
                        )

                    if not private_response or not str(private_response).strip():
                        challenge["attempts"] += 1
                        if challenge["attempts"] >= max_attempts:
                            cls._delete_challenge(challenge)
                            return (False, f"Maximum challenge attempts ({max_attempts}) exceeded. Session locked.", True, None)
                        return (False, "Private security response is required for Stage 2.", False, None)

                    priv_valid = AdaptiveAuthService.verify_enrolled_factor(
                        db=db,
                        user_id=user_id,
                        factor_type="PRIVATE_RESPONSE",
                        private_response=str(private_response).strip()
                    )
                    if not priv_valid:
                        challenge["attempts"] += 1
                        if challenge["attempts"] >= max_attempts:
                            cls._delete_challenge(challenge)
                            return (False, f"Maximum challenge attempts ({max_attempts}) exceeded. Session locked.", True, None)
                        remaining = max_attempts - challenge["attempts"]
                        return (False, f"Invalid private response. {remaining} attempt{'s' if remaining != 1 else ''} remaining.", False, None)

                    # Stage 2 succeeds: consume and delete challenge immediately (single use / replay protection)
                    cid = challenge.get("challenge_id")
                    cls._delete_challenge(challenge)
                    return (
                        True,
                        "Identity step-up verified. Full access restored.",
                        False,
                        {
                            "stage": 2,
                            "stage_1_passed": True,
                            "completed": True,
                            "challenge_id": cid
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

        session = db.query(DbSession).filter(DbSession.id == session_id).first()
        if not session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found."
            )

        if session.status == "TERMINATED":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot issue challenge for a terminated session. Please sign in again."
            )

        if session.status == "ACTIVE":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Session is already authenticated and active."
            )

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
                user_email = user.email
                masked_email = EmailService.mask_email(user_email)
                return_otp = existing.get("otp", "") if (settings.EXHIBITION_MODE or settings.ENVIRONMENT in ("test", "testing")) else ""
                return {
                    "challenge_id": existing["challenge_id"],
                    "session_id": session_id,
                    "challenge_type": "LOGIN_OTP",
                    "masked_email": masked_email,
                    "expires_in_seconds": int((existing["expires_at"] - now).total_seconds()),
                    "message": f"Verification code sent to {masked_email}.",
                    "otp": return_otp,
                    "is_demo_otp": bool(settings.EXHIBITION_MODE)
                }

        user = db.query(User).filter(User.id == user_id).first()
        if not user or not user.email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Authenticated user account does not have a registered email address."
            )
        user_email = user.email
        masked_email = EmailService.mask_email(user_email)

        otp_val = f"{secrets.randbelow(1000000):06d}"
        otp_hash = cls._hash_otp(otp_val)
        challenge_id = f"chal_login_{secrets.token_hex(8)}"
        expires_at = now + timedelta(seconds=ttl_seconds)

        # Dispatch via SMTP without holding threading lock
        email_ok, email_msg = EmailService.send_otp_email(
            recipient_email=user_email,
            otp_code=otp_val,
            expires_in_minutes=ttl_seconds // 60,
            challenge_id=challenge_id
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
                "attempts": 0,
                "max_attempts": cls.MAX_ATTEMPTS,
            }

        return {
            "challenge_id": challenge_id,
            "session_id": session_id,
            "challenge_type": "LOGIN_OTP",
            "masked_email": masked_email,
            "expires_in_seconds": ttl_seconds,
            "message": f"Verification code sent to {masked_email}.",
            "otp": return_otp,
            "is_demo_otp": bool(settings.EXHIBITION_MODE)
        }

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

        session = db.query(DbSession).filter(DbSession.id == session_id).first()
        if not session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found."
            )

        if session.status == "TERMINATED":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot resend code for a terminated session. Please sign in again."
            )

        if session.status == "ACTIVE":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Session is already authenticated and active."
            )

        # Invalidate previous challenge atomically
        with cls._lock:
            cls._challenges.pop(session_id, None)

        user = db.query(User).filter(User.id == user_id).first()
        if not user or not user.email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Authenticated user account does not have a registered email address."
            )
        user_email = user.email
        masked_email = EmailService.mask_email(user_email)

        otp_val = f"{secrets.randbelow(1000000):06d}"
        otp_hash = cls._hash_otp(otp_val)
        challenge_id = f"chal_login_{secrets.token_hex(8)}"
        now = utc_now()
        expires_at = now + timedelta(seconds=ttl_seconds)

        email_ok, email_msg = EmailService.send_otp_email(
            recipient_email=user_email,
            otp_code=otp_val,
            expires_in_minutes=ttl_seconds // 60,
            challenge_id=challenge_id
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
                "attempts": 0,
                "max_attempts": cls.MAX_ATTEMPTS,
            }

        session.login_otp_challenge_id = challenge_id
        db.commit()

        return {
            "challenge_id": challenge_id,
            "session_id": session_id,
            "challenge_type": "LOGIN_OTP",
            "masked_email": masked_email,
            "expires_in_seconds": ttl_seconds,
            "message": f"Verification code sent to {masked_email}.",
            "otp": return_otp,
            "is_demo_otp": bool(settings.EXHIBITION_MODE)
        }

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
        If correct: marks challenge used and activates session.
        If incorrect: invalidates challenge, terminates session immediately, requires fresh login.
        """
        from app.services.session_service import SessionService
        with cls._lock:
            cls._cleanup_expired()

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
                SessionService.activate_session_after_login_otp(db, session_id, challenge.get("challenge_id"))
                return (True, "Login verification successful. Full access granted.")

            # Incorrect OTP: consume challenge, terminate pending session immediately
            cls._challenges.pop(session_id, None)
            SessionService.terminate_session_failed_otp(db, session_id)
            return (
                False,
                "Invalid verification code. For your security, this pending login session has been terminated. Please sign in again."
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
    def reset(cls):
        """Reset all challenges (used for test isolation)."""
        with cls._lock:
            cls._challenges.clear()
            cls._password_resets.clear()
            cls._neuraltrace_resets.clear()
            cls._reset_tickets.clear()

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
    ) -> Tuple[bool, str, str]:
        """
        Generates and delivers a secure 6-digit OTP for account password recovery.
        Resolves account strictly from verified database record.
        """
        norm_email = email.lower().strip()
        from app.services.auth_service import AuthService
        user = AuthService.get_user_by_email(db, norm_email)
        if not user:
            # Anti-enumeration response
            masked = EmailService.mask_email(norm_email)
            return (True, f"If this account is registered, a verification code has been sent to {masked}.", masked)

        masked_email = EmailService.mask_email(user.email)
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
                return (True, f"Verification code sent to {masked_email}.", masked_email)

            cls._password_resets[norm_email] = {
                "user_id": user.id,
                "email": user.email,
                "otp_hash": otp_hash,
                "created_at": now,
                "expires_at": expires_at,
                "attempts": 0,
                "max_attempts": cls.MAX_ATTEMPTS
            }

        # Send via EmailService using dedicated password reset template
        email_ok, email_msg = EmailService.send_password_reset_email(
            recipient_email=user.email,
            otp_code=otp,
            expires_in_minutes=ttl_seconds // 60
        )
        if not email_ok and not settings.EXHIBITION_MODE:
            with cls._lock:
                cls._password_resets.pop(norm_email, None)
            safe_err = "Email delivery failed: unable to dispatch verification code."
            if "timed out" in email_msg.lower():
                safe_err = "Email delivery failed: connection timed out."
            elif "rejected" in email_msg.lower():
                safe_err = f"Email delivery failed: {email_msg}"
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=safe_err
            )

        return (True, f"Verification code sent to {masked_email}.", masked_email)

    @classmethod
    def resend_password_reset_challenge(
        cls,
        email: str,
        db: Session,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        cooldown_seconds: int = 30
    ) -> Tuple[bool, str, str, int]:
        """
        Resends password recovery OTP to registered email.
        Enforces cooldown, supersedes previous OTP, and returns delivery status.
        Returns: (success, message, masked_email, retry_after)
        """
        norm_email = email.lower().strip()
        from app.services.auth_service import AuthService
        user = AuthService.get_user_by_email(db, norm_email)
        masked = EmailService.mask_email(norm_email)
        if not user:
            # Anti-enumeration response: preserve identical format
            return (True, f"If this account is registered, a verification code has been sent to {masked}.", masked, cooldown_seconds)

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
                    return (False, f"Please wait {remaining} second{'s' if remaining != 1 else ''} before requesting a new code.", masked_email, remaining)

            # Generate fresh 6-digit OTP and supersede any prior challenge
            otp = f"{secrets.randbelow(1000000):06d}"
            otp_hash = cls._hash_otp(otp)
            expires_at = now + timedelta(seconds=ttl_seconds)

            cls._password_resets[norm_email] = {
                "user_id": user.id,
                "email": user.email,
                "otp_hash": otp_hash,
                "created_at": now,
                "expires_at": expires_at,
                "attempts": 0,
                "max_attempts": cls.MAX_ATTEMPTS
            }

        # Dispatch via EmailService
        email_ok, email_msg = EmailService.send_password_reset_email(
            recipient_email=user.email,
            otp_code=otp,
            expires_in_minutes=ttl_seconds // 60
        )
        if not email_ok and not settings.EXHIBITION_MODE:
            with cls._lock:
                cls._password_resets.pop(norm_email, None)
            safe_err = "Email delivery failed: unable to dispatch verification code."
            if "timed out" in email_msg.lower():
                safe_err = "Email delivery failed: connection timed out."
            elif "rejected" in email_msg.lower():
                safe_err = f"Email delivery failed: {email_msg}"
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=safe_err
            )

        logger.info(f"[COGNISEC-AI] [PASSWORD_RESET_RESEND] Successfully dispatched fresh reset OTP to {masked_email}.")
        return (True, f"A new verification code has been dispatched to {masked_email}.", masked_email, cooldown_seconds)

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

