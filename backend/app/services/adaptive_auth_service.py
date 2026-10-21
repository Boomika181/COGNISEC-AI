import json
import logging
import secrets
import bcrypt
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from app.models.adaptive_factor import AdaptiveFactor
from app.models.security_event import SecurityEvent
from app.models.user import User

logger = logging.getLogger(__name__)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# Documented, stable 3x3 cognitive symbol image catalogue
COGNITIVE_CATALOGUE: List[Dict[str, str]] = [
    {"id": "img_shield", "label": "Security Shield", "icon": "🛡️", "category": "defense"},
    {"id": "img_key", "label": "Cryptographic Key", "icon": "🔑", "category": "access"},
    {"id": "img_lock", "label": "Security Padlock", "icon": "🔒", "category": "access"},
    {"id": "img_radar", "label": "Threat Radar", "icon": "📡", "category": "monitoring"},
    {"id": "img_vault", "label": "Secure Vault", "icon": "🏛️", "category": "storage"},
    {"id": "img_biometric", "label": "Biometric Scanner", "icon": "🧬", "category": "identity"},
    {"id": "img_firewall", "label": "Perimeter Firewall", "icon": "🧱", "category": "defense"},
    {"id": "img_token", "label": "Hardware Token", "icon": "🪙", "category": "hardware"},
    {"id": "img_chip", "label": "Secure Enclave", "icon": "💾", "category": "hardware"},
]

CATALOGUE_IDS = {item["id"] for item in COGNITIVE_CATALOGUE}


# 14-Node Canonical NeuralTrace Graph Topology (Nodes 0..13, Undirected Edges)
NEURALTRACE_EDGES = {
    # Layer 0 internal
    (0, 1), (1, 0), (1, 2), (2, 1),
    # Layer 0 to Layer 1
    (0, 3), (3, 0), (0, 4), (4, 0),
    (1, 3), (3, 1), (1, 4), (4, 1), (1, 5), (5, 1),
    (2, 5), (5, 2), (2, 6), (6, 2),
    # Layer 1 internal
    (3, 4), (4, 3), (4, 5), (5, 4), (5, 6), (6, 5),
    # Layer 1 to Layer 2
    (3, 7), (7, 3), (3, 8), (8, 3),
    (4, 7), (7, 4), (4, 8), (8, 4), (4, 9), (9, 4),
    (5, 8), (8, 5), (5, 9), (9, 5), (5, 10), (10, 5),
    (6, 9), (9, 6), (6, 10), (10, 6),
    # Layer 2 internal
    (7, 8), (8, 7), (8, 9), (9, 8), (9, 10), (10, 9),
    # Layer 2 to Layer 3
    (7, 11), (11, 7), (7, 12), (12, 7),
    (8, 11), (11, 8), (8, 12), (12, 8), (8, 13), (13, 8),
    (9, 11), (11, 9), (9, 12), (12, 9), (9, 13), (13, 9),
    (10, 12), (12, 10), (10, 13), (13, 10),
    # Layer 3 internal
    (11, 12), (12, 11), (12, 13), (13, 12)
}


class AdaptiveAuthService:
    """
    Adaptive Multi-Factor Authentication Service.
    Enforces privacy-preserving factor enrollment and constant-time verifier matching.
    Never persists raw gesture traces, answers, or plaintext sequences.
    """

    @classmethod
    def get_catalogue(cls) -> List[Dict[str, str]]:
        """Returns the public cognitive symbol image catalogue."""
        return COGNITIVE_CATALOGUE

    @classmethod
    def get_enrollment_status(cls, db: Session, user_id: int) -> Dict[str, Any]:
        """
        Inspects enrolled factors for a user.
        Never exposes verifiers, answers, or secret patterns.
        """
        factors = db.query(AdaptiveFactor).filter(AdaptiveFactor.user_id == user_id).all()
        factor_map = {f.factor_type: f for f in factors}

        private_question = None
        if "PRIVATE_RESPONSE" in factor_map:
            try:
                meta = json.loads(factor_map["PRIVATE_RESPONSE"].metadata_json or "{}")
                private_question = meta.get("question")
            except Exception:
                private_question = "Security Verification Question"

        return {
            "user_id": user_id,
            "has_gesture_pattern": "GESTURE_PATTERN" in factor_map,
            "has_cognitive_image_sequence": "COGNITIVE_IMAGE_SEQUENCE" in factor_map,
            "has_private_response": "PRIVATE_RESPONSE" in factor_map,
            "private_question": private_question,
        }

    @classmethod
    def get_factor(cls, db: Session, user_id: int, factor_type: str) -> Optional[AdaptiveFactor]:
        """Retrieves an enrolled factor record."""
        return db.query(AdaptiveFactor).filter(
            AdaptiveFactor.user_id == user_id,
            AdaptiveFactor.factor_type == factor_type.upper()
        ).first()

    @classmethod
    def enroll_gesture_pattern(
        cls,
        db: Session,
        user_id: int,
        pattern: List[int],
        confirm_pattern: List[int]
    ) -> Dict[str, Any]:
        """
        Enrolls a NeuralTrace signal route (and maintains backward compatibility with 3x3 gestures).
        - Minimum length: 4 nodes
        - Maximum length: 16 nodes
        - Valid node indices: 0..15 (NeuralTrace uses 0..13)
        - Validates graph edge connections for network routes
        - No adjacent duplicates
        - Stores only salted bcrypt verifier hash
        """
        if not pattern or not confirm_pattern:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Gesture pattern and confirmation are required."
            )

        if pattern != confirm_pattern:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Gesture pattern confirmation does not match original pattern."
            )

        if len(pattern) < 4:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Gesture pattern must connect at least 4 nodes for security."
            )

        if len(pattern) > 16:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Gesture pattern cannot exceed 16 nodes."
            )

        for idx, node in enumerate(pattern):
            if not isinstance(node, int) or node < 0 or node > 15:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid node index {node}. Nodes must be integers from 0 to 15."
                )
            if idx > 0 and node == pattern[idx - 1]:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Gesture pattern cannot contain consecutive duplicate nodes."
                )

        # Enforce valid network edge traversal for NeuralTrace routes
        if any(n > 8 for n in pattern):
            for idx in range(1, len(pattern)):
                edge = (pattern[idx - 1], pattern[idx])
                if edge not in NEURALTRACE_EDGES:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Invalid network route: nodes {edge[0]} and {edge[1]} are not connected by an active network edge."
                    )

        canonical = "-".join(map(str, pattern))
        salt = bcrypt.gensalt()
        verifier_hash = bcrypt.hashpw(canonical.encode("utf-8"), salt).decode("utf-8")

        factor = cls.get_factor(db, user_id, "GESTURE_PATTERN")
        meta = json.dumps({"node_count": len(pattern), "factor_name": "NEURALTRACE"})
        if not factor:
            factor = AdaptiveFactor(
                user_id=user_id,
                factor_type="GESTURE_PATTERN",
                verifier_hash=verifier_hash,
                metadata_json=meta,
                created_at=utc_now()
            )
            db.add(factor)
        else:
            factor.verifier_hash = verifier_hash
            factor.metadata_json = meta
            factor.created_at = utc_now()

        db.commit()
        db.refresh(factor)

        return {
            "success": True,
            "factor_type": "GESTURE_PATTERN",
            "message": "NeuralTrace signal route successfully enrolled and protected."
        }

    @classmethod
    def enroll_image_sequence(
        cls,
        db: Session,
        user_id: int,
        image_sequence: List[str],
        confirm_image_sequence: List[str]
    ) -> Dict[str, Any]:
        """
        Enrolls a cognitive image sequence from the fixed catalogue.
        - Length: 3 to 5 images
        - All image IDs must belong to catalogue
        - Stores only salted bcrypt hash
        """
        if not image_sequence or not confirm_image_sequence:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Image sequence and confirmation are required."
            )

        if image_sequence != confirm_image_sequence:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Image sequence confirmation does not match original sequence."
            )

        if len(image_sequence) < 3 or len(image_sequence) > 5:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Image sequence must contain between 3 and 5 items."
            )

        if len(set(image_sequence)) != len(image_sequence):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Image sequence cannot contain duplicate symbols."
            )

        for img_id in image_sequence:
            if img_id not in CATALOGUE_IDS:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid image identifier '{img_id}'. Must belong to catalogue."
                )

        canonical = "|".join(image_sequence)
        salt = bcrypt.gensalt()
        verifier_hash = bcrypt.hashpw(canonical.encode("utf-8"), salt).decode("utf-8")

        factor = cls.get_factor(db, user_id, "COGNITIVE_IMAGE_SEQUENCE")
        if not factor:
            factor = AdaptiveFactor(
                user_id=user_id,
                factor_type="COGNITIVE_IMAGE_SEQUENCE",
                verifier_hash=verifier_hash,
                metadata_json=json.dumps({"sequence_length": len(image_sequence)}),
                created_at=utc_now()
            )
            db.add(factor)
        else:
            factor.verifier_hash = verifier_hash
            factor.metadata_json = json.dumps({"sequence_length": len(image_sequence)})
            factor.created_at = utc_now()

        db.commit()
        db.refresh(factor)

        return {
            "success": True,
            "factor_type": "COGNITIVE_IMAGE_SEQUENCE",
            "message": "Cognitive image sequence successfully enrolled and protected."
        }

    @classmethod
    def enroll_private_response(
        cls,
        db: Session,
        user_id: int,
        question: str,
        response: str,
        confirm_response: str
    ) -> Dict[str, Any]:
        """
        Enrolls a user-defined private response challenge.
        - Question: 5..200 chars
        - Response: 3..100 chars, normalized
        - Stores only salted bcrypt hash; stores question prompt in metadata
        """
        clean_q = (question or "").strip()
        clean_r = (response or "").strip()
        clean_cr = (confirm_response or "").strip()

        if len(clean_q) < 5 or len(clean_q) > 200:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Question prompt must be between 5 and 200 characters."
            )

        if len(clean_r) < 3 or len(clean_r) > 100:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Response answer must be between 3 and 100 characters."
            )

        if clean_r != clean_cr:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Answer confirmation does not match original answer."
            )

        # Consistent normalization: lowercase, collapse duplicate whitespace
        normalized = " ".join(clean_r.lower().split())
        salt = bcrypt.gensalt()
        verifier_hash = bcrypt.hashpw(normalized.encode("utf-8"), salt).decode("utf-8")

        factor = cls.get_factor(db, user_id, "PRIVATE_RESPONSE")
        if not factor:
            factor = AdaptiveFactor(
                user_id=user_id,
                factor_type="PRIVATE_RESPONSE",
                verifier_hash=verifier_hash,
                metadata_json=json.dumps({"question": clean_q}),
                created_at=utc_now()
            )
            db.add(factor)
        else:
            factor.verifier_hash = verifier_hash
            factor.metadata_json = json.dumps({"question": clean_q})
            factor.created_at = utc_now()

        db.commit()
        db.refresh(factor)

        return {
            "success": True,
            "factor_type": "PRIVATE_RESPONSE",
            "message": "Private response challenge successfully enrolled and protected."
        }

    @classmethod
    def verify_enrolled_factor(
        cls,
        db: Session,
        user_id: int,
        factor_type: str,
        challenge_code: Optional[str] = None,
        gesture_pattern: Optional[List[int]] = None,
        image_sequence: Optional[List[str]] = None,
        private_response: Optional[str] = None
    ) -> bool:
        """
        Verifies client submission against enrolled verifier hash.
        Returns True if match, False otherwise.
        """
        factor = cls.get_factor(db, user_id, factor_type)
        if not factor or not factor.verifier_hash:
            return False

        try:
            if factor_type == "GESTURE_PATTERN":
                if not gesture_pattern:
                    return False
                canonical = "-".join(map(str, gesture_pattern))
                return bcrypt.checkpw(canonical.encode("utf-8"), factor.verifier_hash.encode("utf-8"))

            elif factor_type == "COGNITIVE_IMAGE_SEQUENCE":
                if not image_sequence:
                    return False
                canonical = "|".join(image_sequence)
                return bcrypt.checkpw(canonical.encode("utf-8"), factor.verifier_hash.encode("utf-8"))

            elif factor_type == "PRIVATE_RESPONSE":
                if not private_response:
                    return False
                normalized = " ".join(private_response.strip().lower().split())
                return bcrypt.checkpw(normalized.encode("utf-8"), factor.verifier_hash.encode("utf-8"))

            return False
        except Exception:
            return False

    @classmethod
    def request_neuraltrace_reset(cls, db: Session, user: User) -> Dict[str, Any]:
        """
        Initiates re-authentication workflow to reset the user's NeuralTrace factor.
        - Generates a single-use 6-digit OTP.
        - Sends it to the authenticated user's canonical registered email address.
        - Stores challenge in StepUpService._neuraltrace_resets.
        - Never reveals OTP in response or server logs.
        """
        from app.services.email_service import EmailService
        from app.services.step_up_service import StepUpService

        otp = f"{secrets.randbelow(1000000):06d}"
        challenge_id = StepUpService.create_neuraltrace_reset_challenge(
            user_id=user.id,
            otp=otp,
            ttl_seconds=600
        )

        masked_email = EmailService.mask_email(user.email)
        subject = "COGNISEC-AI: NeuralTrace Reset Verification Code"
        body_text = (
            f"Hello {user.name},\n\n"
            f"A request was received to reset your NeuralTrace route for your COGNISEC-AI account.\n\n"
            f"Your single-use 6-digit re-authentication code is: {otp}\n\n"
            f"This code will expire in 10 minutes. If you did not initiate this reset, your account is safe; "
            f"your existing NeuralTrace route remains active and protected.\n\n"
            f"— COGNISEC-AI Zero-Trust Security"
        )
        body_html = f"""
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 540px; margin: 0 auto; padding: 24px; background: #0c0714; border: 1px solid #7f1d1d; border-radius: 16px; color: #f8fafc;">
          <h2 style="color: #ef4444; margin-top: 0;">🛡️ COGNISEC-AI SECURITY ALERT</h2>
          <p style="color: #cbd5e1; font-size: 14px;">A request to reset your enrolled <strong>NeuralTrace Signal Route</strong> was initiated.</p>
          <div style="background: #180928; border: 1px solid #991b1b; border-radius: 12px; padding: 18px; margin: 20px 0; text-align: center;">
            <span style="font-size: 11px; font-family: monospace; color: #fca5a5; letter-spacing: 1px; display: block; margin-bottom: 8px;">SINGLE-USE RESET VERIFICATION CODE</span>
            <strong style="font-size: 32px; letter-spacing: 8px; font-family: monospace; color: #ffffff;">{otp}</strong>
          </div>
          <p style="color: #94a3b8; font-size: 12px; line-height: 1.5;">This verification code is valid for 10 minutes. Enter this code on your security dashboard to draw and confirm your new route. If you did not request this, your existing route remains active and untouched.</p>
        </div>
        """

        try:
            EmailService.send_email(
                recipient_email=user.email,
                subject=subject,
                plain_text=body_text,
                html_text=body_html
            )
        except Exception as e:
            logger.warning(f"[NeuralTraceReset] Email delivery notice: {e}")

        logger.info(f"[NeuralTraceReset] Dispatched reset OTP to {masked_email} for user_id={user.id}")

        return {
            "success": True,
            "reset_challenge_id": challenge_id,
            "message": f"Verification code dispatched to {masked_email}.",
            "masked_email": masked_email
        }

    @classmethod
    def verify_neuraltrace_reset(
        cls,
        user_id: int,
        reset_challenge_id: str,
        otp: str
    ) -> Dict[str, Any]:
        """
        Validates the 6-digit recovery OTP for resetting NeuralTrace.
        If valid, issues a scoped reset ticket.
        If invalid, preserves existing enrollment and returns error.
        """
        from app.services.step_up_service import StepUpService

        success, ticket, message = StepUpService.verify_neuraltrace_reset_challenge(
            user_id=user_id,
            challenge_id=reset_challenge_id,
            otp=otp,
            ticket_ttl_seconds=600
        )
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=message
            )
        return {
            "success": True,
            "reset_ticket": ticket,
            "message": message
        }

    @classmethod
    def confirm_neuraltrace_reset(
        cls,
        db: Session,
        user_id: int,
        reset_ticket: str,
        pattern: List[int],
        confirm_pattern: List[int]
    ) -> Dict[str, Any]:
        """
        Enrolls the new route following successful recovery verification:
        1. Validates and consumes single-use reset ticket.
        2. Validates pattern and confirmation match, min 4 nodes, valid network edges.
        3. Updates AdaptiveFactor verifier_hash with new bcrypt salt.
        4. Invalidates old NeuralTrace challenges and pending verification attempts.
        5. Records SecurityEvent audit log (never logging the raw route).
        """
        from app.services.step_up_service import StepUpService

        valid_ticket = StepUpService.validate_neuraltrace_reset_ticket(user_id, reset_ticket)
        if not valid_ticket:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid, expired, or already-used reset ticket. Please complete identity verification again."
            )

        # Enroll the new pattern (validates length, edges, duplicates, confirmation)
        cls.enroll_gesture_pattern(
            db=db,
            user_id=user_id,
            pattern=pattern,
            confirm_pattern=confirm_pattern
        )

        # Consume ticket upon successful enrollment to prevent replays
        StepUpService.consume_neuraltrace_reset_ticket(user_id, reset_ticket)

        # Invalidate old NeuralTrace challenges and pending verification attempts
        StepUpService.invalidate_user_challenges(user_id=user_id, factor_type="GESTURE_PATTERN")

        # Record audit event without logging the secret route
        now_utc = utc_now()
        audit_event = SecurityEvent(
            user_id=user_id,
            application="platform",
            event_type="NEURALTRACE_RESET",
            severity="LOW",
            decision="ALLOW",
            details="NeuralTrace signal route successfully reset following verified email re-authentication.",
            timestamp=now_utc
        )
        db.add(audit_event)
        db.commit()

        logger.info(f"[NeuralTraceReset] Successfully reset NeuralTrace route for user_id={user_id}. Old challenges invalidated.")

        return {
            "success": True,
            "factor_type": "GESTURE_PATTERN",
            "message": "NeuralTrace route successfully updated and old verification attempts invalidated."
        }

