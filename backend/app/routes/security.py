import datetime
import logging
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Response

logger = logging.getLogger(__name__)
from sqlalchemy.orm import Session
from app.core.config import settings
from app.database.connection import get_db
from app.schemas.security import (
    RiskEvaluationRequest,
    SecurityDecisionResponse,
    StepUpChallengeRequest,
    StepUpChallengeResponse,
    StepUpVerifyRequest,
    UserSecurityOutcome,
    CatalogueItem,
    MfaEnrollmentStatusResponse,
    GestureEnrollRequest,
    ImageSequenceEnrollRequest,
    PrivateResponseEnrollRequest,
    MfaEnrollResponse,
    GestureVerifyRequest,
    FactorVerifyResponse,
    NeuralTraceResetRequestResponse,
    NeuralTraceResetVerifyRequest,
    NeuralTraceResetVerifyResponse,
    NeuralTraceResetConfirmRequest,
    NeuralTraceResetConfirmResponse,
    AccessDecisionRequest,
    AccessDecisionResponse,
    VaultRelockRequest,
    VaultRelockResponse,
)
from app.services.session_service import SessionService
from app.services.risk_service import RiskService
from app.services.decision_service import DecisionService
from app.services.step_up_service import StepUpService
from app.services.adaptive_auth_service import AdaptiveAuthService
from app.core.rate_limit import rate_limiter
from app.models.behavior import BehaviorLog
from app.routes.deps import get_current_user, verify_session_access
from app.models.user import User
from app.models.session import Session as DbSession
from app.models.security_event import SecurityEvent
from app.models.application_grant import ApplicationGrant

router = APIRouter(prefix="/security", tags=["Security Decision Engine"])


# ==============================================================================
# ADAPTIVE MULTI-FACTOR ENROLLMENT & CATALOGUE ENDPOINTS
# ==============================================================================

@router.get("/adaptive/catalogue", response_model=List[CatalogueItem])
def get_cognitive_catalogue():
    """
    Returns the fixed, public 9-symbol cognitive image catalogue.
    Used for 3x3 cognitive image sequence challenge interfaces.
    """
    return AdaptiveAuthService.get_catalogue()


@router.get("/adaptive/status", response_model=MfaEnrollmentStatusResponse)
def get_user_adaptive_mfa_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Returns the user's enrolled adaptive authentication factor inventory.
    Never exposes raw patterns, answer data, or cryptographic verifiers.
    """
    status_data = AdaptiveAuthService.get_enrollment_status(db, current_user.id)
    return MfaEnrollmentStatusResponse(**status_data)


@router.post("/adaptive/enroll/gesture", response_model=MfaEnrollResponse)
def enroll_gesture_pattern(
    request: GestureEnrollRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Enrolls a 3x3 gesture pattern.
    Stores only a salted bcrypt verifier hash; never the raw gesture trace.
    """
    rate_limiter.enforce(
        key=f"mfa_enroll_gesture:{current_user.id}",
        max_requests=10,
        window_seconds=60,
        detail="Too many gesture pattern enrollment attempts. Please wait."
    )
    result = AdaptiveAuthService.enroll_gesture_pattern(
        db=db,
        user_id=current_user.id,
        pattern=request.pattern,
        confirm_pattern=request.confirm_pattern
    )
    return MfaEnrollResponse(**result)


@router.post("/adaptive/verify/gesture", response_model=FactorVerifyResponse)
def verify_gesture_pattern(
    request: GestureVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Verifies a 3x3 gesture pattern against user's enrolled verifier.
    Rate-limited, securely hashed comparison, never logs or exposes pattern.
    """
    rate_limiter.enforce(
        key=f"mfa_verify_gesture:{current_user.id}",
        max_requests=10,
        window_seconds=60,
        detail="Too many gesture verification attempts. Please wait."
    )
    is_valid = AdaptiveAuthService.verify_enrolled_factor(
        db=db,
        user_id=current_user.id,
        factor_type="GESTURE_PATTERN",
        gesture_pattern=request.gesture_pattern
    )
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Gesture pattern verification failed: Pattern does not match enrolled factor."
        )
    return FactorVerifyResponse(
        success=True,
        factor_type="GESTURE_PATTERN",
        message="Gesture pattern successfully verified."
    )


@router.post("/adaptive/enroll/image-sequence", response_model=MfaEnrollResponse)
def enroll_cognitive_image_sequence(
    request: ImageSequenceEnrollRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Enrolls a 3x3 cognitive image sequence.
    Stores only a salted bcrypt verifier hash; never the raw sequence.
    """
    rate_limiter.enforce(
        key=f"mfa_enroll_image:{current_user.id}",
        max_requests=10,
        window_seconds=60,
        detail="Too many image sequence enrollment attempts. Please wait."
    )
    result = AdaptiveAuthService.enroll_image_sequence(
        db=db,
        user_id=current_user.id,
        image_sequence=request.image_sequence,
        confirm_image_sequence=request.confirm_image_sequence
    )
    return MfaEnrollResponse(**result)


@router.post("/adaptive/enroll/private-response", response_model=MfaEnrollResponse)
def enroll_private_response(
    request: PrivateResponseEnrollRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Enrolls a private question/response challenge.
    Stores only the question prompt in metadata and a salted bcrypt hash of the normalized answer.
    """
    rate_limiter.enforce(
        key=f"mfa_enroll_private:{current_user.id}",
        max_requests=10,
        window_seconds=60,
        detail="Too many private response enrollment attempts. Please wait."
    )
    result = AdaptiveAuthService.enroll_private_response(
        db=db,
        user_id=current_user.id,
        question=request.question,
        response=request.response,
        confirm_response=request.confirm_response
    )
    return MfaEnrollResponse(**result)


# ==============================================================================
# ADAPTIVE STEP-UP CHALLENGE & VERIFICATION LIFECYCLE
# ==============================================================================

@router.post("/step-up/challenge", response_model=StepUpChallengeResponse)
def request_step_up_challenge(
    request: StepUpChallengeRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Policy-driven Adaptive Challenge Generator.
    Maps current session risk to appropriate authentication factor:
    - Mild risk (0.30 <= risk < 0.50): OTP challenge
    - Moderate risk (0.50 <= risk < 0.65): GESTURE_PATTERN challenge (or OTP fallback)
    - High risk (0.65 <= risk < 0.85): COGNITIVE_IMAGE_SEQUENCE or PRIVATE_RESPONSE challenge
    - Critical risk (>= 0.85): PROHIBITED (session terminated)
    """
    rate_limiter.enforce(
        key=f"stepup_chal:{request.session_id}",
        max_requests=10,
        window_seconds=60,
        detail="Too many step-up challenge requests."
    )

    session = SessionService.get_session(db, request.session_id)
    verify_session_access(session, current_user)

    if session.status == "TERMINATED":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot issue challenge for a terminated session."
        )

    if session.current_risk_level == "CRITICAL":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot issue challenge: Session terminated due to critical security risk."
        )

    # Brute-force lockout protection: do not issue challenges if session was locked
    hard_lock = db.query(SecurityEvent).filter(
        SecurityEvent.session_id == session.id,
        SecurityEvent.event_type.in_(["STEP_UP_LOCKED", "ADMIN_REVOCATION", "SESSION_TERMINATED"])
    ).first()
    if hard_lock:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Session locked after exceeding maximum verification attempts. Please sign out and sign in again."
        )

    # Resolve latest session risk score from security events
    latest_event = db.query(SecurityEvent).filter(
        SecurityEvent.session_id == session.id
    ).order_by(SecurityEvent.id.desc()).first()

    risk_score = 0.40
    if session.current_risk_level == "LOW":
        risk_score = 0.15
    elif session.current_risk_level == "MEDIUM":
        risk_score = 0.45
    elif session.current_risk_level == "HIGH":
        risk_score = 0.75
    elif latest_event and latest_event.risk_score is not None:
        risk_score = float(latest_event.risk_score)

    norm_app = SessionService.normalize_application(request.application or session.application)
    norm_res = SessionService.normalize_resource(request.resource) if request.resource else SessionService.get_resource_for_application(norm_app)

    # Generate adaptive challenge bound to application and resource
    challenge_data = StepUpService.create_adaptive_challenge(
        session_id=session.id,
        user_id=current_user.id,
        db=db,
        risk_score=risk_score,
        risk_level=session.current_risk_level or "MEDIUM",
        preferred_factor=request.preferred_factor,
        ttl_seconds=300,
        application=norm_app,
        resource=norm_res
    )

    # Record security event in audit trail
    sec_event = SecurityEvent(
        user_id=current_user.id,
        session_id=session.id,
        application=norm_app or session.application,
        event_type="STEP_UP_CHALLENGE_ISSUED",
        severity=session.current_risk_level or "MEDIUM",
        decision="STEP_UP_VERIFICATION",
        details=f"Adaptive challenge '{challenge_data['challenge_type']}' issued for application '{norm_app or session.application}'."
    )
    db.add(sec_event)
    db.commit()

    return StepUpChallengeResponse(**challenge_data)


@router.post("/step-up/verify", response_model=UserSecurityOutcome)
def verify_step_up_challenge(
    request: StepUpVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Verifies adaptive step-up challenge (OTP, Gesture, Cognitive Image Sequence, or Private Response).
    Enforces server-side risk and session state guards:
    - Never restores access if session is TERMINATED or risk is CRITICAL.
    - Locks session to RESTRICTED upon brute-force failure.
    - Preserves baseline anti-poisoning (zero sample learning from verification).
    """
    rate_limiter.enforce(
        key=f"stepup_ver:{request.session_id}",
        max_requests=10,
        window_seconds=60,
        detail="Too many step-up verification attempts."
    )

    session = SessionService.get_session(db, request.session_id)
    verify_session_access(session, current_user)

    if session.status == "TERMINATED":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot verify a terminated session."
        )

    if session.current_risk_level == "CRITICAL":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot override CRITICAL security risk: session is irrevocably revoked."
        )

    norm_app = SessionService.normalize_application(request.application or session.application)
    norm_res = SessionService.normalize_resource(request.resource) if request.resource else SessionService.get_resource_for_application(norm_app)

    # Verify adaptive challenge submission bound to application and resource
    success, message, is_locked, details = StepUpService.verify_adaptive_challenge(
        session_id=request.session_id,
        user_id=current_user.id,
        db=db,
        challenge_type=request.challenge_type,
        challenge_code=request.challenge_code,
        gesture_pattern=request.gesture_pattern,
        image_sequence=request.image_sequence,
        private_response=request.private_response,
        application=norm_app,
        resource=norm_res,
        challenge_id=request.challenge_id,
        stage=request.stage
    )

    if not success:
        if is_locked:
            # Check if repeated vault denials combined with failed verification elevate to CRITICAL
            from app.services.access_tracker import ConfidentialAccessTracker
            recent_denials = ConfidentialAccessTracker.get_recent_denials_count(current_user.id, session.id)
            if recent_denials >= 2 or session.current_risk_level in ("HIGH", "CRITICAL"):
                session.status = "TERMINATED"
                session.current_risk_level = "CRITICAL"
                sec_event = SecurityEvent(
                    user_id=current_user.id,
                    session_id=session.id,
                    application=norm_app or session.application,
                    event_type="SESSION_TERMINATED",
                    severity="CRITICAL",
                    decision="TERMINATE_SESSION",
                    details="Session terminated due to repeated confidential vault access denials combined with failed verification attempts."
                )
                db.add(sec_event)
                db.commit()
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Session terminated due to critical security risk. Access denied."
                )

            # Session locked due to brute-force attempts
            SessionService.update_session_status(db, request.session_id, status="RESTRICTED", risk_level="HIGH")
            sec_event = SecurityEvent(
                user_id=current_user.id,
                session_id=session.id,
                application=norm_app or session.application,
                event_type="STEP_UP_LOCKED",
                severity="HIGH",
                decision="RESTRICT",
                details="Session locked to RESTRICTED after exceeding maximum adaptive verification attempts."
            )
            db.add(sec_event)
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Maximum verification attempts exceeded. Session has been restricted for security."
            )

        # Log failed verification attempt
        sec_event = SecurityEvent(
            user_id=current_user.id,
            session_id=session.id,
            application=norm_app or session.application,
            event_type="STEP_UP_FAILED",
            severity="MEDIUM",
            decision="STEP_UP_VERIFICATION",
            details=f"Step-up verification failed for challenge type '{request.challenge_type or 'OTP'}' in application '{norm_app}'."
        )
        db.add(sec_event)
        db.commit()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message
        )

    # Check for intermediate Stage 1 verification success of HIGH_RISK_DUAL
    if details and details.get("stage_1_passed") and not details.get("completed"):
        # Crucial security guard: DO NOT create application grant after Stage 1 alone.
        # Session remains restricted / step_up is not marked fresh.
        sec_event = SecurityEvent(
            user_id=current_user.id,
            session_id=session.id,
            application=norm_app or session.application,
            event_type="STEP_UP_STAGE_1_VERIFIED",
            severity="HIGH",
            decision="STEP_UP_VERIFICATION",
            details=f"Stage 1 cognitive image sequence verified for '{norm_app}'. Awaiting Stage 2 private security response."
        )
        db.add(sec_event)
        db.commit()

        return UserSecurityOutcome(
            decision="STEP_UP_VERIFICATION",
            message="Cognitive image sequence verified. Please answer your enrolled private security question to complete authentication.",
            session_status=session.status,
            verification_required=True,
            confidential_access_granted=False,
            step_up_fresh=False,
            step_up_factor="HIGH_RISK_DUAL",
            application=norm_app,
            resource=norm_res,
            stage=2,
            stage_1_passed=True,
            prompt=details.get("prompt"),
            challenge_id=details.get("challenge_id")
        )

    factor_to_grant = request.challenge_type or "GESTURE_PATTERN"

    # Verification succeeded: Authoritatively create application-scoped grant in database if portal resource is targeted
    grant = None
    if norm_app and norm_res and norm_app in ("college", "shopping", "healthcare"):
        grant = SessionService.record_application_grant(
            db=db,
            session_id=request.session_id,
            user_id=current_user.id,
            application=norm_app,
            resource=norm_res,
            factor=factor_to_grant,
            validity_minutes=15
        )
        if not grant:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create application grant after verification."
            )

    # Persist Step-Up success atomically with freshness window
    updated_session = SessionService.record_step_up_success(
        db=db,
        session_id=request.session_id,
        factor=factor_to_grant,
        cleared_risk_score=0.45,
        validity_minutes=15
    )
    if not updated_session:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Session could not be verified or is already terminated."
        )

    # Verify the grant through the same backend authorization path used by protected-resource endpoints
    if grant:
        is_app_authorized = SessionService.is_application_authorized(
            db=db,
            db_session=updated_session,
            user_id=current_user.id,
            application=norm_app,
            resource=norm_res,
            required_factor=factor_to_grant
        )
        if not is_app_authorized:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Application grant authorization check failed."
            )

    sec_event = SecurityEvent(
        user_id=current_user.id,
        session_id=session.id,
        application=norm_app or session.application,
        event_type="STEP_UP_VERIFIED",
        severity="LOW",
        decision="ALLOW",
        details=f"Adaptive challenge '{factor_to_grant}' successfully verified for '{norm_app}'. Full access restored."
    )
    db.add(sec_event)
    db.commit()

    logger.info(
        f"[StepUp] Session {request.session_id} successfully verified factor '{factor_to_grant}' for {norm_app}. "
        f"Valid until {updated_session.step_up_valid_until.isoformat() if updated_session.step_up_valid_until else 'N/A'}."
    )

    return UserSecurityOutcome(
        decision="ALLOW",
        message="Identity step-up verified. Full access restored.",
        session_status=updated_session.status,
        verification_required=False,
        confidential_access_granted=True,
        step_up_fresh=True,
        step_up_factor=factor_to_grant,
        application=norm_app,
        resource=norm_res,
        stage=details.get("stage", 2) if details else 2,
        stage_1_passed=True,
        challenge_id=details.get("challenge_id") if details else None
    )


@router.get("/status/{session_id}", response_model=UserSecurityOutcome)
def get_user_session_security_status(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Returns clean user-facing security outcome for a session.
    Enforces session ownership. DOES NOT reveal raw risk scores or ML internals to the end user.
    """
    session = SessionService.get_session(db, session_id)
    verify_session_access(session, current_user)

    is_fresh = SessionService.is_step_up_fresh(
        session,
        current_risk_score=0.0,
        current_risk_level=session.current_risk_level
    )
    confidential_allowed = bool(
        session.status == "ACTIVE"
        and is_fresh
        and session.current_risk_level not in ("HIGH", "CRITICAL")
    )

    if session.status == "TERMINATED" or session.current_risk_level in ("CRITICAL", "TERMINATED"):
        return UserSecurityOutcome(
            decision="TERMINATE_SESSION",
            message="Session terminated for security protection.",
            session_status="TERMINATED",
            verification_required=False,
            confidential_access_granted=False,
            step_up_fresh=False,
            step_up_factor=None
        )

    if session.status == "ACTIVE":
        return UserSecurityOutcome(
            decision="ALLOW",
            message="Access allowed. Continuous identity verified.",
            session_status="ACTIVE",
            verification_required=False,
            confidential_access_granted=confidential_allowed,
            step_up_fresh=is_fresh,
            step_up_factor=session.step_up_factor
        )
    elif session.status == "PENDING_OBSERVATION":
        return UserSecurityOutcome(
            decision="OBSERVATION_PENDING",
            message=f"Behavioral baseline observation active ({settings.OBSERVATION_WINDOW_SECONDS} seconds). Protected access locked.",
            session_status="PENDING_OBSERVATION",
            verification_required=False,
            confidential_access_granted=False,
            step_up_fresh=False,
            step_up_factor=session.step_up_factor
        )
    elif session.status in ("PENDING_OTP", "STEP_UP_REQUIRED"):
        return UserSecurityOutcome(
            decision="STEP_UP_VERIFICATION",
            message="Identity verification required to access protected applications.",
            session_status=session.status,
            verification_required=True,
            confidential_access_granted=False,
            step_up_fresh=False,
            step_up_factor=session.step_up_factor
        )
    elif session.status == "RESTRICTED":
        return UserSecurityOutcome(
            decision="RESTRICT",
            message="Access temporarily restricted.",
            session_status="RESTRICTED",
            verification_required=False,
            confidential_access_granted=False,
            step_up_fresh=False,
            step_up_factor=session.step_up_factor
        )
    else:
        return UserSecurityOutcome(
            decision="TERMINATE_SESSION",
            message="Session terminated for security protection.",
            session_status="TERMINATED",
            verification_required=False,
            confidential_access_granted=False,
            step_up_fresh=False,
            step_up_factor=session.step_up_factor
        )


@router.post("/access-decision", response_model=AccessDecisionResponse)
def evaluate_resource_access_decision(
    request: AccessDecisionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Authoritative server-side policy evaluation for confidential record access
    (transcripts, financial profile, clinical records).
    Independent authorization: enforces that step-up verification on one portal
    NEVER authorizes access on any other portal.
    """
    session = SessionService.get_session(db, request.session_id)
    verify_session_access(session, current_user)

    norm_app = SessionService.normalize_application(request.application or session.application)
    norm_res = SessionService.normalize_resource(request.resource)
    if not norm_app and norm_res:
        norm_app = SessionService.get_application_for_resource(norm_res)
    if not norm_res and norm_app:
        norm_res = SessionService.get_resource_for_application(norm_app)

    check_factor = "HIGH_RISK_DUAL" if session.step_up_factor == "HIGH_RISK_DUAL" else "GESTURE_PATTERN"
    # Server-side authoritative validation: verify exact application, resource, and session grant
    is_app_authorized = SessionService.is_application_authorized(
        db=db,
        db_session=session,
        user_id=current_user.id,
        application=norm_app,
        resource=norm_res,
        required_factor=check_factor
    )

    if session.status == "TERMINATED":
        return AccessDecisionResponse(
            decision="TERMINATE_SESSION",
            access_granted=False,
            session_status="TERMINATED",
            risk_level=session.current_risk_level,
            step_up_fresh=False,
            step_up_factor=None,
            message="Session terminated for security protection.",
            verification_required=False,
            resource=norm_res or request.resource,
            application=norm_app
        )

    if session.current_risk_level == "CRITICAL":
        return AccessDecisionResponse(
            decision="TERMINATE_SESSION",
            access_granted=False,
            session_status="TERMINATED",
            risk_level="CRITICAL",
            step_up_fresh=False,
            step_up_factor=None,
            message="Session revoked due to critical security risk policy.",
            verification_required=False,
            resource=norm_res or request.resource,
            application=norm_app
        )

    # Check if there is an active brute-force or admin lockout on this session
    hard_lock = db.query(SecurityEvent).filter(
        SecurityEvent.session_id == session.id,
        SecurityEvent.event_type.in_(["STEP_UP_LOCKED", "ADMIN_REVOCATION", "SESSION_TERMINATED"])
    ).first()
    if hard_lock:
        return AccessDecisionResponse(
            decision="RESTRICT",
            access_granted=False,
            session_status="RESTRICTED",
            risk_level=session.current_risk_level or "HIGH",
            step_up_fresh=False,
            step_up_factor=None,
            message=(
                "Maximum verification attempts exceeded. Session is restricted for security. "
                "Sign out and sign in again to start a new verified session."
            ),
            verification_required=False,
            resource=norm_res or request.resource,
            application=norm_app
        )

    # Server-side tracking: Repeated unauthorized clicks to confidential vaults elevate risk
    if not is_app_authorized:
        from app.services.access_tracker import ConfidentialAccessTracker
        denials = ConfidentialAccessTracker.record_denial(
            user_id=current_user.id,
            session_id=session.id,
            resource=norm_res or request.resource
        )
        if denials >= settings.CONFIDENTIAL_ACCESS_DENIAL_THRESHOLD:
            if session.current_risk_level not in ("CRITICAL", "TERMINATED"):
                session.current_risk_level = "HIGH"
                db.commit()

    if session.status == "PENDING_OBSERVATION":
        return AccessDecisionResponse(
            decision="OBSERVATION_PENDING",
            access_granted=False,
            session_status="PENDING_OBSERVATION",
            risk_level=session.current_risk_level,
            step_up_fresh=False,
            step_up_factor=None,
            message="Behavioral baseline observation active. Confidential access locked.",
            verification_required=False,
            resource=norm_res or request.resource,
            application=norm_app
        )

    # Server-authoritative check: If application grant is already valid and unexpired
    if is_app_authorized:
        active_factor = "HIGH_RISK_DUAL" if session.step_up_factor == "HIGH_RISK_DUAL" else "GESTURE_PATTERN"
        return AccessDecisionResponse(
            decision="ALLOW",
            access_granted=True,
            session_status=session.status if session.status == "ACTIVE" else "ACTIVE",
            risk_level=session.current_risk_level,
            step_up_fresh=True,
            step_up_factor=active_factor,
            message=f"Confidential access authorized via server-authoritative {active_factor} verification for {norm_app}.",
            verification_required=False,
            resource=norm_res or request.resource,
            application=norm_app
        )

    # Step-up verification required to access confidential vault
    if session.current_risk_level == "HIGH":
        # Check enrollment of both cognitive factors
        enrollment = AdaptiveAuthService.get_enrollment_status(db, current_user.id)
        has_img = enrollment.get("has_cognitive_image_sequence", False)
        has_priv = enrollment.get("has_private_response", False)

        if not (has_img and has_priv):
            missing = []
            if not has_img:
                missing.append("Cognitive Image Sequence")
            if not has_priv:
                missing.append("Private Security Response")
            missing_str = " and ".join(missing)
            return AccessDecisionResponse(
                decision="RESTRICT",
                access_granted=False,
                session_status="RESTRICTED",
                risk_level="HIGH",
                step_up_fresh=False,
                step_up_factor=None,
                message=f"High risk detected. Sequential cognitive verification required, but {missing_str} must be enrolled first. Access denied.",
                verification_required=False,
                required_factor="HIGH_RISK_DUAL",
                resource=norm_res or request.resource,
                application=norm_app
            )

        return AccessDecisionResponse(
            decision="STEP_UP_VERIFICATION",
            access_granted=False,
            session_status=session.status if session.status in ("ACTIVE", "RESTRICTED") else "RESTRICTED",
            risk_level="HIGH",
            step_up_fresh=False,
            step_up_factor=None,
            message=f"High risk detected. Sequential cognitive verification (Image Sequence and Private Response) required to access {norm_res or 'confidential records'} in {norm_app or 'this portal'}.",
            verification_required=True,
            required_factor="HIGH_RISK_DUAL",
            resource=norm_res or request.resource,
            application=norm_app
        )

    # For LOW and MEDIUM risk, confidential vault access strictly requires NeuralTrace (GESTURE_PATTERN), never OTP
    return AccessDecisionResponse(
        decision="STEP_UP_VERIFICATION",
        access_granted=False,
        session_status=session.status,
        risk_level=session.current_risk_level or "LOW",
        step_up_fresh=False,
        step_up_factor=None,
        message=f"Zero Trust policy requires NeuralTrace verification to access {norm_res or 'confidential records'} in {norm_app or 'this portal'}.",
        verification_required=True,
        required_factor="GESTURE_PATTERN",
        resource=norm_res or request.resource,
        application=norm_app
    )

    return AccessDecisionResponse(
        decision="TERMINATE_SESSION",
        access_granted=False,
        session_status=session.status,
        risk_level=session.current_risk_level,
        step_up_fresh=False,
        step_up_factor=None,
        message="Session revoked.",
        verification_required=False,
        resource=norm_res or request.resource,
        application=norm_app
    )


@router.get("/vault/{resource}")
def get_confidential_vault_data(
    resource: str,
    session_id: Optional[str] = None,
    response: Response = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Authoritative server-side endpoint serving confidential vault data.
    Enforces independent application-scoped authorization:
    - User must be authenticated
    - Active valid session
    - Verified, unexpired NeuralTrace (GESTURE_PATTERN) grant for this exact application and resource
    - Risk level must be LOW or MEDIUM
    Fails closed with HTTP 403 Forbidden on any violation.
    Sets Cache-Control: no-store to prevent browser history or proxy caching.
    """
    if response is not None:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, private"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    target_session = None
    if session_id:
        target_session = SessionService.get_session(db, session_id)
        verify_session_access(target_session, current_user)
    else:
        active_sessions = SessionService.get_active_sessions(db, user_id=current_user.id)
        if active_sessions:
            target_session = active_sessions[0]

    def _record_denial_and_raise(detail_msg: str, status_code: int = status.HTTP_403_FORBIDDEN):
        if target_session:
            from app.services.access_tracker import ConfidentialAccessTracker
            denials = ConfidentialAccessTracker.record_denial(
                user_id=current_user.id,
                session_id=target_session.id,
                resource=resource
            )
            if denials >= settings.CONFIDENTIAL_ACCESS_DENIAL_THRESHOLD:
                import numpy as np
                r_score, a_score, r_level, factors, _, _ = RiskService.calculate_risk(
                    db=db,
                    user_id=current_user.id,
                    session_id=target_session.id,
                    application=target_session.application,
                    behavior_vector=np.zeros(10),
                    context_signals={"denied_access_count": denials}
                )
                DecisionService.enforce_zero_trust_decision(
                    db=db,
                    user_id=current_user.id,
                    session_id=target_session.id,
                    application=target_session.application,
                    risk_score=r_score,
                    anomaly_score=a_score,
                    risk_level=r_level,
                    contributing_factors=factors
                )
        raise HTTPException(status_code=status_code, detail=detail_msg)

    norm_res = SessionService.normalize_resource(resource)
    target_app = SessionService.get_application_for_resource(norm_res)
    if not norm_res or not target_app or norm_res not in ("academic_vault", "financial_vault", "ehr_vault"):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Unknown or invalid confidential vault resource."
        )

    if not target_session:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Valid active session required to access confidential vault."
        )

    if target_session.current_risk_level in ("CRITICAL", "TERMINATED") or target_session.status == "TERMINATED":
        sec_event = SecurityEvent(
            user_id=current_user.id,
            session_id=target_session.id,
            application=target_session.application,
            event_type="VAULT_ACCESS_BLOCKED",
            severity="CRITICAL",
            decision="DENY",
            details=f"Confidential vault access blocked for {resource} due to {target_session.current_risk_level or 'CRITICAL'} risk policy."
        )
        db.add(sec_event)
        db.commit()
        _record_denial_and_raise(f"Confidential access blocked due to {target_session.current_risk_level or 'CRITICAL'} risk policy.")

    if target_session.status != "ACTIVE":
        _record_denial_and_raise("Valid active session required to access confidential vault.")

    grant = db.query(ApplicationGrant).filter(
        ApplicationGrant.session_id == target_session.id,
        ApplicationGrant.user_id == current_user.id,
        ApplicationGrant.application == target_app,
        ApplicationGrant.resource == norm_res,
        ApplicationGrant.revoked == False
    ).order_by(ApplicationGrant.id.desc()).first()

    if not grant:
        factor_desc = "sequential cognitive" if target_session.current_risk_level == "HIGH" else "NeuralTrace"
        _record_denial_and_raise(f"Zero Trust policy requires {factor_desc} verification to access {norm_res} in {target_app}.")

    if target_session.current_risk_level == "HIGH" and grant.factor != "HIGH_RISK_DUAL":
        _record_denial_and_raise("High risk policy requires sequential cognitive verification (HIGH_RISK_DUAL).")

    req_factor = grant.factor or ("HIGH_RISK_DUAL" if target_session.step_up_factor == "HIGH_RISK_DUAL" else "GESTURE_PATTERN")

    is_authorized = SessionService.is_application_authorized(
        db=db,
        db_session=target_session,
        user_id=current_user.id,
        application=target_app,
        resource=norm_res,
        required_factor=req_factor
    )

    if not is_authorized:
        factor_desc = "sequential cognitive" if req_factor == "HIGH_RISK_DUAL" else "NeuralTrace"
        _record_denial_and_raise(f"Zero Trust policy requires {factor_desc} verification to access {norm_res} in {target_app}.")

    # Clear denial history upon successful authorized access
    from app.services.access_tracker import ConfidentialAccessTracker
    ConfidentialAccessTracker.clear_denials(user_id=current_user.id, session_id=target_session.id)

    res_norm = norm_res
    if res_norm == "financial_vault":
        is_jane = bool(
            current_user.email and ("customer.jane" in current_user.email.lower() or "jane" in current_user.name.lower())
        )
        if is_jane:
            return {
                "resource": "financial_vault",
                "application": "shopping",
                "access_granted": True,
                "success": True,
                "data": {
                    "account_holder": current_user.name,
                    "account_email": current_user.email,
                    "saved_cards": [
                        {
                            "bank": "HDFC Regalia Gold Visa",
                            "number": "•••• •••• •••• 4821",
                            "last4": "4821",
                            "network": "VISA Platinum",
                            "expiry": "08/28",
                            "type": "Primary Corporate Card",
                            "limit_available": "₹3,42,500 / ₹5,00,000",
                            "token_status": "Zero-Trust Token Active (EMVCo 3DS)"
                        },
                        {
                            "bank": "ICICI Sapphiro Mastercard",
                            "number": "•••• •••• •••• 9104",
                            "last4": "9104",
                            "network": "Mastercard World",
                            "expiry": "11/27",
                            "type": "Secondary Retail Card",
                            "limit_available": "₹4,18,000 / ₹5,00,000",
                            "token_status": "Verified Hardware Cryptogram"
                        }
                    ],
                    "upi_vpa": {
                        "primary": "customer.jane@okhdfcbank",
                        "secondary": "jane.doe99@axisbank",
                        "linked_account": "State Bank of India (••3921)",
                        "mandate_id": "#MAND-UPI-2026-8810",
                        "mandate_limit": "₹25,000 / transaction",
                        "status": "AutoPay Active"
                    },
                    "billing_info": {
                        "name": "Jane Doe",
                        "address_line": "Flat 402, Prestige Palms, 12th Main Indiranagar",
                        "city_state_pin": "Bengaluru, Karnataka - 560038",
                        "tax_gstin": "29AAACN8491M1Z5 (Verified)",
                        "phone": "+91 98450 •••••"
                    },
                    "bank_account": {
                        "bank": "State Bank of India",
                        "branch": "Indiranagar Branch, Bengaluru",
                        "account_number": "••••••••••3921",
                        "ifsc": "SBIN0004012",
                        "type": "Salary Account (Verified Mandate)"
                    },
                    "bank_mandates": [
                        {
                            "bank": "State Bank of India (Savings)",
                            "account": "••••••••••3921",
                            "ifsc": "SBIN0004012",
                            "branch": "MG Road, Bengaluru",
                            "mandate_type": "Retail Auto-Pay Mandate",
                            "status": "ACTIVE",
                            "mandate_cap": "₹25,000 / transaction",
                            "ref": "#MAND-2026-NYRAA-88419"
                        }
                    ],
                    "recent_confidential_orders": [
                        {
                            "order_id": "#NYR-98421",
                            "date": "28 Oct 2026",
                            "item": "Nyraa Titan Chronograph",
                            "amount": "₹14,999",
                            "payment_method": "UPI AutoPay (HDFC)",
                            "status": "Settled & Delivered",
                            "delivery": "Indiranagar, Bengaluru"
                        },
                        {
                            "order_id": "#NYR-97105",
                            "date": "15 Oct 2026",
                            "item": "Artisanal Leather Duffle",
                            "amount": "₹5,999",
                            "payment_method": "HDFC Regalia Token",
                            "status": "Settled & Delivered",
                            "delivery": "Koramangala, Bengaluru"
                        },
                        {
                            "order_id": "#NYR-96540",
                            "date": "04 Oct 2026",
                            "item": "Premium Wireless ANC Headphones",
                            "amount": "₹3,499",
                            "payment_method": "ICICI Sapphiro ••9104",
                            "status": "Settled & Delivered",
                            "delivery": "Indiranagar, Bengaluru"
                        }
                    ],
                    "recent_orders": [
                        {
                            "order_id": "#NYR-98421",
                            "item": "Nyraa Titan Chronograph",
                            "amount": "₹14,999",
                            "method": "Paid via UPI 1-Tap",
                            "status": "Settled",
                            "delivery": "Delivered: Indiranagar, Bengaluru"
                        }
                    ],
                    "refund_records": [
                        {
                            "refund_id": "#REF-2026-0814",
                            "order_ref": "#NYR-94812",
                            "amount": "₹1,299.00",
                            "method": "Original Payment (HDFC Visa ••4821)",
                            "status": "PROCESSED (ARN: 489201948210)",
                            "date": "18 Oct 2026",
                            "reason": "Return processed at warehouse"
                        }
                    ],
                    "fraud_review": {
                        "risk_assessment": "VERY_LOW (0.002)",
                        "3ds_history": "3DS 2.2 Frictionless Auth (Auth Ref #AUTH-3DS-884192)",
                        "device_trust": "Trusted Client Hardware Token",
                        "behavioral_velocity": "Within Normal Baseline (0.012)"
                    },
                    "invoice_ref": "#INV-2026-0419"
                }
            }

        # Authenticated account data isolation: Query genuine user orders
        from app.models.shopping_order import ShoppingOrder
        genuine_orders = db.query(ShoppingOrder).filter(ShoppingOrder.user_id == current_user.id).order_by(ShoppingOrder.created_at.desc()).all()
        orders_list = []
        for ord in genuine_orders:
            orders_list.append({
                "order_id": ord.order_id,
                "date": ord.created_at.strftime("%d %b %Y") if ord.created_at else "Recent",
                "item": ord.item_summary,
                "amount": f"₹{ord.amount:,.2f}",
                "payment_method": ord.payment_method,
                "status": "Settled & Delivered" if ord.payment_status == "PAID" else ord.payment_status,
                "delivery": ord.shipping_address or "Registered Address"
            })

        return {
            "resource": "financial_vault",
            "application": "shopping",
            "access_granted": True,
            "success": True,
            "data": {
                "account_holder": current_user.name,
                "account_email": current_user.email,
                "saved_cards": [],
                "upi_vpa": None,
                "billing_info": {
                    "name": current_user.name,
                    "email": current_user.email,
                    "phone": getattr(current_user, "phone", "+91 98450 •••••"),
                    "address_line": "No saved address on file",
                    "city_state_pin": "",
                    "tax_gstin": ""
                },
                "bank_account": None,
                "bank_mandates": [],
                "recent_confidential_orders": orders_list,
                "recent_orders": orders_list,
                "refund_records": [],
                "fraud_review": {
                    "risk_assessment": "VERY_LOW (0.002)",
                    "3ds_history": "3DS 2.2 Frictionless Auth",
                    "device_trust": "Trusted Client Hardware Token",
                    "behavioral_velocity": "Within Normal Baseline (0.000)"
                },
                "invoice_ref": f"#INV-2026-{current_user.id:04d}" if orders_list else None
            }
        }
    elif res_norm == "academic_vault":
        is_alex = bool(
            current_user.email and ("student.alex" in current_user.email.lower() or "alex" in current_user.name.lower())
        )
        student_id = "BITS-2022-CS-9841" if is_alex else f"BITS-2022-CS-20{current_user.id:02d}"
        enrollment_no = "2022A7PS0841P" if is_alex else f"2022A7PS{current_user.id:04d}P"
        full_name = "Alex Mercer" if is_alex else current_user.name
        campus_desc = "Pilani Campus • Hall of Residence 4" if is_alex else "Pilani Campus"

        return {
            "resource": "academic_vault",
            "application": "college",
            "access_granted": True,
            "success": True,
            "data": {
                "student_profile": {
                    "student_id": student_id,
                    "enrollment_number": enrollment_no,
                    "full_name": full_name,
                    "program": "B.Tech (Hons) Computer Science & Engineering",
                    "batch": "2022 – 2026 (Semester 7)",
                    "campus": campus_desc,
                    "academic_advisor": "Prof. K. R. Sharma (Dept of CS)",
                    "enrollment_status": "Active / Verified Regular Student",
                    "degree_expected": "July 2026"
                },
                "student_id": student_id,
                "program": "B.Tech Computer Science & Engineering",
                "cgpa": "9.42 / 10.00",
                "academic_standing": "Dean's Honor Roll",
                "credits_completed": "142 / 148 Completed",
                "major": "B.Tech (Hons) CSE",
                "provisional_certificate": f"PC-2026-CS-{current_user.id:05d}",
                "scholarship": "Merit Excellence Fellowship (100% Tuition Waiver)",
                "fee_balance": "₹0.00 (Cleared)",
                "transcripts": [
                    {"code": "CS F301", "name": "Principles of Programming Languages", "grade": "A (10/10)", "credits": 4, "semester": "Sem 7"},
                    {"code": "CS F402", "name": "AI Security & Adversarial ML", "grade": "A (10/10)", "credits": 4, "semester": "Sem 7"},
                    {"code": "CS F360", "name": "Distributed Operating Systems", "grade": "A- (9/10)", "credits": 4, "semester": "Sem 7"},
                    {"code": "AI F420", "name": "Deep Reinforcement Learning", "grade": "A (10/10)", "credits": 4, "semester": "Sem 7"},
                    {"code": "CS F303", "name": "Computer Networks & Protocols", "grade": "A (10/10)", "credits": 4, "semester": "Sem 6"},
                    {"code": "CS F342", "name": "Computer Architecture", "grade": "A- (9/10)", "credits": 4, "semester": "Sem 6"}
                ],
                "examination_records": [
                    {"exam": "Comprehensive Semester 7 End-Term", "session": "Autumn 2026", "score": "94.5%", "status": "CONFIDENTIAL GRADE RECORDED", "seal": "Registrar Exam Division #EXAM-2026-9481"},
                    {"exam": "Mid-Semester Evaluation", "session": "Autumn 2026", "score": "92.0%", "status": "VERIFIED", "seal": "Faculty Proctor Seal #PROC-8814"},
                    {"exam": "Hardware Security Lab Practical Viva", "session": "Autumn 2026", "score": "98.0%", "status": "DISTINCTION", "seal": "External Examiner Affirmed"}
                ],
                "academic_integrity": {
                    "standing": "EXEMPLARY RECORD",
                    "infractions": "0 Violations Recorded",
                    "honor_code_status": "Affirmed & Validated",
                    "proctor_endorsement": "Dean of Students Affairs Clearance Granted",
                    "last_audit": "2026-10-15 (Automated Clearance Archive)"
                },
                "documents": [
                    {"title": "Official Cumulative Transcript (Sem 1-7)", "doc_id": "#BITS-DIGI-84920", "status": "Signed & Cryptographically Sealed", "authority": "NAD / DigiLocker National Registry"},
                    {"title": "Provisional Degree Certificate", "doc_id": "#PDC-2026-CS-092", "status": "Sealed & Issued", "authority": "Registrar Cryptographic PKI Seal"},
                    {"title": "Institutional Clearance & Dues Certificate", "doc_id": "#ICC-2026-NIL", "status": "Nil Dues Cleared", "authority": "Central Library, Hostel 4, Accounts Division"},
                    {"title": "Merit Fellowship Sanction Letter", "doc_id": "#FELL-2025-0814", "status": "Active & Disbursed", "authority": "Dean Academic Research"}
                ],
                "financial_ledger": {
                    "scholarship": "Merit-cum-Need National Fellowship (100% Tuition Waiver)",
                    "tuition_due": "₹0.00 (Fully Settled)",
                    "status": "Clearance Active — Nil Dues",
                    "bank_mandate": "State Bank of India, Pilani Campus (•••3921)",
                    "receipt_ref": "#REC-2026-7810",
                    "receipt_status": "₹0 Due • Confirmed Settled",
                    "stipend_disbursement": "₹25,000 / month (Research Assistantship • Active)"
                }
            }
        }
    elif res_norm == "ehr_vault":
        return {
            "resource": "ehr_vault",
            "application": "healthcare",
            "access_granted": True,
            "success": True,
            "data": {
                "patient_id": "MED-2026-BLR-00418",
                "clinical_diagnosis": "Post-Op Coronary Angioplasty (CAD - LAD Stent) & Essential Hypertension",
                "patient_profile": {
                    "name": "Rajesh Kumar",
                    "age": 52,
                    "gender": "Male",
                    "blood_group": "B+ (Rh Positive)",
                    "abha_id": "91-0982-1249-92",
                    "unit": "Cardiology ICU",
                    "bay": "Bay 4 • Bengaluru Facility",
                    "attending_physician": "Dr. Boomika Ram (KMC #84920)",
                    "emergency_contact": "Priya Kumar (Spouse) — +91 98450 ••••• (Verified)"
                },
                "vitals": {
                    "heart_rate": "72 bpm (Resting)",
                    "cardiac_rhythm": "Normal Sinus Rhythm",
                    "blood_pressure": "128 / 84 mmHg (Optimal)",
                    "spo2": "98% on room air",
                    "respiratory_rate": "16 / min",
                    "temperature": "98.4°F (Afebrile)",
                    "hba1c": "5.6% (Normal)"
                },
                "medical_history": {
                    "primary_diagnosis": "Post-Op Coronary Angioplasty (CAD - Proximal LAD Stent)",
                    "surgical_details": "Drug-eluting stent (DES) placed in proximal LAD. Post-procedure Day 3 recovery course uncomplicated.",
                    "comorbidities": "Essential Hypertension (Stage II) - Well Controlled; Mild Dyslipidemia",
                    "allergies": "No known drug allergies (NKDA). Penicillin skin test negative.",
                    "progress_note": "Patient is awake, alert, and ambulatory with minimal assistance. Chest discomfort has fully resolved. Femoral access site clean and dry with intact distal pulses. Dual antiplatelet therapy and high-intensity Statin well tolerated. Cardiac troponin-I has trended down from peak 2.4 ng/mL to 0.04 ng/mL. Scheduled for safe ward step-down in 24 hours.",
                    "signed_by": "Dr. Boomika Ram (KMC #84920)"
                },
                "clinical_notes": {
                    "diagnosis": "Post-Op Coronary Angioplasty (CAD - LAD Stent)",
                    "comorbidities": "Essential Hypertension (Stage II) • NKDA",
                    "note": "Patient is awake, alert, and ambulatory. Chest discomfort has fully resolved. Dual antiplatelet therapy and high-intensity Statin well tolerated. Troponin-I resolved to 0.04 ng/mL baseline. Scheduled for step-down.",
                    "signed_by": "Dr. Boomika Ram (Cardiology Consultant)"
                },
                "prescriptions": [
                    {"medicine": "Telmisartan 40mg", "medication": "Telmisartan 40mg", "category": "Antihypertensive (ARB)", "dosage": "1-0-0 Daily", "frequency": "Morning with breakfast", "refills_left": 3},
                    {"medicine": "Atorvastatin 40mg", "medication": "Atorvastatin 40mg", "category": "Lipid Lowering (Statin)", "dosage": "0-0-1 Night", "frequency": "Bedtime", "refills_left": 2},
                    {"medicine": "Ticagrelor 90mg", "medication": "Ticagrelor 90mg", "category": "Antiplatelet (P2Y12)", "dosage": "1-0-1 Twice Daily", "frequency": "Every 12 hours", "refills_left": 4},
                    {"medicine": "Aspirin 75mg", "medication": "Aspirin 75mg", "category": "Antiplatelet (Enteric-coated)", "dosage": "1-0-0 Daily", "frequency": "Post-lunch", "refills_left": 4}
                ],
                "lab_reports": [
                    {"test": "Cardiac Biomarkers (Troponin-I)", "date": "2026-10-28", "status": "NORMAL (0.04 ng/mL)", "result": "0.04 ng/mL (Ref: < 0.05 ng/mL - Baseline Resolved)", "hash": "SHA-256: 7f8b9e...092a"},
                    {"test": "Comprehensive Metabolic Panel (CMP)", "date": "2026-10-28", "status": "NORMAL", "result": "Serum Creatinine: 0.9 mg/dL; eGFR > 90 mL/min; K+: 4.2 mEq/L", "hash": "SHA-256: 3c1a2f...881b"},
                    {"test": "Lipid Profile & HbA1c", "date": "2026-10-26", "status": "STABLE", "result": "Total Chol: 164 mg/dL; LDL: 68 mg/dL; Triglycerides: 122 mg/dL; HbA1c: 5.6%", "hash": "SHA-256: e8d40a...941c"},
                    {"test": "12-Lead Electrocardiogram (ECG)", "date": "2026-10-29", "status": "NORMAL SINUS", "result": "Normal Sinus Rhythm (72 bpm), PR: 142ms, QRS: 88ms, ST Elevation Resolved", "hash": "SHA-256: a19f2c...4401"},
                    {"test": "2D Echocardiogram with Doppler", "date": "2026-10-25", "status": "OPTIMAL (LVEF 60%)", "result": "Preserved Left Ventricular Function (LVEF 60%), No regional wall motion abnormality", "hash": "SHA-256: d58b3e...771a"}
                ],
                "consultations": [
                    {"date": "2026-10-29", "physician": "Dr. Boomika Ram (KMC #84920)", "specialty": "Interventional Cardiology", "summary": "Post-intervention Day 3 round: Hemodynamically stable, access site intact, telemetry monitoring shows uninterrupted normal sinus rhythm. Cleared for transfer to ward.", "recommendation": "Step-down to step-down ward; continue dual antiplatelet therapy for 12 months."}
                ],
                "allergies": {
                    "drug_allergies": "No Known Drug Allergies (NKDA)",
                    "skin_tests": "Penicillin skin prick test: Negative",
                    "food_latex": "No environmental or latex sensitivities documented"
                },
                "diagnostics": {
                    "ecg": {
                        "title": "12-Lead Electrocardiogram (ECG)",
                        "status": "NORMAL SINUS",
                        "pr_interval": "142 ms (Normal)",
                        "qrs_duration": "88 ms",
                        "st_segment": "Anterior ST elevation resolved",
                        "digest": "SHA-256: 7f8b9e...092a"
                    },
                    "lipid_cardiac_panel": {
                        "title": "Cardiac Biomarkers & Lipid Panel",
                        "status": "STABLE",
                        "total_cholesterol": "164 mg/dL",
                        "ldl_cholesterol": "68 mg/dL (Target < 70)",
                        "troponin_i": "0.04 ng/mL (< 0.05 baseline)",
                        "audit_gateway_id": "#ABDM-PATH-94812"
                    }
                }
            }
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Unknown confidential vault resource."
        )


@router.post("/vault/relock", response_model=VaultRelockResponse)
@router.post("/vault/revoke", response_model=VaultRelockResponse)
def relock_confidential_vault(
    request: VaultRelockRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Authoritative server-enforced revocation of confidential vault access grant.
    Revokes the active ApplicationGrant for the given session and resource without
    terminating the user's entire authenticated portal session.
    Logs VAULT_GRANT_REVOKED in the security audit trail.
    """
    session = SessionService.get_session(db, request.session_id)
    verify_session_access(session, current_user)

    norm_res = SessionService.normalize_resource(request.resource)
    if not norm_res or norm_res not in ("academic_vault", "financial_vault", "ehr_vault"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid or unknown confidential vault resource '{request.resource}'."
        )

    expected_app = SessionService.get_application_for_resource(norm_res)
    norm_app = SessionService.normalize_application(request.application) if request.application else expected_app

    if norm_app and norm_app != expected_app:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Resource '{norm_res}' does not belong to application '{norm_app}'."
        )

    count = SessionService.revoke_application_grants(
        db=db,
        session_id=session.id,
        user_id=current_user.id,
        application=expected_app,
        resource=norm_res
    )

    # Record security audit event
    sec_event = SecurityEvent(
        user_id=current_user.id,
        session_id=session.id,
        application=expected_app,
        event_type="VAULT_GRANT_REVOKED",
        severity="INFO",
        decision="ALLOW",
        details=f"Confidential vault grant for resource '{norm_res}' in application '{expected_app}' authoritatively revoked on portal exit. Vault is LOCKED."
    )
    db.add(sec_event)
    db.commit()

    return VaultRelockResponse(
        success=True,
        message=f"Vault grant for '{norm_res}' successfully revoked. Vault is locked.",
        resource=norm_res,
        application=expected_app,
        revoked_count=count,
        vault_status="LOCKED"
    )


@router.post("/adaptive/neuraltrace/reset-request", response_model=NeuralTraceResetRequestResponse)
def request_neuraltrace_reset(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Initiates re-authentication workflow for resetting the user's NeuralTrace factor.
    Requires registered email verification before allowing route replacement.
    Rate-limited and securely dispatched.
    """
    rate_limiter.enforce(
        key=f"nt_reset_req:{current_user.id}",
        max_requests=5,
        window_seconds=300,
        detail="Too many reset requests. Please wait."
    )
    result = AdaptiveAuthService.request_neuraltrace_reset(db, current_user)
    return NeuralTraceResetRequestResponse(**result)


@router.post("/adaptive/neuraltrace/reset-verify", response_model=NeuralTraceResetVerifyResponse)
def verify_neuraltrace_reset(
    request: NeuralTraceResetVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Verifies the email re-authentication code.
    If valid, returns a single-use scoped reset ticket.
    If invalid, preserves existing enrollment and returns error.
    """
    rate_limiter.enforce(
        key=f"nt_reset_ver:{current_user.id}",
        max_requests=10,
        window_seconds=60,
        detail="Too many verification attempts. Please wait."
    )
    cid = request.reset_challenge_id or request.challenge_id
    if not cid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing reset challenge ID."
        )
    result = AdaptiveAuthService.verify_neuraltrace_reset(
        user_id=current_user.id,
        reset_challenge_id=cid,
        otp=request.otp
    )
    return NeuralTraceResetVerifyResponse(**result)


@router.post("/adaptive/neuraltrace/reset-confirm", response_model=NeuralTraceResetConfirmResponse)
def confirm_neuraltrace_reset(
    request: NeuralTraceResetConfirmRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Enrolls the new NeuralTrace route using the validated reset ticket.
    Validates confirmation matching, invalidates old challenges, and logs an audit event.
    """
    rate_limiter.enforce(
        key=f"nt_reset_conf:{current_user.id}",
        max_requests=5,
        window_seconds=60,
        detail="Too many reset confirmation requests. Please wait."
    )
    result = AdaptiveAuthService.confirm_neuraltrace_reset(
        db=db,
        user_id=current_user.id,
        reset_ticket=request.reset_ticket,
        pattern=request.pattern,
        confirm_pattern=request.confirm_pattern
    )
    return NeuralTraceResetConfirmResponse(**result)


# ==========================================
# COLLEGE ONLINE EXAMINATION OTP ENDPOINTS
# ==========================================
from pydantic import BaseModel

class ExamOtpRequestPayload(BaseModel):
    session_id: str
    course_name: Optional[str] = "CS F301 • End-Semester Proctored Assessment"


class ExamOtpVerifyPayload(BaseModel):
    session_id: str
    challenge_id: Optional[str] = None
    otp: str
    course_name: Optional[str] = None


@router.post("/exam-otp/request")
def request_college_exam_otp(
    request: ExamOtpRequestPayload,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Requests a protected-action OTP challenge before launching an online examination
    in the College Portal. Dispatches the 6-digit OTP to the student's registered email
    via Gmail SMTP and deduplicates concurrent/rapid requests.
    """
    session = SessionService.get_session(db, request.session_id)
    verify_session_access(session, current_user)
    return StepUpService.create_exam_otp_challenge(
        session_id=session.id,
        user_id=current_user.id,
        course_name=request.course_name or "CS F301 • End-Semester Proctored Assessment",
        db=db
    )


@router.post("/exam-otp/resend")
def resend_college_exam_otp(
    request: ExamOtpRequestPayload,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Resends the online examination OTP subject to a 15-second cooldown.
    Invalidates any previous unconsumed examination OTP challenge.
    """
    session = SessionService.get_session(db, request.session_id)
    verify_session_access(session, current_user)
    return StepUpService.resend_exam_otp_challenge(
        session_id=session.id,
        user_id=current_user.id,
        course_name=request.course_name,
        db=db
    )


@router.post("/exam-otp/verify")
def verify_college_exam_otp(
    request: ExamOtpVerifyPayload,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Verifies the submitted 6-digit examination OTP on the backend.
    On success, issues a scoped ApplicationGrant for (application='college', resource='online_exam').
    """
    session = SessionService.get_session(db, request.session_id)
    verify_session_access(session, current_user)
    ok, msg, data = StepUpService.verify_exam_otp_challenge(
        session_id=session.id,
        user_id=current_user.id,
        challenge_id=request.challenge_id,
        otp_code=request.otp,
        course_name=request.course_name,
        db=db
    )
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=msg
        )
    return {
        "verified": True,
        "message": msg,
        **(data or {})
    }


@router.get("/exam-session")
def get_authorized_exam_session(
    session_id: str,
    course_name: Optional[str] = "CS F301 • End-Semester Proctored Assessment",
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Protected examination launch endpoint.
    Rejects direct API calls or URL access unless the session holds an active,
    unexpired ApplicationGrant for (application='college', resource='online_exam', factor='EXAM_OTP').
    """
    session = SessionService.get_session(db, session_id)
    verify_session_access(session, current_user)

    if session.status != "ACTIVE" or session.current_risk_level in ("CRITICAL", "HIGH", "RESTRICTED"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Session is not in an active, low-risk state required for online examination."
        )

    is_authorized = SessionService.is_application_authorized(
        db=db,
        db_session=session,
        user_id=current_user.id,
        application="college",
        resource="online_exam",
        required_factor="EXAM_OTP"
    )
    if not is_authorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Online examination access denied: Valid examination OTP verification is required before launching the exam."
        )

    return {
        "authorized": True,
        "session_id": session.id,
        "student_name": current_user.name,
        "student_email": current_user.email,
        "course_name": course_name or "CS F301 • End-Semester Proctored Assessment",
        "exam_token": f"#BITS-EXM-{session.id[-4:].upper()}",
        "proctoring_status": "ACTIVE_BEHAVIORAL_SHIELD"
    }


