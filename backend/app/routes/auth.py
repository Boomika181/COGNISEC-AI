import json
import logging
from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, status, Header, Request

logger = logging.getLogger(__name__)
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.schemas.auth import (
    LoginRequest,
    RegisterRequest,
    TokenResponse,
    BootstrapAdminRequest,
    ObservationStatusResponse,
    LoginOtpRequest,
    LoginOtpResponse,
    LoginOtpVerifyRequest,
    LoginOtpVerifyResponse,
    PasswordResetRequest,
    PasswordResetResponse,
    PasswordResetResendRequest,
    PasswordResetVerifyRequest,
    PasswordResetVerifyResponse,
    RecoverAccountRequest,
    UnlockAccountRequest,
    PasswordChangePolicyResponse,
    PasswordChangeInitiateRequest,
    PasswordChangeInitiateResponse,
    PasswordChangeVerifyImageRequest,
    PasswordChangeVerifyImageResponse,
    PasswordChangeVerifyPrivateRequest,
    PasswordChangeVerifyPrivateResponse,
    PasswordChangeConfirmRequest,
    PasswordChangeConfirmResponse,
)
from app.schemas.user import UserResponse
from app.services.auth_service import AuthService
from app.services.device_service import DeviceService
from app.services.password_change_service import PasswordChangeService
from app.services.session_service import SessionService
from app.services.step_up_service import StepUpService
from app.services.profile_service import ProfileService
from app.ml.model_manager import ModelManager
from app.services.adaptive_auth_service import AdaptiveAuthService, NEURALTRACE_EDGES
from app.core.security import create_access_token, decode_access_token
from app.core.config import settings
from app.core.rate_limit import rate_limiter
from app.routes.deps import get_current_user, verify_session_access
from app.models.user import User
from app.models.behavior import BehaviorProfile
from app.models.security_event import SecurityEvent

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(request: RegisterRequest, request_conn: Request, db: Session = Depends(get_db)):
    """Registers a new standard user. Normal public registration ALWAYS creates role=USER."""
    # Extract client IP for anti-bot rate limiting
    client_ip = request_conn.client.host if request_conn.client else "127.0.0.1"
    forwarded = request_conn.headers.get("x-forwarded-for")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()

    rate_limiter.enforce(
        key=f"auth_reg:{client_ip}",
        max_requests=40,
        window_seconds=60,
        detail="Registration rate limit exceeded. Please wait before creating another account."
    )

    # Prevent privilege escalation: Reject attempted self-assignment of ADMIN role
    if request.role and request.role.upper() == "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Privilege escalation prohibited: Cannot self-assign ADMIN role during public registration.",
        )

    existing = AuthService.get_user_by_email(db, request.email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email address already exists.",
        )

    # Pre-validate gesture factor if provided
    if request.gesture_pattern is not None:
        if not request.confirm_gesture_pattern:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Gesture pattern confirmation is required."
            )
        if request.gesture_pattern != request.confirm_gesture_pattern:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Gesture pattern confirmation does not match original pattern."
            )
        if len(request.gesture_pattern) < 4:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Gesture pattern must connect at least 4 nodes for security."
            )
        if len(request.gesture_pattern) > 16:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Gesture pattern cannot exceed 16 nodes."
            )
        for idx, node in enumerate(request.gesture_pattern):
            if not isinstance(node, int) or node < 0 or node > 15:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid node index {node}. Nodes must be integers from 0 to 15."
                )
            if idx > 0 and node == request.gesture_pattern[idx - 1]:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Gesture pattern cannot contain consecutive duplicate nodes."
                )
        if any(n > 8 for n in request.gesture_pattern):
            for idx in range(1, len(request.gesture_pattern)):
                edge = (request.gesture_pattern[idx - 1], request.gesture_pattern[idx])
                if edge not in NEURALTRACE_EDGES:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Invalid network route: nodes {edge[0]} and {edge[1]} are not connected by an active network edge."
                    )

    # Force role to USER for all public registrations
    new_user = AuthService.create_user(db, request, forced_role="USER")
    new_user.registration_source = "PUBLIC_REGISTRATION"
    require_email_verif = bool(getattr(request, "require_email_verification", False))
    if require_email_verif:
        new_user.account_status = "PENDING_VERIFICATION"
        new_user.email_verified = False
        new_user.email_verified_at = None
        new_user.security_enrollment_completed = False
    else:
        new_user.email_verified = (new_user.account_status == "ACTIVE")
        new_user.email_verified_at = datetime.now(timezone.utc) if new_user.email_verified else None
        # If factors are omitted in legacy API calls, default remains True unless require_email_verification=True
        new_user.security_enrollment_completed = True

    db.add(SecurityEvent(
        user_id=new_user.id,
        application="platform",
        event_type="USER_REGISTERED",
        severity="LOW",
        anomaly_score=0.0,
        risk_score=0.0,
        decision="ALLOW",
        details='{"registration_source": "PUBLIC_REGISTRATION", "email_verified": ' + ('true' if new_user.email_verified else 'false') + ', "require_email_verification": ' + ('true' if require_email_verif else 'false') + '}',
    ))
    db.commit()
    db.refresh(new_user)

    if require_email_verif:
        _, _, masked_email, _, delivery_status, dev_otp = StepUpService.create_email_verification_challenge(
            email=new_user.email,
            db=db,
        )
        return {
            "id": new_user.id,
            "name": new_user.name,
            "email": new_user.email,
            "role": new_user.role,
            "account_status": new_user.account_status,
            "failed_login_attempts": new_user.failed_login_attempts,
            "created_at": new_user.created_at,
            "email_verified": new_user.email_verified,
            "security_enrollment_completed": new_user.security_enrollment_completed,
            "email_verification_required": True,
            "masked_email": masked_email,
            "delivery_status": delivery_status,
            "dev_otp": dev_otp,
        }

    # Enroll verified factors atomically for the newly registered account
    if request.gesture_pattern is not None:
        AdaptiveAuthService.enroll_gesture_pattern(
            db=db,
            user_id=new_user.id,
            pattern=request.gesture_pattern,
            confirm_pattern=request.confirm_gesture_pattern or []
        )

    if request.image_sequence is not None:
        AdaptiveAuthService.enroll_image_sequence(
            db=db,
            user_id=new_user.id,
            image_sequence=request.image_sequence,
            confirm_image_sequence=request.confirm_image_sequence or []
        )

    if request.private_response is not None and request.private_question is not None:
        AdaptiveAuthService.enroll_private_response(
            db=db,
            user_id=new_user.id,
            question=request.private_question,
            response=request.private_response,
            confirm_response=request.confirm_private_response or ""
        )

    return new_user


@router.post("/bootstrap-admin", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def bootstrap_admin(
    request: BootstrapAdminRequest,
    x_bootstrap_key: Optional[str] = Header(None, alias="X-Bootstrap-Key"),
    db: Session = Depends(get_db)
):
    """
    Secure development/bootstrap mechanism to initialize an ADMIN account.
    Requires server-side secret key; not publicly accessible.
    """
    if not settings.BOOTSTRAP_ADMIN_KEY or x_bootstrap_key != settings.BOOTSTRAP_ADMIN_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing bootstrap authorization key.",
        )

    existing = AuthService.get_user_by_email(db, request.email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email address already exists.",
        )

    admin_reg = RegisterRequest(
        name=request.name,
        email=request.email,
        password=request.password,
        role="ADMIN"
    )
    admin_user = AuthService.create_user(db, admin_reg, forced_role="ADMIN")
    admin_user.registration_source = "ADMIN_BOOTSTRAP"
    db.commit()
    db.refresh(admin_user)
    return admin_user


@router.post("/login", response_model=TokenResponse)
def login(
    request: LoginRequest,
    request_conn: Request,
    user_agent: str = Header(None),
    db: Session = Depends(get_db)
):
    """Authenticates credentials, registers device context, creates session, and issues JWT bound to session_id."""
    # Extract real client IP
    client_ip = request_conn.client.host if request_conn.client else "127.0.0.1"
    forwarded = request_conn.headers.get("x-forwarded-for")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()

    # Rate limiting: anti-brute-force per IP & per account target
    rate_limiter.enforce(
        key=f"auth_login_ip:{client_ip}",
        max_requests=50,
        window_seconds=60,
        detail="Too many login attempts from this network. Please wait before retrying."
    )
    rate_limiter.enforce(
        key=f"auth_login_target:{client_ip}:{request.email.lower()}",
        max_requests=25,
        window_seconds=60,
        detail="Too many login attempts for this account. Please wait before retrying."
    )

    # Check if account is already locked
    existing_user = AuthService.get_user_by_email(db, request.email)
    if existing_user and existing_user.account_status != "ACTIVE":
        if existing_user.account_status in ("PENDING_VERIFICATION", "PENDING_EMAIL_VERIFICATION"):
            detail = "EMAIL_VERIFICATION_REQUIRED (pending_verification): Please verify your email address with the OTP code before signing in."
        elif getattr(request, "doctor_required", False):
            detail = f"Doctor account is {existing_user.account_status.lower()}. Please contact clinical administration."
        else:
            detail = f"Account is {existing_user.account_status.lower()}. Access denied."
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail,
        )

    user = AuthService.authenticate_user(db, request.email, request.password)
    if not user:
        # Record failed attempt, check 3-attempt lockout policy and audit
        db_user, is_now_locked, fails = AuthService.record_failed_login(
            db=db,
            email=request.email,
            ip_address=client_ip,
            user_agent=user_agent or request.browser or ""
        )
        if is_now_locked or (db_user and db_user.account_status != "ACTIVE"):
            if db_user and is_now_locked:
                from app.agents.execution.orchestrator import SecurityOrchestrator
                SecurityOrchestrator.dispatch_background(
                    db_bind=db.get_bind(),
                    user_id=db_user.id,
                    session_id=None,
                    application=getattr(request, "application", None) or "platform",
                    deterministic_risk_score=0.80,
                    deterministic_risk_level="HIGH",
                    contributing_reasons=[f"repeated_failed_login:{fails}"],
                    auto_containment=False,
                    skip_containment=True,
                    idempotency_key=f"login_lock:{db_user.id}:{fails}",
                    trigger_event="SUSPICIOUS_LOGIN_LOCKOUT",
                )
            if getattr(request, "doctor_required", False):
                detail = "Doctor account is locked. Please contact clinical administration."
            else:
                detail = "Account is locked. Access denied."
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=detail,
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email address or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user.account_status != "ACTIVE":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Account is {user.account_status.lower()}. Access denied.",
        )

    # Reset failed login attempt counter upon successful authentication
    if getattr(user, "failed_login_attempts", 0) != 0:
        user.failed_login_attempts = 0
        db.commit()

    # Enforce role validation when doctor login is explicitly requested
    if getattr(request, "doctor_required", False):
        if user.role.upper() not in ("DOCTOR", "ADMIN"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Account does not possess verified Doctor credentials.",
            )

    # Register or identify device with rich context & optional location
    fingerprint = request.device_fingerprint or "web_client_fp_default"
    device, is_new = DeviceService.register_or_update_device(
        db,
        user_id=user.id,
        device_fingerprint=fingerprint,
        browser=request.browser or user_agent or "Chrome/Modern",
        os=request.os or "Desktop",
        device_type="Desktop",
        ip_address=client_ip,
        latitude=request.latitude,
        longitude=request.longitude,
        location_accuracy=request.location_accuracy,
        location_source=request.location_source,
        nickname=request.nickname,
        user_agent=user_agent or request.browser
    )

    # Create session: Administrators on platform application are granted ACTIVE sessions immediately; regular portal users enter observation window
    app_name = SessionService.normalize_application(request.application) or (request.application or "platform").lower()
    if app_name in ("college", "shopping", "healthcare"):
        from app.services.portal_lock_service import PortalLockService
        active_lock = PortalLockService.get_active_lock(db, user.id, app_name)
        if active_lock:
            PortalLockService.record_reentry_attempt(
                db=db,
                user=user,
                application=app_name,
                source="CREDENTIAL_LOGIN",
                client_ip=client_ip,
                user_agent=user_agent or request.browser or "",
            )
            PortalLockService.raise_locked_http_exception(active_lock)
    is_privileged = (user.role.upper() == "ADMIN") and (app_name == "platform")
    active_session = SessionService.create_session(
        db,
        user_id=user.id,
        application=app_name,
        device_id=device.id,
        ip_address=client_ip,
        status="ACTIVE" if is_privileged else "PENDING_OBSERVATION",
        is_pending_observation=False if is_privileged else True
    )

    # Retrieve user's behavioral baseline from DB if established and ensure ML anomaly detector is hydrated
    user_profile = db.query(BehaviorProfile).filter(BehaviorProfile.user_id == user.id).first()
    if user_profile and user_profile.sample_count > 0:
        ModelManager.ensure_hydrated(db, user.id, ProfileService.get_profile_dict(user_profile))

    # Trigger security notification & email if unfamiliar/new device
    if is_new:
        from app.services.notification_service import NotificationService
        NotificationService.notify_new_device_login(
            db=db,
            user=user,
            device=device,
            ip_address=client_ip,
            session_id=active_session.id
        )

    # Generate JWT access token cryptographically bound to session_id (sid)
    access_token = create_access_token(
        subject=user.id,
        role=user.role,
        session_id=active_session.id
    )

    from app.services.portal_lock_service import PortalLockService
    active_portal_lock = PortalLockService.get_active_lock(db, user.id, app_name)
    if active_portal_lock:
        active_session.status = "RESTRICTED"
        active_session.login_outcome = "portal_locked"
        db.commit()
        lock_payload = PortalLockService.record_reentry_attempt(
            db=db,
            user=user,
            application=app_name,
            session_id=active_session.id,
            client_ip=client_ip,
            user_agent=user_agent or request.browser or "",
            source="CREDENTIAL_LOGIN",
        ) or PortalLockService.serialize_lock(active_portal_lock)
        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            role=user.role,
            user_id=user.id,
            name=user.name,
            email=user.email,
            session_id=active_session.id,
            session_status="RESTRICTED",
            observation_seconds_remaining=0,
            is_new_device=is_new,
            device_id=device.device_id,
            trust_state=device.trust_state,
            portal_locked=True,
            portal_lock=lock_payload,
        )

    # Record genuine user LOGIN_SUCCESS event for Security Intelligence
    db.add(SecurityEvent(
        user_id=user.id,
        session_id=active_session.id,
        application=app_name,
        event_type="LOGIN_SUCCESS",
        severity="LOW",
        anomaly_score=0.0,
        risk_score=0.0,
        decision="ALLOW",
        details=json.dumps({
            "portal": app_name,
            "is_new_device": bool(is_new),
            "device_trust_state": device.trust_state,
            "session_status": active_session.status,
        }),
    ))
    db.commit()

    enroll_status = AdaptiveAuthService.get_enrollment_status(db, user.id)
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        role=user.role,
        user_id=user.id,
        name=user.name,
        email=user.email,
        session_id=active_session.id,
        session_status=active_session.status,
        observation_seconds_remaining=0 if is_privileged else settings.OBSERVATION_WINDOW_SECONDS,
        is_new_device=is_new,
        device_id=device.device_id,
        trust_state=device.trust_state,
        security_enrollment_completed=bool(getattr(user, "security_enrollment_completed", True)),
        missing_factors=enroll_status.get("missing_factors", []),
    )


@router.get("/observation-status/{session_id}", response_model=ObservationStatusResponse)
def get_observation_status(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Returns server-authoritative observation status for a pending session.
    Enforces minimum observation window based on server clock.
    """
    session = SessionService.get_session(db, session_id)
    verify_session_access(session, current_user)

    status_data = SessionService.get_observation_status(db, session_id)
    if not status_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found."
        )
    return ObservationStatusResponse(**status_data)


@router.post("/login-otp/request", response_model=LoginOtpResponse)
def request_login_otp(
    request: LoginOtpRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Issues mandatory 6-digit login OTP after the observation window has completed.
    Server strictly enforces observation duration: rejects requests made before window elapses.
    Delivers OTP via configured Gmail SMTP service to account's registered email.
    """
    rate_limiter.enforce(
        key=f"login_otp_req:{request.session_id}",
        max_requests=10,
        window_seconds=60,
        detail="Too many verification code requests. Please wait."
    )
    session = SessionService.get_session(db, request.session_id)
    verify_session_access(session, current_user)

    from app.services.portal_lock_service import PortalLockService
    PortalLockService.enforce_not_locked(db, current_user.id, session.application)

    if session.status == "TERMINATED":
        PortalLockService.raise_terminated_http_exception(status_code=status.HTTP_401_UNAUTHORIZED)

    if session.status == "ACTIVE":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Session is already authenticated and active."
        )

    # Server-authoritative enforcement of minimum observation duration
    now = datetime.now(timezone.utc)
    started_at = session.observation_started_at
    if started_at:
        if started_at.tzinfo is None:
            started_at = started_at.replace(tzinfo=timezone.utc)
        elapsed = (now - started_at).total_seconds()
        if elapsed < (settings.OBSERVATION_WINDOW_SECONDS - 1.0) and session.status == "PENDING_OBSERVATION":
            remaining = max(1, int(settings.OBSERVATION_WINDOW_SECONDS - elapsed))
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Observation period incomplete. {remaining} second{'s' if remaining != 1 else ''} remaining."
            )

    # Server-authoritative risk-based policy handling at end of observation
    if session.current_risk_level == "CRITICAL" or session.status == "TERMINATED":
        session.status = "TERMINATED"
        session.observation_completed_at = now
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Session terminated due to critical security risk policy."
        )

    if session.current_risk_level == "HIGH" or session.status == "RESTRICTED":
        session.status = "RESTRICTED"
        session.observation_completed_at = now
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="High risk detected during observation. Access restricted; multi-factor authorization required."
        )

    # If initial login OTP has already been completed once and session later became STEP_UP_REQUIRED, do not re-use login-otp/request
    if session.status == "STEP_UP_REQUIRED" and session.login_outcome == "verified":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Session is already authenticated; complete step-up verification."
        )

    # Note: MEDIUM risk does NOT bypass initial OTP verification.
    # Initial login OTP is required after the observation window across LOW and MEDIUM risk tiers.
    # NeuralTrace gesture verification is reserved exclusively as a step-up challenge for confidential vault access.

    # Transition session to PENDING_OTP and record observation completion
    session.status = "PENDING_OTP"
    session.observation_completed_at = now
    session.login_outcome = "otp_pending"
    db.commit()

    # Generate single active login challenge bound to session and user
    challenge_data = StepUpService.create_login_otp_challenge(
        session_id=session.id,
        user_id=current_user.id,
        db=db,
        ttl_seconds=300
    )

    if session.login_otp_challenge_id != challenge_data["challenge_id"]:
        session.login_otp_challenge_id = challenge_data["challenge_id"]
        db.commit()

        from app.models.security_event import SecurityEvent
        sec_event = SecurityEvent(
            user_id=current_user.id,
            session_id=session.id,
            application=session.application,
            event_type="LOGIN_OTP_CHALLENGE_ISSUED",
            severity="LOW",
            decision="STEP_UP_VERIFICATION",
            details=f"Login OTP issued following {settings.OBSERVATION_WINDOW_SECONDS}s observation window. Dispatched to {challenge_data['masked_email']}."
        )
        db.add(sec_event)
        db.commit()

    logger.info(
        f"[COGNISEC-AI] [LOGIN_OTP_REQUEST] timestamp={now.isoformat()} "
        f"session_id={session.id} challenge_id={challenge_data['challenge_id']} "
        f"recipient={challenge_data['masked_email']} outcome=SUCCESS"
    )

    challenge_data["risk_level"] = session.current_risk_level or "LOW"
    return LoginOtpResponse(**challenge_data)


@router.post("/login-otp/verify", response_model=LoginOtpVerifyResponse)
def verify_login_otp(
    request: LoginOtpVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Atomically verifies the login OTP for a pending session.
    If valid: consumes challenge atomically, activates session, permits dashboard entry.
    If invalid: terminates pending session immediately, invalidates challenge, requires fresh login.
    """
    rate_limiter.enforce(
        key=f"login_otp_ver:{request.session_id}",
        max_requests=10,
        window_seconds=60,
        detail="Too many verification attempts. Please wait."
    )
    session = SessionService.get_session(db, request.session_id)
    verify_session_access(session, current_user)

    from app.services.portal_lock_service import PortalLockService
    PortalLockService.enforce_not_locked(db, current_user.id, session.application)

    if session.status == "TERMINATED":
        PortalLockService.raise_terminated_http_exception(status_code=status.HTTP_401_UNAUTHORIZED)

    if session.status == "ACTIVE":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Session is already authenticated and active."
        )

    success, message = StepUpService.verify_login_otp(
        session_id=request.session_id,
        user_id=current_user.id,
        otp_code=request.otp_code,
        db=db,
        challenge_id=request.challenge_id
    )

    from app.models.security_event import SecurityEvent
    if not success:
        logger.warning(
            f"[COGNISEC-AI] [LOGIN_OTP_VERIFY] timestamp={datetime.now(timezone.utc).isoformat()} "
            f"session_id={session.id} outcome=FAILURE reason={message}"
        )
        db.refresh(session)
        active_lock = PortalLockService.get_active_lock(db, current_user.id, session.application)
        is_term = (session.status == "TERMINATED")
        sec_event = SecurityEvent(
            user_id=current_user.id,
            session_id=session.id,
            application=session.application,
            event_type="LOGIN_OTP_FAILED",
            severity="HIGH",
            decision="LOCK_PORTAL" if active_lock else ("TERMINATE_SESSION" if is_term else "DENY"),
            details=message
        )
        db.add(sec_event)
        db.commit()
        db.refresh(sec_event)
        if active_lock or is_term:
            from app.agents.execution.orchestrator import SecurityOrchestrator
            SecurityOrchestrator.dispatch_background(
                db_bind=db.get_bind(),
                event_id=sec_event.id,
                user_id=current_user.id,
                session_id=session.id,
                application=session.application,
                deterministic_risk_score=0.88 if is_term else 0.75,
                deterministic_risk_level="CRITICAL" if is_term else "HIGH",
                contributing_reasons=["login_otp_lockout" if active_lock else "login_otp_session_terminated"],
                auto_containment=False,
                skip_containment=True,
                idempotency_key=f"login_otp_lock:{session.id}:{sec_event.id}",
                trigger_event="LOGIN_OTP_LOCKOUT",
            )
        if active_lock:
            PortalLockService.raise_locked_http_exception(active_lock, status_code=status.HTTP_423_LOCKED)
        if is_term:
            PortalLockService.raise_terminated_http_exception(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=PortalLockService.SESSION_TERMINATED_MESSAGE,
            )
        cnt_status = PortalLockService.get_attempt_counter_status(
            db,
            user_id=current_user.id,
            application=session.application,
            verification_purpose="LOGIN_OTP",
            factor_key="EMAIL_OTP",
            session_id=session.id,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message,
            headers={"X-Cognisec-Attempts-Remaining": str(cnt_status["attempts_remaining"])},
        )

    logger.info(
        f"[COGNISEC-AI] [LOGIN_OTP_VERIFY] timestamp={datetime.now(timezone.utc).isoformat()} "
        f"session_id={session.id} outcome=SUCCESS session_status=ACTIVE"
    )

    sec_event = SecurityEvent(
        user_id=current_user.id,
        session_id=session.id,
        application=session.application,
        event_type="LOGIN_OTP_VERIFIED",
        severity="LOW",
        decision="ALLOW",
        details="Login OTP verified successfully. Full session access granted."
    )
    db.add(sec_event)
    db.commit()

    return LoginOtpVerifyResponse(
        success=True,
        decision="ALLOW",
        session_status="ACTIVE",
        message="Login verification successful. Full access granted."
    )


@router.post("/login-otp/resend", response_model=LoginOtpResponse)
def resend_login_otp(
    request: LoginOtpRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Resends login OTP with rate limiting and cooldown.
    Invalidates previous challenge and dispatches a fresh 6-digit code.
    """
    rate_limiter.enforce(
        key=f"login_otp_resend:{request.session_id}",
        max_requests=3,
        window_seconds=60,
        detail="Too many resend attempts. Please wait before requesting another verification code."
    )
    session = SessionService.get_session(db, request.session_id)
    verify_session_access(session, current_user)

    from app.services.portal_lock_service import PortalLockService
    PortalLockService.enforce_not_locked(db, current_user.id, session.application)

    if session.status == "TERMINATED":
        PortalLockService.raise_terminated_http_exception(status_code=status.HTTP_401_UNAUTHORIZED)

    if session.status == "ACTIVE":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Session is already authenticated and active."
        )

    challenge_data = StepUpService.resend_login_otp_challenge(
        session_id=session.id,
        user_id=current_user.id,
        db=db,
        ttl_seconds=300
    )

    from app.models.security_event import SecurityEvent
    sec_event = SecurityEvent(
        user_id=current_user.id,
        session_id=session.id,
        application=session.application,
        event_type="LOGIN_OTP_RESENT",
        severity="LOW",
        decision="STEP_UP_VERIFICATION",
        details=f"Fresh Login OTP challenge {challenge_data['challenge_id']} dispatched to {challenge_data['masked_email']}."
    )
    db.add(sec_event)
    db.commit()

    challenge_data["risk_level"] = session.current_risk_level or "LOW"
    return LoginOtpResponse(**challenge_data)


@router.get("/me", response_model=UserResponse)
def get_current_user_profile(current_user: User = Depends(get_current_user)):
    """Retrieves profile of currently authenticated user."""
    return current_user


@router.post("/logout")
def logout(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Invalidates active session upon sign out.
    Enforces that users can only terminate their own sessions (unless ADMIN).
    """
    session = SessionService.get_session(db, session_id)
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found.")

    if session.user_id != current_user.id and current_user.role.upper() != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized: Cannot terminate another user's session."
        )

    SessionService.terminate_session(db, session_id)
    db.add(SecurityEvent(
        user_id=session.user_id,
        session_id=session.id,
        application=session.application or "platform",
        event_type="SESSION_LOGOUT",
        severity=session.current_risk_level or "LOW",
        anomaly_score=0.0,
        risk_score=float(getattr(session, "risk_score", 0.0) or 0.0),
        decision="ALLOW",
        details=json.dumps({
            "portal": session.application or "platform",
            "terminated_by_user_id": current_user.id,
        }),
    ))
    db.commit()
    return {"status": "success", "message": "Session terminated successfully."}


class VerifyEmailRequest(BaseModel):
    email: str
    verification_code: str


class ResendVerificationRequest(BaseModel):
    email: str


@router.post("/resend-verification")
def resend_verification_email(
    request: ResendVerificationRequest,
    request_conn: Request,
    db: Session = Depends(get_db)
):
    """Resends the 6-digit email verification OTP for a newly registered account."""
    client_ip = request_conn.client.host if request_conn.client else "127.0.0.1"
    rate_limiter.enforce(
        key=f"resend_email_verif:{client_ip}:{request.email.lower().strip()}",
        max_requests=5,
        window_seconds=60,
        detail="Too many verification code requests. Please wait before retrying."
    )
    normalized_email = request.email.lower().strip()
    user = AuthService.get_user_by_email(db, normalized_email)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account with this email does not exist.")
    if user.account_status == "ACTIVE" and user.email_verified:
        return {"status": "ACTIVE", "message": "Email is already verified."}

    _, msg_text, masked_email, _, delivery_status, dev_otp = StepUpService.create_email_verification_challenge(
        email=normalized_email,
        db=db,
    )
    return {
        "success": True,
        "message": msg_text,
        "masked_email": masked_email,
        "delivery_status": delivery_status,
        "dev_otp": dev_otp,
    }


@router.post("/verify-email")
def verify_email(
    request: VerifyEmailRequest,
    request_conn: Request,
    user_agent: str = Header(None),
    db: Session = Depends(get_db)
):
    """
    Activates an unverified account upon verification of email ownership.
    Issues an authenticated platform session token so mandatory 3-factor adaptive enrollment can proceed.
    """
    normalized_email = request.email.lower().strip()
    user = AuthService.get_user_by_email(db, normalized_email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Account with this email does not exist."
        )
    if user.account_status == "ACTIVE":
        return {
            "status": "ACTIVE",
            "message": "Email is already verified.",
            "security_enrollment_completed": bool(getattr(user, "security_enrollment_completed", True)),
        }

    if user.account_status == "PENDING_EMAIL_VERIFICATION" or StepUpService.has_email_verification_challenge(normalized_email):
        ok, err_msg = StepUpService.verify_email_verification_challenge(
            email=normalized_email,
            otp_code=request.verification_code,
        )
        if not ok:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=err_msg
            )
    else:
        if not request.verification_code or len(request.verification_code.strip()) < 4:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired email verification code."
            )

    AuthService.activate_user_account(db, normalized_email)
    user.email_verified = True
    user.email_verified_at = datetime.now(timezone.utc)

    client_ip = request_conn.client.host if request_conn.client else "127.0.0.1"
    device, _ = DeviceService.register_or_update_device(
        db=db,
        user_id=user.id,
        device_fingerprint=f"reg_{user.id}",
        ip_address=client_ip,
        user_agent=user_agent or "",
    )
    enroll_session = SessionService.create_session(
        db,
        user_id=user.id,
        application="platform",
        device_id=device.id,
        ip_address=client_ip,
        status="ACTIVE",
        is_pending_observation=False,
    )
    access_token = create_access_token(
        subject=user.id,
        role=user.role,
        session_id=enroll_session.id,
    )

    db.add(SecurityEvent(
        user_id=user.id,
        session_id=enroll_session.id,
        application="platform",
        event_type="EMAIL_VERIFICATION_COMPLETED",
        severity="LOW",
        anomaly_score=0.0,
        risk_score=0.0,
        decision="ALLOW",
        details='{"email_verified": true}',
    ))
    db.commit()
    db.refresh(user)

    enroll_status = AdaptiveAuthService.get_enrollment_status(db, user.id)
    return {
        "status": "ACTIVE",
        "message": "Email verified successfully. Account activated.",
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
        "name": user.name,
        "email": user.email,
        "role": user.role,
        "session_id": enroll_session.id,
        "security_enrollment_completed": bool(getattr(user, "security_enrollment_completed", True)),
        "missing_factors": enroll_status.get("missing_factors", []),
    }


@router.post("/password-reset/request", response_model=PasswordResetResponse)
def request_password_reset(
    request: PasswordResetRequest,
    request_conn: Request,
    db: Session = Depends(get_db)
):
    """
    Initiates account password recovery by delivering a 6-digit OTP to the registered email address.
    Protected against brute-force and account enumeration.
    """
    client_ip = request_conn.client.host if request_conn.client else "127.0.0.1"
    rate_limiter.enforce(
        key=f"pwd_reset_req:{client_ip}:{request.email.lower().strip()}",
        max_requests=10,
        window_seconds=60,
        detail="Too many password reset requests. Please wait before retrying."
    )

    success, message, masked_email, email_delivered, delivery_status, return_otp = StepUpService.create_password_reset_challenge(
        email=request.email,
        db=db,
        ttl_seconds=300
    )
    return PasswordResetResponse(
        success=success,
        masked_email=masked_email,
        message=message,
        email_delivered=email_delivered,
        delivery_status=delivery_status,
        otp=return_otp
    )


@router.post("/password-reset/resend", response_model=PasswordResetResponse)
def resend_password_reset(
    request: PasswordResetResendRequest,
    request_conn: Request,
    db: Session = Depends(get_db)
):
    """
    Resends a fresh 6-digit verification code to the registered email address.
    Enforces a strict 30-second cooldown between successive resend attempts.
    Supersedes previous OTPs. Protected against enumeration.
    """
    client_ip = request_conn.client.host if request_conn.client else "127.0.0.1"
    rate_limiter.enforce(
        key=f"pwd_reset_resend_ip:{client_ip}",
        max_requests=15,
        window_seconds=60,
        detail="Too many resend attempts from this network. Please wait."
    )
    rate_limiter.enforce(
        key=f"pwd_reset_resend:{client_ip}:{request.email.lower().strip()}",
        max_requests=8,
        window_seconds=60,
        detail="Too many resend requests for this account. Please wait before retrying."
    )

    success, message, masked_email, retry_after, email_delivered, delivery_status = StepUpService.resend_password_reset_challenge(
        email=request.email,
        db=db,
        ttl_seconds=300,
        cooldown_seconds=30
    )
    if not success:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=message,
            headers={"Retry-After": str(retry_after)}
        )

    return PasswordResetResponse(
        success=True,
        masked_email=masked_email,
        message=message,
        email_delivered=email_delivered,
        delivery_status=delivery_status
    )


@router.post("/password-reset/verify", response_model=PasswordResetVerifyResponse)
def verify_password_reset(
    request: PasswordResetVerifyRequest,
    request_conn: Request,
    db: Session = Depends(get_db)
):
    """
    Verifies the password reset OTP and safely updates the account's password.
    Preserves all existing user records, devices, sessions, and behavioral biometrics.
    """
    if request.confirm_password is not None and request.confirm_password != request.new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passwords do not match. Please verify both fields."
        )
    client_ip = request_conn.client.host if request_conn.client else "127.0.0.1"
    rate_limiter.enforce(
        key=f"pwd_reset_verify:{client_ip}:{request.email.lower().strip()}",
        max_requests=15,
        window_seconds=60,
        detail="Too many verification attempts. Please wait."
    )

    is_valid, err_msg = StepUpService.verify_password_reset_challenge(
        email=request.email,
        otp_code=request.otp_code
    )
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=err_msg
        )

    updated_user = AuthService.update_user_password(
        db=db,
        email=request.email,
        new_password=request.new_password
    )
    if not updated_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User account not found."
        )

    # Revoke all existing sessions for zero-trust post-reset hygiene
    revoked_count = SessionService.terminate_all_user_sessions(db, updated_user.id)

    # Log persistent security event
    sec_event = SecurityEvent(
        user_id=updated_user.id,
        application="platform",
        event_type="PASSWORD_RESET_SUCCESS",
        severity="LOW",
        decision="ALLOW",
        details=f"Password successfully reset via verified email OTP. {revoked_count} prior sessions terminated. Client IP: {client_ip}."
    )
    db.add(sec_event)
    db.commit()

    logger.info(f"[COGNISEC-AI] [PASSWORD_RESET] Successfully updated password for {request.email}. {revoked_count} sessions revoked.")
    return PasswordResetVerifyResponse(
        success=True,
        message="Password has been successfully updated. You may now sign in."
    )


@router.post("/recover-account", response_model=PasswordResetVerifyResponse)
def recover_account_dev(
    request: RecoverAccountRequest,
    x_bootstrap_key: Optional[str] = Header(None, alias="X-Bootstrap-Key"),
    db: Session = Depends(get_db)
):
    """
    Secure local-development / administrative recovery mechanism.
    Requires server-side BOOTSTRAP_ADMIN_KEY; safely updates password without deleting user data.
    """
    if not settings.BOOTSTRAP_ADMIN_KEY or x_bootstrap_key != settings.BOOTSTRAP_ADMIN_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing bootstrap authorization key."
        )

    user = AuthService.get_user_by_email(db, request.email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Account with this email does not exist."
        )

    AuthService.update_user_password(db, request.email, request.new_password)
    rate_limiter.clear_keys_matching(request.email.lower().strip())
    logger.info(f"[COGNISEC-AI] [DEV_RECOVERY] Account {request.email} password restored via authorized bootstrap key.")
    return PasswordResetVerifyResponse(
        success=True,
        message="Account password has been restored. All existing records preserved."
    )


@router.post("/dev-unlock-account", response_model=PasswordResetVerifyResponse)
def dev_unlock_account(
    request: UnlockAccountRequest,
    request_conn: Request,
    x_bootstrap_key: Optional[str] = Header(None, alias="X-Bootstrap-Key"),
    db: Session = Depends(get_db)
):
    """
    Secure development recovery mechanism to clear failed-attempt counters and restore ACTIVE status.
    Protected by:
    1. Development environment or exhibition mode.
    2. Localhost requester (127.0.0.1, ::1, localhost, testclient).
    3. Server-side BOOTSTRAP_ADMIN_KEY.
    """
    env = getattr(settings, "ENVIRONMENT", "").lower().strip()
    is_dev = env in ("development", "dev", "test") or getattr(settings, "EXHIBITION_MODE", False)
    if not is_dev:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Development lockout reset is disabled in production environments."
        )

    if not settings.BOOTSTRAP_ADMIN_KEY or x_bootstrap_key != settings.BOOTSTRAP_ADMIN_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing bootstrap authorization key."
        )

    client_ip = request_conn.client.host if request_conn.client else "127.0.0.1"
    forwarded = request_conn.headers.get("x-forwarded-for")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()

    if client_ip not in ("127.0.0.1", "::1", "localhost", "testclient"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Development lockout reset is restricted to local workstation access (localhost only)."
        )

    user = AuthService.get_user_by_email(db, request.email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target account '{request.email}' not found."
        )

    user.failed_login_attempts = 0
    user.account_status = "ACTIVE"

    # Clear rate limiter keys for this email and IP
    rate_limiter.clear_keys_matching(request.email.lower().strip())
    rate_limiter.clear_keys_matching(client_ip)

    import json
    from app.models.security_event import SecurityEvent
    sec_event = SecurityEvent(
        user_id=user.id,
        application="platform",
        event_type="DEV_LOCKOUT_RESET",
        severity="LOW",
        decision="ALLOW",
        details=json.dumps({
            "action": "DEV_LOCKOUT_RESET",
            "target_email": user.email,
            "ip_address": client_ip
        })
    )
    db.add(sec_event)
    db.commit()

    logger.info(f"[COGNISEC-AI] [DEV_LOCKOUT_RESET] Account {request.email} unlocked via authorized bootstrap key.")
    return PasswordResetVerifyResponse(
        success=True,
        message=f"Account '{request.email}' has been successfully unlocked. All existing records preserved."
    )


# ==============================================================================
# AUTHENTICATED COGNITIVE-VERIFIED PASSWORD CHANGE ROUTES (ALL PORTALS)
# ==============================================================================

def _extract_auth_ctx(
    request_conn: Request,
    authorization: Optional[str],
    x_session_id: Optional[str],
) -> tuple:
    client_ip = request_conn.client.host if request_conn.client else "127.0.0.1"
    forwarded = request_conn.headers.get("x-forwarded-for")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()

    token_sid = None
    if authorization and authorization.lower().startswith("bearer "):
        payload = decode_access_token(authorization[7:].strip())
        if payload:
            token_sid = payload.get("sid")
    return client_ip, token_sid, x_session_id


@router.get("/password-change/policy", response_model=PasswordChangePolicyResponse)
def get_password_change_policy(
    request_conn: Request,
    application: str = "platform",
    session_id: Optional[str] = None,
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_session_id: Optional[str] = Header(None, alias="X-Session-ID"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Returns enrollment inventory, cognitive catalogue, and deterministic risk posture for password change."""
    _, token_sid, hdr_sid = _extract_auth_ctx(request_conn, authorization, x_session_id)
    db_session = PasswordChangeService.resolve_and_validate_session(
        db=db,
        current_user=current_user,
        requested_session_id=session_id or hdr_sid,
        token_session_id=token_sid,
    )
    data = PasswordChangeService.get_policy(
        db=db,
        current_user=current_user,
        db_session=db_session,
        application=application,
    )
    return PasswordChangePolicyResponse(**data)


@router.post("/password-change/initiate", response_model=PasswordChangeInitiateResponse)
def initiate_password_change(
    request: PasswordChangeInitiateRequest,
    request_conn: Request,
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_session_id: Optional[str] = Header(None, alias="X-Session-ID"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Verifies current password and behavioral risk, then issues bound two-part cognitive challenges."""
    client_ip, token_sid, hdr_sid = _extract_auth_ctx(request_conn, authorization, x_session_id)
    rate_limiter.enforce(
        key=f"pwd_chg_init:{current_user.id}:{client_ip}",
        max_requests=12,
        window_seconds=60,
        detail="Too many password change attempts. Please wait before retrying."
    )
    db_session = PasswordChangeService.resolve_and_validate_session(
        db=db,
        current_user=current_user,
        requested_session_id=request.session_id or hdr_sid,
        token_session_id=token_sid,
    )
    data = PasswordChangeService.initiate_change(
        db=db,
        current_user=current_user,
        db_session=db_session,
        application=request.application,
        current_password=request.current_password,
        bound_high_risk_challenge_id=request.bound_high_risk_challenge_id,
    )
    return PasswordChangeInitiateResponse(**data)


@router.post("/password-change/verify-image", response_model=PasswordChangeVerifyImageResponse)
def verify_password_change_image(
    request: PasswordChangeVerifyImageRequest,
    request_conn: Request,
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_session_id: Optional[str] = Header(None, alias="X-Session-ID"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Cognitive Step 1: verifies user's image sequence bound to the password-change transaction."""
    client_ip, token_sid, hdr_sid = _extract_auth_ctx(request_conn, authorization, x_session_id)
    rate_limiter.enforce(
        key=f"pwd_chg_img:{current_user.id}:{client_ip}",
        max_requests=15,
        window_seconds=60,
        detail="Too many cognitive verification attempts. Please wait."
    )
    db_session = PasswordChangeService.resolve_and_validate_session(
        db=db,
        current_user=current_user,
        requested_session_id=request.session_id or hdr_sid,
        token_session_id=token_sid,
    )
    data = PasswordChangeService.verify_image_challenge(
        db=db,
        current_user=current_user,
        db_session=db_session,
        application=request.application,
        transaction_id=request.transaction_id,
        image_challenge_id=request.image_challenge_id,
        image_sequence=request.image_sequence,
    )
    return PasswordChangeVerifyImageResponse(**data)


@router.post("/password-change/verify-private", response_model=PasswordChangeVerifyPrivateResponse)
def verify_password_change_private(
    request: PasswordChangeVerifyPrivateRequest,
    request_conn: Request,
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_session_id: Optional[str] = Header(None, alias="X-Session-ID"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Cognitive Step 2: verifies user's private security response bound to the same transaction."""
    client_ip, token_sid, hdr_sid = _extract_auth_ctx(request_conn, authorization, x_session_id)
    rate_limiter.enforce(
        key=f"pwd_chg_priv:{current_user.id}:{client_ip}",
        max_requests=15,
        window_seconds=60,
        detail="Too many security response verification attempts. Please wait."
    )
    db_session = PasswordChangeService.resolve_and_validate_session(
        db=db,
        current_user=current_user,
        requested_session_id=request.session_id or hdr_sid,
        token_session_id=token_sid,
    )
    data = PasswordChangeService.verify_private_challenge(
        db=db,
        current_user=current_user,
        db_session=db_session,
        application=request.application,
        transaction_id=request.transaction_id,
        private_challenge_id=request.private_challenge_id,
        private_response=request.private_response,
    )
    return PasswordChangeVerifyPrivateResponse(**data)


@router.post("/password-change/confirm", response_model=PasswordChangeConfirmResponse)
def confirm_password_change(
    request: PasswordChangeConfirmRequest,
    request_conn: Request,
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_session_id: Optional[str] = Header(None, alias="X-Session-ID"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Atomically updates password after confirming both cognitive checks, invalidates sessions, and sends security email."""
    client_ip, token_sid, hdr_sid = _extract_auth_ctx(request_conn, authorization, x_session_id)
    rate_limiter.enforce(
        key=f"pwd_chg_confirm:{current_user.id}:{client_ip}",
        max_requests=10,
        window_seconds=60,
        detail="Too many password update requests. Please wait."
    )
    db_session = PasswordChangeService.resolve_and_validate_session(
        db=db,
        current_user=current_user,
        requested_session_id=request.session_id or hdr_sid,
        token_session_id=token_sid,
    )
    data = PasswordChangeService.confirm_password_change(
        db=db,
        current_user=current_user,
        db_session=db_session,
        application=request.application,
        transaction_id=request.transaction_id,
        new_password=request.new_password,
        confirm_password=request.confirm_password,
        client_ip=client_ip,
        bound_high_risk_challenge_id=request.bound_high_risk_challenge_id,
    )
    return PasswordChangeConfirmResponse(**data)
