import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Header, status
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.models.user import User
from app.services.healthcare_service import HealthcareService
from app.services.auth_service import AuthService
from app.services.device_service import DeviceService
from app.services.session_service import SessionService
from app.core.security import create_access_token
from app.core.rate_limit import rate_limiter
import json
from app.routes.deps import get_current_user, require_admin, get_optional_current_user
from app.models.security_event import SecurityEvent
from app.schemas.admin import DevResetLockoutRequest, DevResetLockoutResponse
from app.core.config import settings
from app.services.step_up_service import StepUpService
from app.schemas.healthcare import (
    DoctorResponse,
    DepartmentResponse,
    AppointmentCreateRequest,
    AppointmentResponse,
    DoctorLoginRequest,
    DoctorProfileResponse,
    AppointmentOtpRequest,
    AppointmentOtpResponse,
    AppointmentOtpVerifyRequest,
    AppointmentOtpVerifyResponse,
    AppointmentOtpResendRequest
)
from app.schemas.auth import TokenResponse

logger = logging.getLogger("cognisec.healthcare")
router = APIRouter(prefix="/healthcare", tags=["Healthcare Portal & OPD Services"])


@router.get("/departments", response_model=List[DepartmentResponse])
def get_departments():
    """Returns verified hospital clinical departments."""
    return HealthcareService.get_departments()


@router.get("/doctors", response_model=List[DoctorResponse])
def get_doctors(dept: Optional[str] = Query(None, description="Filter by department id")):
    """Returns verified hospital consultant staff with credentials, rooms, and fees."""
    return HealthcareService.get_doctors(dept=dept)


@router.get("/doctors/{doctor_id}", response_model=DoctorResponse)
def get_doctor_by_id(doctor_id: str):
    """Retrieves verified physician profile."""
    doc = HealthcareService.get_doctor_by_id(doctor_id)
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Doctor '{doctor_id}' not found in hospital registry."
        )
    return DoctorResponse(**doc)


@router.get("/availability")
def check_availability(
    doctor_id: str = Query(..., description="Doctor ID"),
    date: str = Query(..., description="Appointment date (YYYY-MM-DD)"),
    slot: str = Query(..., description="Time slot (e.g. '11:00 AM')"),
    db: Session = Depends(get_db)
):
    """Checks whether an appointment slot is currently available."""
    is_available = HealthcareService.check_slot_availability(db, doctor_id, date, slot)
    return {
        "available": is_available,
        "doctor_id": doctor_id,
        "date": date,
        "slot": slot
    }


@router.post("/appointment-otp/request", response_model=AppointmentOtpResponse)
def request_appointment_otp(
    request: AppointmentOtpRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Initiates outpatient appointment verification OTP for AyuSync MedCare.
    Dispatches a single-use 6-digit code via Gmail SMTP to user's registered address (boomikaram35@gmail.com).
    Binds challenge to patient details, doctor, date, time slot, session, and user.
    """
    if not request.session_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Session ID is required."
        )

    session = SessionService.get_session(db, request.session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found."
        )

    if session.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Session does not belong to the authenticated user."
        )

    if session.status in ("TERMINATED", "REVOKED") or session.current_risk_level == "CRITICAL":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Session is terminated or restricted by security policy."
        )

    if session.status in ("PENDING_OBSERVATION", "PENDING_OTP"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Baseline behavioral observation or initial login verification is incomplete."
        )

    appointment_data = {
        "doctor_id": request.doctor_id,
        "appointment_date": request.appointment_date,
        "time_slot": request.time_slot,
        "patient_name": request.patient_name,
        "patient_phone": request.patient_phone,
        "patient_email": request.patient_email,
        "department": request.department,
        "consultation_mode": request.consultation_mode,
        "room": request.room
    }

    challenge_data = StepUpService.create_appointment_otp_challenge(
        session_id=session.id,
        user_id=current_user.id,
        appointment_data=appointment_data,
        db=db
    )

    return AppointmentOtpResponse(**challenge_data)


@router.post("/appointment-otp/verify", response_model=AppointmentOtpVerifyResponse)
def verify_appointment_otp(
    request: AppointmentOtpVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Atomically verifies the single-use appointment OTP code.
    Upon success: re-checks slot availability, persists HealthcareAppointment, and logs security event.
    Upon failure: rejects booking, decrements remaining attempts.
    """
    session = SessionService.get_session(db, request.session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found."
        )

    if session.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Session does not belong to the authenticated user."
        )

    success, message, appointment = StepUpService.verify_appointment_otp(
        session_id=request.session_id,
        user_id=current_user.id,
        challenge_id=request.challenge_id,
        otp_code=request.otp_code,
        db=db
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message
        )

    return AppointmentOtpVerifyResponse(
        success=True,
        reference_id=appointment.reference_id,
        status="CONFIRMED",
        message="Appointment confirmed successfully.",
        appointment=AppointmentResponse.model_validate(appointment)
    )


@router.post("/appointment-otp/resend", response_model=AppointmentOtpResponse)
def resend_appointment_otp(
    request: AppointmentOtpResendRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Resends appointment verification OTP subject to 15s cooldown.
    """
    session = SessionService.get_session(db, request.session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found."
        )

    if session.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Session does not belong to the authenticated user."
        )

    challenge_data = StepUpService.resend_appointment_otp_challenge(
        session_id=request.session_id,
        user_id=current_user.id,
        challenge_id=request.challenge_id,
        db=db
    )

    return AppointmentOtpResponse(**challenge_data)


@router.post("/appointments", response_model=AppointmentResponse, status_code=status.HTTP_201_CREATED)
def book_appointment(
    request: AppointmentCreateRequest,
    current_user: Optional[User] = Depends(get_optional_current_user),
    db: Session = Depends(get_db)
):
    """
    Atomically books and persists a patient outpatient appointment in the hospital database.
    Validates specialist availability, department, and patient contact parameters.
    """
    rate_limiter.enforce(
        key=f"appointment_booking:{request.patient_email}",
        max_requests=15,
        window_seconds=60,
        detail="Too many appointment booking attempts. Please wait a moment."
    )

    appointment = HealthcareService.create_appointment(
        db=db,
        req=request,
        user_id=current_user.id if current_user else None
    )
    return appointment


@router.get("/appointments", response_model=List[AppointmentResponse])
def list_appointments(
    email: Optional[str] = Query(None, description="Patient email address to retrieve appointments"),
    current_user: Optional[User] = Depends(get_optional_current_user),
    db: Session = Depends(get_db)
):
    """Retrieves persisted appointments for patient view."""
    if current_user and current_user.role.upper() not in ("DOCTOR", "ADMIN"):
        # Regular patients can only view their own appointments
        target_email = current_user.email
        return HealthcareService.get_appointments(db=db, user_id=current_user.id, email=target_email)

    if email:
        return HealthcareService.get_appointments(db=db, email=email)
    elif current_user and current_user.role.upper() in ("DOCTOR", "ADMIN"):
        return HealthcareService.get_appointments(db=db, limit=100)
    return []


@router.post("/appointments/{reference_id}/cancel", response_model=AppointmentResponse)
def cancel_appointment(
    reference_id: str,
    patient_email: Optional[str] = Query(None, description="Patient email address for verification"),
    current_user: Optional[User] = Depends(get_optional_current_user),
    db: Session = Depends(get_db)
):
    """
    Cancels an appointment subject to patient ownership or doctor authorization rules.
    """
    return HealthcareService.cancel_appointment(
        db=db,
        reference_id=reference_id,
        current_user=current_user,
        patient_email=patient_email
    )


@router.post("/doctor/login", response_model=TokenResponse)
def doctor_login(
    request: DoctorLoginRequest,
    request_conn: Request,
    user_agent: str = Header(None),
    db: Session = Depends(get_db)
):
    """
    Dedicated medical officer sign-in endpoint.
    - Validates physician credentials.
    - Authoritatively validates DOCTOR (or ADMIN) role in the database.
    - Rejects unauthorized accounts (such as students or patients) with HTTP 403 Forbidden.
    - Binds session to healthcare application and issues cryptographic JWT.
    """
    client_ip = request_conn.client.host if request_conn.client else "127.0.0.1"
    forwarded = request_conn.headers.get("x-forwarded-for")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()

    rate_limiter.enforce(
        key=f"doctor_login_ip:{client_ip}",
        max_requests=30,
        window_seconds=60,
        detail="Too many sign-in attempts from this workstation network."
    )

    # Check if account is already locked
    existing_user = AuthService.get_user_by_email(db, request.email)
    if existing_user and existing_user.account_status != "ACTIVE":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Doctor account is {existing_user.account_status.lower()}. Please contact clinical administration.",
        )

    user = AuthService.authenticate_user(db, request.email, request.password)
    if not user:
        db_user, is_now_locked, fails = AuthService.record_failed_login(
            db=db,
            email=request.email,
            ip_address=client_ip,
            user_agent=user_agent or request.browser or ""
        )
        if is_now_locked or (db_user and db_user.account_status != "ACTIVE"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Doctor account is locked. Please contact clinical administration.",
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid doctor registration credentials or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user.account_status != "ACTIVE":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Doctor account is {user.account_status.lower()}. Please contact clinical administration.",
        )

    # Reset failed attempts upon successful doctor authentication
    if getattr(user, "failed_login_attempts", 0) != 0:
        user.failed_login_attempts = 0
        db.commit()

    # Strictly enforce doctor/clinical permission boundary
    if user.role.upper() not in ("DOCTOR", "ADMIN"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized: Physician credentials required. This account does not possess clinical doctor permissions.",
        )

    # Register/identify device
    fingerprint = request.device_fingerprint or "doc_workstation_fp_default"
    device, is_new = DeviceService.register_or_update_device(
        db,
        user_id=user.id,
        device_fingerprint=fingerprint,
        browser=request.browser or user_agent or "Clinical-Browser/Modern",
        os=request.os or "Clinical-OS",
        device_type="Desktop",
        ip_address=client_ip,
        nickname="Hospital Workstation"
    )

    # Provision clinical workstation session entering 20-second mandatory behavioral observation window
    active_session = SessionService.create_session(
        db,
        user_id=user.id,
        application="healthcare",
        device_id=device.id,
        ip_address=client_ip,
        status="PENDING_OBSERVATION",
        is_pending_observation=True
    )

    access_token = create_access_token(
        subject=user.id,
        role=user.role,
        session_id=active_session.id
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        role=user.role,
        user_id=user.id,
        name=user.name,
        email=user.email,
        session_id=active_session.id,
        session_status=active_session.status,
        observation_seconds_remaining=settings.OBSERVATION_WINDOW_SECONDS,
        is_new_device=is_new,
        device_id=device.device_id,
        trust_state=device.trust_state
    )


@router.get("/doctor/profile", response_model=DoctorProfileResponse)
def get_doctor_profile(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Returns clinical profile and current workstation state for authenticated physician."""
    if current_user.role.upper() not in ("DOCTOR", "ADMIN"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized: Access restricted to verified hospital medical staff."
        )

    doc_meta = HealthcareService.get_doctor_details_for_user(current_user) or {}
    return DoctorProfileResponse(
        id=current_user.id,
        name=current_user.name,
        email=current_user.email,
        role=current_user.role,
        department=doc_meta.get("dept_label", "Multispecialty Consultation"),
        license_no=doc_meta.get("reg", "KMC Verified"),
        opd_room=doc_meta.get("room", "Clinical Wing")
    )


@router.post("/dev/reset-lockout", response_model=DevResetLockoutResponse)
def healthcare_dev_reset_account_lockout(
    request: DevResetLockoutRequest,
    request_conn: Request,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Healthcare portal development-only administrative endpoint to clear doctor lockout.
    Enforces dev environment, localhost access, and admin credentials.
    """
    env = getattr(settings, "ENVIRONMENT", "").lower().strip()
    if env not in ("development", "dev", "test"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Development administrative lockout reset is disabled in production environments."
        )

    client_ip = request_conn.client.host if request_conn.client else "127.0.0.1"
    forwarded = request_conn.headers.get("x-forwarded-for")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()

    if client_ip not in ("127.0.0.1", "::1", "localhost", "testclient"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Development administrative reset is restricted to local workstation access (localhost only)."
        )

    target_user = AuthService.get_user_by_email(db, request.email)
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Target account '{request.email}' not found.")

    target_user.failed_login_attempts = 0
    target_user.account_status = "ACTIVE"

    db.query(SecurityEvent).filter(
        SecurityEvent.user_id == target_user.id,
        SecurityEvent.event_type == "STEP_UP_LOCKED"
    ).delete(synchronize_session=False)

    rate_limiter.clear_keys_matching(request.email.lower().strip())
    rate_limiter.clear_keys_matching(client_ip)

    sec_event = SecurityEvent(
        user_id=target_user.id,
        application="healthcare",
        event_type="ADMIN_LOCKOUT_RESET",
        severity="LOW",
        decision="ALLOW",
        details=json.dumps({
            "action": "DEV_LOCKOUT_RESET",
            "target_email": target_user.email,
            "target_role": target_user.role,
            "reset_by_admin": current_admin.email,
            "admin_id": current_admin.id,
            "client_ip": client_ip,
            "environment": env
        })
    )
    db.add(sec_event)
    db.commit()
    db.refresh(target_user)

    return DevResetLockoutResponse(
        success=True,
        message=f"Doctor account lockout and failed login attempts counter successfully reset for '{target_user.email}'.",
        account_status=target_user.account_status,
        failed_login_attempts=target_user.failed_login_attempts,
        target_email=target_user.email
    )

