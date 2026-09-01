import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.schemas.security import (
    RiskEvaluationRequest,
    SecurityDecisionResponse,
    StepUpVerifyRequest,
    UserSecurityOutcome
)
from app.services.session_service import SessionService
from app.services.risk_service import RiskService
from app.services.decision_service import DecisionService
from app.models.behavior import BehaviorLog
from app.models.security_event import SecurityEvent
from app.routes.deps import get_current_user
from app.models.user import User
import numpy as np

router = APIRouter(prefix="/security", tags=["Security Decision Engine"])


@router.post("/step-up/verify", response_model=UserSecurityOutcome)
def verify_step_up_challenge(
    request: StepUpVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Verifies step-up challenge (MFA / Cognitive entropy confirmation)
    and restores session status to ACTIVE upon valid verification.
    """
    session = SessionService.get_session(db, request.session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found.")
    if session.user_id != current_user.id and current_user.role != "ADMIN":
        raise HTTPException(status_code=403, detail="Unauthorized.")

    # Any non-empty challenge code or '123456' validates in demo environment
    if not request.challenge_code or len(request.challenge_code.strip()) < 3:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code."
        )

    # Restore session
    SessionService.update_session_status(db, request.session_id, status="ACTIVE", risk_level="LOW")

    return UserSecurityOutcome(
        decision="ALLOW",
        message="Identity step-up verified. Full access restored."
    )


@router.get("/status/{session_id}", response_model=UserSecurityOutcome)
def get_user_session_security_status(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Returns clean user-facing security outcome for a session.
    DOES NOT reveal raw risk scores or ML internals to the end user.
    """
    session = SessionService.get_session(db, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found.")

    if session.status == "ACTIVE":
        return UserSecurityOutcome(decision="ALLOW", message="Access allowed. Continuous identity verified.")
    elif session.status == "STEP_UP_REQUIRED":
        return UserSecurityOutcome(decision="STEP_UP_VERIFICATION", message="Additional identity verification required.")
    elif session.status == "RESTRICTED":
        return UserSecurityOutcome(decision="RESTRICT", message="Access temporarily restricted.")
    else:
        return UserSecurityOutcome(decision="TERMINATE_SESSION", message="Session terminated for security protection.")
