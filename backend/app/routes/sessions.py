from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.schemas.session import SessionStartRequest, SessionResponse
from app.services.session_service import SessionService
from app.services.device_service import DeviceService
from app.routes.deps import get_current_user
from app.models.user import User

router = APIRouter(prefix="/sessions", tags=["Sessions"])


@router.post("/start", response_model=SessionResponse)
def start_session(
    request: SessionStartRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Starts an application-specific session (college, ecommerce, healthcare, platform)."""
    device, _ = DeviceService.register_or_update_device(
        db,
        user_id=current_user.id,
        device_fingerprint=request.device_fingerprint or "unknown_client",
        browser=request.browser,
        os=request.os
    )

    session = SessionService.create_session(
        db,
        user_id=current_user.id,
        application=request.application.lower(),
        device_id=device.id,
        ip_address=request.ip_address or "127.0.0.1"
    )
    return session


@router.get("/active", response_model=List[SessionResponse])
def get_active_sessions(
    application: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Returns active sessions for the current user."""
    return SessionService.get_active_sessions(db, application=application, user_id=current_user.id)


@router.post("/{session_id}/terminate", response_model=SessionResponse)
def terminate_session(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Terminates an active session."""
    session = SessionService.get_session(db, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found.")
    if session.user_id != current_user.id and current_user.role != "ADMIN":
        raise HTTPException(status_code=403, detail="Unauthorized to terminate this session.")
    
    updated = SessionService.terminate_session(db, session_id)
    return updated
