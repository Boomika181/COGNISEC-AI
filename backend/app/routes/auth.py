from fastapi import APIRouter, Depends, HTTPException, status, Header
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse
from app.schemas.user import UserResponse
from app.services.auth_service import AuthService
from app.services.device_service import DeviceService
from app.services.session_service import SessionService
from app.core.security import create_access_token
from app.routes.deps import get_current_user
from app.models.user import User

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(request: RegisterRequest, db: Session = Depends(get_db)):
    """Registers a new user or administrator."""
    existing = AuthService.get_user_by_email(db, request.email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email address already exists.",
        )
    return AuthService.create_user(db, request)


@router.post("/login", response_model=TokenResponse)
def login(
    request: LoginRequest,
    user_agent: str = Header(None),
    db: Session = Depends(get_db)
):
    """Authenticates credentials, registers device context, creates session, and issues JWT."""
    user = AuthService.authenticate_user(db, request.email, request.password)
    if not user:
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

    # Register or identify device
    fingerprint = request.device_fingerprint or "web_client_fp_default"
    device, is_new = DeviceService.register_or_update_device(
        db,
        user_id=user.id,
        device_fingerprint=fingerprint,
        browser=request.browser or "Chrome/Modern",
        os=request.os or "macOS/Desktop",
        device_type="Desktop"
    )

    # Create active session for multi-app context
    app_name = (request.application or "platform").lower()
    active_session = SessionService.create_session(
        db,
        user_id=user.id,
        application=app_name,
        device_id=device.id,
        ip_address="127.0.0.1"
    )

    # Generate JWT access token
    access_token = create_access_token(subject=user.id, role=user.role)

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        role=user.role,
        user_id=user.id,
        name=user.name,
        email=user.email,
        session_id=active_session.id
    )


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
    """Invalidates active session upon sign out."""
    SessionService.terminate_session(db, session_id)
    return {"status": "success", "message": "Session terminated successfully."}
