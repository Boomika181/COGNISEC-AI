from typing import Generator, Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.core.security import decode_access_token
from app.models.user import User
from app.models.session import Session as DbSession

security_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    auth_creds: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    db: Session = Depends(get_db)
) -> User:
    """
    Validates JWT access token from Authorization Bearer header.
    Enforces server-side session revocation: validates that the bound session
    is active and not TERMINATED or EXPIRED in the database.
    """
    if not auth_creds:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token is missing. Please sign in.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = auth_creds.credentials
    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        user_id = int(payload["sub"])
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token subject identifier.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account not found.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user.account_status != "ACTIVE":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"User account is {user.account_status.lower()}.",
        )

    # Server-Side Session Revocation Enforcement
    session_id = payload.get("sid")
    if session_id:
        db_session = db.query(DbSession).filter(DbSession.id == session_id).first()
        if not db_session:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session not found or has been revoked. Please sign in again.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if db_session.user_id != user.id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session token mismatch.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if db_session.status in ("TERMINATED", "EXPIRED"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session has been terminated or expired. Please sign in again.",
                headers={"WWW-Authenticate": "Bearer"},
            )

    return user


def verify_session_access(session: Optional[DbSession], user: User) -> None:
    """
    BOLA Authorization Guard:
    Enforces that non-admin users can ONLY access and manipulate their own sessions.
    """
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found."
        )
    if session.user_id != user.id and user.role.upper() != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized: Access to this session is forbidden."
        )


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Enforces that the authenticated user possesses the ADMIN role."""
    if current_user.role.upper() != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access restricted: Security Administrator privileges required.",
        )
    return current_user


def require_active_session(
    auth_creds: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> User:
    """
    Enforces that the requesting session has completed mandatory 60-second observation
    and successful login OTP verification. Blocks access to protected applications and sensitive
    data when the session is in PENDING_OBSERVATION or PENDING_OTP state.
    """
    if auth_creds:
        payload = decode_access_token(auth_creds.credentials)
        if payload and "sid" in payload:
            db_session = db.query(DbSession).filter(DbSession.id == payload["sid"]).first()
            if db_session and db_session.status in ("PENDING_OBSERVATION", "PENDING_OTP"):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Access denied: Session is in {db_session.status} state. Observation and OTP verification required."
                )
    return current_user
