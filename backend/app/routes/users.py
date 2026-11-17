from fastapi import APIRouter, Depends, HTTPException, Header, status
from typing import Optional
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.schemas.user import UserResponse, UserUpdate
from app.routes.deps import get_current_user, require_active_session
from app.core.security import decode_access_token
from app.models.session import Session as DbSession
from app.models.user import User

router = APIRouter(prefix="/users", tags=["Users"])


@router.get("/profile", response_model=UserResponse)
def get_profile(
    authorization: Optional[str] = Header(None),
    current_user: User = Depends(require_active_session),
    db: Session = Depends(get_db)
):
    if authorization and " " in authorization:
        payload = decode_access_token(authorization.split(" ", 1)[1].strip())
        sid = payload.get("sid") if payload else None
        if sid:
            sess = db.query(DbSession).filter(DbSession.id == sid).first()
            if sess and sess.application:
                from app.services.portal_lock_service import PortalLockService
                PortalLockService.enforce_not_locked(db, current_user.id, sess.application)
    return current_user


@router.put("/profile", response_model=UserResponse)
def update_profile(
    update_data: UserUpdate,
    authorization: Optional[str] = Header(None),
    current_user: User = Depends(require_active_session),
    db: Session = Depends(get_db)
):
    if authorization and " " in authorization:
        payload = decode_access_token(authorization.split(" ", 1)[1].strip())
        sid = payload.get("sid") if payload else None
        if sid:
            sess = db.query(DbSession).filter(DbSession.id == sid).first()
            if sess and sess.application:
                from app.services.portal_lock_service import PortalLockService
                PortalLockService.enforce_not_locked(db, current_user.id, sess.application)
    if update_data.role is not None or update_data.account_status is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account role and security status cannot be modified through profile settings."
        )
    if update_data.name is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Display name is required."
        )
    cleaned_name = update_data.name.strip()
    if len(cleaned_name) < 2 or len(cleaned_name) > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Display name must be between 2 and 100 characters."
        )
    current_user.name = cleaned_name
    db.commit()
    db.refresh(current_user)
    return current_user
