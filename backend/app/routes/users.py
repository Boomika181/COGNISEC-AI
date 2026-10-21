from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.schemas.user import UserResponse, UserUpdate
from app.routes.deps import get_current_user, require_active_session
from app.models.user import User

router = APIRouter(prefix="/users", tags=["Users"])


@router.get("/profile", response_model=UserResponse)
def get_profile(current_user: User = Depends(require_active_session)):
    return current_user


@router.put("/profile", response_model=UserResponse)
def update_profile(
    update_data: UserUpdate,
    current_user: User = Depends(require_active_session),
    db: Session = Depends(get_db)
):
    if update_data.name:
        current_user.name = update_data.name.strip()
    db.commit()
    db.refresh(current_user)
    return current_user
