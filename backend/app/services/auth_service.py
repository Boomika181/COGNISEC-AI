from typing import Optional
from sqlalchemy.orm import Session
from app.models.user import User
from app.schemas.auth import RegisterRequest
from app.core.security import get_password_hash, verify_password


class AuthService:
    @staticmethod
    def get_user_by_email(db: Session, email: str) -> Optional[User]:
        return db.query(User).filter(User.email == email.lower()).first()

    @staticmethod
    def get_user_by_id(db: Session, user_id: int) -> Optional[User]:
        return db.query(User).filter(User.id == user_id).first()

    @staticmethod
    def authenticate_user(db: Session, email: str, password: str) -> Optional[User]:
        user = AuthService.get_user_by_email(db, email)
        if not user:
            return None
        if not verify_password(password, user.password_hash):
            return None
        return user

    @staticmethod
    def create_user(db: Session, request: RegisterRequest) -> User:
        db_user = User(
            name=request.name.strip(),
            email=request.email.lower().strip(),
            password_hash=get_password_hash(request.password),
            role=request.role.upper() if request.role else "USER",
            account_status="ACTIVE"
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return db_user
