from typing import Optional
from sqlalchemy.orm import Session
from app.models.user import User
from app.schemas.auth import RegisterRequest
from app.core.security import get_password_hash, verify_password
from app.services.profile_service import ProfileService


class AuthService:
    @staticmethod
    def get_user_by_email(db: Session, email: str) -> Optional[User]:
        if not email:
            return None
        return db.query(User).filter(User.email == email.lower().strip()).first()

    @staticmethod
    def activate_user_account(db: Session, email: str) -> Optional[User]:
        user = AuthService.get_user_by_email(db, email)
        if user:
            user.account_status = "ACTIVE"
            db.commit()
            db.refresh(user)
        return user

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
    def create_user(db: Session, request: RegisterRequest, forced_role: Optional[str] = None) -> User:
        assigned_role = forced_role.upper() if forced_role else (request.role.upper() if request.role else "USER")
        db_user = User(
            name=request.name.strip(),
            email=request.email.lower().strip(),
            password_hash=get_password_hash(request.password),
            role=assigned_role,
            account_status="ACTIVE"
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)

        # Baseline enrollment at account creation if sample is supplied
        telemetry = getattr(request, "enrollment_telemetry", None)
        if telemetry:
            try:
                ProfileService.enroll_registration_baseline(db, db_user.id, sample_data=telemetry)
            except Exception:
                pass

        return db_user

    @staticmethod
    def update_user_password(db: Session, email: str, new_password: str) -> Optional[User]:
        user = AuthService.get_user_by_email(db, email)
        if not user:
            return None
        user.password_hash = get_password_hash(new_password)
        db.commit()
        db.refresh(user)
        return user
