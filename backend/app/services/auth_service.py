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
        user.account_status = "ACTIVE"
        user.failed_login_attempts = 0
        db.commit()
        db.refresh(user)
        return user

    @staticmethod
    def record_failed_login(
        db: Session,
        email: str,
        ip_address: str,
        user_agent: Optional[str] = None
    ) -> tuple:
        """
        Records a failed authentication attempt.
        Applies strict 3-attempt security policy:
        - When consecutive failed attempts reaches 3, account_status becomes 'LOCKED'.
        - Emits ACCOUNT_LOCKED security event.
        - Invokes NotificationService for failed login telemetry & alerts.
        Returns: (user, is_now_locked, failed_attempts_count)
        """
        import json
        from app.models.security_event import SecurityEvent
        from app.services.notification_service import NotificationService

        user = AuthService.get_user_by_email(db, email)
        if not user:
            NotificationService.handle_failed_login(
                db=db,
                email=email,
                ip_address=ip_address,
                user_agent=user_agent
            )
            return None, False, 0

        current_fails = (getattr(user, "failed_login_attempts", 0) or 0) + 1
        user.failed_login_attempts = current_fails

        is_now_locked = False
        if current_fails >= 3:
            user.account_status = "LOCKED"
            is_now_locked = True
            sec_lock = SecurityEvent(
                user_id=user.id,
                application="platform",
                event_type="ACCOUNT_LOCKED",
                severity="HIGH",
                anomaly_score=0.35,
                risk_score=0.75,
                decision="BLOCK",
                details=json.dumps({
                    "reason": "MAX_FAILED_LOGIN_ATTEMPTS_EXCEEDED",
                    "failed_attempts": current_fails,
                    "target_email": user.email,
                    "ip_address": ip_address,
                    "user_agent": user_agent or ""
                })
            )
            db.add(sec_lock)

        NotificationService.handle_failed_login(
            db=db,
            email=email,
            ip_address=ip_address,
            user_agent=user_agent
        )

        db.commit()
        db.refresh(user)
        return user, is_now_locked, current_fails

    @staticmethod
    def reset_failed_logins(db: Session, email: str) -> Optional[User]:
        """Clears failed login attempt counter and restores account_status to ACTIVE."""
        user = AuthService.get_user_by_email(db, email)
        if user:
            user.failed_login_attempts = 0
            user.account_status = "ACTIVE"
            db.commit()
            db.refresh(user)
        return user

