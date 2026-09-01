import uuid
from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy.orm import Session
from app.models.session import Session as DbSession


class SessionService:
    @staticmethod
    def create_session(
        db: Session,
        user_id: int,
        application: str,
        device_id: Optional[int] = None,
        ip_address: Optional[str] = "127.0.0.1"
    ) -> DbSession:
        session_id = f"sess_{uuid.uuid4().hex[:16]}"
        db_session = DbSession(
            id=session_id,
            user_id=user_id,
            application=application.lower(),
            device_id=device_id,
            ip_address=ip_address,
            login_time=datetime.now(timezone.utc),
            status="ACTIVE",
            current_risk_level="LOW"
        )
        db.add(db_session)
        db.commit()
        db.refresh(db_session)
        return db_session

    @staticmethod
    def get_session(db: Session, session_id: str) -> Optional[DbSession]:
        return db.query(DbSession).filter(DbSession.id == session_id).first()

    @staticmethod
    def update_session_status(
        db: Session,
        session_id: str,
        status: str,
        risk_level: Optional[str] = None
    ) -> Optional[DbSession]:
        db_session = db.query(DbSession).filter(DbSession.id == session_id).first()
        if not db_session:
            return None
        
        db_session.status = status
        if risk_level:
            db_session.current_risk_level = risk_level
        if status == "TERMINATED":
            db_session.logout_time = datetime.now(timezone.utc)
            
        db.commit()
        db.refresh(db_session)
        return db_session

    @staticmethod
    def terminate_session(db: Session, session_id: str) -> Optional[DbSession]:
        return SessionService.update_session_status(db, session_id, status="TERMINATED", risk_level=None)

    @staticmethod
    def get_active_sessions(
        db: Session,
        application: Optional[str] = None,
        user_id: Optional[int] = None
    ) -> List[DbSession]:
        query = db.query(DbSession).filter(DbSession.status == "ACTIVE")
        if application:
            query = query.filter(DbSession.application == application.lower())
        if user_id:
            query = query.filter(DbSession.user_id == user_id)
        return query.order_by(DbSession.login_time.desc()).all()

    @staticmethod
    def get_all_sessions(
        db: Session,
        application: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100
    ) -> List[DbSession]:
        query = db.query(DbSession)
        if application:
            query = query.filter(DbSession.application == application.lower())
        if status:
            query = query.filter(DbSession.status == status.upper())
        return query.order_by(DbSession.login_time.desc()).limit(limit).all()
