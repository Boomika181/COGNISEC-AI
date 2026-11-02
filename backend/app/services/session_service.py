import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List
from sqlalchemy.orm import Session
from app.core.config import settings
from app.models.session import Session as DbSession
from app.models.application_grant import ApplicationGrant


class SessionService:
    @staticmethod
    def create_session(
        db: Session,
        user_id: int,
        application: str,
        device_id: Optional[int] = None,
        ip_address: Optional[str] = "127.0.0.1",
        status: str = "ACTIVE",
        is_pending_observation: bool = False
    ) -> DbSession:
        session_id = f"sess_{uuid.uuid4().hex[:16]}"
        now = datetime.now(timezone.utc)
        final_status = "PENDING_OBSERVATION" if is_pending_observation else status

        # Terminate any existing active/pending sessions for the same user on this application and device
        # to ensure multiple logins from the same browser/app do not stack up duplicate active sessions,
        # while preserving valid sessions on the user's other enrolled devices.
        if final_status in ("ACTIVE", "PENDING_OBSERVATION"):
            try:
                term_query = db.query(DbSession).filter(
                    DbSession.user_id == user_id,
                    DbSession.application == application.lower(),
                    DbSession.status.in_(["ACTIVE", "PENDING_OBSERVATION", "STEP_UP_REQUIRED"])
                )
                if device_id:
                    term_query = term_query.filter(DbSession.device_id == device_id)
                term_query.update({
                    "status": "TERMINATED",
                    "logout_time": now
                }, synchronize_session=False)
            except Exception:
                pass

        db_session = DbSession(
            id=session_id,
            user_id=user_id,
            application=application.lower(),
            device_id=device_id,
            ip_address=ip_address,
            login_time=now,
            status=final_status,
            current_risk_level="LOW",
            observation_started_at=now if is_pending_observation else None,
            observation_ends_at=(now + timedelta(seconds=getattr(settings, "OBSERVATION_WINDOW_SECONDS", 20))) if is_pending_observation else None,
            login_outcome="observation_pending" if is_pending_observation else "active"
        )
        db.add(db_session)
        db.commit()
        db.refresh(db_session)
        return db_session

    @staticmethod
    def reap_expired_sessions(db: Session, max_lifetime_minutes: Optional[int] = None) -> int:
        """
        Authoritatively marks expired active sessions as TERMINATED in the database:
        - Sessions whose token lifetime has elapsed without explicit logout.
        - Preserves all historical session records in DB while ensuring they are not counted as active.
        - Reconciles any orphaned duplicate active sessions per user/application.
        """
        from app.core.config import settings
        lifetime = max_lifetime_minutes or getattr(settings, "ACCESS_TOKEN_EXPIRE_MINUTES", 1440)
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(minutes=lifetime)

        reaped = 0
        try:
            # 1. Terminate sessions older than token expiration cutoff
            expired_count = db.query(DbSession).filter(
                DbSession.status == "ACTIVE",
                DbSession.login_time < cutoff
            ).update({
                "status": "TERMINATED",
                "logout_time": DbSession.login_time + timedelta(minutes=lifetime)
            }, synchronize_session=False)
            reaped += expired_count

            # 2. For any user with multiple active sessions on the same application, keep only the newest
            active_sessions = db.query(DbSession).filter(
                DbSession.status == "ACTIVE"
            ).order_by(DbSession.login_time.desc()).all()

            seen_user_apps = set()
            for s in active_sessions:
                key = (s.user_id, (s.application or "").lower())
                if key in seen_user_apps:
                    s.status = "TERMINATED"
                    s.logout_time = s.login_time + timedelta(hours=1)
                    reaped += 1
                else:
                    seen_user_apps.add(key)

            db.commit()
        except Exception:
            db.rollback()
        return reaped

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
            db_session.current_risk_level = risk_level.upper()
        if status in ("TERMINATED", "REVOKED") or (risk_level and risk_level.upper() in ("HIGH", "CRITICAL")):
            if status in ("TERMINATED", "REVOKED"):
                db_session.logout_time = datetime.now(timezone.utc)
            db_session.step_up_valid_until = None
            db_session.step_up_factor = None
            db_session.step_up_verified_at = None
            db_session.step_up_risk_cleared = None
            try:
                db.query(ApplicationGrant).filter(
                    ApplicationGrant.session_id == session_id,
                    ApplicationGrant.revoked == False
                ).update({"revoked": True})
            except Exception:
                db.rollback()
                raise

            # Atomic cleanup of active challenges upon session termination or critical escalation
            try:
                from app.services.step_up_service import StepUpService
                StepUpService.purge_session_challenges(session_id)
            except Exception:
                pass

            try:
                from app.models.otp_challenge import OTPChallenge
                db.query(OTPChallenge).filter(
                    OTPChallenge.session_id == session_id,
                    OTPChallenge.is_consumed == False
                ).update({"is_consumed": True, "consumed_at": datetime.now(timezone.utc)})
            except Exception:
                pass

            try:
                from app.services.behavior_drift_service import BehavioralDriftTracker
                BehavioralDriftTracker.clear_session(session_id)
            except Exception:
                pass
            
        try:
            db.commit()
            db.refresh(db_session)
        except Exception:
            db.rollback()
            raise
        return db_session

    @staticmethod
    def terminate_session(db: Session, session_id: str, risk_level: Optional[str] = None) -> Optional[DbSession]:
        return SessionService.update_session_status(db, session_id, status="TERMINATED", risk_level=risk_level)

    @staticmethod
    def terminate_all_user_sessions(db: Session, user_id: int) -> int:
        """Terminates all active or pending sessions for a user upon credential reset."""
        sessions = db.query(DbSession).filter(
            DbSession.user_id == user_id,
            DbSession.status != "TERMINATED"
        ).all()
        now = datetime.now(timezone.utc)
        count = len(sessions)
        for s in sessions:
            s.status = "TERMINATED"
            s.is_active = False
            s.logout_time = now
        try:
            db.query(ApplicationGrant).filter(
                ApplicationGrant.user_id == user_id,
                ApplicationGrant.revoked == False
            ).update({"revoked": True})
        except Exception:
            pass
        db.commit()
        return count

    @staticmethod
    def get_active_sessions(
        db: Session,
        application: Optional[str] = None,
        user_id: Optional[int] = None
    ) -> List[DbSession]:
        query = db.query(DbSession).filter(DbSession.status == "ACTIVE", ~DbSession.id.like("sim_%"))
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

    @staticmethod
    def record_step_up_success(
        db: Session,
        session_id: str,
        factor: str = "OTP",
        cleared_risk_score: float = 0.40,
        validity_minutes: int = 15
    ) -> Optional[DbSession]:
        """
        Atomically records successful Step-Up verification on the active session.
        Guards:
        - If session does not exist, return None.
        - If session is TERMINATED or CRITICAL, refuses to restore or record.
        - Sets status to "ACTIVE", current_risk_level to "LOW", step_up_verified_at,
          step_up_valid_until, step_up_factor, and step_up_risk_cleared.
        - Commits to database.
        """
        db_session = db.query(DbSession).filter(DbSession.id == session_id).first()
        if not db_session:
            return None

        if db_session.status == "TERMINATED":
            return None

        if db_session.current_risk_level == "CRITICAL":
            return None

        now = datetime.now(timezone.utc)
        db_session.status = "ACTIVE"
        db_session.current_risk_level = "LOW"
        db_session.step_up_verified_at = now
        db_session.step_up_valid_until = now + timedelta(minutes=validity_minutes)
        db_session.step_up_factor = factor
        db_session.step_up_risk_cleared = float(cleared_risk_score)

        db.commit()
        db.refresh(db_session)
        return db_session

    @staticmethod
    def is_step_up_fresh(
        db_session: Optional[DbSession],
        current_risk_score: float = 0.0,
        current_risk_level: str = "LOW",
        required_factor: Optional[str] = None
    ) -> bool:
        """
        Determines whether the session holds a valid, active, unexpired Step-Up verification.
        Policy:
        - Must have step_up_valid_until set and in the future.
        - Session status must be ACTIVE (not TERMINATED, RESTRICTED, or PENDING).
        - If current_risk_level is CRITICAL or HIGH, confidential step-up is never fresh.
        - If required_factor is GESTURE_PATTERN / NEURALTRACE, step_up_factor must match.
          A general login OTP or SMS factor NEVER grants confidential vault access.
        """
        if not db_session:
            return False

        if db_session.status != "ACTIVE":
            return False

        if current_risk_level in ("CRITICAL", "HIGH", "RESTRICTED"):
            return False

        if not db_session.step_up_valid_until:
            return False

        now = datetime.now(timezone.utc)
        valid_until = db_session.step_up_valid_until
        if valid_until.tzinfo is None:
            valid_until = valid_until.replace(tzinfo=timezone.utc)

        if now > valid_until:
            return False

        if required_factor:
            req_norm = required_factor.upper().strip()
            sess_factor = (db_session.step_up_factor or "").upper().strip()
            if req_norm in ("GESTURE_PATTERN", "NEURALTRACE"):
                if sess_factor not in ("GESTURE_PATTERN", "NEURALTRACE"):
                    return False
            elif sess_factor != req_norm:
                return False

        return True

    @staticmethod
    def get_observation_status(db: Session, session_id: str) -> Optional[dict]:
        from app.models.behavior import BehaviorLog
        from app.core.config import settings
        db_session = db.query(DbSession).filter(DbSession.id == session_id).first()
        if not db_session:
            return None

        now = datetime.now(timezone.utc)
        started_at = db_session.observation_started_at
        if started_at:
            if started_at.tzinfo is None:
                started_at = started_at.replace(tzinfo=timezone.utc)
            elapsed = (now - started_at).total_seconds()
            remaining = max(0, int(settings.OBSERVATION_WINDOW_SECONDS - elapsed))
            is_completed = elapsed >= settings.OBSERVATION_WINDOW_SECONDS or db_session.status in ("PENDING_OTP", "ACTIVE")
        else:
            remaining = 0
            is_completed = True

        sample_count = db.query(BehaviorLog).filter(BehaviorLog.session_id == session_id).count()

        return {
            "session_id": session_id,
            "status": db_session.status,
            "observation_seconds_remaining": remaining,
            "is_completed": is_completed,
            "telemetry_samples_count": sample_count,
            "observation_started_at": started_at
        }

    @staticmethod
    def activate_session_after_login_otp(
        db: Session,
        session_id: str,
        challenge_id: Optional[str] = None
    ) -> Optional[DbSession]:
        db_session = db.query(DbSession).filter(DbSession.id == session_id).first()
        if not db_session:
            return None
        if db_session.status == "TERMINATED":
            return None

        now = datetime.now(timezone.utc)
        db_session.status = "ACTIVE"
        db_session.current_risk_level = "LOW"
        db_session.login_outcome = "verified"
        if challenge_id:
            db_session.login_otp_challenge_id = challenge_id

        # Login OTP grants active session for general browsing,
        # but does NOT grant access to confidential vaults (transcripts, payments, EHR).
        # Confidential vaults strictly require NeuralTrace (GESTURE_PATTERN).
        db_session.step_up_verified_at = now
        db_session.step_up_valid_until = now + timedelta(minutes=15)
        db_session.step_up_factor = "EMAIL_OTP"
        db_session.step_up_risk_cleared = 0.0

        try:
            from app.services.access_tracker import ConfidentialAccessTracker
            ConfidentialAccessTracker.clear_denials(db_session.user_id, session_id)
        except Exception:
            pass

        db.commit()
        db.refresh(db_session)
        return db_session

    @staticmethod
    def terminate_session_failed_otp(
        db: Session,
        session_id: str
    ) -> Optional[DbSession]:
        db_session = db.query(DbSession).filter(DbSession.id == session_id).first()
        if not db_session:
            return None
        now = datetime.now(timezone.utc)
        db_session.status = "TERMINATED"
        db_session.logout_time = now
        db_session.login_outcome = "rejected"
        db.commit()
        db.refresh(db_session)
        return db_session

    @staticmethod
    def normalize_application(app: Optional[str]) -> str:
        """Normalizes portal application names to canonical identifiers: college, shopping, healthcare."""
        if not app:
            return ""
        norm = app.lower().strip()
        if norm in ("college", "college_portal", "academic", "university"):
            return "college"
        if norm in ("shopping", "shopping_portal", "ecommerce", "nyraa", "retail"):
            return "shopping"
        if norm in ("healthcare", "healthcare_portal", "ehr", "clinical", "hospital"):
            return "healthcare"
        return norm

    @staticmethod
    def normalize_resource(res: Optional[str]) -> str:
        """Normalizes confidential resource identifiers to canonical names."""
        if not res:
            return ""
        norm = res.lower().strip()
        if norm in ("academic_vault", "transcripts", "grades", "academic", "college"):
            return "academic_vault"
        if norm in ("online_exam", "exam", "proctored_exam", "college_exam"):
            return "online_exam"
        if norm in ("financial_vault", "payment_methods", "payments", "cards", "shopping"):
            return "financial_vault"
        if norm in ("ehr_vault", "patient_records", "medical_history", "clinical", "healthcare"):
            return "ehr_vault"
        return norm

    @staticmethod
    def get_application_for_resource(resource: Optional[str]) -> str:
        """Returns the canonical application responsible for a confidential resource."""
        norm_res = SessionService.normalize_resource(resource)
        mapping = {
            "academic_vault": "college",
            "online_exam": "college",
            "financial_vault": "shopping",
            "ehr_vault": "healthcare"
        }
        return mapping.get(norm_res, "")

    @staticmethod
    def get_resource_for_application(app: Optional[str]) -> str:
        """Returns the confidential resource associated with a canonical application."""
        norm_app = SessionService.normalize_application(app)
        mapping = {
            "college": "academic_vault",
            "shopping": "financial_vault",
            "healthcare": "ehr_vault"
        }
        return mapping.get(norm_app, "")

    @staticmethod
    def record_application_grant(
        db: Session,
        session_id: str,
        user_id: int,
        application: str,
        resource: Optional[str] = None,
        factor: str = "GESTURE_PATTERN",
        validity_minutes: int = 15
    ) -> Optional[ApplicationGrant]:
        """
        Authoritatively creates an application- and resource-scoped step-up grant in database.
        Ensures that step-up verification in one demo website NEVER satisfies another website.
        """
        norm_app = SessionService.normalize_application(application)
        norm_res = SessionService.normalize_resource(resource) if resource else SessionService.get_resource_for_application(norm_app)
        if not norm_app and norm_res:
            norm_app = SessionService.get_application_for_resource(norm_res)
        if not norm_res and norm_app:
            norm_res = SessionService.get_resource_for_application(norm_app)

        if not norm_app or not norm_res:
            return None

        db_session = db.query(DbSession).filter(DbSession.id == session_id).first()
        if not db_session or db_session.status == "TERMINATED" or db_session.current_risk_level == "CRITICAL":
            return None

        # Ensure session belongs to user (BOLA protection)
        if db_session.user_id != user_id:
            return None

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=validity_minutes)

        # Revoke existing grants for this exact session, application, and resource to maintain single active grant
        db.query(ApplicationGrant).filter(
            ApplicationGrant.session_id == session_id,
            ApplicationGrant.application == norm_app,
            ApplicationGrant.resource == norm_res,
            ApplicationGrant.revoked == False
        ).update({"revoked": True})

        grant = ApplicationGrant(
            session_id=session_id,
            user_id=user_id,
            application=norm_app,
            resource=norm_res,
            factor=factor,
            granted_at=now,
            expires_at=expires_at,
            revoked=False
        )
        db.add(grant)

        # Maintain session-level freshness so general active state is preserved
        db_session.status = "ACTIVE"
        if db_session.current_risk_level in ("MEDIUM", "RESTRICTED", "HIGH"):
            db_session.current_risk_level = "LOW"
        db_session.step_up_verified_at = now
        db_session.step_up_valid_until = expires_at
        db_session.step_up_factor = factor
        db_session.step_up_risk_cleared = 0.45

        db.commit()
        db.refresh(grant)
        return grant

    @staticmethod
    def is_application_authorized(
        db: Session,
        db_session: Optional[DbSession],
        user_id: int,
        application: Optional[str] = None,
        resource: Optional[str] = None,
        required_factor: str = "GESTURE_PATTERN"
    ) -> bool:
        """
        Authoritatively validates whether the given session holds an unexpired,
        unrevoked ApplicationGrant for the exact application, user, and confidential resource.
        Source of truth: database table 'application_grants'.
        """
        if not db_session:
            return False
        if db_session.status != "ACTIVE":
            return False
        if db_session.current_risk_level in ("CRITICAL", "HIGH", "RESTRICTED"):
            return False
        if db_session.user_id != user_id:
            return False

        norm_app = SessionService.normalize_application(application)
        norm_res = SessionService.normalize_resource(resource)
        if not norm_app and norm_res:
            norm_app = SessionService.get_application_for_resource(norm_res)
        if not norm_res and norm_app:
            norm_res = SessionService.get_resource_for_application(norm_app)

        if not norm_app or not norm_res:
            return False

        # Cross-portal check: confirm application and resource align
        expected_app = SessionService.get_application_for_resource(norm_res)
        if expected_app and expected_app != norm_app:
            # Mismatched resource and application (e.g. asking for academic_vault under shopping)
            return False

        now = datetime.now(timezone.utc)
        grant = db.query(ApplicationGrant).filter(
            ApplicationGrant.session_id == db_session.id,
            ApplicationGrant.user_id == user_id,
            ApplicationGrant.application == norm_app,
            ApplicationGrant.resource == norm_res,
            ApplicationGrant.revoked == False
        ).order_by(ApplicationGrant.id.desc()).first()

        if not grant:
            return False

        exp = grant.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)

        if now > exp:
            return False

        if required_factor:
            req_norm = required_factor.upper().strip()
            grant_factor = (grant.factor or "").upper().strip()
            if req_norm in ("GESTURE_PATTERN", "NEURALTRACE"):
                if grant_factor not in ("GESTURE_PATTERN", "NEURALTRACE"):
                    return False
            elif req_norm == "HIGH_RISK_DUAL":
                if grant_factor != "HIGH_RISK_DUAL":
                    return False
            elif grant_factor != req_norm:
                return False

        return True

    @staticmethod
    def revoke_application_grants(
        db: Session,
        session_id: Optional[str] = None,
        user_id: Optional[int] = None,
        application: Optional[str] = None,
        resource: Optional[str] = None
    ) -> int:
        """Revokes all active application grants matching the given filters."""
        query = db.query(ApplicationGrant).filter(ApplicationGrant.revoked == False)
        if session_id:
            query = query.filter(ApplicationGrant.session_id == session_id)
        if user_id:
            query = query.filter(ApplicationGrant.user_id == user_id)
        if application:
            norm_app = SessionService.normalize_application(application)
            if norm_app:
                query = query.filter(ApplicationGrant.application == norm_app)
        if resource:
            norm_res = SessionService.normalize_resource(resource)
            if norm_res:
                query = query.filter(ApplicationGrant.resource == norm_res)
        matching_grants = query.all()
        for g in matching_grants:
            g.revoked = True
        db.commit()
        return len(matching_grants)
