import logging
from sqlalchemy import inspect, text
from app.database.connection import engine

logger = logging.getLogger(__name__)

def sync_device_and_notification_schemas():
    """
    Safely inspects and synchronizes SQLite/Postgres schemas for the Device and DeviceNotification models.
    Executes idempotent ALTER TABLE statements for any newly added columns.
    """
    try:
        insp = inspect(engine)
        if insp.has_table("users"):
            user_cols = {col["name"] for col in insp.get_columns("users")}
            user_cols_to_add = [
                ("registration_source", "VARCHAR(40)"),
                ("email_verified", "BOOLEAN DEFAULT FALSE NOT NULL" if engine.dialect.name != "sqlite" else "BOOLEAN DEFAULT 0 NOT NULL"),
                ("email_verified_at", "TIMESTAMP"),
                ("security_enrollment_completed", "BOOLEAN DEFAULT TRUE NOT NULL" if engine.dialect.name != "sqlite" else "BOOLEAN DEFAULT 1 NOT NULL"),
            ]
            with engine.begin() as conn:
                for col_name, col_type in user_cols_to_add:
                    if col_name not in user_cols:
                        logger.info(f"[SchemaSync] Adding column {col_name} to users table")
                        try:
                            conn.execute(text(f"ALTER TABLE users ADD COLUMN {col_name} {col_type};"))
                        except Exception as err:
                            logger.debug(f"[SchemaSync] Users column add notice: {err}")

        if not insp.has_table("devices"):
            return

        existing_cols = {col["name"] for col in insp.get_columns("devices")}

        columns_to_add = [
            ("device_id", "VARCHAR(64)"),
            ("nickname", "VARCHAR(100)"),
            ("browser_name", "VARCHAR(100)"),
            ("browser_version", "VARCHAR(50)"),
            ("os_name", "VARCHAR(100)"),
            ("os_version", "VARCHAR(50)"),
            ("trust_state", "VARCHAR(30) DEFAULT 'PENDING_CONFIRMATION'"),
            ("last_ip", "VARCHAR(45)"),
            ("latitude", "FLOAT"),
            ("longitude", "FLOAT"),
            ("city", "VARCHAR(100)"),
            ("region", "VARCHAR(100)"),
            ("country", "VARCHAR(100)"),
            ("location_source", "VARCHAR(50) DEFAULT 'UNKNOWN'"),
            ("location_accuracy", "FLOAT"),
            ("location_updated_at", "TIMESTAMP"),
        ]

        with engine.begin() as conn:
            for col_name, col_type in columns_to_add:
                if col_name not in existing_cols:
                    logger.info(f"[SchemaSync] Adding column {col_name} to devices table")
                    try:
                        conn.execute(text(f"ALTER TABLE devices ADD COLUMN {col_name} {col_type};"))
                    except Exception as err:
                        logger.debug(f"[SchemaSync] Column add notice: {err}")

            # Backfill existing rows if any
            if engine.dialect.name == "sqlite":
                conn.execute(text("""
                    UPDATE devices
                    SET device_id = 'dev_' || hex(randomblob(12))
                    WHERE device_id IS NULL OR device_id = '';
                """))
                conn.execute(text("""
                    UPDATE devices
                    SET trust_state = CASE WHEN is_trusted = 1 THEN 'TRUSTED' ELSE 'PENDING_CONFIRMATION' END
                    WHERE trust_state IS NULL OR trust_state = '';
                """))
            else:
                conn.execute(text("""
                    UPDATE devices
                    SET device_id = 'dev_' || md5(random()::text)
                    WHERE device_id IS NULL OR device_id = '';
                """))
                conn.execute(text("""
                    UPDATE devices
                    SET trust_state = CASE WHEN is_trusted = true THEN 'TRUSTED' ELSE 'PENDING_CONFIRMATION' END
                    WHERE trust_state IS NULL OR trust_state = '';
                """))

    except Exception as e:
        logger.warning(f"[SchemaSync] Schema check completed or deferred: {e}")


def sync_session_schema():
    """
    Safely inspects and synchronizes SQLite/Postgres schemas for the Session model.
    Adds step_up_verified_at, step_up_valid_until, step_up_factor, and step_up_risk_cleared columns.
    """
    try:
        insp = inspect(engine)
        if not insp.has_table("sessions"):
            return

        existing_cols = {col["name"] for col in insp.get_columns("sessions")}

        columns_to_add = [
            ("step_up_verified_at", "TIMESTAMP"),
            ("step_up_valid_until", "TIMESTAMP"),
            ("step_up_factor", "VARCHAR(50)"),
            ("step_up_risk_cleared", "FLOAT"),
            ("observation_started_at", "TIMESTAMP"),
            ("observation_ends_at", "TIMESTAMP"),
            ("observation_completed_at", "TIMESTAMP"),
            ("login_outcome", "VARCHAR(50)"),
            ("login_otp_challenge_id", "VARCHAR(64)"),
        ]

        with engine.begin() as conn:
            for col_name, col_type in columns_to_add:
                if col_name not in existing_cols:
                    logger.info(f"[SchemaSync] Adding column {col_name} to sessions table")
                    try:
                        conn.execute(text(f"ALTER TABLE sessions ADD COLUMN {col_name} {col_type};"))
                    except Exception as err:
                        logger.debug(f"[SchemaSync] Session column add notice: {err}")
    except Exception as e:
        logger.warning(f"[SchemaSync] Session schema sync completed or deferred: {e}")


def sync_application_grants_schema():
    """
    Safely inspects and ensures the application_grants table exists in SQLite and PostgreSQL.
    """
    try:
        insp = inspect(engine)
        if not insp.has_table("application_grants"):
            logger.info("[SchemaSync] Creating application_grants table")
            with engine.begin() as conn:
                if engine.dialect.name == "sqlite":
                    conn.execute(text("""
                        CREATE TABLE IF NOT EXISTS application_grants (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            session_id VARCHAR(64) NOT NULL,
                            user_id INTEGER NOT NULL,
                            application VARCHAR(50) NOT NULL,
                            resource VARCHAR(50) NOT NULL,
                            factor VARCHAR(50) NOT NULL DEFAULT 'GESTURE_PATTERN',
                            granted_at TIMESTAMP NOT NULL,
                            expires_at TIMESTAMP NOT NULL,
                            revoked BOOLEAN NOT NULL DEFAULT 0,
                            FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE,
                            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                        );
                    """))
                    conn.execute(text("CREATE INDEX IF NOT EXISTS ix_app_grants_session_id ON application_grants(session_id);"))
                    conn.execute(text("CREATE INDEX IF NOT EXISTS ix_app_grants_user_id ON application_grants(user_id);"))
                    conn.execute(text("CREATE INDEX IF NOT EXISTS ix_app_grants_app_res ON application_grants(application, resource);"))
                else:
                    conn.execute(text("""
                        CREATE TABLE IF NOT EXISTS application_grants (
                            id SERIAL PRIMARY KEY,
                            session_id VARCHAR(64) NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                            application VARCHAR(50) NOT NULL,
                            resource VARCHAR(50) NOT NULL,
                            factor VARCHAR(50) NOT NULL DEFAULT 'GESTURE_PATTERN',
                            granted_at TIMESTAMPTZ NOT NULL,
                            expires_at TIMESTAMPTZ NOT NULL,
                            revoked BOOLEAN NOT NULL DEFAULT FALSE
                        );
                    """))
                    conn.execute(text("CREATE INDEX IF NOT EXISTS ix_app_grants_session_id ON application_grants(session_id);"))
                    conn.execute(text("CREATE INDEX IF NOT EXISTS ix_app_grants_user_id ON application_grants(user_id);"))
                    conn.execute(text("CREATE INDEX IF NOT EXISTS ix_app_grants_app_res ON application_grants(application, resource);"))
    except Exception as e:
        logger.warning(f"[SchemaSync] Application grants schema sync: {e}")


def sync_historical_device_identities():
    """
    Idempotent database integrity sync for device inventory:
    - Backfills browser_name, browser_version, os_name, os_version, and device_type
      from raw browser/os strings using UserAgentParser for existing records.
    - Replaces unverified placeholder nicknames ('Device #N' or unverified empty nicknames)
      with evidence-derived names (e.g. 'macOS · Chrome') or honest 'Identity not verified'.
    - Synchronizes is_trusted boolean with trust_state == 'TRUSTED'.
    """
    try:
        from app.database.connection import SessionLocal
        from app.models.device import Device
        from app.core.user_agent import UserAgentParser

        db = SessionLocal()
        devices = db.query(Device).all()
        updated_count = 0

        for d in devices:
            changed = False
            # 1. Backfill browser_name and os_name if raw string exists but parsed is empty
            if d.browser and (not d.browser_name or not d.os_name or d.browser_name == "Unknown"):
                info = UserAgentParser.parse(d.browser, d.os)
                if info["browser_name"] != "Unknown":
                    d.browser_name = info["browser_name"]
                    d.browser_version = info["browser_version"]
                    changed = True
                if info["os_name"] != "Unknown":
                    d.os_name = info["os_name"]
                    d.os_version = info["os_version"]
                    changed = True
                if info["device_type"] != "Unknown" and d.device_type == "Desktop":
                    d.device_type = info["device_type"]
                    changed = True

            # 2. Fix unverified placeholder nicknames ('Device #N' or empty/broken)
            current_nick = (d.nickname or "").strip()
            if current_nick.startswith("Device #"):
                if d.browser_name and d.os_name and d.browser_name != "Unknown" and d.os_name != "Unknown":
                    d.nickname = f"{d.os_name} · {d.browser_name}"
                elif d.os_name and d.os_name != "Unknown":
                    d.nickname = f"{d.os_name} ({d.device_type or 'Desktop'})"
                else:
                    d.nickname = "Identity not verified"
                changed = True

            # 3. Ensure is_trusted and trust_state are strictly synchronized
            expected_trusted = (d.trust_state == "TRUSTED")
            if d.is_trusted != expected_trusted:
                d.is_trusted = expected_trusted
                changed = True

            if changed:
                updated_count += 1

        if updated_count > 0:
            db.commit()
            logger.info(f"[SchemaSync] Successfully harmonized {updated_count} historical device records.")
        db.close()
    except Exception as e:
        logger.warning(f"[SchemaSync] Device identity synchronization notice: {e}")


def ensure_admin_account_provisioned():
    """
    Idempotent provisioning and integrity verification for the primary SOC administrator account:
    - Verifies presence of the requested admin account (cognisecai.security@gmail.com).
    - If absent, safely provisions the user with ADMIN role and bcrypt-hashed credentials.
    - If present, ensures role is ADMIN, account_status is ACTIVE, and verifies credential validity.
    - Never exposes passwords in responses, logs, or external outputs.
    """
    try:
        from datetime import datetime, timezone
        from app.database.connection import SessionLocal
        from app.models.user import User
        from app.core.config import settings
        from app.core.security import get_password_hash, verify_password

        admin_email = getattr(settings, "ADMIN_EMAIL", "cognisecai.security@gmail.com").strip().lower()
        admin_pwd = getattr(settings, "ADMIN_INITIAL_PASSWORD", None)
        env_name = (getattr(settings, "ENVIRONMENT", "") or "").strip().lower()
        if env_name == "production":
            if not admin_pwd or admin_pwd == "cognisecai2026":
                logger.warning("[SchemaSync] Skipping automatic admin password provisioning in production: ADMIN_INITIAL_PASSWORD must be explicitly configured.")
                return
        else:
            admin_pwd = admin_pwd or "cognisecai2026"

        db = SessionLocal()
        try:
            admin = db.query(User).filter(User.email == admin_email).first()
            if not admin:
                admin = User(
                    name="CogniSec SOC Administrator",
                    email=admin_email,
                    password_hash=get_password_hash(admin_pwd),
                    role="ADMIN",
                    account_status="ACTIVE",
                    created_at=datetime.now(timezone.utc)
                )
                db.add(admin)
                db.commit()
                logger.info(f"[SchemaSync] Successfully provisioned primary SOC Administrator: {admin_email}")
            else:
                updated = False
                if admin.role != "ADMIN":
                    admin.role = "ADMIN"
                    updated = True
                if admin.account_status != "ACTIVE":
                    admin.account_status = "ACTIVE"
                    updated = True
                if admin.password_hash and not verify_password(admin_pwd, admin.password_hash):
                    # Update to match local-development credentials if out of sync
                    admin.password_hash = get_password_hash(admin_pwd)
                    updated = True
                if updated:
                    db.commit()
                    logger.info(f"[SchemaSync] Harmonized SOC Administrator credentials & privileges for: {admin_email}")
        finally:
            db.close()
    except Exception as e:
        logger.warning(f"[SchemaSync] Admin account provisioning notice: {e}")


def sync_alert_schema():
    """
    Safely inspects and synchronizes SQLite/Postgres schemas for the Alert model.
    Adds triage fields: assigned_to, notes, resolution_reason, resolved_at, resolved_by.
    """
    try:
        insp = inspect(engine)
        if not insp.has_table("alerts"):
            return

        existing_cols = {col["name"] for col in insp.get_columns("alerts")}
        columns_to_add = [
            ("assigned_to", "VARCHAR(120)"),
            ("notes", "TEXT"),
            ("resolution_reason", "VARCHAR(255)"),
            ("resolved_at", "TIMESTAMP WITH TIME ZONE" if engine.dialect.name != "sqlite" else "TIMESTAMP"),
            ("resolved_by", "VARCHAR(120)"),
        ]

        with engine.begin() as conn:
            for col_name, col_type in columns_to_add:
                if col_name not in existing_cols:
                    logger.info(f"[SchemaSync] Adding column {col_name} to alerts table")
                    try:
                        conn.execute(text(f"ALTER TABLE alerts ADD COLUMN {col_name} {col_type};"))
                    except Exception as err:
                        logger.debug(f"[SchemaSync] Column add notice: {err}")

            # Data integrity fix: harmonize historical LOGIN_ATTEMPT_FAILED decision from ALLOW to DENY
            try:
                conn.execute(text("UPDATE security_events SET decision = 'DENY' WHERE event_type = 'LOGIN_ATTEMPT_FAILED' AND decision = 'ALLOW';"))
            except Exception as e:
                logger.debug(f"[SchemaSync] Failed login event harmonization notice: {e}")
    except Exception as e:
        logger.warning(f"[SchemaSync] Alert schema synchronization notice: {e}")


def sync_user_schema():
    """
    Safely inspects and synchronizes SQLite/Postgres schemas for the User model.
    Adds failed_login_attempts column if not already present.
    """
    try:
        insp = inspect(engine)
        if not insp.has_table("users"):
            return
        existing_cols = {col["name"] for col in insp.get_columns("users")}
        if "failed_login_attempts" not in existing_cols:
            logger.info("[SchemaSync] Adding column failed_login_attempts to users table")
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0;"))
    except Exception as e:
        logger.warning(f"[SchemaSync] User schema synchronization notice: {e}")


def sync_doctor_roles_and_identities():
    """
    Safely inspects and synchronizes doctor identities and ensures healthcare tables are created:
    - Non-destructively provisions healthcare_appointments and otp_challenges tables if not present.
    - Adds newly introduced appointment & OTP columns idempotently across SQLite/Postgres.
    - Idempotently harmonizes role='DOCTOR' for verified medical staff accounts.
    - Preserves all existing users, devices, sessions, and records untouched.
    """
    try:
        from app.models.appointment import HealthcareAppointment
        from app.models.otp_challenge import OTPChallenge
        from app.models.user import User
        from app.database.connection import SessionLocal
        from app.core.config import settings
        from app.core.security import get_password_hash

        # 1. Create tables non-destructively if not exist
        HealthcareAppointment.__table__.create(bind=engine, checkfirst=True)
        OTPChallenge.__table__.create(bind=engine, checkfirst=True)

        # 1b. Idempotently add new appointment and OTP challenge columns
        insp = inspect(engine)
        ts_type = "TIMESTAMP WITH TIME ZONE" if engine.dialect.name != "sqlite" else "TIMESTAMP"
        if insp.has_table("healthcare_appointments"):
            apt_cols = {c["name"] for c in insp.get_columns("healthcare_appointments")}
            apt_additions = [
                ("patient_age", "INTEGER"),
                ("patient_gender", "VARCHAR(20)"),
                ("reason_for_visit", "VARCHAR(500)"),
                ("consultation_fee", "VARCHAR(30)"),
                ("otp_challenge_id", "VARCHAR(64)"),
                ("verified_at", ts_type),
            ]
            with engine.begin() as conn:
                for col_name, col_type in apt_additions:
                    if col_name not in apt_cols:
                        logger.info(f"[SchemaSync] Adding column {col_name} to healthcare_appointments")
                        try:
                            conn.execute(text(f"ALTER TABLE healthcare_appointments ADD COLUMN {col_name} {col_type};"))
                        except Exception as col_err:
                            logger.debug(f"[SchemaSync] healthcare_appointments column notice: {col_err}")
                if engine.dialect.name != "sqlite":
                    try:
                        conn.execute(text("ALTER TABLE healthcare_appointments ALTER COLUMN status TYPE VARCHAR(30);"))
                    except Exception as st_err:
                        logger.debug(f"[SchemaSync] healthcare_appointments status type notice: {st_err}")

        if insp.has_table("otp_challenges"):
            otp_cols = {c["name"]: c for c in insp.get_columns("otp_challenges")}
            with engine.begin() as conn:
                if "appointment_id" not in otp_cols:
                    logger.info("[SchemaSync] Adding column appointment_id to otp_challenges")
                    try:
                        conn.execute(text("ALTER TABLE otp_challenges ADD COLUMN appointment_id INTEGER;"))
                    except Exception as col_err:
                        logger.debug(f"[SchemaSync] otp_challenges appointment_id notice: {col_err}")
                if engine.dialect.name != "sqlite":
                    for nullable_col in ("session_id", "user_id"):
                        if nullable_col in otp_cols and not otp_cols[nullable_col].get("nullable", True):
                            try:
                                conn.execute(text(f"ALTER TABLE otp_challenges ALTER COLUMN {nullable_col} DROP NOT NULL;"))
                            except Exception as null_err:
                                logger.debug(f"[SchemaSync] otp_challenges {nullable_col} nullable notice: {null_err}")

        # 2. Harmonize doctor roles for verified hospital medical officers
        db = SessionLocal()
        try:
            doctor_emails = [
                "dr.boomika@ayusync.med.in",
                "dr.sarah@aetheriahealth.org"
            ]
            for doc_email in doctor_emails:
                u = db.query(User).filter(User.email == doc_email).first()
                if u and u.role != "DOCTOR":
                    u.role = "DOCTOR"
                    db.commit()
                    logger.info(f"[SchemaSync] Verified clinical DOCTOR role assigned to: {doc_email}")

            # 3. Development-only dedicated doctor test account
            env = getattr(settings, "ENVIRONMENT", "").lower()
            if env in ("development", "dev", "test"):
                dev_doc_email = "doctor.test@ayusync.med.in"
                dev_doc = db.query(User).filter(User.email == dev_doc_email).first()
                if not dev_doc:
                    dev_doc = User(
                        name="Dr. Alex Taylor (Dev Test Physician)",
                        email=dev_doc_email,
                        password_hash=get_password_hash("DoctorTest2026!"),
                        role="DOCTOR",
                        account_status="ACTIVE",
                        failed_login_attempts=0
                    )
                    db.add(dev_doc)
                    db.commit()
                    logger.info(f"[SchemaSync] Successfully provisioned development doctor test account: {dev_doc_email}")
                else:
                    if dev_doc.role != "DOCTOR":
                        dev_doc.role = "DOCTOR"
                        db.commit()
        finally:
            db.close()
    except Exception as e:
        logger.warning(f"[SchemaSync] Doctor identity synchronization notice: {e}")


def sync_portal_lock_and_counter_schemas():
    """
    Non-destructively ensures portal_security_locks, verification_attempt_counters,
    and per-factor attempt columns on password_change_transactions exist across SQLite & PostgreSQL.
    """
    try:
        from app.models.portal_lock import PortalSecurityLock, VerificationAttemptCounter
        from app.models.password_change import PasswordChangeTransaction

        PortalSecurityLock.__table__.create(bind=engine, checkfirst=True)
        VerificationAttemptCounter.__table__.create(bind=engine, checkfirst=True)
        PasswordChangeTransaction.__table__.create(bind=engine, checkfirst=True)

        insp = inspect(engine)
        if insp.has_table("verification_attempt_counters"):
            cnt_cols = {c["name"] for c in insp.get_columns("verification_attempt_counters")}
            with engine.begin() as conn:
                if "session_id" not in cnt_cols:
                    try:
                        conn.execute(text("ALTER TABLE verification_attempt_counters ADD COLUMN session_id VARCHAR(64) DEFAULT '' NOT NULL;"))
                    except Exception as col_err:
                        logger.debug(f"[SchemaSync] verification_attempt_counters session_id notice: {col_err}")
                try:
                    if engine.dialect.name != "sqlite":
                        conn.execute(text("ALTER TABLE verification_attempt_counters DROP CONSTRAINT IF EXISTS uq_verification_attempt_scope;"))
                    else:
                        conn.execute(text("DROP INDEX IF EXISTS uq_verification_attempt_scope;"))
                except Exception as drop_err:
                    logger.debug(f"[SchemaSync] uq_verification_attempt_scope drop notice: {drop_err}")
                try:
                    conn.execute(text(
                        "CREATE UNIQUE INDEX IF NOT EXISTS uq_verification_attempt_session_scope "
                        "ON verification_attempt_counters (user_id, session_id, application, verification_purpose, factor_key);"
                    ))
                except Exception as idx_err:
                    logger.debug(f"[SchemaSync] uq_verification_attempt_session_scope notice: {idx_err}")

        if insp.has_table("password_change_transactions"):
            existing_cols = {c["name"] for c in insp.get_columns("password_change_transactions")}
            additions = [
                ("image_attempts", "INTEGER DEFAULT 0 NOT NULL"),
                ("image_max_attempts", "INTEGER DEFAULT 2 NOT NULL"),
                ("private_attempts", "INTEGER DEFAULT 0 NOT NULL"),
                ("private_max_attempts", "INTEGER DEFAULT 2 NOT NULL"),
            ]
            with engine.begin() as conn:
                for col_name, col_type in additions:
                    if col_name not in existing_cols:
                        try:
                            conn.execute(text(f"ALTER TABLE password_change_transactions ADD COLUMN {col_name} {col_type};"))
                        except Exception as col_err:
                            logger.debug(f"[SchemaSync] password_change_transactions {col_name} notice: {col_err}")
    except Exception as e:
        logger.warning(f"[SchemaSync] Portal lock & counter schema sync notice: {e}")




