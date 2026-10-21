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

