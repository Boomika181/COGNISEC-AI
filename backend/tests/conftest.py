import pytest
import os
import sys

# Ensure backend root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Explicitly enforce isolated test database environment before importing any app modules
os.environ["DATABASE_URL"] = "sqlite:///./test_cognisec.db"
os.environ["ENVIRONMENT"] = "test"

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database.base import Base
from app.database.connection import get_db, get_simulator_db
from app.main import app
from app.core.security import get_password_hash
from app.core.config import settings
from app.models.user import User
from app.models.device import Device
from app.models.behavior import BehaviorProfile

# Configure test environment
settings.ENVIRONMENT = "test"
settings.EXHIBITION_MODE = True
settings.VERIFIED_COGNISIC_MAILBOXES = [
    "test.admin@cognisec.ai",
    "test.user@cognisec.ai",
    "admin.soc@cognisec.ai",
    "user.portal@cognisec.ai",
    "security@cognisec.ai",
    "security.ops@cognisec.ai"
]


@pytest.fixture(autouse=True)
def mock_smtp_in_tests(monkeypatch):
    """Prevents tests from connecting to real Gmail SMTP unless explicitly testing live delivery."""
    from app.services.email_service import EmailService
    original_send_otp = getattr(EmailService, "_original_send_otp", EmailService.send_otp_email)
    original_send_alert = getattr(EmailService, "_original_send_alert", EmailService.send_new_device_login_alert)
    original_send_reset = getattr(EmailService, "_original_send_reset", EmailService.send_password_reset_email)
    EmailService._original_send_otp = original_send_otp
    EmailService._original_send_alert = original_send_alert
    EmailService._original_send_reset = original_send_reset

    def mocked_send_otp(recipient_email, otp_code, expires_in_minutes=5, *args, **kwargs):
        if not EmailService.is_configured():
            return original_send_otp(recipient_email, otp_code, expires_in_minutes, *args, **kwargs)
        is_deliv, reason = EmailService.is_deliverable_recipient(recipient_email)
        if not is_deliv:
            return (False, f"Delivery rejected: {reason}")
        if os.getenv("TEST_USE_REAL_SMTP", "false").lower() == "true":
            return original_send_otp(recipient_email, otp_code, expires_in_minutes, *args, **kwargs)
        return (True, f"Mocked email dispatched to {EmailService.mask_email(recipient_email)}")

    def mocked_send_reset(recipient_email, otp_code, expires_in_minutes=5, *args, **kwargs):
        if not EmailService.is_configured():
            return original_send_reset(recipient_email, otp_code, expires_in_minutes, *args, **kwargs)
        is_deliv, reason = EmailService.is_deliverable_recipient(recipient_email)
        if not is_deliv:
            return (False, f"Delivery rejected: {reason}")
        if os.getenv("TEST_USE_REAL_SMTP", "false").lower() == "true":
            return original_send_reset(recipient_email, otp_code, expires_in_minutes, *args, **kwargs)
        return (True, f"Mocked password reset email dispatched to {EmailService.mask_email(recipient_email)}")

    def mocked_send_alert(*args, **kwargs):
        if not EmailService.is_configured():
            return original_send_alert(*args, **kwargs)
        recip = kwargs.get("recipient_email") or (args[0] if len(args) > 0 else "")
        is_deliv, reason = EmailService.is_deliverable_recipient(recip)
        if not is_deliv:
            return (False, f"Delivery rejected: {reason}")
        if os.getenv("TEST_USE_REAL_SMTP", "false").lower() == "true":
            return original_send_alert(*args, **kwargs)
        return (True, "Mocked new device alert dispatched")

    monkeypatch.setattr("app.services.email_service.EmailService.send_otp_email", mocked_send_otp)
    monkeypatch.setattr("app.services.email_service.EmailService.send_new_device_login_alert", mocked_send_alert)
    monkeypatch.setattr("app.services.email_service.EmailService.send_password_reset_email", mocked_send_reset)

TEST_DB_URL = "sqlite:///./test_cognisec.db"
test_engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

# Monkeypatch connection module so direct SessionLocal() calls in tests/services strictly use test_engine
import app.database.connection as conn_module
conn_module.engine = test_engine
conn_module.SessionLocal = TestingSessionLocal


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    settings.ENVIRONMENT = "test"
    settings.EXHIBITION_MODE = True
    conn_module.engine = test_engine
    conn_module.SessionLocal = TestingSessionLocal
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    
    # Pre-seed test admin and user in isolated SQLite test database
    db = TestingSessionLocal()
    admin = User(
        name="Test Admin",
        email="test.admin@cognisec.ai",
        password_hash=get_password_hash("Admin@123"),
        role="ADMIN",
        account_status="ACTIVE"
    )
    user = User(
        name="Test User",
        email="test.user@cognisec.ai",
        password_hash=get_password_hash("User@123"),
        role="USER",
        account_status="ACTIVE"
    )
    doctor = User(
        name="Dr. Boomika Ram",
        email="dr.boomika@ayusync.med.in",
        password_hash=get_password_hash("Doctor@123"),
        role="DOCTOR",
        account_status="ACTIVE"
    )
    db.add(admin)
    db.add(user)
    db.add(doctor)
    db.commit()
    db.close()

    yield

    Base.metadata.drop_all(bind=test_engine)
    if os.path.exists("./test_cognisec.db"):
        try:
            os.remove("./test_cognisec.db")
        except Exception:
            pass


@pytest.fixture(autouse=True)
def global_db_isolation():
    """Autouse fixture ensuring every FastAPI request in all tests uses the isolated test DB."""
    # Strict safety invariant: tests must NEVER connect to non-sqlite production DB
    assert "sqlite" in TEST_DB_URL, f"CRITICAL: Tests attempted to use non-sqlite DB: {TEST_DB_URL}"

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_simulator_db] = override_get_db
    yield
    app.dependency_overrides.pop(get_db, None)
    app.dependency_overrides.pop(get_simulator_db, None)


@pytest.fixture
def db_session():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def client(db_session):
    from app.core.rate_limit import rate_limiter
    rate_limiter.reset()

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_simulator_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    rate_limiter.reset()


@pytest.fixture
def admin_token(client, db_session):
    res = client.post("/api/auth/login", json={
        "email": "test.admin@cognisec.ai",
        "password": "Admin@123",
        "application": "platform"
    })
    sid = res.json()["session_id"]
    from app.services.session_service import SessionService
    SessionService.activate_session_after_login_otp(db_session, sid)
    return res.json()["access_token"]


@pytest.fixture
def user_token(client, db_session):
    res = client.post("/api/auth/login", json={
        "email": "test.user@cognisec.ai",
        "password": "User@123",
        "application": "platform"
    })
    sid = res.json()["session_id"]
    from app.services.session_service import SessionService
    SessionService.activate_session_after_login_otp(db_session, sid)
    return res.json()["access_token"]
