import uuid
import pytest
from datetime import timedelta
from fastapi.testclient import TestClient
from app.core.config import settings
from app.services.step_up_service import StepUpService, utc_now
from app.services.auth_service import AuthService
from app.core.rate_limit import rate_limiter
from app.models.user import User


@pytest.fixture(autouse=True)
def reset_in_memory_state():
    """Ensure in-memory OTP dictionaries and rate limiters are cleared for each test."""
    rate_limiter.reset()
    with StepUpService._lock:
        StepUpService._password_resets.clear()
        StepUpService._challenges.clear()
    yield
    rate_limiter.reset()
    with StepUpService._lock:
        StepUpService._password_resets.clear()
        StepUpService._challenges.clear()


def test_1_resend_succeeds_after_cooldown_and_returns_correct_status(client: TestClient, db_session, monkeypatch):
    """Scenario 1: Resend succeeds after cooldown expires, generates fresh OTP, and returns success."""
    email = f"resend.success.{uuid.uuid4().hex[:6]}@cognisec.ai"
    reg = client.post("/api/auth/register", json={"name": "Resend User", "email": email, "password": "InitialPassword123!"})
    assert reg.status_code == 201

    captured_otps = []
    def mock_send(recipient_email, otp_code, **kwargs):
        captured_otps.append(otp_code)
        return True, "Mock email dispatched"
    monkeypatch.setattr("app.services.email_service.EmailService.send_password_reset_email", mock_send)

    # 1. Initial request
    req1 = client.post("/api/auth/password-reset/request", json={"email": email})
    assert req1.status_code == 200
    assert len(captured_otps) == 1
    otp1 = captured_otps[0]

    # Advance timestamp past 30-second cooldown
    with StepUpService._lock:
        StepUpService._password_resets[email]["created_at"] -= timedelta(seconds=35)

    # 2. Resend after cooldown
    req2 = client.post("/api/auth/password-reset/resend", json={"email": email})
    assert req2.status_code == 200
    res_json = req2.json()
    assert res_json["success"] is True
    assert "masked_email" in res_json
    assert len(captured_otps) == 2
    otp2 = captured_otps[1]
    assert otp1 != otp2, "Resend must generate a fresh OTP"

    # Verify new OTP succeeds
    ver = client.post("/api/auth/password-reset/verify", json={
        "email": email,
        "otp_code": otp2,
        "new_password": "NewValidPassword123!",
        "confirm_password": "NewValidPassword123!"
    })
    assert ver.status_code == 200
    assert ver.json()["success"] is True


def test_2_resend_blocked_during_cooldown_and_rate_limits(client: TestClient, db_session, monkeypatch):
    """Scenario 2: Resend within cooldown window is rejected with HTTP 429 Too Many Requests and Retry-After."""
    email = f"cooldown.block.{uuid.uuid4().hex[:6]}@cognisec.ai"
    client.post("/api/auth/register", json={"name": "Cooldown User", "email": email, "password": "InitialPassword123!"})

    captured_otps = []
    def mock_send(recipient_email, otp_code, **kwargs):
        captured_otps.append(otp_code)
        return True, "Mock email dispatched"
    monkeypatch.setattr("app.services.email_service.EmailService.send_password_reset_email", mock_send)

    # Initial request
    req1 = client.post("/api/auth/password-reset/request", json={"email": email})
    assert req1.status_code == 200
    assert len(captured_otps) == 1

    # Immediate resend (cooldown is active, 0s elapsed)
    res_blocked = client.post("/api/auth/password-reset/resend", json={"email": email})
    assert res_blocked.status_code == 429
    assert "wait" in res_blocked.json()["detail"].lower()
    assert "retry-after" in res_blocked.headers or "Retry-After" in res_blocked.headers
    # Email must not have been sent during blocked cooldown
    assert len(captured_otps) == 1


def test_3_expired_incorrect_and_reused_otps_cannot_reset(client: TestClient, db_session, monkeypatch):
    """Scenario 3: Expired OTP, incorrect OTP, and already consumed (reused) OTP are strictly denied."""
    email = f"otp.security.{uuid.uuid4().hex[:6]}@cognisec.ai"
    client.post("/api/auth/register", json={"name": "OTP Sec", "email": email, "password": "InitialPassword123!"})

    captured_otps = []
    def mock_send(recipient_email, otp_code, **kwargs):
        captured_otps.append(otp_code)
        return True, "Mock email dispatched"
    monkeypatch.setattr("app.services.email_service.EmailService.send_password_reset_email", mock_send)

    client.post("/api/auth/password-reset/request", json={"email": email})
    otp = captured_otps[0]

    # 3a. Incorrect OTP
    bad_res = client.post("/api/auth/password-reset/verify", json={
        "email": email,
        "otp_code": "000000",
        "new_password": "NewValidPassword123!",
        "confirm_password": "NewValidPassword123!"
    })
    assert bad_res.status_code == 400
    assert "invalid" in bad_res.json()["detail"].lower()

    # 3b. Expired OTP
    with StepUpService._lock:
        StepUpService._password_resets[email]["expires_at"] = utc_now() - timedelta(seconds=10)

    exp_res = client.post("/api/auth/password-reset/verify", json={
        "email": email,
        "otp_code": otp,
        "new_password": "NewValidPassword123!",
        "confirm_password": "NewValidPassword123!"
    })
    assert exp_res.status_code == 400
    assert "expired" in exp_res.json()["detail"].lower()

    # 3c. Fresh request then attempt reuse after success
    client.post("/api/auth/password-reset/request", json={"email": email})
    fresh_otp = captured_otps[-1]

    # First use succeeds
    good_res = client.post("/api/auth/password-reset/verify", json={
        "email": email,
        "otp_code": fresh_otp,
        "new_password": "FirstNewPassword123!",
        "confirm_password": "FirstNewPassword123!"
    })
    assert good_res.status_code == 200

    # Second use (reuse) must fail
    reuse_res = client.post("/api/auth/password-reset/verify", json={
        "email": email,
        "otp_code": fresh_otp,
        "new_password": "SecondNewPassword123!",
        "confirm_password": "SecondNewPassword123!"
    })
    assert reuse_res.status_code == 400
    assert "no active password reset" in reuse_res.json()["detail"].lower()


def test_4_and_5_successful_reset_allows_login_and_old_password_rejected(client: TestClient, db_session, monkeypatch):
    """Scenarios 4 & 5: Successful reset allows login with new password and strictly rejects old password."""
    email = f"login.consistency.{uuid.uuid4().hex[:6]}@cognisec.ai"
    old_password = "OldStrongPassword123!"
    new_password = "BrandNewPassword456@"

    # 1. Register with old password
    reg = client.post("/api/auth/register", json={"name": "Consistency User", "email": email, "password": old_password})
    assert reg.status_code == 201

    # Verify old password works initially
    l1 = client.post("/api/auth/login", json={"email": email, "password": old_password})
    assert l1.status_code == 200

    captured_otps = []
    def mock_send(recipient_email, otp_code, **kwargs):
        captured_otps.append(otp_code)
        return True, "Dispatched"
    monkeypatch.setattr("app.services.email_service.EmailService.send_password_reset_email", mock_send)

    # 2. Reset password flow
    client.post("/api/auth/password-reset/request", json={"email": email})
    otp = captured_otps[0]

    reset_res = client.post("/api/auth/password-reset/verify", json={
        "email": email,
        "otp_code": otp,
        "new_password": new_password,
        "confirm_password": new_password
    })
    assert reset_res.status_code == 200
    assert reset_res.json()["success"] is True

    # 3. Scenario 5: Old password MUST NO LONGER WORK
    old_login = client.post("/api/auth/login", json={"email": email, "password": old_password})
    assert old_login.status_code == 401
    assert "invalid" in old_login.json()["detail"].lower()

    # 4. Scenario 4: New password MUST AUTHENTICATE SUCCESSFULLY
    new_login = client.post("/api/auth/login", json={"email": email, "password": new_password})
    assert new_login.status_code == 200
    assert "access_token" in new_login.json()
    assert new_login.json()["session_status"] == "PENDING_OBSERVATION"


def test_6_incorrect_password_confirmation_is_rejected(client: TestClient, db_session, monkeypatch):
    """Scenario 6: Mismatched password confirmation is rejected without updating the user's password."""
    email = f"mismatch.pass.{uuid.uuid4().hex[:6]}@cognisec.ai"
    init_pass = "InitialPass123!"
    client.post("/api/auth/register", json={"name": "Mismatch User", "email": email, "password": init_pass})

    captured = []
    def mock_capture(*args, **kwargs):
        otp = kwargs.get("otp_code") or (args[1] if len(args) > 1 else "")
        captured.append(otp)
        return True, "OK"
    monkeypatch.setattr("app.services.email_service.EmailService.send_password_reset_email", mock_capture)

    client.post("/api/auth/password-reset/request", json={"email": email})
    otp = captured[0]

    # Mismatched confirmation
    mismatch_res = client.post("/api/auth/password-reset/verify", json={
        "email": email,
        "otp_code": otp,
        "new_password": "NewValidPassword123!",
        "confirm_password": "CompletelyDifferent456!"
    })
    assert mismatch_res.status_code in (400, 422)
    assert "match" in str(mismatch_res.json()).lower()

    # Old password still intact
    l = client.post("/api/auth/login", json={"email": email, "password": init_pass})
    assert l.status_code == 200


def test_7_smtp_failure_is_reported_accurately_without_leaking_secrets(client: TestClient, db_session, monkeypatch):
    """Scenario 7: SMTP delivery failure returns 502 Bad Gateway with sanitized message, never claiming false success."""
    email = f"smtp.error.{uuid.uuid4().hex[:6]}@cognisec.ai"
    client.post("/api/auth/register", json={"name": "SMTP Test", "email": email, "password": "InitialPass123!"})

    monkeypatch.setattr(settings, "EXHIBITION_MODE", False)
    def mock_smtp_err(*args, **kwargs):
        # Simulated sensitive internal SMTP traceback
        return False, "SMTPAuthenticationError: 535-5.7.8 Username and Password not accepted. Host=internal-mail.corp:587 SecretKey=SECRET_PASS_99"
    monkeypatch.setattr("app.services.email_service.EmailService.send_password_reset_email", mock_smtp_err)

    # 1. Request endpoint reports 502 failure
    req_res = client.post("/api/auth/password-reset/request", json={"email": email})
    assert req_res.status_code == 502
    detail = req_res.json()["detail"]
    assert "SECRET_PASS_99" not in detail, "Internal credentials must never leak in error response"
    assert "Username and Password" not in detail, "SMTP credentials must never leak"
    assert "failed" in detail.lower() or "unable" in detail.lower()

    # 2. Resend endpoint also reports 502 failure without leaking secrets
    resend_res = client.post("/api/auth/password-reset/resend", json={"email": email})
    assert resend_res.status_code == 502
    rdetail = resend_res.json()["detail"]
    assert "SECRET_PASS_99" not in rdetail
    assert "failed" in rdetail.lower() or "unable" in rdetail.lower()


def test_8_login_and_reset_operate_on_same_database_user_record(client: TestClient, db_session, monkeypatch):
    """Scenario 8: Verifies login and reset manipulate the exact same database User row across operations."""
    email = f"db.record.{uuid.uuid4().hex[:6]}@cognisec.ai"
    init_pass = "StartPass123!"
    new_pass = "UpdatedPass789!"

    reg = client.post("/api/auth/register", json={"name": "DB Row User", "email": email, "password": init_pass})
    assert reg.status_code == 201

    # Fetch user row id directly from db_session
    user_before = AuthService.get_user_by_email(db_session, email)
    assert user_before is not None
    user_id = user_before.id
    init_hash = user_before.password_hash

    captured = []
    def mock_capture(*args, **kwargs):
        otp = kwargs.get("otp_code") or (args[1] if len(args) > 1 else "")
        captured.append(otp)
        return True, "OK"
    monkeypatch.setattr("app.services.email_service.EmailService.send_password_reset_email", mock_capture)

    client.post("/api/auth/password-reset/request", json={"email": email})
    client.post("/api/auth/password-reset/verify", json={
        "email": email,
        "otp_code": captured[0],
        "new_password": new_pass,
        "confirm_password": new_pass
    })

    # Query same user row from database
    db_session.expire_all()
    user_after = db_session.query(User).filter(User.id == user_id).first()
    assert user_after is not None
    assert user_after.email == email
    assert user_after.password_hash != init_hash, "Password hash must be updated in the existing user row"

    # Authenticate via login
    login_res = client.post("/api/auth/login", json={"email": email, "password": new_pass})
    assert login_res.status_code == 200
    assert login_res.json()["user_id"] == user_id
