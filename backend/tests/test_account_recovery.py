import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.config import settings
from app.services.step_up_service import StepUpService
from app.services.auth_service import AuthService
from app.core.rate_limit import rate_limiter
from app.models.user import User


@pytest.fixture(autouse=True)
def reset_state():
    StepUpService.reset()
    rate_limiter.reset()
    yield
    StepUpService.reset()
    rate_limiter.reset()


def test_password_reset_request_anti_enumeration(client: TestClient, db_session):
    # Non-existent user should return generic success without revealing absence
    res = client.post("/api/auth/password-reset/request", json={"email": "nonexistent.user@cognisec.ai"})
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert "verification code has been sent" in data["message"].lower()


def test_password_reset_flow_e2e(client: TestClient, db_session, monkeypatch):
    # Register a new user
    reg_email = "recovery.test.user@cognisec.ai"
    initial_pass = "Initial@Pass123"
    reg_res = client.post("/api/auth/register", json={
        "name": "Recovery User",
        "email": reg_email,
        "password": initial_pass
    })
    assert reg_res.status_code == 201

    # Intercept EmailService.send_password_reset_email to capture OTP
    captured = {}
    def mock_send_otp(recipient_email, otp_code, **kwargs):
        captured["recipient"] = recipient_email
        captured["otp"] = otp_code
        return True, "Mock email dispatched"
    monkeypatch.setattr("app.services.email_service.EmailService.send_password_reset_email", mock_send_otp)
    monkeypatch.setattr("app.services.email_service.EmailService.send_otp_email", mock_send_otp)

    # 1. Request password reset
    req_res = client.post("/api/auth/password-reset/request", json={"email": reg_email})
    assert req_res.status_code == 200
    assert captured["recipient"] == reg_email
    otp_code = captured["otp"]
    assert len(otp_code) == 6

    # 2. Reject weak new password
    weak_res = client.post("/api/auth/password-reset/verify", json={
        "email": reg_email,
        "otp_code": otp_code,
        "new_password": "weak"
    })
    assert weak_res.status_code == 422  # Pydantic strength validator rejection

    # 3. Reject incorrect OTP
    bad_otp_res = client.post("/api/auth/password-reset/verify", json={
        "email": reg_email,
        "otp_code": "000000",
        "new_password": "NewSecret@Pass456"
    })
    assert bad_otp_res.status_code == 400
    assert "Invalid verification code" in bad_otp_res.json()["detail"]

    # 4. Verify with correct OTP and valid new password
    new_pass = "NewSecret@Pass456"
    verify_res = client.post("/api/auth/password-reset/verify", json={
        "email": reg_email,
        "otp_code": otp_code,
        "new_password": new_pass
    })
    assert verify_res.status_code == 200
    assert verify_res.json()["success"] is True

    # 5. Old password must now be rejected
    old_login = client.post("/api/auth/login", json={
        "email": reg_email,
        "password": initial_pass
    })
    assert old_login.status_code == 401
    assert "Invalid email address or password" in old_login.json()["detail"]

    # 6. New password must authenticate successfully
    new_login = client.post("/api/auth/login", json={
        "email": reg_email,
        "password": new_pass
    })
    assert new_login.status_code == 200
    assert "access_token" in new_login.json()
    assert new_login.json()["session_status"] == "PENDING_OBSERVATION"


def test_dev_account_recovery_endpoint_requires_auth(client: TestClient, db_session):
    # Without header -> 403 Forbidden
    res = client.post("/api/auth/recover-account", json={
        "email": "user.portal@cognisec.ai",
        "new_password": "NewSecret@Pass456"
    })
    assert res.status_code == 403

    # With invalid header -> 403 Forbidden
    res_bad = client.post(
        "/api/auth/recover-account",
        headers={"X-Bootstrap-Key": "wrong_key"},
        json={"email": "user.portal@cognisec.ai", "new_password": "NewSecret@Pass456"}
    )
    assert res_bad.status_code == 403


def test_dev_account_recovery_preserves_user_data(client: TestClient, db_session):
    # Register user with specific role
    email = "preserve.data@cognisec.ai"
    reg_res = client.post("/api/auth/register", json={
        "name": "Preserve Data User",
        "email": email,
        "password": "Initial@Pass123"
    })
    assert reg_res.status_code == 201

    user_before = AuthService.get_user_by_email(db_session, email)
    original_id = user_before.id
    original_role = user_before.role
    original_status = user_before.account_status

    # Recover account
    new_pass = "Recovered@Pass999"
    rec_res = client.post(
        "/api/auth/recover-account",
        headers={"X-Bootstrap-Key": settings.BOOTSTRAP_ADMIN_KEY},
        json={"email": email, "new_password": new_pass}
    )
    assert rec_res.status_code == 200

    db_session.expire_all()
    user_after = AuthService.get_user_by_email(db_session, email)
    assert user_after.id == original_id
    assert user_after.role == original_role
    assert user_after.account_status == original_status

    # Authenticates with new password
    login_res = client.post("/api/auth/login", json={"email": email, "password": new_pass})
    assert login_res.status_code == 200


def test_password_reset_expired_otp_rejected(client: TestClient, db_session, monkeypatch):
    """Expired password reset OTP is safely rejected."""
    email = "expired.otp@cognisec.ai"
    client.post("/api/auth/register", json={"name": "Expired Test", "email": email, "password": "SecurePassword1!"})

    captured = {}
    def mock_send(recipient_email, otp_code, **kwargs):
        captured["otp"] = otp_code
        return True, "Dispatched"
    monkeypatch.setattr("app.services.email_service.EmailService.send_password_reset_email", mock_send)

    client.post("/api/auth/password-reset/request", json={"email": email})
    otp = captured["otp"]

    # Fast-forward expiry
    from datetime import datetime, timezone, timedelta
    from app.services.step_up_service import StepUpService
    with StepUpService._lock:
        if email in StepUpService._password_resets:
            StepUpService._password_resets[email]["expires_at"] = datetime.now(timezone.utc) - timedelta(seconds=10)

    res = client.post("/api/auth/password-reset/verify", json={
        "email": email,
        "otp_code": otp,
        "new_password": "NewSecurePassword2!"
    })
    assert res.status_code == 400
    assert "expired" in res.json()["detail"].lower()


def test_password_reset_single_use_prevents_reuse(client: TestClient, db_session, monkeypatch):
    """Reset OTP is consumed on first valid use and cannot be replayed."""
    email = "single.use@cognisec.ai"
    client.post("/api/auth/register", json={"name": "Single Use", "email": email, "password": "SecurePassword1!"})

    captured = {}
    def mock_send(recipient_email, otp_code, **kwargs):
        captured["otp"] = otp_code
        return True, "Dispatched"
    monkeypatch.setattr("app.services.email_service.EmailService.send_password_reset_email", mock_send)

    client.post("/api/auth/password-reset/request", json={"email": email})
    otp = captured["otp"]

    # First verify succeeds
    res1 = client.post("/api/auth/password-reset/verify", json={
        "email": email,
        "otp_code": otp,
        "new_password": "NewSecurePassword2!"
    })
    assert res1.status_code == 200

    # Second verify with same OTP is rejected
    res2 = client.post("/api/auth/password-reset/verify", json={
        "email": email,
        "otp_code": otp,
        "new_password": "AnotherPassword3!"
    })
    assert res2.status_code == 400
    assert "no active" in res2.json()["detail"].lower() or "expired" in res2.json()["detail"].lower()


def test_password_reset_cross_user_isolation(client: TestClient, db_session, monkeypatch):
    """OTP issued for User A cannot reset User B's password."""
    email_a = "user.alpha@cognisec.ai"
    email_b = "user.beta@cognisec.ai"
    client.post("/api/auth/register", json={"name": "User Alpha", "email": email_a, "password": "SecurePassword1!"})
    client.post("/api/auth/register", json={"name": "User Beta", "email": email_b, "password": "SecurePassword1!"})

    captured = {}
    def mock_send(recipient_email, otp_code, **kwargs):
        captured["recipient"] = recipient_email
        captured["otp"] = otp_code
        return True, "Dispatched"
    monkeypatch.setattr("app.services.email_service.EmailService.send_password_reset_email", mock_send)

    # Request reset for User A
    client.post("/api/auth/password-reset/request", json={"email": email_a})
    otp_a = captured["otp"]

    # Attempt to use User A's OTP to reset User B
    res_b = client.post("/api/auth/password-reset/verify", json={
        "email": email_b,
        "otp_code": otp_a,
        "new_password": "HackedPassword99!"
    })
    assert res_b.status_code == 400

    # User B's password remains intact
    login_b = client.post("/api/auth/login", json={"email": email_b, "password": "SecurePassword1!"})
    assert login_b.status_code == 200


def test_password_reset_revokes_active_sessions(client: TestClient, db_session, monkeypatch):
    """Password reset immediately revokes all prior active sessions for zero-trust hygiene."""
    email = "revoke.sessions@cognisec.ai"
    client.post("/api/auth/register", json={"name": "Revoke Test", "email": email, "password": "SecurePassword1!"})
    login_res = client.post("/api/auth/login", json={"email": email, "password": "SecurePassword1!"})
    sid = login_res.json()["session_id"]
    headers = {"Authorization": f"Bearer {login_res.json()['access_token']}"}

    captured = {}
    def mock_send(recipient_email, otp_code, **kwargs):
        captured["otp"] = otp_code
        return True, "Dispatched"
    monkeypatch.setattr("app.services.email_service.EmailService.send_password_reset_email", mock_send)

    # Reset password
    client.post("/api/auth/password-reset/request", json={"email": email})
    client.post("/api/auth/password-reset/verify", json={
        "email": email,
        "otp_code": captured["otp"],
        "new_password": "NewSecurePassword2!"
    })

    # Prior session cannot access protected endpoints
    prot_res = client.get("/api/users/profile", headers=headers)
    assert prot_res.status_code in (401, 403)


def test_password_reset_smtp_failure_handling(client: TestClient, db_session, monkeypatch):
    """When SMTP genuinely fails, returns 502 Bad Gateway and reports actual error."""
    import uuid
    email = f"smtp.fail.{uuid.uuid4().hex[:6]}@cognisec.ai"
    reg_res = client.post("/api/auth/register", json={"name": "SMTP Fail", "email": email, "password": "SecurePassword1!"})
    assert reg_res.status_code == 201

    monkeypatch.setattr(settings, "EXHIBITION_MODE", False)
    def mock_fail(*args, **kwargs):
        return False, "Connection to mail.smtp.server timed out"
    monkeypatch.setattr("app.services.email_service.EmailService.send_password_reset_email", mock_fail)

    res = client.post("/api/auth/password-reset/request", json={"email": email})
    assert res.status_code == 502
    assert "timed out" in res.json()["detail"].lower() or "failed" in res.json()["detail"].lower()


def test_password_reset_across_all_four_portals(client: TestClient, db_session, monkeypatch):
    """Password reset workflow operates identically for all portal application accounts."""
    portal_apps = ["platform", "PORTAL_COLLEGE", "PORTAL_HEALTHCARE", "PORTAL_SHOPPING"]

    captured = {}
    def mock_send(recipient_email, otp_code, **kwargs):
        captured["recipient"] = recipient_email
        captured["otp"] = otp_code
        return True, "Dispatched"
    monkeypatch.setattr("app.services.email_service.EmailService.send_password_reset_email", mock_send)

    for app_id in portal_apps:
        email = f"reset_{app_id.lower()}@cognisec.ai"
        init_pass = "InitialPass123!"
        new_pass = "UpdatedPass456!"

        # Register & Login
        client.post("/api/auth/register", json={"name": f"User {app_id}", "email": email, "password": init_pass})
        res1 = client.post("/api/auth/login", json={"email": email, "password": init_pass, "application": app_id})
        assert res1.status_code == 200

        # Reset Password
        req = client.post("/api/auth/password-reset/request", json={"email": email})
        assert req.status_code == 200
        assert captured["recipient"] == email

        ver = client.post("/api/auth/password-reset/verify", json={
            "email": email,
            "otp_code": captured["otp"],
            "new_password": new_pass
        })
        assert ver.status_code == 200

        # Login with new password
        res2 = client.post("/api/auth/login", json={"email": email, "password": new_pass, "application": app_id})
        assert res2.status_code == 200


def test_password_visibility_and_frontend_portals_contract():
    """Confirms that all 4 portals define recovery entry points and password visibility toggles."""
    import os
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

    portal_files = ["index.html", "college.html", "healthcare.html", "shopping.html"]
    for pf in portal_files:
        fpath = os.path.join(base_dir, pf)
        assert os.path.exists(fpath), f"{pf} not found"
        with open(fpath, "r", encoding="utf-8") as f:
            html = f.read()
        assert "openForgotPasswordModal" in html, f"{pf} missing Forgot Password trigger"
        assert "togglePasswordVisibility" in html, f"{pf} missing password visibility toggle"

    # Confirm cognisec-client.js defines universal togglePasswordVisibility
    client_js_path = os.path.join(base_dir, "cognisec-client.js")
    with open(client_js_path, "r", encoding="utf-8") as f:
        client_js = f.read()
    assert "window.togglePasswordVisibility" in client_js
    assert "EYE_ON_SVG" in client_js
    assert "EYE_OFF_SVG" in client_js



