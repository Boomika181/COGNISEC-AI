import pytest
import smtplib
import socket
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from app.main import app
from app.core.config import settings
from app.services.email_service import EmailService
from app.services.step_up_service import StepUpService
from app.models.user import User
from app.models.device import Device
from app.models.notification import DeviceNotification
from app.models.security_event import SecurityEvent
from app.models.session import Session as DbSession
import uuid
from app.core.security import get_password_hash, create_access_token
from app.services.session_service import SessionService


@pytest.fixture
def test_user(db_session):
    unique_id = uuid.uuid4().hex[:8]
    user = User(
        name=f"SMTP Test Subject {unique_id}",
        email=f"smtp.user.{unique_id}@cognisec.ai",
        password_hash=get_password_hash("Password123!"),
        role="USER",
        account_status="ACTIVE"
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def auth_headers(test_user, db_session):
    db_sess = SessionService.create_session(db_session, user_id=test_user.id, application="platform")
    token = create_access_token(subject=test_user.id, role=test_user.role, session_id=db_sess.id)
    return {"Authorization": f"Bearer {token}"}, db_sess.id


@pytest.fixture
def admin_headers(db_session):
    admin = db_session.query(User).filter(User.role == "ADMIN").first()
    if not admin:
        unique_id = uuid.uuid4().hex[:8]
        admin = User(
            name="SMTP Admin",
            email=f"smtp.admin.{unique_id}@cognisec.ai",
            password_hash=get_password_hash("Admin123!"),
            role="ADMIN",
            account_status="ACTIVE"
        )
        db_session.add(admin)
        db_session.commit()
        db_session.refresh(admin)

    db_sess = SessionService.create_session(db_session, user_id=admin.id, application="platform")
    token = create_access_token(subject=admin.id, role=admin.role, session_id=db_sess.id)
    return {"Authorization": f"Bearer {token}"}


# 1. SMTP disabled
def test_smtp_disabled():
    with patch.object(settings, "SMTP_ENABLED", False), patch.object(settings, "EXHIBITION_MODE", False):
        assert EmailService.is_configured() is False
        diag = EmailService.get_diagnostics()
        assert diag["smtp_enabled"] is False
        assert diag["delivery_status"] == "DISABLED"

        success, msg = EmailService.send_email(
            recipient_email="target@example.com",
            subject="Test",
            plain_text="Hello"
        )
        assert success is False
        assert "not configured or disabled" in msg


# 2. Missing environment variables
def test_missing_environment_variables():
    with patch.object(settings, "SMTP_ENABLED", True), \
         patch.object(settings, "SMTP_HOST", "smtp.gmail.com"), \
         patch.object(settings, "SMTP_USER", None), \
         patch.object(settings, "SMTP_PASSWORD", None), \
         patch.object(settings, "EXHIBITION_MODE", False):
        assert EmailService.is_configured() is False
        diag = EmailService.get_diagnostics()
        assert diag["delivery_status"] == "INCOMPLETE_CONFIGURATION"
        assert diag["smtp_user_configured"] is False
        assert diag["smtp_password_configured"] is False


# 3. Successful SMTP send using mocked transport
def test_successful_smtp_send_mocked_transport():
    mock_server = MagicMock()
    with patch.object(settings, "SMTP_ENABLED", True), \
         patch.object(settings, "SMTP_HOST", "smtp.gmail.com"), \
         patch.object(settings, "SMTP_USER", "security@cognisec.ai"), \
         patch.object(settings, "SMTP_PASSWORD", "test-app-pass"), \
         patch.object(settings, "SMTP_FROM", "security@cognisec.ai"), \
         patch.object(settings, "SMTP_TLS", True), \
         patch("smtplib.SMTP", return_value=mock_server):

        success, msg = EmailService.send_email(
            recipient_email="user@example.com",
            subject="Verification Test",
            plain_text="Test Body",
            html_text="<p>Test Body</p>"
        )

        assert success is True
        assert "dispatched successfully" in msg
        mock_server.ehlo.assert_called()
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with("security@cognisec.ai", "test-app-pass")
        mock_server.sendmail.assert_called_once()
        mock_server.quit.assert_called_once()


# 4. Authentication failure
def test_smtp_authentication_failure():
    mock_server = MagicMock()
    mock_server.login.side_effect = smtplib.SMTPAuthenticationError(535, b"5.7.8 Bad credentials")

    with patch.object(settings, "SMTP_ENABLED", True), \
         patch.object(settings, "SMTP_HOST", "smtp.gmail.com"), \
         patch.object(settings, "SMTP_USER", "user@gmail.com"), \
         patch.object(settings, "SMTP_PASSWORD", "wrong-pass"), \
         patch.object(settings, "SMTP_FROM", "user@gmail.com"), \
         patch("smtplib.SMTP", return_value=mock_server):

        success, msg = EmailService.send_email(
            recipient_email="target@example.com",
            subject="Test Auth",
            plain_text="Hello"
        )
        assert success is False
        assert "authentication failure (535)" in msg
        mock_server.quit.assert_called_once()


# 5. Connection timeout
def test_smtp_connection_timeout():
    mock_server = MagicMock()
    mock_server.starttls.side_effect = socket.timeout("Timed out connecting")

    with patch.object(settings, "SMTP_ENABLED", True), \
         patch.object(settings, "SMTP_HOST", "smtp.gmail.com"), \
         patch.object(settings, "SMTP_USER", "user@gmail.com"), \
         patch.object(settings, "SMTP_PASSWORD", "pass"), \
         patch.object(settings, "SMTP_FROM", "user@gmail.com"), \
         patch("smtplib.SMTP", return_value=mock_server):

        success, msg = EmailService.send_email(
            recipient_email="target@example.com",
            subject="Test Timeout",
            plain_text="Hello"
        )
        assert success is False
        assert "timed out" in msg.lower()
        mock_server.quit.assert_called_once()


# 6. New-device notification sent to database-resolved recipient
def test_new_device_notification_sent_to_database_resolved_recipient(client, test_user, db_session):
    with patch.object(EmailService, "send_new_device_login_alert", return_value=(True, "Alert sent")) as mock_alert:
        res = client.post("/api/auth/login", json={
            "email": test_user.email,
            "password": "Password123!",
            "device_fingerprint": "fp_second_login_unrecognized",
            "browser": "Firefox/124.0",
            "os": "Linux"
        })
        assert res.status_code == 200
        assert mock_alert.call_count >= 1
        kwargs = mock_alert.call_args[1]
        assert kwargs["recipient_email"] == test_user.email
        assert kwargs["user_name"] == test_user.name


# 7. OTP email sent to registered user
def test_otp_email_sent_to_registered_user(client, auth_headers, test_user):
    headers, session_id = auth_headers
    with patch.object(EmailService, "send_otp_email", return_value=(True, "Code dispatched")) as mock_send_otp:
        res = client.post("/api/security/step-up/challenge", headers=headers, json={"session_id": session_id})
        assert res.status_code == 200
        mock_send_otp.assert_called_once()
        kwargs = mock_send_otp.call_args[1]
        assert kwargs["recipient_email"] == test_user.email
        assert len(kwargs["otp_code"]) == 6
        assert kwargs["otp_code"].isdigit()


# 8. OTP never returned in normal API responses
def test_otp_never_returned_in_normal_api_responses(client, auth_headers):
    headers, session_id = auth_headers
    with patch.object(settings, "ENVIRONMENT", "production"), \
         patch.object(settings, "EXHIBITION_MODE", False), \
         patch.object(EmailService, "send_otp_email", return_value=(True, "Sent")):

        res = client.post("/api/security/step-up/challenge", headers=headers, json={"session_id": session_id})
        assert res.status_code == 200
        data = res.json()
        assert data["otp"] == ""
        assert data["is_demo_otp"] is False
        assert data["delivery_status"] == "SENT"


# 9. Expired, invalid, replayed and resent OTPs
def test_expired_invalid_replayed_and_resent_otps(client, auth_headers, test_user):
    headers, session_id = auth_headers

    # Capture generated OTP via send_otp_email mock
    captured_otps = []

    def mock_send(recipient_email, otp_code, **kwargs):
        captured_otps.append(otp_code)
        return True, "Code delivered"

    with patch.object(EmailService, "send_otp_email", side_effect=mock_send):
        # A. Create challenge
        res = client.post("/api/security/step-up/challenge", headers=headers, json={"session_id": session_id})
        assert res.status_code == 200
        first_otp = captured_otps[0]

        # B. Invalid code fails with 400
        bad_res = client.post("/api/security/step-up/verify", headers=headers, json={
            "session_id": session_id,
            "challenge_code": "000000" if first_otp != "000000" else "111111"
        })
        assert bad_res.status_code == 400
        assert "Invalid verification" in bad_res.json()["detail"]

        # C. Resent OTP invalidates previous challenge
        res2 = client.post("/api/security/step-up/challenge", headers=headers, json={"session_id": session_id})
        assert res2.status_code == 200
        second_otp = captured_otps[1]
        assert second_otp != first_otp or len(captured_otps) == 2

        # Submitting the invalidated first_otp now fails with 400
        stale_res = client.post("/api/security/step-up/verify", headers=headers, json={
            "session_id": session_id,
            "challenge_code": first_otp
        })
        assert stale_res.status_code == 400
        assert "Invalid verification" in stale_res.json()["detail"]

        # D. Submitting second_otp succeeds with 200
        valid_res = client.post("/api/security/step-up/verify", headers=headers, json={
            "session_id": session_id,
            "challenge_code": second_otp
        })
        assert valid_res.status_code == 200
        assert valid_res.json()["decision"] == "ALLOW"
        assert valid_res.json()["session_status"] == "ACTIVE"

        # E. Replaying the consumed second_otp fails immediately with 400
        replay_res = client.post("/api/security/step-up/verify", headers=headers, json={
            "session_id": session_id,
            "challenge_code": second_otp
        })
        assert replay_res.status_code == 400
        assert "No active step-up challenge found" in replay_res.json()["detail"]


# 10. Failed email delivery keeps protected access blocked
def test_failed_email_delivery_keeps_protected_access_blocked(client, auth_headers):
    headers, session_id = auth_headers
    with patch.object(settings, "EXHIBITION_MODE", False), \
         patch.object(EmailService, "send_otp_email", return_value=(False, "Connection to mail server refused")):

        res = client.post("/api/security/step-up/challenge", headers=headers, json={"session_id": session_id})
        assert res.status_code == 502
        assert "Email OTP transmission failed" in res.json()["detail"]


# 11. Email failure does not erase security events or notifications
def test_email_failure_does_not_erase_security_events_or_notifications(client, test_user, db_session):
    with patch.object(EmailService, "send_new_device_login_alert", return_value=(False, "Connection to smtp.gmail.com timed out")):
        res = client.post("/api/auth/login", json={
            "email": test_user.email,
            "password": "Password123!",
            "device_fingerprint": "fp_email_failed_unrecognized",
            "browser": "Edge/120.0"
        })
        assert res.status_code == 200

        # Verify notification persists with FAILED delivery status
        notif = db_session.query(DeviceNotification).filter(
            DeviceNotification.user_id == test_user.id,
            DeviceNotification.notification_type == "NEW_DEVICE_LOGIN"
        ).order_by(DeviceNotification.created_at.desc()).first()
        assert notif is not None
        assert notif.email_delivery_status == "FAILED"
        assert "timed out" in notif.email_error

        # Verify security event persists
        sec_event = db_session.query(SecurityEvent).filter(
            SecurityEvent.user_id == test_user.id,
            SecurityEvent.event_type == "UNRECOGNIZED_DEVICE_LOGIN"
        ).first()
        assert sec_event is not None


# 12. Admin email diagnostics and test endpoints
def test_admin_email_diagnostics_and_test_endpoints(client, admin_headers, auth_headers):
    user_hdr, _ = auth_headers

    # Normal user is blocked (403 Forbidden)
    denied_diag = client.get("/api/admin/email/diagnostics", headers=user_hdr)
    assert denied_diag.status_code == 403

    denied_test = client.post("/api/admin/email/send-test", headers=user_hdr, json={"recipient_email": "test@example.com"})
    assert denied_test.status_code == 403

    # Admin access allowed
    diag_res = client.get("/api/admin/email/diagnostics", headers=admin_headers)
    assert diag_res.status_code == 200
    diag_data = diag_res.json()
    assert "smtp_enabled" in diag_data
    assert "smtp_password_configured" in diag_data
    # Ensure password itself is NOT in response
    assert "smtp_password" not in diag_data
    assert "password" not in diag_data

    # Test connection endpoint
    with patch.object(EmailService, "test_connection", return_value=(True, "Connected")):
        conn_res = client.post("/api/admin/email/test-connection", headers=admin_headers)
        assert conn_res.status_code == 200
        assert conn_res.json()["success"] is True

    # Send test email endpoint
    with patch.object(EmailService, "send_email", return_value=(True, "Delivered")):
        send_res = client.post("/api/admin/email/send-test", headers=admin_headers, json={"recipient_email": "admin@example.com"})
        assert send_res.status_code == 200
        assert send_res.json()["success"] is True
