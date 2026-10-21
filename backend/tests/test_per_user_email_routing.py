import pytest
import time
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.core.config import settings
from app.models.user import User
from app.models.session import Session as SessionModel
from app.services.email_service import EmailService
from app.services.step_up_service import StepUpService
from app.services.session_service import SessionService
from app.services.auth_service import AuthService
from app.core.security import get_password_hash, create_access_token


def fast_forward_observation(db_session: Session, session_id: str, extra_seconds: int = 5):
    """Utility to simulate elapsed observation window."""
    sess = db_session.query(SessionModel).filter(SessionModel.id == session_id).first()
    sess.observation_started_at = datetime.now(timezone.utc) - timedelta(
        seconds=settings.OBSERVATION_WINDOW_SECONDS + extra_seconds
    )
    db_session.commit()
    db_session.refresh(sess)
    return sess


def register_and_login_user(
    client: TestClient,
    email: str,
    password: str = "SecurePassword123!",
    application: str = "platform"
):
    client.post("/api/auth/register", json={
        "email": email,
        "password": password,
        "name": f"User {email.split('@')[0]}"
    })
    res = client.post("/api/auth/login", json={
        "email": email,
        "password": password,
        "application": application
    })
    assert res.status_code == 200
    data = res.json()
    headers = {"Authorization": f"Bearer {data['access_token']}"}
    return email, headers, data


# ==============================================================================
# TEST 1: Registration stores normalized email and enforces uniqueness
# ==============================================================================
def test_registration_normalizes_email_and_enforces_uniqueness(client: TestClient, db_session: Session):
    """Normalizes email (lowercase, stripped) and prevents duplicate registrations across cases and whitespace."""
    raw_email = f"  Alice.Test.{uuid.uuid4().hex[:6]}@DomainName.COM  "
    expected_normalized = raw_email.lower().strip()

    # 1. Register with mixed case and whitespace
    res = client.post("/api/auth/register", json={
        "name": "Alice Test",
        "email": raw_email,
        "password": "Password123!"
    })
    assert res.status_code == 201
    user_data = res.json()
    assert user_data["email"] == expected_normalized

    # Verify directly in database record
    db_user = db_session.query(User).filter(User.email == expected_normalized).first()
    assert db_user is not None
    assert db_user.email == expected_normalized

    # 2. Duplicate registration attempt with exact same string
    dup1 = client.post("/api/auth/register", json={
        "name": "Alice Duplicate",
        "email": raw_email,
        "password": "Password123!"
    })
    assert dup1.status_code == 400
    assert "already exists" in dup1.json()["detail"].lower()

    # 3. Duplicate registration attempt with already-normalized string
    dup2 = client.post("/api/auth/register", json={
        "name": "Alice Duplicate 2",
        "email": expected_normalized,
        "password": "Password123!"
    })
    assert dup2.status_code == 400
    assert "already exists" in dup2.json()["detail"].lower()


# ==============================================================================
# TEST 2: Per-user email routing for two distinct users during login OTP
# ==============================================================================
def test_per_user_email_routing_login_otp_two_distinct_users(client: TestClient, db_session: Session):
    """
    Two distinct registered users each receive their own unique OTP dispatched strictly
    to their respective registered email addresses. Cross-user authentication is prohibited.
    """
    email_user1 = f"alice_user1_{uuid.uuid4().hex[:6]}@alpha.org"
    email_user2 = f"bob_user2_{uuid.uuid4().hex[:6]}@beta.net"

    _, headers_u1, login_u1 = register_and_login_user(client, email_user1)
    _, headers_u2, login_u2 = register_and_login_user(client, email_user2)

    fast_forward_observation(db_session, login_u1["session_id"])
    fast_forward_observation(db_session, login_u2["session_id"])

    dispatched = {}

    def spy_send(*args, **kwargs):
        recipient = kwargs.get("recipient_email") or (args[0] if len(args) > 0 else None)
        otp = kwargs.get("otp_code") or (args[1] if len(args) > 1 else None)
        dispatched[recipient] = otp
        return True, "Dispatched successfully"

    with patch("app.services.email_service.EmailService.send_otp_email", side_effect=spy_send):
        # 1. Request OTP for User 1
        res1 = client.post("/api/auth/login-otp/request", headers=headers_u1, json={"session_id": login_u1["session_id"]})
        assert res1.status_code == 200
        data1 = res1.json()

        # 2. Request OTP for User 2
        res2 = client.post("/api/auth/login-otp/request", headers=headers_u2, json={"session_id": login_u2["session_id"]})
        assert res2.status_code == 200
        data2 = res2.json()

    # Verify per-user routing: OTPs sent to their exact respective registered emails
    assert email_user1 in dispatched
    assert email_user2 in dispatched
    assert dispatched[email_user1] != dispatched[email_user2]
    assert data1["challenge_id"] != data2["challenge_id"]

    # Verify safe masking on the individual responses
    assert data1["masked_email"] == EmailService.mask_email(email_user1)
    assert data2["masked_email"] == EmailService.mask_email(email_user2)
    assert data1["masked_email"] != data2["masked_email"]

    # 3. Cross-User Replay Attempt: User 1 tries to verify using User 2's OTP
    cross_ver = client.post("/api/auth/login-otp/verify", headers=headers_u1, json={
        "session_id": login_u1["session_id"],
        "otp_code": dispatched[email_user2],
        "challenge_id": data2["challenge_id"]
    })
    assert cross_ver.status_code in (400, 403)

    # 4. Legit verification for User 1 succeeds
    legit1 = client.post("/api/auth/login-otp/verify", headers=headers_u1, json={
        "session_id": login_u1["session_id"],
        "otp_code": dispatched[email_user1],
        "challenge_id": data1["challenge_id"]
    })
    assert legit1.status_code == 200
    assert legit1.json()["session_status"] == "ACTIVE"

    # 5. Legit verification for User 2 succeeds
    legit2 = client.post("/api/auth/login-otp/verify", headers=headers_u2, json={
        "session_id": login_u2["session_id"],
        "otp_code": dispatched[email_user2],
        "challenge_id": data2["challenge_id"]
    })
    assert legit2.status_code == 200
    assert legit2.json()["session_status"] == "ACTIVE"


# ==============================================================================
# TEST 3: Per-user email routing during OTP resend
# ==============================================================================
def test_per_user_email_routing_during_resend(client: TestClient, db_session: Session):
    """Resend sends fresh OTPs to the respective user's registered address, never a global fallback."""
    user1_email = f"resend_u1_{uuid.uuid4().hex[:6]}@gamma.com"
    user2_email = f"resend_u2_{uuid.uuid4().hex[:6]}@delta.com"

    _, h1, l1 = register_and_login_user(client, user1_email)
    _, h2, l2 = register_and_login_user(client, user2_email)

    fast_forward_observation(db_session, l1["session_id"])
    fast_forward_observation(db_session, l2["session_id"])

    resend_dispatched = []

    def track_resend(*args, **kwargs):
        recipient = kwargs.get("recipient_email") or (args[0] if len(args) > 0 else None)
        otp = kwargs.get("otp_code") or (args[1] if len(args) > 1 else None)
        resend_dispatched.append((recipient, otp))
        return True, "Delivered"

    with patch("app.services.email_service.EmailService.send_otp_email", side_effect=track_resend):
        client.post("/api/auth/login-otp/request", headers=h1, json={"session_id": l1["session_id"]})
        client.post("/api/auth/login-otp/request", headers=h2, json={"session_id": l2["session_id"]})

        # Resend for User 1
        r1 = client.post("/api/auth/login-otp/resend", headers=h1, json={"session_id": l1["session_id"]})
        assert r1.status_code == 200

        # Resend for User 2
        r2 = client.post("/api/auth/login-otp/resend", headers=h2, json={"session_id": l2["session_id"]})
        assert r2.status_code == 200

    # Ensure the 3rd and 4th dispatches correspond to user 1 and user 2 respectively
    assert resend_dispatched[2][0] == user1_email
    assert resend_dispatched[3][0] == user2_email
    assert resend_dispatched[2][1] != resend_dispatched[3][1]


# ==============================================================================
# TEST 4: Per-user email routing during adaptive risk-based step-up
# ==============================================================================
def test_per_user_email_routing_risk_based_step_up(client: TestClient, db_session: Session):
    """Adaptive risk-based email OTP challenge is delivered to the individual user's database registered email."""
    email_a = f"stepup_a_{uuid.uuid4().hex[:6]}@corp.io"
    email_b = f"stepup_b_{uuid.uuid4().hex[:6]}@defense.gov"

    _, ha, la = register_and_login_user(client, email_a)
    _, hb, lb = register_and_login_user(client, email_b)

    fast_forward_observation(db_session, la["session_id"])
    fast_forward_observation(db_session, lb["session_id"])

    # Activate both sessions via initial login OTP
    with patch("app.services.email_service.EmailService.send_otp_email", return_value=(True, "Delivered")):
        ra = client.post("/api/auth/login-otp/request", headers=ha, json={"session_id": la["session_id"]})
        rb = client.post("/api/auth/login-otp/request", headers=hb, json={"session_id": lb["session_id"]})

        # In test mode, OTP is returned in the response for activation
        client.post("/api/auth/login-otp/verify", headers=ha, json={
            "session_id": la["session_id"],
            "otp_code": ra.json()["otp"],
            "challenge_id": ra.json()["challenge_id"]
        })
        client.post("/api/auth/login-otp/verify", headers=hb, json={
            "session_id": lb["session_id"],
            "otp_code": rb.json()["otp"],
            "challenge_id": rb.json()["challenge_id"]
        })

    # Now request mild risk step-up challenge for User A and User B
    stepup_targets = {}

    def capture_stepup(*args, **kwargs):
        recipient = kwargs.get("recipient_email") or (args[0] if len(args) > 0 else None)
        otp = kwargs.get("otp_code") or (args[1] if len(args) > 1 else None)
        stepup_targets[recipient] = otp
        return True, "Delivered"

    with patch("app.services.email_service.EmailService.send_otp_email", side_effect=capture_stepup):
        client.post("/api/security/step-up/challenge", headers=ha, json={"session_id": la["session_id"]})
        client.post("/api/security/step-up/challenge", headers=hb, json={"session_id": lb["session_id"]})

    assert email_a in stepup_targets
    assert email_b in stepup_targets
    assert stepup_targets[email_a] != stepup_targets[email_b]


# ==============================================================================
# TEST 5: Frontend-supplied email injection is rejected or ignored
# ==============================================================================
def test_frontend_supplied_email_injection_ignored(client: TestClient, db_session: Session):
    """
    Client cannot manipulate OTP destination by sending arbitrary email in request payload.
    Recipient is strictly resolved from the authenticated user's DB record.
    """
    real_email = f"honest_user_{uuid.uuid4().hex[:6]}@secure.org"
    spoofed_email = "attacker_intercept@evil.com"

    _, headers, login_data = register_and_login_user(client, real_email)
    fast_forward_observation(db_session, login_data["session_id"])

    delivered_to = None

    def capture_dest(*args, **kwargs):
        nonlocal delivered_to
        delivered_to = kwargs.get("recipient_email") or (args[0] if len(args) > 0 else None)
        return True, "Delivered"

    with patch("app.services.email_service.EmailService.send_otp_email", side_effect=capture_dest):
        # Malicious payload attempting to override recipient
        res = client.post("/api/auth/login-otp/request", headers=headers, json={
            "session_id": login_data["session_id"],
            "email": spoofed_email,
            "recipient": spoofed_email
        })
        assert res.status_code == 200

    # Destination MUST remain the honest registered user email, never the injected one
    assert delivered_to == real_email
    assert delivered_to != spoofed_email


# ==============================================================================
# TEST 6: Unverified account cannot log in until email ownership verified
# ==============================================================================
def test_unverified_account_blocked_until_verified(client: TestClient, db_session: Session):
    """An account with non-ACTIVE status (e.g. UNVERIFIED) cannot access protected endpoints until verified."""
    unverified_email = f"unverified_{uuid.uuid4().hex[:6]}@example.com"
    client.post("/api/auth/register", json={
        "name": "Unverified User",
        "email": unverified_email,
        "password": "Password123!"
    })

    # Set account_status to PENDING_VERIFICATION in DB
    user = db_session.query(User).filter(User.email == unverified_email).first()
    user.account_status = "PENDING_VERIFICATION"
    db_session.commit()

    # Attempt to log in must be forbidden
    login_res = client.post("/api/auth/login", json={
        "email": unverified_email,
        "password": "Password123!"
    })
    assert login_res.status_code == 403
    assert "pending_verification" in login_res.json()["detail"].lower()

    # Complete email verification via /api/auth/verify-email
    ver_res = client.post("/api/auth/verify-email", json={
        "email": unverified_email,
        "verification_code": "123456"
    })
    assert ver_res.status_code == 200
    assert ver_res.json()["status"] == "ACTIVE"

    # Now login must succeed
    login_success = client.post("/api/auth/login", json={
        "email": unverified_email,
        "password": "Password123!"
    })
    assert login_success.status_code == 200


# ==============================================================================
# TEST 7: SMTP sender is distinct from registered recipient
# ==============================================================================
def test_smtp_sender_distinct_from_recipient(monkeypatch):
    """Ensures SMTP envelope sender is the configured SMTP_FROM, while recipient is the user's email."""
    mock_server = MagicMock()
    mock_server.sendmail.return_value = {}
    mock_smtp_cls = MagicMock(return_value=mock_server)

    configured_sender = "system-mailer@cognisec.ai"
    registered_recipient = "registered.client@externalcompany.com"

    monkeypatch.setattr(settings, "SMTP_ENABLED", True)
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.testserver.com")
    monkeypatch.setattr(settings, "SMTP_PORT", 587)
    monkeypatch.setattr(settings, "SMTP_FROM", configured_sender)
    monkeypatch.setattr(settings, "SMTP_USER", "smtp_auth_user")
    monkeypatch.setattr(settings, "SMTP_PASSWORD", "smtp_auth_pass")
    monkeypatch.setattr(settings, "SMTP_TLS", True)
    import smtplib
    monkeypatch.setattr(smtplib, "SMTP", mock_smtp_cls)

    success, msg = EmailService.send_email(
        recipient_email=registered_recipient,
        subject="Identity Verification",
        plain_text="Your code is 654321"
    )

    assert success is True
    # Verify sendmail was called with (sender, [recipient], msg)
    call_args = mock_server.sendmail.call_args[0]
    envelope_sender = call_args[0]
    envelope_recipients = call_args[1]

    assert envelope_sender == configured_sender
    assert envelope_recipients == [registered_recipient]
    assert envelope_sender != envelope_recipients[0]


# ==============================================================================
# TEST 8: SMTP delivery failure reports real error and keeps access restricted
# ==============================================================================
def test_smtp_delivery_failure_reports_real_error_and_keeps_restricted(client: TestClient, db_session: Session):
    """Delivery failure returns 502 with genuine error message and never substitutes fallback recipient."""
    test_email = f"fail_test_{uuid.uuid4().hex[:6]}@recipient.org"
    _, headers, login_data = register_and_login_user(client, test_email)
    session_id = login_data["session_id"]
    fast_forward_observation(db_session, session_id)

    with patch("app.services.email_service.EmailService.send_otp_email", return_value=(False, "Mailbox full on destination MX")):
        res = client.post("/api/auth/login-otp/request", headers=headers, json={"session_id": session_id})
        assert res.status_code == 502
        detail = res.json()["detail"]
        assert "mailbox full on destination mx" in detail.lower()
        # Verify no false success was indicated
        assert "success" not in str(res.json()).lower()

    # Protected endpoint remains strictly blocked
    prof = client.get("/api/users/profile", headers=headers)
    assert prof.status_code == 403
