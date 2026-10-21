import pytest
import smtplib
import socket
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.core.config import settings
from app.models.user import User
from app.models.session import Session as SessionModel
from app.models.security_event import SecurityEvent
from app.services.email_service import EmailService
from app.services.step_up_service import StepUpService
from app.services.session_service import SessionService
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
    email: str = "test.subject@example.com",
    password: str = "TestPassword123!",
    application: str = "platform"
):
    client.post("/api/auth/register", json={
        "email": email,
        "password": password,
        "name": "Test Subject"
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


def make_otp_spy():
    """Helper mock for send_otp_email handling both args and kwargs."""
    captured = {}
    def spy(*args, **kwargs):
        recipient = kwargs.get("recipient_email") or (args[0] if len(args) > 0 else None)
        otp = kwargs.get("otp_code") or (args[1] if len(args) > 1 else None)
        captured["recipient"] = recipient
        captured["otp"] = otp
        return True, "Code dispatched successfully"
    return spy, captured


# ==============================================================================
# TEST 1: Correct SMTP success response
# ==============================================================================
def test_1_smtp_success_response(monkeypatch):
    """EmailService returns success only after SMTP server accepts the message without errors."""
    mock_server = MagicMock()
    mock_server.sendmail.return_value = {}  # Empty dict indicates 0 refused recipients
    mock_smtp_cls = MagicMock(return_value=mock_server)

    monkeypatch.setattr(settings, "SMTP_ENABLED", True)
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.testserver.com")
    monkeypatch.setattr(settings, "SMTP_PORT", 587)
    monkeypatch.setattr(settings, "SMTP_USER", "testuser@cognisec.ai")
    monkeypatch.setattr(settings, "SMTP_PASSWORD", "testpass")
    monkeypatch.setattr(settings, "SMTP_TLS", True)
    monkeypatch.setattr(smtplib, "SMTP", mock_smtp_cls)

    success, msg = EmailService.send_email(
        recipient_email="test.delivery@example.com",
        subject="CogniSec Test",
        plain_text="Test Content"
    )

    assert success is True
    assert "dispatched successfully" in msg.lower()
    mock_server.starttls.assert_called_once()
    mock_server.login.assert_called_once_with("testuser@cognisec.ai", "testpass")
    mock_server.sendmail.assert_called_once()
    mock_server.quit.assert_called_once()


# ==============================================================================
# TEST 2: Genuine SMTP failure response
# ==============================================================================
def test_2_genuine_smtp_failure_response(client: TestClient, db_session: Session):
    """When SMTP genuinely fails, returns 502 Bad Gateway and keeps access restricted."""
    email, headers, login_data = register_and_login_user(client, "smtp_fail@example.com")
    session_id = login_data["session_id"]
    fast_forward_observation(db_session, session_id)

    # Force send_otp_email to simulate SMTP connection error
    with patch("app.services.email_service.EmailService.send_otp_email", return_value=(False, "Connection to SMTP server timed out.")):
        res = client.post("/api/auth/login-otp/request", headers=headers, json={"session_id": session_id})
        assert res.status_code == 502
        assert "failed" in res.json()["detail"].lower()

    # Verify session remains restricted (cannot access protected APIs)
    profile_res = client.get("/api/users/profile", headers=headers)
    assert profile_res.status_code == 403


# ==============================================================================
# TEST 3: SMTP failure followed by successful retry
# ==============================================================================
def test_3_smtp_failure_followed_by_successful_retry(client: TestClient, db_session: Session):
    """Failed SMTP delivery preserves restricted state and permits a successful retry."""
    email, headers, login_data = register_and_login_user(client, "retry_test@example.com")
    session_id = login_data["session_id"]
    fast_forward_observation(db_session, session_id)

    # 1. First attempt fails due to simulated network failure
    with patch("app.services.email_service.EmailService.send_otp_email", return_value=(False, "SMTP temporary timeout")):
        res1 = client.post("/api/auth/login-otp/request", headers=headers, json={"session_id": session_id})
        assert res1.status_code == 502

    # 2. Second attempt succeeds when SMTP recovers
    spy, captured = make_otp_spy()
    with patch("app.services.email_service.EmailService.send_otp_email", side_effect=spy):
        res2 = client.post("/api/auth/login-otp/request", headers=headers, json={"session_id": session_id})
        assert res2.status_code == 200
        data = res2.json()
        assert data["challenge_type"] == "LOGIN_OTP"
        assert "challenge_id" in data


# ==============================================================================
# TEST 4: Correct registered email used for delivery and masking
# ==============================================================================
def test_4_correct_registered_email_used_for_delivery_and_masking(client: TestClient, db_session: Session):
    """The database user's email is the authoritative recipient. UI displays correct masked recipient."""
    registered_email = "synthetic_recipient@example.com"
    email, headers, login_data = register_and_login_user(client, registered_email)
    session_id = login_data["session_id"]
    fast_forward_observation(db_session, session_id)

    spy, captured = make_otp_spy()
    with patch("app.services.email_service.EmailService.send_otp_email", side_effect=spy):
        res = client.post("/api/auth/login-otp/request", headers=headers, json={"session_id": session_id})
        assert res.status_code == 200
        data = res.json()

        # Recipient used by SMTP service MUST be the registered user email
        assert captured["recipient"] == "synthetic_recipient@example.com"
        # Masked email displayed in UI
        assert data["masked_email"] == "s***t@example.com"


# ==============================================================================
# TEST 5: OTP issued for one user cannot verify another user's session
# ==============================================================================
def test_5_otp_issued_for_one_user_cannot_verify_another_user_session(client: TestClient, db_session: Session):
    """OTP issued for user A cannot verify user B's session."""
    _, headers_a, login_a = register_and_login_user(client, "user_a@example.com")
    fast_forward_observation(db_session, login_a["session_id"])

    spy_a, captured_a = make_otp_spy()
    with patch("app.services.email_service.EmailService.send_otp_email", side_effect=spy_a):
        res_a = client.post("/api/auth/login-otp/request", headers=headers_a, json={"session_id": login_a["session_id"]})
        assert res_a.status_code == 200
        challenge_id_a = res_a.json()["challenge_id"]

    _, headers_b, login_b = register_and_login_user(client, "user_b@example.com")
    fast_forward_observation(db_session, login_b["session_id"])

    # User B attempts to verify User B's session using User A's OTP and challenge_id
    res_cross = client.post("/api/auth/login-otp/verify", headers=headers_b, json={
        "session_id": login_b["session_id"],
        "otp_code": captured_a["otp"],
        "challenge_id": challenge_id_a
    })
    # Must be rejected
    assert res_cross.status_code in (400, 403)


# ==============================================================================
# TEST 6: One mandatory OTP challenge per login session
# ==============================================================================
def test_6_one_mandatory_otp_challenge_per_login_session(client: TestClient, db_session: Session):
    """Multiple requests return the same active challenge without creating duplicates or duplicate emails."""
    _, headers, login_data = register_and_login_user(client, "single_challenge@example.com")
    session_id = login_data["session_id"]
    fast_forward_observation(db_session, session_id)

    dispatch_count = 0
    def counting_send(*args, **kwargs):
        nonlocal dispatch_count
        dispatch_count += 1
        return True, "Delivered"

    with patch("app.services.email_service.EmailService.send_otp_email", side_effect=counting_send):
        res1 = client.post("/api/auth/login-otp/request", headers=headers, json={"session_id": session_id})
        res2 = client.post("/api/auth/login-otp/request", headers=headers, json={"session_id": session_id})

    assert res1.status_code == 200
    assert res2.status_code == 200
    assert res1.json()["challenge_id"] == res2.json()["challenge_id"]
    # Only 1 dispatch occurred for initial challenge creation
    assert dispatch_count == 1


# ==============================================================================
# TEST 7: Successful verification transitions to ACTIVE
# ==============================================================================
def test_7_successful_verification_transitions_to_active(client: TestClient, db_session: Session):
    """Correct OTP verification transitions session status to ACTIVE atomically."""
    _, headers, login_data = register_and_login_user(client, "verify_success@example.com")
    session_id = login_data["session_id"]
    fast_forward_observation(db_session, session_id)

    spy, captured = make_otp_spy()
    with patch("app.services.email_service.EmailService.send_otp_email", side_effect=spy):
        req_res = client.post("/api/auth/login-otp/request", headers=headers, json={"session_id": session_id})
        challenge_id = req_res.json()["challenge_id"]

    ver_res = client.post("/api/auth/login-otp/verify", headers=headers, json={
        "session_id": session_id,
        "otp_code": captured["otp"],
        "challenge_id": challenge_id
    })
    assert ver_res.status_code == 200
    assert ver_res.json()["session_status"] == "ACTIVE"
    assert ver_res.json()["success"] is True

    # Now verify protected endpoints are accessible
    prof = client.get("/api/users/profile", headers=headers)
    assert prof.status_code == 200


# ==============================================================================
# TEST 8: Normal telemetry and button clicks do not reopen mandatory login OTP
# ==============================================================================
def test_8_normal_telemetry_does_not_reopen_login_otp(client: TestClient, db_session: Session):
    """Subsequent normal behavioral telemetry on ACTIVE session does NOT trigger OTP modal or downgrade status."""
    _, headers, login_data = register_and_login_user(client, "telemetry_test@example.com")
    session_id = login_data["session_id"]
    fast_forward_observation(db_session, session_id)

    spy, captured = make_otp_spy()
    with patch("app.services.email_service.EmailService.send_otp_email", side_effect=spy):
        req_res = client.post("/api/auth/login-otp/request", headers=headers, json={"session_id": session_id})
        challenge_id = req_res.json()["challenge_id"]

    ver_res = client.post("/api/auth/login-otp/verify", headers=headers, json={
        "session_id": session_id,
        "otp_code": captured["otp"],
        "challenge_id": challenge_id
    })
    assert ver_res.status_code == 200

    # Send multiple normal telemetry packets via /api/behavior/events
    import time
    for seq in range(1, 4):
        tel_res = client.post("/api/behavior/events", headers=headers, json={
            "session_id": session_id,
            "application": "platform",
            "avg_flight_time_ms": 120.0,
            "avg_dwell_time_ms": 75.0,
            "typing_speed_wpm": 60.0,
            "sequence_number": seq,
            "telemetry_nonce": f"nonce_seq_{seq}_{time.time()}"
        })
        assert tel_res.status_code == 200
        # Decision must allow normal interaction
        assert tel_res.json()["decision"] == "ALLOW"

    # Session remains ACTIVE in database
    db_session.expire_all()
    sess = db_session.query(SessionModel).filter(SessionModel.id == session_id).first()
    assert sess.status == "ACTIVE"


# ==============================================================================
# TEST 9: Navigation and refresh preserve an active session
# ==============================================================================
def test_9_navigation_and_refresh_preserve_active_session(client: TestClient, db_session: Session):
    """Observation status endpoint confirms active session is preserved on refresh or navigation."""
    _, headers, login_data = register_and_login_user(client, "refresh_test@example.com")
    session_id = login_data["session_id"]
    fast_forward_observation(db_session, session_id)

    spy, captured = make_otp_spy()
    with patch("app.services.email_service.EmailService.send_otp_email", side_effect=spy):
        req_res = client.post("/api/auth/login-otp/request", headers=headers, json={"session_id": session_id})
        challenge_id = req_res.json()["challenge_id"]

    client.post("/api/auth/login-otp/verify", headers=headers, json={
        "session_id": session_id,
        "otp_code": captured["otp"],
        "challenge_id": challenge_id
    })

    # Frontend calls /api/auth/observation-status/{session_id} on page load/navigation
    obs_res = client.get(f"/api/auth/observation-status/{session_id}", headers=headers)
    assert obs_res.status_code == 200
    data = obs_res.json()
    assert data["status"] == "ACTIVE"
    assert data["is_completed"] is True
    assert data["observation_seconds_remaining"] == 0


# ==============================================================================
# TEST 10: Expired OTP is rejected
# ==============================================================================
def test_10_expired_otp_is_rejected(client: TestClient, db_session: Session):
    """OTP expired according to authoritative backend timestamp is rejected."""
    _, headers, login_data = register_and_login_user(client, "expired_test@example.com")
    session_id = login_data["session_id"]
    fast_forward_observation(db_session, session_id)

    spy, captured = make_otp_spy()
    with patch("app.services.email_service.EmailService.send_otp_email", side_effect=spy):
        req_res = client.post("/api/auth/login-otp/request", headers=headers, json={"session_id": session_id})
        challenge_id = req_res.json()["challenge_id"]

    # Authoritatively expire the challenge in backend cache
    with StepUpService._lock:
        if session_id in StepUpService._challenges:
            StepUpService._challenges[session_id]["expires_at"] = (
                datetime.now(timezone.utc) - timedelta(seconds=10)
            )

    ver_res = client.post("/api/auth/login-otp/verify", headers=headers, json={
        "session_id": session_id,
        "otp_code": captured["otp"],
        "challenge_id": challenge_id
    })
    assert ver_res.status_code == 400
    assert "expired" in ver_res.json()["detail"].lower()


# ==============================================================================
# TEST 11: Resend produces a new OTP and invalidates the previous one
# ==============================================================================
def test_11_resend_produces_new_otp_and_invalidates_previous(client: TestClient, db_session: Session):
    """Resend generates a fresh OTP code and new challenge ID; old OTP cannot be used."""
    _, headers, login_data = register_and_login_user(client, "resend_inval@example.com")
    session_id = login_data["session_id"]
    fast_forward_observation(db_session, session_id)

    otps_dispatched = []
    def track_send(*args, **kwargs):
        otp = kwargs.get("otp_code") or (args[1] if len(args) > 1 else None)
        otps_dispatched.append(otp)
        return True, "Delivered"

    with patch("app.services.email_service.EmailService.send_otp_email", side_effect=track_send):
        req1 = client.post("/api/auth/login-otp/request", headers=headers, json={"session_id": session_id})
        challenge1 = req1.json()["challenge_id"]
        otp1 = otps_dispatched[0]

        # Resend code
        resend_res = client.post("/api/auth/login-otp/resend", headers=headers, json={"session_id": session_id})
        assert resend_res.status_code == 200
        challenge2 = resend_res.json()["challenge_id"]
        otp2 = otps_dispatched[1]

    assert challenge1 != challenge2
    assert otp1 != otp2

    # Attempt to verify using old OTP fails
    old_try = client.post("/api/auth/login-otp/verify", headers=headers, json={
        "session_id": session_id,
        "otp_code": otp1,
        "challenge_id": challenge1
    })
    assert old_try.status_code in (400, 403)


# ==============================================================================
# TEST 12: Repeated resend requests are rate-limited
# ==============================================================================
def test_12_repeated_resend_requests_are_rate_limited(client: TestClient, db_session: Session):
    """Server-side rate limiter enforces max resend frequency and returns 429."""
    _, headers, login_data = register_and_login_user(client, "rate_lim_resend@example.com")
    session_id = login_data["session_id"]
    fast_forward_observation(db_session, session_id)

    with patch("app.services.email_service.EmailService.send_otp_email", return_value=(True, "Delivered")):
        client.post("/api/auth/login-otp/request", headers=headers, json={"session_id": session_id})

        # Resend up to the limit (max 3 allowed per 60s window)
        r1 = client.post("/api/auth/login-otp/resend", headers=headers, json={"session_id": session_id})
        r2 = client.post("/api/auth/login-otp/resend", headers=headers, json={"session_id": session_id})
        r3 = client.post("/api/auth/login-otp/resend", headers=headers, json={"session_id": session_id})
        # 4th request must be rate limited
        r4 = client.post("/api/auth/login-otp/resend", headers=headers, json={"session_id": session_id})

    assert r4.status_code == 429
    assert "too many" in r4.json()["detail"].lower()


# ==============================================================================
# TEST 13: Duplicate verification requests cannot consume the challenge twice
# ==============================================================================
def test_13_duplicate_verification_cannot_consume_twice(client: TestClient, db_session: Session):
    """Idempotency check: once consumed, repeating verification request fails gracefully."""
    _, headers, login_data = register_and_login_user(client, "idempotent@example.com")
    session_id = login_data["session_id"]
    fast_forward_observation(db_session, session_id)

    spy, captured = make_otp_spy()
    with patch("app.services.email_service.EmailService.send_otp_email", side_effect=spy):
        req_res = client.post("/api/auth/login-otp/request", headers=headers, json={"session_id": session_id})
        challenge_id = req_res.json()["challenge_id"]

    ver1 = client.post("/api/auth/login-otp/verify", headers=headers, json={
        "session_id": session_id,
        "otp_code": captured["otp"],
        "challenge_id": challenge_id
    })
    assert ver1.status_code == 200
    assert ver1.json()["session_status"] == "ACTIVE"

    ver2 = client.post("/api/auth/login-otp/verify", headers=headers, json={
        "session_id": session_id,
        "otp_code": captured["otp"],
        "challenge_id": challenge_id
    })
    assert ver2.status_code == 400
    assert "already authenticated and active" in ver2.json()["detail"].lower()


# ==============================================================================
# TEST 14: Incorrect OTP follows attempt/termination policy
# ==============================================================================
def test_14_incorrect_otp_terminates_session(client: TestClient, db_session: Session):
    """Supplying an incorrect OTP terminates the pending session immediately."""
    _, headers, login_data = register_and_login_user(client, "bad_otp@example.com")
    session_id = login_data["session_id"]
    fast_forward_observation(db_session, session_id)

    with patch("app.services.email_service.EmailService.send_otp_email", return_value=(True, "Delivered")):
        req_res = client.post("/api/auth/login-otp/request", headers=headers, json={"session_id": session_id})
        challenge_id = req_res.json()["challenge_id"]

    ver_res = client.post("/api/auth/login-otp/verify", headers=headers, json={
        "session_id": session_id,
        "otp_code": "000000",
        "challenge_id": challenge_id
    })
    assert ver_res.status_code == 400

    db_session.expire_all()
    sess = db_session.query(SessionModel).filter(SessionModel.id == session_id).first()
    assert sess.status == "TERMINATED"


# ==============================================================================
# TEST 15: Risk-based step-up still works independently after login verification
# ==============================================================================
def test_15_risk_based_stepup_works_independently(client: TestClient, db_session: Session):
    """Subsequent risk elevation triggers adaptive step-up independently from login OTP."""
    _, headers, login_data = register_and_login_user(client, "adaptive_stepup@example.com")
    session_id = login_data["session_id"]
    fast_forward_observation(db_session, session_id)

    spy, captured = make_otp_spy()
    with patch("app.services.email_service.EmailService.send_otp_email", side_effect=spy):
        req_res = client.post("/api/auth/login-otp/request", headers=headers, json={"session_id": session_id})
        challenge_id = req_res.json()["challenge_id"]

    # Complete login OTP
    client.post("/api/auth/login-otp/verify", headers=headers, json={
        "session_id": session_id,
        "otp_code": captured["otp"],
        "challenge_id": challenge_id
    })

    # Enroll gesture factor
    client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": [0, 1, 2, 4],
        "confirm_pattern": [0, 1, 2, 4]
    })

    # Elevate session risk level to MEDIUM
    db_session.expire_all()
    sess = db_session.query(SessionModel).filter(SessionModel.id == session_id).first()
    sess.current_risk_level = "MEDIUM"
    db_session.commit()

    # Request step-up challenge
    chal_res = client.post("/api/security/step-up/challenge", headers=headers, json={"session_id": session_id})
    assert chal_res.status_code == 200
    res_data = chal_res.json()
    assert res_data["challenge_type"] == "GESTURE_PATTERN"


# ==============================================================================
# TEST 16: All four portals behave consistently
# ==============================================================================
def test_16_all_four_portals_behave_consistently(client: TestClient, db_session: Session):
    """Observation and login OTP lifecycle works identically for college, healthcare, shopping, and dashboard."""
    portals = ["PORTAL_COLLEGE", "PORTAL_HEALTHCARE", "PORTAL_SHOPPING", "ADMIN_DASHBOARD"]

    for portal in portals:
        email = f"user_{portal.lower()}@example.com"
        _, headers, login_data = register_and_login_user(client, email=email, application=portal)
        session_id = login_data["session_id"]
        assert login_data["session_status"] == "PENDING_OBSERVATION"

        fast_forward_observation(db_session, session_id)

        spy, captured = make_otp_spy()
        with patch("app.services.email_service.EmailService.send_otp_email", side_effect=spy):
            req = client.post("/api/auth/login-otp/request", headers=headers, json={"session_id": session_id})
            assert req.status_code == 200, f"Portal {portal} failed challenge request"
            ch_id = req.json()["challenge_id"]

        ver = client.post("/api/auth/login-otp/verify", headers=headers, json={
            "session_id": session_id,
            "otp_code": captured["otp"],
            "challenge_id": ch_id
        })
        assert ver.status_code == 200, f"Portal {portal} failed verification"
        assert ver.json()["session_status"] == "ACTIVE"
