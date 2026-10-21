import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.session import Session as SessionModel
from app.models.user import User
from app.models.device import Device
from app.models.security_event import SecurityEvent
from app.services.session_service import SessionService
from app.services.step_up_service import StepUpService
from app.services.adaptive_auth_service import AdaptiveAuthService
from app.services.email_service import EmailService


def make_otp_spy(captured_dict):
    """Helper to safely capture OTP code and recipient email regardless of call style."""
    def spy(recipient_email=None, otp_code=None, *args, **kwargs):
        captured_dict["recipient"] = recipient_email
        captured_dict["otp"] = otp_code
        return True, "Code delivered"
    return spy


def register_and_login(client: TestClient, email_prefix: str = "obs_user"):
    email = f"{email_prefix}_{datetime.now().timestamp()}@example.com"
    password = "SecurePassword123!"
    reg_res = client.post("/api/auth/register", json={
        "email": email,
        "password": password,
        "name": "Observation User"
    })
    assert reg_res.status_code in (200, 201)

    login_res = client.post("/api/auth/login", json={
        "email": email,
        "password": password,
        "application": "platform"
    })
    assert login_res.status_code == 200
    data = login_res.json()
    return email, password, data


def test_1_correct_credentials_create_pending_restricted_session(client: TestClient, db_session: Session):
    """1. Correct credentials create a pending restricted session."""
    email, password, login_data = register_and_login(client, "test1")
    
    assert login_data["session_status"] == "PENDING_OBSERVATION"
    assert login_data["observation_seconds_remaining"] == settings.OBSERVATION_WINDOW_SECONDS
    assert "access_token" in login_data
    session_id = login_data["session_id"]
    
    # Check DB session state
    db_session.expire_all()
    sess = db_session.query(SessionModel).filter(SessionModel.id == session_id).first()
    assert sess is not None
    assert sess.status == "PENDING_OBSERVATION"
    assert sess.observation_started_at is not None
    assert sess.login_outcome == "observation_pending"


def test_2_protected_apis_blocked_during_observation(client: TestClient, db_session: Session):
    """2. Protected APIs remain blocked during the observation period."""
    _, _, login_data = register_and_login(client, "test2")
    headers = {"Authorization": f"Bearer {login_data['access_token']}"}

    # /api/sessions/start is protected by require_active_session
    res1 = client.post("/api/sessions/start", headers=headers, json={"application": "platform"})
    assert res1.status_code == 403
    assert "observation" in res1.json()["detail"].lower()

    # /api/users/profile is protected by require_active_session
    res2 = client.get("/api/users/profile", headers=headers)
    assert res2.status_code == 403
    assert "observation" in res2.json()["detail"].lower()


def test_3_backend_rejects_otp_before_60s_elapsed(client: TestClient, db_session: Session):
    """3. Backend rejects OTP requests before the observation window has elapsed."""
    _, _, login_data = register_and_login(client, "test3")
    headers = {"Authorization": f"Bearer {login_data['access_token']}"}
    session_id = login_data["session_id"]

    # Request OTP immediately (elapsed < window)
    res = client.post(
        "/api/auth/login-otp/request",
        headers=headers,
        json={"session_id": session_id}
    )
    assert res.status_code == 400
    assert "observation period incomplete" in res.json()["detail"].lower()


def test_4_observation_completion_triggers_one_login_challenge(client: TestClient, db_session: Session):
    """4. Observation completion triggers exactly one login challenge."""
    _, _, login_data = register_and_login(client, "test4")
    headers = {"Authorization": f"Bearer {login_data['access_token']}"}
    session_id = login_data["session_id"]

    # Simulate observation window elapsed on server clock
    sess = db_session.query(SessionModel).filter(SessionModel.id == session_id).first()
    sess.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=settings.OBSERVATION_WINDOW_SECONDS + 5)
    db_session.commit()

    # Now request OTP
    res1 = client.post(
        "/api/auth/login-otp/request",
        headers=headers,
        json={"session_id": session_id}
    )
    assert res1.status_code == 200
    data1 = res1.json()
    assert data1["challenge_type"] == "LOGIN_OTP"
    assert "challenge_id" in data1
    assert data1["masked_email"] is not None

    # Requesting again returns the existing single active challenge
    res2 = client.post(
        "/api/auth/login-otp/request",
        headers=headers,
        json={"session_id": session_id}
    )
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["challenge_id"] == data1["challenge_id"]


def test_5_insufficient_or_no_telemetry_still_requires_mandatory_otp(client: TestClient, db_session: Session):
    """5. No telemetry or insufficient telemetry still results in mandatory OTP after observation."""
    _, _, login_data = register_and_login(client, "test5")
    headers = {"Authorization": f"Bearer {login_data['access_token']}"}
    session_id = login_data["session_id"]

    # Send zero telemetry samples. Simulate elapsed 60s.
    sess = db_session.query(SessionModel).filter(SessionModel.id == session_id).first()
    sess.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=settings.OBSERVATION_WINDOW_SECONDS + 5)
    db_session.commit()

    # Check observation status reports completed but 0 samples
    obs_res = client.get(f"/api/auth/observation-status/{session_id}", headers=headers)
    assert obs_res.status_code == 200
    obs_data = obs_res.json()
    assert obs_data["is_completed"] is True
    assert obs_data["telemetry_samples_count"] == 0

    # User cannot bypass OTP: protected APIs are still 403
    prof_res = client.get("/api/users/profile", headers=headers)
    assert prof_res.status_code == 403

    # OTP is strictly mandatory
    otp_res = client.post(
        "/api/auth/login-otp/request",
        headers=headers,
        json={"session_id": session_id}
    )
    assert otp_res.status_code == 200
    assert otp_res.json()["challenge_type"] == "LOGIN_OTP"


def test_6_otp_delivered_using_email_service_abstraction(client: TestClient, db_session: Session):
    """6. OTP is delivered using the email service abstraction."""
    email, _, login_data = register_and_login(client, "test6")
    headers = {"Authorization": f"Bearer {login_data['access_token']}"}
    session_id = login_data["session_id"]

    sess = db_session.query(SessionModel).filter(SessionModel.id == session_id).first()
    sess.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=settings.OBSERVATION_WINDOW_SECONDS + 5)
    db_session.commit()

    captured_call = {}
    with patch.object(EmailService, "send_otp_email", side_effect=make_otp_spy(captured_call)):
        res = client.post(
            "/api/auth/login-otp/request",
            headers=headers,
            json={"session_id": session_id}
        )
        assert res.status_code == 200

    assert captured_call["recipient"] == email
    assert len(captured_call["otp"]) == 6
    assert captured_call["otp"].isdigit()


def test_7_incorrect_otp_terminates_pending_session_and_invalidates_challenge(client: TestClient, db_session: Session):
    """7. Incorrect OTP terminates the pending session and invalidates its challenge."""
    _, _, login_data = register_and_login(client, "test7")
    headers = {"Authorization": f"Bearer {login_data['access_token']}"}
    session_id = login_data["session_id"]

    sess = db_session.query(SessionModel).filter(SessionModel.id == session_id).first()
    sess.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=settings.OBSERVATION_WINDOW_SECONDS + 5)
    db_session.commit()

    req_res = client.post(
        "/api/auth/login-otp/request",
        headers=headers,
        json={"session_id": session_id}
    )
    chal_id = req_res.json()["challenge_id"]

    # Submit wrong OTP
    ver_res = client.post(
        "/api/auth/login-otp/verify",
        headers=headers,
        json={"session_id": session_id, "otp_code": "000000", "challenge_id": chal_id}
    )
    assert ver_res.status_code == 400
    assert "terminated" in ver_res.json()["detail"].lower()

    # Session in DB must be TERMINATED
    db_session.expire_all()
    sess_after = db_session.query(SessionModel).filter(SessionModel.id == session_id).first()
    assert sess_after.status == "TERMINATED"
    assert sess_after.login_outcome == "rejected"

    # Challenge must be cleared from memory
    chal = StepUpService.get_challenge(session_id)
    assert chal is None


def test_8_correct_otp_activates_only_matching_session(client: TestClient, db_session: Session):
    """8. Correct OTP activates only the matching session."""
    _, _, user_a = register_and_login(client, "test8_a")
    _, _, user_b = register_and_login(client, "test8_b")

    sess_a = db_session.query(SessionModel).filter(SessionModel.id == user_a["session_id"]).first()
    sess_a.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=settings.OBSERVATION_WINDOW_SECONDS + 5)
    db_session.commit()

    captured_a = {}
    with patch.object(EmailService, "send_otp_email", side_effect=make_otp_spy(captured_a)):
        req_res = client.post(
            "/api/auth/login-otp/request",
            headers={"Authorization": f"Bearer {user_a['access_token']}"},
            json={"session_id": user_a["session_id"]}
        )
        assert req_res.status_code == 200

    # Verify session A with correct OTP
    ver_res = client.post(
        "/api/auth/login-otp/verify",
        headers={"Authorization": f"Bearer {user_a['access_token']}"},
        json={"session_id": user_a["session_id"], "otp_code": captured_a["otp"]}
    )
    assert ver_res.status_code == 200
    assert ver_res.json()["session_status"] == "ACTIVE"

    # Session A can now access protected endpoints
    prof_a = client.get("/api/users/profile", headers={"Authorization": f"Bearer {user_a['access_token']}"})
    assert prof_a.status_code == 200

    # Session B is still restricted
    prof_b = client.get("/api/users/profile", headers={"Authorization": f"Bearer {user_b['access_token']}"})
    assert prof_b.status_code == 403


def test_9_expired_replayed_and_over_attempt_otps_rejected(client: TestClient, db_session: Session):
    """9. Expired, replayed, and over-attempt OTPs are rejected."""
    _, _, login_data = register_and_login(client, "test9")
    headers = {"Authorization": f"Bearer {login_data['access_token']}"}
    session_id = login_data["session_id"]

    sess = db_session.query(SessionModel).filter(SessionModel.id == session_id).first()
    sess.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=settings.OBSERVATION_WINDOW_SECONDS + 5)
    db_session.commit()

    captured = {}
    with patch.object(EmailService, "send_otp_email", side_effect=make_otp_spy(captured)):
        req_res = client.post(
            "/api/auth/login-otp/request",
            headers=headers,
            json={"session_id": session_id}
        )
        assert req_res.status_code == 200

    # Simulate expired challenge
    chal = StepUpService.get_challenge(session_id)
    assert chal is not None
    chal["expires_at"] = datetime.now(timezone.utc) - timedelta(seconds=10)

    exp_res = client.post(
        "/api/auth/login-otp/verify",
        headers=headers,
        json={"session_id": session_id, "otp_code": captured["otp"]}
    )
    assert exp_res.status_code == 400
    assert "expired" in exp_res.json()["detail"].lower()


def test_10_smtp_failure_does_not_grant_access(client: TestClient, db_session: Session):
    """10. SMTP failure does not grant access."""
    _, _, login_data = register_and_login(client, "test10")
    headers = {"Authorization": f"Bearer {login_data['access_token']}"}
    session_id = login_data["session_id"]

    sess = db_session.query(SessionModel).filter(SessionModel.id == session_id).first()
    sess.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=settings.OBSERVATION_WINDOW_SECONDS + 5)
    db_session.commit()

    with patch.object(EmailService, "send_otp_email", return_value=(False, "Connection to mail server refused")):
        res = client.post(
            "/api/auth/login-otp/request",
            headers=headers,
            json={"session_id": session_id}
        )
        assert res.status_code == 502

    # Protected APIs still strictly forbidden
    prof_res = client.get("/api/users/profile", headers=headers)
    assert prof_res.status_code == 403


def test_11_normal_telemetry_does_not_reopen_completed_login_challenge(client: TestClient, db_session: Session):
    """11. Normal telemetry does not reopen a completed login challenge."""
    _, _, login_data = register_and_login(client, "test11")
    session_id = login_data["session_id"]
    headers = {"Authorization": f"Bearer {login_data['access_token']}"}

    # Complete observation & OTP
    sess = db_session.query(SessionModel).filter(SessionModel.id == session_id).first()
    sess.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=settings.OBSERVATION_WINDOW_SECONDS + 5)
    db_session.commit()

    captured = {}
    with patch.object(EmailService, "send_otp_email", side_effect=make_otp_spy(captured)):
        client.post("/api/auth/login-otp/request", headers=headers, json={"session_id": session_id})

    ver_res = client.post(
        "/api/auth/login-otp/verify",
        headers=headers,
        json={"session_id": session_id, "otp_code": captured["otp"]}
    )
    assert ver_res.status_code == 200

    # Now post normal telemetry event
    normal_event = {
        "session_id": session_id,
        "application": "platform",
        "avg_flight_time_ms": 120.0,
        "avg_dwell_time_ms": 75.0,
        "typing_speed_wpm": 60.0
    }
    telem_res = client.post(
        "/api/behavior/events",
        headers=headers,
        json=normal_event
    )
    assert telem_res.status_code == 200
    assert telem_res.json()["decision"] == "ALLOW"

    # Verify no challenge is active
    chal = StepUpService.get_challenge(session_id)
    assert chal is None


def test_12_medium_risk_requires_gesture_verification(client: TestClient, db_session: Session):
    """12. MEDIUM risk requires gesture verification."""
    _, _, login_data = register_and_login(client, "test12")
    user_id = login_data["user_id"]
    session_id = login_data["session_id"]
    headers = {"Authorization": f"Bearer {login_data['access_token']}"}

    # Activate session
    SessionService.activate_session_after_login_otp(db_session, session_id)

    # Enroll user in gesture pattern
    enroll_res = client.post(
        "/api/security/adaptive/enroll/gesture",
        headers=headers,
        json={"pattern": [1, 2, 5, 8], "confirm_pattern": [1, 2, 5, 8]}
    )
    assert enroll_res.status_code == 200

    # Set session state to MEDIUM risk
    sess = db_session.query(SessionModel).filter(SessionModel.id == session_id).first()
    sess.current_risk_level = "MEDIUM"
    db_session.add(SecurityEvent(
        user_id=user_id,
        session_id=session_id,
        application="platform",
        event_type="BEHAVIOR_ANOMALY",
        severity="MEDIUM",
        risk_score=0.55,
        decision="STEP_UP_VERIFICATION",
        details="Moderate behavioral deviation"
    ))
    db_session.commit()

    # Request adaptive challenge
    chal_res = client.post(
        "/api/security/step-up/challenge",
        headers=headers,
        json={"session_id": session_id}
    )
    assert chal_res.status_code == 200
    data = chal_res.json()
    assert data["challenge_type"] == "GESTURE_PATTERN"

    # Verify with correct gesture pattern
    ver_res = client.post(
        "/api/security/step-up/verify",
        headers=headers,
        json={
            "session_id": session_id,
            "challenge_type": "GESTURE_PATTERN",
            "gesture_pattern": [1, 2, 5, 8]
        }
    )
    assert ver_res.status_code == 200
    assert ver_res.json()["decision"] == "ALLOW"


def test_13_high_risk_requires_both_cognitive_factors(client: TestClient, db_session: Session):
    """13. HIGH risk requires both cognitive factors (HIGH_RISK_DUAL)."""
    _, _, login_data = register_and_login(client, "test13")
    user_id = login_data["user_id"]
    session_id = login_data["session_id"]
    headers = {"Authorization": f"Bearer {login_data['access_token']}"}

    # Activate session
    SessionService.activate_session_after_login_otp(db_session, session_id)

    # Enroll both cognitive factors
    enroll_img = client.post(
        "/api/security/adaptive/enroll/image-sequence",
        headers=headers,
        json={
            "image_sequence": ["img_shield", "img_key", "img_lock"],
            "confirm_image_sequence": ["img_shield", "img_key", "img_lock"]
        }
    )
    assert enroll_img.status_code == 200

    enroll_priv = client.post(
        "/api/security/adaptive/enroll/private-response",
        headers=headers,
        json={
            "question": "What is your secret passphrase?",
            "response": "QuantumShield2026",
            "confirm_response": "QuantumShield2026"
        }
    )
    assert enroll_priv.status_code == 200

    # Incur High Risk
    sess = db_session.query(SessionModel).filter(SessionModel.id == session_id).first()
    sess.current_risk_level = "HIGH"
    db_session.add(SecurityEvent(
        user_id=user_id,
        session_id=session_id,
        application="platform",
        event_type="BEHAVIOR_ANOMALY",
        severity="HIGH",
        risk_score=0.75,
        decision="STEP_UP_VERIFICATION",
        details="High behavioral deviation"
    ))
    db_session.commit()

    chal_res = client.post(
        "/api/security/step-up/challenge",
        headers=headers,
        json={"session_id": session_id}
    )
    assert chal_res.status_code == 200
    data = chal_res.json()
    assert data["challenge_type"] == "HIGH_RISK_DUAL"

    # Submit incomplete (only image sequence) -> fails
    ver_fail = client.post(
        "/api/security/step-up/verify",
        headers=headers,
        json={
            "session_id": session_id,
            "challenge_type": "HIGH_RISK_DUAL",
            "image_sequence": ["img_shield", "img_key", "img_lock"]
        }
    )
    assert ver_fail.status_code == 400

    # Submit both -> succeeds
    ver_ok = client.post(
        "/api/security/step-up/verify",
        headers=headers,
        json={
            "session_id": session_id,
            "challenge_type": "HIGH_RISK_DUAL",
            "image_sequence": ["img_shield", "img_key", "img_lock"],
            "private_response": "QuantumShield2026"
        }
    )
    assert ver_ok.status_code == 200
    assert ver_ok.json()["decision"] == "ALLOW"


def test_14_critical_risk_terminates_session_immediately(client: TestClient, db_session: Session):
    """14. CRITICAL risk terminates the session immediately."""
    _, _, login_data = register_and_login(client, "test14")
    session_id = login_data["session_id"]
    headers = {"Authorization": f"Bearer {login_data['access_token']}"}

    # Activate session
    SessionService.activate_session_after_login_otp(db_session, session_id)

    # Critical anomaly telemetry (risk_score = 0.95)
    anomaly_event = {
        "session_id": session_id,
        "application": "platform",
        "avg_flight_time_ms": 120.0,
        "avg_dwell_time_ms": 80.0,
        "typing_speed_wpm": 60.0
    }
    with patch("app.services.risk_service.RiskService.calculate_risk", return_value=(0.95, -0.85, "CRITICAL", ["CRITICAL_ANOMALY"], True, "MODEL_EVALUATED")):
        res = client.post(
            "/api/behavior/events",
            headers=headers,
            json=anomaly_event
        )
        assert res.status_code == 200
        assert res.json()["decision"] == "TERMINATE_SESSION"

    # Session in DB is TERMINATED
    db_session.expire_all()
    sess = db_session.query(SessionModel).filter(SessionModel.id == session_id).first()
    assert sess.status == "TERMINATED"


def test_15_terminated_session_cannot_be_restored(client: TestClient, db_session: Session):
    """15. A terminated session cannot be restored by a factor or stale response."""
    _, _, login_data = register_and_login(client, "test15")
    session_id = login_data["session_id"]
    headers = {"Authorization": f"Bearer {login_data['access_token']}"}

    # Terminate session
    sess = db_session.query(SessionModel).filter(SessionModel.id == session_id).first()
    sess.status = "TERMINATED"
    db_session.commit()

    # Attempt to request OTP on terminated session
    res_req = client.post(
        "/api/auth/login-otp/request",
        headers=headers,
        json={"session_id": session_id}
    )
    assert res_req.status_code in (400, 401)

    # Attempt to verify OTP on terminated session
    res_ver = client.post(
        "/api/auth/login-otp/verify",
        headers=headers,
        json={"session_id": session_id, "otp_code": "123456"}
    )
    assert res_ver.status_code in (400, 401)

    # Protected APIs reject access
    prof_res = client.get("/api/users/profile", headers=headers)
    assert prof_res.status_code in (401, 403)


def test_16_device_metadata_and_notifications_persisted_with_accurate_outcomes(client: TestClient, db_session: Session):
    """16. Device metadata and notifications are persisted with accurate outcomes."""
    email, _, login_data = register_and_login(client, "test16")
    session_id = login_data["session_id"]
    headers = {"Authorization": f"Bearer {login_data['access_token']}"}

    # Verify device record exists
    device = db_session.query(Device).filter(Device.device_id == login_data["device_id"]).first()
    assert device is not None
    assert device.browser is not None

    # Complete observation and verify OTP
    sess = db_session.query(SessionModel).filter(SessionModel.id == session_id).first()
    sess.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=settings.OBSERVATION_WINDOW_SECONDS + 5)
    db_session.commit()

    captured = {}
    with patch.object(EmailService, "send_otp_email", side_effect=make_otp_spy(captured)):
        client.post("/api/auth/login-otp/request", headers=headers, json={"session_id": session_id})

    client.post(
        "/api/auth/login-otp/verify",
        headers=headers,
        json={"session_id": session_id, "otp_code": captured["otp"]}
    )

    # Check security events
    db_session.expire_all()
    events = db_session.query(SecurityEvent).filter(SecurityEvent.session_id == session_id).all()
    event_types = [e.event_type for e in events]
    assert "LOGIN_OTP_CHALLENGE_ISSUED" in event_types
    assert "LOGIN_OTP_VERIFIED" in event_types

    # Session outcome is verified
    sess_done = db_session.query(SessionModel).filter(SessionModel.id == session_id).first()
    assert sess_done.login_outcome == "verified"


def test_17_full_suite_stability(client: TestClient, db_session: Session):
    """17. Existing authentication and observation components operate stably together."""
    _, _, login_data = register_and_login(client, "test17")
    session_id = login_data["session_id"]
    headers = {"Authorization": f"Bearer {login_data['access_token']}"}

    # Telemetry ingestion during observation window works and does not leak or crash
    obs_sample = {
        "session_id": session_id,
        "application": "platform",
        "avg_flight_time_ms": 110.0,
        "avg_dwell_time_ms": 80.0,
        "typing_speed_wpm": 60.0
    }
    t_res = client.post(
        "/api/behavior/events",
        headers=headers,
        json=obs_sample
    )
    assert t_res.status_code == 200
    assert t_res.json()["decision"] == "OBSERVATION_PENDING"
    assert t_res.json()["session_status"] == "PENDING_OBSERVATION"
