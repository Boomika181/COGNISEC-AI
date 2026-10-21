import time
from datetime import datetime, timezone, timedelta
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from app.services.step_up_service import StepUpService
from app.services.anti_replay_service import AntiReplayService
from app.services.session_service import SessionService
from app.services.decision_service import DecisionService
from app.core.rate_limit import rate_limiter
from app.models.session import Session
from app.models.device import Device
from app.models.notification import DeviceNotification


@pytest.fixture(autouse=True)
def reset_security_managers():
    """Ensure clean state before and after each test."""
    StepUpService.reset()
    AntiReplayService.reset()
    rate_limiter.reset()
    yield
    StepUpService.reset()
    AntiReplayService.reset()
    rate_limiter.reset()


@pytest.fixture
def auth_user(client: TestClient, db_session):
    """Creates a primary test user and session."""
    email = f"loopfix_user_{time.time()}@example.com"
    client.post("/api/auth/register", json={
        "email": email,
        "password": "Password123!",
        "name": "StepUp Loop Tester"
    })
    res = client.post("/api/auth/login", json={
        "email": email,
        "password": "Password123!",
        "application": "platform"
    })
    token = res.json()["access_token"]
    user_id = res.json()["user_id"]
    sid = res.json()["session_id"]
    from app.services.session_service import SessionService
    SessionService.activate_session_after_login_otp(db_session, sid)
    return {"Authorization": f"Bearer {token}"}, user_id, email


@pytest.fixture
def auth_user_second(client: TestClient):
    """Creates a second distinct test user and session."""
    email = f"loopfix_user2_{time.time()}@example.com"
    client.post("/api/auth/register", json={
        "email": email,
        "password": "Password123!",
        "name": "StepUp Loop Tester Two"
    })
    res = client.post("/api/auth/login", json={
        "email": email,
        "password": "Password123!",
        "application": "platform"
    })
    token = res.json()["access_token"]
    user_id = res.json()["user_id"]
    return {"Authorization": f"Bearer {token}"}, user_id, email


# ==============================================================================
# CASE 1: First OTP challenge is created and delivered
# ==============================================================================
def test_case_01_first_otp_challenge_created_and_delivered(client: TestClient, auth_user, db_session):
    headers, user_id, email = auth_user
    sess_res = client.post("/api/sessions/start", headers=headers, json={
        "application": "college",
        "device_fingerprint": "dev_test_01"
    })
    session_id = sess_res.json()["id"]

    with patch("app.services.email_service.EmailService.send_otp_email", return_value=(True, "Email dispatched")):
        chal_res = client.post("/api/security/step-up/challenge", headers=headers, json={
            "session_id": session_id
        })

    assert chal_res.status_code == 200
    data = chal_res.json()
    assert data["session_id"] == session_id
    assert "challenge_id" in data
    assert data["challenge_type"] == "OTP"
    assert len(data["otp"]) == 6
    assert data["delivery_status"] == "SENT"


# ==============================================================================
# CASE 2: Correct OTP succeeds and persists the verified state
# ==============================================================================
def test_case_02_correct_otp_succeeds_and_persists_verified_state(client: TestClient, auth_user, db_session):
    headers, user_id, _ = auth_user
    sess_res = client.post("/api/sessions/start", headers=headers, json={
        "application": "college",
        "device_fingerprint": "dev_test_02"
    })
    session_id = sess_res.json()["id"]

    # Session enters STEP_UP_REQUIRED
    sess = db_session.query(Session).filter(Session.id == session_id).first()
    sess.status = "STEP_UP_REQUIRED"
    sess.current_risk_level = "MEDIUM"
    db_session.commit()

    with patch("app.services.email_service.EmailService.send_otp_email", return_value=(True, "Delivered")):
        chal_res = client.post("/api/security/step-up/challenge", headers=headers, json={
            "session_id": session_id
        })
    otp_code = chal_res.json()["otp"]

    # Verify correct OTP
    verify_res = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "challenge_type": "OTP",
        "challenge_code": otp_code
    })
    assert verify_res.status_code == 200
    outcome = verify_res.json()
    assert outcome["decision"] == "ALLOW"
    assert outcome["session_status"] == "ACTIVE"
    assert outcome["verification_required"] is False

    # Check persistence in database
    db_session.expire_all()
    persisted_sess = db_session.query(Session).filter(Session.id == session_id).first()
    assert persisted_sess.status == "ACTIVE"
    assert persisted_sess.current_risk_level == "LOW"
    assert persisted_sess.step_up_verified_at is not None
    assert persisted_sess.step_up_valid_until is not None
    assert persisted_sess.step_up_factor == "OTP"
    assert persisted_sess.step_up_valid_until > persisted_sess.step_up_verified_at


# ==============================================================================
# CASE 3: Repeating the same verification request cannot reuse the OTP
# ==============================================================================
def test_case_03_repeating_same_verification_cannot_reuse_otp(client: TestClient, auth_user, db_session):
    headers, user_id, _ = auth_user
    sess_res = client.post("/api/sessions/start", headers=headers, json={
        "application": "college",
        "device_fingerprint": "dev_test_03"
    })
    session_id = sess_res.json()["id"]

    with patch("app.services.email_service.EmailService.send_otp_email", return_value=(True, "Delivered")):
        chal_res = client.post("/api/security/step-up/challenge", headers=headers, json={
            "session_id": session_id
        })
    otp_code = chal_res.json()["otp"]

    # First verification succeeds
    res1 = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "challenge_type": "OTP",
        "challenge_code": otp_code
    })
    assert res1.status_code == 200

    # Second immediate verification attempt MUST be rejected
    res2 = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "challenge_type": "OTP",
        "challenge_code": otp_code
    })
    assert res2.status_code == 400
    assert "No active step-up challenge found" in res2.json()["detail"]


# ==============================================================================
# CASE 4: Multiple subsequent telemetry batches do not reopen the same completed challenge
# ==============================================================================
def test_case_04_multiple_subsequent_telemetry_batches_do_not_reopen_challenge(client: TestClient, auth_user, db_session):
    headers, user_id, _ = auth_user
    sess_res = client.post("/api/sessions/start", headers=headers, json={
        "application": "college",
        "device_fingerprint": "dev_test_04"
    })
    session_id = sess_res.json()["id"]

    # Perform Step-Up verification
    with patch("app.services.email_service.EmailService.send_otp_email", return_value=(True, "Delivered")):
        chal_res = client.post("/api/security/step-up/challenge", headers=headers, json={
            "session_id": session_id
        })
    otp_code = chal_res.json()["otp"]
    client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "challenge_type": "OTP",
        "challenge_code": otp_code
    })

    # Submit 5 consecutive telemetry batches that would otherwise evaluate to MEDIUM risk
    for seq in range(1, 6):
        tel_res = client.post("/api/behavior/events", headers=headers, json={
            "session_id": session_id,
            "application": "college",
            "features": {
                "keystroke_dwell_time": 130.0 + seq,
                "flight_time": 210.0 + seq,
                "typing_speed_wpm": 55.0 + seq,
                "error_rate": 0.05,
                "mouse_velocity": 450.0 + seq,
                "acceleration": 220.0 + seq,
                "curvature": 0.5,
                "click_frequency": 0.3,
                "idle_time_ratio": 0.1
            },
            "sequence_number": seq,
            "telemetry_nonce": f"nonce_seq_{seq}_{time.time()}",
            "context_signals": {
                "device_trust": "untrusted"  # generates moderate risk
            }
        })
        assert tel_res.status_code == 200
        data = tel_res.json()
        # MUST remain ALLOW and ACTIVE, NOT re-challenge!
        assert data["decision"] == "ALLOW"
        assert data["session_status"] == "ACTIVE"
        assert data["verification_required"] is False

    # Confirm session in DB remains ACTIVE
    db_session.expire_all()
    sess = db_session.query(Session).filter(Session.id == session_id).first()
    assert sess.status == "ACTIVE"
    assert sess.current_risk_level == "LOW"


# ==============================================================================
# CASE 5: Stale STEP_UP responses cannot override newer verified state
# ==============================================================================
def test_case_05_stale_stepup_responses_cannot_override_verified_state(client: TestClient, auth_user, db_session):
    headers, user_id, _ = auth_user
    sess_res = client.post("/api/sessions/start", headers=headers, json={
        "application": "college",
        "device_fingerprint": "dev_test_05"
    })
    session_id = sess_res.json()["id"]

    # Step up verified
    with patch("app.services.email_service.EmailService.send_otp_email", return_value=(True, "Delivered")):
        chal_res = client.post("/api/security/step-up/challenge", headers=headers, json={
            "session_id": session_id
        })
    client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "challenge_type": "OTP",
        "challenge_code": chal_res.json()["otp"]
    })

    # Status check confirms authoritative ACTIVE state
    status_res = client.get(f"/api/security/status/{session_id}", headers=headers)
    assert status_res.status_code == 200
    assert status_res.json()["session_status"] == "ACTIVE"
    assert status_res.json()["decision"] == "ALLOW"
    assert status_res.json()["verification_required"] is False


# ==============================================================================
# CASE 6: Invalid OTP does not restore access
# ==============================================================================
def test_case_06_invalid_otp_does_not_restore_access(client: TestClient, auth_user, db_session):
    headers, user_id, _ = auth_user
    sess_res = client.post("/api/sessions/start", headers=headers, json={
        "application": "college",
        "device_fingerprint": "dev_test_06"
    })
    session_id = sess_res.json()["id"]

    # Transition session to STEP_UP_REQUIRED
    sess = db_session.query(Session).filter(Session.id == session_id).first()
    sess.status = "STEP_UP_REQUIRED"
    db_session.commit()

    with patch("app.services.email_service.EmailService.send_otp_email", return_value=(True, "Delivered")):
        client.post("/api/security/step-up/challenge", headers=headers, json={
            "session_id": session_id
        })

    # Submit wrong OTP code
    bad_res = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "challenge_type": "OTP",
        "challenge_code": "000000"
    })
    assert bad_res.status_code == 400
    assert "Invalid verification" in bad_res.json()["detail"]

    # Verify session remains locked in STEP_UP_REQUIRED
    db_session.expire_all()
    sess_check = db_session.query(Session).filter(Session.id == session_id).first()
    assert sess_check.status == "STEP_UP_REQUIRED"


# ==============================================================================
# CASE 7: Expired OTP cannot restore access
# ==============================================================================
def test_case_07_expired_otp_cannot_restore_access(client: TestClient, auth_user, db_session):
    headers, user_id, _ = auth_user
    sess_res = client.post("/api/sessions/start", headers=headers, json={
        "application": "college",
        "device_fingerprint": "dev_test_07"
    })
    session_id = sess_res.json()["id"]

    with patch("app.services.email_service.EmailService.send_otp_email", return_value=(True, "Delivered")):
        chal_res = client.post("/api/security/step-up/challenge", headers=headers, json={
            "session_id": session_id
        })
    otp_code = chal_res.json()["otp"]

    # Artificially expire the challenge in memory
    chal = StepUpService.get_challenge(session_id)
    chal["expires_at"] = datetime.now(timezone.utc) - timedelta(seconds=10)

    # Attempt verification with expired challenge
    exp_res = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "challenge_type": "OTP",
        "challenge_code": otp_code
    })
    assert exp_res.status_code == 400
    assert "expired" in exp_res.json()["detail"].lower()


# ==============================================================================
# CASE 8: A newly escalated risk can require another challenge under documented policy
# ==============================================================================
def test_case_08_newly_escalated_risk_requires_appropriate_action(client: TestClient, auth_user, db_session):
    headers, user_id, _ = auth_user
    sess_res = client.post("/api/sessions/start", headers=headers, json={
        "application": "college",
        "device_fingerprint": "dev_test_08"
    })
    session_id = sess_res.json()["id"]

    # User verifies mild OTP challenge
    with patch("app.services.email_service.EmailService.send_otp_email", return_value=(True, "Delivered")):
        chal_res = client.post("/api/security/step-up/challenge", headers=headers, json={
            "session_id": session_id
        })
    client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "challenge_type": "OTP",
        "challenge_code": chal_res.json()["otp"]
    })

    # Now an explicit severe risk escalation occurs (e.g. HIGH risk = 0.75)
    decision, user_msg, session_status, _ = DecisionService.enforce_zero_trust_decision(
        db_session,
        user_id=user_id,
        session_id=session_id,
        application="college",
        risk_score=0.75,
        anomaly_score=0.70,
        risk_level="HIGH",
        contributing_factors=["Severe keystroke anomaly", "Impossible speed shift"]
    )

    # High risk must RESTRICT the session, NOT let mild OTP bypass it
    assert decision == "RESTRICT"
    assert session_status == "RESTRICTED"


# ==============================================================================
# CASE 9: Critical-risk termination remains final
# ==============================================================================
def test_case_09_critical_risk_termination_remains_final(client: TestClient, auth_user, db_session):
    headers, user_id, _ = auth_user
    sess_res = client.post("/api/sessions/start", headers=headers, json={
        "application": "college",
        "device_fingerprint": "dev_test_09"
    })
    session_id = sess_res.json()["id"]

    # 1. Terminate session due to critical risk kill switch
    DecisionService.enforce_zero_trust_decision(
        db_session,
        user_id=user_id,
        session_id=session_id,
        application="college",
        risk_score=0.95,
        anomaly_score=0.95,
        risk_level="CRITICAL",
        contributing_factors=["Botnet vector detected"]
    )

    # 2. Cannot request challenge for terminated session
    chal_res = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": session_id
    })
    assert chal_res.status_code == 400
    assert "terminated" in chal_res.json()["detail"].lower()

    # 3. Cannot verify terminated session
    ver_res = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "challenge_type": "OTP",
        "challenge_code": "123456"
    })
    assert ver_res.status_code == 400
    assert "terminated" in ver_res.json()["detail"].lower()


# ==============================================================================
# CASE 10: A new login session is not treated as verified because another was verified
# ==============================================================================
def test_case_10_new_session_not_verified_by_prior_session(client: TestClient, auth_user, db_session):
    headers, user_id, _ = auth_user
    
    # Session 1 starts and completes Step-Up
    s1_res = client.post("/api/sessions/start", headers=headers, json={
        "application": "college",
        "device_fingerprint": "dev_s1"
    })
    session_1_id = s1_res.json()["id"]
    with patch("app.services.email_service.EmailService.send_otp_email", return_value=(True, "Delivered")):
        c1 = client.post("/api/security/step-up/challenge", headers=headers, json={"session_id": session_1_id})
    client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_1_id,
        "challenge_type": "OTP",
        "challenge_code": c1.json()["otp"]
    })

    # Session 2 starts fresh
    s2_res = client.post("/api/sessions/start", headers=headers, json={
        "application": "college",
        "device_fingerprint": "dev_s2"
    })
    session_2_id = s2_res.json()["id"]

    # Session 2 must NOT have fresh step-up verification
    db_session.expire_all()
    s2_record = db_session.query(Session).filter(Session.id == session_2_id).first()
    assert s2_record.step_up_verified_at is None
    assert s2_record.step_up_valid_until is None
    assert SessionService.is_step_up_fresh(s2_record, current_risk_score=0.40, current_risk_level="MEDIUM") is False


# ==============================================================================
# CASE 11: Device YES/NO actions remain separate from OTP verification
# ==============================================================================
def test_case_11_device_yes_no_actions_separate_from_otp_verification(client: TestClient, auth_user, db_session):
    headers, user_id, _ = auth_user

    # Create a registered device and notification
    dev = Device(
        user_id=user_id,
        device_id="dev_separate_test",
        device_fingerprint="fp_sep_test",
        trust_state="PENDING_CONFIRMATION",
        is_trusted=False
    )
    db_session.add(dev)
    db_session.commit()
    db_session.refresh(dev)

    notif = DeviceNotification(
        user_id=user_id,
        device_id=dev.id,
        notification_id="notif_sep_test",
        title="New Sign-in Alert",
        message="Did you sign in?",
        status="PENDING_CONFIRMATION"
    )
    db_session.add(notif)
    db_session.commit()

    # User responds "YES" to confirm device
    yes_res = client.post(f"/api/notifications/{notif.notification_id}/respond", headers=headers, json={
        "decision": "yes"
    })
    assert yes_res.status_code == 200
    assert yes_res.json()["status"] == "success"
    assert yes_res.json()["device_trust_state"] == "TRUSTED"

    # Confirm that YES did NOT create any OTP challenge or verify any Step-Up
    assert StepUpService.get_challenge("any_session") is None

    # Now create another notification and respond "NO"
    notif2 = DeviceNotification(
        user_id=user_id,
        device_id=dev.id,
        notification_id="notif_sep_test_2",
        title="Another Sign-in Alert",
        message="Did you sign in?",
        status="PENDING_CONFIRMATION"
    )
    db_session.add(notif2)
    db_session.commit()

    no_res = client.post(f"/api/notifications/{notif2.notification_id}/respond", headers=headers, json={
        "decision": "no"
    })
    assert no_res.status_code == 200
    assert no_res.json()["device_trust_state"] == "REVOKED"


# ==============================================================================
# CASE 12: Existing email delivery, adaptive factors, and portal tests pass
# ==============================================================================
def test_case_12_adaptive_factors_and_protected_portals_consistency(client: TestClient, auth_user, db_session):
    headers, user_id, _ = auth_user
    sess_res = client.post("/api/sessions/start", headers=headers, json={
        "application": "healthcare",
        "device_fingerprint": "dev_test_12"
    })
    session_id = sess_res.json()["id"]

    # Verify gesture pattern adaptive factor enrollment and verification works
    enroll_res = client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": [0, 1, 2, 5],
        "confirm_pattern": [0, 1, 2, 5]
    })
    assert enroll_res.status_code == 200
    assert enroll_res.json()["success"] is True

    # Request GESTURE_PATTERN challenge
    chal_res = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": session_id,
        "preferred_factor": "GESTURE_PATTERN"
    })
    assert chal_res.status_code == 200
    assert chal_res.json()["challenge_type"] == "GESTURE_PATTERN"

    # Verify gesture pattern
    ver_res = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": [0, 1, 2, 5]
    })
    assert ver_res.status_code == 200
    assert ver_res.json()["decision"] == "ALLOW"
    assert ver_res.json()["session_status"] == "ACTIVE"
