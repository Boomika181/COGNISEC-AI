import time
import pytest
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from app.services.step_up_service import StepUpService
from app.services.anti_replay_service import AntiReplayService
from app.core.rate_limit import rate_limiter
from app.models.session import Session


@pytest.fixture(autouse=True)
def reset_security_managers():
    """Ensure clean state before each test."""
    StepUpService.reset()
    AntiReplayService.reset()
    rate_limiter.reset()
    yield
    StepUpService.reset()
    AntiReplayService.reset()
    rate_limiter.reset()


@pytest.fixture
def auth_user(client: TestClient, db_session):
    """Creates User A and returns auth header and user_id."""
    email = f"phase2_a_{time.time()}@example.com"
    client.post("/api/auth/register", json={
        "email": email,
        "password": "Password123!",
        "name": "Phase Two Alpha"
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
    return {"Authorization": f"Bearer {token}"}, user_id


@pytest.fixture
def auth_user_b(client: TestClient, db_session):
    """Creates User B and returns auth header and user_id."""
    email = f"phase2_b_{time.time()}@example.com"
    client.post("/api/auth/register", json={
        "email": email,
        "password": "Password123!",
        "name": "Phase Two Beta"
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
    return {"Authorization": f"Bearer {token}"}, user_id


# ==============================================================================
# 1. REAL STEP-UP CHALLENGE & VERIFICATION TESTS
# ==============================================================================

def test_step_up_challenge_generation(client: TestClient, auth_user):
    headers, _ = auth_user
    sess_res = client.post("/api/sessions/start", headers=headers, json={
        "application": "finance",
        "device_fingerprint": "dev_fp_1"
    })
    session_id = sess_res.json()["id"]

    res = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": session_id
    })
    assert res.status_code == 200
    data = res.json()
    assert "challenge_id" in data
    assert data["session_id"] == session_id
    assert "otp" in data
    assert len(data["otp"]) == 6
    assert data["otp"].isdigit()
    assert data["expires_in_seconds"] == 300


def test_step_up_verify_success_restores_active_session(client: TestClient, auth_user, db_session):
    headers, _ = auth_user
    sess_res = client.post("/api/sessions/start", headers=headers, json={
        "application": "finance",
        "device_fingerprint": "dev_fp_2"
    })
    session_id = sess_res.json()["id"]

    # Manually transition session to STEP_UP_REQUIRED
    sess_record = db_session.query(Session).filter(Session.id == session_id).first()
    sess_record.status = "STEP_UP_REQUIRED"
    db_session.commit()

    # Request challenge
    chal_res = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": session_id
    })
    otp = chal_res.json()["otp"]

    # Verify with correct OTP
    verify_res = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "challenge_code": otp
    })
    assert verify_res.status_code == 200
    outcome = verify_res.json()
    assert outcome["decision"] == "ALLOW"
    assert outcome["session_status"] == "ACTIVE"
    assert outcome["verification_required"] is False

    # Check database state
    db_session.refresh(sess_record)
    assert sess_record.status == "ACTIVE"
    assert sess_record.current_risk_level == "LOW"


def test_step_up_verify_invalid_code_decrements_attempts(client: TestClient, auth_user):
    headers, _ = auth_user
    sess_res = client.post("/api/sessions/start", headers=headers, json={
        "application": "finance",
        "device_fingerprint": "dev_fp_3"
    })
    session_id = sess_res.json()["id"]

    client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": session_id
    })

    # Send wrong OTP
    res = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "challenge_code": "000000"
    })
    assert res.status_code == 400
    assert "2 attempts remaining" in res.json()["detail"].lower()


def test_step_up_max_attempts_lockout(client: TestClient, auth_user, db_session):
    headers, _ = auth_user
    sess_res = client.post("/api/sessions/start", headers=headers, json={
        "application": "finance",
        "device_fingerprint": "dev_fp_4"
    })
    session_id = sess_res.json()["id"]

    client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": session_id
    })

    # Fail 3 consecutive times
    client.post("/api/security/step-up/verify", headers=headers, json={"session_id": session_id, "challenge_code": "111111"})
    client.post("/api/security/step-up/verify", headers=headers, json={"session_id": session_id, "challenge_code": "222222"})
    third_res = client.post("/api/security/step-up/verify", headers=headers, json={"session_id": session_id, "challenge_code": "333333"})

    assert third_res.status_code == 400
    assert "maximum verification attempts exceeded" in third_res.json()["detail"].lower()

    # Session must now be locked to RESTRICTED in database
    sess_record = db_session.query(Session).filter(Session.id == session_id).first()
    assert sess_record.status == "RESTRICTED"


def test_step_up_challenge_single_use(client: TestClient, auth_user):
    headers, _ = auth_user
    sess_res = client.post("/api/sessions/start", headers=headers, json={
        "application": "finance",
        "device_fingerprint": "dev_fp_5"
    })
    session_id = sess_res.json()["id"]

    chal_res = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": session_id
    })
    otp = chal_res.json()["otp"]

    # First verification -> Success
    res1 = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "challenge_code": otp
    })
    assert res1.status_code == 200

    # Second verification with same OTP -> Rejected (Already consumed)
    res2 = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "challenge_code": otp
    })
    assert res2.status_code == 400
    assert "no active step-up challenge found" in res2.json()["detail"].lower()


def test_step_up_cross_user_forbidden(client: TestClient, auth_user, auth_user_b):
    headers_a, _ = auth_user
    headers_b, _ = auth_user_b

    sess_res = client.post("/api/sessions/start", headers=headers_b, json={
        "application": "finance",
        "device_fingerprint": "dev_fp_b"
    })
    b_session_id = sess_res.json()["id"]

    # User A tries to request challenge for User B's session -> 403
    res_chal = client.post("/api/security/step-up/challenge", headers=headers_a, json={
        "session_id": b_session_id
    })
    assert res_chal.status_code == 403

    # User A tries to verify User B's session -> 403
    res_ver = client.post("/api/security/step-up/verify", headers=headers_a, json={
        "session_id": b_session_id,
        "challenge_code": "123456"
    })
    assert res_ver.status_code == 403


def test_step_up_challenge_expiry(client: TestClient, auth_user):
    headers, _ = auth_user
    sess_res = client.post("/api/sessions/start", headers=headers, json={
        "application": "finance",
        "device_fingerprint": "dev_fp_exp"
    })
    session_id = sess_res.json()["id"]

    chal_res = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": session_id
    })
    assert chal_res.status_code == 200
    otp = chal_res.json()["otp"]

    # Fast-forward expires_at to simulate TTL expiration
    from app.services.step_up_service import StepUpService, utc_now
    with StepUpService._lock:
        if session_id in StepUpService._challenges:
            from datetime import timedelta
            StepUpService._challenges[session_id]["expires_at"] = utc_now() - timedelta(seconds=10)

    # Submitting after expiration must fail with 400
    res = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "challenge_code": otp
    })
    assert res.status_code == 400
    assert "expired" in res.json()["detail"].lower()


def test_session_security_status_sanitized_for_user(client: TestClient, auth_user, db_session):
    headers, _ = auth_user
    sess_res = client.post("/api/sessions/start", headers=headers, json={
        "application": "ecommerce",
        "device_fingerprint": "dev_fp_status"
    })
    session_id = sess_res.json()["id"]

    # Active status
    stat_res = client.get(f"/api/security/status/{session_id}", headers=headers)
    assert stat_res.status_code == 200
    data = stat_res.json()
    assert data["decision"] == "ALLOW"
    assert data["session_status"] == "ACTIVE"
    assert data["verification_required"] is False
    # Ensure no internal ML scores leaked to user
    assert "anomaly_score" not in data
    assert "risk_score" not in data
    assert "isolation_forest" not in data

    # When session transitioned to STEP_UP_REQUIRED
    sess_record = db_session.query(Session).filter(Session.id == session_id).first()
    sess_record.status = "STEP_UP_REQUIRED"
    db_session.commit()

    stat_step = client.get(f"/api/security/status/{session_id}", headers=headers)
    assert stat_step.status_code == 200
    step_data = stat_step.json()
    assert step_data["decision"] == "STEP_UP_VERIFICATION"
    assert step_data["session_status"] == "STEP_UP_REQUIRED"
    assert step_data["verification_required"] is True


def test_step_up_failed_leaves_access_protected(client: TestClient, auth_user, db_session):
    headers, _ = auth_user
    sess_res = client.post("/api/sessions/start", headers=headers, json={
        "application": "healthcare",
        "device_fingerprint": "dev_fp_prot"
    })
    session_id = sess_res.json()["id"]

    # Set status to STEP_UP_REQUIRED
    sess_record = db_session.query(Session).filter(Session.id == session_id).first()
    sess_record.status = "STEP_UP_REQUIRED"
    db_session.commit()

    # Request challenge
    client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": session_id
    })

    # Submit wrong OTP
    res = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "challenge_code": "000000"
    })
    assert res.status_code == 400

    # Verify session remains locked/STEP_UP_REQUIRED (NOT unlocked)
    db_session.refresh(sess_record)
    assert sess_record.status == "STEP_UP_REQUIRED"



# ==============================================================================
# 2. TELEMETRY ANTI-REPLAY & ANTI-TAMPER TESTS
# ==============================================================================

def test_telemetry_monotonic_sequence_accepted(client: TestClient, auth_user):
    headers, _ = auth_user
    sess_res = client.post("/api/sessions/start", headers=headers, json={
        "application": "ecommerce",
        "device_fingerprint": "ecom_fp_1"
    })
    session_id = sess_res.json()["id"]

    # Sequence 1
    res1 = client.post("/api/behavior/events", headers=headers, json={
        "session_id": session_id,
        "application": "ecommerce",
        "typing_speed_wpm": 60.0,
        "sequence_number": 1
    })
    assert res1.status_code == 200

    # Sequence 2
    res2 = client.post("/api/behavior/events", headers=headers, json={
        "session_id": session_id,
        "application": "ecommerce",
        "typing_speed_wpm": 62.0,
        "sequence_number": 2
    })
    assert res2.status_code == 200


def test_telemetry_replayed_sequence_number_rejected(client: TestClient, auth_user):
    headers, _ = auth_user
    sess_res = client.post("/api/sessions/start", headers=headers, json={
        "application": "ecommerce",
        "device_fingerprint": "ecom_fp_2"
    })
    session_id = sess_res.json()["id"]

    # Send sequence 5
    client.post("/api/behavior/events", headers=headers, json={
        "session_id": session_id,
        "application": "ecommerce",
        "sequence_number": 5
    })

    # Replay sequence 5 -> Rejected
    replay_res = client.post("/api/behavior/events", headers=headers, json={
        "session_id": session_id,
        "application": "ecommerce",
        "sequence_number": 5
    })
    assert replay_res.status_code == 400
    assert "replay detected" in replay_res.json()["detail"].lower()

    # Out-of-order/replayed sequence 4 -> Rejected
    older_res = client.post("/api/behavior/events", headers=headers, json={
        "session_id": session_id,
        "application": "ecommerce",
        "sequence_number": 4
    })
    assert older_res.status_code == 400
    assert "replay detected" in older_res.json()["detail"].lower()


def test_telemetry_duplicate_nonce_rejected(client: TestClient, auth_user):
    headers, _ = auth_user
    sess_res = client.post("/api/sessions/start", headers=headers, json={
        "application": "ecommerce",
        "device_fingerprint": "ecom_fp_3"
    })
    session_id = sess_res.json()["id"]

    nonce = f"nonce_{time.time()}"
    res1 = client.post("/api/behavior/events", headers=headers, json={
        "session_id": session_id,
        "application": "ecommerce",
        "typing_speed_wpm": 55.0,
        "telemetry_nonce": nonce
    })
    assert res1.status_code == 200

    # Replaying same nonce -> Rejected
    res2 = client.post("/api/behavior/events", headers=headers, json={
        "session_id": session_id,
        "application": "ecommerce",
        "typing_speed_wpm": 58.0,
        "telemetry_nonce": nonce
    })
    assert res2.status_code == 400
    assert "nonce has already been processed" in res2.json()["detail"].lower()


def test_telemetry_timestamp_skew_rejected(client: TestClient, auth_user):
    headers, _ = auth_user
    sess_res = client.post("/api/sessions/start", headers=headers, json={
        "application": "ecommerce",
        "device_fingerprint": "ecom_fp_4"
    })
    session_id = sess_res.json()["id"]

    # Telemetry timestamp 10 minutes in the past
    stale_timestamp = time.time() - 600
    res = client.post("/api/behavior/events", headers=headers, json={
        "session_id": session_id,
        "application": "ecommerce",
        "timestamp": stale_timestamp
    })
    assert res.status_code == 400
    assert "timestamp skew too large" in res.json()["detail"].lower()


def test_telemetry_anti_tamper_negative_values_rejected(client: TestClient, auth_user):
    headers, _ = auth_user
    sess_res = client.post("/api/sessions/start", headers=headers, json={
        "application": "ecommerce",
        "device_fingerprint": "ecom_fp_5"
    })
    session_id = sess_res.json()["id"]

    res = client.post("/api/behavior/events", headers=headers, json={
        "session_id": session_id,
        "application": "ecommerce",
        "avg_flight_time_ms": -45.0  # Physically impossible negative time
    })
    assert res.status_code == 400
    assert "tampering detected" in res.json()["detail"].lower()


def test_telemetry_anti_tamper_superhuman_speed_rejected(client: TestClient, auth_user):
    headers, _ = auth_user
    sess_res = client.post("/api/sessions/start", headers=headers, json={
        "application": "ecommerce",
        "device_fingerprint": "ecom_fp_6"
    })
    session_id = sess_res.json()["id"]

    res = client.post("/api/behavior/events", headers=headers, json={
        "session_id": session_id,
        "application": "ecommerce",
        "typing_speed_wpm": 800.0  # Superhuman bot speed
    })
    assert res.status_code == 400
    assert "physiological human limits" in res.json()["detail"].lower()


# ==============================================================================
# 3. RATE LIMITING TESTS
# ==============================================================================

def test_step_up_challenge_rate_limiting(client: TestClient, auth_user):
    """Exceeding step-up challenge limit (10/min) returns HTTP 429."""
    headers, _ = auth_user
    sess_res = client.post("/api/sessions/start", headers=headers, json={
        "application": "college",
        "device_fingerprint": "college_fp_rl"
    })
    session_id = sess_res.json()["id"]

    # Send 10 allowed requests
    for _ in range(10):
        r = client.post("/api/security/step-up/challenge", headers=headers, json={"session_id": session_id})
        assert r.status_code == 200

    # 11th request triggers HTTP 429
    r11 = client.post("/api/security/step-up/challenge", headers=headers, json={"session_id": session_id})
    assert r11.status_code == 429
    assert "too many" in r11.json()["detail"].lower() or "rate limit" in r11.json()["detail"].lower()
    assert "retry-after" in r11.headers
