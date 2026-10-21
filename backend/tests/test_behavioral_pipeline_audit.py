import pytest
import time
import json
import numpy as np
from fastapi.testclient import TestClient
from app.main import app
from app.models.user import User
from app.models.session import Session as DbSession
from app.models.device import Device
from app.models.behavior import BehaviorLog, BehaviorProfile
from app.schemas.behavior import BehaviorEventCreate
from app.ml.feature_engineering import FeatureEngineering, FEATURE_NAMES
from app.services.step_up_service import StepUpService
from app.services.anti_replay_service import AntiReplayService
from app.services.profile_service import ProfileService
from app.services.risk_service import RiskService
from app.core.rate_limit import rate_limiter


@pytest.fixture(autouse=True)
def reset_security_managers():
    StepUpService.reset()
    AntiReplayService.reset()
    rate_limiter.reset()
    yield
    StepUpService.reset()
    AntiReplayService.reset()
    rate_limiter.reset()


def register_and_login_synthetic_user(client: TestClient, email: str, role: str = "USER", app_name: str = "platform"):
    reg_res = client.post("/api/auth/register", json={
        "name": f"Synthetic User {email.split('@')[0]}",
        "email": email,
        "password": "Password@123",
        "role": role
    })
    assert reg_res.status_code == 201

    login_res = client.post("/api/auth/login", json={
        "email": email,
        "password": "Password@123",
        "application": app_name,
        "device_fingerprint": f"fp_{email.split('@')[0]}"
    })
    assert login_res.status_code == 200
    login_data = login_res.json()
    token = login_data["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    return email, headers, login_data


# ==============================================================================
# 1. NORMAL INTERACTION PRODUCES VALID FEATURE DATA
# ==============================================================================
def test_1_normal_interaction_produces_valid_feature_vector():
    """Verifies that all 10 features extracted from telemetry conform to physical boundaries."""
    event = BehaviorEventCreate(
        session_id="sess_synth_001",
        application="platform",
        typing_speed_wpm=72.5,
        avg_flight_time_ms=115.0,
        avg_dwell_time_ms=88.5,
        mouse_velocity_avg=450.0,
        mouse_acceleration_avg=620.0,
        mouse_curvature_entropy=1.25,
        click_frequency=1.2,
        scroll_speed_avg=280.0,
        idle_duration_sec=0.5,
        navigation_entropy=1.1,
        timestamp=time.time(),
        sequence_number=1,
        telemetry_nonce="nonce_test_001"
    )

    vec = FeatureEngineering.extract_vector(event)
    assert len(vec) == 10
    is_valid, err = FeatureEngineering.validate_vector(vec)
    assert is_valid is True, f"Validation failed: {err}"
    assert err is None


# ==============================================================================
# 2. BACKEND RECEIVES AND PERSISTS TELEMETRY
# ==============================================================================
def test_2_backend_receives_and_persists_telemetry(client: TestClient, db_session):
    """Verifies that POST /api/behavior/events ingests and commits telemetry to BehaviorLog."""
    email = "synth.persist@cognisec.ai"
    _, headers, login_data = register_and_login_synthetic_user(client, email)
    sid = login_data["session_id"]

    event_payload = {
        "session_id": sid,
        "application": "platform",
        "typing_speed_wpm": 65.0,
        "avg_flight_time_ms": 120.0,
        "avg_dwell_time_ms": 90.0,
        "mouse_velocity_avg": 500.0,
        "mouse_acceleration_avg": 350.0,
        "mouse_curvature_entropy": 0.85,
        "click_frequency": 0.5,
        "scroll_speed_avg": 150.0,
        "idle_duration_sec": 1.2,
        "navigation_entropy": 0.95,
        "timestamp": time.time(),
        "sequence_number": 1,
        "telemetry_nonce": "nonce_persist_001"
    }

    res = client.post("/api/behavior/events", headers=headers, json=event_payload)
    assert res.status_code == 200

    db_session.expire_all()
    user = db_session.query(User).filter(User.email == email).first()
    logs = db_session.query(BehaviorLog).filter(BehaviorLog.session_id == sid).all()
    assert len(logs) == 1
    log = logs[0]
    assert log.user_id == user.id
    assert log.typing_speed_wpm == 65.0
    assert log.scroll_speed_avg == 150.0
    assert log.mouse_acceleration_avg == 350.0


# ==============================================================================
# 3. PERSISTED RECORDS BELONG TO CORRECT USER, DEVICE, AND SESSION
# ==============================================================================
def test_3_persisted_records_belong_to_correct_user_device_session(client: TestClient, db_session):
    """Verifies relational integrity: BehaviorLog -> Session -> Device & User."""
    email = "synth.relations@cognisec.ai"
    _, headers, login_data = register_and_login_synthetic_user(client, email)
    sid = login_data["session_id"]

    event_payload = {
        "session_id": sid,
        "application": "platform",
        "typing_speed_wpm": 55.0,
        "avg_flight_time_ms": 140.0,
        "avg_dwell_time_ms": 95.0,
        "mouse_velocity_avg": 320.0,
        "mouse_acceleration_avg": 210.0,
        "mouse_curvature_entropy": 0.75,
        "click_frequency": 0.4,
        "scroll_speed_avg": 80.0,
        "idle_duration_sec": 0.8,
        "navigation_entropy": 0.5,
        "timestamp": time.time(),
        "sequence_number": 1,
        "telemetry_nonce": "nonce_rel_001"
    }

    res = client.post("/api/behavior/events", headers=headers, json=event_payload)
    assert res.status_code == 200

    db_session.expire_all()
    session = db_session.query(DbSession).filter(DbSession.id == sid).first()
    user = db_session.query(User).filter(User.email == email).first()
    device = db_session.query(Device).filter(Device.id == session.device_id).first()
    log = db_session.query(BehaviorLog).filter(BehaviorLog.session_id == sid).first()

    assert log.user_id == user.id
    assert log.session_id == session.id
    assert session.user_id == user.id
    assert device.user_id == user.id


# ==============================================================================
# 4. MISSING OR MALFORMED FEATURES ARE HANDLED SAFELY
# ==============================================================================
def test_4_missing_or_malformed_features_handled_safely(client: TestClient, db_session):
    """Malformed bounds are rejected; missing optional features default safely."""
    email = "synth.malformed@cognisec.ai"
    _, headers, login_data = register_and_login_synthetic_user(client, email)
    sid = login_data["session_id"]

    # Negative typing speed is rejected
    bad_payload = {
        "session_id": sid,
        "application": "platform",
        "typing_speed_wpm": -25.0,
        "timestamp": time.time(),
        "sequence_number": 1,
        "telemetry_nonce": "nonce_bad_001"
    }
    res = client.post("/api/behavior/events", headers=headers, json=bad_payload)
    assert res.status_code == 400
    assert any(k in res.json()["detail"].lower() for k in ("bounds", "sanity", "negative", "tampering"))

    # Missing optional features default safely to 0.0 and succeed
    minimal_payload = {
        "session_id": sid,
        "application": "platform",
        "timestamp": time.time(),
        "sequence_number": 2,
        "telemetry_nonce": "nonce_min_002"
    }
    res_ok = client.post("/api/behavior/events", headers=headers, json=minimal_payload)
    assert res_ok.status_code == 200


# ==============================================================================
# 5. SENSITIVE INPUTS NEVER ENTER TELEMETRY PAYLOADS OR STORED LOGS
# ==============================================================================
def test_5_sensitive_inputs_never_enter_telemetry_payloads_or_stored_logs(client: TestClient, db_session):
    """Verifies strict schema privacy: schema and database contain no raw characters or passwords."""
    # Check Schema fields
    fields = BehaviorEventCreate.model_fields.keys()
    assert "password" not in fields
    assert "raw_keystrokes" not in fields
    assert "text" not in fields
    assert "input_value" not in fields

    email = "synth.privacy@cognisec.ai"
    _, headers, login_data = register_and_login_synthetic_user(client, email)
    sid = login_data["session_id"]

    payload = {
        "session_id": sid,
        "application": "platform",
        "typing_speed_wpm": 60.0,
        "avg_flight_time_ms": 110.0,
        "avg_dwell_time_ms": 80.0,
        "timestamp": time.time(),
        "sequence_number": 1,
        "telemetry_nonce": "nonce_priv_001"
    }
    res = client.post("/api/behavior/events", headers=headers, json=payload)
    assert res.status_code == 200

    db_session.expire_all()
    log = db_session.query(BehaviorLog).filter(BehaviorLog.session_id == sid).first()
    assert hasattr(log, "password") is False
    assert hasattr(log, "raw_keystroke_chars") is False
    assert "password" not in (log.raw_feature_json or "").lower()


# ==============================================================================
# 6. INSUFFICIENT TELEMETRY DOES NOT PRODUCE FALSE HIGH-CONFIDENCE MATCH
# ==============================================================================
def test_6_insufficient_telemetry_does_not_produce_false_confidence(client: TestClient, db_session):
    """Verifies that zero/insufficient telemetry yields COLD_START and 0.0 confidence."""
    email = "synth.coldstart@cognisec.ai"
    _, headers, login_data = register_and_login_synthetic_user(client, email)
    user = db_session.query(User).filter(User.email == email).first()

    status_label, confidence, is_mature = ProfileService.get_maturity_info(sample_count=0)
    assert status_label == "COLD_START"
    assert confidence == 0.0
    assert is_mature is False

    # Risk calculation for cold start user does NOT fabricate confidence
    vec = np.zeros(10, dtype=np.float64)
    risk_score, anomaly_score, risk_level, factors, is_anomaly, ml_status = RiskService.calculate_risk(
        db=db_session,
        user_id=user.id,
        session_id=login_data["session_id"],
        application="platform",
        behavior_vector=vec,
        context_signals={}
    )
    assert ml_status == "ML_COLD_START"
    assert is_anomaly is False
    assert risk_level == "LOW"


# ==============================================================================
# 7. SECOND LOGIN CREATES NEW OBSERVATION WINDOW AND DOES NOT REUSE FIRST STATE
# ==============================================================================
def test_7_second_login_creates_new_observation_window_without_state_reuse(client: TestClient, db_session):
    """Consecutive logins produce distinct sessions with independent observation states."""
    email = "synth.multilogin@cognisec.ai"
    _, _, login1 = register_and_login_synthetic_user(client, email)
    sid1 = login1["session_id"]
    assert login1["session_status"] == "PENDING_OBSERVATION"

    # Second login
    login_res2 = client.post("/api/auth/login", json={
        "email": email,
        "password": "Password@123",
        "application": "platform"
    })
    assert login_res2.status_code == 200
    login2 = login_res2.json()
    sid2 = login2["session_id"]

    assert sid1 != sid2
    assert login2["session_status"] == "PENDING_OBSERVATION"

    db_session.expire_all()
    s1 = db_session.query(DbSession).filter(DbSession.id == sid1).first()
    s2 = db_session.query(DbSession).filter(DbSession.id == sid2).first()
    assert s1.id != s2.id


# ==============================================================================
# 8. CROSS-USER TELEMETRY INJECTION IS REJECTED
# ==============================================================================
def test_8_cross_user_telemetry_injection_rejected(client: TestClient, db_session):
    """User B cannot submit telemetry targeting User A's session ID (BOLA prevention)."""
    email_a = "synth.victim@cognisec.ai"
    email_b = "synth.attacker@cognisec.ai"
    _, _, login_a = register_and_login_synthetic_user(client, email_a)
    _, headers_b, _ = register_and_login_synthetic_user(client, email_b)

    payload_spoofed = {
        "session_id": login_a["session_id"],
        "application": "platform",
        "typing_speed_wpm": 70.0,
        "timestamp": time.time(),
        "sequence_number": 1,
        "telemetry_nonce": "nonce_spoof_001"
    }

    res = client.post("/api/behavior/events", headers=headers_b, json=payload_spoofed)
    assert res.status_code == 403
    assert "Unauthorized" in res.json()["detail"]


# ==============================================================================
# 9. RISK ENGINE USES VALIDATED FEATURES AND APPLIES CORRECT RISK POLICY
# ==============================================================================
def test_9_risk_engine_uses_validated_features_and_applies_correct_policy(client: TestClient, db_session):
    """Validates risk mapping: normal behavior -> LOW risk; severe anomalies -> elevated risk."""
    email = "synth.risk@cognisec.ai"
    _, headers, login_data = register_and_login_synthetic_user(client, email)
    sid = login_data["session_id"]

    # Normal low-risk telemetry
    normal_payload = {
        "session_id": sid,
        "application": "platform",
        "typing_speed_wpm": 60.0,
        "avg_flight_time_ms": 120.0,
        "avg_dwell_time_ms": 90.0,
        "mouse_velocity_avg": 300.0,
        "mouse_acceleration_avg": 250.0,
        "mouse_curvature_entropy": 0.5,
        "click_frequency": 0.5,
        "scroll_speed_avg": 100.0,
        "idle_duration_sec": 1.0,
        "navigation_entropy": 0.5,
        "timestamp": time.time(),
        "sequence_number": 1,
        "telemetry_nonce": "nonce_risk_001"
    }
    res_normal = client.post("/api/behavior/events", headers=headers, json=normal_payload)
    assert res_normal.status_code == 200
    assert res_normal.json()["decision"] in ["ALLOW", "OBSERVATION_PENDING"]

    # Critical risk attack simulation (e.g. impossible travel + request flood)
    critical_payload = {
        "session_id": sid,
        "application": "platform",
        "typing_speed_wpm": 300.0,
        "click_frequency": 25.0,
        "mouse_velocity_avg": 8000.0,
        "mouse_acceleration_avg": 20000.0,
        "context_signals": {
            "impossible_travel": True,
            "request_flood": True,
            "failed_attempts_count": 5
        },
        "timestamp": time.time(),
        "sequence_number": 2,
        "telemetry_nonce": "nonce_crit_002"
    }
    res_crit = client.post("/api/behavior/events", headers=headers, json=critical_payload)
    assert res_crit.status_code == 200
    crit_data = res_crit.json()
    assert crit_data["decision"] == "TERMINATE_SESSION"
    assert crit_data["session_status"] == "TERMINATED"


# ==============================================================================
# 10. LOGOUT AND SESSION TERMINATION STOP AUTHORIZED TELEMETRY INGESTION
# ==============================================================================
def test_10_logout_and_session_termination_stop_authorized_telemetry(client: TestClient, db_session):
    """Once a session is terminated or logged out, subsequent telemetry is rejected."""
    email = "synth.logout@cognisec.ai"
    _, headers, login_data = register_and_login_synthetic_user(client, email)
    sid = login_data["session_id"]

    # Log out
    logout_res = client.post(f"/api/auth/logout?session_id={sid}", headers=headers)
    assert logout_res.status_code == 200

    # Attempt to submit telemetry after logout
    payload_after_logout = {
        "session_id": sid,
        "application": "platform",
        "typing_speed_wpm": 50.0,
        "timestamp": time.time(),
        "sequence_number": 1,
        "telemetry_nonce": "nonce_after_logout_001"
    }
    res = client.post("/api/behavior/events", headers=headers, json=payload_after_logout)
    assert res.status_code in (400, 401)
