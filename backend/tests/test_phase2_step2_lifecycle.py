import json
import time
import numpy as np
import pytest
from fastapi.testclient import TestClient
from app.models.user import User
from app.models.session import Session as DbSession
from app.models.behavior import BehaviorLog, BehaviorProfile
from app.models.security_event import SecurityEvent
from app.models.alert import Alert
from app.services.profile_service import ProfileService
from app.services.session_service import SessionService
from app.ml.model_manager import ModelManager
from app.ml.anomaly_detector import IsolationForestDetector


# ==============================================================================
# PHASE-II STEP 2: END-TO-END CONTINUOUS AUTHENTICATION & BASELINE LIFECYCLE
# ==============================================================================

def test_registration_does_not_create_artificial_baseline(client: TestClient, db_session):
    """
    Task 2: Account creation must create only the user account,
    not an artificial behavioral profile or fabricated baseline samples.
    """
    unique_email = f"fresh.user.{time.time_ns()}@cognisec.ai"
    reg_res = client.post("/api/auth/register", json={
        "name": "Fresh Test User",
        "email": unique_email,
        "password": "Password@123",
        "role": "USER"
    })
    assert reg_res.status_code == 201
    user_id = reg_res.json()["id"]

    # Verify no behavior logs exist for the new user
    logs = db_session.query(BehaviorLog).filter(BehaviorLog.user_id == user_id).all()
    assert len(logs) == 0

    # Verify no established profile exists in database
    profile = db_session.query(BehaviorProfile).filter(BehaviorProfile.user_id == user_id).first()
    assert profile is None


def test_first_authenticated_session_and_telemetry_persistence(client: TestClient, db_session):
    """
    Task 2: After authentication, establish a session, ingest the first telemetry
    event, and verify database persistence under the correct user and session.
    """
    unique_email = f"telemetry.user.{time.time_ns()}@cognisec.ai"
    client.post("/api/auth/register", json={
        "name": "Telemetry User",
        "email": unique_email,
        "password": "Password@123",
        "role": "USER"
    })

    # Sign in
    login_res = client.post("/api/auth/login", json={
        "email": unique_email,
        "password": "Password@123",
        "application": "college"
    })
    assert login_res.status_code == 200
    login_data = login_res.json()
    token = login_data["access_token"]
    session_id = login_data["session_id"]
    user_id = login_data["user_id"]
    SessionService.activate_session_after_login_otp(db_session, session_id)
    headers = {"Authorization": f"Bearer {token}"}

    # Submit first valid telemetry event
    event_payload = {
        "session_id": session_id,
        "application": "college",
        "typing_speed_wpm": 66.0,
        "avg_flight_time_ms": 122.0,
        "avg_dwell_time_ms": 82.0,
        "mouse_velocity_avg": 580.0,
        "mouse_acceleration_avg": 360.0,
        "mouse_curvature_entropy": 0.42,
        "click_frequency": 0.8,
        "scroll_speed_avg": 240.0,
        "idle_duration_sec": 1.2,
        "navigation_entropy": 0.32,
        "context_signals": {"is_new_device": False},
        "sequence_number": 1,
        "telemetry_nonce": f"nonce_first_{time.time_ns()}"
    }

    res = client.post("/api/behavior/events", headers=headers, json=event_payload)
    assert res.status_code == 200
    res_data = res.json()
    assert res_data["decision"] == "ALLOW"
    assert res_data["session_status"] == "ACTIVE"

    # Verify BehaviorLog persisted in database
    db_logs = db_session.query(BehaviorLog).filter(BehaviorLog.user_id == user_id).all()
    assert len(db_logs) == 1
    saved_log = db_logs[0]
    assert saved_log.session_id == session_id
    assert saved_log.application == "college"
    assert abs(saved_log.typing_speed_wpm - 66.0) < 1e-2
    assert abs(saved_log.avg_dwell_time_ms - 82.0) < 1e-2


def test_baseline_progression_from_cold_start_to_established(client: TestClient, db_session):
    """
    Task 3: Verifies sample count progression:
    COLD_START (0) -> LEARNING (1-4) -> ESTABLISHED (5+).
    """
    unique_email = f"baseline.prog.{time.time_ns()}@cognisec.ai"
    client.post("/api/auth/register", json={
        "name": "Progressing User",
        "email": unique_email,
        "password": "Password@123"
    })
    login_res = client.post("/api/auth/login", json={
        "email": unique_email,
        "password": "Password@123",
        "application": "ecommerce"
    })
    login_json = login_res.json()
    token = login_json["access_token"]
    session_id = login_json["session_id"]
    user_id = login_json["user_id"]
    SessionService.activate_session_after_login_otp(db_session, session_id)
    headers = {"Authorization": f"Bearer {token}"}

    # Before events: COLD_START
    profile = ProfileService.get_or_create_profile(db_session, user_id)
    status_0, conf_0, is_mat_0 = ProfileService.get_maturity_info(profile.sample_count)
    assert status_0 == "COLD_START"
    assert not is_mat_0

    # Ingest 4 legitimate samples: LEARNING
    for seq in range(1, 5):
        event = {
            "session_id": session_id,
            "application": "ecommerce",
            "typing_speed_wpm": 68.0 + (seq * 0.5),
            "avg_flight_time_ms": 118.0,
            "avg_dwell_time_ms": 84.0,
            "mouse_velocity_avg": 620.0 + (seq * 2.0),
            "mouse_acceleration_avg": 390.0,
            "mouse_curvature_entropy": 0.44,
            "click_frequency": 1.0,
            "scroll_speed_avg": 300.0,
            "idle_duration_sec": 1.5,
            "navigation_entropy": 0.35,
            "context_signals": {"is_new_device": False},
            "sequence_number": seq,
            "telemetry_nonce": f"nonce_prog_{seq}_{time.time_ns()}"
        }
        res = client.post("/api/behavior/events", headers=headers, json=event)
        assert res.status_code == 200

    db_session.refresh(profile)
    assert profile.sample_count == 4
    status_4, conf_4, is_mat_4 = ProfileService.get_maturity_info(profile.sample_count)
    assert status_4 == "LEARNING"
    assert conf_4 == 0.8
    assert not is_mat_4

    # Ingest 5th legitimate sample: ESTABLISHED
    event_5 = {
        "session_id": session_id,
        "application": "ecommerce",
        "typing_speed_wpm": 70.0,
        "avg_flight_time_ms": 116.0,
        "avg_dwell_time_ms": 85.0,
        "mouse_velocity_avg": 630.0,
        "mouse_acceleration_avg": 395.0,
        "mouse_curvature_entropy": 0.45,
        "click_frequency": 1.1,
        "scroll_speed_avg": 310.0,
        "idle_duration_sec": 1.4,
        "navigation_entropy": 0.36,
        "context_signals": {"is_new_device": False},
        "sequence_number": 5,
        "telemetry_nonce": f"nonce_prog_5_{time.time_ns()}"
    }
    client.post("/api/behavior/events", headers=headers, json=event_5)

    db_session.refresh(profile)
    assert profile.sample_count == 5
    status_5, conf_5, is_mat_5 = ProfileService.get_maturity_info(profile.sample_count)
    assert status_5 == "ESTABLISHED"
    assert conf_5 == 1.0
    assert is_mat_5


def test_cross_user_profile_isolation(client: TestClient, db_session):
    """
    Task 3: Verifies that User A cannot submit telemetry for User B's session,
    and User A's observations never modify User B's baseline profile.
    """
    # Create User A and User B
    email_a = f"user.a.{time.time_ns()}@cognisec.ai"
    email_b = f"user.b.{time.time_ns()}@cognisec.ai"
    client.post("/api/auth/register", json={"name": "User A", "email": email_a, "password": "Password@123"})
    client.post("/api/auth/register", json={"name": "User B", "email": email_b, "password": "Password@123"})

    login_a = client.post("/api/auth/login", json={"email": email_a, "password": "Password@123", "application": "college"})
    login_b = client.post("/api/auth/login", json={"email": email_b, "password": "Password@123", "application": "college"})

    token_a = login_a.json()["access_token"]
    user_b_id = login_b.json()["user_id"]
    session_b_id = login_b.json()["session_id"]

    # User A tries to submit telemetry using User B's session_id -> HTTP 403 Forbidden
    res = client.post("/api/behavior/events", headers={"Authorization": f"Bearer {token_a}"}, json={
        "session_id": session_b_id,
        "application": "college",
        "typing_speed_wpm": 75.0,
        "sequence_number": 1,
        "telemetry_nonce": f"nonce_cross_{time.time_ns()}"
    })
    assert res.status_code == 403
    assert "another user's session" in res.json()["detail"].lower()

    # User B's profile must remain completely untouched
    profile_b = db_session.query(BehaviorProfile).filter(BehaviorProfile.user_id == user_b_id).first()
    assert profile_b is None


def test_suspicious_behavior_does_not_poison_baseline(client: TestClient, db_session):
    """
    Task 3: Verifies that attacker/suspicious behavior (risk >= 0.30, abnormal deviations)
    is strictly blocked from updating the baseline or entering the ML training buffer.
    """
    unique_email = f"poison.guard.{time.time_ns()}@cognisec.ai"
    client.post("/api/auth/register", json={"name": "Poison Guard", "email": unique_email, "password": "Password@123"})
    login_res = client.post("/api/auth/login", json={"email": unique_email, "password": "Password@123", "application": "college"})
    login_json = login_res.json()
    token = login_json["access_token"]
    session_id = login_json["session_id"]
    user_id = login_json["user_id"]
    SessionService.activate_session_after_login_otp(db_session, session_id)
    headers = {"Authorization": f"Bearer {token}"}

    # Ingest 5 normal samples to establish baseline
    for seq in range(1, 6):
        client.post("/api/behavior/events", headers=headers, json={
            "session_id": session_id,
            "application": "college",
            "typing_speed_wpm": 68.0,
            "avg_flight_time_ms": 118.0,
            "avg_dwell_time_ms": 84.0,
            "mouse_velocity_avg": 620.0,
            "mouse_acceleration_avg": 390.0,
            "mouse_curvature_entropy": 0.44,
            "click_frequency": 1.0,
            "scroll_speed_avg": 300.0,
            "idle_duration_sec": 1.5,
            "navigation_entropy": 0.35,
            "context_signals": {"is_new_device": False},
            "sequence_number": seq,
            "telemetry_nonce": f"nonce_pg_{seq}_{time.time_ns()}"
        })

    profile = ProfileService.get_or_create_profile(db_session, user_id)
    assert profile.sample_count == 5

    # Submit an abnormal bot-attack payload with impossible travel context signal
    attack_res = client.post("/api/behavior/events", headers=headers, json={
        "session_id": session_id,
        "application": "college",
        "typing_speed_wpm": 240.0,
        "avg_flight_time_ms": 15.0,
        "avg_dwell_time_ms": 15.0,
        "mouse_velocity_avg": 3200.0,
        "mouse_acceleration_avg": 4500.0,
        "mouse_curvature_entropy": 0.05,
        "click_frequency": 22.0,
        "scroll_speed_avg": 2500.0,
        "idle_duration_sec": 0.0,
        "navigation_entropy": 0.05,
        "context_signals": {"impossible_travel": True, "request_flood": True},
        "sequence_number": 6,
        "telemetry_nonce": f"nonce_pg_attack_{time.time_ns()}"
    })
    assert attack_res.status_code == 200
    attack_data = attack_res.json()
    assert attack_data["decision"] in ["RESTRICT", "TERMINATE_SESSION", "STEP_UP_VERIFICATION"]

    # Verify baseline sample_count DID NOT INCREMENT (remains 5)
    db_session.refresh(profile)
    assert profile.sample_count == 5


def test_model_hydration_from_database_after_restart(client: TestClient, db_session):
    """
    Task 4 & 6: Verifies that clearing ModelManager in-memory registry simulates
    a server restart, and ensure_hydrated correctly re-reads trusted BehaviorLogs
    from the database to restore the user's training dataset and model.
    """
    unique_email = f"hydrate.user.{time.time_ns()}@cognisec.ai"
    client.post("/api/auth/register", json={"name": "Hydrate User", "email": unique_email, "password": "Password@123"})
    login_res = client.post("/api/auth/login", json={"email": unique_email, "password": "Password@123", "application": "ecommerce"})
    login_json = login_res.json()
    token = login_json["access_token"]
    session_id = login_json["session_id"]
    user_id = login_json["user_id"]
    SessionService.activate_session_after_login_otp(db_session, session_id)
    headers = {"Authorization": f"Bearer {token}"}

    # Ingest 6 legitimate samples
    for seq in range(1, 7):
        client.post("/api/behavior/events", headers=headers, json={
            "session_id": session_id,
            "application": "ecommerce",
            "typing_speed_wpm": 69.0,
            "avg_flight_time_ms": 117.0,
            "avg_dwell_time_ms": 85.0,
            "mouse_velocity_avg": 630.0,
            "mouse_acceleration_avg": 395.0,
            "mouse_curvature_entropy": 0.45,
            "click_frequency": 1.0,
            "scroll_speed_avg": 310.0,
            "idle_duration_sec": 1.5,
            "navigation_entropy": 0.35,
            "context_signals": {"is_new_device": False},
            "sequence_number": seq,
            "telemetry_nonce": f"nonce_hyd_{seq}_{time.time_ns()}"
        })

    # Clear memory to simulate backend restart
    ModelManager.reset_memory()
    assert user_id not in ModelManager._instances
    assert user_id not in ModelManager._user_training_data

    # Hydrate from database
    profile = ProfileService.get_or_create_profile(db_session, user_id)
    baseline_stats = ProfileService.get_profile_dict(profile)
    detector = ModelManager.ensure_hydrated(db_session, user_id, baseline_stats)

    # Verify user training data was restored from BehaviorLog records in database
    assert user_id in ModelManager._user_training_data
    assert len(ModelManager._user_training_data[user_id]) == 6
    assert detector.trained_sample_count == 6


def test_end_to_end_attacker_detection_and_soc_alert_visibility(client: TestClient, admin_token, db_session):
    """
    Task 5: End-to-end user lifecycle test:
    1. User establishes legitimate baseline.
    2. Controlled abnormal attack behavior is submitted.
    3. Anomaly detection + context triggers RESTRICT.
    4. SecurityEvent and Alert are generated and verified in the database and SOC dashboard.
    """
    unique_email = f"attacker.target.{time.time_ns()}@cognisec.ai"
    client.post("/api/auth/register", json={"name": "Target User", "email": unique_email, "password": "Password@123"})
    login_res = client.post("/api/auth/login", json={"email": unique_email, "password": "Password@123", "application": "healthcare"})
    login_json = login_res.json()
    token = login_json["access_token"]
    session_id = login_json["session_id"]
    user_id = login_json["user_id"]
    SessionService.activate_session_after_login_otp(db_session, session_id)
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Establish legitimate baseline (5 samples)
    for seq in range(1, 6):
        client.post("/api/behavior/events", headers=headers, json={
            "session_id": session_id,
            "application": "healthcare",
            "typing_speed_wpm": 72.0,
            "avg_flight_time_ms": 115.0,
            "avg_dwell_time_ms": 85.0,
            "mouse_velocity_avg": 610.0,
            "mouse_acceleration_avg": 380.0,
            "mouse_curvature_entropy": 0.44,
            "click_frequency": 1.0,
            "scroll_speed_avg": 300.0,
            "idle_duration_sec": 1.5,
            "navigation_entropy": 0.35,
            "context_signals": {"is_new_device": False},
            "sequence_number": seq,
            "telemetry_nonce": f"nonce_att_legit_{seq}_{time.time_ns()}"
        })

    # 2. Submit high-risk robotic attacker burst
    attack_res = client.post("/api/behavior/events", headers=headers, json={
        "session_id": session_id,
        "application": "healthcare",
        "typing_speed_wpm": 250.0,
        "avg_flight_time_ms": 12.0,
        "avg_dwell_time_ms": 10.0,
        "mouse_velocity_avg": 3400.0,
        "mouse_acceleration_avg": 4800.0,
        "mouse_curvature_entropy": 0.01,
        "click_frequency": 25.0,
        "scroll_speed_avg": 3000.0,
        "idle_duration_sec": 0.0,
        "navigation_entropy": 0.01,
        "context_signals": {"request_flood": True, "rapid_click_burst": True},
        "sequence_number": 6,
        "telemetry_nonce": f"nonce_att_burst_{time.time_ns()}"
    })
    assert attack_res.status_code == 200
    attack_data = attack_res.json()
    assert attack_data["decision"] in ["RESTRICT", "TERMINATE_SESSION"]
    assert attack_data["session_status"] in ["RESTRICTED", "TERMINATED"]

    # 3. Verify security event was recorded in database
    sec_event = db_session.query(SecurityEvent).filter(
        SecurityEvent.user_id == user_id,
        SecurityEvent.session_id == session_id
    ).order_by(SecurityEvent.timestamp.desc()).first()
    assert sec_event is not None
    assert sec_event.decision in ["RESTRICT", "TERMINATE_SESSION"]
    assert sec_event.severity in ["HIGH", "CRITICAL"]

    # 4. Verify SOC Alert was created
    alert = db_session.query(Alert).filter(Alert.security_event_id == sec_event.id).first()
    assert alert is not None
    assert alert.status == "OPEN"

    # 5. Verify SOC admin API (/api/admin/events and /api/admin/alerts) sees this incident
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    admin_events_res = client.get("/api/admin/events?limit=10", headers=admin_headers)
    assert admin_events_res.status_code == 200
    events_list = admin_events_res.json()
    assert any(ev["session_id"] == session_id for ev in events_list)

    admin_alerts_res = client.get("/api/admin/alerts", headers=admin_headers)
    assert admin_alerts_res.status_code == 200
    alerts_list = admin_alerts_res.json()
    assert any(al["id"] == alert.id for al in alerts_list)


def test_step_up_challenge_and_verification_restores_active_session(client: TestClient, db_session):
    """
    Task 5: Verifies that when a session enters STEP_UP_REQUIRED,
    the user must complete OTP verification, which restores ACTIVE status.
    """
    unique_email = f"stepup.recovery.{time.time_ns()}@cognisec.ai"
    client.post("/api/auth/register", json={"name": "StepUp User", "email": unique_email, "password": "Password@123"})
    login_res = client.post("/api/auth/login", json={"email": unique_email, "password": "Password@123", "application": "college"})
    token = login_res.json()["access_token"]
    session_id = login_res.json()["session_id"]
    SessionService.activate_session_after_login_otp(db_session, session_id)
    headers = {"Authorization": f"Bearer {token}"}

    # Manually simulate medium risk decision setting session to STEP_UP_REQUIRED
    sess = db_session.query(DbSession).filter(DbSession.id == session_id).first()
    sess.status = "STEP_UP_REQUIRED"
    db_session.commit()

    # Request step-up challenge
    chal_res = client.post("/api/security/step-up/challenge", headers=headers, json={"session_id": session_id})
    assert chal_res.status_code == 200
    otp = chal_res.json()["otp"]
    assert len(otp) == 6

    # Verify challenge
    ver_res = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "challenge_code": otp
    })
    assert ver_res.status_code == 200
    assert ver_res.json()["decision"] == "ALLOW"
    assert ver_res.json()["session_status"] == "ACTIVE"

    # Confirm session status is back to ACTIVE in database
    db_session.refresh(sess)
    assert sess.status == "ACTIVE"


def test_kill_switch_terminates_session_and_blocks_subsequent_requests(client: TestClient, db_session):
    """
    Task 5: Verifies that when a session is TERMINATED, subsequent requests
    bearing that session's token are rejected with 401 Unauthorized.
    """
    unique_email = f"killswitch.user.{time.time_ns()}@cognisec.ai"
    client.post("/api/auth/register", json={"name": "KillSwitch User", "email": unique_email, "password": "Password@123"})
    login_res = client.post("/api/auth/login", json={"email": unique_email, "password": "Password@123", "application": "ecommerce"})
    token = login_res.json()["access_token"]
    session_id = login_res.json()["session_id"]
    SessionService.activate_session_after_login_otp(db_session, session_id)
    headers = {"Authorization": f"Bearer {token}"}

    # Verify user can access profile while active
    prof_res = client.get("/api/users/profile", headers=headers)
    assert prof_res.status_code == 200

    # Terminate the session (Zero Trust Kill Switch)
    term_res = client.post(f"/api/sessions/{session_id}/terminate", headers=headers)
    assert term_res.status_code == 200
    assert term_res.json()["status"] == "TERMINATED"

    # Subsequent request using that session token must be immediately rejected with 401
    blocked_res = client.get("/api/users/profile", headers=headers)
    assert blocked_res.status_code == 401
    assert "terminated or expired" in blocked_res.json()["detail"].lower()


def test_replayed_and_invalid_telemetry_rejected(client: TestClient, db_session):
    """
    Task 2: Verifies that replayed sequence numbers or duplicate nonces are rejected.
    """
    unique_email = f"replay.test.{time.time_ns()}@cognisec.ai"
    client.post("/api/auth/register", json={"name": "Replay User", "email": unique_email, "password": "Password@123"})
    login_res = client.post("/api/auth/login", json={"email": unique_email, "password": "Password@123", "application": "college"})
    token = login_res.json()["access_token"]
    session_id = login_res.json()["session_id"]
    SessionService.activate_session_after_login_otp(db_session, session_id)
    headers = {"Authorization": f"Bearer {token}"}

    nonce = f"nonce_unique_{time.time_ns()}"
    event_1 = {
        "session_id": session_id,
        "application": "college",
        "sequence_number": 10,
        "telemetry_nonce": nonce,
        "typing_speed_wpm": 65.0
    }
    res1 = client.post("/api/behavior/events", headers=headers, json=event_1)
    assert res1.status_code == 200

    # Replay identical sequence number -> 400 Bad Request
    res_replay = client.post("/api/behavior/events", headers=headers, json={
        "session_id": session_id,
        "application": "college",
        "sequence_number": 10,
        "telemetry_nonce": f"nonce_another_{time.time_ns()}",
        "typing_speed_wpm": 65.0
    })
    assert res_replay.status_code == 400
    assert "replay detected" in res_replay.json()["detail"].lower()

