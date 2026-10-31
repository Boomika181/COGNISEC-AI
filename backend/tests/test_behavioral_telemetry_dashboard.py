import uuid
import json
import pytest
from datetime import datetime, timezone
from app.models.session import Session as DbSession
from app.models.behavior import BehaviorLog, BehaviorProfile
from app.services.access_tracker import ConfidentialAccessTracker
from app.services.behavior_drift_service import BehavioralDriftTracker


@pytest.fixture(autouse=True)
def reset_trackers():
    """Ensure clean isolation between tests."""
    ConfidentialAccessTracker.reset_all()
    BehavioralDriftTracker.reset_all()
    yield
    ConfidentialAccessTracker.reset_all()
    BehavioralDriftTracker.reset_all()


def create_user(client, role="USER"):
    uid = uuid.uuid4().hex[:8]
    email = f"user_{uid}@cognisec.ai"
    res = client.post("/api/auth/register", json={
        "name": f"Test User {uid}",
        "email": email,
        "password": "Password123!",
        "role": role
    })
    assert res.status_code == 201
    return res.json(), email, "Password123!"


def create_authenticated_session(client, user_info, db_session, app_name="college"):
    user_data, email, password = user_info
    res = client.post("/api/auth/login", json={
        "email": email,
        "password": password,
        "application": app_name,
        "device_fingerprint": f"dev_{user_data['id']}"
    })
    assert res.status_code == 200
    data = res.json()
    token = data["access_token"]
    session_id = data["session_id"]

    db_s = db_session.query(DbSession).filter(DbSession.id == session_id).first()
    db_s.status = "ACTIVE"
    db_session.commit()

    return {
        "user_id": user_data["id"],
        "email": email,
        "token": token,
        "session_id": session_id,
        "headers": {"Authorization": f"Bearer {token}"}
    }


def test_1_authenticated_user_can_view_own_profile_and_telemetry(client, db_session):
    """
    Requirement 2 & 10: Authenticated user can view their own profile and telemetry.
    Returns enrollment_status, total_observations, last_observation_timestamp, and baseline statistics.
    """
    user_info = create_user(client)
    auth = create_authenticated_session(client, user_info, db_session)

    res = client.get("/api/behavior/profile", headers=auth["headers"])
    assert res.status_code == 200
    profile = res.json()

    assert profile["user_id"] == auth["user_id"]
    assert "enrollment_status" in profile
    assert profile["enrollment_status"] == "NOT_ENROLLED"
    assert profile["sample_count"] == 0
    assert profile["total_observations"] == 0
    assert profile["last_observation_timestamp"] is None
    assert "baseline_features" in profile
    assert "maturity_confidence" in profile
    assert "anomaly_score" in profile

    # Logs should initially be empty
    logs_res = client.get("/api/behavior/logs", headers=auth["headers"])
    assert logs_res.status_code == 200
    assert logs_res.json() == []


def test_2_cross_user_isolation_prevent_telemetry_leak_and_bola(client, db_session):
    """
    Requirement 7 & 10: BOLA & Information Disclosure Protection:
    - User B cannot read User A's profile or logs
    - User B cannot submit telemetry against User A's session
    """
    user_a = create_user(client)
    auth_a = create_authenticated_session(client, user_a, db_session)

    user_b = create_user(client)
    auth_b = create_authenticated_session(client, user_b, db_session)

    # User A submits a telemetry event
    sample_event = {
        "session_id": auth_a["session_id"],
        "application": "college",
        "typing_speed_wpm": 62.0,
        "avg_flight_time_ms": 110.0,
        "avg_dwell_time_ms": 78.0,
        "mouse_velocity_avg": 250.0,
        "mouse_acceleration_avg": 320.0,
        "mouse_curvature_entropy": 1.25,
        "click_frequency": 0.5,
        "scroll_speed_avg": 40.0,
        "idle_duration_sec": 1.2,
        "navigation_entropy": 0.45,
        "timestamp": datetime.now(timezone.utc).timestamp(),
        "sequence_number": 1,
        "telemetry_nonce": "nonce_user_a_001"
    }
    submit_res = client.post("/api/behavior/events", headers=auth_a["headers"], json=sample_event)
    assert submit_res.status_code == 200

    # User A sees 1 observation
    a_profile = client.get("/api/behavior/profile", headers=auth_a["headers"]).json()
    assert a_profile["total_observations"] == 1

    a_logs = client.get("/api/behavior/logs", headers=auth_a["headers"]).json()
    assert len(a_logs) == 1
    assert a_logs[0]["user_id"] == auth_a["user_id"]

    # User B checks their own logs -> must be 0 (isolated from User A)
    b_logs = client.get("/api/behavior/logs", headers=auth_b["headers"]).json()
    assert len(b_logs) == 0

    # User B checks their profile -> must have 0 observations
    b_profile = client.get("/api/behavior/profile", headers=auth_b["headers"]).json()
    assert b_profile["total_observations"] == 0
    assert b_profile["user_id"] == auth_b["user_id"]

    # User B attempts to hijack and submit telemetry to User A's session -> must be rejected with 403 Forbidden
    hijack_event = dict(sample_event)
    hijack_event["sequence_number"] = 2
    hijack_event["telemetry_nonce"] = "nonce_hijack_001"
    hijack_res = client.post("/api/behavior/events", headers=auth_b["headers"], json=hijack_event)
    assert hijack_res.status_code == 403
    assert "Unauthorized" in hijack_res.json()["detail"]


def test_3_enrollment_status_lifecycle_reflects_actual_persisted_state(client, db_session):
    """
    Requirement 2, 5 & 10: Enrollment status reflects actual persisted sample counts:
    - 0 samples: NOT_ENROLLED
    - 1-4 samples: ENROLLMENT_IN_PROGRESS
    - 5+ samples: ENROLLED
    """
    user_info = create_user(client)
    auth = create_authenticated_session(client, user_info, db_session)

    # 1. Start: 0 samples
    prof = client.get("/api/behavior/profile", headers=auth["headers"]).json()
    assert prof["enrollment_status"] == "NOT_ENROLLED"
    assert prof["sample_count"] == 0

    # 2. Submit 1 trusted low-risk observation -> becomes ENROLLMENT_IN_PROGRESS
    for seq in range(1, 5):
        event = {
            "session_id": auth["session_id"],
            "application": "college",
            "typing_speed_wpm": 55.0,
            "avg_flight_time_ms": 115.0,
            "avg_dwell_time_ms": 80.0,
            "mouse_velocity_avg": 220.0,
            "mouse_acceleration_avg": 300.0,
            "mouse_curvature_entropy": 1.10,
            "click_frequency": 0.4,
            "scroll_speed_avg": 35.0,
            "idle_duration_sec": 1.0,
            "navigation_entropy": 0.30,
            "timestamp": datetime.now(timezone.utc).timestamp(),
            "sequence_number": seq,
            "telemetry_nonce": f"nonce_seq_{seq}"
        }
        res = client.post("/api/behavior/events", headers=auth["headers"], json=event)
        assert res.status_code == 200

        prof = client.get("/api/behavior/profile", headers=auth["headers"]).json()
        if seq < 5:
            assert prof["enrollment_status"] == "ENROLLMENT_IN_PROGRESS"
            assert prof["sample_count"] == seq

    # 3. Submit 5th trusted observation -> reaches minimum mature threshold (ENROLLED)
    event_5 = {
        "session_id": auth["session_id"],
        "application": "college",
        "typing_speed_wpm": 56.0,
        "avg_flight_time_ms": 114.0,
        "avg_dwell_time_ms": 81.0,
        "mouse_velocity_avg": 225.0,
        "mouse_acceleration_avg": 305.0,
        "mouse_curvature_entropy": 1.12,
        "click_frequency": 0.4,
        "scroll_speed_avg": 35.0,
        "idle_duration_sec": 0.9,
        "navigation_entropy": 0.32,
        "timestamp": datetime.now(timezone.utc).timestamp(),
        "sequence_number": 5,
        "telemetry_nonce": "nonce_seq_5"
    }
    res5 = client.post("/api/behavior/events", headers=auth["headers"], json=event_5)
    assert res5.status_code == 200

    prof5 = client.get("/api/behavior/profile", headers=auth["headers"]).json()
    assert prof5["enrollment_status"] == "ENROLLED"
    assert prof5["sample_count"] >= 5
    assert prof5["is_mature"] is True
    assert prof5["total_observations"] == 5


def test_4_observations_persist_and_reload_correctly(client, db_session):
    """
    Requirement 3, 7 & 10: Verified telemetry observations persist in the database
    and reload accurately with all 10 canonical features.
    """
    user_info = create_user(client)
    auth = create_authenticated_session(client, user_info, db_session)

    test_features = {
        "session_id": auth["session_id"],
        "application": "college",
        "typing_speed_wpm": 68.5,
        "avg_flight_time_ms": 95.2,
        "avg_dwell_time_ms": 72.4,
        "mouse_velocity_avg": 312.8,
        "mouse_acceleration_avg": 450.6,
        "mouse_curvature_entropy": 1.48,
        "click_frequency": 1.25,
        "scroll_speed_avg": 85.0,
        "idle_duration_sec": 2.5,
        "navigation_entropy": 0.88,
        "timestamp": datetime.now(timezone.utc).timestamp(),
        "sequence_number": 1,
        "telemetry_nonce": "nonce_persistence_01"
    }

    res = client.post("/api/behavior/events", headers=auth["headers"], json=test_features)
    assert res.status_code == 200

    # Retrieve logs directly from API
    logs_res = client.get("/api/behavior/logs?limit=5", headers=auth["headers"])
    assert logs_res.status_code == 200
    logs = logs_res.json()
    assert len(logs) == 1

    log = logs[0]
    assert log["typing_speed_wpm"] == 68.5
    assert log["avg_flight_time_ms"] == 95.2
    assert log["avg_dwell_time_ms"] == 72.4
    assert log["mouse_velocity_avg"] == 312.8
    assert log["mouse_acceleration_avg"] == 450.6
    assert log["mouse_curvature_entropy"] == 1.48
    assert log["click_frequency"] == 1.25
    assert log["scroll_speed_avg"] == 85.0
    assert log["idle_duration_sec"] == 2.5
    assert log["navigation_entropy"] == 0.88
    assert log["raw_feature_json"] is not None

    # Check database model directly
    db_log = db_session.query(BehaviorLog).filter(BehaviorLog.user_id == auth["user_id"]).first()
    assert db_log is not None
    assert db_log.typing_speed_wpm == 68.5


def test_5_sensitive_raw_input_and_secrets_never_stored_or_exposed(client, db_session):
    """
    Requirement 7 & 10: Privacy and Security Invariant:
    Never store or expose raw passwords, OTPs, private answers, or raw keystroke characters.
    """
    user_info = create_user(client)
    auth = create_authenticated_session(client, user_info, db_session)

    # Submit telemetry
    event = {
        "session_id": auth["session_id"],
        "application": "college",
        "typing_speed_wpm": 60.0,
        "avg_flight_time_ms": 100.0,
        "avg_dwell_time_ms": 75.0,
        "mouse_velocity_avg": 200.0,
        "mouse_acceleration_avg": 250.0,
        "mouse_curvature_entropy": 1.0,
        "click_frequency": 0.5,
        "scroll_speed_avg": 30.0,
        "idle_duration_sec": 1.0,
        "navigation_entropy": 0.2,
        "timestamp": datetime.now(timezone.utc).timestamp(),
        "sequence_number": 1,
        "telemetry_nonce": "nonce_privacy_01"
    }
    res = client.post("/api/behavior/events", headers=auth["headers"], json=event)
    assert res.status_code == 200

    # Query DB logs and profile
    logs = db_session.query(BehaviorLog).filter(BehaviorLog.user_id == auth["user_id"]).all()
    profiles = db_session.query(BehaviorProfile).filter(BehaviorProfile.user_id == auth["user_id"]).all()

    forbidden_terms = ["Password123!", "otp", "password", "keystroke", "character", "secret"]

    for l in logs:
        raw_json = l.raw_feature_json or ""
        for term in forbidden_terms:
            assert term not in raw_json.lower()

    for p in profiles:
        raw_base = p.baseline_features or ""
        for term in forbidden_terms:
            assert term not in raw_base.lower()


def test_6_baseline_poisoning_prevention_untrusted_observations_rejected(client, db_session):
    """
    Requirement 5 & 10: Strict Baseline Contamination Guard:
    Observations from non-ACTIVE sessions or high-risk evaluations must NOT increment sample_count.
    """
    user_info = create_user(client)
    auth = create_authenticated_session(client, user_info, db_session)

    # Submit 1 trusted sample
    event_1 = {
        "session_id": auth["session_id"],
        "application": "college",
        "typing_speed_wpm": 50.0,
        "avg_flight_time_ms": 120.0,
        "avg_dwell_time_ms": 85.0,
        "mouse_velocity_avg": 200.0,
        "mouse_acceleration_avg": 250.0,
        "mouse_curvature_entropy": 1.0,
        "click_frequency": 0.4,
        "scroll_speed_avg": 30.0,
        "idle_duration_sec": 1.0,
        "navigation_entropy": 0.2,
        "timestamp": datetime.now(timezone.utc).timestamp(),
        "sequence_number": 1,
        "telemetry_nonce": "nonce_poison_01"
    }
    client.post("/api/behavior/events", headers=auth["headers"], json=event_1)

    prof1 = client.get("/api/behavior/profile", headers=auth["headers"]).json()
    assert prof1["sample_count"] == 1

    # Now set session to RESTRICTED (untrusted state)
    db_s = db_session.query(DbSession).filter(DbSession.id == auth["session_id"]).first()
    db_s.status = "RESTRICTED"
    db_session.commit()

    event_2 = dict(event_1)
    event_2["sequence_number"] = 2
    event_2["telemetry_nonce"] = "nonce_poison_02"
    client.post("/api/behavior/events", headers=auth["headers"], json=event_2)

    # Sample count must STILL be 1 (untrusted event rejected from baseline)
    prof2 = client.get("/api/behavior/profile", headers=auth["headers"]).json()
    assert prof2["sample_count"] == 1
    # But total_observations in audit log increments to 2
    assert prof2["total_observations"] == 2
