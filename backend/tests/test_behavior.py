from app.models.behavior import BehaviorLog


def test_start_application_session(client, user_token):
    res = client.post("/api/sessions/start", headers={"Authorization": f"Bearer {user_token}"}, json={
        "application": "college",
        "device_fingerprint": "fp_test_device_1",
        "browser": "Chrome 128",
        "os": "macOS Sonoma"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["application"] == "college"
    assert data["status"] == "ACTIVE"
    assert data["id"].startswith("sess_")


def test_submit_behavioral_telemetry(client, user_token):
    # 1. Start a session
    sess_res = client.post("/api/sessions/start", headers={"Authorization": f"Bearer {user_token}"}, json={
        "application": "ecommerce",
        "device_fingerprint": "fp_test_device_1"
    })
    session_id = sess_res.json()["id"]

    # 2. Submit normal behavioral event
    res = client.post("/api/behavior/events", headers={"Authorization": f"Bearer {user_token}"}, json={
        "session_id": session_id,
        "application": "ecommerce",
        "typing_speed_wpm": 68.0,
        "avg_flight_time_ms": 115.0,
        "avg_dwell_time_ms": 85.0,
        "mouse_velocity_avg": 650.0,
        "mouse_acceleration_avg": 400.0,
        "mouse_curvature_entropy": 0.45,
        "click_frequency": 1.2,
        "scroll_speed_avg": 350.0,
        "idle_duration_sec": 2.0,
        "navigation_entropy": 0.35,
        "context_signals": {"is_new_device": False}
    })

    assert res.status_code == 200
    data = res.json()
    assert data["decision"] in ["ALLOW", "STEP_UP_VERIFICATION"]
    assert "user_message" in data
    assert data["session_status"] == "ACTIVE"
    assert 0.0 <= data["risk_score"] <= 1.0


def test_get_behavior_profile(client, user_token):
    res = client.get("/api/behavior/profile", headers={"Authorization": f"Bearer {user_token}"})
    assert res.status_code == 200
    data = res.json()
    assert "sample_count" in data
    assert "baseline_features" in data
    assert "maturity_confidence" in data
    assert "is_mature" in data
    assert data["baseline_status"] in ["COLD_START", "LEARNING", "ESTABLISHED"]


def test_baseline_creation_and_incremental_update(client, user_token):
    # Retrieve current baseline
    before_res = client.get("/api/behavior/profile", headers={"Authorization": f"Bearer {user_token}"})
    assert before_res.status_code == 200
    before_count = before_res.json()["sample_count"]

    # Start session
    sess_res = client.post("/api/sessions/start", headers={"Authorization": f"Bearer {user_token}"}, json={
        "application": "college",
        "device_fingerprint": "fp_test_device_1"
    })
    session_id = sess_res.json()["id"]

    # Send legitimate telemetry event (Risk < 0.30, Decision == ALLOW)
    event_res = client.post("/api/behavior/events", headers={"Authorization": f"Bearer {user_token}"}, json={
        "session_id": session_id,
        "application": "college",
        "typing_speed_wpm": 70.0,
        "avg_flight_time_ms": 112.0,
        "avg_dwell_time_ms": 83.0,
        "mouse_velocity_avg": 640.0,
        "mouse_acceleration_avg": 395.0,
        "mouse_curvature_entropy": 0.46,
        "click_frequency": 1.1,
        "scroll_speed_avg": 320.0,
        "idle_duration_sec": 1.5,
        "navigation_entropy": 0.36,
        "context_signals": {"is_new_device": False}
    })
    assert event_res.status_code == 200
    assert event_res.json()["decision"] == "ALLOW"

    # Verify baseline updated incrementally
    after_res = client.get("/api/behavior/profile", headers={"Authorization": f"Bearer {user_token}"})
    assert after_res.status_code == 200
    after_data = after_res.json()
    assert after_data["sample_count"] == before_count + 1
    assert "means" in after_data["baseline_features"]
    assert "stds" in after_data["baseline_features"]
    assert "typing_speed_wpm" in after_data["baseline_features"]["means"]


def test_baseline_not_contaminated_by_suspicious_behavior(client, user_token):
    # Retrieve current baseline sample count
    init_prof = client.get("/api/behavior/profile", headers={"Authorization": f"Bearer {user_token}"}).json()
    initial_sample_count = init_prof["sample_count"]

    # Start a session
    sess_res = client.post("/api/sessions/start", headers={"Authorization": f"Bearer {user_token}"}, json={
        "application": "ecommerce",
        "device_fingerprint": "fp_attacker_device"
    })
    session_id = sess_res.json()["id"]

    # Submit extreme/suspicious event with impossible travel & bot bursts (Risk > 0.65)
    res = client.post("/api/behavior/events", headers={"Authorization": f"Bearer {user_token}"}, json={
        "session_id": session_id,
        "application": "ecommerce",
        "typing_speed_wpm": 240.0,
        "avg_flight_time_ms": 8.0,
        "avg_dwell_time_ms": 10.0,
        "mouse_velocity_avg": 3200.0,
        "mouse_acceleration_avg": 4500.0,
        "mouse_curvature_entropy": 0.01,
        "click_frequency": 25.0,
        "scroll_speed_avg": 2000.0,
        "idle_duration_sec": 0.0,
        "navigation_entropy": 0.05,
        "context_signals": {
            "is_new_device": True,
            "impossible_travel": True,
            "request_flood": True
        }
    })

    assert res.status_code == 200
    event_data = res.json()
    assert event_data["decision"] in ["RESTRICT", "TERMINATE_SESSION", "STEP_UP_VERIFICATION"]
    assert event_data["risk_score"] >= 0.30

    # Verify baseline sample count DID NOT INCREASE (baseline protection enforced)
    after_prof = client.get("/api/behavior/profile", headers={"Authorization": f"Bearer {user_token}"}).json()
    assert after_prof["sample_count"] == initial_sample_count


def test_restricted_session_does_not_update_baseline(client, user_token, db_session):
    # Retrieve current baseline sample count
    init_prof = client.get("/api/behavior/profile", headers={"Authorization": f"Bearer {user_token}"}).json()
    initial_sample_count = init_prof["sample_count"]

    # Start a session and explicitly mark as RESTRICTED
    sess_res = client.post("/api/sessions/start", headers={"Authorization": f"Bearer {user_token}"}, json={
        "application": "healthcare",
        "device_fingerprint": "fp_test_device_1"
    })
    session_id = sess_res.json()["id"]
    
    from app.services.session_service import SessionService
    SessionService.update_session_status(db_session, session_id, status="RESTRICTED")

    # Send behavior event
    res = client.post("/api/behavior/events", headers={"Authorization": f"Bearer {user_token}"}, json={
        "session_id": session_id,
        "application": "healthcare",
        "typing_speed_wpm": 68.0,
        "avg_flight_time_ms": 115.0,
        "avg_dwell_time_ms": 85.0
    })
    assert res.status_code == 200

    # Baseline must NOT be updated
    after_prof = client.get("/api/behavior/profile", headers={"Authorization": f"Bearer {user_token}"}).json()
    assert after_prof["sample_count"] == initial_sample_count


def test_terminated_session_does_not_update_baseline(client, user_token):
    # Start and terminate session
    sess_res = client.post("/api/sessions/start", headers={"Authorization": f"Bearer {user_token}"}, json={
        "application": "ecommerce",
        "device_fingerprint": "fp_test_device_1"
    })
    session_id = sess_res.json()["id"]
    
    term_res = client.post(f"/api/sessions/{session_id}/terminate", headers={"Authorization": f"Bearer {user_token}"})
    assert term_res.status_code == 200

    # Ingest event on terminated session -> Should be rejected with 400 Bad Request
    res = client.post("/api/behavior/events", headers={"Authorization": f"Bearer {user_token}"}, json={
        "session_id": session_id,
        "application": "ecommerce",
        "typing_speed_wpm": 68.0,
        "avg_flight_time_ms": 115.0
    })
    assert res.status_code == 400
    assert "Active session required" in res.json()["detail"]


def test_passwords_and_raw_text_never_stored(client, user_token, db_session):
    # Start session and send event
    sess_res = client.post("/api/sessions/start", headers={"Authorization": f"Bearer {user_token}"}, json={
        "application": "college",
        "device_fingerprint": "fp_test_device_1"
    })
    session_id = sess_res.json()["id"]

    client.post("/api/behavior/events", headers={"Authorization": f"Bearer {user_token}"}, json={
        "session_id": session_id,
        "application": "college",
        "typing_speed_wpm": 65.0,
        "avg_flight_time_ms": 120.0,
        "avg_dwell_time_ms": 85.0
    })

    # Query all BehaviorLog records directly from database
    logs = db_session.query(BehaviorLog).all()
    assert len(logs) > 0

    for log in logs:
        # Verify no password or character fields exist
        assert hasattr(log, "typing_speed_wpm")
        assert hasattr(log, "avg_flight_time_ms")
        assert not hasattr(log, "password")
        assert not hasattr(log, "keystroke_characters")
        assert not hasattr(log, "raw_text")
        
        # Verify JSON context does not contain credentials
        if log.raw_feature_json:
            assert "password" not in log.raw_feature_json.lower()
            assert "secret" not in log.raw_feature_json.lower()


def test_admin_inspect_user_behavior_profile(client, admin_token, user_token):
    # Get user profile as admin
    user_me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {user_token}"}).json()
    user_id = user_me["id"]

    res = client.get(f"/api/admin/users/{user_id}/profile", headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["user_id"] == user_id
    assert "sample_count" in data
    assert "baseline_features" in data
    assert "maturity_confidence" in data
    assert "is_mature" in data
