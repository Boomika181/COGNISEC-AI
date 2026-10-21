import pytest
import numpy as np
from app.ml.anomaly_detector import IsolationForestDetector
from app.ml.model_manager import ModelManager
from app.models.behavior import BehaviorLog
from app.models.session import Session as DbSessionModel


def test_ml_cold_start_lifecycle():
    detector = IsolationForestDetector(contamination=0.05, random_state=42)
    sample_vec = np.array([68.0, 118.0, 88.0, 650.0, 410.0, 0.45, 1.2, 350.0, 2.0, 0.38])
    
    # 0 samples -> ML_COLD_START
    is_ano, score, status = detector.predict_anomaly(sample_vec, None, sample_count=0)
    assert status == "ML_COLD_START"
    assert not is_ano
    assert score <= 0.10


def test_ml_learning_state_before_five_samples():
    detector = IsolationForestDetector(contamination=0.05, random_state=42)
    baseline_stats = {
        "means": {"typing_speed_wpm": 68.0, "avg_flight_time_ms": 118.0, "avg_dwell_time_ms": 88.0},
        "stds": {"typing_speed_wpm": 6.0, "avg_flight_time_ms": 12.0, "avg_dwell_time_ms": 8.0}
    }
    sample_vec = np.array([70.0, 115.0, 90.0, 640.0, 400.0, 0.46, 1.3, 360.0, 1.8, 0.37])
    
    # 1 to 4 samples -> ML_LEARNING
    is_ano, score, status = detector.predict_anomaly(sample_vec, baseline_stats, sample_count=3)
    assert status == "ML_LEARNING"
    assert not is_ano
    assert score <= 0.40


def test_ml_training_at_five_samples_and_ml_ready():
    detector = IsolationForestDetector(contamination=0.05, random_state=42, min_samples_for_training=5)
    
    # 5 consistent trusted samples
    trusted_training_vectors = np.array([
        [68.0, 118.0, 88.0, 650.0, 410.0, 0.45, 1.2, 350.0, 2.0, 0.38],
        [70.0, 115.0, 86.0, 660.0, 405.0, 0.46, 1.3, 360.0, 1.9, 0.37],
        [67.0, 120.0, 89.0, 640.0, 415.0, 0.44, 1.1, 340.0, 2.1, 0.39],
        [69.0, 117.0, 87.0, 655.0, 408.0, 0.45, 1.2, 355.0, 2.0, 0.38],
        [71.0, 114.0, 85.0, 665.0, 402.0, 0.47, 1.4, 365.0, 1.8, 0.36],
    ])
    
    baseline_stats = {
        "means": {
            "typing_speed_wpm": 69.0, "avg_flight_time_ms": 116.8, "avg_dwell_time_ms": 87.0,
            "mouse_velocity_avg": 654.0, "mouse_acceleration_avg": 408.0, "mouse_curvature_entropy": 0.454,
            "click_frequency": 1.24, "scroll_speed_avg": 354.0, "idle_duration_sec": 1.96, "navigation_entropy": 0.376
        },
        "stds": {
            "typing_speed_wpm": 1.5, "avg_flight_time_ms": 2.2, "avg_dwell_time_ms": 1.5,
            "mouse_velocity_avg": 9.6, "mouse_acceleration_avg": 5.0, "mouse_curvature_entropy": 0.01,
            "click_frequency": 0.1, "scroll_speed_avg": 9.6, "idle_duration_sec": 0.1, "navigation_entropy": 0.01
        }
    }
    
    detector.fit(trusted_training_vectors, baseline_stats)
    assert detector.is_fitted
    assert detector.trained_sample_count == 5

    # 1. Normal in-distribution behavioral sample -> Low anomaly score
    normal_sample = np.array([69.5, 116.0, 86.5, 658.0, 406.0, 0.458, 1.25, 358.0, 1.95, 0.375])
    is_ano, norm_score, status = detector.predict_anomaly(normal_sample, baseline_stats, sample_count=5)
    assert status == "ML_READY"
    assert not is_ano
    assert norm_score < 0.40

    # 2. Extreme anomalous behavioral sample (e.g. robotic bot burst) -> High anomaly score
    abnormal_sample = np.array([220.0, 10.0, 12.0, 3400.0, 4800.0, 0.01, 22.0, 2800.0, 0.0, 0.02])
    is_ano_ab, ab_score, status_ab = detector.predict_anomaly(abnormal_sample, baseline_stats, sample_count=5)
    assert status_ab == "ML_READY"
    assert is_ano_ab
    assert ab_score > 0.65
    assert ab_score > norm_score


def test_end_to_end_ml_integration_and_anti_poisoning(client, user_token):
    # 1. Start a session
    sess_res = client.post("/api/sessions/start", headers={"Authorization": f"Bearer {user_token}"}, json={
        "application": "ecommerce",
        "device_fingerprint": "fp_ml_test_device"
    })
    session_id = sess_res.json()["id"]

    # 2. Ingest 5 consistent legitimate behavioral events to train user model
    for i in range(5):
        legit_res = client.post("/api/behavior/events", headers={"Authorization": f"Bearer {user_token}"}, json={
            "session_id": session_id,
            "application": "ecommerce",
            "typing_speed_wpm": 68.0 + (i * 0.5),
            "avg_flight_time_ms": 118.0 - (i * 0.5),
            "avg_dwell_time_ms": 86.0,
            "mouse_velocity_avg": 650.0 + (i * 2.0),
            "mouse_acceleration_avg": 405.0,
            "mouse_curvature_entropy": 0.45,
            "click_frequency": 1.2,
            "scroll_speed_avg": 350.0,
            "idle_duration_sec": 2.0,
            "navigation_entropy": 0.38,
            "context_signals": {"is_new_device": False}
        })
        assert legit_res.status_code == 200
        assert legit_res.json()["decision"] == "ALLOW"

    # Verify Profile reaches ML_READY
    prof = client.get("/api/behavior/profile", headers={"Authorization": f"Bearer {user_token}"}).json()
    assert prof["sample_count"] >= 5
    assert prof["is_mature"] is True
    assert prof["ml_status"] == "ML_READY"
    model_samples_before = prof["model_sample_count"]

    # 3. Submit abnormal behavioral attack -> must trigger elevated risk and NOT train model
    attack_res = client.post("/api/behavior/events", headers={"Authorization": f"Bearer {user_token}"}, json={
        "session_id": session_id,
        "application": "ecommerce",
        "typing_speed_wpm": 230.0,
        "avg_flight_time_ms": 9.0,
        "avg_dwell_time_ms": 12.0,
        "mouse_velocity_avg": 3200.0,
        "mouse_acceleration_avg": 4500.0,
        "mouse_curvature_entropy": 0.01,
        "click_frequency": 24.0,
        "scroll_speed_avg": 2200.0,
        "idle_duration_sec": 0.0,
        "navigation_entropy": 0.05,
        "context_signals": {
            "is_new_device": True,
            "request_flood": True
        }
    })
    assert attack_res.status_code == 200
    attack_data = attack_res.json()
    assert attack_data["decision"] in ["STEP_UP_VERIFICATION", "RESTRICT", "TERMINATE_SESSION"]
    assert "anomaly_score" not in attack_data
    assert "risk_score" not in attack_data
    assert "ml_status" not in attack_data


    # 4. Anti-Poisoning Verification: Model sample count did not increase from the attack
    prof_after = client.get("/api/behavior/profile", headers={"Authorization": f"Bearer {user_token}"}).json()
    assert prof_after["model_sample_count"] == model_samples_before


def test_model_hydration_from_database_after_restart(client, user_token):
    # 1. Establish 5 trusted events in database
    sess_res = client.post("/api/sessions/start", headers={"Authorization": f"Bearer {user_token}"}, json={
        "application": "college",
        "device_fingerprint": "fp_hydrated_test"
    })
    session_id = sess_res.json()["id"]

    for i in range(5):
        client.post("/api/behavior/events", headers={"Authorization": f"Bearer {user_token}"}, json={
            "session_id": session_id,
            "application": "college",
            "typing_speed_wpm": 68.0 + (i * 0.4),
            "avg_flight_time_ms": 118.0 - (i * 0.4),
            "avg_dwell_time_ms": 86.0,
            "mouse_velocity_avg": 650.0 + (i * 2.0),
            "mouse_acceleration_avg": 405.0,
            "mouse_curvature_entropy": 0.45,
            "click_frequency": 1.2,
            "scroll_speed_avg": 350.0,
            "idle_duration_sec": 2.0,
            "navigation_entropy": 0.38,
            "context_signals": {"is_new_device": False}
        })

    # 2. Clear in-memory ModelManager to simulate process restart / cold-start
    ModelManager.reset_memory()

    # 3. Get profile -> triggers on-demand DB hydration and immediately returns ML_READY
    prof_res = client.get("/api/behavior/profile", headers={"Authorization": f"Bearer {user_token}"})
    assert prof_res.status_code == 200
    prof = prof_res.json()
    assert prof["ml_status"] == "ML_READY"
    assert prof["model_sample_count"] >= 5

    # 4. Evaluate event on hydrated model -> successfully runs without requiring 5 new live samples
    ev_res = client.post("/api/behavior/events", headers={"Authorization": f"Bearer {user_token}"}, json={
        "session_id": session_id,
        "application": "college",
        "typing_speed_wpm": 69.0,
        "avg_flight_time_ms": 117.0,
        "avg_dwell_time_ms": 86.0,
        "mouse_velocity_avg": 652.0,
        "mouse_acceleration_avg": 406.0,
        "mouse_curvature_entropy": 0.455,
        "click_frequency": 1.2,
        "scroll_speed_avg": 352.0,
        "idle_duration_sec": 1.9,
        "navigation_entropy": 0.38,
        "context_signals": {"is_new_device": False}
    })
    assert ev_res.status_code == 200
    d = ev_res.json()
    assert d["decision"] == "ALLOW"
    assert "ml_status" not in d
    assert "anomaly_score" not in d
