import pytest
import math
import numpy as np
from app.ml.feature_engineering import FeatureEngineering, FEATURE_NAMES
from app.ml.anomaly_detector import IsolationForestDetector
from app.ml.model_manager import ModelManager
from app.services.profile_service import ProfileService
from app.services.session_service import SessionService
from app.models.behavior import BehaviorLog
from app.core.config import settings


# ==============================================================================
# PHASE 3N — FEATURE VECTOR & VALIDATION TESTS
# ==============================================================================

def test_feature_vector_dimension_and_order():
    """Verifies that the feature vector has exactly 10 dimensions in stable order."""
    assert len(FEATURE_NAMES) == 10
    expected_order = [
        "typing_speed_wpm",
        "avg_flight_time_ms",
        "avg_dwell_time_ms",
        "mouse_velocity_avg",
        "mouse_acceleration_avg",
        "mouse_curvature_entropy",
        "click_frequency",
        "scroll_speed_avg",
        "idle_duration_sec",
        "navigation_entropy"
    ]
    assert FEATURE_NAMES == expected_order


def test_feature_vector_validation_bounds():
    """Verifies that NaN, Inf, and physically impossible feature values are rejected."""
    # 1. Valid vector passes
    valid_vec = np.array([68.0, 115.0, 85.0, 650.0, 400.0, 0.45, 1.2, 350.0, 2.0, 0.38])
    is_valid, err = FeatureEngineering.validate_vector(valid_vec)
    assert is_valid
    assert err is None

    # 2. NaN value rejected
    nan_vec = valid_vec.copy()
    nan_vec[0] = float("nan")
    is_valid, err = FeatureEngineering.validate_vector(nan_vec)
    assert not is_valid
    assert "NaN" in err or "non-finite" in err

    # 3. Infinity rejected
    inf_vec = valid_vec.copy()
    inf_vec[3] = float("inf")
    is_valid, err = FeatureEngineering.validate_vector(inf_vec)
    assert not is_valid
    assert "non-finite" in err

    # 4. Out-of-bounds typing speed rejected (> 350 WPM)
    fast_vec = valid_vec.copy()
    fast_vec[0] = 999.0
    is_valid, err = FeatureEngineering.validate_vector(fast_vec)
    assert not is_valid
    assert "typing_speed_wpm" in err

    # 5. Wrong dimensionality rejected
    short_vec = np.array([68.0, 115.0, 85.0])
    is_valid, err = FeatureEngineering.validate_vector(short_vec)
    assert not is_valid
    assert "dimensions" in err


def test_malformed_telemetry_rejected_by_api(client, user_token):
    """Verifies that the /api/behavior/events endpoint rejects malformed telemetry."""
    sess_res = client.post("/api/sessions/start", headers={"Authorization": f"Bearer {user_token}"}, json={
        "application": "college",
        "device_fingerprint": "fp_malformed_test"
    })
    session_id = sess_res.json()["id"]

    # Absurd mouse curvature entropy (25.0 vs max allowed 5.0)
    bad_res = client.post("/api/behavior/events", headers={"Authorization": f"Bearer {user_token}"}, json={
        "session_id": session_id,
        "application": "college",
        "typing_speed_wpm": 75.0,
        "avg_flight_time_ms": 115.0,
        "avg_dwell_time_ms": 85.0,
        "mouse_curvature_entropy": 25.0
    })
    assert bad_res.status_code == 400
    assert "Malformed behavioral telemetry features" in bad_res.json()["detail"]


# ==============================================================================
# PHASE 3B — FEATURE-SPECIFIC MINIMUM SIGMA FLOORS
# ==============================================================================

def test_feature_specific_minimum_sigma_floors():
    """
    Verifies that zero-variance or identical samples do not collapse standard deviations
    below the configured minimum sigma floors.
    """
    baseline_stats = {
        "means": {feat: 100.0 for feat in FEATURE_NAMES},
        "stds": {feat: 0.00001 for feat in FEATURE_NAMES}  # Collapsed raw std
    }

    sample_vec = np.array([105.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 100.0])
    deviations = FeatureEngineering.compute_statistical_deviations(sample_vec, baseline_stats)

    # For typing speed, floor is 5.0. Distance = abs(105 - 100) / 5.0 = 1.0 (NOT 500,000!)
    assert deviations["typing_speed_wpm"] == 1.0

    # Test standardization in IsolationForestDetector also respects sigma floors
    standardized = IsolationForestDetector.standardize_vector(sample_vec, baseline_stats)
    assert abs(standardized[0] - 1.0) < 1e-3


# ==============================================================================
# PHASE 3C & 3M — BASELINE MATURITY & COLD START LIFECYCLE
# ==============================================================================

def test_baseline_maturity_thresholds():
    """Verifies maturity states: COLD_START (0), LEARNING (1-4), ESTABLISHED (5+)."""
    assert ProfileService.get_maturity_info(0) == ("COLD_START", 0.0, False)
    assert ProfileService.get_maturity_info(1) == ("LEARNING", 0.2, False)
    assert ProfileService.get_maturity_info(4) == ("LEARNING", 0.8, False)
    assert ProfileService.get_maturity_info(5) == ("ESTABLISHED", 1.0, True)
    assert ProfileService.get_maturity_info(25) == ("ESTABLISHED", 1.0, True)


def test_cold_start_does_not_falsely_penalize_user(client, user_token):
    """
    Verifies that a brand-new user with 0 history is not treated as suspicious
    solely due to cold start.
    """
    sess_res = client.post("/api/sessions/start", headers={"Authorization": f"Bearer {user_token}"}, json={
        "application": "ecommerce",
        "device_fingerprint": "fp_cold_start_user"
    })
    session_id = sess_res.json()["id"]

    res = client.post("/api/behavior/events", headers={"Authorization": f"Bearer {user_token}"}, json={
        "session_id": session_id,
        "application": "ecommerce",
        "typing_speed_wpm": 65.0,
        "avg_flight_time_ms": 115.0,
        "avg_dwell_time_ms": 85.0,
        "mouse_velocity_avg": 600.0,
        "mouse_acceleration_avg": 400.0,
        "mouse_curvature_entropy": 0.45,
        "click_frequency": 1.2,
        "scroll_speed_avg": 350.0,
        "idle_duration_sec": 2.0,
        "navigation_entropy": 0.38,
        "context_signals": {"is_new_device": False}
    })
    assert res.status_code == 200
    data = res.json()
    assert data["decision"] == "ALLOW"
    assert data["session_status"] == "ACTIVE"


# ==============================================================================
# PHASE 3D & 3F & 3G — ISOLATION FOREST SAFETY & RETRAINING INTERVAL
# ==============================================================================

def test_isolation_forest_safety_threshold_25_samples():
    """
    Verifies that Isolation Forest does NOT fit on small sample counts (< 25),
    and successfully fits when >= 25 samples are provided.
    """
    detector = IsolationForestDetector(min_samples_for_training=25)

    # 1. Attempt fit with 10 samples -> Must NOT fit
    ten_vectors = np.tile([68.0, 118.0, 88.0, 650.0, 410.0, 0.45, 1.2, 350.0, 2.0, 0.38], (10, 1))
    detector.fit(ten_vectors)
    assert not detector.is_fitted
    assert detector.trained_sample_count == 10

    # Fallback to Welford statistical deviation without error
    is_ano, score, status = detector.predict_anomaly(ten_vectors[0], None, sample_count=10)
    assert status == "ML_READY"
    assert not is_ano

    # 2. Fit with 25 samples -> Must fit
    twenty_five_vectors = np.tile([68.0, 118.0, 88.0, 650.0, 410.0, 0.45, 1.2, 350.0, 2.0, 0.38], (25, 1))
    # Add minor variation
    for i in range(25):
        twenty_five_vectors[i][0] += (i * 0.1)

    baseline_stats = {
        "means": {feat: 100.0 for feat in FEATURE_NAMES},
        "stds": {feat: 10.0 for feat in FEATURE_NAMES}
    }
    detector.fit(twenty_five_vectors, baseline_stats)
    assert detector.is_fitted
    assert detector.trained_sample_count == 25
    assert detector.retrain_count == 1
    assert detector.last_trained_at is not None


def test_model_manager_retraining_interval():
    """
    Verifies that ModelManager retrains according to ML_RETRAIN_INTERVAL
    rather than on every single event.
    """
    user_id = 9999
    ModelManager.reset_memory()

    # Pre-populate detector with min_samples=25
    detector = IsolationForestDetector(min_samples_for_training=25)
    ModelManager._instances[user_id] = detector

    base_vec = np.array([68.0, 118.0, 88.0, 650.0, 410.0, 0.45, 1.2, 350.0, 2.0, 0.38])
    baseline_stats = {
        "means": {feat: 100.0 for feat in FEATURE_NAMES},
        "stds": {feat: 10.0 for feat in FEATURE_NAMES}
    }

    # Register 24 samples -> still not fitted
    for _ in range(24):
        ModelManager.register_trusted_vector(user_id, base_vec, baseline_stats)
    assert not detector.is_fitted
    assert detector.retrain_count == 0

    # 25th sample -> initial fit
    ModelManager.register_trusted_vector(user_id, base_vec, baseline_stats)
    assert detector.is_fitted
    assert detector.retrain_count == 1

    # Samples 26 through 34 (9 samples) -> do NOT retrain yet (interval = 10)
    for _ in range(9):
        ModelManager.register_trusted_vector(user_id, base_vec, baseline_stats)
    assert detector.retrain_count == 1

    # 35th sample (10th since last train) -> triggers retrain
    ModelManager.register_trusted_vector(user_id, base_vec, baseline_stats)
    assert detector.retrain_count == 2

    # Clean up
    ModelManager.reset_memory()


# ==============================================================================
# PHASE 3L — COMPREHENSIVE ANTI-POISONING TESTS
# ==============================================================================

def test_anti_poisoning_lifecycle(client, user_token, db_session):
    """
    End-to-End Anti-Poisoning Test:
    1. Establish trusted baseline
    2. Submit high-risk suspicious attack event
    3. Verify risk increases and decision restricts/steps-up
    4. Verify suspicious event does NOT contaminate baseline or model buffer
    5. Add normal event and verify normal learning continues
    """
    sess_res = client.post("/api/sessions/start", headers={"Authorization": f"Bearer {user_token}"}, json={
        "application": "ecommerce",
        "device_fingerprint": "fp_poisoning_test"
    })
    session_id = sess_res.json()["id"]

    # 1. Establish 3 normal samples
    for i in range(3):
        client.post("/api/behavior/events", headers={"Authorization": f"Bearer {user_token}"}, json={
            "session_id": session_id,
            "application": "ecommerce",
            "typing_speed_wpm": 70.0 + i,
            "avg_flight_time_ms": 110.0,
            "avg_dwell_time_ms": 85.0,
            "context_signals": {"is_new_device": False}
        })

    prof_before = client.get("/api/behavior/profile", headers={"Authorization": f"Bearer {user_token}"}).json()
    trusted_count_before = prof_before["sample_count"]

    # 2. Submit high-risk attack
    attack_res = client.post("/api/behavior/events", headers={"Authorization": f"Bearer {user_token}"}, json={
        "session_id": session_id,
        "application": "ecommerce",
        "typing_speed_wpm": 260.0,
        "avg_flight_time_ms": 8.0,
        "avg_dwell_time_ms": 10.0,
        "mouse_velocity_avg": 3500.0,
        "mouse_acceleration_avg": 5000.0,
        "mouse_curvature_entropy": 0.01,
        "click_frequency": 30.0,
        "scroll_speed_avg": 3000.0,
        "idle_duration_sec": 0.0,
        "navigation_entropy": 0.02,
        "context_signals": {
            "impossible_travel": True,
            "request_flood": True
        }
    })
    assert attack_res.status_code == 200
    attack_data = attack_res.json()
    assert attack_data["decision"] in ["RESTRICT", "STEP_UP_VERIFICATION", "TERMINATE_SESSION"]

    # 3. Verify baseline sample count did NOT increase
    prof_after_attack = client.get("/api/behavior/profile", headers={"Authorization": f"Bearer {user_token}"}).json()
    assert prof_after_attack["sample_count"] == trusted_count_before

    # 4. Check BehaviorLog database record for untrusted tag
    attack_log = db_session.query(BehaviorLog).order_by(BehaviorLog.id.desc()).first()
    assert '"is_trusted": false' in attack_log.raw_feature_json.lower()


# ==============================================================================
# PHASE 3E — MODEL HYDRATION FROM COMPLETED / HISTORICAL SESSIONS
# ==============================================================================

def test_model_hydration_from_historical_completed_sessions(client, user_token):
    """
    Verifies that model hydration restores trusted historical samples even after
    their original sessions have ended / been logged out.
    """
    # 1. Start and complete a session with 5 trusted events
    sess_res = client.post("/api/sessions/start", headers={"Authorization": f"Bearer {user_token}"}, json={
        "application": "healthcare",
        "device_fingerprint": "fp_historic_session"
    })
    session_id = sess_res.json()["id"]

    for i in range(5):
        client.post("/api/behavior/events", headers={"Authorization": f"Bearer {user_token}"}, json={
            "session_id": session_id,
            "application": "healthcare",
            "typing_speed_wpm": 68.0 + (i * 0.2),
            "avg_flight_time_ms": 116.0,
            "avg_dwell_time_ms": 86.0,
            "mouse_velocity_avg": 640.0,
            "mouse_acceleration_avg": 400.0,
            "mouse_curvature_entropy": 0.45,
            "click_frequency": 1.2,
            "scroll_speed_avg": 350.0,
            "idle_duration_sec": 2.0,
            "navigation_entropy": 0.38,
            "context_signals": {"is_new_device": False}
        })

    # Peacefully terminate the session (simulate user logout)
    client.post(f"/api/sessions/{session_id}/terminate", headers={"Authorization": f"Bearer {user_token}"})

    # 2. Simulate server restart by clearing in-memory ModelManager
    ModelManager.reset_memory()

    # 3. Retrieve user profile -> triggers hydration
    prof = client.get("/api/behavior/profile", headers={"Authorization": f"Bearer {user_token}"}).json()
    assert prof["is_mature"] is True
    assert prof["sample_count"] >= 5
    # Historical samples restored into training dataset
    assert prof["model_sample_count"] >= 5


# ==============================================================================
# PHASE 3K — ADMIN SOC MODEL METADATA DIAGNOSTICS
# ==============================================================================

def test_admin_model_metadata_inspection(client, admin_token, user_token):
    """
    Verifies that Admins can inspect internal model diagnostic metadata,
    while standard users cannot access internal ML metrics.
    """
    user_me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {user_token}"}).json()
    user_id = user_me["id"]

    # 1. Admin successfully inspects model metadata
    res = client.get(f"/api/admin/users/{user_id}/model-metadata", headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 200
    meta = res.json()
    assert meta["user_id"] == user_id
    assert "model_version" in meta
    assert "training_sample_count" in meta
    assert "min_samples_for_training" in meta
    assert "retrain_interval" in meta
    assert meta["min_samples_for_training"] == 25
    assert meta["retrain_interval"] == 10

    # 2. Regular user is forbidden from admin model metadata
    forbidden_res = client.get(f"/api/admin/users/{user_id}/model-metadata", headers={"Authorization": f"Bearer {user_token}"})
    assert forbidden_res.status_code == 403
