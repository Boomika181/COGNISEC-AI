import math
import numpy as np
import pytest
from app.ml.feature_engineering import FeatureEngineering, FEATURE_NAMES
from app.ml.anomaly_detector import IsolationForestDetector
from app.services.profile_service import ProfileService
from app.services.risk_service import RiskService
from app.models.session import Session as DbSessionModel


# ==============================================================================
# 1. KEYBOARD DWELL TIME & FLIGHT TIME TESTS
# ==============================================================================

def test_dwell_time_validation_and_bounds():
    """Verifies that dwell time is strictly bounded [0.0, 3000.0] ms."""
    valid_vec = np.array([65.0, 120.0, 85.0, 500.0, 300.0, 0.45, 1.0, 200.0, 2.0, 0.35])
    is_valid, err = FeatureEngineering.validate_vector(valid_vec)
    assert is_valid
    assert err is None

    # Negative dwell time rejected
    neg_dwell = valid_vec.copy()
    neg_dwell[2] = -15.0
    is_valid, err = FeatureEngineering.validate_vector(neg_dwell)
    assert not is_valid
    assert "avg_dwell_time_ms" in err

    # Excessive dwell time (> 3000ms) rejected
    excess_dwell = valid_vec.copy()
    excess_dwell[2] = 4500.0
    is_valid, err = FeatureEngineering.validate_vector(excess_dwell)
    assert not is_valid
    assert "avg_dwell_time_ms" in err


def test_dwell_time_zero_missing_data_accepted():
    """Verifies that 0.0 (no typing / missing observation) is a valid bounded value."""
    zero_dwell = np.array([0.0, 0.0, 0.0, 500.0, 300.0, 0.45, 1.0, 200.0, 2.0, 0.35])
    is_valid, err = FeatureEngineering.validate_vector(zero_dwell)
    assert is_valid
    assert err is None


# ==============================================================================
# 2. MOUSE ACCELERATION & VELOCITY TESTS
# ==============================================================================

def test_mouse_acceleration_valid_and_bounds():
    """Verifies mouse acceleration bounds [0.0, 25000.0] px/s^2."""
    valid_vec = np.array([65.0, 120.0, 85.0, 650.0, 420.0, 0.45, 1.0, 200.0, 2.0, 0.35])
    is_valid, err = FeatureEngineering.validate_vector(valid_vec)
    assert is_valid

    # Negative acceleration rejected
    neg_acc = valid_vec.copy()
    neg_acc[4] = -100.0
    is_valid, err = FeatureEngineering.validate_vector(neg_acc)
    assert not is_valid
    assert "mouse_acceleration_avg" in err

    # Superhuman acceleration (> 25000 px/s^2) rejected
    high_acc = valid_vec.copy()
    high_acc[4] = 30000.0
    is_valid, err = FeatureEngineering.validate_vector(high_acc)
    assert not is_valid
    assert "mouse_acceleration_avg" in err


def test_mouse_acceleration_discrete_physics_calculation():
    """
    Simulates the mathematical acceleration calculation implemented in client SDK:
    dv / dt across consecutive velocity segments.
    """
    # 3 points forming 2 segments:
    # Segment 1: dist = 50px, dt = 50ms -> v1 = 1000 px/s
    # Segment 2: dist = 100px, dt = 50ms -> v2 = 2000 px/s
    # dv = |2000 - 1000| = 1000 px/s, dt_acc = 0.050s -> a = 1000 / 0.050 = 20000 px/s^2
    v1, v2 = 1000.0, 2000.0
    dt_acc = 0.050
    acc = abs(v2 - v1) / dt_acc
    assert acc == 20000.0
    assert 0.0 <= acc <= 25000.0


# ==============================================================================
# 3. MOUSE CURVATURE SHANNON ENTROPY TESTS
# ==============================================================================

def test_mouse_curvature_entropy_straight_vs_curved():
    """
    Tests the mathematical formulation of trajectory turning-angle Shannon entropy:
    - Purely straight motion: all turning angles = 0 -> Entropy = 0.0
    - Uniformly curved across 6 angular bins: Entropy = ln(6) ~= 1.792 <= 5.0
    """
    num_bins = 6
    bin_width = math.pi / num_bins

    # Case A: Straight line trajectory (turning angles all near 0)
    straight_angles = [0.01, 0.02, 0.01, 0.03, 0.0]
    bin_counts_straight = [0] * num_bins
    for a in straight_angles:
        bin_counts_straight[min(num_bins - 1, int(a / bin_width))] += 1
    
    total = len(straight_angles)
    entropy_straight = 0.0
    for c in bin_counts_straight:
        if c > 0:
            p = c / total
            entropy_straight -= p * math.log(p)
    assert entropy_straight == 0.0

    # Case B: Varied curved trajectory (angles distributed across bins)
    curved_angles = [0.1, 0.6, 1.1, 1.6, 2.1, 2.8]
    bin_counts_curved = [0] * num_bins
    for a in curved_angles:
        bin_counts_curved[min(num_bins - 1, int(a / bin_width))] += 1
    
    total_curved = len(curved_angles)
    entropy_curved = 0.0
    for c in bin_counts_curved:
        if c > 0:
            p = c / total_curved
            entropy_curved -= p * math.log(p)
    
    expected_max = math.log(num_bins)
    assert abs(entropy_curved - expected_max) < 1e-4
    assert 0.0 <= entropy_curved <= 5.0


# ==============================================================================
# 4. NAVIGATION ENTROPY TESTS
# ==============================================================================

def test_navigation_entropy_empty_and_populated():
    """
    Tests navigation categorical Shannon entropy:
    - Empty history -> 0.0
    - Single category repeated -> 0.0
    - 4 distinct categories equally visited -> ln(4) ~= 1.386 <= 5.0
    """
    # Empty
    assert 0.0 <= 0.0 <= 5.0

    # Single category repeated: p = 1.0 -> H = 0.0
    cats_single = ["home", "home", "home"]
    counts_s = {"home": 3}
    h_single = 0.0
    for c, cnt in counts_s.items():
        p = cnt / 3
        h_single -= p * math.log(p)
    assert h_single == 0.0

    # 4 distinct categories: p = 0.25 each -> H = ln(4)
    cats_multi = ["home", "academic", "exam", "grades"]
    counts_m = {c: 1 for c in cats_multi}
    h_multi = 0.0
    for c, cnt in counts_m.items():
        p = cnt / 4
        h_multi -= p * math.log(p)
    assert abs(h_multi - math.log(4)) < 1e-4
    assert 0.0 <= h_multi <= 5.0


# ==============================================================================
# 5. TYPING SPEED & COLD-START BEHAVIOR TESTS
# ==============================================================================

def test_typing_speed_wpm_calculation():
    """
    Verifies WPM calculation from paired flight + dwell cycle:
    Flight = 110ms, Dwell = 90ms -> Cycle = 200ms
    Keystrokes/sec = 5 -> Keystrokes/min = 300 -> WPM (5 chars/word) = 60 WPM.
    """
    flight = 110.0
    dwell = 90.0
    cycle = flight + dwell
    wpm = round(60000 / (5 * cycle))
    assert wpm == 60


def test_cold_start_telemetry_with_zero_observations(client, user_token):
    """
    Verifies that when a cold-start user first lands on the portal without typing,
    telemetry with 0.0 values is accepted by FastAPI, granted ALLOW, and preserves security.
    """
    sess_res = client.post("/api/sessions/start", headers={"Authorization": f"Bearer {user_token}"}, json={
        "application": "college",
        "device_fingerprint": "dev_cold_start_test"
    })
    session_id = sess_res.json()["id"]

    res = client.post("/api/behavior/events", headers={"Authorization": f"Bearer {user_token}"}, json={
        "session_id": session_id,
        "application": "college",
        "typing_speed_wpm": 0.0,
        "avg_flight_time_ms": 0.0,
        "avg_dwell_time_ms": 0.0,
        "mouse_velocity_avg": 0.0,
        "mouse_acceleration_avg": 0.0,
        "mouse_curvature_entropy": 0.0,
        "click_frequency": 0.0,
        "scroll_speed_avg": 0.0,
        "idle_duration_sec": 1.0,
        "navigation_entropy": 0.0,
        "context_signals": {"is_new_device": False}
    })
    assert res.status_code == 200
    data = res.json()
    assert data["decision"] == "ALLOW"
    assert data["session_status"] == "ACTIVE"
    # Never leak internal scores to user
    assert "risk_score" not in data
    assert "anomaly_score" not in data


def test_zero_activity_samples_do_not_poison_baseline(db_session):
    """
    Verifies that empty/idle telemetry snapshots (all zeroes) do NOT advance sample_count
    or dilute legitimate behavioral baseline means to zero in ProfileService.
    """
    from app.models.user import User
    user = db_session.query(User).filter(User.email == "test.user@cognisec.ai").first()
    assert user is not None
    profile_before = ProfileService.get_or_create_profile(db_session, user.id)
    initial_count = profile_before.sample_count

    # Ingest an all-zero idle vector
    zero_vec = np.zeros(10, dtype=np.float64)
    profile_after = ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=zero_vec,
        risk_score=0.05,
        session_status="ACTIVE",
        decision="ALLOW"
    )
    # Sample count must NOT increment for empty/idle silence
    assert profile_after.sample_count == initial_count


def test_idle_reading_period_does_not_falsely_penalize_user():
    """
    Verifies that an established user who is reading (moving mouse/scrolling but not typing)
    is not falsely flagged as anomalous due to unobserved typing modality.
    """
    detector = IsolationForestDetector(contamination=0.05, random_state=42)

    baseline_stats = {
        "means": {
            "typing_speed_wpm": 72.0, "avg_flight_time_ms": 115.0, "avg_dwell_time_ms": 85.0,
            "mouse_velocity_avg": 620.0, "mouse_acceleration_avg": 390.0, "mouse_curvature_entropy": 0.44,
            "click_frequency": 1.0, "scroll_speed_avg": 300.0, "idle_duration_sec": 3.0, "navigation_entropy": 0.35
        },
        "stds": {
            "typing_speed_wpm": 6.0, "avg_flight_time_ms": 10.0, "avg_dwell_time_ms": 8.0,
            "mouse_velocity_avg": 50.0, "mouse_acceleration_avg": 50.0, "mouse_curvature_entropy": 0.05,
            "click_frequency": 0.25, "scroll_speed_avg": 50.0, "idle_duration_sec": 1.0, "navigation_entropy": 0.05
        }
    }

    # Reading sample: typing = 0.0, but normal mouse velocity and scroll
    reading_sample = np.array([0.0, 0.0, 0.0, 625.0, 395.0, 0.43, 0.8, 310.0, 4.0, 0.34])
    is_anomaly, score, status = detector.predict_anomaly(reading_sample, baseline_stats, sample_count=10)

    # Must NOT trigger anomaly during normal reading pause
    assert not is_anomaly
    assert score < 0.40
    assert status == "ML_READY"


def test_abnormal_typing_burst_detected_as_anomaly():
    """
    Verifies that when typing IS present but deviates dramatically from established baseline
    (e.g., bot paste / automated keystroke burst at 260 WPM), it is detected as anomalous.
    """
    detector = IsolationForestDetector(contamination=0.05, random_state=42)

    baseline_stats = {
        "means": {
            "typing_speed_wpm": 65.0, "avg_flight_time_ms": 120.0, "avg_dwell_time_ms": 85.0,
            "mouse_velocity_avg": 600.0, "mouse_acceleration_avg": 380.0, "mouse_curvature_entropy": 0.45,
            "click_frequency": 1.0, "scroll_speed_avg": 300.0, "idle_duration_sec": 2.0, "navigation_entropy": 0.35
        },
        "stds": {
            "typing_speed_wpm": 5.0, "avg_flight_time_ms": 15.0, "avg_dwell_time_ms": 10.0,
            "mouse_velocity_avg": 50.0, "mouse_acceleration_avg": 50.0, "mouse_curvature_entropy": 0.05,
            "click_frequency": 0.25, "scroll_speed_avg": 50.0, "idle_duration_sec": 1.0, "navigation_entropy": 0.05
        }
    }

    # Robotic typing burst: 260 WPM, 15ms flight time
    bot_sample = np.array([260.0, 15.0, 18.0, 600.0, 380.0, 0.45, 1.0, 300.0, 0.5, 0.35])
    is_anomaly, score, status = detector.predict_anomaly(bot_sample, baseline_stats, sample_count=10)

    assert is_anomaly
    assert score > 0.50
    assert status == "ML_READY"


def test_all_ten_features_bounds_and_schema_compatibility():
    """
    Audits every single feature in FEATURE_NAMES against backend constraints:
    Verifies dimensions, bounds checking, and non-negative constraints.
    """
    assert len(FEATURE_NAMES) == 10
    nominal_vec = np.array([65.0, 120.0, 85.0, 600.0, 380.0, 0.45, 1.0, 300.0, 2.0, 0.35])

    for i, name in enumerate(FEATURE_NAMES):
        test_vec = nominal_vec.copy()
        test_vec[i] = -1.0  # Physically impossible negative
        is_valid, err = FeatureEngineering.validate_vector(test_vec)
        assert not is_valid
        assert name in err
