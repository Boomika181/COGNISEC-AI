import math
import time
import numpy as np
import pytest
from sqlalchemy.orm import Session
from fastapi.testclient import TestClient

from app.services.profile_service import ProfileService
from app.ml.feature_engineering import FeatureEngineering, FEATURE_NAMES
from app.ml.anomaly_detector import IsolationForestDetector
from app.models.user import User
from app.models.behavior import BehaviorProfile
from app.core.security import get_password_hash


@pytest.fixture
def test_user_with_baseline(db_session: Session):
    """Creates a user with an established 5-sample baseline across all 10 features."""
    email = "modality.user@cognisec.ai"
    user = db_session.query(User).filter(User.email == email).first()
    if not user:
        user = User(
            name="Modality User",
            email=email,
            password_hash=get_password_hash("ValidPass123!"),
            role="USER",
            account_status="ACTIVE"
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

    profile = ProfileService.get_or_create_profile(db_session, user.id)
    profile.sample_count = 0
    db_session.commit()

    # Seed 5 complete observations
    initial_vector = np.array([65.0, 115.0, 85.0, 420.0, 550.0, 1.25, 0.8, 180.0, 2.0, 0.9], dtype=np.float64)
    for _ in range(5):
        ProfileService.update_baseline_from_event(
            db=db_session,
            user_id=user.id,
            event_vector=initial_vector,
            risk_score=0.10,
            session_status="ACTIVE",
            decision="ALLOW"
        )
    db_session.refresh(profile)
    return user, profile


# -----------------------------------------------------------------------------
# 1. Mouse-only observation does NOT dilute keyboard statistics
# -----------------------------------------------------------------------------
def test_mouse_only_observation_does_not_change_keyboard_statistics(db_session: Session, test_user_with_baseline):
    user, profile = test_user_with_baseline
    data_before = ProfileService.get_profile_dict(profile)

    wpm_before = data_before["means"]["typing_speed_wpm"]
    flight_before = data_before["means"]["avg_flight_time_ms"]
    dwell_before = data_before["means"]["avg_dwell_time_ms"]
    wpm_m2_before = data_before["m2"]["typing_speed_wpm"]
    wpm_count_before = data_before["sample_counts"]["typing_speed_wpm"]
    mouse_count_before = data_before["sample_counts"]["mouse_velocity_avg"]

    # Active mouse-only observation (keystroke features are 0.0)
    mouse_only_vec = np.array([0.0, 0.0, 0.0, 480.0, 620.0, 1.35, 1.2, 190.0, 1.8, 0.9], dtype=np.float64)
    
    updated_profile = ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=mouse_only_vec,
        risk_score=0.12,
        session_status="ACTIVE",
        decision="ALLOW"
    )
    data_after = ProfileService.get_profile_dict(updated_profile)

    # 1. Keyboard means, variances, and sample counts must remain UNTOUCHED
    assert data_after["means"]["typing_speed_wpm"] == wpm_before
    assert data_after["means"]["avg_flight_time_ms"] == flight_before
    assert data_after["means"]["avg_dwell_time_ms"] == dwell_before
    assert data_after["m2"]["typing_speed_wpm"] == wpm_m2_before
    assert data_after["sample_counts"]["typing_speed_wpm"] == wpm_count_before

    # 2. Mouse statistics and sample count MUST update
    assert data_after["sample_counts"]["mouse_velocity_avg"] == mouse_count_before + 1
    assert data_after["means"]["mouse_velocity_avg"] != data_before["means"]["mouse_velocity_avg"]
    assert updated_profile.sample_count == 6


# -----------------------------------------------------------------------------
# 2. Typing-only observation does NOT dilute mouse statistics
# -----------------------------------------------------------------------------
def test_typing_only_observation_does_not_change_mouse_statistics(db_session: Session, test_user_with_baseline):
    user, profile = test_user_with_baseline
    data_before = ProfileService.get_profile_dict(profile)

    mouse_vel_before = data_before["means"]["mouse_velocity_avg"]
    mouse_acc_before = data_before["means"]["mouse_acceleration_avg"]
    mouse_curv_before = data_before["means"]["mouse_curvature_entropy"]
    mouse_click_before = data_before["means"]["click_frequency"]
    mouse_count_before = data_before["sample_counts"]["mouse_velocity_avg"]
    typing_count_before = data_before["sample_counts"]["typing_speed_wpm"]

    # Active typing-only observation (mouse features are 0.0)
    typing_only_vec = np.array([72.0, 108.0, 82.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.5, 0.0], dtype=np.float64)

    updated_profile = ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=typing_only_vec,
        risk_score=0.10,
        session_status="ACTIVE",
        decision="ALLOW"
    )
    data_after = ProfileService.get_profile_dict(updated_profile)

    # 1. Mouse means, variances, and sample counts must remain UNTOUCHED
    assert data_after["means"]["mouse_velocity_avg"] == mouse_vel_before
    assert data_after["means"]["mouse_acceleration_avg"] == mouse_acc_before
    assert data_after["means"]["mouse_curvature_entropy"] == mouse_curv_before
    assert data_after["means"]["click_frequency"] == mouse_click_before
    assert data_after["sample_counts"]["mouse_velocity_avg"] == mouse_count_before

    # 2. Typing statistics and sample count MUST update
    assert data_after["sample_counts"]["typing_speed_wpm"] == typing_count_before + 1
    assert data_after["means"]["typing_speed_wpm"] != data_before["means"]["typing_speed_wpm"]
    assert updated_profile.sample_count == 6


# -----------------------------------------------------------------------------
# 3. Genuine observed zero-valued features are handled correctly
# -----------------------------------------------------------------------------
def test_genuine_observed_zero_values_are_updated_correctly(db_session: Session, test_user_with_baseline):
    user, profile = test_user_with_baseline
    data_before = ProfileService.get_profile_dict(profile)
    click_count_before = data_before["sample_counts"]["click_frequency"]
    curv_count_before = data_before["sample_counts"]["mouse_curvature_entropy"]

    # Pointer movement in a straight line without clicking:
    # mouse_velocity_avg > 0 and mouse_acceleration_avg > 0 (Mouse modality IS observed)
    # mouse_curvature_entropy == 0.0 and click_frequency == 0.0 are GENUINE observed zero values
    straight_mouse_vec = np.array([0.0, 0.0, 0.0, 450.0, 580.0, 0.0, 0.0, 0.0, 1.2, 0.0], dtype=np.float64)

    updated_profile = ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=straight_mouse_vec,
        risk_score=0.10,
        session_status="ACTIVE",
        decision="ALLOW"
    )
    data_after = ProfileService.get_profile_dict(updated_profile)

    # Both zero-valued features belonged to an active mouse modality, so their sample counts MUST increment
    # and their means must reflect Welford updates with 0.0
    assert data_after["sample_counts"]["click_frequency"] == click_count_before + 1
    assert data_after["sample_counts"]["mouse_curvature_entropy"] == curv_count_before + 1
    assert data_after["means"]["click_frequency"] < data_before["means"]["click_frequency"]
    assert data_after["means"]["mouse_curvature_entropy"] < data_before["means"]["mouse_curvature_entropy"]


# -----------------------------------------------------------------------------
# 4. Imputed values are excluded from baseline updates
# -----------------------------------------------------------------------------
def test_imputed_values_are_excluded_from_baseline_updates(db_session: Session, test_user_with_baseline):
    user, profile = test_user_with_baseline
    data_before = ProfileService.get_profile_dict(profile)
    typing_counts_before = data_before["sample_counts"]["typing_speed_wpm"]
    typing_m2_before = data_before["m2"]["typing_speed_wpm"]

    # Simulating a reading snapshot: AnomalyDetector imputes typing mean for evaluation
    detector = IsolationForestDetector()
    reading_vec = np.array([0.0, 0.0, 0.0, 430.0, 560.0, 1.20, 0.8, 170.0, 2.1, 0.85], dtype=np.float64)
    is_ano, score, status = detector.predict_anomaly(reading_vec, data_before, sample_count=5)
    assert not is_ano
    assert score < 0.30

    # Submit reading observation to baseline updater
    updated_profile = ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=reading_vec,
        risk_score=score,
        session_status="ACTIVE",
        decision="ALLOW"
    )
    data_after = ProfileService.get_profile_dict(updated_profile)

    # Even though AnomalyDetector evaluated with imputed typing means, the baseline updater
    # must NOT update keyboard sample counts or variance using imputed values
    assert data_after["sample_counts"]["typing_speed_wpm"] == typing_counts_before
    assert data_after["m2"]["typing_speed_wpm"] == typing_m2_before


# -----------------------------------------------------------------------------
# 5. A fully observed valid observation updates all eligible features
# -----------------------------------------------------------------------------
def test_fully_observed_valid_observation_updates_all_features(db_session: Session, test_user_with_baseline):
    user, profile = test_user_with_baseline
    data_before = ProfileService.get_profile_dict(profile)
    initial_counts = {feat: data_before["sample_counts"][feat] for feat in FEATURE_NAMES}

    full_vec = np.array([68.0, 112.0, 84.0, 440.0, 560.0, 1.28, 0.85, 185.0, 1.9, 0.92], dtype=np.float64)
    updated_profile = ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=full_vec,
        risk_score=0.15,
        session_status="ACTIVE",
        decision="ALLOW"
    )
    data_after = ProfileService.get_profile_dict(updated_profile)

    for feat in FEATURE_NAMES:
        assert data_after["sample_counts"][feat] == initial_counts[feat] + 1
    assert updated_profile.sample_count == profile.sample_count


# -----------------------------------------------------------------------------
# 6. A rejected or anomalous observation updates NO baseline features
# -----------------------------------------------------------------------------
def test_rejected_or_anomalous_observation_updates_no_baseline_features(db_session: Session, test_user_with_baseline):
    user, profile = test_user_with_baseline
    data_before = ProfileService.get_profile_dict(profile)
    initial_counts = {feat: data_before["sample_counts"][feat] for feat in FEATURE_NAMES}
    initial_sample_count = profile.sample_count

    poison_vec = np.array([250.0, 50.0, 30.0, 2000.0, 3000.0, 4.0, 15.0, 1000.0, 0.1, 4.5], dtype=np.float64)

    # 6a. High risk
    ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=poison_vec,
        risk_score=0.85,
        session_status="ACTIVE",
        decision="TERMINATE_SESSION"
    )
    db_session.refresh(profile)
    data_after = ProfileService.get_profile_dict(profile)
    assert profile.sample_count == initial_sample_count
    for feat in FEATURE_NAMES:
        assert data_after["sample_counts"][feat] == initial_counts[feat]

    # 6b. Restricted session
    ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=poison_vec,
        risk_score=0.10,
        session_status="RESTRICTED",
        decision="RESTRICT"
    )
    db_session.refresh(profile)
    assert profile.sample_count == initial_sample_count


# -----------------------------------------------------------------------------
# 7. Existing profile maturity thresholds remain unchanged
# -----------------------------------------------------------------------------
def test_existing_profile_maturity_thresholds_remain_unchanged():
    assert ProfileService.get_maturity_info(0) == ("COLD_START", 0.0, False)
    assert ProfileService.get_maturity_info(1) == ("LEARNING", 0.2, False)
    assert ProfileService.get_maturity_info(4) == ("LEARNING", 0.8, False)
    assert ProfileService.get_maturity_info(5) == ("ESTABLISHED", 1.0, True)
    assert ProfileService.get_maturity_info(25) == ("ESTABLISHED", 1.0, True)
    assert ProfileService.MIN_MATURE_SAMPLES == 5


# -----------------------------------------------------------------------------
# 8. Anomaly scoring still uses intended imputation behavior
# -----------------------------------------------------------------------------
def test_anomaly_scoring_still_uses_intended_imputation_behavior():
    detector = IsolationForestDetector()
    baseline = {
        "means": {
            "typing_speed_wpm": 60.0,
            "avg_flight_time_ms": 120.0,
            "avg_dwell_time_ms": 85.0,
            "mouse_velocity_avg": 400.0,
            "mouse_acceleration_avg": 500.0,
            "mouse_curvature_entropy": 1.2,
            "click_frequency": 0.7,
            "scroll_speed_avg": 150.0,
            "idle_duration_sec": 2.0,
            "navigation_entropy": 0.8
        },
        "stds": {feat: 10.0 for feat in FEATURE_NAMES}
    }

    # Reading vector (mouse active, zero typing)
    reading_sample = np.array([0.0, 0.0, 0.0, 410.0, 510.0, 1.25, 0.7, 155.0, 2.1, 0.82], dtype=np.float64)

    is_ano, score, status = detector.predict_anomaly(reading_sample, baseline, sample_count=10)
    # Must NOT flag anomaly because typing baseline was imputed
    assert not is_ano
    assert score < 0.30
    assert status == "ML_READY"


# -----------------------------------------------------------------------------
# 9. Server rejects client claiming keyboard=true with all-zero typing features
# -----------------------------------------------------------------------------
def test_client_claim_keyboard_true_with_zero_features_rejected(db_session: Session, test_user_with_baseline):
    user, profile = test_user_with_baseline
    data_before = ProfileService.get_profile_dict(profile)
    typing_count_before = data_before["sample_counts"]["typing_speed_wpm"]
    wpm_before = data_before["means"]["typing_speed_wpm"]
    mouse_count_before = data_before["sample_counts"]["mouse_velocity_avg"]

    # Active mouse, but zero typing features; client claims keyboard=True
    tampered_vec = np.array([0.0, 0.0, 0.0, 460.0, 590.0, 1.30, 0.9, 180.0, 1.5, 0.9], dtype=np.float64)
    claims = {"keyboard": True, "mouse": True}

    updated_profile = ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=tampered_vec,
        risk_score=0.12,
        session_status="ACTIVE",
        decision="ALLOW",
        observed_modalities=claims
    )
    data_after = ProfileService.get_profile_dict(updated_profile)

    # Server must reject unevidenced keyboard claim: keyboard statistics must NOT change
    assert data_after["sample_counts"]["typing_speed_wpm"] == typing_count_before
    assert data_after["means"]["typing_speed_wpm"] == wpm_before
    # Verified mouse modality must update
    assert data_after["sample_counts"]["mouse_velocity_avg"] == mouse_count_before + 1


# -----------------------------------------------------------------------------
# 10. Server rejects client claiming mouse=true with all-zero mouse features
# -----------------------------------------------------------------------------
def test_client_claim_mouse_true_with_zero_features_rejected(db_session: Session, test_user_with_baseline):
    user, profile = test_user_with_baseline
    data_before = ProfileService.get_profile_dict(profile)
    mouse_count_before = data_before["sample_counts"]["mouse_velocity_avg"]
    mouse_vel_before = data_before["means"]["mouse_velocity_avg"]
    typing_count_before = data_before["sample_counts"]["typing_speed_wpm"]

    # Active typing, but all mouse features are 0.0; client claims mouse=True
    tampered_vec = np.array([75.0, 105.0, 80.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0], dtype=np.float64)
    claims = {"keyboard": True, "mouse": True}

    updated_profile = ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=tampered_vec,
        risk_score=0.10,
        session_status="ACTIVE",
        decision="ALLOW",
        observed_modalities=claims
    )
    data_after = ProfileService.get_profile_dict(updated_profile)

    # Server must reject unevidenced mouse claim: mouse statistics must NOT change
    assert data_after["sample_counts"]["mouse_velocity_avg"] == mouse_count_before
    assert data_after["means"]["mouse_velocity_avg"] == mouse_vel_before
    # Verified typing modality must update
    assert data_after["sample_counts"]["typing_speed_wpm"] == typing_count_before + 1


# -----------------------------------------------------------------------------
# 11. Client suppression of active modality is respected (e.g. password fields)
# -----------------------------------------------------------------------------
def test_client_suppression_of_active_modality_is_respected(db_session: Session, test_user_with_baseline):
    user, profile = test_user_with_baseline
    data_before = ProfileService.get_profile_dict(profile)
    typing_count_before = data_before["sample_counts"]["typing_speed_wpm"]
    mouse_count_before = data_before["sample_counts"]["mouse_velocity_avg"]

    # User both types and moves mouse, but client suppresses keyboard (keyboard=False)
    dual_vec = np.array([70.0, 110.0, 85.0, 450.0, 580.0, 1.25, 0.8, 175.0, 1.5, 0.88], dtype=np.float64)
    suppressed_claims = {"keyboard": False, "mouse": True}

    updated_profile = ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=dual_vec,
        risk_score=0.10,
        session_status="ACTIVE",
        decision="ALLOW",
        observed_modalities=suppressed_claims
    )
    data_after = ProfileService.get_profile_dict(updated_profile)

    # Keyboard was suppressed -> must NOT update
    assert data_after["sample_counts"]["typing_speed_wpm"] == typing_count_before
    assert data_after["means"]["typing_speed_wpm"] == data_before["means"]["typing_speed_wpm"]
    # Mouse was not suppressed and had physical evidence -> MUST update
    assert data_after["sample_counts"]["mouse_velocity_avg"] == mouse_count_before + 1


# -----------------------------------------------------------------------------
# 12. Contradictory metadata fails safely
# -----------------------------------------------------------------------------
def test_contradictory_metadata_fails_safely(db_session: Session, test_user_with_baseline):
    user, profile = test_user_with_baseline
    data_before = ProfileService.get_profile_dict(profile)
    typing_count_before = data_before["sample_counts"]["typing_speed_wpm"]
    mouse_count_before = data_before["sample_counts"]["mouse_velocity_avg"]

    # Case A: Positive typing metrics with keystrokes=0 (contradiction)
    # Case B: Positive mouse metrics with mouse_points=0, clicks=0 (contradiction)
    contradictory_vec = np.array([72.0, 108.0, 82.0, 480.0, 600.0, 1.2, 0.5, 0.0, 1.0, 0.0], dtype=np.float64)
    contradictory_counts = {"keystrokes": 0, "mouse_points": 0, "clicks": 0}

    # resolve_observed_features directly
    obs = FeatureEngineering.resolve_observed_features(
        contradictory_vec,
        sample_counts=contradictory_counts
    )
    # Contradictory modalities must resolve to False
    assert obs["typing_speed_wpm"] is False
    assert obs["mouse_velocity_avg"] is False

    # Through baseline updater: contradictory modalities fail safe without updating statistics
    updated_profile = ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=contradictory_vec,
        risk_score=0.10,
        session_status="ACTIVE",
        decision="ALLOW",
        sample_counts=contradictory_counts
    )
    data_after = ProfileService.get_profile_dict(updated_profile)
    assert data_after["sample_counts"]["typing_speed_wpm"] == typing_count_before
    assert data_after["sample_counts"]["mouse_velocity_avg"] == mouse_count_before


# -----------------------------------------------------------------------------
# 13. Genuine zero scroll speed and navigation entropy with server evidence
# -----------------------------------------------------------------------------
def test_genuine_zero_scroll_and_navigation_preserved(db_session: Session, test_user_with_baseline):
    user, profile = test_user_with_baseline
    data_before = ProfileService.get_profile_dict(profile)
    scroll_count_before = data_before["sample_counts"]["scroll_speed_avg"]
    nav_count_before = data_before["sample_counts"]["navigation_entropy"]

    # Mouse movement + stopped scroll (speed=0, scrolls=3) + direct navigation (entropy=0, navigations=2)
    vec = np.array([0.0, 0.0, 0.0, 420.0, 540.0, 1.2, 0.7, 0.0, 1.5, 0.0], dtype=np.float64)
    valid_counts = {"scrolls": 3, "navigations": 2}

    obs = FeatureEngineering.resolve_observed_features(vec, sample_counts=valid_counts)
    assert obs["scroll_speed_avg"] is True
    assert obs["navigation_entropy"] is True

    updated_profile = ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=vec,
        risk_score=0.10,
        session_status="ACTIVE",
        decision="ALLOW",
        sample_counts=valid_counts
    )
    data_after = ProfileService.get_profile_dict(updated_profile)
    assert data_after["sample_counts"]["scroll_speed_avg"] == scroll_count_before + 1
    assert data_after["sample_counts"]["navigation_entropy"] == nav_count_before + 1


# -----------------------------------------------------------------------------
# 14. Entire observation with no server-validated evidence rejected completely
# -----------------------------------------------------------------------------
def test_observation_with_no_server_validated_evidence_rejected_completely(db_session: Session, test_user_with_baseline):
    user, profile = test_user_with_baseline
    data_before = ProfileService.get_profile_dict(profile)
    initial_sample_count = profile.sample_count

    # Empty / all-zero vector, but client claims all modalities are true
    empty_vec = np.zeros(10, dtype=np.float64)
    false_claims = {
        "keyboard": True,
        "mouse": True,
        "scroll": True,
        "navigation": True,
        "inactivity": True
    }

    updated_profile = ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=empty_vec,
        risk_score=0.10,
        session_status="ACTIVE",
        decision="ALLOW",
        observed_modalities=false_claims
    )
    db_session.refresh(profile)
    data_after = ProfileService.get_profile_dict(profile)

    # The profile must remain completely untouched
    assert profile.sample_count == initial_sample_count
    for feat in FEATURE_NAMES:
        assert data_after["sample_counts"][feat] == data_before["sample_counts"][feat]
        assert data_after["means"][feat] == data_before["means"][feat]


# -----------------------------------------------------------------------------
# 15. Inactivity alone without active interaction cannot update baseline
# -----------------------------------------------------------------------------
def test_inactivity_without_interaction_cannot_update_baseline(db_session: Session, test_user_with_baseline):
    user, profile = test_user_with_baseline
    data_before = ProfileService.get_profile_dict(profile)
    initial_sample_count = profile.sample_count

    # Idle duration 15s without any keyboard, mouse, scroll, or navigation interaction
    idle_only_vec = np.array([0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 15.0, 0.0], dtype=np.float64)
    obs = FeatureEngineering.resolve_observed_features(idle_only_vec, observed_modalities={"inactivity": True})
    # Since no active interaction occurred, inactivity claim is rejected
    assert obs["idle_duration_sec"] is False

    updated_profile = ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=idle_only_vec,
        risk_score=0.10,
        session_status="ACTIVE",
        decision="ALLOW",
        observed_modalities={"inactivity": True}
    )
    db_session.refresh(profile)
    assert profile.sample_count == initial_sample_count


# -----------------------------------------------------------------------------
# 16. Existing risk, session, anti-replay and ownership gates remain intact
# -----------------------------------------------------------------------------
def test_existing_risk_session_anti_replay_and_ownership_gates(client, user_token, db_session):
    # 1. Start a valid session
    sess_res = client.post(
        "/api/sessions/start",
        headers={"Authorization": f"Bearer {user_token}"},
        json={"application": "college", "device_fingerprint": "gate_test_fp"}
    )
    assert sess_res.status_code == 200
    session_id = sess_res.json()["id"]

    # 2. Gate: Application mismatch must be rejected
    mismatch_res = client.post(
        "/api/behavior/events",
        headers={"Authorization": f"Bearer {user_token}"},
        json={
            "session_id": session_id,
            "application": "ecommerce",
            "typing_speed_wpm": 60.0,
            "avg_flight_time_ms": 110.0,
            "avg_dwell_time_ms": 80.0
        }
    )
    assert mismatch_res.status_code == 400
    assert "Application mismatch" in mismatch_res.json()["detail"]

    # 3. Gate: Malformed feature values (out of bounds) must be rejected
    malformed_res = client.post(
        "/api/behavior/events",
        headers={"Authorization": f"Bearer {user_token}"},
        json={
            "session_id": session_id,
            "application": "college",
            "typing_speed_wpm": 99999.0,  # exceeds MAX_WPM
            "avg_flight_time_ms": 110.0,
            "avg_dwell_time_ms": 80.0
        }
    )
    assert malformed_res.status_code == 400
    assert (
        "Telemetry tampering detected" in malformed_res.json()["detail"]
        or "Malformed behavioral telemetry features" in malformed_res.json()["detail"]
    )

    # 4. Gate: Anti-replay protection (nonce reuse must be rejected)
    valid_payload = {
        "session_id": session_id,
        "application": "college",
        "typing_speed_wpm": 65.0,
        "avg_flight_time_ms": 110.0,
        "avg_dwell_time_ms": 85.0,
        "mouse_velocity_avg": 400.0,
        "mouse_acceleration_avg": 500.0,
        "mouse_curvature_entropy": 1.2,
        "click_frequency": 0.8,
        "scroll_speed_avg": 120.0,
        "idle_duration_sec": 1.5,
        "navigation_entropy": 0.8,
        "telemetry_nonce": "test_nonce_gate_verification_12345",
        "timestamp": time.time(),
        "sequence_number": 1
    }
    first_res = client.post(
        "/api/behavior/events",
        headers={"Authorization": f"Bearer {user_token}"},
        json=valid_payload
    )
    assert first_res.status_code == 200

    # Replaying identical nonce must be rejected
    replay_res = client.post(
        "/api/behavior/events",
        headers={"Authorization": f"Bearer {user_token}"},
        json=valid_payload
    )
    assert replay_res.status_code in [400, 403]
    assert "Replay detected" in replay_res.json()["detail"]

