import json
import math
import pytest
import numpy as np
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.models.user import User
from app.models.behavior import BehaviorProfile
from app.core.security import get_password_hash
from app.services.profile_service import ProfileService
from app.services.risk_service import RiskService
from app.ml.feature_engineering import FeatureEngineering, FEATURE_NAMES, MODALITY_FEATURE_GROUPS


def get_or_create_test_user(db, email: str = "modality_user@example.com") -> User:
    user = db.query(User).filter(User.email == email).first()
    if user:
        return user
    user = User(
        name="Modality Test User",
        email=email,
        password_hash=get_password_hash("ValidPass123!"),
        role="USER",
        account_status="ACTIVE",
        failed_login_attempts=0
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def test_1_modality_maturity_cold_start():
    """Verify that a new profile has COLD_START across all 5 modalities."""
    breakdown = ProfileService.get_modality_maturity_breakdown({m: 0 for m in MODALITY_FEATURE_GROUPS})
    assert len(breakdown) == 5
    for mod in ["keyboard", "mouse", "scroll", "navigation", "inactivity"]:
        assert mod in breakdown
        assert breakdown[mod]["sample_count"] == 0
        assert breakdown[mod]["status"] == "COLD_START"
        assert breakdown[mod]["confidence"] == 0.0
        assert breakdown[mod]["is_mature"] is False

    status, conf, is_mature = ProfileService.get_maturity_info(
        sample_count=0,
        modality_counts={m: 0 for m in MODALITY_FEATURE_GROUPS}
    )
    assert status == "COLD_START"
    assert conf == 0.0
    assert is_mature is False


def test_2_sparse_modalities_profile_remains_immature():
    """
    Requirement: A modality with insufficient observations must remain immature even
    if other modalities have many samples. Do not use global sample_count alone.
    """
    counts = {
        "keyboard": 0,
        "mouse": 25,
        "scroll": 0,
        "navigation": 0,
        "inactivity": 25
    }
    breakdown = ProfileService.get_modality_maturity_breakdown(counts)
    assert breakdown["mouse"]["status"] == "ESTABLISHED"
    assert breakdown["mouse"]["confidence"] == 1.0
    assert breakdown["mouse"]["is_mature"] is True

    assert breakdown["keyboard"]["status"] == "COLD_START"
    assert breakdown["keyboard"]["confidence"] == 0.0
    assert breakdown["keyboard"]["is_mature"] is False

    # Despite global sample_count of 25, overall profile must NOT be ESTABLISHED
    status, conf, is_mature = ProfileService.get_maturity_info(
        sample_count=25,
        modality_counts=counts
    )
    assert status == "LEARNING"
    assert is_mature is False
    # (0.0 + 1.0 + 0.0 + 0.0 + 1.0) / 5 = 0.40
    assert conf == 0.40


def test_3_independent_confidence_and_counts_across_modalities():
    """Verify confidence and sample counts are evaluated independently across all 5 modalities."""
    counts = {
        "keyboard": 3,
        "mouse": 5,
        "scroll": 1,
        "navigation": 0,
        "inactivity": 5
    }
    breakdown = ProfileService.get_modality_maturity_breakdown(counts)
    assert breakdown["keyboard"] == {"sample_count": 3, "status": "LEARNING", "confidence": 0.60, "is_mature": False}
    assert breakdown["mouse"] == {"sample_count": 5, "status": "ESTABLISHED", "confidence": 1.0, "is_mature": True}
    assert breakdown["scroll"] == {"sample_count": 1, "status": "LEARNING", "confidence": 0.20, "is_mature": False}
    assert breakdown["navigation"] == {"sample_count": 0, "status": "COLD_START", "confidence": 0.0, "is_mature": False}
    assert breakdown["inactivity"] == {"sample_count": 5, "status": "ESTABLISHED", "confidence": 1.0, "is_mature": True}

    status, conf, is_mature = ProfileService.get_maturity_info(
        sample_count=14,
        modality_counts=counts
    )
    assert status == "LEARNING"
    assert is_mature is False
    # (0.60 + 1.0 + 0.20 + 0.0 + 1.0) / 5 = 0.56
    assert conf == 0.56


def test_4_missing_and_imputed_modalities_do_not_increase_modality_maturity(db_session):
    """
    Requirement: Do not let missing or imputed values increase modality maturity.
    Mouse-only telemetry must only increment mouse modality count.
    """
    user = get_or_create_test_user(db_session, "user_f10_4@example.com")
    user_id = user.id
    profile = ProfileService.get_or_create_profile(db_session, user_id)
    initial_stats = ProfileService.get_profile_dict(profile)

    # 10D vector with mouse motion and clicks, but typing, scroll, navigation = 0
    # Keyboard is unobserved (imputed), mouse is observed
    mouse_only_vector = np.array([
        0.0, 0.0, 0.0,     # keyboard (unobserved)
        200.0, 300.0, 1.2, # mouse motion
        0.5,               # click frequency
        0.0,               # scroll (unobserved)
        1.0,               # idle duration
        0.0                # navigation (unobserved)
    ], dtype=float)

    observed_modalities = {
        "keyboard": False,
        "mouse": True,
        "scroll": False,
        "navigation": False,
        "inactivity": True
    }
    sample_counts = {
        "keystrokes": 0,
        "mouse_points": 45,
        "clicks": 3,
        "scrolls": 0,
        "navigations": 0
    }

    updated_profile = ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user_id,
        event_vector=mouse_only_vector,
        risk_score=0.10,
        session_status="ACTIVE",
        decision="ALLOW",
        observed_modalities=observed_modalities,
        sample_counts=sample_counts,
        context_signals={"event_id": "evt_test_4_1"}
    )

    stats = ProfileService.get_profile_dict(updated_profile)
    mod_counts = stats["modality_sample_counts"]
    assert mod_counts["mouse"] == 1
    assert mod_counts["inactivity"] == 1
    # Missing/imputed modalities must strictly remain at 0
    assert mod_counts["keyboard"] == 0
    assert mod_counts["scroll"] == 0
    assert mod_counts["navigation"] == 0

    breakdown = stats["modality_maturity"]
    assert breakdown["mouse"]["status"] == "LEARNING"
    assert breakdown["keyboard"]["status"] == "COLD_START"
    assert breakdown["scroll"]["status"] == "COLD_START"
    assert breakdown["navigation"]["status"] == "COLD_START"


def test_5_genuine_zero_observations_increment_modality_maturity(db_session):
    """
    Requirement: Genuine zero observations (e.g. curvature == 0.0 or click_frequency == 0.0
    during active pointer motion) must increment modality maturity.
    """
    user = get_or_create_test_user(db_session, "user_f10_5@example.com")
    user_id = user.id
    ProfileService.get_or_create_profile(db_session, user_id)

    # Mouse pointer moving in a straight line: curvature entropy == 0.0, click_frequency == 0.0
    straight_line_vector = np.array([
        0.0, 0.0, 0.0,     # keyboard
        180.0, 250.0, 0.0, # mouse motion with genuine zero curvature
        0.0,               # genuine zero clicks
        0.0,               # scroll
        1.5,               # idle
        0.0                # navigation
    ], dtype=float)

    observed_modalities = {
        "keyboard": False,
        "mouse": True,
        "scroll": False,
        "navigation": False,
        "inactivity": True
    }
    sample_counts = {
        "keystrokes": 0,
        "mouse_points": 50,
        "clicks": 0
    }

    updated_profile = ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user_id,
        event_vector=straight_line_vector,
        risk_score=0.08,
        session_status="ACTIVE",
        decision="ALLOW",
        observed_modalities=observed_modalities,
        sample_counts=sample_counts,
        context_signals={"event_id": "evt_test_5_1"}
    )

    stats = ProfileService.get_profile_dict(updated_profile)
    mod_counts = stats["modality_sample_counts"]
    # Mouse was genuinely active with genuine zero curvature and genuine zero clicks:
    assert mod_counts["mouse"] == 1
    assert stats["feature_sample_counts"]["mouse_curvature_entropy"] == 1
    assert stats["feature_sample_counts"]["click_frequency"] == 1
    # Keyboard remains 0
    assert mod_counts["keyboard"] == 0


def test_6_all_modalities_mature_declares_profile_established(db_session):
    """
    Requirement: When all modalities reach >= 5 genuine observations, profile
    becomes ESTABLISHED with confidence 1.0 and is_mature=True.
    """
    user = get_or_create_test_user(db_session, "user_f10_6@example.com")
    user_id = user.id
    ProfileService.get_or_create_profile(db_session, user_id)

    all_active_vector = np.array([
        50.0, 120.0, 80.0,   # keyboard
        210.0, 310.0, 1.15,  # mouse motion
        0.4,                 # clicks
        40.0,                # scroll
        1.2,                 # idle
        0.35                 # navigation
    ], dtype=float)

    observed_modalities = {m: True for m in MODALITY_FEATURE_GROUPS}
    sample_counts = {
        "keystrokes": 30,
        "mouse_points": 60,
        "clicks": 4,
        "scrolls": 15,
        "navigations": 2
    }

    for i in range(1, 6):
        updated_profile = ProfileService.update_baseline_from_event(
            db=db_session,
            user_id=user_id,
            event_vector=all_active_vector,
            risk_score=0.05,
            session_status="ACTIVE",
            decision="ALLOW",
            observed_modalities=observed_modalities,
            sample_counts=sample_counts,
            context_signals={"event_id": f"evt_test_6_{i}"}
        )

    stats = ProfileService.get_profile_dict(updated_profile)
    mod_counts = stats["modality_sample_counts"]
    for mod in MODALITY_FEATURE_GROUPS:
        assert mod_counts[mod] == 5
        assert stats["modality_maturity"][mod]["status"] == "ESTABLISHED"
        assert stats["modality_maturity"][mod]["confidence"] == 1.0
        assert stats["modality_maturity"][mod]["is_mature"] is True

    assert stats["confidence_status"] == "ESTABLISHED"
    assert stats["confidence_score"] == 1.0
    assert stats["is_mature"] is True


def test_7_risk_service_dampens_behavioral_weight_on_immature_modality(db_session):
    """
    Requirement: An immature modality must not trigger full 55% ESTABLISHED behavioral weight.
    """
    user = get_or_create_test_user(db_session, "user_f10_7@example.com")
    user_id = user.id
    profile = ProfileService.get_or_create_profile(db_session, user_id)

    # Seed profile with mature mouse (5 samples) but 0 keyboard samples
    stats = ProfileService.get_profile_dict(profile)
    stats["sample_count"] = 5
    stats["modality_sample_counts"] = {
        "keyboard": 0,
        "mouse": 5,
        "scroll": 0,
        "navigation": 0,
        "inactivity": 5
    }
    profile.sample_count = 5
    profile.baseline_features = json.dumps(stats)
    db_session.commit()

    test_vector = np.array([
        45.0, 110.0, 85.0,
        200.0, 300.0, 1.1,
        0.3, 30.0, 1.0, 0.2
    ], dtype=float)

    # Telemetry observes keyboard (which has 0 baseline samples)
    risk_score, anomaly_score, risk_level, factors, is_anomaly, ml_status = RiskService.calculate_risk(
        db=db_session,
        user_id=user_id,
        session_id=None,
        application="HEALTHCARE",
        behavior_vector=test_vector,
        context_signals={"is_new_device": False},
        observed_modalities={"keyboard": True, "mouse": False}
    )

    # Because keyboard is COLD_START (0 samples), behavioral weight is dampened to 0.05
    # Risk score must remain safely low (< 0.30) rather than blowing up
    assert risk_level == "LOW"
    assert risk_score < 0.30


def test_8_backward_compatibility_scalar_sample_count():
    """Verify that calling get_maturity_info with only sample_count preserves exact historical behavior."""
    assert ProfileService.get_maturity_info(0) == ("COLD_START", 0.0, False)
    assert ProfileService.get_maturity_info(1) == ("LEARNING", 0.2, False)
    assert ProfileService.get_maturity_info(4) == ("LEARNING", 0.8, False)
    assert ProfileService.get_maturity_info(5) == ("ESTABLISHED", 1.0, True)
    assert ProfileService.get_maturity_info(25) == ("ESTABLISHED", 1.0, True)


def test_9_welford_statistics_and_10d_schema_preserved(db_session):
    """Verify Welford means, stds, m2, and 10D schema integrity are maintained alongside modality maturity."""
    user = get_or_create_test_user(db_session, "user_f10_9@example.com")
    user_id = user.id
    profile = ProfileService.get_or_create_profile(db_session, user_id)

    vector_1 = np.array([50.0, 100.0, 80.0, 200.0, 300.0, 1.0, 0.5, 30.0, 1.0, 0.2], dtype=float)
    vector_2 = np.array([60.0, 120.0, 90.0, 220.0, 320.0, 1.2, 0.6, 40.0, 1.2, 0.3], dtype=float)

    all_mods = {m: True for m in MODALITY_FEATURE_GROUPS}
    all_counts = {"keystrokes": 10, "mouse_points": 10, "clicks": 2, "scrolls": 5, "navigations": 2}

    ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user_id,
        event_vector=vector_1,
        risk_score=0.05,
        decision="ALLOW",
        observed_modalities=all_mods,
        sample_counts=all_counts,
        context_signals={"event_id": "evt_test_9_1"}
    )
    p2 = ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user_id,
        event_vector=vector_2,
        risk_score=0.05,
        decision="ALLOW",
        observed_modalities=all_mods,
        sample_counts=all_counts,
        context_signals={"event_id": "evt_test_9_2"}
    )

    stats = ProfileService.get_profile_dict(p2)
    # Means must match exact mathematical average of vector_1 and vector_2:
    assert stats["means"]["typing_speed_wpm"] == 55.0
    assert stats["means"]["avg_flight_time_ms"] == 110.0
    assert stats["means"]["avg_dwell_time_ms"] == 85.0
    assert stats["means"]["mouse_velocity_avg"] == 210.0
    assert stats["means"]["scroll_speed_avg"] == 35.0

    # 10D features present in means, stds, m2, sample_counts:
    for feat in FEATURE_NAMES:
        assert feat in stats["means"]
        assert feat in stats["stds"]
        assert feat in stats["m2"]
        assert stats["feature_sample_counts"][feat] == 2

    # Modality sample counts:
    for mod in MODALITY_FEATURE_GROUPS:
        assert stats["modality_sample_counts"][mod] == 2
        assert stats["modality_maturity"][mod]["status"] == "LEARNING"
        assert stats["modality_maturity"][mod]["confidence"] == 0.40


def test_10_profile_api_endpoint_returns_modality_breakdown(client: TestClient, db_session):
    """Verify GET /api/behavior/profile returns modality_sample_counts and modality_maturity."""
    user = get_or_create_test_user(db_session, "user_f10_10@example.com")
    profile = ProfileService.get_or_create_profile(db_session, user.id)

    from app.core.security import create_access_token
    token = create_access_token(subject=str(user.id), role=user.role)
    headers = {"Authorization": f"Bearer {token}"}

    res = client.get("/api/behavior/profile", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "modality_sample_counts" in data
    assert "modality_maturity" in data
    assert data["baseline_status"] == "COLD_START"
    assert data["is_mature"] is False
    assert data["maturity_confidence"] == 0.0
    for mod in ["keyboard", "mouse", "scroll", "navigation", "inactivity"]:
        assert mod in data["modality_sample_counts"]
        assert mod in data["modality_maturity"]


def test_11_click_frequency_contributes_to_mouse_maturity(db_session):
    """
    Requirement: Click frequency (feature index 6) contributes directly to mouse maturity,
    even during static clicking without pointer translation.
    """
    user = get_or_create_test_user(db_session, "user_f10_11@example.com")
    ProfileService.get_or_create_profile(db_session, user.id)

    # Static clicking vector: no keyboard, no mouse velocity, but click_frequency = 1.5
    click_only_vector = np.array([
        0.0, 0.0, 0.0,     # keyboard (unobserved)
        0.0, 0.0, 0.0,     # mouse motion (unobserved)
        1.5,               # click_frequency (observed!)
        0.0,               # scroll (unobserved)
        1.0,               # idle_duration (observed)
        0.0                # navigation (unobserved)
    ], dtype=float)

    observed_modalities = {
        "keyboard": False,
        "mouse": True,
        "scroll": False,
        "navigation": False,
        "inactivity": True
    }
    sample_counts = {
        "keystrokes": 0,
        "mouse_points": 0,
        "clicks": 6,
        "scrolls": 0,
        "navigations": 0
    }

    updated_profile = ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=click_only_vector,
        risk_score=0.10,
        session_status="ACTIVE",
        decision="ALLOW",
        observed_modalities=observed_modalities,
        sample_counts=sample_counts,
        context_signals={"event_id": "evt_test_11_1"}
    )

    stats = ProfileService.get_profile_dict(updated_profile)
    # Click frequency updated mouse modality
    assert stats["modality_sample_counts"]["mouse"] == 1
    assert stats["feature_sample_counts"]["click_frequency"] == 1
    # Other modalities unobserved
    assert stats["modality_sample_counts"]["keyboard"] == 0
    assert stats["modality_sample_counts"]["scroll"] == 0
    assert stats["modality_sample_counts"]["navigation"] == 0


def test_12_scroll_speed_contributes_to_scroll_maturity(db_session):
    """
    Requirement: Scroll speed (feature index 7) contributes directly to scroll maturity.
    """
    user = get_or_create_test_user(db_session, "user_f10_12@example.com")
    ProfileService.get_or_create_profile(db_session, user.id)

    scroll_vector = np.array([
        0.0, 0.0, 0.0,     # keyboard (unobserved)
        0.0, 0.0, 0.0,     # mouse (unobserved)
        0.0,               # clicks (unobserved)
        120.0,             # scroll_speed_avg (observed!)
        1.2,               # idle_duration (observed)
        0.0                # navigation (unobserved)
    ], dtype=float)

    observed_modalities = {
        "keyboard": False,
        "mouse": False,
        "scroll": True,
        "navigation": False,
        "inactivity": True
    }
    sample_counts = {
        "keystrokes": 0,
        "mouse_points": 0,
        "clicks": 0,
        "scrolls": 8,
        "navigations": 0
    }

    updated_profile = ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=scroll_vector,
        risk_score=0.08,
        session_status="ACTIVE",
        decision="ALLOW",
        observed_modalities=observed_modalities,
        sample_counts=sample_counts,
        context_signals={"event_id": "evt_test_12_1"}
    )

    stats = ProfileService.get_profile_dict(updated_profile)
    assert stats["modality_sample_counts"]["scroll"] == 1
    assert stats["feature_sample_counts"]["scroll_speed_avg"] == 1
    assert stats["modality_sample_counts"]["keyboard"] == 0
    assert stats["modality_sample_counts"]["mouse"] == 0
    assert stats["modality_sample_counts"]["navigation"] == 0


def test_13_navigation_entropy_contributes_to_navigation_maturity(db_session):
    """
    Requirement: Navigation entropy (feature index 9) contributes directly to navigation maturity.
    """
    user = get_or_create_test_user(db_session, "user_f10_13@example.com")
    ProfileService.get_or_create_profile(db_session, user.id)

    nav_vector = np.array([
        0.0, 0.0, 0.0,     # keyboard (unobserved)
        150.0, 200.0, 1.1, # mouse (observed to provide interaction context)
        0.0,               # clicks
        0.0,               # scroll
        1.0,               # idle
        0.75               # navigation_entropy (observed!)
    ], dtype=float)

    observed_modalities = {
        "keyboard": False,
        "mouse": True,
        "scroll": False,
        "navigation": True,
        "inactivity": True
    }
    sample_counts = {
        "keystrokes": 0,
        "mouse_points": 30,
        "clicks": 0,
        "scrolls": 0,
        "navigations": 3
    }

    updated_profile = ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=nav_vector,
        risk_score=0.07,
        session_status="ACTIVE",
        decision="ALLOW",
        observed_modalities=observed_modalities,
        sample_counts=sample_counts,
        context_signals={"event_id": "evt_test_13_1"}
    )

    stats = ProfileService.get_profile_dict(updated_profile)
    assert stats["modality_sample_counts"]["navigation"] == 1
    assert stats["feature_sample_counts"]["navigation_entropy"] == 1
    assert stats["modality_sample_counts"]["keyboard"] == 0
    assert stats["modality_sample_counts"]["scroll"] == 0


def test_14_all_five_modalities_independent_maturity_milestones():
    """
    Requirement: All 5 modalities can independently reach maturity at different times.
    """
    counts = {
        "keyboard": 5,
        "mouse": 5,
        "scroll": 2,
        "navigation": 1,
        "inactivity": 5
    }
    breakdown = ProfileService.get_modality_maturity_breakdown(counts)
    assert breakdown["keyboard"]["is_mature"] is True
    assert breakdown["mouse"]["is_mature"] is True
    assert breakdown["inactivity"]["is_mature"] is True
    assert breakdown["scroll"]["is_mature"] is False
    assert breakdown["navigation"]["is_mature"] is False

    # Overall profile is NOT mature because scroll and navigation are < 5
    status, conf, is_mature = ProfileService.get_maturity_info(sample_count=18, modality_counts=counts)
    assert status == "LEARNING"
    assert is_mature is False

    # When scroll and navigation also reach 5:
    counts["scroll"] = 5
    counts["navigation"] = 5
    breakdown_full = ProfileService.get_modality_maturity_breakdown(counts)
    for m in MODALITY_FEATURE_GROUPS:
        assert breakdown_full[m]["is_mature"] is True
        assert breakdown_full[m]["status"] == "ESTABLISHED"
    status_full, conf_full, is_mature_full = ProfileService.get_maturity_info(sample_count=25, modality_counts=counts)
    assert status_full == "ESTABLISHED"
    assert is_mature_full is True
    assert conf_full == 1.0


def test_15_admin_profile_and_model_metadata_endpoints(client: TestClient, db_session):
    """
    Requirement: Admin endpoints /users/{id}/profile and /users/{id}/model-metadata
    accurately expose modality_sample_counts and modality_maturity.
    """
    admin_user = get_or_create_test_user(db_session, "soc_admin_f10@cognisec.ai")
    admin_user.role = "ADMIN"
    db_session.commit()

    target_user = get_or_create_test_user(db_session, "target_f10@example.com")
    profile = ProfileService.get_or_create_profile(db_session, target_user.id)

    from app.core.security import create_access_token
    token = create_access_token(subject=str(admin_user.id), role="ADMIN")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Inspect /api/admin/users/{id}/profile
    res = client.get(f"/api/admin/users/{target_user.id}/profile", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "modality_sample_counts" in data
    assert "modality_maturity" in data
    for mod in ["keyboard", "mouse", "scroll", "navigation", "inactivity"]:
        assert mod in data["modality_sample_counts"]
        assert mod in data["modality_maturity"]

    # 2. Inspect /api/admin/users/{id}/model-metadata
    res_meta = client.get(f"/api/admin/users/{target_user.id}/model-metadata", headers=headers)
    assert res_meta.status_code == 200
    meta = res_meta.json()
    assert "baseline_maturity" in meta
    assert "modality_sample_counts" in meta
    assert "modality_maturity" in meta


