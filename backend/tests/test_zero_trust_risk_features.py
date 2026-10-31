import time
import uuid
import pytest
import numpy as np
from unittest.mock import patch
from datetime import datetime, timezone, timedelta

from app.models.user import User
from app.models.session import Session as DbSession
from app.models.device import Device
from app.models.application_grant import ApplicationGrant
from app.models.behavior import BehaviorProfile
from app.services.session_service import SessionService
from app.services.risk_service import RiskService
from app.services.decision_service import DecisionService
from app.services.access_tracker import ConfidentialAccessTracker
from app.services.behavior_drift_service import BehavioralDriftTracker
from app.services.geo_service import GeoLocationService
from app.core.config import settings
from app.core.security import create_access_token


@pytest.fixture(autouse=True)
def reset_trackers():
    """Ensure clean isolation between tests."""
    ConfidentialAccessTracker.reset_all()
    BehavioralDriftTracker.reset_all()
    yield
    ConfidentialAccessTracker.reset_all()
    BehavioralDriftTracker.reset_all()


@pytest.fixture
def registered_user(client):
    uid = uuid.uuid4().hex[:8]
    email = f"zt_{uid}@cognisec.ai"
    res = client.post("/api/auth/register", json={
        "name": f"ZeroTrust User {uid}",
        "email": email,
        "password": "Password123!",
        "role": "USER"
    })
    assert res.status_code == 201
    return res.json(), email, "Password123!"


@pytest.fixture
def auth_session(client, registered_user, db_session):
    user_data, email, password = registered_user
    res = client.post("/api/auth/login", json={
        "email": email,
        "password": password,
        "application": "college",
        "device_fingerprint": f"dev_zt_{user_data['id']}"
    })
    assert res.status_code == 200
    data = res.json()
    token = data["access_token"]
    session_id = data["session_id"]

    # Activate session in DB so it can perform active actions
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


# =====================================================================
# FEATURE 1: Repeated Confidential-Access Attempts
# =====================================================================

def test_1_five_server_side_denials_within_60s_trigger_risk_signal(client, auth_session, db_session):
    """
    Scenario 1: 5 server-side denials within 60s contribute configured risk signal,
    escalating session risk.
    """
    headers = auth_session["headers"]
    user_id = auth_session["user_id"]
    session_id = auth_session["session_id"]

    # Session has no grant for academic_vault, so requests will be denied (403)
    for i in range(4):
        # Use slightly distinct query params or timestamps to avoid 1.0s dedup
        time.sleep(1.05)
        res = client.get(f"/api/security/vault/academic_vault?session_id={session_id}", headers=headers)
        assert res.status_code == 403

    # Check tracker has recorded 4 attempts
    denials = ConfidentialAccessTracker.get_recent_denials_count(user_id, session_id, window_seconds=60)
    assert denials == 4

    # 5th attempt within 60s reaches threshold
    time.sleep(1.05)
    res5 = client.get(f"/api/security/vault/academic_vault?session_id={session_id}", headers=headers)
    assert res5.status_code == 403

    denials5 = ConfidentialAccessTracker.get_recent_denials_count(user_id, session_id, window_seconds=60)
    assert denials5 >= 5

    # Check that session risk was evaluated and elevated to at least MEDIUM
    db_s = db_session.query(DbSession).filter(DbSession.id == session_id).first()
    assert db_s.current_risk_level in ("MEDIUM", "HIGH", "CRITICAL")
    assert db_s.status in ("STEP_UP_REQUIRED", "RESTRICTED", "TERMINATED")


def test_2_denials_outside_rolling_window_not_counted(auth_session):
    """
    Scenario 2: Attempts outside the rolling window are expired and not counted.
    """
    user_id = auth_session["user_id"]
    session_id = auth_session["session_id"]

    # Record 4 old denials 70 seconds ago
    with ConfidentialAccessTracker._lock:
        key = ConfidentialAccessTracker._make_key(user_id, session_id)
        old_time = time.time() - 70.0
        ConfidentialAccessTracker._denial_history[key] = [
            (old_time, "academic_vault"),
            (old_time + 1, "academic_vault"),
            (old_time + 2, "academic_vault"),
            (old_time + 3, "academic_vault"),
        ]

    # Current count within 60s should be 0
    active_denials = ConfidentialAccessTracker.get_recent_denials_count(user_id, session_id, window_seconds=60)
    assert active_denials == 0

    # Record 1 fresh attempt now
    count_now = ConfidentialAccessTracker.record_denial(user_id, session_id, "academic_vault", window_seconds=60)
    assert count_now == 1


def test_3_direct_api_requests_counted_correctly(client, auth_session):
    """
    Scenario 3: Direct API calls to protected vaults increment the server-side counter.
    """
    headers = auth_session["headers"]
    user_id = auth_session["user_id"]
    session_id = auth_session["session_id"]

    for i in range(3):
        time.sleep(1.05)
        res = client.get(f"/api/security/vault/ehr_vault?session_id={session_id}", headers=headers)
        assert res.status_code == 403

    count = ConfidentialAccessTracker.get_recent_denials_count(user_id, session_id)
    assert count == 3


def test_4_duplicate_requests_within_dedup_window_not_inflated(auth_session):
    """
    Scenario 4: Rapid requests within the 1.0s dedup window do not inflate counts.
    """
    user_id = auth_session["user_id"]
    session_id = auth_session["session_id"]

    # 5 calls in rapid succession (within milliseconds) for the same resource
    c1 = ConfidentialAccessTracker.record_denial(user_id, session_id, "financial_vault", dedup_seconds=1.0)
    c2 = ConfidentialAccessTracker.record_denial(user_id, session_id, "financial_vault", dedup_seconds=1.0)
    c3 = ConfidentialAccessTracker.record_denial(user_id, session_id, "financial_vault", dedup_seconds=1.0)
    assert c1 == 1
    assert c2 == 1
    assert c3 == 1

    # After sleeping 1.05s, a subsequent call is counted
    time.sleep(1.05)
    c4 = ConfidentialAccessTracker.record_denial(user_id, session_id, "financial_vault", dedup_seconds=1.0)
    assert c4 == 2


# =====================================================================
# FEATURE 2: Continuous Behavioural Drift Detection
# =====================================================================

def test_5_behavioural_drift_across_multiple_observations_triggers_risk(db_session, auth_session):
    """
    Scenario 5: Sustained deviations across multiple continuous observations trigger
    behavioural drift detection and risk escalation.
    """
    user_id = auth_session["user_id"]
    session_id = auth_session["session_id"]

    # Enrolled user with mature profile
    profile = db_session.query(BehaviorProfile).filter(BehaviorProfile.user_id == user_id).first()
    if not profile:
        profile = BehaviorProfile(user_id=user_id, sample_count=10)
        db_session.add(profile)
    else:
        profile.sample_count = 10
    db_session.commit()

    # Simulate 3 consecutive observations with significant deviation (0.75)
    with patch("app.ml.anomaly_detector.IsolationForestDetector.predict_anomaly", return_value=(True, 0.75, "ML_READY")):
        vec = np.array([120.0, 300.0, 250.0, 4500.0, 12000.0, 0.9, 8.0, 600.0, 1.0, 0.85])

        # Obs 1
        r1, a1, lvl1, factors1, is_anom1, _ = RiskService.calculate_risk(
            db=db_session,
            user_id=user_id,
            session_id=session_id,
            application="college",
            behavior_vector=vec,
            context_signals={}
        )

        # Obs 2
        r2, a2, lvl2, factors2, is_anom2, _ = RiskService.calculate_risk(
            db=db_session,
            user_id=user_id,
            session_id=session_id,
            application="college",
            behavior_vector=vec,
            context_signals={}
        )

        # Obs 3
        r3, a3, lvl3, factors3, is_anom3, _ = RiskService.calculate_risk(
            db=db_session,
            user_id=user_id,
            session_id=session_id,
            application="college",
            behavior_vector=vec,
            context_signals={}
        )

    # Sustained drift across multiple observations triggers MEDIUM or higher
    assert lvl3 in ("MEDIUM", "HIGH")
    assert any("drift" in f.lower() for f in factors3)
    assert is_anom3 is True


def test_6_single_noisy_sample_does_not_cause_inappropriate_escalation(db_session, auth_session):
    """
    Scenario 6: A single noisy sample with no contextual risk is dampened as transient variance
    and does not inappropriately force HIGH or CRITICAL escalation.
    """
    user_id = auth_session["user_id"]
    session_id = auth_session["session_id"]

    profile = db_session.query(BehaviorProfile).filter(BehaviorProfile.user_id == user_id).first()
    if profile:
        profile.sample_count = 10
        db_session.commit()

    # Single isolated spike (0.65) with zero context risk (trusted device, normal location)
    with patch("app.ml.anomaly_detector.IsolationForestDetector.predict_anomaly", return_value=(True, 0.65, "ML_READY")):
        vec = np.zeros(10)
        risk_score, anomaly_score, risk_level, factors, is_anomaly, _ = RiskService.calculate_risk(
            db=db_session,
            user_id=user_id,
            session_id=session_id,
            application="college",
            behavior_vector=vec,
            context_signals={"is_new_device": False, "is_device_trusted": True}
        )

    # Dampened single spike should NOT jump to HIGH or CRITICAL
    assert risk_level in ("LOW", "MEDIUM")
    assert risk_score < 0.65
    assert any("transient" in f.lower() or "dampened" in f.lower() for f in factors)


def test_7_baseline_poisoning_prevented(client, auth_session, db_session):
    """
    Scenario 7: Anomalous or drifting telemetry is strictly prevented from updating the baseline.
    """
    user_id = auth_session["user_id"]
    session_id = auth_session["session_id"]
    headers = auth_session["headers"]

    profile = db_session.query(BehaviorProfile).filter(BehaviorProfile.user_id == user_id).first()
    initial_samples = profile.sample_count if profile else 0

    # Submit telemetry that triggers high anomaly
    with patch("app.services.risk_service.RiskService.calculate_risk", return_value=(0.75, 0.80, "HIGH", ["Anomalous drift"], True, "MODEL_EVALUATED")):
        res = client.post("/api/behavior/events", headers=headers, json={
            "session_id": session_id,
            "application": "college",
            "typing_speed_wpm": 180.0,
            "avg_flight_time_ms": 10.0,
            "avg_dwell_time_ms": 10.0,
            "mouse_velocity_avg": 5000.0,
            "mouse_acceleration_avg": 12000.0,
            "mouse_curvature_entropy": 0.9,
            "click_frequency": 4.0,
            "scroll_speed_avg": 200.0,
            "idle_duration_sec": 0.5,
            "navigation_entropy": 0.8,
            "sequence_number": 1
        })
        assert res.status_code == 200

    db_session.refresh(profile) if profile else None
    current_samples = profile.sample_count if profile else 0
    # Samples count must NOT have increased for anomalous telemetry
    assert current_samples == initial_samples


# =====================================================================
# FEATURE 3: Device and Session Anomaly Detection
# =====================================================================

def test_8_new_device_combines_with_suspicious_evidence(db_session, auth_session):
    """
    Scenario 8: A new device alone produces low/moderate signal; when combined with
    behavioral deviation or repeated denials, it appropriately escalates risk.
    """
    user_id = auth_session["user_id"]
    session_id = auth_session["session_id"]

    profile = db_session.query(BehaviorProfile).filter(BehaviorProfile.user_id == user_id).first()
    if profile:
        profile.sample_count = 10
        db_session.commit()

    # 1. New device alone (normal behavior)
    with patch("app.ml.anomaly_detector.IsolationForestDetector.predict_anomaly", return_value=(False, 0.10, "ML_READY")):
        r_solo, _, lvl_solo, f_solo, _, _ = RiskService.calculate_risk(
            db=db_session,
            user_id=user_id,
            session_id=session_id,
            application="college",
            behavior_vector=np.zeros(10),
            context_signals={"is_new_device": True}
        )
    # A new device alone must not be CRITICAL or force termination
    assert lvl_solo in ("LOW", "MEDIUM")
    assert r_solo < 0.30

    # 2. New device combined with behavioral deviation (0.65) + prior denial
    with patch("app.ml.anomaly_detector.IsolationForestDetector.predict_anomaly", return_value=(True, 0.65, "ML_READY")):
        r_comb, _, lvl_comb, f_comb, _, _ = RiskService.calculate_risk(
            db=db_session,
            user_id=user_id,
            session_id=session_id,
            application="college",
            behavior_vector=np.zeros(10),
            context_signals={"is_new_device": True, "denied_access_count": 5}
        )
    # Combined novelty + 5 denials + anomaly escalates to HIGH
    assert lvl_comb in ("HIGH", "CRITICAL")
    assert r_comb >= 0.65


def test_9_invalid_or_replayed_tokens_rejected(client, auth_session, db_session):
    """
    Scenario 9: Replayed, revoked, or terminated session tokens are rejected with 401.
    """
    session_id = auth_session["session_id"]
    token = auth_session["token"]

    # 1. Valid request works
    res1 = client.get(f"/api/auth/observation-status/{session_id}", headers={"Authorization": f"Bearer {token}"})
    assert res1.status_code == 200

    # 2. Terminate the session server-side
    SessionService.terminate_session(db_session, session_id, risk_level="CRITICAL")

    # 3. Subsequent request with the same token must be rejected (401)
    res2 = client.get(f"/api/auth/observation-status/{session_id}", headers={"Authorization": f"Bearer {token}"})
    assert res2.status_code == 401
    assert "terminated" in res2.json()["detail"].lower() or "revoked" in res2.json()["detail"].lower()


def test_10_cross_user_isolation_of_counters_and_state(auth_session, client):
    """
    Scenario 10: Denial counters and drift histories are strictly isolated across users/sessions.
    """
    user_a = auth_session["user_id"]
    session_a = auth_session["session_id"]

    # Register user B
    uid_b = uuid.uuid4().hex[:8]
    res_b = client.post("/api/auth/register", json={
        "name": f"User B {uid_b}",
        "email": f"b_{uid_b}@cognisec.ai",
        "password": "Password123!",
        "role": "USER"
    })
    user_b = res_b.json()["id"]
    session_b = f"sess_b_{uid_b}"

    # Record 4 denials for User A
    for _ in range(4):
        time.sleep(1.05)
        ConfidentialAccessTracker.record_denial(user_a, session_a, "academic_vault")

    # User B should have 0 denials
    assert ConfidentialAccessTracker.get_recent_denials_count(user_b, session_b) == 0
    assert ConfidentialAccessTracker.get_recent_denials_count(user_a, session_a) == 4


def test_11_implausible_travel_velocity_detection():
    """
    Scenario 11: Implausible travel calculations correctly flag impossible velocities.
    """
    # NYC to London (~5570 km)
    nyc_lat, nyc_lon = 40.7128, -74.0060
    lon_lat, lon_lon = 51.5074, -0.1278

    t0 = datetime.now(timezone.utc)
    t_15min = t0 + timedelta(minutes=15)  # 5570 km in 15 minutes is ~22,000 km/h (impossible)

    is_imp, dist, speed = GeoLocationService.check_implausible_travel(
        lat1=nyc_lat,
        lon1=nyc_lon,
        time1=t0,
        lat2=lon_lat,
        lon2=lon_lon,
        time2=t_15min,
        max_speed_kmh=900.0
    )
    assert is_imp is True
    assert dist > 5000.0
    assert speed > 900.0

    # Plausible trip: 500 km in 2 hours (~250 km/h, high-speed rail)
    t_2hr = t0 + timedelta(hours=2)
    is_imp2, dist2, speed2 = GeoLocationService.check_implausible_travel(
        lat1=nyc_lat,
        lon1=nyc_lon,
        time1=t0,
        lat2=nyc_lat + 4.0,
        lon2=nyc_lon,
        time2=t_2hr,
        max_speed_kmh=900.0
    )
    assert is_imp2 is False


def test_12_existing_threshold_boundaries_preserved(db_session):
    """
    Scenario 12: Verify exact threshold boundaries:
    LOW: < 0.30, MEDIUM: 0.30 - < 0.65, HIGH: 0.65 - < 0.85, CRITICAL: >= 0.85
    """
    assert settings.RISK_THRESHOLD_LOW == 0.30
    assert settings.RISK_THRESHOLD_MEDIUM == 0.65
    assert settings.RISK_THRESHOLD_HIGH == 0.85
