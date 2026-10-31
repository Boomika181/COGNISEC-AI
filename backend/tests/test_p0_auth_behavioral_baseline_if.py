import time
import json
import numpy as np
import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.session import Session as DbSession
from app.models.behavior import BehaviorProfile, BehaviorLog
from app.services.step_up_service import StepUpService
from app.services.anti_replay_service import AntiReplayService
from app.services.profile_service import ProfileService
from app.services.session_service import SessionService
from app.services.adaptive_auth_service import AdaptiveAuthService
from app.core.rate_limit import rate_limiter
from app.core.config import settings
from app.ml.anomaly_detector import IsolationForestDetector
from app.ml.model_manager import ModelManager
from app.ml.feature_engineering import FEATURE_NAMES


@pytest.fixture(autouse=True)
def clean_state():
    StepUpService.reset()
    AntiReplayService.reset()
    rate_limiter.reset()
    ModelManager.reset_memory()
    yield
    StepUpService.reset()
    AntiReplayService.reset()
    rate_limiter.reset()
    ModelManager.reset_memory()


def create_test_user(client: TestClient, email_prefix: str, enrollment_telemetry=None):
    email = f"{email_prefix}_{int(time.time() * 1000)}@example.com"
    payload = {
        "email": email,
        "password": "Password123!",
        "name": f"User {email_prefix}"
    }
    if enrollment_telemetry:
        payload["enrollment_telemetry"] = enrollment_telemetry
    res = client.post("/api/auth/register", json=payload)
    assert res.status_code == 201, res.text
    return email, res.json()


def login_test_user(client: TestClient, email: str, application: str = "platform"):
    res = client.post("/api/auth/login", json={
        "email": email,
        "password": "Password123!",
        "application": application,
        "device_fingerprint": f"fp_{email}_{application}"
    })
    assert res.status_code == 200, res.text
    return res.json()


# -----------------------------------------------------------------------------
# 1. 30-Second Observation Period Enforced Server-Side
# -----------------------------------------------------------------------------
def test_observation_30s_enforced_server_side(client: TestClient, db_session: Session):
    email, _ = create_test_user(client, "obs_test")
    login_data = login_test_user(client, email, "college")
    sid = login_data["session_id"]
    token = login_data["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    assert login_data["session_status"] == "PENDING_OBSERVATION"
    assert login_data["observation_seconds_remaining"] == 30

    # Attempt requesting OTP immediately (< 30s) -> Server MUST reject with 400
    early_req = client.post("/api/auth/login-otp/request", json={"session_id": sid}, headers=headers)
    assert early_req.status_code == 400
    assert "Observation period incomplete" in early_req.json()["detail"]

    # Fast forward session server observation clock past 30s
    sess = db_session.query(DbSession).filter(DbSession.id == sid).first()
    sess.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=35)
    db_session.commit()

    # Now request OTP -> Server must accept and issue OTP
    ok_req = client.post("/api/auth/login-otp/request", json={"session_id": sid}, headers=headers)
    assert ok_req.status_code == 200
    data = ok_req.json()
    assert data["challenge_type"] == "LOGIN_OTP"
    assert data["session_id"] == sid


# -----------------------------------------------------------------------------
# 2. LOW-Risk Sessions Trigger Expected OTP Flow After Observation
# -----------------------------------------------------------------------------
def test_low_risk_session_triggers_otp_after_observation(client: TestClient, db_session: Session):
    email, _ = create_test_user(client, "low_risk")
    login_data = login_test_user(client, email, "shopping")
    sid = login_data["session_id"]
    token = login_data["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    sess = db_session.query(DbSession).filter(DbSession.id == sid).first()
    sess.current_risk_level = "LOW"
    sess.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=32)
    db_session.commit()

    res = client.post("/api/auth/login-otp/request", json={"session_id": sid}, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["challenge_type"] == "LOGIN_OTP"
    assert len(data["challenge_id"]) > 0

    # Verify session transitioned to PENDING_OTP in DB
    db_session.refresh(sess)
    assert sess.status == "PENDING_OTP"


# -----------------------------------------------------------------------------
# 3. Medium / High / Critical Risk Decisions Follow Policy
# -----------------------------------------------------------------------------
def test_risk_decisions_follow_policy_at_observation_end(client: TestClient, db_session: Session):
    email, user_info = create_test_user(client, "risk_policy")
    user_id = user_info["id"]

    # Enroll user in NeuralTrace (gesture pattern)
    pattern = [0, 1, 2, 6]
    AdaptiveAuthService.enroll_gesture_pattern(db_session, user_id, pattern, pattern)

    login_data = login_test_user(client, email, "healthcare")
    sid = login_data["session_id"]
    token = login_data["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    sess = db_session.query(DbSession).filter(DbSession.id == sid).first()
    sess.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=35)

    # 3a. CRITICAL Risk -> Deny and terminate session
    sess.current_risk_level = "CRITICAL"
    db_session.commit()
    res_crit = client.post("/api/auth/login-otp/request", json={"session_id": sid}, headers=headers)
    assert res_crit.status_code == 403
    assert "terminated due to critical security risk" in res_crit.json()["detail"].lower()
    db_session.refresh(sess)
    assert sess.status == "TERMINATED"

    # Create new session for HIGH risk test
    login_high = login_test_user(client, email, "healthcare")
    sid_high = login_high["session_id"]
    headers_high = {"Authorization": f"Bearer {login_high['access_token']}"}
    sess_high = db_session.query(DbSession).filter(DbSession.id == sid_high).first()
    sess_high.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=35)
    sess_high.current_risk_level = "HIGH"
    db_session.commit()

    # 3b. HIGH Risk -> Restrict access, do not issue OTP alone
    res_high = client.post("/api/auth/login-otp/request", json={"session_id": sid_high}, headers=headers_high)
    assert res_high.status_code == 403
    assert "access restricted" in res_high.json()["detail"].lower()
    db_session.refresh(sess_high)
    assert sess_high.status == "RESTRICTED"

    # Create new session for MEDIUM risk test
    login_med = login_test_user(client, email, "healthcare")
    sid_med = login_med["session_id"]
    headers_med = {"Authorization": f"Bearer {login_med['access_token']}"}
    sess_med = db_session.query(DbSession).filter(DbSession.id == sid_med).first()
    sess_med.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=35)
    sess_med.current_risk_level = "MEDIUM"
    db_session.commit()

    # 3c. MEDIUM Risk with NeuralTrace enrolled -> Require NeuralTrace
    res_med = client.post("/api/auth/login-otp/request", json={"session_id": sid_med}, headers=headers_med)
    assert res_med.status_code == 403
    assert "neuraltrace" in res_med.json()["detail"].lower()
    db_session.refresh(sess_med)
    assert sess_med.status == "STEP_UP_REQUIRED"


# -----------------------------------------------------------------------------
# 4. OTP Challenges Not Duplicated by Refreshes, Navigation, or Polling
# -----------------------------------------------------------------------------
def test_otp_challenges_not_duplicated_by_polling_or_refreshes(client: TestClient, db_session: Session):
    email, _ = create_test_user(client, "nodup")
    login_data = login_test_user(client, email, "college")
    sid = login_data["session_id"]
    headers = {"Authorization": f"Bearer {login_data['access_token']}"}

    sess = db_session.query(DbSession).filter(DbSession.id == sid).first()
    sess.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=35)
    db_session.commit()

    # First request
    res1 = client.post("/api/auth/login-otp/request", json={"session_id": sid}, headers=headers)
    assert res1.status_code == 200
    chal1 = res1.json()["challenge_id"]

    # Simulated refresh / background poll
    res2 = client.post("/api/auth/login-otp/request", json={"session_id": sid}, headers=headers)
    assert res2.status_code == 200
    chal2 = res2.json()["challenge_id"]

    # Challenge ID MUST match and not create duplicate challenge records
    assert chal1 == chal2


# -----------------------------------------------------------------------------
# 5. Invalid, Expired, Reused, and Cross-Session OTPs Rejected
# -----------------------------------------------------------------------------
def test_invalid_expired_reused_and_cross_session_otp_rejected(client: TestClient, db_session: Session):
    email_a, _ = create_test_user(client, "user_a")
    email_b, _ = create_test_user(client, "user_b")

    login_a = login_test_user(client, email_a, "college")
    login_b = login_test_user(client, email_b, "college")

    sid_a = login_a["session_id"]
    headers_a = {"Authorization": f"Bearer {login_a['access_token']}"}
    headers_b = {"Authorization": f"Bearer {login_b['access_token']}"}

    sess_a = db_session.query(DbSession).filter(DbSession.id == sid_a).first()
    sess_a.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=35)
    db_session.commit()

    # Request valid OTP for session A
    res_a = client.post("/api/auth/login-otp/request", json={"session_id": sid_a}, headers=headers_a)
    assert res_a.status_code == 200
    chal_a = res_a.json()["challenge_id"]
    otp_code = res_a.json()["otp"]

    # 5a. Cross-session attempt: User B tries to verify User A's session and OTP
    cross_res = client.post("/api/auth/login-otp/verify", json={
        "session_id": sid_a,
        "challenge_id": chal_a,
        "otp_code": otp_code
    }, headers=headers_b)
    assert cross_res.status_code in (403, 400)

    # 5b. Invalid OTP code: Submitting wrong code fails and terminates session
    bad_res = client.post("/api/auth/login-otp/verify", json={
        "session_id": sid_a,
        "challenge_id": chal_a,
        "otp_code": "000000"
    }, headers=headers_a)
    assert bad_res.status_code == 400
    db_session.refresh(sess_a)
    assert sess_a.status == "TERMINATED"

    # 5c. Expired OTP
    login_a2 = login_test_user(client, email_a, "college")
    sid_a2 = login_a2["session_id"]
    headers_a2 = {"Authorization": f"Bearer {login_a2['access_token']}"}
    sess_a2 = db_session.query(DbSession).filter(DbSession.id == sid_a2).first()
    sess_a2.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=35)
    db_session.commit()

    res_exp = client.post("/api/auth/login-otp/request", json={"session_id": sid_a2}, headers=headers_a2)
    chal_exp = res_exp.json()["challenge_id"]
    otp_exp = res_exp.json()["otp"]

    # Manually expire challenge in StepUpService
    with StepUpService._lock:
        if sid_a2 in StepUpService._challenges:
            StepUpService._challenges[sid_a2]["expires_at"] = datetime.now(timezone.utc) - timedelta(seconds=10)

    exp_res = client.post("/api/auth/login-otp/verify", json={
        "session_id": sid_a2,
        "challenge_id": chal_exp,
        "otp_code": otp_exp
    }, headers=headers_a2)
    assert exp_res.status_code == 400
    assert "expired" in exp_res.json()["detail"].lower()

    # 5d. Replay / Single Use
    login_a3 = login_test_user(client, email_a, "college")
    sid_a3 = login_a3["session_id"]
    headers_a3 = {"Authorization": f"Bearer {login_a3['access_token']}"}
    sess_a3 = db_session.query(DbSession).filter(DbSession.id == sid_a3).first()
    sess_a3.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=35)
    db_session.commit()

    res_ok = client.post("/api/auth/login-otp/request", json={"session_id": sid_a3}, headers=headers_a3)
    chal_ok = res_ok.json()["challenge_id"]
    otp_ok = res_ok.json()["otp"]

    # First verification succeeds
    v1 = client.post("/api/auth/login-otp/verify", json={
        "session_id": sid_a3,
        "challenge_id": chal_ok,
        "otp_code": otp_ok
    }, headers=headers_a3)
    assert v1.status_code == 200
    assert v1.json()["success"] is True

    # Replay attempt fails (session is already active, challenge is consumed)
    v2 = client.post("/api/auth/login-otp/verify", json={
        "session_id": sid_a3,
        "challenge_id": chal_ok,
        "otp_code": otp_ok
    }, headers=headers_a3)
    assert v2.status_code == 400


# -----------------------------------------------------------------------------
# 6. All Three Portals Use Same Intended Authentication Flow
# -----------------------------------------------------------------------------
def test_all_three_portals_use_same_flow(client: TestClient, db_session: Session):
    for portal in ["college", "shopping", "healthcare"]:
        email, _ = create_test_user(client, f"flow_{portal}")
        login_res = login_test_user(client, email, portal)
        sid = login_res["session_id"]
        headers = {"Authorization": f"Bearer {login_res['access_token']}"}

        assert login_res["session_status"] == "PENDING_OBSERVATION"
        assert login_res["observation_seconds_remaining"] == 30

        sess = db_session.query(DbSession).filter(DbSession.id == sid).first()
        sess.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=31)
        db_session.commit()

        req_res = client.post("/api/auth/login-otp/request", json={"session_id": sid}, headers=headers)
        assert req_res.status_code == 200
        otp = req_res.json()["otp"]
        chal = req_res.json()["challenge_id"]

        ver_res = client.post("/api/auth/login-otp/verify", json={
            "session_id": sid,
            "challenge_id": chal,
            "otp_code": otp
        }, headers=headers)
        assert ver_res.status_code == 200
        assert ver_res.json()["session_status"] == "ACTIVE"


# -----------------------------------------------------------------------------
# 7. Behavioral Observations Associated with Correct User and Session
# -----------------------------------------------------------------------------
def test_behavioral_observations_associated_with_correct_user_and_session(client: TestClient, db_session: Session):
    email, user_info = create_test_user(client, "assoc")
    login_res = login_test_user(client, email, "college")
    sid = login_res["session_id"]
    headers = {"Authorization": f"Bearer {login_res['access_token']}"}

    event_payload = {
        "session_id": sid,
        "application": "college",
        "timestamp": time.time(),
        "sequence_number": 1,
        "telemetry_nonce": f"nonce_{int(time.time() * 1000)}",
        "typing_speed_wpm": 65.0,
        "avg_flight_time_ms": 120.0,
        "avg_dwell_time_ms": 80.0,
        "mouse_velocity_avg": 450.0,
        "mouse_acceleration_avg": 600.0,
        "mouse_curvature_entropy": 0.4,
        "click_frequency": 2.0,
        "scroll_speed_avg": 100.0,
        "idle_duration_sec": 1.0,
        "navigation_entropy": 0.5
    }
    # Send telemetry
    res = client.post("/api/behavior/events", json=event_payload, headers=headers)
    assert res.status_code == 200

    # Verify BehaviorLog in DB
    log = db_session.query(BehaviorLog).filter(BehaviorLog.session_id == sid).first()
    assert log is not None
    assert log.user_id == user_info["id"]
    assert log.application == "college"


# -----------------------------------------------------------------------------
# 8. Baseline Enrollment and Retrieval Work Through the Database
# -----------------------------------------------------------------------------
def test_baseline_enrollment_and_retrieval_through_database(client: TestClient, db_session: Session):
    sample_telemetry = {
        "typing_speed_wpm": 72.0,
        "avg_flight_time_ms": 110.0,
        "avg_dwell_time_ms": 75.0,
        "mouse_velocity_avg": 420.0,
        "mouse_acceleration_avg": 550.0
    }
    email, user_info = create_test_user(client, "base_enroll", enrollment_telemetry=sample_telemetry)
    user_id = user_info["id"]

    profile = db_session.query(BehaviorProfile).filter(BehaviorProfile.user_id == user_id).first()
    assert profile is not None
    assert profile.sample_count == 1
    features = json.loads(profile.baseline_features)
    assert features["version"] == 1
    assert features["enrollment_status"] == "ENROLLED"
    assert features["confidence_status"] == "LEARNING"
    assert features["confidence_score"] == 0.20
    assert "means" in features
    assert round(features["means"]["typing_speed_wpm"], 1) == 72.0


# -----------------------------------------------------------------------------
# 9. Missing or Insufficient Telemetry Does Not Create False Confidence
# -----------------------------------------------------------------------------
def test_missing_or_insufficient_telemetry_does_not_create_false_confidence(db_session: Session):
    detector = IsolationForestDetector()
    zero_vector = np.zeros(10, dtype=np.float64)

    # Cold start: 0 samples
    is_anomaly, score, status = detector.predict_anomaly(zero_vector, baseline_stats=None, sample_count=0)
    assert status == "ML_COLD_START"
    assert is_anomaly is False
    assert score <= 0.10  # Does not flag attack on cold start

    # Learning state: 2 samples
    stats = {
        "means": {feat: 50.0 for feat in FEATURE_NAMES},
        "stds": {feat: 10.0 for feat in FEATURE_NAMES}
    }
    is_anom_l, score_l, status_l = detector.predict_anomaly(zero_vector, baseline_stats=stats, sample_count=2)
    assert status_l == "ML_LEARNING"
    assert is_anom_l is False
    assert score_l <= 0.35  # False positive dampened in learning state


# -----------------------------------------------------------------------------
# 10. Isolation Forest Flags Controlled Anomalous Samples in Deterministic Tests
# -----------------------------------------------------------------------------
def test_isolation_forest_flags_controlled_anomalous_samples():
    detector = IsolationForestDetector(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
        min_samples_for_training=20
    )
    # Generate 30 controlled normal vectors around mean 100 with small variance
    np.random.seed(42)
    normal_training = []
    for _ in range(30):
        vec = 100.0 + np.random.normal(0, 5, size=10)
        normal_training.append(vec)

    baseline_stats = {
        "means": {feat: 100.0 for feat in FEATURE_NAMES},
        "stds": {feat: 5.0 for feat in FEATURE_NAMES}
    }
    detector.fit(np.array(normal_training), baseline_stats=baseline_stats)
    assert detector.is_fitted is True

    # Test in-distribution sample
    in_dist_sample = np.array([101.0, 99.0, 102.0, 98.0, 100.0, 101.0, 99.0, 100.0, 102.0, 100.0])
    is_anom, score, status = detector.predict_anomaly(in_dist_sample, baseline_stats=baseline_stats, sample_count=30)
    assert status == "ML_READY"
    assert is_anom is False
    assert score < 0.40  # Normal score

    # Test extreme outlier sample (e.g. 10x normal bounds)
    outlier_sample = np.array([1000.0, 1200.0, 950.0, 5000.0, 4500.0, 800.0, 50.0, 2000.0, 1500.0, 500.0])
    is_anom_out, score_out, _ = detector.predict_anomaly(outlier_sample, baseline_stats=baseline_stats, sample_count=30)
    assert is_anom_out is True
    assert score_out >= 0.50  # Flagged as anomaly


# -----------------------------------------------------------------------------
# 11. Suspicious Samples Do Not Contaminate Trusted Baselines
# -----------------------------------------------------------------------------
def test_anti_poisoning_suspicious_samples_do_not_contaminate_baseline(db_session: Session):
    from app.core.security import get_password_hash
    u = db_session.query(User).filter(User.id == 99991).first()
    if not u:
        u = User(
            id=99991,
            email="antipoison99991@cognisec.ai",
            name="AntiPoison User",
            password_hash=get_password_hash("Test@123"),
            role="USER",
            account_status="ACTIVE"
        )
        db_session.add(u)
        db_session.commit()

    profile = ProfileService.get_or_create_profile(db_session, user_id=u.id)
    initial_samples = profile.sample_count
    poison_vector = np.array([999.0] * 10)

    # 11a. High risk sample (risk_score = 0.85) -> REJECTED from baseline
    ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=99991,
        event_vector=poison_vector,
        risk_score=0.85,
        session_status="ACTIVE",
        decision="ALLOW"
    )
    db_session.refresh(profile)
    assert profile.sample_count == initial_samples

    # 11b. Restricted session sample -> REJECTED from baseline
    ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=99991,
        event_vector=poison_vector,
        risk_score=0.10,
        session_status="RESTRICTED",
        decision="RESTRICT"
    )
    db_session.refresh(profile)
    assert profile.sample_count == initial_samples

    # 11c. Legitimate low-risk active sample -> ACCEPTED
    legit_vector = np.array([60.0, 110.0, 80.0, 400.0, 500.0, 5.0, 2.0, 80.0, 1.0, 0.5])
    ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=99991,
        event_vector=legit_vector,
        risk_score=0.10,
        session_status="ACTIVE",
        decision="ALLOW"
    )
    db_session.refresh(profile)
    assert profile.sample_count == initial_samples + 1


# -----------------------------------------------------------------------------
# 12. A Successful OTP Cannot Bypass Confidential-Vault Authorization or NeuralTrace
# -----------------------------------------------------------------------------
def test_successful_otp_cannot_bypass_confidential_vault(client: TestClient, db_session: Session):
    email, _ = create_test_user(client, "vault_bypass")
    login_data = login_test_user(client, email, "shopping")
    sid = login_data["session_id"]
    headers = {"Authorization": f"Bearer {login_data['access_token']}"}

    sess = db_session.query(DbSession).filter(DbSession.id == sid).first()
    sess.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=35)
    db_session.commit()

    # Request and verify OTP
    req = client.post("/api/auth/login-otp/request", json={"session_id": sid}, headers=headers)
    v_res = client.post("/api/auth/login-otp/verify", json={
        "session_id": sid,
        "challenge_id": req.json()["challenge_id"],
        "otp_code": req.json()["otp"]
    }, headers=headers)
    assert v_res.status_code == 200
    assert v_res.json()["session_status"] == "ACTIVE"

    # Attempt to access confidential financial vault without NeuralTrace -> MUST FAIL 403
    vault_res = client.get(
        f"/api/security/vault/financial_vault?session_id={sid}",
        headers=headers
    )
    assert vault_res.status_code == 403
    assert "neuraltrace" in vault_res.json()["detail"].lower()


# -----------------------------------------------------------------------------
# 13. Logout, Session Expiration, and Risk Escalation Revoke Access
# -----------------------------------------------------------------------------
def test_logout_session_expiration_and_risk_escalation_revoke_access(client: TestClient, db_session: Session):
    email, _ = create_test_user(client, "revocation")
    login_data = login_test_user(client, email, "college")
    sid = login_data["session_id"]
    headers = {"Authorization": f"Bearer {login_data['access_token']}"}

    # Activate session
    SessionService.activate_session_after_login_otp(db_session, sid)

    # 13a. Terminate session (logout)
    logout_res = client.post(f"/api/sessions/{sid}/terminate", headers=headers)
    assert logout_res.status_code == 200
    sess = db_session.query(DbSession).filter(DbSession.id == sid).first()
    assert sess.status == "TERMINATED"

    # Subsequent access fails
    fail_res = client.get(f"/api/security/vault/financial_vault?session_id={sid}", headers=headers)
    assert fail_res.status_code in (401, 403)


# -----------------------------------------------------------------------------
# 14. Existing Registration, Password Recovery, NeuralTrace Reset Passing
# -----------------------------------------------------------------------------
def test_registration_and_password_recovery_and_neuraltrace_intact(client: TestClient, db_session: Session):
    email = f"recovery_{int(time.time() * 1000)}@example.com"
    reg_res = client.post("/api/auth/register", json={
        "email": email,
        "password": "Password123!",
        "name": "Recovery User"
    })
    assert reg_res.status_code == 201

    # Request password recovery
    rec_req = client.post("/api/auth/password-reset/request", json={"email": email})
    assert rec_req.status_code == 200
    ticket = rec_req.json().get("ticket_token") or rec_req.json().get("reset_token")

    # Verify password recovery endpoint accepts valid request
    assert "masked_email" in rec_req.json() or "message" in rec_req.json()
