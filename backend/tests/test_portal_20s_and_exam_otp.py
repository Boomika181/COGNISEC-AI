import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.session import Session as DbSession
from app.models.otp_challenge import OTPChallenge
from app.services.auth_service import AuthService
from app.services.step_up_service import StepUpService
from app.services.decision_service import DecisionService
from app.services.email_service import EmailService
from app.core.security import get_password_hash


@pytest.fixture(autouse=True)
def reset_challenges_and_mock_smtp(monkeypatch):
    StepUpService.reset()
    dispatched_emails = []

    def fake_send_otp_email(recipient_email, otp_code, expires_in_minutes=5, challenge_id=None):
        dispatched_emails.append({
            "recipient": recipient_email,
            "otp": otp_code,
            "challenge_id": challenge_id
        })
        return True, f"Accepted by Gmail SMTP for {recipient_email}"

    monkeypatch.setattr(EmailService, "send_otp_email", staticmethod(fake_send_otp_email))
    return dispatched_emails


def _ensure_test_user(db: Session, email="boomikaram35@gmail.com", password="SecurePassword123!"):
    user = AuthService.get_user_by_email(db, email)
    if not user:
        user = User(
            name="Boomika Ram",
            email=email,
            password_hash=get_password_hash(password),
            role="USER",
            failed_login_attempts=0
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        user.password_hash = get_password_hash(password)
        user.failed_login_attempts = 0
        db.commit()
    return user


def _login_and_complete_20s_observation(
    client: TestClient,
    db: Session,
    application: str,
    dispatched_emails: list,
    email="boomikaram35@gmail.com",
    password="SecurePassword123!"
):
    _ensure_test_user(db, email, password)
    login_res = client.post("/api/auth/login", json={
        "email": email,
        "password": password,
        "application": application,
        "device_fingerprint": f"fp_test_{application}"
    })
    assert login_res.status_code == 200, login_res.text
    login_data = login_res.json()
    assert login_data["session_status"] == "PENDING_OBSERVATION"
    assert login_data["observation_seconds_remaining"] == 20
    token = login_data["access_token"]
    sid = login_data["session_id"]
    headers = {"Authorization": f"Bearer {token}"}

    # Verify mid-observation telemetry does NOT overwrite PENDING_OBSERVATION status
    DecisionService.enforce_zero_trust_decision(
        db=db,
        user_id=login_data["user_id"],
        session_id=sid,
        application=application,
        anomaly_score=0.52,
        risk_score=0.53,
        risk_level="MEDIUM",
        contributing_factors=["Behavioral telemetry calibration"]
    )
    obs_res = client.get(f"/api/auth/observation-status/{sid}", headers=headers)
    assert obs_res.status_code == 200
    assert obs_res.json()["status"] == "PENDING_OBSERVATION"

    # Fast-forward 20-second observation window completion
    sess = db.query(DbSession).filter(DbSession.id == sid).first()
    sess.current_risk_level = "LOW"
    sess.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=21)
    db.commit()

    # Automatic trigger at 20s -> request login OTP
    otp_req = client.post("/api/auth/login-otp/request", json={"session_id": sid}, headers=headers)
    assert otp_req.status_code == 200, otp_req.text
    otp_data = otp_req.json()
    assert otp_data["challenge_type"] == "LOGIN_OTP"
    assert "accepted by gmail smtp" in otp_data["message"].lower() or "sent" in otp_data["message"].lower()

    # Verify login OTP to activate session
    ver_res = client.post("/api/auth/login-otp/verify", json={
        "session_id": sid,
        "challenge_id": otp_data["challenge_id"],
        "otp_code": dispatched_emails[-1]["otp"]
    }, headers=headers)
    assert ver_res.status_code == 200, ver_res.text
    assert ver_res.json()["session_status"] == "ACTIVE"
    return sid, headers, login_data["user_id"]


def test_scenario_1_2_3_all_three_portals_20s_observation_and_verification(
    client: TestClient, db_session: Session, reset_challenges_and_mock_smtp
):
    """
    Scenarios 1, 2, 3:
    1. Shopping login -> 20s observation runs; verification triggers automatically at 20s
    2. College login -> 20s observation runs; verification triggers automatically at 20s
    3. Healthcare login -> 20s observation runs; verification triggers automatically at 20s
    """
    for portal in ("shopping", "college", "healthcare"):
        sid, headers, _ = _login_and_complete_20s_observation(
            client, db_session, portal, reset_challenges_and_mock_smtp
        )
        assert sid.startswith("sess_")
    assert len(reset_challenges_and_mock_smtp) >= 3
    for item in reset_challenges_and_mock_smtp:
        assert item["recipient"] == "boomikaram35@gmail.com"


def test_scenario_4_5_6_7_8_9_college_online_exam_otp_flow(
    client: TestClient, db_session: Session, reset_challenges_and_mock_smtp
):
    """
    Scenarios 4, 5, 6, 7, 8, 9:
    4. College exam launch -> OTP challenge appears when required
    5. Correct exam OTP -> Exam launches
    6. Incorrect exam OTP -> Exam remains locked
    7. Expired exam OTP -> Exam remains locked
    8. Repeated exam launch requests -> No duplicate or conflicting challenges
    9. Direct exam API access -> Rejected without valid authorization
    """
    db = db_session
    sid, headers, _ = _login_and_complete_20s_observation(
        client, db, "college", reset_challenges_and_mock_smtp
    )
    course = "CS F301 - Data Structures & Algorithms"

    # Scenario 9: Direct exam API access before OTP verification -> Rejected (403)
    direct_res = client.get(
        f"/api/security/exam-session?session_id={sid}&course_name={course}",
        headers=headers
    )
    assert direct_res.status_code == 403
    assert "Valid examination OTP verification is required" in direct_res.json()["detail"]

    # Scenario 4: Request exam OTP challenge
    emails_before = len(reset_challenges_and_mock_smtp)
    req1 = client.post("/api/security/exam-otp/request", json={
        "session_id": sid,
        "course_name": course
    }, headers=headers)
    assert req1.status_code == 200, req1.text
    chal1 = req1.json()
    assert chal1["challenge_type"] == "COLLEGE_EXAM_OTP"
    assert chal1["email_delivered"] is True
    assert len(reset_challenges_and_mock_smtp) == emails_before + 1
    assert reset_challenges_and_mock_smtp[-1]["recipient"] == "boomikaram35@gmail.com"

    # Scenario 8: Repeated exam launch request -> Deduplicated (no duplicate email sent, same challenge_id)
    req2 = client.post("/api/security/exam-otp/request", json={
        "session_id": sid,
        "course_name": course
    }, headers=headers)
    assert req2.status_code == 200
    chal2 = req2.json()
    assert chal2["challenge_id"] == chal1["challenge_id"]
    assert chal2["deduplicated"] is True
    assert len(reset_challenges_and_mock_smtp) == emails_before + 1

    # Scenario 6: Incorrect exam OTP -> Exam remains locked
    wrong_res = client.post("/api/security/exam-otp/verify", json={
        "session_id": sid,
        "challenge_id": chal1["challenge_id"],
        "otp": "000000" if chal1["otp"] != "000000" else "999999",
        "course_name": course
    }, headers=headers)
    assert wrong_res.status_code == 400
    assert "Invalid verification code" in wrong_res.json()["detail"]

    # Direct exam API access still locked after wrong OTP
    still_locked = client.get(
        f"/api/security/exam-session?session_id={sid}&course_name={course}",
        headers=headers
    )
    assert still_locked.status_code == 403

    # Scenario 5: Correct exam OTP -> Exam launches and protected exam-session endpoint succeeds
    right_res = client.post("/api/security/exam-otp/verify", json={
        "session_id": sid,
        "challenge_id": chal1["challenge_id"],
        "otp": chal1["otp"],
        "course_name": course
    }, headers=headers)
    assert right_res.status_code == 200, right_res.text
    assert right_res.json()["verified"] is True
    assert right_res.json()["authorized"] is True

    # Reusing the same OTP must be rejected (single-use)
    reuse_res = client.post("/api/security/exam-otp/verify", json={
        "session_id": sid,
        "challenge_id": chal1["challenge_id"],
        "otp": chal1["otp"],
        "course_name": course
    }, headers=headers)
    assert reuse_res.status_code == 400

    # Protected exam session endpoint now authorizes launch
    exam_access = client.get(
        f"/api/security/exam-session?session_id={sid}&course_name={course}",
        headers=headers
    )
    assert exam_access.status_code == 200
    assert exam_access.json()["authorized"] is True

    # Scenario 7: Expired exam OTP -> Exam remains locked
    from app.services.session_service import SessionService
    SessionService.revoke_application_grants(db, session_id=sid, application="college", resource="online_exam")
    req_exp = client.post("/api/security/exam-otp/request", json={
        "session_id": sid,
        "course_name": course
    }, headers=headers)
    assert req_exp.status_code == 200
    exp_chal = req_exp.json()

    db_row = db.query(OTPChallenge).filter(OTPChallenge.challenge_id == exp_chal["challenge_id"]).first()
    if db_row:
        db_row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
        db.commit()
    with StepUpService._lock:
        if exp_chal["challenge_id"] in StepUpService._challenges:
            StepUpService._challenges[exp_chal["challenge_id"]]["expires_at"] = datetime.now(timezone.utc) - timedelta(seconds=10)
        if f"exam:{sid}" in StepUpService._challenges:
            StepUpService._challenges[f"exam:{sid}"]["expires_at"] = datetime.now(timezone.utc) - timedelta(seconds=10)

    exp_ver = client.post("/api/security/exam-otp/verify", json={
        "session_id": sid,
        "challenge_id": exp_chal["challenge_id"],
        "otp": exp_chal["otp"],
        "course_name": course
    }, headers=headers)
    assert exp_ver.status_code == 400
    assert "expired" in exp_ver.json()["detail"].lower()

    locked_after_exp = client.get(
        f"/api/security/exam-session?session_id={sid}&course_name={course}",
        headers=headers
    )
    assert locked_after_exp.status_code == 403


def test_scenario_10_critical_risk_terminates_session_and_denies_access(client: TestClient, db_session: Session):
    """
    Scenario 10: CRITICAL risk -> Existing termination behavior preserved
    """
    db = db_session
    _ensure_test_user(db)
    login_res = client.post("/api/auth/login", json={
        "email": "boomikaram35@gmail.com",
        "password": "SecurePassword123!",
        "application": "college",
        "device_fingerprint": "fp_crit_test"
    })
    assert login_res.status_code == 200
    data = login_res.json()
    sid = data["session_id"]
    headers = {"Authorization": f"Bearer {data['access_token']}"}

    sess = db.query(DbSession).filter(DbSession.id == sid).first()
    sess.current_risk_level = "CRITICAL"
    sess.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=21)
    db.commit()

    res = client.post("/api/auth/login-otp/request", json={"session_id": sid}, headers=headers)
    assert res.status_code == 403
    assert "terminated due to critical security risk" in res.json()["detail"].lower()

    db.refresh(sess)
    assert sess.status == "TERMINATED"


def test_scenario_11_logout_during_observation_invalidates_session_and_challenges(client: TestClient, db_session: Session):
    """
    Scenario 11: Logout during observation -> Timer and pending challenges safely invalidated
    """
    db = db_session
    _ensure_test_user(db)
    login_res = client.post("/api/auth/login", json={
        "email": "boomikaram35@gmail.com",
        "password": "SecurePassword123!",
        "application": "shopping",
        "device_fingerprint": "fp_logout_obs"
    })
    assert login_res.status_code == 200
    data = login_res.json()
    sid = data["session_id"]
    headers = {"Authorization": f"Bearer {data['access_token']}"}

    # Logout during the 20s observation window
    logout_res = client.post(f"/api/auth/logout?session_id={sid}", headers=headers)
    assert logout_res.status_code == 200

    # Attempting to request OTP after logout must be rejected (401/403)
    otp_after_logout = client.post("/api/auth/login-otp/request", json={"session_id": sid}, headers=headers)
    assert otp_after_logout.status_code in (401, 403)
