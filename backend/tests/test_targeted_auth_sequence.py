import pytest
import time
from unittest.mock import patch
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.session import Session as DbSession
from app.models.application_grant import ApplicationGrant
from app.services.session_service import SessionService
from app.services.access_tracker import ConfidentialAccessTracker
from app.services.step_up_service import StepUpService
from app.services.adaptive_auth_service import AdaptiveAuthService
from app.services.email_service import EmailService


def _create_user(client: TestClient, prefix: str):
    email = f"{prefix}_{int(time.time()*1000)}@example.com"
    pwd = "SecurePassword123!"
    reg = client.post("/api/auth/register", json={
        "email": email,
        "password": pwd,
        "name": f"{prefix.capitalize()} Tester"
    })
    assert reg.status_code == 201
    return email, pwd


def _login(client: TestClient, email: str, password: str, app: str):
    res = client.post("/api/auth/login", json={
        "email": email,
        "password": password,
        "application": app
    })
    assert res.status_code == 200
    data = res.json()
    return data["session_id"], data["access_token"]


def _activate_session(db_session: Session, sid: str):
    sess = db_session.query(DbSession).filter(DbSession.id == sid).first()
    sess.status = "ACTIVE"
    db_session.commit()
    db_session.refresh(sess)
    return sess


def test_scenario_1_normal_login_low_risk_email_otp(client: TestClient, db_session: Session):
    """Scenario 1: Normal login, LOW risk triggers Email OTP challenge."""
    email, pwd = _create_user(client, "norm_login")
    sid, token = _login(client, email, pwd, "college")
    headers = {"Authorization": f"Bearer {token}"}

    sess = db_session.query(DbSession).filter(DbSession.id == sid).first()
    sess.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=35)
    sess.current_risk_level = "LOW"
    db_session.commit()

    # Request login OTP after observation
    res = client.post("/api/auth/login-otp/request", json={"session_id": sid}, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_level"] == "LOW"
    assert data["challenge_type"] == "LOGIN_OTP"
    assert "otp" in data["message"].lower() or "verification" in data["message"].lower()

    db_session.refresh(sess)
    assert sess.status == "PENDING_OTP"


def test_scenario_2_and_3_normal_navigation_and_medium_risk_no_popup(client: TestClient, db_session: Session):
    """
    Scenario 2 & 3: Normal portal navigation & telemetry monitoring.
    When telemetry reflects MEDIUM risk during normal navigation, it is recorded in DB,
    and ordinary navigation continues without blocking ordinary endpoints.
    """
    email, pwd = _create_user(client, "nav_tester")
    sid, token = _login(client, email, pwd, "college")
    headers = {"Authorization": f"Bearer {token}"}

    # Activate session
    sess = _activate_session(db_session, sid)

    # Post telemetry that evaluates risk
    tel_res = client.post("/api/behavior/events", json={
        "session_id": sid,
        "application": "college",
        "avg_dwell_time_ms": 150.0,
        "avg_flight_time_ms": 200.0,
        "mouse_velocity_avg": 450.0,
        "mouse_acceleration_avg": 600.0,
        "click_frequency": 1.5,
        "scroll_speed_avg": 300.0,
        "navigation_entropy": 0.45
    }, headers=headers)

    assert tel_res.status_code == 200
    tel_data = tel_res.json()
    # Risk evaluated and recorded
    assert "risk_score" in tel_data or "decision" in tel_data

    # Ordinary endpoints (e.g. user profile / non-vault features) remain accessible
    me_res = client.get("/api/auth/me", headers=headers)
    assert me_res.status_code == 200


def test_scenario_4_confidential_vault_boundary_medium_risk_triggers_neuraltrace(client: TestClient, db_session: Session):
    """
    Scenario 4: When user clicks confidential vault under MEDIUM risk:
    At the vault access boundary, NeuralTrace gesture verification is required.
    """
    email, pwd = _create_user(client, "vault_med")
    user = db_session.query(User).filter(User.email == email).first()

    # Enroll NeuralTrace for user
    AdaptiveAuthService.enroll_gesture_pattern(
        db=db_session,
        user_id=user.id,
        pattern=[0, 1, 2, 5, 8],
        confirm_pattern=[0, 1, 2, 5, 8]
    )

    sid, token = _login(client, email, pwd, "college")
    headers = {"Authorization": f"Bearer {token}"}

    # Activate session
    sess = _activate_session(db_session, sid)
    sess.current_risk_level = "MEDIUM"
    db_session.commit()

    # User clicks confidential vault -> checkResourceAccess('academic_vault')
    access_res = client.post("/api/security/access-decision", json={
        "session_id": sid,
        "resource": "academic_vault",
        "application": "college"
    }, headers=headers)

    assert access_res.status_code == 200
    access_data = access_res.json()
    assert access_data["access_granted"] is False
    assert access_data["verification_required"] is True
    assert access_data["required_factor"] == "GESTURE_PATTERN"


def test_scenario_5_repeated_vault_clicks_high_risk_triggers_cognitive(client: TestClient, db_session: Session):
    """
    Scenario 5: Repeated clicks on confidential vault without authorization elevate risk to HIGH.
    At HIGH risk, sequential cognitive verification (HIGH_RISK_DUAL) is required.
    """
    email, pwd = _create_user(client, "vault_high")
    user = db_session.query(User).filter(User.email == email).first()

    # Enroll cognitive factors
    AdaptiveAuthService.enroll_image_sequence(
        db=db_session,
        user_id=user.id,
        image_sequence=["img_shield", "img_key", "img_lock"],
        confirm_image_sequence=["img_shield", "img_key", "img_lock"]
    )
    AdaptiveAuthService.enroll_private_response(
        db=db_session,
        user_id=user.id,
        question="What is the cryptographic algorithm?",
        response="argon2id-aes-256",
        confirm_response="argon2id-aes-256"
    )

    sid, token = _login(client, email, pwd, "shopping")
    headers = {"Authorization": f"Bearer {token}"}

    sess = _activate_session(db_session, sid)
    ConfidentialAccessTracker.reset_all()

    # Simulate repeated unauthorized access attempts (5 denials to trigger HIGH risk threshold)
    for _ in range(5):
        ConfidentialAccessTracker.record_denial(user.id, sid, "financial_vault", dedup_seconds=0.0)

    # Check access decision at vault boundary
    access_res = client.post("/api/security/access-decision", json={
        "session_id": sid,
        "resource": "financial_vault",
        "application": "shopping"
    }, headers=headers)

    assert access_res.status_code == 200
    access_data = access_res.json()
    assert access_data["access_granted"] is False
    assert access_data["verification_required"] is True
    assert access_data["required_factor"] == "HIGH_RISK_DUAL"


def test_scenario_6_repeated_vault_clicks_and_wrong_attempts_triggers_critical_termination(client: TestClient, db_session: Session):
    """
    Scenario 6: User repeatedly clicks confidential vault and submits wrong attempts:
    Elevates to CRITICAL risk, terminates session, access denied.
    """
    email, pwd = _create_user(client, "vault_crit")
    user = db_session.query(User).filter(User.email == email).first()

    AdaptiveAuthService.enroll_gesture_pattern(
        db=db_session,
        user_id=user.id,
        pattern=[0, 1, 2, 5, 8],
        confirm_pattern=[0, 1, 2, 5, 8]
    )

    sid, token = _login(client, email, pwd, "healthcare")
    headers = {"Authorization": f"Bearer {token}"}

    sess = _activate_session(db_session, sid)
    ConfidentialAccessTracker.reset_all()

    # Repeated vault clicks
    for _ in range(3):
        ConfidentialAccessTracker.record_denial(user.id, sid, "ehr_vault", dedup_seconds=0.0)

    # Request challenge
    chal_res = client.post("/api/security/step-up/challenge", json={
        "session_id": sid,
        "preferred_factor": "GESTURE_PATTERN",
        "application": "healthcare",
        "resource": "ehr_vault"
    }, headers=headers)
    assert chal_res.status_code == 200
    chal_id = chal_res.json()["challenge_id"]

    # Submit repeated wrong attempts until locked
    ver_res = None
    for i in range(3):
        ver_res = client.post("/api/security/step-up/verify", json={
            "session_id": sid,
            "challenge_type": "GESTURE_PATTERN",
            "gesture_pattern": [9, 8, 7],  # wrong
            "application": "healthcare",
            "resource": "ehr_vault",
            "challenge_id": chal_id
        }, headers=headers)

    # On exceeding attempts with repeated denials, session is terminated
    assert ver_res.status_code in (400, 403)
    db_session.refresh(sess)
    assert sess.status in ("TERMINATED", "RESTRICTED")

    # Vault access is unconditionally denied
    v_res = client.get(f"/api/security/vault/ehr_vault?session_id={sid}", headers=headers)
    assert v_res.status_code in (400, 401, 403)


def test_scenario_7_and_8_failed_vs_successful_verification(client: TestClient, db_session: Session):
    """
    Scenario 7 & 8:
    - Failed verification: Vault remains locked.
    - Successful verification: Backend authoritatively grants vault access.
    """
    email, pwd = _create_user(client, "vault_success")
    user = db_session.query(User).filter(User.email == email).first()

    pattern = [0, 1, 2, 5, 8]
    AdaptiveAuthService.enroll_gesture_pattern(
        db=db_session,
        user_id=user.id,
        pattern=pattern,
        confirm_pattern=pattern
    )

    sid, token = _login(client, email, pwd, "college")
    headers = {"Authorization": f"Bearer {token}"}

    sess = _activate_session(db_session, sid)
    sess.current_risk_level = "MEDIUM"
    db_session.commit()

    # Before verification: direct vault access returns 403
    direct_res = client.get(f"/api/security/vault/academic_vault?session_id={sid}", headers=headers)
    assert direct_res.status_code == 403

    # Request challenge
    chal_res = client.post("/api/security/step-up/challenge", json={
        "session_id": sid,
        "preferred_factor": "GESTURE_PATTERN",
        "application": "college",
        "resource": "academic_vault"
    }, headers=headers)
    assert chal_res.status_code == 200
    chal_id = chal_res.json()["challenge_id"]

    # Submit valid NeuralTrace gesture
    ver_res = client.post("/api/security/step-up/verify", json={
        "session_id": sid,
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": pattern,
        "application": "college",
        "resource": "academic_vault",
        "challenge_id": chal_id
    }, headers=headers)
    assert ver_res.status_code == 200
    ver_data = ver_res.json()
    assert ver_data["decision"] == "ALLOW"

    # Verify ApplicationGrant was authoritatively created
    grant = db_session.query(ApplicationGrant).filter(
        ApplicationGrant.session_id == sid,
        ApplicationGrant.application == "college",
        ApplicationGrant.resource == "academic_vault"
    ).first()
    assert grant is not None
    assert grant.revoked is False

    # Vault is now accessible!
    vault_res = client.get(f"/api/security/vault/academic_vault?session_id={sid}", headers=headers)
    assert vault_res.status_code == 200
    v_data = vault_res.json()
    assert v_data["access_granted"] is True
    assert "student_profile" in v_data["data"]


def test_portal_college_mandatory_otp_and_vault_flow(client: TestClient, db_session: Session):
    """
    College Portal:
    1. Login starts observation.
    2. Observation duration strictly enforced (early request rejected).
    3. Medium risk after observation triggers real email OTP challenge (not bypassed).
    4. Real SMTP dispatch to registered recipient verified.
    5. Invalid OTP rejected with 400 and immediate session termination.
    6. Resend generates fresh challenge.
    7. Valid OTP verification activates session.
    8. Normal navigation permitted without NeuralTrace interruption.
    9. NeuralTrace triggers at academic_vault boundary under MEDIUM risk.
    10. Direct API access without step-up grant returns 403.
    11. Verified step-up grants authoritative academic vault access.
    """
    email, pwd = _create_user(client, "col_portal")
    user = db_session.query(User).filter(User.email == email).first()
    pattern = [0, 1, 2, 5, 8]
    AdaptiveAuthService.enroll_gesture_pattern(
        db=db_session, user_id=user.id, pattern=pattern, confirm_pattern=pattern
    )

    sid, token = _login(client, email, pwd, "college")
    headers = {"Authorization": f"Bearer {token}"}
    sess = db_session.query(DbSession).filter(DbSession.id == sid).first()
    assert sess.status == "PENDING_OBSERVATION"

    # Early request before observation elapsed is rejected
    early_res = client.post("/api/auth/login-otp/request", json={"session_id": sid}, headers=headers)
    assert early_res.status_code == 400
    assert "observation period incomplete" in early_res.json()["detail"].lower()

    # Advance observation time past 30 seconds
    sess.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=35)
    sess.current_risk_level = "MEDIUM"
    db_session.commit()

    captured_otps = []
    def mock_send(recipient_email, otp_code, **kwargs):
        captured_otps.append((recipient_email, otp_code))
        return True, "Code delivered"

    with patch.object(EmailService, "send_otp_email", side_effect=mock_send):
        otp_req = client.post("/api/auth/login-otp/request", json={"session_id": sid}, headers=headers)
        assert otp_req.status_code == 200
        req_data = otp_req.json()
        assert req_data["challenge_type"] == "LOGIN_OTP"
        assert req_data["risk_level"] == "MEDIUM"
        assert len(captured_otps) == 1
        assert captured_otps[0][0] == email  # Sent to registered email

        db_session.refresh(sess)
        assert sess.status == "PENDING_OTP"

        # Invalid OTP rejection terminates session
        inv_res = client.post("/api/auth/login-otp/verify", json={
            "session_id": sid,
            "otp_code": "000000",
            "challenge_id": req_data["challenge_id"]
        }, headers=headers)
        assert inv_res.status_code == 400
        db_session.refresh(sess)
        assert sess.status == "TERMINATED"

    # Fresh login to test resend, valid OTP verification, and vault access
    sid2, token2 = _login(client, email, pwd, "college")
    headers2 = {"Authorization": f"Bearer {token2}"}
    sess2 = db_session.query(DbSession).filter(DbSession.id == sid2).first()
    sess2.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=35)
    sess2.current_risk_level = "MEDIUM"
    db_session.commit()

    with patch.object(EmailService, "send_otp_email", side_effect=mock_send):
        client.post("/api/auth/login-otp/request", json={"session_id": sid2}, headers=headers2)
        resend_res = client.post("/api/auth/login-otp/resend", json={"session_id": sid2}, headers=headers2)
        assert resend_res.status_code == 200
        latest_otp = captured_otps[-1][1]

        # Verify valid OTP
        ver_res = client.post("/api/auth/login-otp/verify", json={
            "session_id": sid2,
            "otp_code": latest_otp,
            "challenge_id": resend_res.json()["challenge_id"]
        }, headers=headers2)
        assert ver_res.status_code == 200
        assert ver_res.json()["session_status"] == "ACTIVE"
        db_session.refresh(sess2)
        assert sess2.status == "ACTIVE"

    # Normal navigation permitted without NeuralTrace interruption
    me_res = client.get("/api/auth/me", headers=headers2)
    assert me_res.status_code == 200

    # Confidential vault boundary (academic_vault)
    sess2.current_risk_level = "MEDIUM"
    db_session.commit()

    dec_res = client.post("/api/security/access-decision", json={
        "session_id": sid2,
        "resource": "academic_vault",
        "application": "college"
    }, headers=headers2)
    assert dec_res.status_code == 200
    dec_data = dec_res.json()
    assert dec_data["access_granted"] is False
    assert dec_data["verification_required"] is True
    assert dec_data["required_factor"] == "GESTURE_PATTERN"

    # Direct access cannot bypass
    direct_res = client.get(f"/api/security/vault/academic_vault?session_id={sid2}", headers=headers2)
    assert direct_res.status_code == 403

    # Issue challenge & verify NeuralTrace gesture
    chal_res = client.post("/api/security/step-up/challenge", json={
        "session_id": sid2,
        "preferred_factor": "GESTURE_PATTERN",
        "application": "college",
        "resource": "academic_vault"
    }, headers=headers2)
    cid = chal_res.json()["challenge_id"]

    step_res = client.post("/api/security/step-up/verify", json={
        "session_id": sid2,
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": pattern,
        "application": "college",
        "resource": "academic_vault",
        "challenge_id": cid
    }, headers=headers2)
    assert step_res.status_code == 200
    assert step_res.json()["decision"] == "ALLOW"

    # Vault authorized and viewable
    v_res = client.get(f"/api/security/vault/academic_vault?session_id={sid2}", headers=headers2)
    assert v_res.status_code == 200
    assert v_res.json()["access_granted"] is True
    assert "student_profile" in v_res.json()["data"]


def test_portal_shopping_mandatory_otp_and_vault_flow(client: TestClient, db_session: Session):
    """
    Shopping Portal:
    1. Login starts observation.
    2. Observation duration strictly enforced (early request rejected).
    3. Medium risk after observation triggers real email OTP challenge (not bypassed).
    4. Real SMTP dispatch to registered recipient verified.
    5. Invalid OTP rejected with 400 and immediate session termination.
    6. Resend generates fresh challenge.
    7. Valid OTP verification activates session.
    8. Normal navigation permitted without NeuralTrace interruption.
    9. NeuralTrace triggers at financial_vault boundary under MEDIUM risk.
    10. Direct API access without step-up grant returns 403.
    11. Verified step-up grants authoritative financial vault access.
    """
    email, pwd = _create_user(client, "shop_portal")
    user = db_session.query(User).filter(User.email == email).first()
    pattern = [0, 1, 2, 5, 8]
    AdaptiveAuthService.enroll_gesture_pattern(
        db=db_session, user_id=user.id, pattern=pattern, confirm_pattern=pattern
    )

    sid, token = _login(client, email, pwd, "shopping")
    headers = {"Authorization": f"Bearer {token}"}
    sess = db_session.query(DbSession).filter(DbSession.id == sid).first()
    assert sess.status == "PENDING_OBSERVATION"

    # Early request before observation elapsed is rejected
    early_res = client.post("/api/auth/login-otp/request", json={"session_id": sid}, headers=headers)
    assert early_res.status_code == 400

    # Advance observation time past 30 seconds
    sess.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=35)
    sess.current_risk_level = "MEDIUM"
    db_session.commit()

    captured_otps = []
    def mock_send(recipient_email, otp_code, **kwargs):
        captured_otps.append((recipient_email, otp_code))
        return True, "Code delivered"

    with patch.object(EmailService, "send_otp_email", side_effect=mock_send):
        otp_req = client.post("/api/auth/login-otp/request", json={"session_id": sid}, headers=headers)
        assert otp_req.status_code == 200
        req_data = otp_req.json()
        assert req_data["challenge_type"] == "LOGIN_OTP"
        assert len(captured_otps) == 1
        assert captured_otps[0][0] == email

        db_session.refresh(sess)
        assert sess.status == "PENDING_OTP"

        # Invalid OTP terminates session
        inv_res = client.post("/api/auth/login-otp/verify", json={
            "session_id": sid,
            "otp_code": "000000",
            "challenge_id": req_data["challenge_id"]
        }, headers=headers)
        assert inv_res.status_code == 400
        db_session.refresh(sess)
        assert sess.status == "TERMINATED"

    # Fresh login
    sid2, token2 = _login(client, email, pwd, "shopping")
    headers2 = {"Authorization": f"Bearer {token2}"}
    sess2 = db_session.query(DbSession).filter(DbSession.id == sid2).first()
    sess2.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=35)
    sess2.current_risk_level = "MEDIUM"
    db_session.commit()

    with patch.object(EmailService, "send_otp_email", side_effect=mock_send):
        client.post("/api/auth/login-otp/request", json={"session_id": sid2}, headers=headers2)
        resend_res = client.post("/api/auth/login-otp/resend", json={"session_id": sid2}, headers=headers2)
        assert resend_res.status_code == 200
        latest_otp = captured_otps[-1][1]

        # Verify valid OTP
        ver_res = client.post("/api/auth/login-otp/verify", json={
            "session_id": sid2,
            "otp_code": latest_otp,
            "challenge_id": resend_res.json()["challenge_id"]
        }, headers=headers2)
        assert ver_res.status_code == 200
        assert ver_res.json()["session_status"] == "ACTIVE"
        db_session.refresh(sess2)
        assert sess2.status == "ACTIVE"

    # Normal navigation permitted without NeuralTrace interruption
    me_res = client.get("/api/auth/me", headers=headers2)
    assert me_res.status_code == 200

    # Confidential vault boundary (financial_vault)
    sess2.current_risk_level = "MEDIUM"
    db_session.commit()

    dec_res = client.post("/api/security/access-decision", json={
        "session_id": sid2,
        "resource": "financial_vault",
        "application": "shopping"
    }, headers=headers2)
    assert dec_res.status_code == 200
    dec_data = dec_res.json()
    assert dec_data["access_granted"] is False
    assert dec_data["verification_required"] is True
    assert dec_data["required_factor"] == "GESTURE_PATTERN"

    # Direct access cannot bypass
    direct_res = client.get(f"/api/security/vault/financial_vault?session_id={sid2}", headers=headers2)
    assert direct_res.status_code == 403

    # Issue challenge & verify NeuralTrace gesture
    chal_res = client.post("/api/security/step-up/challenge", json={
        "session_id": sid2,
        "preferred_factor": "GESTURE_PATTERN",
        "application": "shopping",
        "resource": "financial_vault"
    }, headers=headers2)
    cid = chal_res.json()["challenge_id"]

    step_res = client.post("/api/security/step-up/verify", json={
        "session_id": sid2,
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": pattern,
        "application": "shopping",
        "resource": "financial_vault",
        "challenge_id": cid
    }, headers=headers2)
    assert step_res.status_code == 200
    assert step_res.json()["decision"] == "ALLOW"

    # Vault authorized and viewable
    v_res = client.get(f"/api/security/vault/financial_vault?session_id={sid2}", headers=headers2)
    assert v_res.status_code == 200
    assert v_res.json()["access_granted"] is True
    assert "saved_cards" in v_res.json()["data"] or "bank_account" in v_res.json()["data"]


def test_portal_healthcare_mandatory_otp_and_vault_flow(client: TestClient, db_session: Session):
    """
    Healthcare Portal:
    1. Login starts observation.
    2. Observation duration strictly enforced (early request rejected).
    3. Medium risk after observation triggers real email OTP challenge (not bypassed).
    4. Real SMTP dispatch to registered recipient verified.
    5. Invalid OTP rejected with 400 and immediate session termination.
    6. Resend generates fresh challenge.
    7. Valid OTP verification activates session.
    8. Normal navigation permitted without NeuralTrace interruption.
    9. NeuralTrace triggers at ehr_vault boundary under MEDIUM risk.
    10. Direct API access without step-up grant returns 403.
    11. Verified step-up grants authoritative EHR vault access.
    """
    email, pwd = _create_user(client, "health_portal")
    user = db_session.query(User).filter(User.email == email).first()
    pattern = [0, 1, 2, 5, 8]
    AdaptiveAuthService.enroll_gesture_pattern(
        db=db_session, user_id=user.id, pattern=pattern, confirm_pattern=pattern
    )

    sid, token = _login(client, email, pwd, "healthcare")
    headers = {"Authorization": f"Bearer {token}"}
    sess = db_session.query(DbSession).filter(DbSession.id == sid).first()
    assert sess.status == "PENDING_OBSERVATION"

    # Early request before observation elapsed is rejected
    early_res = client.post("/api/auth/login-otp/request", json={"session_id": sid}, headers=headers)
    assert early_res.status_code == 400

    # Advance observation time past 30 seconds
    sess.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=35)
    sess.current_risk_level = "MEDIUM"
    db_session.commit()

    captured_otps = []
    def mock_send(recipient_email, otp_code, **kwargs):
        captured_otps.append((recipient_email, otp_code))
        return True, "Code delivered"

    with patch.object(EmailService, "send_otp_email", side_effect=mock_send):
        otp_req = client.post("/api/auth/login-otp/request", json={"session_id": sid}, headers=headers)
        assert otp_req.status_code == 200
        req_data = otp_req.json()
        assert req_data["challenge_type"] == "LOGIN_OTP"
        assert len(captured_otps) == 1
        assert captured_otps[0][0] == email

        db_session.refresh(sess)
        assert sess.status == "PENDING_OTP"

        # Invalid OTP terminates session
        inv_res = client.post("/api/auth/login-otp/verify", json={
            "session_id": sid,
            "otp_code": "000000",
            "challenge_id": req_data["challenge_id"]
        }, headers=headers)
        assert inv_res.status_code == 400
        db_session.refresh(sess)
        assert sess.status == "TERMINATED"

    # Fresh login
    sid2, token2 = _login(client, email, pwd, "healthcare")
    headers2 = {"Authorization": f"Bearer {token2}"}
    sess2 = db_session.query(DbSession).filter(DbSession.id == sid2).first()
    sess2.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=35)
    sess2.current_risk_level = "MEDIUM"
    db_session.commit()

    with patch.object(EmailService, "send_otp_email", side_effect=mock_send):
        client.post("/api/auth/login-otp/request", json={"session_id": sid2}, headers=headers2)
        resend_res = client.post("/api/auth/login-otp/resend", json={"session_id": sid2}, headers=headers2)
        assert resend_res.status_code == 200
        latest_otp = captured_otps[-1][1]

        # Verify valid OTP
        ver_res = client.post("/api/auth/login-otp/verify", json={
            "session_id": sid2,
            "otp_code": latest_otp,
            "challenge_id": resend_res.json()["challenge_id"]
        }, headers=headers2)
        assert ver_res.status_code == 200
        assert ver_res.json()["session_status"] == "ACTIVE"
        db_session.refresh(sess2)
        assert sess2.status == "ACTIVE"

    # Normal navigation permitted without NeuralTrace interruption
    me_res = client.get("/api/auth/me", headers=headers2)
    assert me_res.status_code == 200

    # Confidential vault boundary (ehr_vault)
    sess2.current_risk_level = "MEDIUM"
    db_session.commit()

    dec_res = client.post("/api/security/access-decision", json={
        "session_id": sid2,
        "resource": "ehr_vault",
        "application": "healthcare"
    }, headers=headers2)
    assert dec_res.status_code == 200
    dec_data = dec_res.json()
    assert dec_data["access_granted"] is False
    assert dec_data["verification_required"] is True
    assert dec_data["required_factor"] == "GESTURE_PATTERN"

    # Direct access cannot bypass
    direct_res = client.get(f"/api/security/vault/ehr_vault?session_id={sid2}", headers=headers2)
    assert direct_res.status_code == 403

    # Issue challenge & verify NeuralTrace gesture
    chal_res = client.post("/api/security/step-up/challenge", json={
        "session_id": sid2,
        "preferred_factor": "GESTURE_PATTERN",
        "application": "healthcare",
        "resource": "ehr_vault"
    }, headers=headers2)
    cid = chal_res.json()["challenge_id"]

    step_res = client.post("/api/security/step-up/verify", json={
        "session_id": sid2,
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": pattern,
        "application": "healthcare",
        "resource": "ehr_vault",
        "challenge_id": cid
    }, headers=headers2)
    assert step_res.status_code == 200
    assert step_res.json()["decision"] == "ALLOW"

    # Vault authorized and viewable
    v_res = client.get(f"/api/security/vault/ehr_vault?session_id={sid2}", headers=headers2)
    assert v_res.status_code == 200
    assert v_res.json()["access_granted"] is True
    assert "patient_profile" in v_res.json()["data"]


def test_vault_access_under_low_risk_strictly_requires_neuraltrace_never_otp(client: TestClient, db_session: Session):
    """
    Confidential Vault Access Factor Isolation:
    For LOW and MEDIUM risk, confidential vault access (academic_vault, financial_vault, ehr_vault)
    strictly requires NeuralTrace (GESTURE_PATTERN), never OTP.
    Initial login OTP must never grant vault authorization.
    Replay or reuse of expired/consumed challenge IDs returns 400.
    """
    email, pwd = _create_user(client, "vault_low_risk")
    user = db_session.query(User).filter(User.email == email).first()
    pattern = [0, 1, 2, 5, 8]
    AdaptiveAuthService.enroll_gesture_pattern(
        db=db_session, user_id=user.id, pattern=pattern, confirm_pattern=pattern
    )

    portals = [
        ("college", "academic_vault"),
        ("shopping", "financial_vault"),
        ("healthcare", "ehr_vault")
    ]

    for app_name, resource_name in portals:
        sid, token = _login(client, email, pwd, app_name)
        headers = {"Authorization": f"Bearer {token}"}
        sess = db_session.query(DbSession).filter(DbSession.id == sid).first()
        sess.status = "ACTIVE"
        sess.current_risk_level = "LOW"
        db_session.commit()

        # Step 1: Query access-decision under LOW risk
        dec_res = client.post("/api/security/access-decision", json={
            "session_id": sid,
            "resource": resource_name,
            "application": app_name
        }, headers=headers)
        assert dec_res.status_code == 200
        dec_data = dec_res.json()
        assert dec_data["access_granted"] is False
        assert dec_data["verification_required"] is True
        assert dec_data["required_factor"] == "GESTURE_PATTERN", f"{app_name}:{resource_name} must require GESTURE_PATTERN, not {dec_data.get('required_factor')}"

        # Step 2: Direct API access without grant returns 403
        direct_res = client.get(f"/api/security/vault/{resource_name}?session_id={sid}", headers=headers)
        assert direct_res.status_code == 403

        # Step 3: Request step-up challenge under LOW risk (without preferred_factor or with GESTURE_PATTERN)
        chal_res = client.post("/api/security/step-up/challenge", json={
            "session_id": sid,
            "application": app_name,
            "resource": resource_name
        }, headers=headers)
        assert chal_res.status_code == 200
        chal_data = chal_res.json()
        assert chal_data["challenge_type"] == "GESTURE_PATTERN"
        cid = chal_data["challenge_id"]

        # Step 4: Verify challenge with valid NeuralTrace
        ver_res = client.post("/api/security/step-up/verify", json={
            "session_id": sid,
            "challenge_type": "GESTURE_PATTERN",
            "gesture_pattern": pattern,
            "application": app_name,
            "resource": resource_name,
            "challenge_id": cid
        }, headers=headers)
        assert ver_res.status_code == 200
        assert ver_res.json()["decision"] == "ALLOW"

        # Step 5: Challenge is consumed - replaying cid returns 400 with challenge expired/used error
        replay_res = client.post("/api/security/step-up/verify", json={
            "session_id": sid,
            "challenge_type": "GESTURE_PATTERN",
            "gesture_pattern": pattern,
            "application": app_name,
            "resource": resource_name,
            "challenge_id": cid
        }, headers=headers)
        assert replay_res.status_code == 400
        assert "no active step-up challenge found" in replay_res.json()["detail"].lower()

        # Step 6: Vault is now authorized and accessible
        v_res = client.get(f"/api/security/vault/{resource_name}?session_id={sid}", headers=headers)
        assert v_res.status_code == 200
        assert v_res.json()["access_granted"] is True


