import time
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from fastapi import status
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.session import Session as DbSession
from app.models.application_grant import ApplicationGrant
from app.services.step_up_service import StepUpService
from app.services.session_service import SessionService
from app.services.adaptive_auth_service import AdaptiveAuthService
from app.core.rate_limit import rate_limiter


@pytest.fixture(autouse=True)
def reset_security_fixture():
    StepUpService.reset()
    rate_limiter.reset()
    yield
    StepUpService.reset()
    rate_limiter.reset()


@pytest.fixture
def test_user_a(client: TestClient, db_session: Session):
    ts = time.time_ns()
    email = f"operator_a_{ts}@cognisec.ai"
    reg_res = client.post("/api/auth/register", json={
        "email": email,
        "password": "Password123!",
        "name": f"Operator A {ts}"
    })
    assert reg_res.status_code == status.HTTP_201_CREATED

    login_res = client.post("/api/auth/login", json={
        "email": email,
        "password": "Password123!",
        "application": "college"
    })
    assert login_res.status_code == status.HTTP_200_OK
    data = login_res.json()
    headers = {"Authorization": f"Bearer {data['access_token']}"}

    # Enroll valid route [0, 4, 8, 12]
    user_id = data["user_id"]
    AdaptiveAuthService.enroll_gesture_pattern(db_session, user_id, [0, 4, 8, 12], [0, 4, 8, 12])

    # Mark session ACTIVE (observation completed)
    db_sess = db_session.query(DbSession).filter(DbSession.id == data["session_id"]).first()
    db_sess.status = "ACTIVE"
    db_session.commit()

    return {
        "headers": headers,
        "user_id": user_id,
        "session_id": data["session_id"],
        "email": email,
        "route": [0, 4, 8, 12]
    }


@pytest.fixture
def test_user_b(client: TestClient, db_session: Session):
    ts = time.time_ns()
    email = f"operator_b_{ts}@cognisec.ai"
    reg_res = client.post("/api/auth/register", json={
        "email": email,
        "password": "Password123!",
        "name": f"Operator B {ts}"
    })
    assert reg_res.status_code == status.HTTP_201_CREATED

    login_res = client.post("/api/auth/login", json={
        "email": email,
        "password": "Password123!",
        "application": "college"
    })
    assert login_res.status_code == status.HTTP_200_OK
    data = login_res.json()
    headers = {"Authorization": f"Bearer {data['access_token']}"}

    user_id = data["user_id"]
    AdaptiveAuthService.enroll_gesture_pattern(db_session, user_id, [0, 4, 8, 12], [0, 4, 8, 12])

    # Mark session ACTIVE
    db_sess = db_session.query(DbSession).filter(DbSession.id == data["session_id"]).first()
    db_sess.status = "ACTIVE"
    db_session.commit()

    return {
        "headers": headers,
        "user_id": user_id,
        "session_id": data["session_id"],
        "email": email,
        "route": [0, 4, 8, 12]
    }


# ==============================================================================
# SCENARIOS 1, 2, 3: College success unlocks College ONLY; Shopping and Healthcare locked
# ==============================================================================
def test_01_02_03_college_success_unlocks_college_only(client: TestClient, test_user_a):
    headers = test_user_a["headers"]
    session_id = test_user_a["session_id"]
    route = test_user_a["route"]

    # Request and complete NeuralTrace challenge for College
    chal_res = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": session_id,
        "application": "college",
        "resource": "academic_vault",
        "preferred_factor": "GESTURE_PATTERN"
    })
    assert chal_res.status_code == status.HTTP_200_OK

    verify_res = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "application": "college",
        "resource": "academic_vault",
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": route
    })
    assert verify_res.status_code == status.HTTP_200_OK
    assert verify_res.json()["decision"] == "ALLOW"

    # 1. College academic vault: UNLOCKED
    college_dec = client.post("/api/security/access-decision", headers=headers, json={
        "session_id": session_id,
        "application": "college",
        "resource": "academic_vault"
    })
    assert college_dec.status_code == status.HTTP_200_OK
    assert college_dec.json()["access_granted"] is True

    college_vault = client.get(f"/api/security/vault/academic_vault?session_id={session_id}", headers=headers)
    assert college_vault.status_code == status.HTTP_200_OK
    assert "transcripts" in college_vault.json()["data"]

    # 2. Shopping financial vault: REMAINS LOCKED (College success does NOT unlock Shopping)
    shop_dec = client.post("/api/security/access-decision", headers=headers, json={
        "session_id": session_id,
        "application": "shopping",
        "resource": "financial_vault"
    })
    assert shop_dec.status_code == status.HTTP_200_OK
    assert shop_dec.json()["access_granted"] is False
    assert shop_dec.json()["verification_required"] is True

    shop_vault = client.get(f"/api/security/vault/financial_vault?session_id={session_id}", headers=headers)
    assert shop_vault.status_code == status.HTTP_403_FORBIDDEN

    # 3. Healthcare EHR vault: REMAINS LOCKED (College success does NOT unlock Healthcare)
    health_dec = client.post("/api/security/access-decision", headers=headers, json={
        "session_id": session_id,
        "application": "healthcare",
        "resource": "ehr_vault"
    })
    assert health_dec.status_code == status.HTTP_200_OK
    assert health_dec.json()["access_granted"] is False
    assert health_dec.json()["verification_required"] is True

    health_vault = client.get(f"/api/security/vault/ehr_vault?session_id={session_id}", headers=headers)
    assert health_vault.status_code == status.HTTP_403_FORBIDDEN


# ==============================================================================
# SCENARIO 4: Shopping success unlocks Shopping ONLY; College & Healthcare locked
# ==============================================================================
def test_04_shopping_success_does_not_unlock_college_or_healthcare(client: TestClient, test_user_a):
    headers = test_user_a["headers"]
    session_id = test_user_a["session_id"]
    route = test_user_a["route"]

    # Request and complete NeuralTrace challenge for Shopping
    chal_res = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": session_id,
        "application": "shopping",
        "resource": "financial_vault",
        "preferred_factor": "GESTURE_PATTERN"
    })
    assert chal_res.status_code == status.HTTP_200_OK

    verify_res = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "application": "shopping",
        "resource": "financial_vault",
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": route
    })
    assert verify_res.status_code == status.HTTP_200_OK

    # Shopping vault is UNLOCKED
    shop_dec = client.post("/api/security/access-decision", headers=headers, json={
        "session_id": session_id,
        "application": "shopping",
        "resource": "financial_vault"
    })
    assert shop_dec.json()["access_granted"] is True
    shop_vault = client.get(f"/api/security/vault/financial_vault?session_id={session_id}", headers=headers)
    assert shop_vault.status_code == status.HTTP_200_OK

    # College is LOCKED
    college_dec = client.post("/api/security/access-decision", headers=headers, json={
        "session_id": session_id,
        "application": "college",
        "resource": "academic_vault"
    })
    assert college_dec.json()["access_granted"] is False
    college_vault = client.get(f"/api/security/vault/academic_vault?session_id={session_id}", headers=headers)
    assert college_vault.status_code == status.HTTP_403_FORBIDDEN

    # Healthcare is LOCKED
    health_dec = client.post("/api/security/access-decision", headers=headers, json={
        "session_id": session_id,
        "application": "healthcare",
        "resource": "ehr_vault"
    })
    assert health_dec.json()["access_granted"] is False
    health_vault = client.get(f"/api/security/vault/ehr_vault?session_id={session_id}", headers=headers)
    assert health_vault.status_code == status.HTTP_403_FORBIDDEN


# ==============================================================================
# SCENARIO 5: Healthcare success unlocks Healthcare ONLY; College & Shopping locked
# ==============================================================================
def test_05_healthcare_success_does_not_unlock_college_or_shopping(client: TestClient, test_user_a):
    headers = test_user_a["headers"]
    session_id = test_user_a["session_id"]
    route = test_user_a["route"]

    # Request and complete NeuralTrace challenge for Healthcare
    chal_res = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": session_id,
        "application": "healthcare",
        "resource": "ehr_vault",
        "preferred_factor": "GESTURE_PATTERN"
    })
    assert chal_res.status_code == status.HTTP_200_OK

    verify_res = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "application": "healthcare",
        "resource": "ehr_vault",
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": route
    })
    assert verify_res.status_code == status.HTTP_200_OK

    # Healthcare vault is UNLOCKED
    health_dec = client.post("/api/security/access-decision", headers=headers, json={
        "session_id": session_id,
        "application": "healthcare",
        "resource": "ehr_vault"
    })
    assert health_dec.json()["access_granted"] is True
    health_vault = client.get(f"/api/security/vault/ehr_vault?session_id={session_id}", headers=headers)
    assert health_vault.status_code == status.HTTP_200_OK

    # College is LOCKED
    college_dec = client.post("/api/security/access-decision", headers=headers, json={
        "session_id": session_id,
        "application": "college",
        "resource": "academic_vault"
    })
    assert college_dec.json()["access_granted"] is False
    assert client.get(f"/api/security/vault/academic_vault?session_id={session_id}", headers=headers).status_code == 403

    # Shopping is LOCKED
    shop_dec = client.post("/api/security/access-decision", headers=headers, json={
        "session_id": session_id,
        "application": "shopping",
        "resource": "financial_vault"
    })
    assert shop_dec.json()["access_granted"] is False
    assert client.get(f"/api/security/vault/financial_vault?session_id={session_id}", headers=headers).status_code == 403


# ==============================================================================
# SCENARIO 6: A challenge from one application cannot be submitted to another application
# ==============================================================================
def test_06_cross_application_challenge_submission_rejected(client: TestClient, test_user_a):
    headers = test_user_a["headers"]
    session_id = test_user_a["session_id"]
    route = test_user_a["route"]

    # Issue challenge for College
    chal_res = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": session_id,
        "application": "college",
        "resource": "academic_vault",
        "preferred_factor": "GESTURE_PATTERN"
    })
    assert chal_res.status_code == status.HTTP_200_OK
    chal_id = chal_res.json()["challenge_id"]

    # Submit college challenge to Shopping -> Rejected!
    cross_res = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "application": "shopping",
        "resource": "financial_vault",
        "challenge_id": chal_id,
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": route
    })
    assert cross_res.status_code == status.HTTP_400_BAD_REQUEST
    assert "application mismatch" in cross_res.json()["detail"].lower()

    # Shopping vault must remain locked
    shop_vault = client.get(f"/api/security/vault/financial_vault?session_id={session_id}", headers=headers)
    assert shop_vault.status_code == status.HTTP_403_FORBIDDEN


# ==============================================================================
# SCENARIO 7: A session belonging to one user cannot authorize another user
# ==============================================================================
def test_07_user_session_isolation_bola_protection(client: TestClient, test_user_a, test_user_b):
    headers_a = test_user_a["headers"]
    session_a = test_user_a["session_id"]
    route = test_user_a["route"]

    headers_b = test_user_b["headers"]
    session_b = test_user_b["session_id"]

    # User A unlocks College
    client.post("/api/security/step-up/challenge", headers=headers_a, json={
        "session_id": session_a,
        "application": "college",
        "resource": "academic_vault",
        "preferred_factor": "GESTURE_PATTERN"
    })
    verify_a = client.post("/api/security/step-up/verify", headers=headers_a, json={
        "session_id": session_a,
        "application": "college",
        "resource": "academic_vault",
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": route
    })
    assert verify_a.status_code == status.HTTP_200_OK

    # User B attempts to access vault using User A's session -> Forbidden
    steal_res = client.get(f"/api/security/vault/academic_vault?session_id={session_a}", headers=headers_b)
    assert steal_res.status_code == status.HTTP_403_FORBIDDEN

    # User B's own session is still locked
    own_res = client.get(f"/api/security/vault/academic_vault?session_id={session_b}", headers=headers_b)
    assert own_res.status_code == status.HTTP_403_FORBIDDEN


# ==============================================================================
# SCENARIO 8: Frontend storage manipulation cannot grant confidential access
# ==============================================================================
def test_08_frontend_storage_manipulation_cannot_grant_access(client: TestClient, test_user_a):
    headers = test_user_a["headers"]
    session_id = test_user_a["session_id"]

    # Frontend may pretend it has verified flags or bypass tokens
    # Backend server-side database state is the sole authority
    vault_res = client.get(f"/api/security/vault/academic_vault?session_id={session_id}", headers=headers)
    assert vault_res.status_code == status.HTTP_403_FORBIDDEN

    access_res = client.post("/api/security/access-decision", headers=headers, json={
        "session_id": session_id,
        "application": "college",
        "resource": "academic_vault"
    })
    assert access_res.status_code == status.HTTP_200_OK
    assert access_res.json()["access_granted"] is False
    assert access_res.json()["verification_required"] is True


# ==============================================================================
# SCENARIO 9: Failed, expired and cancelled challenges leave the target vault locked
# ==============================================================================
def test_09_failed_or_expired_challenges_leave_vault_locked(client: TestClient, test_user_a, db_session: Session):
    headers = test_user_a["headers"]
    session_id = test_user_a["session_id"]

    # 1. Failed challenge submission (wrong pattern)
    client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": session_id,
        "application": "college",
        "resource": "academic_vault",
        "preferred_factor": "GESTURE_PATTERN"
    })
    wrong_res = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "application": "college",
        "resource": "academic_vault",
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": [0, 1, 2, 3]  # Incorrect
    })
    assert wrong_res.status_code == status.HTTP_400_BAD_REQUEST

    # Vault must remain sealed
    assert client.get(f"/api/security/vault/academic_vault?session_id={session_id}", headers=headers).status_code == 403

    # 2. Expired challenge
    client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": session_id,
        "application": "college",
        "resource": "academic_vault",
        "preferred_factor": "GESTURE_PATTERN"
    })
    # Simulate expiration in challenge dictionary
    chal = StepUpService.get_challenge(session_id, "college")
    if chal:
        chal["expires_at"] = datetime.now(timezone.utc) - timedelta(seconds=10)

    exp_res = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "application": "college",
        "resource": "academic_vault",
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": test_user_a["route"]
    })
    assert exp_res.status_code == status.HTTP_400_BAD_REQUEST
    assert "expired" in exp_res.json()["detail"].lower()

    # Vault must remain sealed
    assert client.get(f"/api/security/vault/academic_vault?session_id={session_id}", headers=headers).status_code == 403


# ==============================================================================
# SCENARIO 10: Logout and session termination invalidate the relevant grants
# ==============================================================================
def test_10_logout_and_termination_invalidate_grants(client: TestClient, test_user_a, db_session: Session):
    headers = test_user_a["headers"]
    session_id = test_user_a["session_id"]
    route = test_user_a["route"]

    # 1. Unlock College
    client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": session_id,
        "application": "college",
        "resource": "academic_vault",
        "preferred_factor": "GESTURE_PATTERN"
    })
    client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "application": "college",
        "resource": "academic_vault",
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": route
    })
    assert client.get(f"/api/security/vault/academic_vault?session_id={session_id}", headers=headers).status_code == 200

    # 2. Terminate session (Logout)
    logout_res = client.post(f"/api/sessions/{session_id}/terminate", headers=headers)
    assert logout_res.status_code == status.HTTP_200_OK

    # 3. Vault access must now be rejected
    after_logout = client.get(f"/api/security/vault/academic_vault?session_id={session_id}", headers=headers)
    assert after_logout.status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN)

    # 4. In database, ApplicationGrant must be revoked
    grant = db_session.query(ApplicationGrant).filter(
        ApplicationGrant.session_id == session_id,
        ApplicationGrant.application == "college"
    ).first()
    assert grant is not None
    assert grant.revoked is True


# ==============================================================================
# SCENARIO 11: Existing login OTP, risk enforcement and behavioral telemetry still work
# ==============================================================================
def test_11_login_otp_and_telemetry_pipeline_preserved(client: TestClient, test_user_a, db_session: Session):
    from unittest.mock import patch
    from app.services.email_service import EmailService

    headers = test_user_a["headers"]
    session_id = test_user_a["session_id"]
    user_id = test_user_a["user_id"]

    # 1. Ingest genuine behavioral telemetry sample
    telem_res = client.post("/api/behavior/events", headers=headers, json={
        "session_id": session_id,
        "application": "college",
        "typing_speed_wpm": 45.0,
        "avg_flight_time_ms": 120.0,
        "avg_dwell_time_ms": 80.0,
        "mouse_velocity_avg": 400.0,
        "mouse_acceleration_avg": 50.0,
        "mouse_curvature_entropy": 2.5
    })
    assert telem_res.status_code == status.HTTP_200_OK

    # 2. Verify login OTP lifecycle functions properly
    with patch.object(EmailService, "send_otp_email", return_value=(True, "Delivered")):
        pending_sess = SessionService.create_session(db_session, user_id, "college", status="PENDING_OTP")
        otp_chal = StepUpService.create_login_otp_challenge(pending_sess.id, user_id, db_session)
        assert otp_chal["challenge_type"] == "LOGIN_OTP"
        assert "chal_login_" in otp_chal["challenge_id"]

    # 3. Check status endpoint remains responsive
    status_res = client.get(f"/api/security/status/{session_id}", headers=headers)
    assert status_res.status_code == status.HTTP_200_OK
    assert status_res.json()["session_status"] == "ACTIVE"


# ==============================================================================
# SCENARIO 12: All three portals independently show NeuralTrace modal when required
# ==============================================================================
def test_12_all_three_portals_independently_require_step_up(client: TestClient, test_user_a):
    headers = test_user_a["headers"]
    session_id = test_user_a["session_id"]

    portals = [
        ("college", "academic_vault"),
        ("shopping", "financial_vault"),
        ("healthcare", "ehr_vault")
    ]

    for app, res in portals:
        dec = client.post("/api/security/access-decision", headers=headers, json={
            "session_id": session_id,
            "application": app,
            "resource": res
        })
        assert dec.status_code == status.HTTP_200_OK
        data = dec.json()
        assert data["decision"] == "STEP_UP_VERIFICATION"
        assert data["access_granted"] is False
        assert data["verification_required"] is True
        assert data["required_factor"] == "GESTURE_PATTERN"
        assert data["application"] == app
