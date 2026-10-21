import pytest
import datetime
from datetime import timedelta, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.session import Session as DbSession
from app.models.application_grant import ApplicationGrant
from app.services.session_service import SessionService
from app.services.step_up_service import StepUpService
from app.services.adaptive_auth_service import AdaptiveAuthService


def _setup_high_risk_user_and_session(db_session: Session, email: str = "highrisk.user@cognisec.ai"):
    """Helper to create an active user, enroll both cognitive factors, and create a HIGH risk session."""
    user = db_session.query(User).filter(User.email == email).first()
    if not user:
        from app.core.security import get_password_hash
        user = User(
            name="High Risk Test User",
            email=email,
            password_hash=get_password_hash("SecurePass@123"),
            role="USER",
            account_status="ACTIVE"
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

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

    # Create session
    session_id = f"test_highrisk_{user.id}_{int(datetime.datetime.now().timestamp())}"
    now = datetime.datetime.now(timezone.utc)
    sess = DbSession(
        id=session_id,
        user_id=user.id,
        application="college",
        login_time=now,
        status="RESTRICTED",
        current_risk_level="HIGH"
    )
    db_session.add(sess)
    db_session.commit()
    db_session.refresh(sess)

    from app.core.security import create_access_token
    token = create_access_token(subject=user.id, role=user.role, session_id=session_id)
    headers = {"Authorization": f"Bearer {token}"}

    return user, sess, headers


def test_high_risk_decision_opens_intended_verification_flow(client: TestClient, db_session: Session):
    """Scenario 1: HIGH-risk protected resource decision requests HIGH_RISK_DUAL verification."""
    user, sess, headers = _setup_high_risk_user_and_session(db_session, "user1@cognisec.ai")

    # 1. Access-decision on confidential academic vault
    resp = client.post("/api/security/access-decision", headers=headers, json={
        "session_id": sess.id,
        "application": "college",
        "resource": "academic_vault"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "STEP_UP_VERIFICATION"
    assert data["access_granted"] is False
    assert data["session_status"] == "RESTRICTED"
    assert data["risk_level"] == "HIGH"
    assert data["verification_required"] is True
    assert data["required_factor"] == "HIGH_RISK_DUAL"

    # 2. Request adaptive challenge
    chal_resp = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": sess.id,
        "application": "college",
        "resource": "academic_vault",
        "preferred_factor": "HIGH_RISK_DUAL"
    })
    assert chal_resp.status_code == 200
    chal = chal_resp.json()
    assert chal["challenge_type"] == "HIGH_RISK_DUAL"
    assert chal["stage"] == 1
    assert chal["stage_1_passed"] is False
    assert chal["challenge_id"] is not None
    assert chal["catalogue"] is not None
    assert len(chal["catalogue"]) >= 3


def test_correct_first_factor_advances_but_grants_no_access(client: TestClient, db_session: Session):
    """Scenario 2: Correct Stage 1 image sequence advances to Stage 2 without granting access."""
    user, sess, headers = _setup_high_risk_user_and_session(db_session, "user2@cognisec.ai")

    chal_resp = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": sess.id,
        "application": "college",
        "resource": "academic_vault",
        "preferred_factor": "HIGH_RISK_DUAL"
    })
    cid = chal_resp.json()["challenge_id"]

    # Submit valid Stage 1
    ver_resp = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sess.id,
        "challenge_id": cid,
        "challenge_type": "HIGH_RISK_DUAL",
        "stage": 1,
        "application": "college",
        "resource": "academic_vault",
        "image_sequence": ["img_shield", "img_key", "img_lock"]
    })
    assert ver_resp.status_code == 200
    ver_data = ver_resp.json()
    assert ver_data["decision"] == "STEP_UP_VERIFICATION"
    assert ver_data["stage"] == 2
    assert ver_data["stage_1_passed"] is True
    assert ver_data["confidential_access_granted"] is False
    assert ver_data["step_up_fresh"] is False
    assert "What is the cryptographic algorithm?" in ver_data["prompt"]

    # Assert no grant was created
    grant = db_session.query(ApplicationGrant).filter(
        ApplicationGrant.session_id == sess.id,
        ApplicationGrant.application == "college",
        ApplicationGrant.revoked == False
    ).first()
    assert grant is None

    # Assert vault remains locked (403 Forbidden)
    vault_resp = client.get(f"/api/security/vault/academic_vault?session_id={sess.id}", headers=headers)
    assert vault_resp.status_code == 403


def test_wrong_first_factor_does_not_advance(client: TestClient, db_session: Session):
    """Scenario 3: Wrong first factor rejects and does not advance."""
    user, sess, headers = _setup_high_risk_user_and_session(db_session, "user3@cognisec.ai")

    chal_resp = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": sess.id,
        "application": "college",
        "resource": "academic_vault"
    })
    cid = chal_resp.json()["challenge_id"]

    # Submit incorrect Stage 1 sequence
    ver_resp = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sess.id,
        "challenge_id": cid,
        "challenge_type": "HIGH_RISK_DUAL",
        "stage": 1,
        "application": "college",
        "resource": "academic_vault",
        "image_sequence": ["img_chip", "img_token", "img_radar"]
    })
    assert ver_resp.status_code == 400
    assert "Invalid cognitive image sequence" in ver_resp.json()["detail"]


def test_correct_second_factor_after_stage1_grants_access(client: TestClient, db_session: Session):
    """Scenario 4: Sequential flow completes both stages and grants vault access."""
    user, sess, headers = _setup_high_risk_user_and_session(db_session, "user4@cognisec.ai")

    chal_resp = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": sess.id,
        "application": "college",
        "resource": "academic_vault"
    })
    cid = chal_resp.json()["challenge_id"]

    # Stage 1: Image sequence
    s1_resp = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sess.id,
        "challenge_id": cid,
        "challenge_type": "HIGH_RISK_DUAL",
        "stage": 1,
        "application": "college",
        "resource": "academic_vault",
        "image_sequence": ["img_shield", "img_key", "img_lock"]
    })
    assert s1_resp.status_code == 200
    assert s1_resp.json()["stage_1_passed"] is True

    # Stage 2: Private response
    s2_resp = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sess.id,
        "challenge_id": cid,
        "challenge_type": "HIGH_RISK_DUAL",
        "stage": 2,
        "application": "college",
        "resource": "academic_vault",
        "private_response": "argon2id-aes-256"
    })
    assert s2_resp.status_code == 200
    s2_data = s2_resp.json()
    assert s2_data["decision"] == "ALLOW"
    assert s2_data["confidential_access_granted"] is True
    assert s2_data["step_up_fresh"] is True
    assert s2_data["step_up_factor"] == "HIGH_RISK_DUAL"
    assert s2_data["session_status"] == "ACTIVE"

    # Verify ApplicationGrant in database
    db_session.expire_all()
    grant = db_session.query(ApplicationGrant).filter(
        ApplicationGrant.session_id == sess.id,
        ApplicationGrant.application == "college",
        ApplicationGrant.resource == "academic_vault",
        ApplicationGrant.factor == "HIGH_RISK_DUAL",
        ApplicationGrant.revoked == False
    ).first()
    assert grant is not None
    assert grant.factor == "HIGH_RISK_DUAL"

    # Verify protected vault access succeeds
    vault_resp = client.get(f"/api/security/vault/academic_vault?session_id={sess.id}", headers=headers)
    assert vault_resp.status_code == 200
    assert vault_resp.json()["access_granted"] is True


def test_wrong_second_factor_remains_denied(client: TestClient, db_session: Session):
    """Scenario 5: Wrong second factor remains denied after Stage 1 passed."""
    user, sess, headers = _setup_high_risk_user_and_session(db_session, "user5@cognisec.ai")

    chal_resp = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": sess.id,
        "application": "college",
        "resource": "academic_vault"
    })
    cid = chal_resp.json()["challenge_id"]

    # Stage 1 succeeds
    client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sess.id,
        "challenge_id": cid,
        "challenge_type": "HIGH_RISK_DUAL",
        "stage": 1,
        "application": "college",
        "resource": "academic_vault",
        "image_sequence": ["img_shield", "img_key", "img_lock"]
    })

    # Stage 2 with wrong answer
    s2_bad = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sess.id,
        "challenge_id": cid,
        "challenge_type": "HIGH_RISK_DUAL",
        "stage": 2,
        "application": "college",
        "resource": "academic_vault",
        "private_response": "WrongAnswer123"
    })
    assert s2_bad.status_code == 400
    assert "Invalid private response" in s2_bad.json()["detail"]

    # Vault access must remain 403
    vault_resp = client.get(f"/api/security/vault/academic_vault?session_id={sess.id}", headers=headers)
    assert vault_resp.status_code == 403


def test_missing_enrollment_does_not_trigger_weaker_fallback(client: TestClient, db_session: Session):
    """Scenario 6: Missing either cognitive factor refuses fallback and denies access."""
    # Create user with NO enrollment
    from app.core.security import get_password_hash, create_access_token
    user = User(
        name="Unenrolled High Risk User",
        email="unenrolled.highrisk@cognisec.ai",
        password_hash=get_password_hash("Pass@123"),
        role="USER",
        account_status="ACTIVE"
    )
    db_session.add(user)
    db_session.commit()

    now = datetime.datetime.now(timezone.utc)
    sess = DbSession(
        id=f"unenrolled_sess_{user.id}",
        user_id=user.id,
        application="college",
        login_time=now,
        status="RESTRICTED",
        current_risk_level="HIGH"
    )
    db_session.add(sess)
    db_session.commit()

    token = create_access_token(subject=user.id, role=user.role, session_id=sess.id)
    headers = {"Authorization": f"Bearer {token}"}

    # 1. /access-decision returns RESTRICT with enrollment required, no fallback to OTP/NeuralTrace
    dec_resp = client.post("/api/security/access-decision", headers=headers, json={
        "session_id": sess.id,
        "application": "college",
        "resource": "academic_vault"
    })
    assert dec_resp.status_code == 200
    dec = dec_resp.json()
    assert dec["decision"] == "RESTRICT"
    assert dec["verification_required"] is False
    assert "enrolled first" in dec["message"]

    # 2. Challenge generation returns 409 Conflict, refuses OTP fallback
    chal_resp = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": sess.id,
        "application": "college",
        "resource": "academic_vault",
        "preferred_factor": "HIGH_RISK_DUAL"
    })
    assert chal_resp.status_code == 409
    assert "High risk verification requires both" in chal_resp.json()["detail"]


def test_challenge_integrity_out_of_order_replay_and_missing_id(client: TestClient, db_session: Session):
    """Scenario 7: Enforce challenge integrity (missing ID, out of order, replay)."""
    user, sess, headers = _setup_high_risk_user_and_session(db_session, "user7@cognisec.ai")

    chal_resp = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": sess.id,
        "application": "college",
        "resource": "academic_vault"
    })
    cid = chal_resp.json()["challenge_id"]

    # 1. Missing challenge ID
    missing_id_resp = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sess.id,
        "challenge_type": "HIGH_RISK_DUAL",
        "stage": 1,
        "image_sequence": ["img_shield", "img_key", "img_lock"]
    })
    assert missing_id_resp.status_code == 400
    assert "Missing challenge ID" in missing_id_resp.json()["detail"]

    # 2. Out-of-order: Submitting Stage 2 before Stage 1
    out_of_order_resp = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sess.id,
        "challenge_id": cid,
        "challenge_type": "HIGH_RISK_DUAL",
        "stage": 2,
        "private_response": "argon2id-aes-256"
    })
    assert out_of_order_resp.status_code == 400
    assert "Out of order" in out_of_order_resp.json()["detail"]

    # Complete Stage 1 and Stage 2 legitimately
    client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sess.id,
        "challenge_id": cid,
        "challenge_type": "HIGH_RISK_DUAL",
        "stage": 1,
        "image_sequence": ["img_shield", "img_key", "img_lock"]
    })
    ok_resp = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sess.id,
        "challenge_id": cid,
        "challenge_type": "HIGH_RISK_DUAL",
        "stage": 2,
        "private_response": "argon2id-aes-256"
    })
    assert ok_resp.status_code == 200

    # 3. Replay protection: Submitting same challenge_id again must be rejected
    replay_resp = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sess.id,
        "challenge_id": cid,
        "challenge_type": "HIGH_RISK_DUAL",
        "stage": 2,
        "private_response": "argon2id-aes-256"
    })
    assert replay_resp.status_code == 400
    assert "No active step-up challenge found" in replay_resp.json()["detail"]


def test_challenge_binding_cross_portal_and_cross_resource(client: TestClient, db_session: Session):
    """Scenario 8: Cross-portal and cross-resource submissions are strictly rejected."""
    user, sess, headers = _setup_high_risk_user_and_session(db_session, "user8@cognisec.ai")

    # Issue challenge bound to college / academic_vault
    chal_resp = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": sess.id,
        "application": "college",
        "resource": "academic_vault"
    })
    cid = chal_resp.json()["challenge_id"]

    # Attempt cross-portal submission to shopping
    cross_app_resp = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sess.id,
        "challenge_id": cid,
        "challenge_type": "HIGH_RISK_DUAL",
        "stage": 1,
        "application": "shopping",
        "resource": "financial_vault",
        "image_sequence": ["img_shield", "img_key", "img_lock"]
    })
    assert cross_app_resp.status_code == 400
    assert "Challenge application mismatch" in cross_app_resp.json()["detail"]


def test_grant_creation_failure_does_not_return_allow(client: TestClient, db_session: Session, monkeypatch):
    """Scenario 9: If grant creation fails/returns None, verify does NOT return ALLOW."""
    user, sess, headers = _setup_high_risk_user_and_session(db_session, "user9@cognisec.ai")

    chal_resp = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": sess.id,
        "application": "college",
        "resource": "academic_vault"
    })
    cid = chal_resp.json()["challenge_id"]

    # Stage 1 succeeds
    client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sess.id,
        "challenge_id": cid,
        "challenge_type": "HIGH_RISK_DUAL",
        "stage": 1,
        "application": "college",
        "resource": "academic_vault",
        "image_sequence": ["img_shield", "img_key", "img_lock"]
    })

    # Monkeypatch record_application_grant to simulate failure (returns None)
    monkeypatch.setattr(SessionService, "record_application_grant", lambda *args, **kwargs: None)

    fail_resp = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sess.id,
        "challenge_id": cid,
        "challenge_type": "HIGH_RISK_DUAL",
        "stage": 2,
        "application": "college",
        "resource": "academic_vault",
        "private_response": "argon2id-aes-256"
    })
    assert fail_resp.status_code == 500
    assert "Failed to create application grant" in fail_resp.json()["detail"]


def test_portal_isolation_college_shopping_healthcare(client: TestClient, db_session: Session):
    """Scenario 10: Preserves independent grants across College, Shopping, and Healthcare."""
    user, sess, headers = _setup_high_risk_user_and_session(db_session, "user10@cognisec.ai")

    # Complete step-up on College
    chal_resp = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": sess.id,
        "application": "college",
        "resource": "academic_vault"
    })
    cid = chal_resp.json()["challenge_id"]
    client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sess.id,
        "challenge_id": cid,
        "challenge_type": "HIGH_RISK_DUAL",
        "stage": 1,
        "application": "college",
        "resource": "academic_vault",
        "image_sequence": ["img_shield", "img_key", "img_lock"]
    })
    ok_resp = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sess.id,
        "challenge_id": cid,
        "challenge_type": "HIGH_RISK_DUAL",
        "stage": 2,
        "application": "college",
        "resource": "academic_vault",
        "private_response": "argon2id-aes-256"
    })
    assert ok_resp.status_code == 200

    # College academic_vault is authorized
    ac_resp = client.get(f"/api/security/vault/academic_vault?session_id={sess.id}", headers=headers)
    assert ac_resp.status_code == 200

    # Shopping financial_vault is NOT authorized (403 Forbidden)
    shop_resp = client.get(f"/api/security/vault/financial_vault?session_id={sess.id}", headers=headers)
    assert shop_resp.status_code == 403

    # Healthcare ehr_vault is NOT authorized (403 Forbidden)
    ehr_resp = client.get(f"/api/security/vault/ehr_vault?session_id={sess.id}", headers=headers)
    assert ehr_resp.status_code == 403


def test_dual_factor_grant_passes_actual_authorization_check(client: TestClient, db_session: Session):
    """Scenario 11: Authoritative SessionService.is_application_authorized validates HIGH_RISK_DUAL."""
    user, sess, headers = _setup_high_risk_user_and_session(db_session, "user11@cognisec.ai")

    now = datetime.datetime.now(timezone.utc)
    grant = ApplicationGrant(
        session_id=sess.id,
        user_id=user.id,
        application="college",
        resource="academic_vault",
        factor="HIGH_RISK_DUAL",
        granted_at=now,
        expires_at=now + timedelta(minutes=15),
        revoked=False
    )
    db_session.add(grant)
    sess.status = "ACTIVE"
    sess.current_risk_level = "LOW"
    db_session.commit()

    # Matching factor check succeeds
    assert SessionService.is_application_authorized(
        db=db_session,
        db_session=sess,
        user_id=user.id,
        application="college",
        resource="academic_vault",
        required_factor="HIGH_RISK_DUAL"
    ) is True

    # Mismatched factor check fails (cannot claim GESTURE_PATTERN)
    assert SessionService.is_application_authorized(
        db=db_session,
        db_session=sess,
        user_id=user.id,
        application="college",
        resource="academic_vault",
        required_factor="GESTURE_PATTERN"
    ) is False
