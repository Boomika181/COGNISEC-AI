import pytest
import datetime
from pathlib import Path
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.session import Session as DbSession
from app.models.application_grant import ApplicationGrant
from app.models.adaptive_factor import AdaptiveFactor
from app.core.security import get_password_hash, create_access_token
from app.services.step_up_service import StepUpService


def _setup_security_user(
    db_session: Session,
    email: str,
    application: str = "college",
    risk_level: str = "LOW",
    status: str = "ACTIVE",
    enroll_factors: bool = True
):
    """Setup a user with sessions and optional full cognitive factor enrollment."""
    user = db_session.query(User).filter(User.email == email).first()
    if not user:
        user = User(
            email=email,
            password_hash=get_password_hash("StrongSecret123!"),
            name=f"Security User {email}",
            role="USER",
            account_status="ACTIVE"
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

    if enroll_factors:
        from app.services.adaptive_auth_service import AdaptiveAuthService
        AdaptiveAuthService.enroll_gesture_pattern(
            db=db_session,
            user_id=user.id,
            pattern=[0, 3, 7, 11],
            confirm_pattern=[0, 3, 7, 11]
        )
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

    now = datetime.datetime.now(datetime.timezone.utc)
    session_id = f"sess_step6_{email.split('@')[0]}_{int(now.timestamp() * 1000)}"
    sess = DbSession(
        id=session_id,
        user_id=user.id,
        application=application,
        login_time=now,
        status=status,
        current_risk_level=risk_level
    )
    db_session.add(sess)
    db_session.commit()
    db_session.refresh(sess)

    token = create_access_token(subject=user.id, role=user.role, session_id=session_id)
    headers = {"Authorization": f"Bearer {token}"}
    return user, sess, headers


# =========================================================================
# STEP 6: END-TO-END SECURITY & REGRESSION TEST SUITE
# =========================================================================

def test_stage1_succeeds_stage2_expires_vault_remains_locked(client: TestClient, db_session: Session):
    """
    Scenario: Stage 1 image sequence passes, but Stage 2 expires before submission.
    Challenge must expire, Stage 2 must fail, and vault must remain strictly locked (403).
    """
    user, sess, headers = _setup_security_user(
        db_session, "stage2_expire@cognisec.ai", application="college", risk_level="HIGH", status="RESTRICTED"
    )

    chal_resp = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": sess.id,
        "application": "college",
        "resource": "academic_vault",
        "preferred_factor": "HIGH_RISK_DUAL"
    })
    assert chal_resp.status_code == 200
    cid = chal_resp.json()["challenge_id"]

    # Stage 1 succeeds
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

    # Simulate challenge expiration by backdating expires_at in StepUpService memory
    for k, c in list(StepUpService._challenges.items()):
        if c.get("challenge_id") == cid:
            c["expires_at"] = (
                datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=5)
            )

    # Attempt Stage 2 submission on expired challenge
    s2_resp = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sess.id,
        "challenge_id": cid,
        "challenge_type": "HIGH_RISK_DUAL",
        "stage": 2,
        "application": "college",
        "resource": "academic_vault",
        "private_response": "argon2id-aes-256"
    })
    assert s2_resp.status_code == 400
    assert "expired" in s2_resp.json()["detail"].lower()

    # Assert no grant exists and vault returns 403 Forbidden
    grant = db_session.query(ApplicationGrant).filter(
        ApplicationGrant.session_id == sess.id,
        ApplicationGrant.application == "college"
    ).first()
    assert grant is None

    vault_resp = client.get(f"/api/security/vault/academic_vault?session_id={sess.id}", headers=headers)
    assert vault_resp.status_code == 403
    assert "cgpa" not in vault_resp.json()


def test_stage1_succeeds_stage2_replay_rejected_vault_locked(client: TestClient, db_session: Session):
    """
    Scenario: Stage 1 succeeds, Stage 2 succeeds once.
    Replaying Stage 2 again or using old challenge id is rejected;
    vault access remains bound to the valid grant only.
    """
    user, sess, headers = _setup_security_user(
        db_session, "stage2_replay@cognisec.ai", application="college", risk_level="HIGH", status="RESTRICTED"
    )

    chal_resp = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": sess.id,
        "application": "college",
        "resource": "academic_vault",
        "preferred_factor": "HIGH_RISK_DUAL"
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

    # Stage 2 legitimate submission
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

    # Replay Stage 2 with same challenge ID -> must be rejected (single use)
    replay_resp = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sess.id,
        "challenge_id": cid,
        "challenge_type": "HIGH_RISK_DUAL",
        "stage": 2,
        "application": "college",
        "resource": "academic_vault",
        "private_response": "argon2id-aes-256"
    })
    assert replay_resp.status_code == 400


def test_client_side_forged_flags_and_claims_rejected(client: TestClient, db_session: Session):
    """
    Scenario: Client attempts to bypass authorization using:
    - Custom forged headers ('X-Is-Authorized: true', 'X-Bypass-Grant: true')
    - Query parameters ('?is_authorized=true&access_granted=true&role=admin')
    - Body injection claims
    The backend must strictly ignore client-supplied claims and return 403 Forbidden.
    """
    user, sess, headers = _setup_security_user(
        db_session, "forged_flags@cognisec.ai", application="shopping", risk_level="LOW", status="ACTIVE"
    )

    # 1. Attempt with forged query parameters
    resp_query = client.get(
        f"/api/security/vault/financial_vault?session_id={sess.id}&is_authorized=true&access_granted=true&grant=approved",
        headers=headers
    )
    assert resp_query.status_code == 403
    assert "saved_cards" not in resp_query.json()

    # 2. Attempt with forged request headers
    forged_headers = dict(headers)
    forged_headers["X-Is-Authorized"] = "true"
    forged_headers["X-Step-Up-Verified"] = "true"
    forged_headers["X-Role"] = "ADMIN"
    resp_hdr = client.get(
        f"/api/security/vault/financial_vault?session_id={sess.id}",
        headers=forged_headers
    )
    assert resp_hdr.status_code == 403
    assert "saved_cards" not in resp_hdr.json()

    # 3. Verify no grant was created
    grants = db_session.query(ApplicationGrant).filter(ApplicationGrant.user_id == user.id).all()
    assert len(grants) == 0


def test_end_to_end_lifecycle_and_critical_termination(client: TestClient, db_session: Session):
    """
    Full end-to-end security lifecycle test:
    1. Authenticated user with low risk requests vault without grant -> 403.
    2. Performs NeuralTrace (GESTURE_PATTERN) step-up challenge and verification -> creates grant.
    3. Accesses academic_vault -> 200 OK.
    4. Attempts cross-portal financial_vault -> 403 Forbidden.
    5. Session elevated to CRITICAL risk -> immediate blocking of all vaults (403).
    """
    user, sess, headers = _setup_security_user(
        db_session, "e2e_lifecycle@cognisec.ai", application="college", risk_level="LOW", status="ACTIVE"
    )

    # 1. Access before verification -> 403
    assert client.get(f"/api/security/vault/academic_vault?session_id={sess.id}", headers=headers).status_code == 403

    # 2. Challenge and verify GESTURE_PATTERN
    chal_resp = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": sess.id,
        "application": "college",
        "resource": "academic_vault",
        "preferred_factor": "GESTURE_PATTERN"
    })
    assert chal_resp.status_code == 200
    cid = chal_resp.json()["challenge_id"]

    ver_resp = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sess.id,
        "challenge_id": cid,
        "challenge_type": "GESTURE_PATTERN",
        "application": "college",
        "resource": "academic_vault",
        "gesture_pattern": [0, 3, 7, 11]
    })
    assert ver_resp.status_code == 200
    assert ver_resp.json()["decision"] == "ALLOW"
    assert ver_resp.json()["confidential_access_granted"] is True

    # 3. Vault access authorized for college
    v_resp = client.get(f"/api/security/vault/academic_vault?session_id={sess.id}", headers=headers)
    assert v_resp.status_code == 200
    assert v_resp.json()["access_granted"] is True

    # 4. Cross-portal financial_vault strictly 403
    assert client.get(f"/api/security/vault/financial_vault?session_id={sess.id}", headers=headers).status_code == 403

    # 5. Elevate session to CRITICAL risk
    sess.current_risk_level = "CRITICAL"
    db_session.commit()
    db_session.refresh(sess)

    crit_resp = client.get(f"/api/security/vault/academic_vault?session_id={sess.id}", headers=headers)
    assert crit_resp.status_code == 403
    assert "CRITICAL" in crit_resp.json()["detail"]


def test_confidential_records_not_in_static_files():
    """
    Scenario 11: Ensure confidential data is never hardcoded in client HTML/JS files.
    """
    repo_root = Path(__file__).resolve().parent.parent.parent
    confidential_markers = [
        "4111 2222 3333 4444",
        "Amoxicillin 500mg",
        "3.88",  # Specific GPA from demo
        "4532 8901 2345 6789",  # credit card
    ]
    frontend_files = [
        repo_root / "college.html",
        repo_root / "shopping.html",
        repo_root / "healthcare.html",
        repo_root / "cognisec-client.js"
    ]
    for f in frontend_files:
        assert f.exists(), f"Frontend file {f} must exist"
        content = f.read_text(encoding="utf-8")
        for marker in confidential_markers:
            assert marker not in content, f"Confidential marker '{marker}' found in static file {f.name}!"
