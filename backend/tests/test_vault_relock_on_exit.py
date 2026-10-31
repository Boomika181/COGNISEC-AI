import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.session import Session as DbSession
from app.models.application_grant import ApplicationGrant
from app.models.security_event import SecurityEvent
from app.core.security import get_password_hash, create_access_token


@pytest.fixture
def test_user_and_session(db_session: Session):
    """Creates a standard active user and session for testing vault operations."""
    email = f"relock_test_{int(datetime.now().timestamp() * 1000)}@cognisec.ai"
    user = User(
        email=email,
        password_hash=get_password_hash("Password123!"),
        name="Relock Tester",
        role="USER",
        account_status="ACTIVE",
        failed_login_attempts=0
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    now = datetime.now(timezone.utc)
    sess = DbSession(
        id=f"sess_relock_{user.id}_{int(now.timestamp())}",
        user_id=user.id,
        application="college",
        login_time=now,
        status="ACTIVE",
        current_risk_level="LOW"
    )
    db_session.add(sess)
    db_session.commit()
    db_session.refresh(sess)

    token = create_access_token(subject=user.id, role=user.role, session_id=sess.id)
    headers = {"Authorization": f"Bearer {token}"}
    return user, sess, headers


@pytest.fixture
def doctor_user_and_session(db_session: Session):
    """Creates an active doctor user and session for testing clinical vault operations."""
    email = f"dr_relock_{int(datetime.now().timestamp() * 1000)}@ayusync.med.in"
    user = User(
        email=email,
        password_hash=get_password_hash("DoctorPassword123!"),
        name="Dr. Relock Tester",
        role="DOCTOR",
        account_status="ACTIVE",
        failed_login_attempts=0
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    now = datetime.now(timezone.utc)
    sess = DbSession(
        id=f"sess_dr_relock_{user.id}_{int(now.timestamp())}",
        user_id=user.id,
        application="healthcare",
        login_time=now,
        status="ACTIVE",
        current_risk_level="LOW"
    )
    db_session.add(sess)
    db_session.commit()
    db_session.refresh(sess)

    token = create_access_token(subject=user.id, role=user.role, session_id=sess.id)
    headers = {"Authorization": f"Bearer {token}"}
    return user, sess, headers


def _issue_grant(db_session: Session, user: User, sess: DbSession, app: str, res: str) -> ApplicationGrant:
    now = datetime.now(timezone.utc)
    grant = ApplicationGrant(
        session_id=sess.id,
        user_id=user.id,
        application=app,
        resource=res,
        factor="GESTURE_PATTERN",
        granted_at=now,
        expires_at=now + timedelta(minutes=15),
        revoked=False
    )
    db_session.add(grant)
    db_session.commit()
    db_session.refresh(grant)
    return grant


# ==============================================================================
# TEST 1: College Academic Vault Relock on Platform Exit
# ==============================================================================
def test_1_college_academic_vault_relock_on_exit(client: TestClient, test_user_and_session, db_session: Session):
    user, sess, headers = test_user_and_session
    _issue_grant(db_session, user, sess, "college", "academic_vault")

    # 1. Access granted initially
    resp = client.get(f"/api/security/vault/academic_vault?session_id={sess.id}", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["access_granted"] is True
    assert "no-store" in resp.headers.get("Cache-Control", "").lower()

    # 2. User exits portal / clicks Back to Platform -> Relock
    relock_resp = client.post("/api/security/vault/relock", headers=headers, json={
        "session_id": sess.id,
        "resource": "academic_vault",
        "application": "college"
    })
    assert relock_resp.status_code == 200
    data = relock_resp.json()
    assert data["success"] is True
    assert data["vault_status"] == "LOCKED"
    assert data["revoked_count"] >= 1

    # 3. Direct vault access immediately returns 403 Forbidden
    denied_resp = client.get(f"/api/security/vault/academic_vault?session_id={sess.id}", headers=headers)
    assert denied_resp.status_code == 403
    assert "transcripts" not in denied_resp.json()

    # 4. Access decision reflects locked status
    dec_resp = client.post("/api/security/access-decision", headers=headers, json={
        "session_id": sess.id,
        "resource": "academic_vault",
        "application": "college"
    })
    assert dec_resp.status_code == 200
    assert dec_resp.json()["access_granted"] is False
    assert dec_resp.json()["verification_required"] is True

    # 5. User session remains ACTIVE (not terminated)
    db_session.refresh(sess)
    assert sess.status == "ACTIVE"


# ==============================================================================
# TEST 2: Shopping Financial Vault Relock on Platform Exit
# ==============================================================================
def test_2_shopping_financial_vault_relock_on_exit(client: TestClient, test_user_and_session, db_session: Session):
    user, sess, headers = test_user_and_session
    sess.application = "shopping"
    db_session.commit()

    _issue_grant(db_session, user, sess, "shopping", "financial_vault")

    # 1. Access granted initially
    resp = client.get(f"/api/security/vault/financial_vault?session_id={sess.id}", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["access_granted"] is True
    assert "no-store" in resp.headers.get("Cache-Control", "").lower()

    # 2. Relock endpoint invoked
    relock_resp = client.post("/api/security/vault/relock", headers=headers, json={
        "session_id": sess.id,
        "resource": "financial_vault",
        "application": "shopping"
    })
    assert relock_resp.status_code == 200
    assert relock_resp.json()["success"] is True

    # 3. Direct access forbidden
    denied_resp = client.get(f"/api/security/vault/financial_vault?session_id={sess.id}", headers=headers)
    assert denied_resp.status_code == 403

    # 4. Session remains active
    db_session.refresh(sess)
    assert sess.status == "ACTIVE"


# ==============================================================================
# TEST 3: Healthcare Clinical EHR Vault Relock on Platform Exit
# ==============================================================================
def test_3_healthcare_clinical_vault_relock_on_exit(client: TestClient, doctor_user_and_session, db_session: Session):
    doc_user, doc_sess, doc_headers = doctor_user_and_session
    _issue_grant(db_session, doc_user, doc_sess, "healthcare", "ehr_vault")

    # 1. Doctor accesses EHR vault
    resp = client.get(f"/api/security/vault/ehr_vault?session_id={doc_sess.id}", headers=doc_headers)
    assert resp.status_code == 200
    assert resp.json()["access_granted"] is True
    assert "clinical_diagnosis" in resp.json()["data"]
    assert "no-store" in resp.headers.get("Cache-Control", "").lower()

    # 2. Doctor leaves portal -> Relock
    relock_resp = client.post("/api/security/vault/relock", headers=doc_headers, json={
        "session_id": doc_sess.id,
        "resource": "ehr_vault",
        "application": "healthcare"
    })
    assert relock_resp.status_code == 200
    assert relock_resp.json()["vault_status"] == "LOCKED"

    # 3. Direct access denied
    denied_resp = client.get(f"/api/security/vault/ehr_vault?session_id={doc_sess.id}", headers=doc_headers)
    assert denied_resp.status_code == 403
    assert "patient_profile" not in denied_resp.json()

    # 4. Doctor session remains ACTIVE
    db_session.refresh(doc_sess)
    assert doc_sess.status == "ACTIVE"


# ==============================================================================
# TEST 4: Security Audit Trail Records VAULT_GRANT_REVOKED Event
# ==============================================================================
def test_4_security_audit_event_logged_on_relock(client: TestClient, test_user_and_session, db_session: Session):
    user, sess, headers = test_user_and_session
    _issue_grant(db_session, user, sess, "college", "academic_vault")

    client.post("/api/security/vault/relock", headers=headers, json={
        "session_id": sess.id,
        "resource": "academic_vault"
    })

    audit_event = db_session.query(SecurityEvent).filter(
        SecurityEvent.user_id == user.id,
        SecurityEvent.session_id == sess.id,
        SecurityEvent.event_type == "VAULT_GRANT_REVOKED"
    ).first()

    assert audit_event is not None
    assert audit_event.decision == "ALLOW"
    assert "academic_vault" in audit_event.details
    assert "LOCKED" in audit_event.details


# ==============================================================================
# TEST 5: Cross-Portal Isolation on Relock
# ==============================================================================
def test_5_cross_portal_isolation_on_relock(client: TestClient, test_user_and_session, db_session: Session):
    """Relocking one portal's vault does NOT revoke a grant in a different portal."""
    user, sess, headers = test_user_and_session
    _issue_grant(db_session, user, sess, "college", "academic_vault")
    _issue_grant(db_session, user, sess, "shopping", "financial_vault")

    # Relock college only
    relock_resp = client.post("/api/security/vault/relock", headers=headers, json={
        "session_id": sess.id,
        "resource": "academic_vault",
        "application": "college"
    })
    assert relock_resp.status_code == 200

    # College is locked
    assert client.get(f"/api/security/vault/academic_vault?session_id={sess.id}", headers=headers).status_code == 403

    # Shopping grant in database is still NOT revoked
    shop_grant = db_session.query(ApplicationGrant).filter(
        ApplicationGrant.session_id == sess.id,
        ApplicationGrant.resource == "financial_vault"
    ).first()
    assert shop_grant is not None
    assert shop_grant.revoked is False


# ==============================================================================
# TEST 6: Unauthorized and Invalid Relock Requests are Rejected
# ==============================================================================
def test_6_unauthorized_and_invalid_relock_requests(client: TestClient, test_user_and_session, doctor_user_and_session):
    user, sess, headers = test_user_and_session
    doc_user, doc_sess, doc_headers = doctor_user_and_session

    # 1. Unauthenticated request -> 401
    r_unauth = client.post("/api/security/vault/relock", json={
        "session_id": sess.id,
        "resource": "academic_vault"
    })
    assert r_unauth.status_code == 401

    # 2. User attempting to relock another user's session -> 403
    r_wrong_user = client.post("/api/security/vault/relock", headers=headers, json={
        "session_id": doc_sess.id,
        "resource": "ehr_vault"
    })
    assert r_wrong_user.status_code == 403

    # 3. Invalid / unknown resource -> 400
    r_invalid_res = client.post("/api/security/vault/relock", headers=headers, json={
        "session_id": sess.id,
        "resource": "super_secret_unregistered_vault"
    })
    assert r_invalid_res.status_code == 400

    # 4. Mismatched application and resource -> 400
    r_mismatch = client.post("/api/security/vault/relock", headers=headers, json={
        "session_id": sess.id,
        "resource": "academic_vault",
        "application": "healthcare"
    })
    assert r_mismatch.status_code == 400


# ==============================================================================
# TEST 7: Fresh Verification Issues New Grant After Relock
# ==============================================================================
def test_7_fresh_verification_restores_vault_access_after_relock(client: TestClient, test_user_and_session, db_session: Session):
    user, sess, headers = test_user_and_session
    _issue_grant(db_session, user, sess, "college", "academic_vault")

    # Relock
    client.post("/api/security/vault/relock", headers=headers, json={
        "session_id": sess.id,
        "resource": "academic_vault"
    })
    assert client.get(f"/api/security/vault/academic_vault?session_id={sess.id}", headers=headers).status_code == 403

    # Now simulate fresh authorized step-up grant
    _issue_grant(db_session, user, sess, "college", "academic_vault")

    # Access is restored
    restored_resp = client.get(f"/api/security/vault/academic_vault?session_id={sess.id}", headers=headers)
    assert restored_resp.status_code == 200
    assert restored_resp.json()["access_granted"] is True
