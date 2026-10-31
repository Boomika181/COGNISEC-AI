import uuid
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import get_password_hash
from app.core.rate_limit import rate_limiter
from app.models.user import User
from app.models.security_event import SecurityEvent
from app.models.application_grant import ApplicationGrant
from app.services.session_service import SessionService


@pytest.fixture(autouse=True)
def reset_limiter():
    rate_limiter.reset()
    yield
    rate_limiter.reset()


@pytest.fixture
def admin_account(db_session: Session) -> User:
    """Provides an authenticated admin user for authorized reset tests."""
    email = f"admin.soc.{uuid.uuid4().hex[:6]}@cognisec.ai"
    admin = User(
        name="Security Admin",
        email=email,
        password_hash=get_password_hash("AdminPass2026!"),
        role="ADMIN",
        account_status="ACTIVE",
        failed_login_attempts=0
    )
    db_session.add(admin)
    db_session.commit()
    db_session.refresh(admin)
    return admin


@pytest.fixture
def dev_doctor_account(db_session: Session) -> User:
    """Provides a verified doctor test account for lockout and reset testing."""
    email = f"dr.test.{uuid.uuid4().hex[:6]}@ayusync.med.in"
    doctor = User(
        name="Dr. Test Physician",
        email=email,
        password_hash=get_password_hash("DoctorSecret2026!"),
        role="DOCTOR",
        account_status="ACTIVE",
        failed_login_attempts=0
    )
    db_session.add(doctor)
    db_session.commit()
    db_session.refresh(doctor)
    return doctor


@pytest.fixture
def patient_user_account(db_session: Session) -> User:
    """Provides a standard non-doctor patient account."""
    email = f"patient.{uuid.uuid4().hex[:6]}@cognisec.ai"
    patient = User(
        name="Standard Patient",
        email=email,
        password_hash=get_password_hash("PatientPass2026!"),
        role="USER",
        account_status="ACTIVE",
        failed_login_attempts=0
    )
    db_session.add(patient)
    db_session.commit()
    db_session.refresh(patient)
    return patient


def get_token_for_user(client: TestClient, email: str, password: str, doctor_required: bool = False) -> dict:
    resp = client.post("/api/auth/login", json={
        "email": email,
        "password": password,
        "doctor_required": doctor_required,
        "device_fingerprint": f"fp_{uuid.uuid4().hex[:8]}"
    })
    return resp


def test_1_three_incorrect_doctor_passwords_trigger_lockout(client: TestClient, dev_doctor_account: User, db_session: Session):
    """
    Requirement 1: Three consecutive incorrect password attempts must lock the doctor account.
    Verifies failed attempt count increments, account_status changes to LOCKED, and ACCOUNT_LOCKED event is logged.
    """
    email = dev_doctor_account.email

    # Attempt 1: Failed
    r1 = client.post("/api/healthcare/doctor/login", json={"email": email, "password": "WrongPassword1!"})
    assert r1.status_code == 401
    db_session.refresh(dev_doctor_account)
    assert dev_doctor_account.failed_login_attempts == 1
    assert dev_doctor_account.account_status == "ACTIVE"

    # Attempt 2: Failed
    r2 = client.post("/api/healthcare/doctor/login", json={"email": email, "password": "WrongPassword2!"})
    assert r2.status_code == 401
    db_session.refresh(dev_doctor_account)
    assert dev_doctor_account.failed_login_attempts == 2
    assert dev_doctor_account.account_status == "ACTIVE"

    # Attempt 3: Triggers lockout
    r3 = client.post("/api/healthcare/doctor/login", json={"email": email, "password": "WrongPassword3!"})
    assert r3.status_code == 403
    assert "locked" in r3.json()["detail"].lower()

    db_session.refresh(dev_doctor_account)
    assert dev_doctor_account.failed_login_attempts == 3
    assert dev_doctor_account.account_status == "LOCKED"

    # Verify audit trail contains ACCOUNT_LOCKED event
    lock_event = db_session.query(SecurityEvent).filter(
        SecurityEvent.user_id == dev_doctor_account.id,
        SecurityEvent.event_type == "ACCOUNT_LOCKED"
    ).first()
    assert lock_event is not None
    assert lock_event.decision == "BLOCK"


def test_2_signing_out_and_signing_back_in_does_not_bypass_lockout(client: TestClient, dev_doctor_account: User, db_session: Session):
    """
    Requirement 2: Signing out or attempting to sign in again does not bypass or clear account lockout.
    """
    dev_doctor_account.account_status = "LOCKED"
    dev_doctor_account.failed_login_attempts = 3
    db_session.commit()

    # Even with the CORRECT password, locked doctor cannot sign in
    r_corr = client.post("/api/healthcare/doctor/login", json={
        "email": dev_doctor_account.email,
        "password": "DoctorSecret2026!"
    })
    assert r_corr.status_code == 403
    assert "locked" in r_corr.json()["detail"].lower()

    # Platform login route also denies access
    r_plat = client.post("/api/auth/login", json={
        "email": dev_doctor_account.email,
        "password": "DoctorSecret2026!",
        "doctor_required": True
    })
    assert r_plat.status_code == 403
    assert "locked" in r_plat.json()["detail"].lower()

    # Status remains LOCKED
    db_session.refresh(dev_doctor_account)
    assert dev_doctor_account.account_status == "LOCKED"


def test_3_authorized_development_reset_clears_test_account_lockout(client: TestClient, admin_account: User, dev_doctor_account: User, db_session: Session):
    """
    Requirement 3: Authorized development reset clears the failed attempt counter and restores ACTIVE status.
    Verifies audit logging with ADMIN_LOCKOUT_RESET.
    """
    dev_doctor_account.account_status = "LOCKED"
    dev_doctor_account.failed_login_attempts = 3
    db_session.commit()

    admin_login = get_token_for_user(client, admin_account.email, "AdminPass2026!")
    assert admin_login.status_code == 200
    admin_token = admin_login.json()["access_token"]

    # Call dev reset endpoint
    reset_resp = client.post(
        "/api/admin/dev/reset-lockout",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"email": dev_doctor_account.email}
    )
    assert reset_resp.status_code == 200
    data = reset_resp.json()
    assert data["success"] is True
    assert data["account_status"] == "ACTIVE"
    assert data["failed_login_attempts"] == 0

    db_session.refresh(dev_doctor_account)
    assert dev_doctor_account.account_status == "ACTIVE"
    assert dev_doctor_account.failed_login_attempts == 0

    # Verify security audit event logged
    reset_event = db_session.query(SecurityEvent).filter(
        SecurityEvent.user_id == dev_doctor_account.id,
        SecurityEvent.event_type == "ADMIN_LOCKOUT_RESET"
    ).first()
    assert reset_event is not None
    assert reset_event.decision == "ALLOW"


def test_4_unauthorized_reset_attempts_are_rejected(client: TestClient, dev_doctor_account: User, patient_user_account: User, db_session: Session):
    """
    Requirement 4: Unauthorized reset attempts are strictly rejected:
    - Unauthenticated request returns 401.
    - Non-admin user returns 403.
    """
    dev_doctor_account.account_status = "LOCKED"
    dev_doctor_account.failed_login_attempts = 3
    db_session.commit()

    # 4a: Unauthenticated
    r_unauth = client.post("/api/admin/dev/reset-lockout", json={"email": dev_doctor_account.email})
    assert r_unauth.status_code in (401, 403)

    # 4b: Non-admin patient account
    patient_login = get_token_for_user(client, patient_user_account.email, "PatientPass2026!")
    assert patient_login.status_code == 200
    patient_token = patient_login.json()["access_token"]

    r_non_admin = client.post(
        "/api/admin/dev/reset-lockout",
        headers={"Authorization": f"Bearer {patient_token}"},
        json={"email": dev_doctor_account.email}
    )
    assert r_non_admin.status_code == 403
    assert "administrator" in r_non_admin.json()["detail"].lower() or "restricted" in r_non_admin.json()["detail"].lower()

    # Lockout remains in place
    db_session.refresh(dev_doctor_account)
    assert dev_doctor_account.account_status == "LOCKED"


def test_5_correct_doctor_credentials_work_after_authorized_reset(client: TestClient, admin_account: User, dev_doctor_account: User, db_session: Session):
    """
    Requirement 5: Correct doctor credentials succeed immediately after an authorized administrative reset.
    """
    dev_doctor_account.account_status = "LOCKED"
    dev_doctor_account.failed_login_attempts = 3
    db_session.commit()

    admin_login = get_token_for_user(client, admin_account.email, "AdminPass2026!")
    admin_token = admin_login.json()["access_token"]

    client.post(
        "/api/healthcare/dev/reset-lockout",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"email": dev_doctor_account.email}
    )

    # Doctor logs in with correct password
    doc_login = client.post("/api/healthcare/doctor/login", json={
        "email": dev_doctor_account.email,
        "password": "DoctorSecret2026!"
    })
    assert doc_login.status_code == 200
    data = doc_login.json()
    assert "access_token" in data
    assert data["role"] == "DOCTOR"
    assert data["session_status"] == "ACTIVE"


def test_6_normal_user_accounts_cannot_access_clinical_vault(client: TestClient, patient_user_account: User):
    """
    Requirement 6: Normal USER accounts cannot access the Clinical EHR Vault (403 Forbidden).
    """
    patient_login = get_token_for_user(client, patient_user_account.email, "PatientPass2026!")
    token = patient_login.json()["access_token"]
    sess_id = patient_login.json()["session_id"]

    vault_res = client.get(
        f"/api/security/vault/ehr_vault?session_id={sess_id}",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert vault_res.status_code == 403
    detail_lower = vault_res.json()["detail"].lower()
    assert any(term in detail_lower for term in ("zero trust", "verification", "denied", "doctor", "valid active session", "forbidden"))


def test_7_doctor_access_still_requires_zero_trust_grant(client: TestClient, dev_doctor_account: User, db_session: Session):
    """
    Requirement 7: Doctor access still requires an active Zero Trust application grant.
    - Without grant: 403 Forbidden.
    - With valid grant: 200 OK and confidential EHR record returned.
    """
    doc_login = client.post("/api/healthcare/doctor/login", json={
        "email": dev_doctor_account.email,
        "password": "DoctorSecret2026!"
    })
    token = doc_login.json()["access_token"]
    sess_id = doc_login.json()["session_id"]

    # 1. Without grant: strictly denied
    no_grant_res = client.get(
        f"/api/security/vault/ehr_vault?session_id={sess_id}",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert no_grant_res.status_code == 403
    assert "zero trust" in no_grant_res.json()["detail"].lower() or "verification" in no_grant_res.json()["detail"].lower()

    # 2. Provision Zero Trust grant
    now = datetime.now(timezone.utc)
    grant = ApplicationGrant(
        session_id=sess_id,
        user_id=dev_doctor_account.id,
        application="healthcare",
        resource="ehr_vault",
        factor="GESTURE_PATTERN",
        granted_at=now,
        expires_at=now + timedelta(minutes=15),
        revoked=False
    )
    db_session.add(grant)
    db_session.commit()

    # 3. With grant: access is authorized
    grant_res = client.get(
        f"/api/security/vault/ehr_vault?session_id={sess_id}",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert grant_res.status_code == 200
    res_data = grant_res.json()
    assert res_data["access_granted"] is True
    assert "clinical_diagnosis" in res_data["data"]


def test_8_logout_locks_vault_and_invalidates_session(client: TestClient, dev_doctor_account: User, db_session: Session):
    """
    Requirement 8: Logout invalidates the authenticated session, revokes the grant, and locks the vault.
    """
    doc_login = client.post("/api/healthcare/doctor/login", json={
        "email": dev_doctor_account.email,
        "password": "DoctorSecret2026!"
    })
    token = doc_login.json()["access_token"]
    sess_id = doc_login.json()["session_id"]

    # Create grant
    now = datetime.now(timezone.utc)
    grant = ApplicationGrant(
        session_id=sess_id,
        user_id=dev_doctor_account.id,
        application="healthcare",
        resource="ehr_vault",
        factor="GESTURE_PATTERN",
        granted_at=now,
        expires_at=now + timedelta(minutes=15),
        revoked=False
    )
    db_session.add(grant)
    db_session.commit()

    # Verify vault is accessible
    v1 = client.get(f"/api/security/vault/ehr_vault?session_id={sess_id}", headers={"Authorization": f"Bearer {token}"})
    assert v1.status_code == 200

    # User signs out
    logout_res = client.post(f"/api/auth/logout?session_id={sess_id}", headers={"Authorization": f"Bearer {token}"})
    assert logout_res.status_code == 200

    # Subsequent vault access with this session is denied
    v2 = client.get(f"/api/security/vault/ehr_vault?session_id={sess_id}", headers={"Authorization": f"Bearer {token}"})
    assert v2.status_code in (401, 403)


def test_9_production_configuration_does_not_expose_development_reset(client: TestClient, admin_account: User, dev_doctor_account: User, monkeypatch):
    """
    Requirement 9: In production configuration (ENVIRONMENT="production"), development reset endpoints return 403.
    """
    admin_login = get_token_for_user(client, admin_account.email, "AdminPass2026!")
    admin_token = admin_login.json()["access_token"]

    monkeypatch.setattr(settings, "ENVIRONMENT", "production")

    prod_res = client.post(
        "/api/admin/dev/reset-lockout",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"email": dev_doctor_account.email}
    )
    assert prod_res.status_code == 403
    assert "production" in prod_res.json()["detail"].lower()
