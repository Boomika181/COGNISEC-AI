import pytest
import datetime
from pathlib import Path
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.session import Session as DbSession
from app.models.application_grant import ApplicationGrant
from app.core.security import get_password_hash, create_access_token


def _setup_user_and_session(
    db_session: Session,
    email: str,
    application: str = "college",
    risk_level: str = "LOW",
    status: str = "ACTIVE",
    session_id: str = None
):
    """Helper to set up an authenticated test user and session."""
    user = db_session.query(User).filter(User.email == email).first()
    if not user:
        user = User(
            email=email,
            password_hash=get_password_hash("SecretPassword123!"),
            name=f"Test User {email}",
            role="USER",
            account_status="ACTIVE"
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

    if not session_id:
        session_id = f"sess_step5_{email.split('@')[0]}_{int(datetime.datetime.now().timestamp() * 1000)}"

    now = datetime.datetime.now(datetime.timezone.utc)
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


def _create_grant(
    db_session: Session,
    user: User,
    sess: DbSession,
    application: str,
    resource: str,
    factor: str = "GESTURE_PATTERN",
    revoked: bool = False,
    expired: bool = False
):
    """Helper to create an ApplicationGrant directly in the database."""
    now = datetime.datetime.now(datetime.timezone.utc)
    granted_at = now - datetime.timedelta(hours=2) if expired else now
    expires_at = now - datetime.timedelta(minutes=10) if expired else now + datetime.timedelta(minutes=30)

    grant = ApplicationGrant(
        session_id=sess.id,
        user_id=user.id,
        application=application,
        resource=resource,
        factor=factor,
        granted_at=granted_at,
        expires_at=expires_at,
        revoked=revoked
    )
    db_session.add(grant)
    db_session.commit()
    db_session.refresh(grant)
    return grant


# =========================================================================
# TEST SUITE: STEP 5 PROTECTED VAULT ACCESS
# =========================================================================

def test_unauthenticated_vault_access_returns_401(client: TestClient):
    """Verify that unauthenticated requests to all three vaults return 401 and zero protected data."""
    vaults = ["academic_vault", "financial_vault", "ehr_vault"]
    for v in vaults:
        resp = client.get(f"/api/security/vault/{v}")
        assert resp.status_code == 401
        data = resp.json()
        assert "detail" in data
        # Ensure no protected data payloads leak
        assert "cgpa" not in data
        assert "transcripts" not in data
        assert "saved_cards" not in data
        assert "patient_profile" not in data


def test_authenticated_without_grant_returns_403(client: TestClient, db_session: Session):
    """Verify that an authenticated active session without an ApplicationGrant receives 403."""
    user, sess, headers = _setup_user_and_session(db_session, "no_grant_user@cognisec.ai", application="college")

    resp = client.get(f"/api/security/vault/academic_vault?session_id={sess.id}", headers=headers)
    assert resp.status_code == 403
    data = resp.json()
    assert "detail" in data
    assert "Zero Trust policy requires" in data["detail"]
    assert "cgpa" not in data


def test_authorized_grant_access_all_three_portals(client: TestClient, db_session: Session):
    """Verify that valid matching ApplicationGrants grant access to each portal's respective vault."""
    # 1. College -> academic_vault
    u_c, s_c, h_c = _setup_user_and_session(db_session, "college_grant_user@cognisec.ai", application="college")
    _create_grant(db_session, u_c, s_c, application="college", resource="academic_vault")

    r_c = client.get(f"/api/security/vault/academic_vault?session_id={s_c.id}", headers=h_c)
    assert r_c.status_code == 200
    d_c = r_c.json()
    assert d_c["resource"] == "academic_vault"
    assert d_c["access_granted"] is True
    assert "data" in d_c or "cgpa" in d_c

    # 2. Shopping -> financial_vault
    u_s, s_s, h_s = _setup_user_and_session(db_session, "shopping_grant_user@cognisec.ai", application="shopping")
    _create_grant(db_session, u_s, s_s, application="shopping", resource="financial_vault")

    r_s = client.get(f"/api/security/vault/financial_vault?session_id={s_s.id}", headers=h_s)
    assert r_s.status_code == 200
    d_s = r_s.json()
    assert d_s["resource"] == "financial_vault"
    assert d_s["access_granted"] is True
    assert "saved_cards" in d_s or ("data" in d_s and "saved_cards" in d_s["data"])

    # 3. Healthcare -> ehr_vault
    u_h, s_h, h_h = _setup_user_and_session(db_session, "ehr_grant_user@cognisec.ai", application="healthcare")
    _create_grant(db_session, u_h, s_h, application="healthcare", resource="ehr_vault")

    r_h = client.get(f"/api/security/vault/ehr_vault?session_id={s_h.id}", headers=h_h)
    assert r_h.status_code == 200
    d_h = r_h.json()
    assert d_h["resource"] == "ehr_vault"
    assert d_h["access_granted"] is True
    assert "patient_profile" in d_h or ("data" in d_h and "patient_profile" in d_h["data"])


def test_cross_portal_isolation_enforcement(client: TestClient, db_session: Session):
    """
    Verify strict security boundaries:
    - College grant must not authorize Shopping or Healthcare.
    - Shopping grant must not authorize College or Healthcare.
    - Healthcare grant must not authorize College or Shopping.
    """
    # User has ONLY College grant
    u_c, s_c, h_c = _setup_user_and_session(db_session, "cross_c_user@cognisec.ai", application="college")
    _create_grant(db_session, u_c, s_c, application="college", resource="academic_vault")

    assert client.get(f"/api/security/vault/financial_vault?session_id={s_c.id}", headers=h_c).status_code == 403
    assert client.get(f"/api/security/vault/ehr_vault?session_id={s_c.id}", headers=h_c).status_code == 403

    # User has ONLY Shopping grant
    u_s, s_s, h_s = _setup_user_and_session(db_session, "cross_s_user@cognisec.ai", application="shopping")
    _create_grant(db_session, u_s, s_s, application="shopping", resource="financial_vault")

    assert client.get(f"/api/security/vault/academic_vault?session_id={s_s.id}", headers=h_s).status_code == 403
    assert client.get(f"/api/security/vault/ehr_vault?session_id={s_s.id}", headers=h_s).status_code == 403

    # User has ONLY Healthcare grant
    u_h, s_h, h_h = _setup_user_and_session(db_session, "cross_h_user@cognisec.ai", application="healthcare")
    _create_grant(db_session, u_h, s_h, application="healthcare", resource="ehr_vault")

    assert client.get(f"/api/security/vault/academic_vault?session_id={s_h.id}", headers=h_h).status_code == 403
    assert client.get(f"/api/security/vault/financial_vault?session_id={s_h.id}", headers=h_h).status_code == 403


def test_revoked_grant_returns_403(client: TestClient, db_session: Session):
    """Verify that a revoked ApplicationGrant fails closed and returns 403."""
    user, sess, headers = _setup_user_and_session(db_session, "revoked_grant_user@cognisec.ai", application="college")
    _create_grant(db_session, user, sess, application="college", resource="academic_vault", revoked=True)

    resp = client.get(f"/api/security/vault/academic_vault?session_id={sess.id}", headers=headers)
    assert resp.status_code == 403


def test_expired_grant_returns_403(client: TestClient, db_session: Session):
    """Verify that an expired ApplicationGrant fails closed and returns 403."""
    user, sess, headers = _setup_user_and_session(db_session, "expired_grant_user@cognisec.ai", application="shopping")
    _create_grant(db_session, user, sess, application="shopping", resource="financial_vault", expired=True)

    resp = client.get(f"/api/security/vault/financial_vault?session_id={sess.id}", headers=headers)
    assert resp.status_code == 403


def test_terminated_or_restricted_session_returns_403(client: TestClient, db_session: Session):
    """Verify that an inactive, restricted, or terminated session cannot access the vault even with a grant."""
    for st in ("RESTRICTED", "TERMINATED", "REVOKED"):
        user, sess, headers = _setup_user_and_session(
            db_session,
            f"status_{st.lower()}@cognisec.ai",
            application="college",
            status=st
        )
        _create_grant(db_session, user, sess, application="college", resource="academic_vault")

        resp = client.get(f"/api/security/vault/academic_vault?session_id={sess.id}", headers=headers)
        assert resp.status_code in (401, 403)
        assert "cgpa" not in resp.json()


def test_critical_risk_session_unconditionally_blocked(client: TestClient, db_session: Session):
    """Verify that a CRITICAL risk level immediately terminates/blocks confidential vault access."""
    user, sess, headers = _setup_user_and_session(
        db_session,
        "critical_risk_user@cognisec.ai",
        application="college",
        risk_level="CRITICAL",
        status="ACTIVE"
    )
    _create_grant(db_session, user, sess, application="college", resource="academic_vault")

    resp = client.get(f"/api/security/vault/academic_vault?session_id={sess.id}", headers=headers)
    assert resp.status_code == 403
    assert "CRITICAL" in resp.json()["detail"]


def test_vault_endpoint_never_creates_grant_on_request(client: TestClient, db_session: Session):
    """Verify that repeatedly hitting the vault endpoint never automatically creates an ApplicationGrant."""
    user, sess, headers = _setup_user_and_session(db_session, "no_auto_grant@cognisec.ai", application="college")

    for _ in range(3):
        resp = client.get(f"/api/security/vault/academic_vault?session_id={sess.id}", headers=headers)
        assert resp.status_code == 403

    grants = db_session.query(ApplicationGrant).filter(
        ApplicationGrant.user_id == user.id,
        ApplicationGrant.application == "college"
    ).all()
    assert len(grants) == 0


def test_frontend_sources_do_not_contain_confidential_records():
    """
    Ensure no raw confidential records or sensitive demo secrets are embedded in
    college.html, shopping.html, or healthcare.html.
    """
    workspace_root = Path(__file__).resolve().parent.parent.parent

    # 1. College
    college_html = (workspace_root / "college.html").read_text(encoding="utf-8")
    assert "9.42 / 10.00" not in college_html, "Confidential student CGPA embedded in college.html!"
    assert "BITS-DIGI-84920" not in college_html, "Confidential transcript document ID embedded in college.html!"

    # 2. Shopping
    shopping_html = (workspace_root / "shopping.html").read_text(encoding="utf-8")
    assert "4821" not in shopping_html, "Confidential credit card number embedded in shopping.html!"
    assert "50100489120491" not in shopping_html, "Confidential bank account number embedded in shopping.html!"
    assert "MAND-2026-NYRAA" not in shopping_html, "Confidential bank mandate ID embedded in shopping.html!"

    # 3. Healthcare
    healthcare_html = (workspace_root / "healthcare.html").read_text(encoding="utf-8")
    assert "Rajesh Kumar" not in healthcare_html, "Confidential patient name embedded in healthcare.html!"
    assert "91-0982-1249-92" not in healthcare_html, "Confidential ABHA ID embedded in healthcare.html!"
    assert "Post-Op Coronary Angioplasty (CAD - LAD Stent)" not in healthcare_html, "Confidential diagnosis embedded in healthcare.html!"
    assert "ABDM-PATH-94812" not in healthcare_html, "Confidential pathology record ID embedded in healthcare.html!"
