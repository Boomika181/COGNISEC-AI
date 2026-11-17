import uuid
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from app.main import app
from app.database.connection import SessionLocal
from app.models.user import User
from app.models.session import Session as DbSession
from app.models.security_event import SecurityEvent
from app.models.alert import Alert
from app.core.security import get_password_hash, create_access_token

client = TestClient(app)


def _create_user_and_token(role: str = "USER", account_status: str = "ACTIVE", with_session: bool = False):
    db = SessionLocal()
    try:
        uid_suffix = uuid.uuid4().hex[:8]
        email = f"soc_verify_{role.lower()}_{uid_suffix}@example.com"
        user = User(
            name=f"SOC Verify {uid_suffix}",
            email=email,
            password_hash=get_password_hash("StrongPass!123"),
            role=role,
            account_status=account_status,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        sid = None
        if with_session:
            sid = f"sess_soc_{uid_suffix}"
            sess = DbSession(
                id=sid,
                user_id=user.id,
                application="platform",
                ip_address="127.0.0.1",
                status="ACTIVE",
                current_risk_level="LOW",
            )
            db.add(sess)
            db.commit()

        token = create_access_token(subject=str(user.id), role=user.role, session_id=sid)
        return user.id, email, token, sid
    finally:
        db.close()


def test_normal_user_cannot_access_new_admin_endpoints():
    user_id, _, user_token, _ = _create_user_and_token(role="USER", with_session=True)
    headers = {"Authorization": f"Bearer {user_token}"}

    for path in [
        "/api/admin/users/directory",
        f"/api/admin/users/{user_id}/details",
        "/api/admin/audit-trail",
        "/api/admin/metrics",
    ]:
        res = client.get(path, headers=headers)
        assert res.status_code == 403, f"Expected 403 for normal user on {path}, got {res.status_code}"


def test_registered_users_directory_includes_users_without_sessions_and_future_registrations():
    _, _, admin_token, _ = _create_user_and_token(role="ADMIN", with_session=True)
    headers = {"Authorization": f"Bearer {admin_token}"}

    # User with zero sessions (never logged in)
    no_sess_id, no_sess_email, _, _ = _create_user_and_token(role="USER", with_session=False)
    # Suspended user
    susp_id, susp_email, _, _ = _create_user_and_token(role="USER", account_status="SUSPENDED", with_session=False)

    # Future registration via real /api/auth/register endpoint
    new_email = f"future_reg_{uuid.uuid4().hex[:8]}@example.com"
    reg_res = client.post(
        "/api/auth/register",
        json={
            "name": "Future Registered User",
            "email": new_email,
            "password": "StrongPassword!2026",
            "role": "USER",
        },
    )
    assert reg_res.status_code in (200, 201), reg_res.text

    # Verify metrics count matches DB User count
    db = SessionLocal()
    try:
        db_user_count = db.query(User).count()
        db_susp_count = db.query(User).filter(User.account_status != "ACTIVE").count()
    finally:
        db.close()

    metrics_res = client.get("/api/admin/metrics", headers=headers)
    assert metrics_res.status_code == 200
    metrics = metrics_res.json()
    assert metrics["total_users_count"] == db_user_count
    assert metrics["suspended_accounts_count"] == db_susp_count

    # Search for each user in directory
    for target_email, expected_status in [
        (no_sess_email, "ACTIVE"),
        (susp_email, "SUSPENDED"),
        (new_email, "ACTIVE"),
    ]:
        dir_res = client.get(
            f"/api/admin/users/directory?scope=all&search={target_email}&page=1&page_size=10",
            headers=headers,
        )
        assert dir_res.status_code == 200
        payload = dir_res.json()
        assert payload["total"] == 1
        row = payload["items"][0]
        assert row["email"] == target_email
        assert row["account_status"] == expected_status
        assert row["total_sessions_count"] == 0
        assert row["last_login"] is None

    # Verify pagination & role filter under scope=all
    pag_res = client.get("/api/admin/users/directory?scope=all&role=ADMIN&page=1&page_size=5", headers=headers)
    assert pag_res.status_code == 200
    pag_data = pag_res.json()
    assert pag_data["page"] == 1
    assert pag_data["page_size"] == 5
    assert all(u["role"] == "ADMIN" for u in pag_data["items"])


def test_user_detail_dossier_excludes_secrets():
    user_id, email, _, _ = _create_user_and_token(role="USER", with_session=False)
    _, _, admin_token, _ = _create_user_and_token(role="ADMIN", with_session=True)
    headers = {"Authorization": f"Bearer {admin_token}"}

    res = client.get(f"/api/admin/users/{user_id}/details", headers=headers)
    assert res.status_code == 200
    body = res.json()
    assert body["user"]["email"] == email
    assert "password_hash" not in body["user"]
    assert "password" not in body["user"]
    assert isinstance(body["devices"], list)
    assert isinstance(body["sessions"], list)
    assert isinstance(body["recent_events"], list)


def test_audit_trail_distinguishes_system_from_admin_and_supports_filters():
    user_id, user_email, _, _ = _create_user_and_token(role="USER", with_session=False)
    _, admin_email, admin_token, _ = _create_user_and_token(role="ADMIN", with_session=True)
    headers = {"Authorization": f"Bearer {admin_token}"}

    marker = uuid.uuid4().hex[:8]
    db = SessionLocal()
    try:
        sys_ev = SecurityEvent(
            user_id=user_id,
            application="shopping",
            event_type="PORTAL_SECURITY_LOCKED",
            severity="HIGH",
            anomaly_score=0.0,
            risk_score=0.9,
            decision="LOCK_PORTAL",
            details=f"System locked shopping portal [{marker}]",
        )
        adm_ev = SecurityEvent(
            user_id=user_id,
            application="shopping",
            event_type="PORTAL_RECOVERY_APPROVED",
            severity="LOW",
            anomaly_score=0.0,
            risk_score=0.0,
            decision="ALLOW",
            details=f"Portal recovery approved by administrator ({admin_email}) [{marker}]",
        )
        db.add(sys_ev)
        db.add(adm_ev)
        db.commit()
    finally:
        db.close()

    # System event must have actor_type == SYSTEM (never ADMIN)
    sys_res = client.get(
        f"/api/admin/audit-trail?activity_scope=all&search={marker}&actor_type=SYSTEM",
        headers=headers,
    )
    assert sys_res.status_code == 200
    sys_items = sys_res.json()["items"]
    assert len(sys_items) == 1
    assert sys_items[0]["actor_type"] == "SYSTEM"
    assert sys_items[0]["actor_label"] == "COGNISEC Security System"
    assert sys_items[0]["action_code"] == "PORTAL_SECURITY_LOCKED"

    # Admin event must have actor_type == ADMIN with admin_email
    adm_res = client.get(
        f"/api/admin/audit-trail?activity_scope=all&search={marker}&actor_type=ADMIN",
        headers=headers,
    )
    assert adm_res.status_code == 200
    adm_items = adm_res.json()["items"]
    assert len(adm_items) == 1
    assert adm_items[0]["actor_type"] == "ADMIN"
    assert adm_items[0]["actor_label"] == admin_email
    assert adm_items[0]["action_code"] == "PORTAL_RECOVERY_APPROVED"


def test_active_sessions_exclude_terminated_and_expired():
    user_id, _, _, active_sid = _create_user_and_token(role="USER", with_session=True)
    _, _, admin_token, _ = _create_user_and_token(role="ADMIN", with_session=True)
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Terminate the session via authorized backend admin endpoint
    term_res = client.post(f"/api/admin/sessions/{active_sid}/terminate", headers=headers)
    assert term_res.status_code == 200
    assert term_res.json()["status"] == "TERMINATED"

    # Active sessions list must NOT include the terminated session
    act_res = client.get(f"/api/admin/sessions?status=ACTIVE&search={active_sid}", headers=headers)
    assert act_res.status_code == 200
    assert all(s["id"] != active_sid for s in act_res.json())

    # Terminated history MUST still contain it
    hist_res = client.get(f"/api/admin/sessions?status=TERMINATED&search={active_sid}", headers=headers)
    assert hist_res.status_code == 200
    assert any(s["id"] == active_sid for s in hist_res.json())
