import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.main import app
from app.database.connection import get_db, SessionLocal
from app.models.user import User
from app.models.device import Device
from app.models.session import Session as DbSession
from app.models.security_event import SecurityEvent
from app.models.alert import Alert
from app.core.security import get_password_hash, create_access_token


@pytest.fixture
def db(db_session):
    return db_session


@pytest.fixture
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as tc:
        yield tc
    app.dependency_overrides.clear()


@pytest.fixture
def admin_account(db: Session):
    admin_email = "cognisecai.security@gmail.com"
    user = db.query(User).filter(User.email == admin_email).first()
    if not user:
        user = User(
            name="CogniSec SOC Administrator",
            email=admin_email,
            password_hash=get_password_hash("cognisecai2026"),
            role="ADMIN",
            account_status="ACTIVE",
            created_at=datetime.now(timezone.utc)
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    elif user.role != "ADMIN" or not user.password_hash:
        user.role = "ADMIN"
        user.password_hash = get_password_hash("cognisecai2026")
        user.account_status = "ACTIVE"
        db.commit()
        db.refresh(user)
    return user


@pytest.fixture
def normal_user(db: Session):
    email = "test_normal_soc_eval@cognisec.ai"
    user = db.query(User).filter(User.email == email).first()
    if not user:
        user = User(
            name="Normal User",
            email=email,
            password_hash=get_password_hash("UserPass@123"),
            role="USER",
            account_status="ACTIVE",
            created_at=datetime.now(timezone.utc)
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    return user


def test_1_admin_authentication_success(client: TestClient, admin_account):
    """Test 1: Correct admin credentials authenticate successfully and issue ACTIVE admin session."""
    resp = client.post("/api/auth/login", json={
        "email": "cognisecai.security@gmail.com",
        "password": "cognisecai2026",
        "application": "platform",
        "device_fingerprint": "admin_test_console_fp_01"
    })
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    data = resp.json()
    assert data["role"] == "ADMIN"
    assert data["email"] == "cognisecai.security@gmail.com"
    assert data["session_status"] == "ACTIVE"
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_2_admin_authentication_invalid_password(client: TestClient):
    """Test 2: Incorrect admin password is rejected with HTTP 401 Unauthorized."""
    resp = client.post("/api/auth/login", json={
        "email": "cognisecai.security@gmail.com",
        "password": "WrongPassword2026!",
        "application": "platform"
    })
    assert resp.status_code == 401
    assert "Invalid email address or password" in resp.json()["detail"]


def test_3_normal_user_forbidden_from_admin_soc(client: TestClient, normal_user):
    """Test 3: Normal user account receives HTTP 403 Forbidden on all privileged SOC endpoints."""
    # Login as normal user
    login_resp = client.post("/api/auth/login", json={
        "email": normal_user.email,
        "password": "UserPass@123",
        "application": "platform"
    })
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Verify access to all SOC admin endpoints is denied
    endpoints = [
        ("GET", "/api/admin/metrics"),
        ("GET", "/api/admin/sessions"),
        ("GET", "/api/admin/devices"),
        ("GET", "/api/admin/users"),
        ("GET", "/api/admin/events"),
        ("GET", "/api/admin/alerts"),
        ("GET", "/api/admin/risk-distribution"),
    ]

    for method, path in endpoints:
        res = client.request(method, path, headers=headers)
        assert res.status_code == 403, f"Expected 403 on {path}, got {res.status_code}"
        assert "Security Administrator privileges required" in res.json()["detail"]


def test_4_unauthenticated_requests_rejected(client: TestClient):
    """Test 4: Unauthenticated requests without token receive HTTP 401 Unauthorized."""
    endpoints = [
        "/api/admin/metrics",
        "/api/admin/sessions",
        "/api/admin/devices",
        "/api/admin/users",
        "/api/admin/events",
        "/api/admin/alerts",
        "/api/admin/risk-distribution",
    ]
    for path in endpoints:
        res = client.get(path)
        assert res.status_code == 401, f"Expected 401 on {path}, got {res.status_code}"


def test_5_forged_admin_claims_rejected(client: TestClient, normal_user):
    """Test 5: Forged JWT claims (user claims role=ADMIN in token, but DB role is USER) are rejected."""
    # Issue a token with role='ADMIN' but sub is normal_user.id
    forged_token = create_access_token(
        subject=normal_user.id,
        role="ADMIN",
        session_id="sess_forged_dummy"
    )
    headers = {"Authorization": f"Bearer {forged_token}"}

    res = client.get("/api/admin/metrics", headers=headers)
    # The server looks up current_user in DB, sees current_user.role == 'USER', and rejects with 403
    assert res.status_code in (401, 403), f"Forged admin token allowed! Status: {res.status_code}"


def test_6_admin_metrics_match_database(client: TestClient, admin_account, db: Session):
    """Test 6: SOC metrics endpoint accurately reflects real database state."""
    login_resp = client.post("/api/auth/login", json={
        "email": admin_account.email,
        "password": "cognisecai2026",
        "application": "platform"
    })
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.get("/api/admin/metrics", headers=headers)
    assert resp.status_code == 200
    data = resp.json()

    # Compare with database queries
    expected_live_sessions = db.query(DbSession).filter(DbSession.status == "ACTIVE").count()
    expected_total_users = db.query(User).count()
    expected_devices = db.query(Device).count()
    expected_alerts = db.query(Alert).filter(Alert.status == "OPEN").count()

    assert data["live_sessions_count"] == expected_live_sessions
    assert data["total_users_count"] == expected_total_users
    assert data["total_devices_count"] == expected_devices
    assert data["open_alerts_count"] == expected_alerts
    assert data["active_alerts_count"] <= expected_alerts


def test_7_admin_sessions_and_termination_audit(client: TestClient, admin_account, normal_user, db: Session):
    """Test 7: Admin can list sessions and terminate a session with audit log created."""
    # Create an active session for normal user
    from app.services.session_service import SessionService
    user_sess = SessionService.create_session(
        db,
        user_id=normal_user.id,
        application="ecommerce",
        status="ACTIVE"
    )

    # Login as admin
    login_resp = client.post("/api/auth/login", json={
        "email": admin_account.email,
        "password": "cognisecai2026",
        "application": "platform"
    })
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # List sessions
    list_resp = client.get("/api/admin/sessions?limit=50", headers=headers)
    assert list_resp.status_code == 200
    sessions_list = list_resp.json()
    assert any(s["id"] == user_sess.id for s in sessions_list)

    # Terminate user session as admin
    term_resp = client.post(f"/api/admin/sessions/{user_sess.id}/terminate", headers=headers)
    assert term_resp.status_code == 200
    term_data = term_resp.json()
    assert term_data["status"] == "TERMINATED"

    # Verify session is terminated in DB
    db.expire_all()
    refreshed = db.query(DbSession).filter(DbSession.id == user_sess.id).first()
    assert refreshed.status == "TERMINATED"

    # Verify administrative SecurityEvent audit log was written
    audit_ev = db.query(SecurityEvent).filter(
        SecurityEvent.session_id == user_sess.id,
        SecurityEvent.event_type == "ADMIN_SESSION_TERMINATED"
    ).first()
    assert audit_ev is not None
    assert audit_ev.decision == "TERMINATE_SESSION"
    assert admin_account.email in audit_ev.details


def test_8_admin_device_inventory_and_revocation_audit(client: TestClient, admin_account, normal_user, db: Session):
    """Test 8: Admin can inspect device inventory and revoke a device with audit log created."""
    # Register a device for normal user
    from app.services.device_service import DeviceService
    dev, _ = DeviceService.register_or_update_device(
        db,
        user_id=normal_user.id,
        device_fingerprint="fp_soc_admin_test_dev_01",
        browser="Firefox/128",
        os="Linux x86_64"
    )

    # Login as admin
    login_resp = client.post("/api/auth/login", json={
        "email": admin_account.email,
        "password": "cognisecai2026",
        "application": "platform"
    })
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # List devices
    dev_resp = client.get("/api/admin/devices", headers=headers)
    assert dev_resp.status_code == 200
    devs = dev_resp.json()
    target_dev = next((d for d in devs if d["id"] == dev.id), None)
    assert target_dev is not None
    assert target_dev["user_email"] == normal_user.email

    # Revoke device as admin
    dev_ident = dev.device_id or str(dev.id)
    revoke_resp = client.post(f"/api/admin/devices/{dev_ident}/revoke", headers=headers)
    assert revoke_resp.status_code == 200
    assert revoke_resp.json()["trust_state"] == "REVOKED"

    # Verify DB state
    db.expire_all()
    refreshed_dev = db.query(Device).filter(Device.id == dev.id).first()
    assert refreshed_dev.trust_state == "REVOKED"
    assert refreshed_dev.is_trusted is False


def test_9_admin_alert_resolution_audit(client: TestClient, admin_account, normal_user, db: Session):
    """Test 9: Admin can resolve alerts and audit history is recorded."""
    # Create an alert
    alert = Alert(
        user_id=normal_user.id,
        application="ecommerce",
        alert_type="SUSPICIOUS_VELOCITY",
        message="Simulated anomaly test alert",
        severity="HIGH",
        status="OPEN",
        created_at=datetime.now(timezone.utc)
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    # Login as admin
    login_resp = client.post("/api/auth/login", json={
        "email": admin_account.email,
        "password": "cognisecai2026",
        "application": "platform"
    })
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Resolve alert
    res_resp = client.post(
        f"/api/admin/alerts/{alert.id}/resolve",
        headers=headers,
        json={"status": "RESOLVED", "resolution_notes": "Verified legitimate user activity."}
    )
    assert res_resp.status_code == 200
    assert res_resp.json()["status"] == "RESOLVED"

    # Verify DB state
    db.expire_all()
    refreshed_alert = db.query(Alert).filter(Alert.id == alert.id).first()
    assert refreshed_alert.status == "RESOLVED"

    # Verify audit event in SecurityEvent
    audit_ev = db.query(SecurityEvent).filter(
        SecurityEvent.event_type == "ADMIN_ALERT_RESOLVED",
        SecurityEvent.user_id == normal_user.id
    ).first()
    assert audit_ev is not None
    assert "ADMIN_ALERT_RESOLVED" in audit_ev.event_type


def test_10_incident_investigation_dossier(client: TestClient, db: Session, admin_account, normal_user):
    """Verifies that GET /api/admin/incidents/{id} correlates user, session, device, and timeline."""
    login_resp = client.post("/api/auth/login", json={
        "email": admin_account.email,
        "password": "cognisecai2026"
    })
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Find an alert to investigate
    alert = db.query(Alert).filter(Alert.user_id == normal_user.id).first()
    if not alert:
        alert = Alert(
            user_id=normal_user.id,
            application="platform",
            alert_type="STEP_UP_CHALLENGE_TRIGGERED",
            message="Test investigation alert",
            severity="MEDIUM",
            status="OPEN"
        )
        db.add(alert)
        db.commit()

    resp = client.get(f"/api/admin/incidents/{alert.id}", headers=headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["incident_id"] == alert.id
    assert data["severity"] == alert.severity
    assert data["user"] is not None
    assert data["user"]["email"] == normal_user.email
    assert "risk_assessment" in data
    assert "behavioral_signals" in data
    assert "related_timeline" in data
    assert "admin_actions" in data


def test_11_alert_triage_lifecycle_and_notes(client: TestClient, db: Session, admin_account, normal_user):
    """Verifies complete alert triage lifecycle (OPEN -> ACKNOWLEDGED -> INVESTIGATING -> RESOLVED -> REOPENED) with notes."""
    login_resp = client.post("/api/auth/login", json={
        "email": admin_account.email,
        "password": "cognisecai2026"
    })
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    alert = Alert(
        user_id=normal_user.id,
        application="ecommerce",
        alert_type="POLICY_VIOLATION",
        message="Suspicious order placement pattern",
        severity="HIGH",
        status="OPEN"
    )
    db.add(alert)
    db.commit()

    # 1. Acknowledge with notes & assignment
    triage1 = client.post(
        f"/api/admin/alerts/{alert.id}/resolve",
        headers=headers,
        json={
            "status": "ACKNOWLEDGED",
            "assigned_to": "analyst@cognisec.ai",
            "notes": "Acknowledged. Beginning correlation."
        }
    )
    assert triage1.status_code == 200
    assert triage1.json()["status"] == "ACKNOWLEDGED"
    assert triage1.json()["assigned_to"] == "analyst@cognisec.ai"
    assert "Acknowledged" in triage1.json()["notes"]

    # 2. Transition to INVESTIGATING
    triage2 = client.post(
        f"/api/admin/alerts/{alert.id}/resolve",
        headers=headers,
        json={
            "status": "INVESTIGATING",
            "notes": "Analyzing IP subnet history."
        }
    )
    assert triage2.status_code == 200
    assert triage2.json()["status"] == "INVESTIGATING"

    # 3. Resolve with reason
    triage3 = client.post(
        f"/api/admin/alerts/{alert.id}/resolve",
        headers=headers,
        json={
            "status": "RESOLVED",
            "resolution_reason": "False positive: user confirmed device via email OTP."
        }
    )
    assert triage3.status_code == 200
    assert triage3.json()["status"] == "RESOLVED"
    assert triage3.json()["resolved_by"] == admin_account.email
    assert triage3.json()["resolved_at"] is not None

    # 4. Reopen alert
    triage4 = client.post(
        f"/api/admin/alerts/{alert.id}/resolve",
        headers=headers,
        json={
            "status": "REOPENED",
            "notes": "Reopening due to subsequent failed challenge."
        }
    )
    assert triage4.status_code == 200
    assert triage4.json()["status"] == "REOPENED"
    assert triage4.json()["resolved_at"] is None


def test_12_audit_logs_retrieval(client: TestClient, db: Session, admin_account):
    """Verifies that GET /api/admin/audit-logs returns genuine administrative audit records."""
    login_resp = client.post("/api/auth/login", json={
        "email": admin_account.email,
        "password": "cognisecai2026"
    })
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.get("/api/admin/audit-logs", headers=headers)
    assert resp.status_code == 200
    logs = resp.json()
    assert isinstance(logs, list)
    if logs:
        first = logs[0]
        assert "action" in first
        assert "operator_email" in first
        assert "timestamp" in first
        assert "outcome" in first


def test_13_historical_analytics_and_system_health(client: TestClient, db: Session, admin_account):
    """Verifies that analytics and system-health endpoints return measurable real metrics."""
    login_resp = client.post("/api/auth/login", json={
        "email": admin_account.email,
        "password": "cognisecai2026"
    })
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Analytics 24h
    ana_resp = client.get("/api/admin/analytics?time_window=24h", headers=headers)
    assert ana_resp.status_code == 200
    ana_data = ana_resp.json()
    assert ana_data["time_window"] == "24h"
    assert "total_auth_attempts" in ana_data
    assert "risk_decisions" in ana_data
    assert "activity_timeline" in ana_data

    # System Health
    health_resp = client.get("/api/admin/system-health", headers=headers)
    assert health_resp.status_code == 200
    h_data = health_resp.json()
    assert h_data["database_connected"] is True
    assert h_data["database_latency_ms"] >= 0.0
    assert "telemetry_pipeline_status" in h_data
    assert h_data["active_sessions_count"] >= 0


def test_14_ai_rescan_bounded_execution(client: TestClient, db: Session, admin_account):
    """Verifies that POST /api/admin/rescan runs a bounded analysis and records an audit log."""
    login_resp = client.post("/api/auth/login", json={
        "email": admin_account.email,
        "password": "cognisecai2026"
    })
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    rescan_resp = client.post("/api/admin/rescan", headers=headers)
    assert rescan_resp.status_code == 200
    data = rescan_resp.json()
    assert data["status"] == "COMPLETED"
    assert "evaluated_sessions" in data
    assert "findings" in data
    assert isinstance(data["findings"], list)

    # Verify audit event
    audit_ev = db.query(SecurityEvent).filter(
        SecurityEvent.event_type == "ADMIN_RESCAN"
    ).order_by(SecurityEvent.timestamp.desc()).first()
    assert audit_ev is not None


def test_15_failed_login_logs_deny_not_allow(client: TestClient, db: Session, normal_user):
    """Verifies data integrity: failed authentication attempts are logged with decision='DENY', NEVER 'ALLOW'."""
    # Attempt login with invalid password
    client.post("/api/auth/login", json={
        "email": normal_user.email,
        "password": "wrongpassword_integrity_test"
    })

    db.expire_all()
    failed_ev = db.query(SecurityEvent).filter(
        SecurityEvent.user_id == normal_user.id,
        SecurityEvent.event_type == "LOGIN_ATTEMPT_FAILED"
    ).order_by(SecurityEvent.timestamp.desc()).first()

    assert failed_ev is not None
    assert failed_ev.decision == "DENY"
    assert failed_ev.decision != "ALLOW"


def test_16_repeated_high_risk_restriction_deduplication(db: Session, normal_user):
    """Verifies that repeating high-risk telemetry within a 60s cooldown window does not flood duplicate restriction events."""
    import uuid
    from app.services.decision_service import DecisionService
    from app.models.session import Session as DbSession

    sess = DbSession(
        id=f"test_dedup_{uuid.uuid4().hex[:16]}",
        user_id=normal_user.id,
        application="platform",
        status="ACTIVE",
        current_risk_level="LOW"
    )
    db.add(sess)
    db.commit()

    # Trigger high-risk restriction once
    DecisionService.enforce_zero_trust_decision(
        db=db,
        user_id=normal_user.id,
        session_id=sess.id,
        application="platform",
        risk_score=0.88,
        anomaly_score=0.85,
        risk_level="HIGH",
        contributing_factors=["ANOMALOUS_TYPING", "UNRECOGNIZED_DEVICE"]
    )

    count_1 = db.query(SecurityEvent).filter(
        SecurityEvent.session_id == sess.id,
        SecurityEvent.event_type == "SESSION_RESTRICTED"
    ).count()
    assert count_1 == 1

    # Immediate second call (within cooldown)
    DecisionService.enforce_zero_trust_decision(
        db=db,
        user_id=normal_user.id,
        session_id=sess.id,
        application="platform",
        risk_score=0.89,
        anomaly_score=0.86,
        risk_level="HIGH",
        contributing_factors=["ANOMALOUS_TYPING"]
    )

    count_2 = db.query(SecurityEvent).filter(
        SecurityEvent.session_id == sess.id,
        SecurityEvent.event_type == "SESSION_RESTRICTED"
    ).count()
    # Must NOT have created a duplicate event
    assert count_2 == 1
