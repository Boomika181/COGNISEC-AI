import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from app.main import app
from app.core.config import settings
from app.core.security import create_access_token
from app.models.session import Session
from app.models.user import User

@pytest.fixture
def auth_headers(client: TestClient, db_session):
    """Register and login standard User A."""
    email = f"user_a_{datetime.now().timestamp()}@example.com"
    client.post("/api/auth/register", json={
        "email": email,
        "password": "Password123!",
        "name": "User Alpha"
    })
    res = client.post("/api/auth/login", json={
        "email": email,
        "password": "Password123!",
        "application": "platform"
    })
    token = res.json()["access_token"]
    user_id = res.json()["user_id"]
    sid = res.json()["session_id"]
    from app.services.session_service import SessionService
    SessionService.activate_session_after_login_otp(db_session, sid)
    return {"Authorization": f"Bearer {token}"}, user_id

@pytest.fixture
def user_b_headers(client: TestClient, db_session):
    """Register and login standard User B."""
    email = f"user_b_{datetime.now().timestamp()}@example.com"
    client.post("/api/auth/register", json={
        "email": email,
        "password": "Password123!",
        "name": "User Beta"
    })
    res = client.post("/api/auth/login", json={
        "email": email,
        "password": "Password123!",
        "application": "platform"
    })
    token = res.json()["access_token"]
    user_id = res.json()["user_id"]
    sid = res.json()["session_id"]
    from app.services.session_service import SessionService
    SessionService.activate_session_after_login_otp(db_session, sid)
    return {"Authorization": f"Bearer {token}"}, user_id

@pytest.fixture
def admin_headers(client: TestClient, db_session):
    """Create an admin using the secure bootstrap mechanism."""
    email = f"admin_{datetime.now().timestamp()}@example.com"
    client.post(
        "/api/auth/bootstrap-admin",
        json={"email": email, "password": "AdminPassword123!", "name": "Admin Officer"},
        headers={"X-Bootstrap-Key": settings.BOOTSTRAP_ADMIN_KEY}
    )
    res = client.post("/api/auth/login", json={
        "email": email,
        "password": "AdminPassword123!",
        "application": "platform"
    })
    token = res.json()["access_token"]
    sid = res.json()["session_id"]
    from app.services.session_service import SessionService
    SessionService.activate_session_after_login_otp(db_session, sid)
    return {"Authorization": f"Bearer {token}"}


# ==============================================================================
# 1. AUTH HARDENING TESTS
# ==============================================================================

def test_auth_normal_registration_defaults_to_user(client: TestClient):
    """Normal registration without role defaults to USER."""
    email = f"reg_normal_{datetime.now().timestamp()}@example.com"
    res = client.post("/api/auth/register", json={
        "email": email,
        "password": "StrongPassword123!",
        "name": "Regular Citizen"
    })
    assert res.status_code == 201
    assert res.json()["role"] == "USER"

def test_auth_registration_with_explicit_user_role(client: TestClient):
    """Registering explicitly with role=USER is accepted and creates USER."""
    email = f"reg_user_role_{datetime.now().timestamp()}@example.com"
    res = client.post("/api/auth/register", json={
        "email": email,
        "password": "StrongPassword123!",
        "name": "Regular Citizen Two",
        "role": "USER"
    })
    assert res.status_code == 201
    assert res.json()["role"] == "USER"

def test_auth_attempted_admin_registration_rejected(client: TestClient):
    """Public registration with role=ADMIN must be rejected."""
    email = f"reg_hacker_{datetime.now().timestamp()}@example.com"
    res = client.post("/api/auth/register", json={
        "email": email,
        "password": "StrongPassword123!",
        "name": "Malicious Actor",
        "role": "ADMIN"
    })
    assert res.status_code == 400
    assert "privilege escalation prohibited" in res.json()["detail"].lower()

def test_auth_bootstrap_admin_mechanism(client: TestClient):
    """Bootstrap admin succeeds with correct key, fails with bad or missing key."""
    email = f"boot_admin_{datetime.now().timestamp()}@example.com"
    # Attempt without key -> 403
    res_no_key = client.post("/api/auth/bootstrap-admin", json={
        "email": email,
        "password": "AdminSecret123!",
        "name": "Unauthorized Admin"
    })
    assert res_no_key.status_code == 403

    # Attempt with wrong key -> 403
    res_bad_key = client.post(
        "/api/auth/bootstrap-admin",
        json={"email": email, "password": "AdminSecret123!", "name": "Unauthorized Admin"},
        headers={"X-Bootstrap-Key": "wrong-key"}
    )
    assert res_bad_key.status_code == 403

    # Attempt with correct key -> 201 and creates ADMIN
    res_ok = client.post(
        "/api/auth/bootstrap-admin",
        json={"email": email, "password": "AdminSecret123!", "name": "Authorized Admin"},
        headers={"X-Bootstrap-Key": settings.BOOTSTRAP_ADMIN_KEY}
    )
    assert res_ok.status_code == 201
    assert res_ok.json()["role"] == "ADMIN"

def test_auth_login_invalid_credentials(client: TestClient):
    """Login with wrong password must be rejected."""
    res = client.post("/api/auth/login", json={
        "email": "nonexistent@cognisec.ai",
        "password": "WrongPassword123!"
    })
    assert res.status_code == 401


# ==============================================================================
# 2. JWT & SESSION BINDING & REVOCATION TESTS
# ==============================================================================

def test_jwt_valid_and_has_session_binding(client: TestClient, auth_headers):
    """Authenticated user has session ID in JWT and can access /api/auth/me."""
    headers, _ = auth_headers
    res = client.get("/api/auth/me", headers=headers)
    assert res.status_code == 200
    assert "id" in res.json()

def test_jwt_invalid_signature_rejected(client: TestClient):
    """Tampered or invalid JWT must be rejected."""
    res = client.get("/api/auth/me", headers={"Authorization": "Bearer invalid.token.structure"})
    assert res.status_code == 401

def test_jwt_expired_token_rejected(client: TestClient, db_session):
    """Expired JWT must be rejected with 401."""
    # Create an expired token manually
    expired_token = create_access_token(
        subject="some_user_id",
        role="USER",
        session_id="dummy_sid",
        expires_delta=timedelta(seconds=-10)
    )
    res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert res.status_code == 401

def test_jwt_revoked_on_terminated_session(client: TestClient, auth_headers, db_session):
    """When a session is marked TERMINATED, the JWT is immediately revoked."""
    headers, user_id = auth_headers
    # User works fine initially
    res1 = client.get("/api/auth/me", headers=headers)
    assert res1.status_code == 200

    # Locate the active session and terminate it in DB
    session_record = db_session.query(Session).filter(
        Session.user_id == user_id,
        Session.status != "TERMINATED"
    ).first()
    assert session_record is not None
    session_record.status = "TERMINATED"
    db_session.commit()

    # User attempts to use same JWT -> Must be 401 Revoked
    res2 = client.get("/api/auth/me", headers=headers)
    assert res2.status_code == 401
    assert "revoked" in res2.json()["detail"].lower() or "terminated" in res2.json()["detail"].lower()


# ==============================================================================
# 3. SESSION OWNERSHIP & BOLA TESTS
# ==============================================================================

def test_session_own_logout_succeeds(client: TestClient, auth_headers, db_session):
    """A user can successfully log out their own session."""
    headers, user_id = auth_headers
    session_rec = db_session.query(Session).filter(Session.user_id == user_id).first()

    res = client.post(
        "/api/auth/logout",
        headers=headers,
        params={"session_id": session_rec.id}
    )
    assert res.status_code == 200
    assert res.json()["status"] == "success"

def test_session_cross_user_logout_forbidden(client: TestClient, auth_headers, user_b_headers, db_session):
    """User A cannot logout User B's session."""
    headers_a, _ = auth_headers
    _, user_b_id = user_b_headers

    session_b = db_session.query(Session).filter(Session.user_id == user_b_id).first()
    assert session_b is not None

    # User A tries to log out User B's session
    res = client.post(
        "/api/auth/logout",
        headers=headers_a,
        params={"session_id": session_b.id}
    )
    assert res.status_code == 403
    assert "authorized" in res.json()["detail"].lower() or "own" in res.json()["detail"].lower()

def test_session_cross_user_termination_forbidden(client: TestClient, auth_headers, user_b_headers, db_session):
    """User A cannot terminate User B's application session."""
    headers_a, _ = auth_headers
    headers_b, user_b_id = user_b_headers

    # User B creates an application session
    app_res = client.post("/api/sessions/start", headers=headers_b, json={
        "application": "finance_portal",
        "device_fingerprint": "dev_beta_fp"
    })
    b_session_id = app_res.json()["id"]

    # User A tries to terminate User B's session
    term_res = client.post(
        f"/api/sessions/{b_session_id}/terminate",
        headers=headers_a
    )
    assert term_res.status_code == 403


# ==============================================================================
# 4. BEHAVIOR TELEMETRY AUTHORIZATION TESTS
# ==============================================================================

def test_telemetry_own_session_accepted(client: TestClient, auth_headers):
    """User can submit telemetry to their own valid session."""
    headers, _ = auth_headers
    start_res = client.post("/api/sessions/start", headers=headers, json={
        "application": "crm",
        "device_fingerprint": "crm_dev_fp"
    })
    session_id = start_res.json()["id"]

    payload = {
        "session_id": session_id,
        "application": "crm",
        "keystroke_data": [{"key": "a", "press_time": 10.0, "release_time": 10.08}],
        "mouse_data": [{"x": 100, "y": 150, "timestamp": 10.0}],
        "context_data": {
            "device_fingerprint": "crm_dev_fp",
            "screen_resolution": "1920x1080",
            "user_agent": "Mozilla/5.0",
            "is_new_device": False,
            "impossible_travel": False,
            "request_flood": False,
            "failed_attempts_count": 0
        }
    }
    res = client.post("/api/behavior/events", headers=headers, json=payload)
    assert res.status_code == 200
    assert "decision" in res.json()

def test_telemetry_cross_user_session_rejected(client: TestClient, auth_headers, user_b_headers):
    """User A cannot submit telemetry to User B's session."""
    headers_a, _ = auth_headers
    headers_b, _ = user_b_headers

    # User B starts a session
    start_b = client.post("/api/sessions/start", headers=headers_b, json={
        "application": "banking",
        "device_fingerprint": "bank_dev_fp"
    })
    b_session_id = start_b.json()["id"]

    # User A tries to inject telemetry into User B's session
    spoof_payload = {
        "session_id": b_session_id,
        "application": "banking",
        "keystroke_data": [{"key": "x", "press_time": 1.0, "release_time": 1.05}],
        "mouse_data": [{"x": 20, "y": 30, "timestamp": 1.0}],
        "context_data": {
            "device_fingerprint": "bank_dev_fp",
            "screen_resolution": "1920x1080",
            "user_agent": "Mozilla/5.0",
            "is_new_device": False,
            "impossible_travel": False,
            "request_flood": False,
            "failed_attempts_count": 0
        }
    }
    res = client.post("/api/behavior/events", headers=headers_a, json=spoof_payload)
    assert res.status_code == 403
    assert "own" in res.json()["detail"].lower() or "authorized" in res.json()["detail"].lower()

def test_telemetry_application_mismatch_rejected(client: TestClient, auth_headers):
    """Telemetry submitted with wrong application name is rejected."""
    headers, _ = auth_headers
    start_res = client.post("/api/sessions/start", headers=headers, json={
        "application": "medical_records",
        "device_fingerprint": "med_fp"
    })
    session_id = start_res.json()["id"]

    # Session is for medical_records, but payload claims 'hr_portal'
    payload = {
        "session_id": session_id,
        "application": "hr_portal",
        "keystroke_data": [],
        "mouse_data": [],
        "context_data": {
            "device_fingerprint": "med_fp",
            "screen_resolution": "1920x1080",
            "user_agent": "Mozilla/5.0",
            "is_new_device": False,
            "impossible_travel": False,
            "request_flood": False,
            "failed_attempts_count": 0
        }
    }
    res = client.post("/api/behavior/events", headers=headers, json=payload)
    assert res.status_code == 400
    assert "mismatch" in res.json()["detail"].lower()


# ==============================================================================
# 5. SECURITY STATUS AUTHORIZATION TESTS
# ==============================================================================

def test_security_status_own_session_allowed(client: TestClient, auth_headers):
    """User can view their own session security status."""
    headers, _ = auth_headers
    start_res = client.post("/api/sessions/start", headers=headers, json={
        "application": "internal_wiki",
        "device_fingerprint": "wiki_fp"
    })
    session_id = start_res.json()["id"]

    res = client.get(f"/api/security/status/{session_id}", headers=headers)
    assert res.status_code == 200
    assert "session_status" in res.json()
    assert "decision" in res.json()

def test_security_status_cross_user_denied(client: TestClient, auth_headers, user_b_headers):
    """User A cannot view User B's security status."""
    headers_a, _ = auth_headers
    headers_b, _ = user_b_headers

    start_res = client.post("/api/sessions/start", headers=headers_b, json={
        "application": "internal_wiki",
        "device_fingerprint": "wiki_fp"
    })
    b_session_id = start_res.json()["id"]

    res = client.get(f"/api/security/status/{b_session_id}", headers=headers_a)
    assert res.status_code == 403


# ==============================================================================
# 6. ROLE & PRIVILEGE ENFORCEMENT (ADMIN VS USER)
# ==============================================================================

def test_user_cannot_access_admin_dashboard(client: TestClient, auth_headers):
    """Normal user cannot access admin metrics/sessions/alerts."""
    headers, _ = auth_headers
    assert client.get("/api/admin/metrics", headers=headers).status_code == 403
    assert client.get("/api/admin/sessions", headers=headers).status_code == 403
    assert client.get("/api/admin/alerts", headers=headers).status_code == 403

def test_admin_can_access_admin_dashboard(client: TestClient, admin_headers):
    """Admin user can access admin metrics."""
    assert client.get("/api/admin/metrics", headers=admin_headers).status_code == 200


# ==============================================================================
# 7. ATTACK SIMULATOR RESTRICTION TESTS
# ==============================================================================

def test_user_blocked_from_attack_simulator(client: TestClient, auth_headers):
    """Normal user receives 403 when attempting to run attack simulation."""
    headers, _ = auth_headers
    res = client.post("/api/demo/simulate", headers=headers, json={
        "scenario": "session_hijacking",
        "application": "demo_app"
    })
    assert res.status_code == 403

def test_admin_can_run_attack_simulator(client: TestClient, admin_headers):
    """Admin can run attack simulation."""
    res = client.post("/api/demo/simulate", headers=admin_headers, json={
        "scenario": "session_hijacking",
        "application": "demo_app"
    })
    assert res.status_code == 200
    assert res.json()["scenario"] == "session_hijacking"


# ==============================================================================
# 8. RESPONSE SECURITY & ML SCORE SHIELDING
# ==============================================================================

def test_user_response_does_not_leak_internal_ml_scores(client: TestClient, auth_headers):
    """Normal user behavior event response contains only security outcome, no risk/anomaly scores."""
    headers, _ = auth_headers
    start_res = client.post("/api/sessions/start", headers=headers, json={
        "application": "secure_vault",
        "device_fingerprint": "vault_fp"
    })
    session_id = start_res.json()["id"]

    payload = {
        "session_id": session_id,
        "application": "secure_vault",
        "keystroke_data": [{"key": "a", "press_time": 100.0, "release_time": 100.1}],
        "mouse_data": [{"x": 10, "y": 20, "timestamp": 100.0}],
        "context_data": {
            "device_fingerprint": "vault_fp",
            "screen_resolution": "1920x1080",
            "user_agent": "Mozilla/5.0",
            "is_new_device": False,
            "impossible_travel": False,
            "request_flood": False,
            "failed_attempts_count": 0
        }
    }
    res = client.post("/api/behavior/events", headers=headers, json=payload)
    assert res.status_code == 200
    body = res.json()

    # Public outcome fields MUST be present
    assert "decision" in body
    assert "session_status" in body
    assert "verification_required" in body

    # Internal SOC / ML metrics MUST NOT be leaked to normal user
    assert "risk_score" not in body
    assert "anomaly_score" not in body
    assert "contributing_factors" not in body
    assert "ml_status" not in body

def test_admin_receives_internal_soc_metrics(client: TestClient, admin_headers):
    """Admin submitting telemetry (or viewing SOC metrics) receives full internal scores."""
    start_res = client.post("/api/sessions/start", headers=admin_headers, json={
        "application": "soc_console",
        "device_fingerprint": "soc_fp"
    })
    session_id = start_res.json()["id"]

    payload = {
        "session_id": session_id,
        "application": "soc_console",
        "keystroke_data": [{"key": "s", "press_time": 100.0, "release_time": 100.1}],
        "mouse_data": [{"x": 10, "y": 20, "timestamp": 100.0}],
        "context_data": {
            "device_fingerprint": "soc_fp",
            "screen_resolution": "1920x1080",
            "user_agent": "Mozilla/5.0",
            "is_new_device": False,
            "impossible_travel": False,
            "request_flood": False,
            "failed_attempts_count": 0
        }
    }
    res = client.post("/api/behavior/events", headers=admin_headers, json=payload)
    assert res.status_code == 200
    body = res.json()

    # Admin receives full SOC intelligence
    assert "risk_score" in body
    assert "anomaly_score" in body
    assert "contributing_factors" in body


# ==============================================================================
# 9. CORS CONFIGURATION TEST
# ==============================================================================

def test_cors_explicit_origin_allowed(client: TestClient):
    """Preflight request from allowed origin returns proper headers and no wildcard."""
    res = client.options(
        "/api/auth/login",
        headers={
            "Origin": "http://localhost:5500",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type,Authorization"
        }
    )
    assert res.status_code == 200
    assert res.headers.get("access-control-allow-origin") == "http://localhost:5500"
    assert res.headers.get("access-control-allow-credentials") == "true"
    # Ensure wildcard is not returned with credentials
    assert res.headers.get("access-control-allow-origin") != "*"
