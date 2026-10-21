def test_register_new_user(client):
    res = client.post("/api/auth/register", json={
        "name": "Sarah Connor",
        "email": "sarah.connor@example.com",
        "password": "Password@123",
        "role": "USER"
    })
    assert res.status_code == 201
    data = res.json()
    assert data["email"] == "sarah.connor@example.com"
    assert data["role"] == "USER"
    assert "password" not in data
    assert "password_hash" not in data


def test_register_duplicate_email(client):
    res = client.post("/api/auth/register", json={
        "name": "Duplicate Sarah",
        "email": "sarah.connor@example.com",
        "password": "Password@123"
    })
    assert res.status_code == 400
    assert "already exists" in res.json()["detail"]


def test_login_valid_credentials(client):
    res = client.post("/api/auth/login", json={
        "email": "sarah.connor@example.com",
        "password": "Password@123",
        "application": "college",
        "device_fingerprint": "fp_sarah_mbp_01"
    })
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["email"] == "sarah.connor@example.com"
    assert data["session_id"] is not None


def test_login_invalid_password(client):
    res = client.post("/api/auth/login", json={
        "email": "sarah.connor@example.com",
        "password": "WrongPassword123"
    })
    assert res.status_code == 401
    assert "Invalid email address or password" in res.json()["detail"]


def test_get_current_user_me(client, user_token):
    res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {user_token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["email"] == "test.user@cognisec.ai"
    assert data["role"] == "USER"


def test_unauthenticated_access_denied(client):
    res = client.get("/api/auth/me")
    assert res.status_code == 401


def test_register_password_too_short_rejected(client):
    res = client.post("/api/auth/register", json={
        "name": "Short Pwd",
        "email": "short.pwd@example.com",
        "password": "Sh1!"
    })
    assert res.status_code == 422
    assert "at least 8 characters" in str(res.json()).lower()


def test_register_password_no_uppercase_rejected(client):
    res = client.post("/api/auth/register", json={
        "name": "No Upper",
        "email": "no.upper@example.com",
        "password": "password123!"
    })
    assert res.status_code == 422
    assert "uppercase" in str(res.json()).lower()


def test_register_password_no_lowercase_rejected(client):
    res = client.post("/api/auth/register", json={
        "name": "No Lower",
        "email": "no.lower@example.com",
        "password": "PASSWORD123!"
    })
    assert res.status_code == 422
    assert "lowercase" in str(res.json()).lower()


def test_register_password_no_digit_rejected(client):
    res = client.post("/api/auth/register", json={
        "name": "No Digit",
        "email": "no.digit@example.com",
        "password": "Password!@#"
    })
    assert res.status_code == 422
    assert "digit" in str(res.json()).lower()


def test_register_password_no_special_char_rejected(client):
    res = client.post("/api/auth/register", json={
        "name": "No Special",
        "email": "no.special@example.com",
        "password": "Password123"
    })
    assert res.status_code == 422
    assert "special character" in str(res.json()).lower()


def test_register_password_boundary_valid_accepted(client):
    res = client.post("/api/auth/register", json={
        "name": "Boundary Valid",
        "email": "boundary.valid@example.com",
        "password": "P@ssw0rd"  # Exactly 8 chars, 1 upper, 1 lower, 1 digit, 1 special
    })
    assert res.status_code == 201
    assert res.json()["email"] == "boundary.valid@example.com"


def test_register_missing_required_fields_rejected(client):
    # Missing name
    res1 = client.post("/api/auth/register", json={
        "email": "missing.name@example.com",
        "password": "Password123!"
    })
    assert res1.status_code == 422

    # Missing email
    res2 = client.post("/api/auth/register", json={
        "name": "Missing Email",
        "password": "Password123!"
    })
    assert res2.status_code == 422

    # Missing password
    res3 = client.post("/api/auth/register", json={
        "name": "Missing Password",
        "email": "missing.pwd@example.com"
    })
    assert res3.status_code == 422


def test_register_attempted_admin_role_rejected(client):
    res = client.post("/api/auth/register", json={
        "name": "Attacker Admin",
        "email": "attacker.admin@example.com",
        "password": "Password123!",
        "role": "ADMIN"
    })
    assert res.status_code == 400
    assert "privilege escalation" in res.json()["detail"].lower()


def test_register_arbitrary_role_forced_to_user(client):
    res = client.post("/api/auth/register", json={
        "name": "Custom Role User",
        "email": "custom.role@example.com",
        "password": "Password123!",
        "role": "auditor"
    })
    assert res.status_code == 201
    assert res.json()["role"] == "USER"


def test_login_unknown_email_fails(client):
    res = client.post("/api/auth/login", json={
        "email": "unknown.ghost.user@cognisec.ai",
        "password": "Password123!"
    })
    assert res.status_code == 401
    assert "invalid email address or password" in res.json()["detail"].lower()


def test_login_session_binding_and_status(client, db_session):
    # 1. Register a fresh user
    reg_res = client.post("/api/auth/register", json={
        "name": "Bound User",
        "email": "bound.user@cognisec.ai",
        "password": "Password123!"
    })
    assert reg_res.status_code == 201

    # 2. Login with device context
    login_res = client.post("/api/auth/login", json={
        "email": "bound.user@cognisec.ai",
        "password": "Password123!",
        "application": "platform",
        "device_fingerprint": "dev_fp_bound_01"
    })
    assert login_res.status_code == 200
    login_data = login_res.json()

    token = login_data["access_token"]
    session_id = login_data["session_id"]
    assert session_id is not None
    assert session_id.startswith("sess_")

    # 3. Verify token decodes with session_id claim
    from app.core.security import decode_access_token
    payload = decode_access_token(token)
    assert payload is not None
    assert payload.get("sid") == session_id
    assert payload.get("sub") == str(reg_res.json()["id"])
    assert payload.get("role") == "USER"

    # 4. Check authoritative security status endpoint
    stat_res = client.get(f"/api/security/status/{session_id}", headers={"Authorization": f"Bearer {token}"})
    assert stat_res.status_code == 200
    stat_data = stat_res.json()
    assert stat_data["session_status"] == "PENDING_OBSERVATION"
    assert stat_data["decision"] == "OBSERVATION_PENDING"

    # 5. Activate session and verify status updates to ACTIVE
    from app.services.session_service import SessionService
    SessionService.activate_session_after_login_otp(db_session, session_id)

    stat_res_active = client.get(f"/api/security/status/{session_id}", headers={"Authorization": f"Bearer {token}"})
    assert stat_res_active.status_code == 200
    stat_active_data = stat_res_active.json()
    assert stat_active_data["decision"] == "ALLOW"
    assert stat_active_data["session_status"] == "ACTIVE"
    assert stat_active_data["verification_required"] is False
