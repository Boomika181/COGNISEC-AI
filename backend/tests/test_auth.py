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
