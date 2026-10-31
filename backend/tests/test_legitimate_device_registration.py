import uuid
import pytest
from app.models.user import User
from app.models.device import Device
from app.models.session import Session as UserSession
from app.services.device_service import DeviceService


@pytest.fixture
def test_users(client):
    uid = uuid.uuid4().hex[:8]
    user_a_email = f"dev_user_a_{uid}@cognisec.ai"
    user_b_email = f"dev_user_b_{uid}@cognisec.ai"

    res_a = client.post("/api/auth/register", json={
        "name": f"User A {uid}",
        "email": user_a_email,
        "password": "Password123!",
        "role": "USER"
    })
    assert res_a.status_code == 201

    res_b = client.post("/api/auth/register", json={
        "name": f"User B {uid}",
        "email": user_b_email,
        "password": "Password123!",
        "role": "USER"
    })
    assert res_b.status_code == 201

    return res_a.json(), res_b.json()


def test_1_first_login_creates_one_legitimate_device_record(client, test_users, db_session):
    """Requirement: First login on a new test device creates one legitimate record."""
    user_a, _ = test_users
    fp = f"fp_hardware_{uuid.uuid4().hex[:12]}"

    res = client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "application": "platform",
        "device_fingerprint": fp,
        "browser": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0",
        "os": "macOS",
        "nickname": "Primary MacBook"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["device_id"] is not None

    devices = db_session.query(Device).filter(Device.user_id == user_a["id"]).all()
    assert len(devices) == 1
    device = devices[0]
    assert device.device_fingerprint == fp
    assert device.nickname == "Primary MacBook"
    assert device.device_id == data["device_id"]
    assert device.trust_state == "TRUSTED"  # First device is trusted


def test_2_repeated_login_same_device_does_not_create_duplicates(client, test_users, db_session):
    """Requirement: Repeated login on the same recognized device does not create duplicate devices."""
    user_a, _ = test_users
    fp = f"fp_hardware_{uuid.uuid4().hex[:12]}"

    # Login 1
    res1 = client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "application": "platform",
        "device_fingerprint": fp,
        "browser": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0",
        "os": "macOS",
        "nickname": "Primary MacBook"
    })
    assert res1.status_code == 200
    dev_id_1 = res1.json()["device_id"]

    # Login 2 from exact same device
    res2 = client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "application": "platform",
        "device_fingerprint": fp,
        "browser": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0",
        "os": "macOS",
        "nickname": "Primary MacBook"
    })
    assert res2.status_code == 200
    dev_id_2 = res2.json()["device_id"]

    assert dev_id_1 == dev_id_2

    devices = db_session.query(Device).filter(Device.user_id == user_a["id"]).all()
    assert len(devices) == 1, "Duplicate device created on repeated login!"


def test_3_second_distinguishable_device_gets_separate_record(client, test_users, db_session):
    """Requirement: A second distinguishable device gets its own record."""
    user_a, _ = test_users
    fp1 = f"fp_laptop_{uuid.uuid4().hex[:12]}"
    fp2 = f"fp_mobile_{uuid.uuid4().hex[:12]}"

    # Device 1: Laptop
    client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "device_fingerprint": fp1,
        "browser": "Mozilla/5.0 Chrome/120.0",
        "os": "macOS",
        "nickname": "Work MacBook"
    })

    # Device 2: Mobile
    client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "device_fingerprint": fp2,
        "browser": "Mozilla/5.0 Mobile Safari/16.0",
        "os": "iOS",
        "nickname": "Personal iPhone"
    })

    devices = db_session.query(Device).filter(Device.user_id == user_a["id"]).order_by(Device.first_seen.asc()).all()
    assert len(devices) == 2
    assert devices[0].device_fingerprint == fp1
    assert devices[0].nickname == "Work MacBook"
    assert devices[0].trust_state == "TRUSTED"

    assert devices[1].device_fingerprint == fp2
    assert devices[1].nickname == "Personal iPhone"
    assert devices[1].trust_state == "PENDING_CONFIRMATION"  # Second device is pending


def test_4_editing_nickname_does_not_change_device_identity(client, test_users, db_session):
    """Requirement: Editing a nickname does not change the underlying device identity."""
    user_a, _ = test_users
    fp = f"fp_hardware_{uuid.uuid4().hex[:12]}"

    login_res = client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "device_fingerprint": fp,
        "browser": "Chrome/120.0",
        "os": "macOS",
        "nickname": "Initial Label"
    })
    token = login_res.json()["access_token"]
    dev_id = login_res.json()["device_id"]

    # Edit nickname via API
    rename_res = client.put(f"/api/devices/{dev_id}/nickname", json={
        "nickname": "Renamed Custom MacBook"
    }, headers={"Authorization": f"Bearer {token}"})
    assert rename_res.status_code == 200
    assert rename_res.json()["nickname"] == "Renamed Custom MacBook"

    # Query DB
    dev = db_session.query(Device).filter(Device.device_id == dev_id).first()
    assert dev.nickname == "Renamed Custom MacBook"
    assert dev.device_fingerprint == fp  # Underlying fingerprint is unchanged!

    # Login again with the same device
    login_res2 = client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "device_fingerprint": fp,
        "browser": "Chrome/120.0",
        "os": "macOS"
    })
    assert login_res2.status_code == 200
    assert login_res2.json()["device_id"] == dev_id

    # Count devices
    devices = db_session.query(Device).filter(Device.user_id == user_a["id"]).all()
    assert len(devices) == 1, "Renaming device must not split or duplicate the device identity!"


def test_5_revoked_devices_remain_revoked(client, test_users, db_session):
    """Requirement: Revoked devices remain revoked."""
    user_a, _ = test_users
    fp = f"fp_hardware_{uuid.uuid4().hex[:12]}"

    login_res = client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "device_fingerprint": fp,
        "browser": "Chrome/120.0",
        "os": "macOS",
        "nickname": "Device To Revoke"
    })
    token = login_res.json()["access_token"]
    dev_id = login_res.json()["device_id"]

    # Revoke device
    revoke_res = client.post(f"/api/devices/{dev_id}/revoke", headers={"Authorization": f"Bearer {token}"})
    assert revoke_res.status_code == 200
    assert revoke_res.json()["trust_state"] == "REVOKED"

    dev = db_session.query(Device).filter(Device.device_id == dev_id).first()
    assert dev.trust_state == "REVOKED"
    assert dev.is_trusted is False

    # Attempt to log in again with revoked device
    login_res2 = client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "device_fingerprint": fp,
        "browser": "Chrome/120.0",
        "os": "macOS"
    })
    assert login_res2.status_code == 200
    assert login_res2.json()["trust_state"] == "REVOKED"

    db_session.refresh(dev)
    assert dev.trust_state == "REVOKED", "Revoked device must not silently revert to trusted or pending!"


def test_6_user_isolation_cannot_see_or_modify_other_devices(client, test_users, db_session):
    """Requirement: User A cannot see or modify User B's devices."""
    user_a, user_b = test_users

    # Login User A
    res_a = client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "device_fingerprint": f"fp_a_{uuid.uuid4().hex[:8]}"
    })
    token_a = res_a.json()["access_token"]
    dev_id_a = res_a.json()["device_id"]

    # Login User B
    res_b = client.post("/api/auth/login", json={
        "email": user_b["email"],
        "password": "Password123!",
        "device_fingerprint": f"fp_b_{uuid.uuid4().hex[:8]}"
    })
    token_b = res_b.json()["access_token"]
    dev_id_b = res_b.json()["device_id"]

    # User A tries to view User B's device inventory
    devices_a = client.get("/api/devices", headers={"Authorization": f"Bearer {token_a}"}).json()
    assert all(d["device_id"] != dev_id_b for d in devices_a), "User A saw User B's device in list!"

    # User A tries to view User B's specific device
    detail_res = client.get(f"/api/devices/{dev_id_b}", headers={"Authorization": f"Bearer {token_a}"})
    assert detail_res.status_code == 403

    # User A tries to rename User B's device
    rename_res = client.put(f"/api/devices/{dev_id_b}/nickname", json={
        "nickname": "Hacked Nickname"
    }, headers={"Authorization": f"Bearer {token_a}"})
    assert rename_res.status_code == 403

    # User A tries to revoke User B's device
    revoke_res = client.post(f"/api/devices/{dev_id_b}/revoke", headers={"Authorization": f"Bearer {token_a}"})
    assert revoke_res.status_code == 403


def test_7_no_placeholder_devices_automatically_generated(client, test_users, db_session):
    """Requirement: No placeholder devices like 'Device #N' or 'Browser on OS' are automatically generated."""
    user_a, _ = test_users

    # Login without providing a nickname, with an unidentifiable/generic user agent
    res = client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "device_fingerprint": f"fp_unidentifiable_{uuid.uuid4().hex[:8]}",
        "browser": "CustomRawAgent/1.0",
        "os": "CustomOS"
    })
    assert res.status_code == 200

    devices = db_session.query(Device).filter(Device.user_id == user_a["id"]).all()
    assert len(devices) == 1
    device = devices[0]

    # Verify no 'Device #' or 'Browser on OS'
    assert not device.nickname.startswith("Device #"), f"Fabricated placeholder: {device.nickname}"
    assert "Browser on OS" not in device.nickname, f"Fabricated placeholder: {device.nickname}"
    assert device.nickname in ("CustomOS Desktop", "Unverified Device", "CustomRawAgent on CustomOS"), f"Unexpected: {device.nickname}"

    # Second login without fingerprint or info
    res2 = client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "device_fingerprint": "unknown",
        "browser": "",
        "os": ""
    })
    assert res2.status_code == 200
    dev2 = db_session.query(Device).filter(Device.device_id == res2.json()["device_id"]).first()
    assert dev2.nickname == "Unverified Device", f"Expected Unverified Device, got: {dev2.nickname}"
    assert not dev2.nickname.startswith("Device #")
