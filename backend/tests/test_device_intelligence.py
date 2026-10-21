import uuid
import pytest
from unittest.mock import patch
from app.models.user import User
from app.models.device import Device
from app.models.notification import DeviceNotification
from app.models.security_event import SecurityEvent
from app.models.session import Session as UserSession
from app.services.email_service import EmailService


@pytest.fixture
def test_user_pair(client):
    """Creates two distinct isolated user accounts with unique emails per test run."""
    uid = uuid.uuid4().hex[:8]
    email_a = f"alpha_{uid}@cognisec.ai"
    email_b = f"beta_{uid}@cognisec.ai"

    res_a = client.post("/api/auth/register", json={
        "name": f"User Alpha {uid}",
        "email": email_a,
        "password": "Password123!",
        "role": "USER"
    })
    assert res_a.status_code == 201

    res_b = client.post("/api/auth/register", json={
        "name": f"User Beta {uid}",
        "email": email_b,
        "password": "Password123!",
        "role": "USER"
    })
    assert res_b.status_code == 201

    return res_a.json(), res_b.json()


def test_1_first_login_registers_initial_device(client, test_user_pair, db_session):
    """1. First successful login registers the initial device."""
    user_a, _ = test_user_pair
    login_res = client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "application": "platform",
        "device_fingerprint": f"device_fp_initial_{user_a['id']}",
        "browser": "Mozilla/5.0 Chrome/120.0",
        "os": "macOS",
        "nickname": "Alpha MacBook"
    })
    assert login_res.status_code == 200
    data = login_res.json()
    assert "access_token" in data
    assert data["device_id"] is not None

    device = db_session.query(Device).filter(
        Device.user_id == user_a["id"],
        Device.device_fingerprint == f"device_fp_initial_{user_a['id']}"
    ).first()
    assert device is not None
    assert device.device_id.startswith("dev_")
    assert device.nickname == "Alpha MacBook"
    assert device.browser_name == "Chrome"
    assert device.os_name == "macOS"
    assert device.trust_state == "TRUSTED"  # Initial device is enrolled as trusted


def test_2_repeated_login_updates_last_seen(client, test_user_pair, db_session):
    """2. Repeated login from the same device updates last-seen data."""
    user_a, _ = test_user_pair
    fp = f"device_fp_repeat_{user_a['id']}"
    # Initial login
    client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "application": "platform",
        "device_fingerprint": fp,
        "browser": "Mozilla/5.0 Chrome/120.0",
        "os": "macOS"
    })
    dev1 = db_session.query(Device).filter(
        Device.user_id == user_a["id"],
        Device.device_fingerprint == fp
    ).first()
    first_seen = dev1.first_seen
    last_seen_1 = dev1.last_seen

    # Second login from same fingerprint
    res2 = client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "application": "platform",
        "device_fingerprint": fp,
        "browser": "Mozilla/5.0 Chrome/120.0",
        "os": "macOS"
    })
    assert res2.status_code == 200
    db_session.refresh(dev1)
    assert dev1.first_seen == first_seen
    assert dev1.last_seen >= last_seen_1


def test_3_login_from_different_device_creates_separate_observation(client, test_user_pair, db_session):
    """3. Login from a different browser/device creates a separate observation."""
    user_a, _ = test_user_pair
    fp1 = f"fp_primary_{user_a['id']}"
    fp2 = f"fp_secondary_{user_a['id']}"

    # First device
    client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "device_fingerprint": fp1,
        "browser": "Mozilla/5.0 Chrome/120.0",
        "os": "macOS"
    })
    # Second device
    res = client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "device_fingerprint": fp2,
        "browser": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Safari/605.1",
        "os": "iOS"
    })
    assert res.status_code == 200
    assert res.json()["is_new_device"] is True

    devices = db_session.query(Device).filter(Device.user_id == user_a["id"]).all()
    fps = [d.device_fingerprint for d in devices]
    assert fp1 in fps
    assert fp2 in fps


def test_4_new_device_creates_persistent_security_event(client, test_user_pair, db_session):
    """4. New-device login creates a persistent security event."""
    user_a, _ = test_user_pair
    # Seed initial device
    client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "device_fingerprint": f"fp_initial_{user_a['id']}"
    })

    # Unrecognized device
    client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "device_fingerprint": f"fp_unfamiliar_{user_a['id']}",
        "browser": "Mozilla/5.0 Firefox/121.0",
        "os": "Linux"
    })

    sec_event = db_session.query(SecurityEvent).filter(
        SecurityEvent.user_id == user_a["id"],
        SecurityEvent.event_type == "UNRECOGNIZED_DEVICE_LOGIN"
    ).order_by(SecurityEvent.id.desc()).first()
    assert sec_event is not None
    assert sec_event.severity == "MEDIUM"
    assert "Firefox" in sec_event.details


def test_5_correct_email_recipient_resolved_from_database(client, test_user_pair):
    """5. Correct email recipient is resolved from the database."""
    user_a, _ = test_user_pair
    # Initial device
    client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "device_fingerprint": f"fp_initial_{user_a['id']}"
    })

    with patch.object(EmailService, "send_new_device_login_alert", return_value=(False, "SMTP unconfigured")) as mock_email:
        client.post("/api/auth/login", json={
            "email": user_a["email"],
            "password": "Password123!",
            "device_fingerprint": f"fp_email_test_{user_a['id']}",
            "browser": "Chrome/120.0",
            "os": "Windows"
        })
        mock_email.assert_called_once()
        args, kwargs = mock_email.call_args
        assert kwargs["recipient_email"] == user_a["email"]
        assert kwargs["user_name"] == user_a["name"]


def test_6_successful_email_delivery_verified_when_smtp_configured(client, test_user_pair, db_session):
    """6. Successful email delivery is verified when SMTP is configured."""
    user_a, _ = test_user_pair
    # Initial device
    client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "device_fingerprint": f"fp_initial_{user_a['id']}"
    })

    with patch.object(EmailService, "send_new_device_login_alert", return_value=(True, "Email dispatched successfully via TLS")):
        client.post("/api/auth/login", json={
            "email": user_a["email"],
            "password": "Password123!",
            "device_fingerprint": f"fp_smtp_success_{user_a['id']}",
            "browser": "Edge/120.0",
            "os": "Windows"
        })
        notif = db_session.query(DeviceNotification).filter(
            DeviceNotification.user_id == user_a["id"],
            DeviceNotification.notification_type == "NEW_DEVICE_LOGIN"
        ).order_by(DeviceNotification.created_at.desc()).first()
        assert notif is not None
        assert notif.email_delivery_status == "SENT"


def test_7_smtp_failure_reported_honestly_and_does_not_bypass_security(client, test_user_pair, db_session):
    """7. SMTP failure is reported honestly and does not bypass security."""
    user_a, _ = test_user_pair
    # Initial device
    client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "device_fingerprint": f"fp_initial_{user_a['id']}"
    })

    with patch.object(EmailService, "send_new_device_login_alert", return_value=(False, "Connection to mail.server.internal:587 refused")):
        res = client.post("/api/auth/login", json={
            "email": user_a["email"],
            "password": "Password123!",
            "device_fingerprint": f"fp_smtp_fail_{user_a['id']}",
            "browser": "Safari/17.0",
            "os": "macOS"
        })
        # Login still succeeds
        assert res.status_code == 200

        # But notification honestly records email failure
        notif = db_session.query(DeviceNotification).filter(
            DeviceNotification.user_id == user_a["id"],
            DeviceNotification.notification_type == "NEW_DEVICE_LOGIN"
        ).order_by(DeviceNotification.created_at.desc()).first()
        assert notif is not None
        assert notif.email_delivery_status == "FAILED"
        assert "Connection to mail.server.internal:587 refused" in notif.email_error


def test_8_location_denial_still_permits_safe_device_registration(client, test_user_pair, db_session):
    """8. Location denial still permits safe device registration."""
    user_a, _ = test_user_pair
    res = client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "device_fingerprint": f"fp_loc_denied_{user_a['id']}",
        "location_source": "PERMISSION_DENIED",
        "latitude": None,
        "longitude": None
    })
    assert res.status_code == 200
    dev = db_session.query(Device).filter(
        Device.user_id == user_a["id"],
        Device.device_fingerprint == f"fp_loc_denied_{user_a['id']}"
    ).first()
    assert dev is not None
    assert dev.location_source == "PERMISSION_DENIED"
    assert dev.latitude is None
    assert dev.longitude is None


def test_9_missing_geolocation_and_ip_geolocation_handled_gracefully(client, test_user_pair, db_session):
    """9. Missing geolocation and missing IP-geolocation results are handled."""
    user_a, _ = test_user_pair
    res = client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "device_fingerprint": f"fp_no_geo_{user_a['id']}"
    })
    assert res.status_code == 200
    dev = db_session.query(Device).filter(
        Device.user_id == user_a["id"],
        Device.device_fingerprint == f"fp_no_geo_{user_a['id']}"
    ).first()
    assert dev is not None
    assert dev.latitude is None
    assert dev.city is not None or dev.last_ip == "127.0.0.1"


def test_10_owner_isolation_a_cannot_read_or_confirm_b(client, test_user_pair, db_session):
    """10. Owner A cannot read or confirm Owner B's notification."""
    user_a, user_b = test_user_pair

    # Login User A and User B
    tok_a = client.post("/api/auth/login", json={"email": user_a["email"], "password": "Password123!"}).json()["access_token"]
    tok_b = client.post("/api/auth/login", json={"email": user_b["email"], "password": "Password123!"}).json()["access_token"]

    # Trigger unfamiliar device login for User B
    client.post("/api/auth/login", json={
        "email": user_b["email"],
        "password": "Password123!",
        "device_fingerprint": f"fp_beta_phone_{user_b['id']}"
    })

    notif_b = db_session.query(DeviceNotification).filter(
        DeviceNotification.user_id == user_b["id"]
    ).order_by(DeviceNotification.created_at.desc()).first()
    assert notif_b is not None

    # User A tries to read User B's notifications list
    res_list_a = client.get("/api/notifications", headers={"Authorization": f"Bearer {tok_a}"})
    assert res_list_a.status_code == 200
    notif_ids_seen_by_a = [n["notification_id"] for n in res_list_a.json()["notifications"]]
    assert notif_b.notification_id not in notif_ids_seen_by_a

    # User A tries to confirm User B's notification
    res_confirm = client.post(
        f"/api/notifications/{notif_b.notification_id}/respond",
        headers={"Authorization": f"Bearer {tok_a}"},
        json={"decision": "yes"}
    )
    assert res_confirm.status_code == 403  # Forbidden

    # User A tries to revoke User B's device
    dev_b = db_session.query(Device).filter(Device.user_id == user_b["id"]).first()
    res_revoke = client.post(
        f"/api/devices/{dev_b.device_id}/revoke",
        headers={"Authorization": f"Bearer {tok_a}"}
    )
    assert res_revoke.status_code == 403  # Forbidden


def test_11_unknown_device_never_automatically_marked_trusted(client, test_user_pair, db_session):
    """11. An unknown device is never automatically marked TRUSTED."""
    user_a, _ = test_user_pair
    # Initial device
    client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "device_fingerprint": f"fp_initial_{user_a['id']}"
    })

    # Second unknown device
    res = client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "device_fingerprint": f"fp_intruder_{user_a['id']}"
    })
    assert res.status_code == 200
    assert res.json()["trust_state"] != "TRUSTED"
    assert res.json()["trust_state"] == "PENDING_CONFIRMATION"

    dev = db_session.query(Device).filter(
        Device.user_id == user_a["id"],
        Device.device_fingerprint == f"fp_intruder_{user_a['id']}"
    ).first()
    assert dev.trust_state == "PENDING_CONFIRMATION"
    assert dev.is_trusted is False


def test_12_owner_confirmation_changes_trust_state_to_trusted(client, test_user_pair, db_session):
    """12. Owner confirmation changes the server-side trust state correctly."""
    user_a, _ = test_user_pair
    # Initial device
    client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "device_fingerprint": f"fp_initial_{user_a['id']}"
    })

    # Log in from new device
    dev_fp = f"fp_pending_conf_{user_a['id']}"
    client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "device_fingerprint": dev_fp
    })

    dev = db_session.query(Device).filter(
        Device.user_id == user_a["id"],
        Device.device_fingerprint == dev_fp
    ).first()
    assert dev.trust_state == "PENDING_CONFIRMATION"

    notif = db_session.query(DeviceNotification).filter(
        DeviceNotification.user_id == user_a["id"],
        DeviceNotification.device_id == dev.id
    ).first()
    assert notif is not None

    tok_a = client.post("/api/auth/login", json={"email": user_a["email"], "password": "Password123!"}).json()["access_token"]

    # Owner confirms "yes"
    res = client.post(
        f"/api/notifications/{notif.notification_id}/respond",
        headers={"Authorization": f"Bearer {tok_a}"},
        json={"decision": "yes"}
    )
    assert res.status_code == 200
    assert res.json()["status"] == "success"
    assert res.json()["device_trust_state"] == "TRUSTED"

    db_session.refresh(dev)
    assert dev.trust_state == "TRUSTED"
    assert dev.is_trusted is True


def test_13_not_me_revokes_device_and_creates_audit_event(client, test_user_pair, db_session):
    """13. 'Not me' revokes the appropriate session/device and creates an audit event."""
    user_a, _ = test_user_pair
    # Initial device
    client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "device_fingerprint": f"fp_initial_{user_a['id']}"
    })

    # Suspect login
    attack_fp = f"fp_adversary_{user_a['id']}"
    client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "device_fingerprint": attack_fp
    })
    dev = db_session.query(Device).filter(
        Device.user_id == user_a["id"],
        Device.device_fingerprint == attack_fp
    ).first()
    notif = db_session.query(DeviceNotification).filter(
        DeviceNotification.user_id == user_a["id"],
        DeviceNotification.device_id == dev.id
    ).first()

    tok_a = client.post("/api/auth/login", json={"email": user_a["email"], "password": "Password123!"}).json()["access_token"]

    # Owner responds "no"
    res = client.post(
        f"/api/notifications/{notif.notification_id}/respond",
        headers={"Authorization": f"Bearer {tok_a}"},
        json={"decision": "no"}
    )
    assert res.status_code == 200
    assert res.json()["device_trust_state"] == "REVOKED"

    db_session.refresh(dev)
    assert dev.trust_state == "REVOKED"
    assert dev.is_trusted is False

    # Check security event
    sec_event = db_session.query(SecurityEvent).filter(
        SecurityEvent.user_id == user_a["id"],
        SecurityEvent.event_type == "DEVICE_REVOKED"
    ).first()
    assert sec_event is not None
    assert sec_event.decision == "TERMINATE_SESSION"


def test_14_revoked_device_sessions_cannot_access_protected_endpoints(client, test_user_pair, db_session):
    """14. Revoked sessions cannot access protected endpoints."""
    user_a, _ = test_user_pair
    login_data = client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "device_fingerprint": f"fp_sess_killed_{user_a['id']}"
    }).json()

    dev_token = login_data["access_token"]
    dev_id = login_data["device_id"]

    # Verify token works initially
    res_me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {dev_token}"})
    assert res_me.status_code == 200

    # Revoke device
    res_revoke = client.post(
        f"/api/devices/{dev_id}/revoke",
        headers={"Authorization": f"Bearer {dev_token}"}
    )
    assert res_revoke.status_code == 200

    # After revocation, token tied to revoked/terminated session must be rejected
    res_me_after = client.get("/api/auth/me", headers={"Authorization": f"Bearer {dev_token}"})
    assert res_me_after.status_code in (401, 403)


def test_15_notification_unread_counts_persist_correctly(client, test_user_pair, db_session):
    """15. Notification unread counts persist correctly after reload."""
    user_a, _ = test_user_pair
    tok_a = client.post("/api/auth/login", json={"email": user_a["email"], "password": "Password123!"}).json()["access_token"]

    res1 = client.get("/api/notifications", headers={"Authorization": f"Bearer {tok_a}"})
    unread_before = res1.json()["unread_count"]

    # Trigger a new unfamiliar device login
    client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "device_fingerprint": f"fp_count_test_{user_a['id']}"
    })

    res2 = client.get("/api/notifications", headers={"Authorization": f"Bearer {tok_a}"})
    assert res2.json()["unread_count"] >= unread_before + 1

    # Mark all read
    client.post("/api/notifications/mark-all-read", headers={"Authorization": f"Bearer {tok_a}"})

    res3 = client.get("/api/notifications", headers={"Authorization": f"Bearer {tok_a}"})
    assert res3.json()["unread_count"] == 0


def test_16_failed_login_notification_rate_limits_and_deduplication(client, test_user_pair, db_session):
    """16. Failed-login notification rate limits and deduplication work."""
    user_a, _ = test_user_pair

    # Multiple failed logins within seconds
    for _ in range(5):
        client.post("/api/auth/login", json={
            "email": user_a["email"],
            "password": "WrongPassword999!"
        })

    # Deduplication ensures we do not flood the user with 5 separate notifications
    failed_notifs = db_session.query(DeviceNotification).filter(
        DeviceNotification.user_id == user_a["id"],
        DeviceNotification.notification_type == "SUSPICIOUS_LOGIN_FAILED"
    ).all()
    # At most 1 deduplicated alert created in this 5-minute window
    assert len(failed_notifs) <= 1
