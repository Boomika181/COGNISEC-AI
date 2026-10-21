import pytest
import uuid
import smtplib
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.user import User
from app.models.device import Device
from app.models.session import Session as DbSession
from app.models.notification import DeviceNotification
from app.models.security_event import SecurityEvent
from app.services.email_service import EmailService
from app.services.notification_service import NotificationService
from app.services.device_service import DeviceService
from app.services.session_service import SessionService
from app.core.security import get_password_hash, create_access_token


# ==============================================================================
# PHASE 1 & 2: VERIFIED RECIPIENT ROUTING & SUPPRESSION OF UNVERIFIED RECIPIENTS
# ==============================================================================

def test_unverified_cognisec_ai_recipient_suppressed():
    """
    Directly addresses the Microsoft NDR bug:
    Sending to an unverified mailbox like audit_shop_62efad@cognisec.ai is suppressed
    before any outbound SMTP network attempt, preventing NDR bounces (550 5.1.10).
    """
    unverified_recipient = "audit_shop_62efad@cognisec.ai"

    # With default configuration, no @cognisec.ai mailboxes are in verified whitelist
    is_deliverable, reason = EmailService.is_deliverable_recipient(unverified_recipient)
    assert is_deliverable is False
    assert "unverified @cognisec.ai mailbox" in reason.lower()
    assert "suppressed to prevent microsoft ndr" in reason.lower()

    # Attempting to send_email must return False and suppress outbound dispatch
    with patch.object(settings, "SMTP_ENABLED", True), \
         patch.object(settings, "SMTP_HOST", "smtp.gmail.com"), \
         patch.object(settings, "SMTP_USER", "real.sender@gmail.com"), \
         patch.object(settings, "SMTP_PASSWORD", "secret-app-password"), \
         patch("smtplib.SMTP") as mock_smtp:
        success, message = EmailService.send_email(
            recipient_email=unverified_recipient,
            subject="[COGNISEC-AI] New Sign-In Detected",
            plain_text="Security Alert"
        )
        assert success is False
        assert "suppressed" in message.lower()
        # Ensure smtplib was never even instantiated
        mock_smtp.assert_not_called()


def test_verified_cognisec_ai_recipient_allowed_when_configured():
    """
    When an explicit corporate mailbox is verified in settings.VERIFIED_COGNISIC_MAILBOXES,
    it passes deliverability validation.
    """
    verified_box = "security.ops@cognisec.ai"
    with patch.object(settings, "VERIFIED_COGNISIC_MAILBOXES", [verified_box]):
        is_deliv, reason = EmailService.is_deliverable_recipient(verified_box)
        assert is_deliv is True
        assert reason == "Deliverable"


def test_non_routable_domain_rejected():
    """
    Reserved and non-routable domains (invalid, localhost) are rejected.
    """
    is_deliv_inv, _ = EmailService.is_deliverable_recipient("attacker@invalid")
    assert is_deliv_inv is False

    is_deliv_loc, _ = EmailService.is_deliverable_recipient("test@localhost")
    assert is_deliv_loc is False


def test_new_device_login_alert_includes_all_required_attributes():
    """
    Rule 4: New-device alert includes recorded device nickname/name, approximate
    location, timestamp, and recognized trust state.
    """
    captured_payloads = []

    def mock_send(recipient_email, subject, plain_text, html_text=None, from_email=None):
        captured_payloads.append({
            "recipient": recipient_email,
            "subject": subject,
            "plain": plain_text,
            "html": html_text
        })
        return True, "Delivered"

    real_send_alert = getattr(EmailService, "_original_send_alert", EmailService.send_new_device_login_alert)
    with patch.object(EmailService, "send_email", side_effect=mock_send):
        success, _ = real_send_alert(
            recipient_email="owner@realdomain.org",
            user_name="Alice Owner",
            device_summary="Chrome 124 on macOS 14.4",
            ip_address="198.51.100.42",
            location_summary="San Francisco, US (GPS)",
            timestamp_str="2026-10-13 11:45:00 UTC",
            device_nickname="Primary MacBook Pro",
            is_recognized=False
        )

        assert success is True
        assert len(captured_payloads) == 1
        p = captured_payloads[0]

        # Verify all required attributes are in both plain text and HTML
        for body in (p["plain"], p["html"]):
            assert "Primary MacBook Pro" in body
            assert "San Francisco, US (GPS)" in body
            assert "2026-10-13 11:45:00 UTC" in body
            assert "198.51.100.42" in body
            assert "Chrome 124 on macOS 14.4" in body

        # Recognition state check
        assert "No (New / Unrecognized Device)" in p["plain"]
        assert "Unrecognized / Action Required" in p["html"]


def test_new_device_alert_for_unverified_domain_does_not_crash_and_preserves_db_event(db_session: Session):
    """
    If a synthetic user with an unverified @cognisec.ai address triggers a new-device alert,
    outbound SMTP is cleanly suppressed, and the notification record and security event
    are cleanly persisted with FAILED status and no crash.
    """
    u_id = uuid.uuid4().hex[:6]
    synthetic_user = User(
        name=f"Synth User {u_id}",
        email=f"audit_portal_{u_id}@cognisec.ai",
        password_hash=get_password_hash("Secret123!"),
        role="USER",
        account_status="ACTIVE"
    )
    db_session.add(synthetic_user)
    db_session.commit()
    db_session.refresh(synthetic_user)

    device = Device(
        user_id=synthetic_user.id,
        device_fingerprint=f"fp_synth_{u_id}",
        nickname="Audit Laptop",
        device_type="Desktop",
        trust_state="PENDING_CONFIRMATION",
        is_trusted=False
    )
    db_session.add(device)
    db_session.commit()
    db_session.refresh(device)

    sess = SessionService.create_session(db_session, user_id=synthetic_user.id, application="platform", device_id=device.id)

    # In test environment, NotificationService dispatches synchronously
    with patch.object(settings, "ENVIRONMENT", "test"):
        notif = NotificationService.notify_new_device_login(
            db=db_session,
            user=synthetic_user,
            device=device,
            ip_address="127.0.0.1",
            session_id=sess.id
        )

        assert notif is not None
        assert notif.email_delivery_status == "FAILED"
        assert "unverified @cognisec.ai mailbox" in notif.email_error.lower()

        # Confirm security event is persisted
        sec_event = db_session.query(SecurityEvent).filter(
            SecurityEvent.user_id == synthetic_user.id,
            SecurityEvent.event_type == "UNRECOGNIZED_DEVICE_LOGIN"
        ).first()
        assert sec_event is not None


# ==============================================================================
# PHASE 3: RECIPIENT ISOLATION ACROSS DISTINCT USERS
# ==============================================================================

def test_recipient_isolation_two_distinct_users(client: TestClient, db_session: Session):
    """
    User A login alerts go exclusively to User A's registered email.
    User B login alerts go exclusively to User B's registered email.
    Cross-routing or leaking to application aliases never occurs.
    """
    uid_a = uuid.uuid4().hex[:6]
    uid_b = uuid.uuid4().hex[:6]
    email_a = f"alice_owner_{uid_a}@independent-domain.org"
    email_b = f"bob_owner_{uid_b}@separate-domain.net"

    # Register both users
    client.post("/api/auth/register", json={"name": "Alice A", "email": email_a, "password": "Password123!"})
    client.post("/api/auth/register", json={"name": "Bob B", "email": email_b, "password": "Password123!"})

    alerts_sent = []

    def spy_alert(*args, **kwargs):
        alerts_sent.append(kwargs)
        return True, "Alert sent"

    with patch.object(EmailService, "send_new_device_login_alert", side_effect=spy_alert):
        # 1. Login User A from new device
        res_a = client.post("/api/auth/login", json={
            "email": email_a,
            "password": "Password123!",
            "device_fingerprint": f"fp_device_a_{uid_a}"
        })
        assert res_a.status_code == 200

        # 2. Login User B from new device
        res_b = client.post("/api/auth/login", json={
            "email": email_b,
            "password": "Password123!",
            "device_fingerprint": f"fp_device_b_{uid_b}"
        })
        assert res_b.status_code == 200

    assert len(alerts_sent) == 2
    # Verify strict recipient isolation
    assert alerts_sent[0]["recipient_email"] == email_a
    assert alerts_sent[0]["user_name"] == "Alice A"
    assert alerts_sent[1]["recipient_email"] == email_b
    assert alerts_sent[1]["user_name"] == "Bob B"


def test_device_confirmation_yes_marks_trusted_and_no_revokes(client: TestClient, db_session: Session):
    """
    Rule 5: Device confirmation YES/NO performs corresponding authenticated server-side action:
    - 'yes': updates device trust state to TRUSTED.
    - 'no': updates device trust state to REVOKED and terminates active sessions.
    """
    uid = uuid.uuid4().hex[:6]
    user_email = f"owner_confirm_{uid}@test-domain.org"
    client.post("/api/auth/register", json={"name": "Owner Confirm", "email": user_email, "password": "Password123!"})

    login_res = client.post("/api/auth/login", json={
        "email": user_email,
        "password": "Password123!",
        "device_fingerprint": f"fp_confirm_{uid}"
    })
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Fetch notification created
    notif = db_session.query(DeviceNotification).join(User).filter(User.email == user_email).first()
    assert notif is not None

    # 1. Confirm device ("yes")
    yes_res = client.post(f"/api/notifications/{notif.notification_id}/respond", headers=headers, json={"decision": "yes"})
    assert yes_res.status_code == 200
    assert yes_res.json()["device_trust_state"] == "TRUSTED"

    db_device = db_session.query(Device).filter(Device.id == notif.device_id).first()
    assert db_device.trust_state == "TRUSTED"
    assert db_device.is_trusted is True

    # 2. Test deny device ("no") on a second notification
    user = db_session.query(User).filter(User.email == user_email).first()
    dev2 = Device(
        user_id=user.id,
        device_fingerprint=f"fp_confirm2_{uid}",
        nickname="Rogue Phone",
        device_type="Mobile",
        trust_state="PENDING_CONFIRMATION",
        is_trusted=False
    )
    db_session.add(dev2)
    db_session.commit()
    db_session.refresh(dev2)

    active_sess = SessionService.create_session(db_session, user_id=user.id, application="platform", device_id=dev2.id, status="ACTIVE")

    notif2 = DeviceNotification(
        user_id=user.id,
        device_id=dev2.id,
        notification_type="NEW_DEVICE_LOGIN",
        title="New Sign-In Detected",
        message="Alert",
        device_summary="Mobile",
        ip_address="127.0.0.1",
        status="PENDING_CONFIRMATION"
    )
    db_session.add(notif2)
    db_session.commit()
    db_session.refresh(notif2)

    no_res = client.post(f"/api/notifications/{notif2.notification_id}/respond", headers=headers, json={"decision": "no"})
    assert no_res.status_code == 200
    assert no_res.json()["device_trust_state"] == "REVOKED"

    db_session.refresh(dev2)
    assert dev2.trust_state == "REVOKED"
    assert dev2.is_trusted is False

    # Verify session was terminated server-side
    db_session.refresh(active_sess)
    assert active_sess.status == "TERMINATED"
