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
from app.services.email_service import EmailService
from app.services.notification_service import NotificationService
from app.services.step_up_service import StepUpService
from app.services.session_service import SessionService
from app.core.security import get_password_hash


# ==============================================================================
# 1. SPECIFIC INCIDENT FIX: 2021bce0492@bits-pilani.ac.in SUPPRESSION
# ==============================================================================

def test_student_roll_number_bits_pilani_suppressed_preventing_ndr():
    """
    Directly addresses the Gmail bounce-back incident:
    2021bce0492@bits-pilani.ac.in failed with 'Address not found'.
    EmailService must identify unverified student roll number / institutional demo
    addresses on bits-pilani.ac.in and suppress outbound SMTP before any network
    connection is initiated, completely preventing Gmail bounce-backs.
    """
    failed_recipient = "2021bce0492@bits-pilani.ac.in"

    is_deliverable, reason = EmailService.is_deliverable_recipient(failed_recipient)
    assert is_deliverable is False
    assert "bits-pilani.ac.in" in reason or "student roll number" in reason.lower()
    assert "suppressed" in reason.lower()

    # Verify that attempting to send to this address never touches SMTP socket
    with patch.object(settings, "SMTP_ENABLED", True), \
         patch.object(settings, "SMTP_HOST", "smtp.gmail.com"), \
         patch.object(settings, "SMTP_USER", "cognisecai.security@gmail.com"), \
         patch.object(settings, "SMTP_PASSWORD", "secret-password"), \
         patch("smtplib.SMTP") as mock_smtp:
        success, message = EmailService.send_email(
            recipient_email=failed_recipient,
            subject="[COGNISEC-AI] Security Verification",
            plain_text="Your OTP is 123456"
        )
        assert success is False
        assert "suppressed" in message.lower()
        mock_smtp.assert_not_called()


def test_verified_mailbox_on_institutional_domain_allowed_if_whitelisted():
    """
    If a real administrative mailbox at bits-pilani.ac.in is explicitly whitelisted
    in VERIFIED_RECIPIENT_MAILBOXES, it is permitted for delivery.
    """
    whitelisted = "placement.officer@bits-pilani.ac.in"
    with patch.object(settings, "VERIFIED_RECIPIENT_MAILBOXES", [whitelisted]):
        is_deliverable, reason = EmailService.is_deliverable_recipient(whitelisted)
        assert is_deliverable is True
        assert reason == "Deliverable"


# ==============================================================================
# 2. DEMO PORTAL DOMAIN SUPPRESSION
# ==============================================================================

def test_demo_portal_domains_suppressed_to_prevent_bounces():
    """
    Simulated demo portal domains (veritas.edu, auraluxe.com, aetheriahealth.org, ayusync.med.in)
    must have outbound SMTP delivery suppressed to prevent provider acceptance bounces.
    """
    demo_recipients = [
        "student.alex@veritas.edu",
        "customer.jane@auraluxe.com",
        "dr.sarah@aetheriahealth.org",
        "dr.boomika@ayusync.med.in",
    ]

    for recip in demo_recipients:
        is_deliv, reason = EmailService.is_deliverable_recipient(recip)
        assert is_deliv is False, f"Expected {recip} to be suppressed"
        assert "suppressed" in reason.lower()


# ==============================================================================
# 3. REAL REGISTERED RECIPIENTS ALLOWED
# ==============================================================================

def test_real_registered_email_passes_deliverability():
    """
    Authentic user domains (e.g. gmail.com, outlook.com, corporate domains)
    pass deliverability checks and are routed to their genuine inbox.
    """
    real_emails = [
        "boomika.ram@gmail.com",
        "security.analyst@microsoft.com",
        "user.identity@yahoo.co.in",
        "employee@enterprise-corp.net"
    ]
    for email in real_emails:
        is_deliv, reason = EmailService.is_deliverable_recipient(email)
        assert is_deliv is True
        assert reason == "Deliverable"


# ==============================================================================
# 4. INVALID EMAIL SYNTAX AND NON-ROUTABLE DOMAINS
# ==============================================================================

def test_invalid_email_syntax_and_non_routable_domains():
    """
    Malformed emails, missing @, spaces, or non-routable domains (invalid, localhost)
    are cleanly rejected with false deliverability and clear error messages.
    """
    invalid_cases = [
        "",
        None,
        "not-an-email",
        "user@",
        "@domain.com",
        "user@localhost",
        "attacker@invalid",
        "user name@domain.com"
    ]
    for bad in invalid_cases:
        is_deliv, reason = EmailService.is_deliverable_recipient(bad)
        assert is_deliv is False
        assert len(reason) > 0


# ==============================================================================
# 5. SMTP SENDER ACCOUNT SEPARATION
# ==============================================================================

def test_smtp_sender_separate_from_recipient(monkeypatch):
    """
    Rule 5: Keep the SMTP sender account separate from the recipient.
    The sender is the configured COGNISEC-AI security email; the recipient
    is the user's registered email.
    """
    mock_server = MagicMock()
    mock_server.sendmail.return_value = {}
    mock_smtp_cls = MagicMock(return_value=mock_server)

    configured_sender = "cognisecai.security@gmail.com"
    registered_recipient = "genuine.user.account@external-domain.org"

    monkeypatch.setattr(settings, "SMTP_ENABLED", True)
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.gmail.com")
    monkeypatch.setattr(settings, "SMTP_PORT", 587)
    monkeypatch.setattr(settings, "SMTP_FROM", configured_sender)
    monkeypatch.setattr(settings, "SMTP_USER", configured_sender)
    monkeypatch.setattr(settings, "SMTP_PASSWORD", "valid-app-password")
    monkeypatch.setattr(settings, "SMTP_TLS", True)
    monkeypatch.setattr(smtplib, "SMTP", mock_smtp_cls)

    success, msg = EmailService.send_email(
        recipient_email=registered_recipient,
        subject="[COGNISEC-AI] Security Alert",
        plain_text="Your account experienced a new sign-in."
    )

    assert success is True
    # Verify exact envelope arguments: sendmail(from_addr, [to_addrs], msg)
    call_args = mock_server.sendmail.call_args[0]
    envelope_sender = call_args[0]
    envelope_recipients = call_args[1]

    assert envelope_sender == configured_sender
    assert envelope_recipients == [registered_recipient]
    assert envelope_sender != envelope_recipients[0]


# ==============================================================================
# 6. DUPLICATE NEW-DEVICE ALERT NOTIFICATION PREVENTION
# ==============================================================================

def test_new_device_login_notification_deduplicated(db_session: Session):
    """
    Rule 7: Prevent duplicate emails caused by repeated telemetry events, repeated
    page loads, or duplicate challenge requests.
    A new device login generates at most 1 security notification alert per (user, device)
    within the deduplication window (10 minutes).
    """
    uid = uuid.uuid4().hex[:6]
    user = User(
        name=f"Dedup User {uid}",
        email=f"dedup_user_{uid}@legit-corp.org",
        password_hash=get_password_hash("Password123!"),
        role="USER",
        account_status="ACTIVE"
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    device = Device(
        user_id=user.id,
        device_fingerprint=f"fp_dedup_test_{uid}",
        nickname="Office Desktop",
        device_type="Desktop",
        trust_state="PENDING_CONFIRMATION",
        is_trusted=False
    )
    db_session.add(device)
    db_session.commit()
    db_session.refresh(device)

    sess = SessionService.create_session(db_session, user_id=user.id, application="platform", device_id=device.id)

    alerts_dispatched = []

    def spy_alert(*args, **kwargs):
        alerts_dispatched.append(kwargs)
        return True, "Alert dispatched"

    with patch.object(settings, "ENVIRONMENT", "test"), \
         patch.object(EmailService, "send_new_device_login_alert", side_effect=spy_alert):
        # 1. First new device login: dispatches alert
        notif1 = NotificationService.notify_new_device_login(
            db=db_session,
            user=user,
            device=device,
            ip_address="192.168.1.100",
            session_id=sess.id
        )
        assert notif1 is not None
        assert len(alerts_dispatched) == 1

        # 2. Immediate duplicate login from same user and device (e.g. page refresh / retry)
        notif2 = NotificationService.notify_new_device_login(
            db=db_session,
            user=user,
            device=device,
            ip_address="192.168.1.100",
            session_id=sess.id
        )
        # Deduplication must return the existing notification without sending a second email
        assert notif2.id == notif1.id
        assert len(alerts_dispatched) == 1


# ==============================================================================
# 7. DUPLICATE STEP-UP CHALLENGE DEDUPLICATION
# ==============================================================================

def test_step_up_challenge_deduplicated_for_same_session(db_session: Session):
    """
    Rule 7: When repeated telemetry events or client re-renders request an adaptive
    challenge for the same active session, existing unexpired challenge is reused
    without generating a duplicate email dispatch.
    """
    uid = uuid.uuid4().hex[:6]
    user = User(
        name=f"StepUp Dedup {uid}",
        email=f"stepup_dedup_{uid}@secure-network.org",
        password_hash=get_password_hash("Password123!"),
        role="USER",
        account_status="ACTIVE"
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    sess = SessionService.create_session(db_session, user_id=user.id, application="platform", status="STEP_UP_REQUIRED")

    email_count = 0

    def mock_send(*args, **kwargs):
        nonlocal email_count
        email_count += 1
        return True, "Dispatched"

    with patch.object(EmailService, "send_otp_email", side_effect=mock_send):
        # 1. Initial challenge creation
        chal1 = StepUpService.create_adaptive_challenge(
            session_id=sess.id,
            user_id=user.id,
            db=db_session,
            risk_score=0.40,
            risk_level="MEDIUM"
        )
        assert chal1["challenge_type"] == "OTP"
        assert email_count == 1

        # 2. Duplicate challenge request (subsequent telemetry event / page reload)
        chal2 = StepUpService.create_adaptive_challenge(
            session_id=sess.id,
            user_id=user.id,
            db=db_session,
            risk_score=0.40,
            risk_level="MEDIUM"
        )
        # Must reuse the same challenge ID and NOT dispatch another email
        assert chal2["challenge_id"] == chal1["challenge_id"]
        assert email_count == 1


# ==============================================================================
# 8. DELIVERY STATUS AND ERROR PERSISTENCE
# ==============================================================================

def test_suppressed_delivery_records_clear_failed_status_and_reason(db_session: Session):
    """
    Rule 4: Do not assume a demo email address is real. If the registered address is
    invalid or delivery fails, record a clear delivery status and show an appropriate message.
    """
    uid = uuid.uuid4().hex[:6]
    demo_user = User(
        name=f"Demo Student {uid}",
        email="2021bce0492@bits-pilani.ac.in",
        password_hash=get_password_hash("Student@123"),
        role="USER",
        account_status="ACTIVE"
    )
    db_session.add(demo_user)
    db_session.commit()
    db_session.refresh(demo_user)

    device = Device(
        user_id=demo_user.id,
        device_fingerprint=f"fp_bits_student_{uid}",
        nickname="Hostel Laptop",
        device_type="Desktop",
        trust_state="PENDING_CONFIRMATION",
        is_trusted=False
    )
    db_session.add(device)
    db_session.commit()
    db_session.refresh(device)

    sess = SessionService.create_session(db_session, user_id=demo_user.id, application="college", device_id=device.id)

    with patch.object(settings, "ENVIRONMENT", "test"), \
         patch.object(settings, "SMTP_ENABLED", True):
        notif = NotificationService.notify_new_device_login(
            db=db_session,
            user=demo_user,
            device=device,
            ip_address="10.0.0.42",
            session_id=sess.id
        )

        assert notif is not None
        assert notif.email_delivery_status == "FAILED"
        assert "unverified student roll number" in notif.email_error.lower()
        assert "Address not found" in notif.email_error or "address not found" in notif.email_error.lower()
