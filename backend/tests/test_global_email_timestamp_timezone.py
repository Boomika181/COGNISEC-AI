"""Comprehensive deterministic tests for global email timestamp, timezone, expiry, and SMTP Date header accuracy."""

from datetime import datetime, timedelta, timezone
from email import message_from_string
from email.utils import parsedate_to_datetime
import smtplib
from unittest.mock import MagicMock, patch

from app.core.config import settings
from app.services.email_service import EmailService
from app.utils.email_time import (
    compute_expiry_display,
    ensure_utc,
    format_appointment_datetime,
    format_email_timestamp,
)


FIXED_ISSUED_UTC = datetime(2026, 11, 12, 10, 0, 0, tzinfo=timezone.utc)  # 3:30 PM IST
FIXED_EXPIRES_UTC = datetime(2026, 11, 12, 10, 5, 0, tzinfo=timezone.utc)  # 3:35 PM IST


def test_utc_to_ist_conversion_and_timezone_aware_handling():
    assert format_email_timestamp(FIXED_ISSUED_UTC) == "12 November 2026, 3:30 PM IST"
    assert format_email_timestamp(FIXED_EXPIRES_UTC) == "12 November 2026, 3:35 PM IST"
    assert format_email_timestamp("2026-11-12T10:00:00Z") == "12 November 2026, 3:30 PM IST"
    assert format_email_timestamp("2026-11-12 10:00:00 UTC") == "12 November 2026, 3:30 PM IST"

    # Naive datetime is treated as UTC and converted to IST
    naive_utc = datetime(2026, 11, 12, 10, 0, 0)
    assert format_email_timestamp(naive_utc) == "12 November 2026, 3:30 PM IST"

    # Non-UTC timezone-aware datetime (UTC-05:00 -> 10:00 UTC -> 15:30 IST)
    est = timezone(timedelta(hours=-5))
    est_dt = datetime(2026, 11, 12, 5, 0, 0, tzinfo=est)
    assert format_email_timestamp(est_dt) == "12 November 2026, 3:30 PM IST"


def test_invalid_or_missing_timestamp_handling():
    assert ensure_utc(None) is None
    assert ensure_utc("") is None
    assert ensure_utc("not-a-valid-timestamp") is None
    assert format_email_timestamp(None) == "Unavailable (server timestamp missing)"
    assert format_email_timestamp("invalid-date") == "Unavailable (server timestamp missing)"
    # Never appends IST to an invalid string
    assert "IST" not in format_email_timestamp("invalid-date")
    # Invalid explicit issued_at or expires_at in compute_expiry_display
    assert compute_expiry_display(issued_at="bad-ts") == (
        "Unavailable (server timestamp missing)",
        "Unavailable (server timestamp missing)",
        "Unavailable",
    )
    assert compute_expiry_display(issued_at=FIXED_ISSUED_UTC, expires_at="bad-exp") == (
        "12 November 2026, 3:30 PM IST",
        "Unavailable (server timestamp missing)",
        "Unavailable",
    )


def test_compute_expiry_display_and_expired_otp_guard():
    issued_s, expires_s, rem = compute_expiry_display(
        issued_at=FIXED_ISSUED_UTC,
        expires_at=FIXED_EXPIRES_UTC,
    )
    assert issued_s == "12 November 2026, 3:30 PM IST"
    assert expires_s == "12 November 2026, 3:35 PM IST"
    assert rem == "5 minutes"

    # Expired OTP is never presented as valid
    _, _, expired_rem = compute_expiry_display(
        issued_at=FIXED_ISSUED_UTC,
        expires_at=FIXED_ISSUED_UTC - timedelta(seconds=10),
    )
    assert expired_rem == "Expired"


def test_appointment_datetime_formatting_accuracy():
    assert (
        format_appointment_datetime("2026-11-13", "09:00 AM")
        == "13 November 2026, 9:00 AM IST"
    )
    assert (
        format_appointment_datetime("2026-11-13", "14:30")
        == "13 November 2026, 2:30 PM IST"
    )
    assert "Unavailable" in format_appointment_datetime("", "")


def _capture_email(fn, **kwargs):
    captured = {}

    def fake_send(**send_kwargs):
        captured.update(send_kwargs)
        return True, "SMTP_ACCEPTED"

    with patch.object(EmailService, "send_email", side_effect=fake_send):
        ok, msg = fn(**kwargs)
    return ok, msg, captured


def test_all_otp_and_portal_emails_display_ist_timestamps_and_preserve_branding():
    # 1. Initial Login OTP
    ok, _, cap = _capture_email(
        getattr(EmailService, "_original_send_otp", EmailService.send_otp_email),
        recipient_email="user@gmail.com",
        otp_code="112233",
        expires_in_minutes=5,
        challenge_id="chal_login_1",
        issued_at=FIXED_ISSUED_UTC,
        expires_at=FIXED_EXPIRES_UTC,
    )
    assert ok is True
    assert "12 November 2026, 3:30 PM IST" in cap["html_text"]
    assert "12 November 2026, 3:35 PM IST" in cap["html_text"]
    assert "12 November 2026, 3:30 PM IST" in cap["plain_text"]

    # 2. Suspended Portal Recovery OTP (converts UTC input to IST)
    ok, _, cap = _capture_email(
        getattr(EmailService, "_original_send_recovery", EmailService.send_recovery_otp_email),
        recipient_email="user@gmail.com",
        otp_code="445566",
        portal="college",
        security_reference_id="SEC-REF-001",
        request_timestamp="2026-11-12 10:00:00 UTC",
        expires_in_minutes=5,
        challenge_id="chal_rec_1",
        issued_at=FIXED_ISSUED_UTC,
        expires_at=FIXED_EXPIRES_UTC,
    )
    assert ok is True
    assert "BITS Pilani Academic Portal" in cap["html_text"]
    assert "12 November 2026, 3:30 PM IST" in cap["html_text"]
    assert "12 November 2026, 3:35 PM IST" in cap["html_text"]
    assert "2026-11-12 10:00:00 UTC" not in cap["html_text"]
    assert "Recovery request: 12 November 2026, 3:30 PM IST" in cap["plain_text"]

    # 3. College Examination OTP
    ok, _, cap = _capture_email(
        getattr(EmailService, "_original_send_exam", EmailService.send_exam_otp_email),
        recipient_email="student@gmail.com",
        otp_code="778899",
        course_name="CS F372 Operating Systems",
        expires_in_minutes=5,
        challenge_id="chal_exam_1",
        issued_at=FIXED_ISSUED_UTC,
        expires_at=FIXED_EXPIRES_UTC,
    )
    assert ok is True
    assert "BITS Pilani Academic Portal" in cap["html_text"]
    assert "12 November 2026, 3:30 PM IST" in cap["html_text"]
    assert "12 November 2026, 3:35 PM IST" in cap["html_text"]

    # 4. Shopping Payment Authorization OTP
    ok, _, cap = _capture_email(
        getattr(EmailService, "_original_send_pay", EmailService.send_payment_otp_email),
        recipient_email="shopper@gmail.com",
        otp_code="998877",
        order_id="ORD-NYR-1001",
        amount=4999.00,
        item_summary="1x Nyraa Silk Dress",
        expires_in_minutes=5,
        challenge_id="chal_pay_1",
        issued_at=FIXED_ISSUED_UTC,
        expires_at=FIXED_EXPIRES_UTC,
    )
    assert ok is True
    assert "NYRAA" in cap["html_text"]
    assert "Aura Luxe Retail" in cap["html_text"]
    assert "12 November 2026, 3:30 PM IST" in cap["html_text"]
    assert "12 November 2026, 3:35 PM IST" in cap["html_text"]

    # 5. Healthcare Appointment OTP (separate Appointment vs Issued vs Expires)
    ok, _, cap = _capture_email(
        EmailService.send_appointment_otp_email,
        recipient_email="patient@gmail.com",
        otp_code="654321",
        patient_name="Aarav Sharma",
        doctor_name="Dr. Meera Krishnan",
        appointment_date="2026-11-13",
        time_slot="09:00 AM",
        department="Cardiology",
        expires_in_minutes=5,
        challenge_id="chal_apt_1",
        appointment_reference="AYU-2026-123456",
        consultation_mode="In-Person Hospital Visit",
        issued_at=FIXED_ISSUED_UTC,
        expires_at=FIXED_EXPIRES_UTC,
    )
    assert ok is True
    assert "AYUSYNC MEDCARE" in cap["html_text"]
    assert "13 November 2026, 9:00 AM IST" in cap["html_text"]
    assert "12 November 2026, 3:30 PM IST" in cap["html_text"]
    assert "12 November 2026, 3:35 PM IST" in cap["html_text"]

    # 6. Password-Change Reset OTP
    ok, _, cap = _capture_email(
        getattr(EmailService, "_original_send_reset", EmailService.send_password_reset_email),
        recipient_email="user@gmail.com",
        otp_code="321654",
        expires_in_minutes=5,
        issued_at=FIXED_ISSUED_UTC,
        expires_at=FIXED_EXPIRES_UTC,
    )
    assert ok is True
    assert "12 November 2026, 3:30 PM IST" in cap["html_text"]
    assert "12 November 2026, 3:35 PM IST" in cap["html_text"]


def test_resent_otp_displays_newly_issued_timestamps():
    resend_issued = FIXED_ISSUED_UTC + timedelta(minutes=2)  # 3:32 PM IST
    resend_expires = resend_issued + timedelta(minutes=5)     # 3:37 PM IST
    ok, _, cap = _capture_email(
        getattr(EmailService, "_original_send_otp", EmailService.send_otp_email),
        recipient_email="user@gmail.com",
        otp_code="223344",
        expires_in_minutes=5,
        challenge_id="chal_resend_2",
        issued_at=resend_issued,
        expires_at=resend_expires,
    )
    assert ok is True
    assert "12 November 2026, 3:32 PM IST" in cap["html_text"]
    assert "12 November 2026, 3:37 PM IST" in cap["html_text"]
    assert "3:30 PM IST" not in cap["html_text"]


def test_security_alerts_and_admin_soc_notifications_display_ist_event_time():
    # New device login alert
    ok, _, cap = _capture_email(
        getattr(EmailService, "_original_send_alert", EmailService.send_new_device_login_alert),
        recipient_email="user@gmail.com",
        user_name="Test User",
        device_summary="Chrome on macOS",
        ip_address="203.0.113.10",
        location_summary="Bengaluru, India",
        timestamp_str="2026-11-12 10:00:00 UTC",
    )
    assert ok is True
    assert "12 November 2026, 3:30 PM IST" in cap["html_text"]
    assert "Time (UTC):" not in cap["html_text"]

    # Password changed notification
    ok, _, cap = _capture_email(
        getattr(EmailService, "_original_send_pwd_chg", EmailService.send_password_changed_notification),
        recipient_email="user@gmail.com",
        user_name="Test User",
        application="college",
        timestamp_str="2026-11-12 10:00:00 UTC",
    )
    assert ok is True
    assert "12 November 2026, 3:30 PM IST" in cap["html_text"]
    assert "Time (UTC):" not in cap["html_text"]

    # Admin/SOC & Portal security notification
    ok, _, cap = _capture_email(
        getattr(EmailService, "_original_send_portal_sec", EmailService.send_portal_security_notification),
        recipient_email="soc@cognisec.ai",
        user_name="SOC Administrator",
        portal="shopping",
        event_type="PORTAL_LOCKED",
        lock_reason="Exceeded max OTP attempts",
        security_reference_id="SEC-999",
        timestamp_str="2026-11-12 10:00:00 UTC",
        is_admin_notice=True,
        target_account_email="user@gmail.com",
    )
    assert ok is True
    assert "12 November 2026, 3:30 PM IST" in cap["html_text"]
    assert "Time (UTC):" not in cap["html_text"]


def test_smtp_date_header_valid_and_retries_preserve_original_timestamps():
    sent_raw_messages = []

    fake_server = MagicMock()

    def sendmail_side_effect(sender, recipients, raw_msg):
        sent_raw_messages.append(raw_msg)
        if len(sent_raw_messages) == 1:
            raise smtplib.SMTPServerDisconnected("Transient drop")
        return {}

    fake_server.sendmail.side_effect = sendmail_side_effect

    with patch.object(settings, "SMTP_HOST", "smtp.gmail.com"), \
         patch.object(settings, "SMTP_PORT", 587), \
         patch.object(settings, "SMTP_USER", "sender@gmail.com"), \
         patch.object(settings, "SMTP_PASSWORD", "app-pass"), \
         patch.object(settings, "SMTP_FROM", "sender@gmail.com"), \
         patch.object(settings, "SMTP_ENABLED", True), \
         patch.object(settings, "ENVIRONMENT", "test"), \
         patch("app.services.email_service.smtplib.SMTP", return_value=fake_server):
        res = EmailService.send_email_with_status(
            recipient_email="recipient@gmail.com",
            subject="COGNISEC-AI Timestamp Retry Test",
            plain_text="Event Time: 12 November 2026, 3:30 PM IST",
            html_text="<p>Event Time: 12 November 2026, 3:30 PM IST</p>",
            max_retries=2,
            correlation_id="retry_ts_check_01",
        )

    assert res["success"] is True
    assert res["attempts"] == 2
    assert len(sent_raw_messages) == 2
    # Retries must transmit the exact same raw MIME message (Date header + event timestamp preserved)
    assert sent_raw_messages[0] == sent_raw_messages[1]

    parsed = message_from_string(sent_raw_messages[0])
    assert parsed["Date"] is not None
    assert parsed["Date"].endswith("GMT")
    parsed_dt = parsedate_to_datetime(parsed["Date"])
    assert parsed_dt.tzinfo is not None
    assert parsed_dt.utcoffset() == timedelta(0)
