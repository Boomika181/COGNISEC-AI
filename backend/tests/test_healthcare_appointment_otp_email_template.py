"""Tests for the AyuSync MedCare Healthcare appointment verification OTP email template."""

from unittest.mock import patch

from app.services.email_service import EmailService


def _render_appointment_email(**overrides):
    captured = {}

    def fake_send_email(*args, **kwargs):
        captured.update(kwargs)
        return True, "SMTP_ACCEPTED"

    params = {
        "recipient_email": "patient.test@gmail.com",
        "otp_code": "739204",
        "patient_name": "Aarav Sharma",
        "doctor_name": "Dr. Meera Krishnan",
        "appointment_date": "2026-11-18",
        "time_slot": "10:30 AM",
        "department": "Cardiology & Electrophysiology",
        "expires_in_minutes": 5,
        "challenge_id": "apt_chal_001",
        "appointment_reference": "AYU-2026-9F3C1A",
        "consultation_mode": "In-Person Hospital Visit",
    }
    params.update(overrides)

    with patch.object(EmailService, "send_email", side_effect=fake_send_email):
        ok, msg = EmailService.send_appointment_otp_email(**params)
    return ok, msg, captured


def test_healthcare_appointment_otp_email_branding_and_content():
    ok, msg, captured = _render_appointment_email()
    assert ok is True
    assert msg == "SMTP_ACCEPTED"
    assert captured["recipient_email"] == "patient.test@gmail.com"
    assert captured["correlation_id"] == "apt_chal_001"
    assert captured["subject"] == "AYUSYNC MEDCARE — Appointment Identity Verification Code"

    html = captured["html_text"]
    text = captured["plain_text"]

    # Branding & header
    assert "AYUSYNC MEDCARE" in html
    assert "HOSPITALS" in html
    assert "Tertiary Multispecialty &amp; Academic Medical Center" in html
    assert "COGNISEC-AI Zero-Trust Healthcare" in html
    assert "COGNISEC-AI SECURE VERIFICATION" in html
    assert "Appointment Identity Verification" in html
    assert (
        "Your clinical appointment requires identity verification. "
        "Please use the secure verification code below to confirm your appointment."
    ) in html

    # Teal, emerald, white, and light-grey palette (no dark/red theme)
    assert "#0d9488" in html
    assert "#0f766e" in html
    assert "#059669" in html
    assert "#f1f5f9" in html
    assert "#ffffff" in html
    assert "#080808" not in html
    assert "#dc2626" not in html

    # Dynamic appointment details
    assert "Appointment Details" in html
    assert "Patient Name" in html
    assert "Aarav Sharma" in html
    assert "Consultant / Doctor" in html
    assert "Dr. Meera Krishnan" in html
    assert "Department / Specialty" in html
    assert "Cardiology &amp; Electrophysiology" in html
    assert "Appointment Date" in html
    assert "2026-11-18" in html
    assert "Appointment Time" in html
    assert "10:30 AM" in html
    assert "Appointment Reference" in html
    assert "AYU-2026-9F3C1A" in html
    assert "Consultation Mode" in html
    assert "In-Person Hospital Visit" in html

    # OTP section
    assert "YOUR SECURE APPOINTMENT VERIFICATION CODE" in html
    assert "739204" in html
    assert "5 minutes" in html
    assert EmailService.mask_email("patient.test@gmail.com") in html

    # Security notice (all 4 bullets)
    assert "Clinical Security Notice" in html
    assert "This code is for the displayed appointment verification only." in html
    assert "Never share your verification code." in html
    assert "If you did not request this verification, contact the hospital." in html
    assert "Verification does not replace clinical appointment confirmation." in html

    # Footer
    assert "COGNISEC-AI Zero-Trust Healthcare Security" in html
    assert "Automated notification &mdash; please do not reply." in html

    # Plain-text parity
    assert "739204" in text
    assert "Aarav Sharma" in text
    assert "Dr. Meera Krishnan" in text
    assert "AYU-2026-9F3C1A" in text
    assert "In-Person Hospital Visit" in text


def test_healthcare_appointment_otp_email_optional_fields_omitted_cleanly():
    ok, _, captured = _render_appointment_email(
        appointment_reference=None,
        consultation_mode=None,
    )
    assert ok is True
    html = captured["html_text"]
    assert "Appointment Reference" not in html
    assert "Consultation Mode" not in html


def test_healthcare_appointment_otp_email_security_and_isolation():
    ok, _, captured = _render_appointment_email(
        patient_name="<script>alert(1)</script> Patient",
        doctor_name="Dr. <b>Test</b>",
    )
    assert ok is True
    html = captured["html_text"]

    assert "<script" not in html.lower()
    assert "<img" not in html.lower()
    assert "@import" not in html.lower()
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "Dr. &lt;b&gt;Test&lt;/b&gt;" in html

    # No Shopping / Nyraa or College branding
    assert "NYRAA" not in html
    assert "Aura Luxe" not in html
    assert "BITS Pilani" not in html


def test_other_portal_email_templates_remain_intact():
    assert hasattr(EmailService, "send_otp_email")
    assert hasattr(EmailService, "send_payment_otp_email")
    assert hasattr(EmailService, "send_exam_otp_email")
    assert hasattr(EmailService, "send_recovery_otp_email")

