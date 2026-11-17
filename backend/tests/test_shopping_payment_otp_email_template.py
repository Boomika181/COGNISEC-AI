"""Tests for the NYRAA Shopping portal payment authorization OTP email template."""

from unittest.mock import patch

from app.services.email_service import EmailService


def _render_payment_email(
    recipient_email: str = "buyer@gmail.com",
    otp_code: str = "482910",
    order_id: str = "ORD-NYR-88412",
    amount: float = 12499.00,
    item_summary: str = "1x Nyraa Silk Evening Midi Dress",
    expires_in_minutes: int = 5,
    challenge_id: str = "pay_chal_001",
):
    captured = {}

    def fake_send_email(*args, **kwargs):
        captured.update(kwargs)
        return True, "SMTP_ACCEPTED"

    fn = getattr(EmailService, "_original_send_pay", EmailService.send_payment_otp_email)
    with patch.object(EmailService, "send_email", side_effect=fake_send_email):
        ok, msg = fn(
            recipient_email=recipient_email,
            otp_code=otp_code,
            order_id=order_id,
            amount=amount,
            item_summary=item_summary,
            expires_in_minutes=expires_in_minutes,
            challenge_id=challenge_id,
        )
    return ok, msg, captured


def test_shopping_payment_otp_email_branding_and_content():
    ok, msg, captured = _render_payment_email()
    assert ok is True
    assert msg == "SMTP_ACCEPTED"
    assert captured["recipient_email"] == "buyer@gmail.com"
    assert captured["correlation_id"] == "pay_chal_001"
    assert captured["subject"] == "NYRAA — Payment Authorization Code for Order ORD-NYR-88412"

    html = captured["html_text"]
    text = captured["plain_text"]

    # Branding & theme
    assert "NYRAA" in html
    assert "RETAIL" in html
    assert "Aura Luxe Retail" in html
    assert "COGNISEC-AI Zero-Trust Checkout" in html
    assert "Secure Your Purchase" in html
    assert "Your payment authorization code is ready. Verify this transaction to securely complete your purchase." in html

    # Warm white, charcoal black, orange palette
    assert "#f6f2eb" in html
    assert "#1c1917" in html
    assert "#ea580c" in html

    # Order summary fields
    assert "Order Summary" in html
    assert "Product" in html
    assert "Nyraa Silk Evening Midi Dress" in html
    assert "Order Reference" in html
    assert "ORD-NYR-88412" in html
    assert "Quantity" in html
    assert "Currency" in html
    assert "INR" in html
    assert "Total Amount" in html
    assert "12,499.00" in html

    # OTP focal block & metadata
    assert "PAYMENT AUTHORIZATION CODE" in html
    assert "482910" in html
    assert "5 minutes" in html
    assert EmailService.mask_email("buyer@gmail.com") in html

    # Checkout Security Notice (all 4 bullets)
    assert "Checkout Security Notice" in html
    assert "This code authorizes the displayed payment transaction only." in html
    assert "Never share the code." in html
    assert "If the transaction was not initiated by the account owner, do not authorize it." in html
    assert "Contact customer support if the transaction is unfamiliar." in html

    # Footer
    assert "NYRAA Retail" in html
    assert "Secured by COGNISEC-AI" in html
    assert "Automated notification; do not reply." in html

    # Plain text parity
    assert "482910" in text
    assert "ORD-NYR-88412" in text
    assert "12,499.00" in text
    assert "NYRAA" in text
    assert "COGNISEC-AI Zero-Trust Checkout" in text


def test_shopping_payment_otp_email_security_and_isolation():
    ok, _, captured = _render_payment_email(
        item_summary="2x <script>alert(1)</script> Silk Scarf",
        order_id="ORD-<bad>",
    )
    assert ok is True
    html = captured["html_text"]

    # No scripts, images, or external font imports
    assert "<script" not in html.lower()
    assert "<img" not in html.lower()
    assert "@import" not in html.lower()
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "ORD-&lt;bad&gt;" in html

    # No College or Healthcare branding leakage
    assert "BITS Pilani" not in html
    assert "Apollo MedVigil" not in html
    assert "EXAMINATION ACCESS AUTHORIZATION" not in html


def test_other_email_templates_remain_intact():
    assert hasattr(EmailService, "send_otp_email")
    assert hasattr(EmailService, "send_exam_otp_email")
    assert hasattr(EmailService, "send_recovery_otp_email")
    assert hasattr(EmailService, "send_appointment_otp_email")
