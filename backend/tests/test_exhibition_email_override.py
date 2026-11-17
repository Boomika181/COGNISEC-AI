import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import settings
from app.services.email_service import EmailService
from app.models.user import User
from app.core.security import get_password_hash, create_access_token
from app.models.session import Session as DbSession
from datetime import datetime, timezone


# ==============================================================================
# SCENARIO A: Production + Override Disabled
# Email goes strictly to the actual registered address.
# ==============================================================================
def test_scenario_a_production_override_disabled():
    with patch.object(settings, "ENVIRONMENT", "production"), \
         patch.object(settings, "EXHIBITION_MODE", False), \
         patch.object(settings, "EXHIBITION_DEMO_MAILBOX_OVERRIDE", False), \
         patch.object(settings, "DEMO_OTP_RECIPIENT_EMAIL", "boomikaram35@gmail.com"):

        is_active, dest = EmailService.is_demo_mailbox_override_active()
        assert is_active is False
        assert dest is None

        # Synthetic demo accounts resolve to their actual registered addresses
        assert EmailService.resolve_delivery_recipient("student.alex@veritas.edu") == "student.alex@veritas.edu"
        assert EmailService.resolve_delivery_recipient("customer.jane@auraluxe.com") == "customer.jane@auraluxe.com"
        assert EmailService.resolve_delivery_recipient("dr.sarah@aetheriahealth.org") == "dr.sarah@aetheriahealth.org"
        assert EmailService.resolve_delivery_recipient("user.portal@cognisec.ai") == "user.portal@cognisec.ai"
        # Real user addresses resolve to themselves
        assert EmailService.resolve_delivery_recipient("real.user@gmail.com") == "real.user@gmail.com"


# ==============================================================================
# SCENARIO B: Production + Override Enabled
# Override is strictly rejected and remains inactive; email goes to actual address.
# ==============================================================================
def test_scenario_b_production_override_enabled_is_rejected():
    with patch.object(settings, "ENVIRONMENT", "production"), \
         patch.object(settings, "EXHIBITION_MODE", True), \
         patch.object(settings, "EXHIBITION_DEMO_MAILBOX_OVERRIDE", True), \
         patch.object(settings, "DEMO_OTP_RECIPIENT_EMAIL", "boomikaram35@gmail.com"):

        is_active, dest = EmailService.is_demo_mailbox_override_active()
        assert is_active is False
        assert dest is None

        # In production, even with override requested, synthetic accounts NEVER redirect
        assert EmailService.resolve_delivery_recipient("student.alex@veritas.edu") == "student.alex@veritas.edu"
        assert EmailService.resolve_delivery_recipient("customer.jane@auraluxe.com") == "customer.jane@auraluxe.com"
        assert EmailService.resolve_delivery_recipient("recovery.user@cognisec.ai") == "recovery.user@cognisec.ai"
        assert EmailService.resolve_delivery_recipient("alice@example.com") == "alice@example.com"


# ==============================================================================
# SCENARIO C: Approved Exhibition Mode + Override Disabled
# Normal registered-email delivery.
# ==============================================================================
def test_scenario_c_approved_exhibition_mode_override_disabled():
    with patch.object(settings, "ENVIRONMENT", "development"), \
         patch.object(settings, "EXHIBITION_MODE", True), \
         patch.object(settings, "EXHIBITION_DEMO_MAILBOX_OVERRIDE", False), \
         patch.object(settings, "DEMO_OTP_RECIPIENT_EMAIL", "boomikaram35@gmail.com"):

        is_active, dest = EmailService.is_demo_mailbox_override_active()
        assert is_active is False
        assert dest is None

        # With override disabled, addresses resolve to registered values
        assert EmailService.resolve_delivery_recipient("student.alex@veritas.edu") == "student.alex@veritas.edu"
        assert EmailService.resolve_delivery_recipient("dr.boomika@ayusync.med.in") == "dr.boomika@ayusync.med.in"
        assert EmailService.resolve_delivery_recipient("genuine.user@yahoo.com") == "genuine.user@yahoo.com"


# ==============================================================================
# SCENARIO D: Approved Exhibition Mode + Override Enabled
# Synthetic demonstration addresses are redirected to the configured demo mailbox.
# ==============================================================================
def test_scenario_d_approved_exhibition_mode_override_enabled():
    demo_mailbox = "boomikaram35@gmail.com"
    with patch.object(settings, "ENVIRONMENT", "development"), \
         patch.object(settings, "EXHIBITION_MODE", True), \
         patch.object(settings, "EXHIBITION_DEMO_MAILBOX_OVERRIDE", True), \
         patch.object(settings, "DEMO_OTP_RECIPIENT_EMAIL", demo_mailbox):

        is_active, dest = EmailService.is_demo_mailbox_override_active()
        assert is_active is True
        assert dest == demo_mailbox

        # Synthetic demonstration accounts redirect to configured demo mailbox
        assert EmailService.resolve_delivery_recipient("student.alex@veritas.edu") == demo_mailbox
        assert EmailService.resolve_delivery_recipient("customer.jane@auraluxe.com") == demo_mailbox
        assert EmailService.resolve_delivery_recipient("dr.sarah@aetheriahealth.org") == demo_mailbox
        assert EmailService.resolve_delivery_recipient("dr.boomika@ayusync.med.in") == demo_mailbox
        assert EmailService.resolve_delivery_recipient("user.portal@cognisec.ai") == demo_mailbox
        assert EmailService.resolve_delivery_recipient("boomika.ram@cognisec.ai") == demo_mailbox

        # Demo portal domains redirect
        assert EmailService.resolve_delivery_recipient("custom.student@veritas.edu") == demo_mailbox
        assert EmailService.resolve_delivery_recipient("shopper@auraluxe.com") == demo_mailbox
        assert EmailService.resolve_delivery_recipient("doctor@aetheriahealth.org") == demo_mailbox


# ==============================================================================
# SCENARIO E: Invalid Destination Configuration Fails Safely
# Configuration fails safely and falls back to original registered email.
# ==============================================================================
def test_scenario_e_invalid_destination_fails_safely():
    # Case 1: Syntactically invalid email string
    with patch.object(settings, "ENVIRONMENT", "development"), \
         patch.object(settings, "EXHIBITION_MODE", True), \
         patch.object(settings, "EXHIBITION_DEMO_MAILBOX_OVERRIDE", True), \
         patch.object(settings, "DEMO_OTP_RECIPIENT_EMAIL", "invalid-not-an-email"):

        is_active, dest = EmailService.is_demo_mailbox_override_active()
        assert is_active is False
        assert dest is None
        assert EmailService.resolve_delivery_recipient("student.alex@veritas.edu") == "student.alex@veritas.edu"

    # Case 2: Empty string
    with patch.object(settings, "ENVIRONMENT", "development"), \
         patch.object(settings, "EXHIBITION_MODE", True), \
         patch.object(settings, "EXHIBITION_DEMO_MAILBOX_OVERRIDE", True), \
         patch.object(settings, "DEMO_OTP_RECIPIENT_EMAIL", ""):

        is_active, dest = EmailService.is_demo_mailbox_override_active()
        assert is_active is False
        assert EmailService.resolve_delivery_recipient("student.alex@veritas.edu") == "student.alex@veritas.edu"

    # Case 3: None
    with patch.object(settings, "ENVIRONMENT", "development"), \
         patch.object(settings, "EXHIBITION_MODE", True), \
         patch.object(settings, "EXHIBITION_DEMO_MAILBOX_OVERRIDE", True), \
         patch.object(settings, "DEMO_OTP_RECIPIENT_EMAIL", None):

        is_active, dest = EmailService.is_demo_mailbox_override_active()
        assert is_active is False
        assert EmailService.resolve_delivery_recipient("student.alex@veritas.edu") == "student.alex@veritas.edu"


# ==============================================================================
# SCENARIO F: Real Registered Addresses Not Silently Redirected
# Authentic non-demo accounts are NEVER redirected even when override is active.
# ==============================================================================
def test_scenario_f_real_registered_addresses_never_redirected():
    demo_mailbox = "boomikaram35@gmail.com"
    with patch.object(settings, "ENVIRONMENT", "development"), \
         patch.object(settings, "EXHIBITION_MODE", True), \
         patch.object(settings, "EXHIBITION_DEMO_MAILBOX_OVERRIDE", True), \
         patch.object(settings, "DEMO_OTP_RECIPIENT_EMAIL", demo_mailbox):

        # Authentic registered email addresses from standard domains MUST NOT redirect
        real_addresses = [
            "jane.doe@gmail.com",
            "security.auditor@microsoft.com",
            "doctor.smith@mayo.org",
            "student.priya@iitb.ac.in",
            "corporate.exec@company.co.uk",
        ]

        for real_addr in real_addresses:
            resolved = EmailService.resolve_delivery_recipient(real_addr)
            assert resolved == real_addr, f"Real registered email '{real_addr}' was inappropriately redirected to '{resolved}'"


# ==============================================================================
# DATABASE INTEGRITY: Registered User Email Never Mutated by Override
# ==============================================================================
def test_registered_user_email_never_modified_in_database(client: TestClient, db_session: Session):
    reg_email = "preserve.db.email@veritas.edu"
    user = User(
        email=reg_email,
        password_hash=get_password_hash("Password123!"),
        name="DB Preservation User",
        role="USER",
        account_status="ACTIVE",
        failed_login_attempts=0
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    captured = {}
    def mock_send(recipient_email, otp_code, **kwargs):
        captured["recipient"] = recipient_email
        captured["otp"] = otp_code
        return True, "Code delivered"

    demo_target = "boomikaram35@gmail.com"
    with patch.object(settings, "ENVIRONMENT", "development"), \
         patch.object(settings, "EXHIBITION_MODE", True), \
         patch.object(settings, "EXHIBITION_DEMO_MAILBOX_OVERRIDE", True), \
         patch.object(settings, "DEMO_OTP_RECIPIENT_EMAIL", demo_target), \
         patch.object(EmailService, "send_password_reset_email", side_effect=mock_send):

        res = client.post("/api/auth/password-reset/request", json={"email": reg_email})
        assert res.status_code == 200

        # Transport recipient was redirected to demo target
        assert captured["recipient"] == demo_target

        # CRITICAL ASSERTION: The user's registered email in the database is UNCHANGED
        db_user = db_session.query(User).filter(User.id == user.id).first()
        assert db_user.email == reg_email, "User account email in database was corrupted by delivery override!"


# ==============================================================================
# SECURITY DIAGNOSTICS & LOGGING INTEGRITY
# ==============================================================================
def test_email_service_diagnostics_exposes_override_status_safely():
    with patch.object(settings, "EXHIBITION_DEMO_MAILBOX_OVERRIDE", True), \
         patch.object(settings, "DEMO_OTP_RECIPIENT_EMAIL", "boomikaram35@gmail.com"), \
         patch.object(settings, "ENVIRONMENT", "development"):

        diag = EmailService.get_diagnostics()
        assert "exhibition_demo_override_enabled" in diag
        assert diag["exhibition_demo_override_enabled"] is True
        assert "demo_mailbox_override_active" in diag
        assert diag["demo_mailbox_override_active"] is True
        # Ensure SMTP passwords or secret keys are not leaked
        assert "smtp_password" not in diag or diag.get("smtp_password") is None
        assert "secret_key" not in diag
