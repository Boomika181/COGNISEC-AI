import re
import uuid
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.security import create_access_token, get_password_hash
from app.models.portal_lock import PortalSecurityLock
from app.models.user import User
from app.services.email_service import EmailService
from app.services.portal_lock_service import PortalLockService
from app.services.step_up_service import StepUpService


PORTAL_CASES = [
    ("college", "BITS Pilani Academic Portal", ["Aura Luxe Retail", "Apollo MedVigil EHR"]),
    ("shopping", "Aura Luxe Retail", ["BITS Pilani Academic Portal", "Apollo MedVigil EHR"]),
    ("healthcare", "Apollo MedVigil EHR", ["BITS Pilani Academic Portal", "Aura Luxe Retail"]),
]


@pytest.mark.parametrize("portal_key,expected_brand,forbidden_brands", PORTAL_CASES)
def test_recovery_otp_email_template_all_three_portals(portal_key, expected_brand, forbidden_brands):
    captured = {}

    def fake_send_email(**kwargs):
        captured.update(kwargs)
        return True, "250 OK"

    ref_id = f"SEC-LOCK-{portal_key.upper()}-918273"
    ts = "2026-11-12 08:45:00 UTC"

    with patch.object(EmailService, "send_email", side_effect=fake_send_email):
        ok, msg = EmailService._original_send_recovery(
            recipient_email="boomikaram35@gmail.com",
            otp_code="649201",
            portal=portal_key,
            security_reference_id=ref_id,
            request_timestamp=ts,
            expires_in_minutes=5,
            challenge_id=f"recov_{portal_key}_001",
        )

    assert ok is True
    assert msg == "250 OK"
    assert captured["correlation_id"] == f"recov_{portal_key}_001"
    assert expected_brand in captured["subject"]

    html_body = captured["html_text"]
    plain_body = captured["plain_text"]

    # Header
    assert "COGNISEC-AI" in html_body
    assert "ZERO-TRUST SECURITY RECOVERY" in html_body
    assert "PORTAL ACCESS RECOVERY" in html_body

    # Main heading & supporting text
    assert "Verify Your Identity to Continue Portal Recovery" in html_body
    assert (
        "A security restriction has been placed on your portal following unsuccessful identity verification attempts. "
        "Complete the registered-email verification step to continue the authorized recovery process."
    ) in html_body

    # Portal identification card
    assert expected_brand in html_body
    for other_brand in forbidden_brands:
        assert other_brand not in html_body
        assert other_brand not in plain_body
    assert "Suspended Portal Identity Verification" in html_body
    assert ref_id in html_body
    assert "12 November 2026, 2:15 PM IST" in html_body
    assert EmailService.mask_email("boomikaram35@gmail.com") in html_body
    assert "boomikaram35@gmail.com" not in html_body

    # OTP section
    assert "YOUR PORTAL RECOVERY CODE" in html_body
    assert "649201" in html_body
    assert "5 minutes" in html_body

    # Mandatory pending admin/SOC clearance notice
    assert "Email verification does not automatically restore suspended portal access." in html_body
    assert (
        "After successful OTP verification, your recovery request will remain pending until the required "
        "authorized Security Administrator/SOC clearance is completed."
    ) in html_body

    # Security notice & footer
    assert "This code is valid only for the current recovery request." in html_body
    assert "Never share this code with anyone." in html_body
    assert "If you did not request recovery, contact your security administrator." in html_body
    assert "The suspended portal remains protected until authorized clearance." in html_body
    assert "COGNISEC-AI Zero-Trust Security" in html_body
    assert "Automated security notification." in html_body
    assert "Do not reply to this email." in html_body

    # Strict email-client safety & no generic login wording
    assert "<script" not in html_body.lower()
    assert "<img" not in html_body.lower()
    assert "@import" not in html_body.lower()
    assert "Login Verification Code" not in html_body

    # Plain-text parity
    assert expected_brand in plain_body
    assert ref_id in plain_body
    assert "649201" in plain_body
    assert "Email verification does not automatically restore suspended portal access." in plain_body


def test_recovery_otp_email_escapes_html_and_singular_minute():
    captured = {}

    def fake_send_email(**kwargs):
        captured.update(kwargs)
        return True, "250 OK"

    with patch.object(EmailService, "send_email", side_effect=fake_send_email):
        ok, _ = EmailService._original_send_recovery(
            recipient_email="user@gmail.com",
            otp_code="102938",
            portal="shopping",
            security_reference_id="<script>alert(1)</script>REF",
            request_timestamp="2026-11-12 09:00:00 UTC",
            expires_in_minutes=1,
            challenge_id="recov_xss_001",
        )

    assert ok is True
    html_body = captured["html_text"]
    assert "<script>alert(1)</script>" not in html_body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;REF" in html_body
    assert "1 minute" in html_body
    assert "1 minutes" not in html_body


@pytest.mark.parametrize("portal_key,expected_brand,forbidden_brands", PORTAL_CASES)
def test_recovery_otp_endpoint_uses_recovery_template_and_keeps_portal_locked_after_verify(
    client: TestClient, db_session: Session, portal_key, expected_brand, forbidden_brands
):
    StepUpService.reset()
    uid = uuid.uuid4().hex[:8]
    user = User(
        name=f"Recovery Test {uid}",
        email=f"recov_{portal_key}_{uid}@gmail.com",
        password_hash=get_password_hash("RecovPass2026!"),
        role="USER",
        account_status="ACTIVE",
        failed_login_attempts=0,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    lock = PortalLockService.lock_portal(
        db_session,
        user_id=user.id,
        application=portal_key,
        verification_purpose="LOGIN_OTP",
        lock_reason="Exceeded maximum login OTP verification attempts",
        failed_attempt_count=3,
        max_attempts=3,
    )
    token = create_access_token(subject=user.id, role=user.role, session_id=None)
    headers = {"Authorization": f"Bearer {token}"}

    dispatched = []

    def spy_recovery_email(
        recipient_email,
        otp_code,
        portal,
        security_reference_id,
        request_timestamp=None,
        expires_in_minutes=5,
        challenge_id=None,
        **kwargs,
    ):
        dispatched.append(
            {
                "recipient_email": recipient_email,
                "otp_code": otp_code,
                "portal": portal,
                "security_reference_id": security_reference_id,
                "request_timestamp": request_timestamp,
                "expires_in_minutes": expires_in_minutes,
                "challenge_id": challenge_id,
            }
        )
        return True, f"Accepted by Gmail SMTP for {EmailService.mask_email(recipient_email)}"

    with patch.object(EmailService, "send_recovery_otp_email", side_effect=spy_recovery_email), patch.object(
        EmailService,
        "send_otp_email",
        side_effect=AssertionError("Generic login OTP template must not be used for portal recovery"),
    ):
        req_res = client.post(
            "/api/security/portal-lock/recovery-otp/request",
            json={"application": portal_key, "security_reference_id": lock.security_reference_id},
            headers=headers,
        )
        assert req_res.status_code == 200
        req_data = req_res.json()
        assert len(dispatched) == 1
        assert dispatched[0]["portal"] == portal_key
        assert dispatched[0]["security_reference_id"] == lock.security_reference_id
        assert re.fullmatch(r"\d{6}", dispatched[0]["otp_code"])

    verify_res = client.post(
        "/api/security/portal-lock/recovery-otp/verify",
        json={
            "application": portal_key,
            "challenge_id": req_data["challenge_id"],
            "otp_code": dispatched[0]["otp_code"],
            "security_reference_id": lock.security_reference_id,
        },
        headers=headers,
    )
    assert verify_res.status_code == 200, verify_res.text
    vdata = verify_res.json()
    assert vdata["otp_verified"] is True
    assert vdata["recovery_status"] == "OTP_VERIFIED_AWAITING_ADMIN"

    # Confirm portal remains LOCKED / pending SOC clearance after OTP verification
    db_session.expire_all()
    refreshed_lock = (
        db_session.query(PortalSecurityLock)
        .filter(PortalSecurityLock.id == lock.id)
        .first()
    )
    assert refreshed_lock is not None
    assert refreshed_lock.unlocked_at is None
    assert refreshed_lock.recovery_otp_verified_at is not None
    assert PortalLockService.get_active_lock(db_session, user.id, portal_key) is not None


def test_login_and_exam_email_templates_remain_unchanged():
    captured = {}

    def fake_send_email(**kwargs):
        captured.update(kwargs)
        return True, "250 OK"

    with patch.object(EmailService, "send_email", side_effect=fake_send_email):
        EmailService._original_send_otp(
            recipient_email="user@gmail.com",
            otp_code="111222",
            expires_in_minutes=5,
            challenge_id="login_001",
        )
    assert captured["subject"] == "CogniSec AI - Login Verification Code"
    assert "PORTAL ACCESS RECOVERY" not in captured["html_text"]

    captured.clear()
    with patch.object(EmailService, "send_email", side_effect=fake_send_email):
        EmailService._original_send_exam(
            recipient_email="user@gmail.com",
            otp_code="333444",
            course_name="CS F301 • End-Semester Proctored Assessment",
            expires_in_minutes=5,
            challenge_id="exam_001",
        )
    assert captured["subject"] == "BITS Pilani Academic Portal — Examination Access Authorization Code"
    assert "EXAMINATION ACCESS AUTHORIZATION" in captured["html_text"]
    assert "PORTAL ACCESS RECOVERY" not in captured["html_text"]
