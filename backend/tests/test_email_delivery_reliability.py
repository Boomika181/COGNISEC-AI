"""
Comprehensive Automated Verification Suite:
Real-Time Email OTP Delivery, Distinct Delivery States, Bounded Retries,
Correlation Idempotency, Diagnostics Secret Safety, and All Email Workflows.
"""

import smtplib
import socket
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.rate_limit import rate_limiter
from app.core.security import create_access_token, get_password_hash
from app.models.portal_lock import PortalSecurityLock
from app.models.session import Session as DbSession
from app.models.user import User
from app.services.email_service import EmailService
from app.services.step_up_service import StepUpService


@pytest.fixture(autouse=True)
def reset_state():
    StepUpService.reset()
    rate_limiter.reset()
    with EmailService._delivery_lock:
        EmailService._delivery_cache.clear()
        EmailService._last_delivery_by_thread.clear()
    yield


def _create_user_and_session(db: Session, application: str = "platform", email: str = None):
    uid = uuid.uuid4().hex[:8]
    user = User(
        name=f"Email Test {uid}",
        email=email or f"email.test.{uid}@gmail.com",
        password_hash=get_password_hash("EmailPass!2026"),
        role="USER",
        account_status="ACTIVE",
        created_at=datetime.now(timezone.utc),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    sess = DbSession(
        id=f"sess_mail_{uid}",
        user_id=user.id,
        application=application,
        status="ACTIVE",
        login_time=datetime.now(timezone.utc),
        ip_address="127.0.0.1",
    )
    db.add(sess)
    db.commit()
    token = create_access_token(user.id, user.role, session_id=sess.id)
    return user, sess, {"Authorization": f"Bearer {token}"}


def test_email_service_distinct_states_and_diagnostics_secret_safety():
    with patch.object(settings, "SMTP_ENABLED", True), \
         patch.object(settings, "SMTP_HOST", "smtp.gmail.com"), \
         patch.object(settings, "SMTP_USER", ""), \
         patch.object(settings, "SMTP_PASSWORD", "super-secret-app-pw"), \
         patch.object(settings, "SMTP_FROM", "cognisecai.security@gmail.com"), \
         patch.object(settings, "EXHIBITION_MODE", False):
        diag = EmailService.get_diagnostics()
        assert diag["delivery_status"] == "INCOMPLETE_CONFIGURATION"
        assert "SMTP_USER" in diag["missing_variables"]
        assert "super-secret-app-pw" not in str(diag)

        res = EmailService.send_email_with_status(
            recipient_email="recipient@gmail.com",
            subject="Test Missing User",
            plain_text="Code 123456",
        )
        assert res["success"] is False
        assert res["delivery_status"] == EmailService.DELIVERY_STATE_FAILED
        assert "SMTP_USER" in res["message"]
        assert "super-secret-app-pw" not in res["message"]


def test_transient_smtp_failure_retries_with_backoff_and_succeeds():
    mock_server = MagicMock()
    attempts = {"count": 0}

    def _smtp_factory(*args, **kwargs):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise smtplib.SMTPConnectError(421, b"4.3.2 Temporary server busy")
        return mock_server

    with patch.object(settings, "SMTP_ENABLED", True), \
         patch.object(settings, "SMTP_HOST", "smtp.gmail.com"), \
         patch.object(settings, "SMTP_USER", "cognisecai.security@gmail.com"), \
         patch.object(settings, "SMTP_PASSWORD", "test-pass"), \
         patch.object(settings, "SMTP_FROM", "cognisecai.security@gmail.com"), \
         patch.object(settings, "ENVIRONMENT", "test"), \
         patch("smtplib.SMTP", side_effect=_smtp_factory):
        res = EmailService.send_email_with_status(
            recipient_email="realuser@gmail.com",
            subject="CogniSec AI - Login Verification Code",
            plain_text="OTP 654321",
            correlation_id="corr_retry_001",
            max_retries=2,
        )

    assert res["success"] is True
    assert res["delivery_status"] == EmailService.DELIVERY_STATE_SMTP_ACCEPTED
    assert res["delivery_status"] != EmailService.DELIVERY_STATE_DELIVERY_CONFIRMED
    assert res["attempts"] == 2
    assert "submitted to the mail server" in res["message"].lower()


def test_permanent_auth_failure_does_not_retry():
    mock_server = MagicMock()
    mock_server.login.side_effect = smtplib.SMTPAuthenticationError(535, b"5.7.8 Bad credentials")

    with patch.object(settings, "SMTP_ENABLED", True), \
         patch.object(settings, "SMTP_HOST", "smtp.gmail.com"), \
         patch.object(settings, "SMTP_USER", "cognisecai.security@gmail.com"), \
         patch.object(settings, "SMTP_PASSWORD", "bad-pass"), \
         patch.object(settings, "SMTP_FROM", "cognisecai.security@gmail.com"), \
         patch.object(settings, "ENVIRONMENT", "test"), \
         patch("smtplib.SMTP", return_value=mock_server) as mock_smtp:
        res = EmailService.send_email_with_status(
            recipient_email="realuser@gmail.com",
            subject="Auth Fail Test",
            plain_text="Test",
            correlation_id="corr_perm_535",
            max_retries=2,
        )

    assert res["success"] is False
    assert res["delivery_status"] == EmailService.DELIVERY_STATE_FAILED
    assert res["attempts"] == 1
    assert mock_smtp.call_count == 1


def test_correlation_idempotency_prevents_duplicate_send():
    mock_server = MagicMock()
    with patch.object(settings, "SMTP_ENABLED", True), \
         patch.object(settings, "SMTP_HOST", "smtp.gmail.com"), \
         patch.object(settings, "SMTP_USER", "cognisecai.security@gmail.com"), \
         patch.object(settings, "SMTP_PASSWORD", "test-pass"), \
         patch.object(settings, "SMTP_FROM", "cognisecai.security@gmail.com"), \
         patch("smtplib.SMTP", return_value=mock_server):
        first = EmailService.send_email_with_status(
            recipient_email="realuser@gmail.com",
            subject="CogniSec AI - Login Verification Code",
            plain_text="OTP 112233",
            correlation_id="chal_dedup_abc",
        )
        second = EmailService.send_email_with_status(
            recipient_email="realuser@gmail.com",
            subject="CogniSec AI - Login Verification Code",
            plain_text="OTP 112233",
            correlation_id="chal_dedup_abc",
        )

    assert first["success"] is True
    assert first["delivery_status"] == EmailService.DELIVERY_STATE_SMTP_ACCEPTED
    assert second["success"] is True
    assert second.get("deduplicated") is True
    assert mock_server.sendmail.call_count == 1


@pytest.mark.parametrize("portal", ["platform", "shopping", "college", "healthcare"])
def test_login_otp_and_recovery_otp_report_smtp_accepted_to_registered_email(
    client: TestClient, db_session: Session, portal: str
):
    user, sess, headers = _create_user_and_session(db_session, application=portal)
    sess.status = "PENDING_OTP"
    db_session.commit()

    with patch.object(settings, "ENVIRONMENT", "production"), \
         patch.object(settings, "EXHIBITION_MODE", False), \
         patch.object(settings, "SMTP_ENABLED", True), \
         patch.object(settings, "SMTP_HOST", "smtp.gmail.com"), \
         patch.object(settings, "SMTP_USER", "cognisecai.security@gmail.com"), \
         patch.object(settings, "SMTP_PASSWORD", "test-pass"), \
         patch.object(settings, "SMTP_FROM", "cognisecai.security@gmail.com"), \
         patch("smtplib.SMTP", return_value=MagicMock()):
        out = StepUpService.create_login_otp_challenge(session_id=sess.id, user_id=user.id, db=db_session)

    assert out["delivery_status"] == "SMTP_ACCEPTED"
    assert out["otp"] == ""
    assert "submitted to the mail server" in out["message"].lower()
    assert "gmail smtp" not in out["message"].lower()


def test_password_reset_create_and_resend_report_smtp_accepted(client: TestClient, db_session: Session):
    user, _, _ = _create_user_and_session(db_session, application="platform")
    with patch.object(settings, "ENVIRONMENT", "production"), \
         patch.object(settings, "EXHIBITION_MODE", False), \
         patch.object(settings, "SMTP_ENABLED", True), \
         patch.object(settings, "SMTP_HOST", "smtp.gmail.com"), \
         patch.object(settings, "SMTP_USER", "cognisecai.security@gmail.com"), \
         patch.object(settings, "SMTP_PASSWORD", "test-pass"), \
         patch.object(settings, "SMTP_FROM", "cognisecai.security@gmail.com"), \
         patch("smtplib.SMTP", return_value=MagicMock()):
        ok, msg, masked, delivered, ds, ret_otp = StepUpService.create_password_reset_challenge(
            email=user.email, db=db_session
        )
    assert ok is True
    assert delivered is True
    assert ds == "SMTP_ACCEPTED"
    assert ret_otp is None
    assert "submitted to the mail server" in msg.lower()

