import re
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.security import create_access_token, get_password_hash
from app.models.otp_challenge import OTPChallenge
from app.models.session import Session as DbSession
from app.models.user import User
from app.services.email_service import EmailService
from app.services.session_service import SessionService
from app.services.step_up_service import StepUpService


def _create_college_session(db: Session):
    uid = uuid.uuid4().hex[:8]
    email = f"student_{uid}@gmail.com"
    user = User(
        name=f"BITS Student {uid}",
        email=email,
        password_hash=get_password_hash("ExamPass2026!"),
        role="USER",
        account_status="ACTIVE",
        failed_login_attempts=0,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    sess = DbSession(
        id=f"sess_{uuid.uuid4().hex[:12]}",
        user_id=user.id,
        application="college",
        ip_address="127.0.0.1",
        status="ACTIVE",
        current_risk_level="LOW",
    )
    db.add(sess)
    db.commit()
    db.refresh(sess)

    token = create_access_token(subject=user.id, role=user.role, session_id=sess.id)

    SessionService.record_application_grant(
        db,
        session_id=sess.id,
        user_id=user.id,
        application="college",
        resource="college_portal_access",
        factor="EMAIL_OTP",
        validity_minutes=15,
    )
    return user, sess, {"Authorization": f"Bearer {token}"}


def test_exam_otp_email_template_structure_and_security():
    captured = {}

    def fake_send_email(**kwargs):
        captured.update(kwargs)
        return True, "250 OK"

    orig_exam_send = EmailService._original_send_exam
    with patch.object(EmailService, "send_email", side_effect=fake_send_email):
        ok, msg = orig_exam_send(
            recipient_email="boomikaram35@gmail.com",
            otp_code="482913",
            course_name="CS F301 • End-Semester Proctored Assessment",
            expires_in_minutes=5,
            challenge_id="exam_test_001",
        )

    assert ok is True
    assert msg == "250 OK"
    assert captured["correlation_id"] == "exam_test_001"
    assert captured["subject"] == "BITS Pilani Academic Portal — Examination Access Authorization Code"

    html_body = captured["html_text"]
    plain_body = captured["plain_text"]

    # Header & branding
    assert "BITS Pilani Academic Portal" in html_body
    assert "COGNISEC-AI Zero-Trust Security" in html_body
    assert "EXAMINATION ACCESS AUTHORIZATION" in html_body

    # Main content
    assert "Verify Your Identity to Launch Your Examination" in html_body
    assert (
        "A secure examination launch request has been initiated for your academic account. "
        "Enter the verification code below to authorize examination access."
    ) in html_body

    # Examination details card (parsed backend values, masked email)
    assert "End-Semester Proctored Assessment" in html_body
    assert "CS F301" in html_body
    assert "Examination Launch Authorization" in html_body
    assert EmailService.mask_email("boomikaram35@gmail.com") in html_body
    assert "boomikaram35@gmail.com" not in html_body

    # OTP section (high-contrast dark background, restrained orange accent, spaced digits, expiry)
    assert "YOUR EXAMINATION VERIFICATION CODE" in html_body
    assert "482913" in html_body
    assert "5 minutes" in html_body
    assert "#f59e0b" in html_body
    assert "#050914" in html_body
    assert "#60a5fa" in html_body

    # Security notices & footer
    assert "Valid only for the current examination authorization request." in html_body
    assert "Never share this code with another person." in html_body
    assert "If you did not initiate this request, contact the appropriate administrator." in html_body
    assert "Secured by COGNISEC-AI Zero-Trust Authentication" in html_body
    assert "Automated security notification; do not reply." in html_body

    # Strict email-client safety & no generic login copy
    assert "<script" not in html_body.lower()
    assert "<img" not in html_body.lower()
    assert "@import" not in html_body.lower()
    assert "animation:" not in html_body.lower()
    assert "Login Verification Code" not in html_body
    assert "Zero-Trust Identity Verification" not in html_body

    # Plain text parity
    assert "EXAMINATION ACCESS AUTHORIZATION" in plain_body
    assert "482913" in plain_body
    assert "CS F301" in plain_body
    assert "End-Semester Proctored Assessment" in plain_body
    assert "5 minutes" in plain_body


def test_exam_otp_email_template_escapes_html_and_handles_single_course_name():
    captured = {}

    def fake_send_email(**kwargs):
        captured.update(kwargs)
        return True, "250 OK"

    orig_exam_send = EmailService._original_send_exam
    with patch.object(EmailService, "send_email", side_effect=fake_send_email):
        ok, _ = orig_exam_send(
            recipient_email="student@gmail.com",
            otp_code="731905",
            course_name="<script>alert(1)</script> Algorithms Final",
            expires_in_minutes=1,
            challenge_id="exam_xss_001",
        )

    assert ok is True
    html_body = captured["html_text"]
    assert "<script>alert(1)</script>" not in html_body
    assert "&lt;script&gt;alert(1)&lt;/script&gt; Algorithms Final" in html_body
    assert "1 minute" in html_body
    assert "1 minutes" not in html_body


def test_exam_otp_request_and_resend_dispatch_exam_template_and_authorize_launch(
    client: TestClient, db_session: Session
):
    StepUpService.reset()
    user, sess, headers = _create_college_session(db_session)
    dispatched = []

    def spy_exam_email(
        recipient_email,
        otp_code,
        course_name=None,
        assessment_name=None,
        expires_in_minutes=5,
        challenge_id=None,
        **kwargs,
    ):
        dispatched.append(
            {
                "recipient_email": recipient_email,
                "otp_code": otp_code,
                "course_name": course_name,
                "expires_in_minutes": expires_in_minutes,
                "challenge_id": challenge_id,
            }
        )
        return True, f"Accepted by Gmail SMTP for {EmailService.mask_email(recipient_email)}"

    with patch.object(EmailService, "send_exam_otp_email", side_effect=spy_exam_email), patch.object(
        EmailService, "send_otp_email", side_effect=AssertionError("Generic login OTP template must not be used for exam OTP")
    ):
        req_res = client.post(
            "/api/security/exam-otp/request",
            json={"session_id": sess.id, "course_name": "CS F363 • Compiler Construction Mid-Term"},
            headers=headers,
        )
        assert req_res.status_code == 200
        req_data = req_res.json()
        assert req_data["challenge_type"] == "COLLEGE_EXAM_OTP"
        assert len(dispatched) == 1
        assert dispatched[0]["course_name"] == "CS F363 • Compiler Construction Mid-Term"
        assert re.fullmatch(r"\d{6}", dispatched[0]["otp_code"])

        db_chal = db_session.query(OTPChallenge).filter(OTPChallenge.challenge_id == req_data["challenge_id"]).first()
        if db_chal is not None:
            db_chal.cooldown_until = datetime.now(timezone.utc) - timedelta(seconds=5)
            db_session.commit()
        if f"exam:{sess.id}" in StepUpService._challenges:
            StepUpService._challenges[f"exam:{sess.id}"]["cooldown_until"] = datetime.now(timezone.utc) - timedelta(seconds=5)

        resend_res = client.post(
            "/api/security/exam-otp/resend",
            json={"session_id": sess.id, "course_name": "CS F363 • Compiler Construction Mid-Term"},
            headers=headers,
        )
        assert resend_res.status_code == 200
        resend_data = resend_res.json()
        assert len(dispatched) == 2
        latest_otp = dispatched[-1]["otp_code"]

        ver_res = client.post(
            "/api/security/exam-otp/verify",
            json={
                "session_id": sess.id,
                "challenge_id": resend_data["challenge_id"],
                "otp": latest_otp,
            },
            headers=headers,
        )
        assert ver_res.status_code == 200
        assert ver_res.json()["verified"] is True

        exam_sess = client.get(
            f"/api/security/exam-session?session_id={sess.id}&course_name=CS%20F363%20%E2%80%A2%20Compiler%20Construction%20Mid-Term",
            headers=headers,
        )
        assert exam_sess.status_code == 200
        assert exam_sess.json()["authorized"] is True


def test_other_email_templates_remain_untouched():
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
    assert "EXAMINATION ACCESS AUTHORIZATION" not in captured["html_text"]
