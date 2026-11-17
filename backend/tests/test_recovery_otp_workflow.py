"""
Comprehensive Automated Verification Suite:
Portal Recovery OTP Workflow Across Shopping, College, and Healthcare.

Covers:
- Valid Recovery OTP across all 3 portals (active global session + logged-out/expired global session)
- Single-attempt Recovery Email OTP enforcement (LIMIT_RECOVERY_OTP == 1)
- Expired, replayed/reused, and superseded (resent) OTP rejection
- Strict binding (user_id, portal, security_reference_id) & purpose isolation (no interchange with login/exam/appointment/step-up OTPs)
- Recovery OTP marks OTP_VERIFIED_AWAITING_ADMIN while keeping PortalSecurityLock ACTIVE & re-entry blocked
- Non-weakening on failure & counter isolation
- Admin/SOC approval & explicit rejection (role check, self-approval block, audit + dual notifications, failure resilience)
- Cross-portal lock isolation & post-clearance fresh login -> 20s observation -> initial Email OTP
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.rate_limit import rate_limiter
from app.core.security import create_access_token, get_password_hash
from app.models.application_grant import ApplicationGrant
from app.models.otp_challenge import OTPChallenge
from app.models.portal_lock import PortalSecurityLock, VerificationAttemptCounter
from app.models.security_event import SecurityEvent
from app.models.session import Session as DbSession
from app.models.user import User
from app.services.email_service import EmailService
from app.services.portal_lock_service import PortalLockService
from app.services.step_up_service import StepUpService

PORTALS = ("shopping", "college", "healthcare")
PASS_USER = "RecoveryPass!2026"
PASS_ADMIN = "SocAdminPass!2026"


@pytest.fixture(autouse=True)
def reset_state():
    StepUpService.reset()
    rate_limiter.reset()
    yield
    StepUpService.reset()
    rate_limiter.reset()


def _ensure_user(db_session: Session, email: str, role: str = "USER", password: str = PASS_USER) -> User:
    u = db_session.query(User).filter(User.email == email).first()
    if not u:
        u = User(
            name="Recovery Verification User",
            email=email,
            password_hash=get_password_hash(password),
            role=role,
            account_status="ACTIVE",
            failed_login_attempts=0,
        )
        db_session.add(u)
        db_session.commit()
        db_session.refresh(u)
    return u


def _login_app(client: TestClient, email: str, password: str, application: str, fingerprint: str = "fp-recov-test"):
    return client.post(
        "/api/auth/login",
        json={
            "email": email,
            "password": password,
            "application": application,
            "device_fingerprint": fingerprint,
            "browser": "Chrome Test",
            "os": "macOS",
        },
    )


def _create_portal_lock_via_failed_login_otp(
    client: TestClient,
    db_session: Session,
    email: str,
    portal: str,
) -> dict:
    """Locks a portal using the real initial Login Email OTP single-attempt lockout path."""
    user = _ensure_user(db_session, email)
    res = _login_app(client, email, PASS_USER, portal, fingerprint=f"fp-{portal}")
    assert res.status_code == 200, res.text
    login_data = res.json()
    token = login_data["access_token"]
    sid = login_data["session_id"]

    sess = db_session.query(DbSession).filter(DbSession.id == sid).first()
    assert sess is not None
    sess.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=settings.OBSERVATION_WINDOW_SECONDS + 2)
    db_session.commit()

    with patch.object(EmailService, "send_otp_email", return_value=(True, "sent")):
        req_res = client.post(
            "/api/auth/login-otp/request",
            json={"session_id": sid},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert req_res.status_code == 200, req_res.text

    ver_res = client.post(
        "/api/auth/login-otp/verify",
        json={"session_id": sid, "otp_code": "000000"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert ver_res.status_code == 423, ver_res.text

    lock = PortalLockService.get_active_lock(db_session, user.id, portal)
    assert lock is not None
    assert lock.lock_status == "ACTIVE"
    return {
        "user": user,
        "lock": lock,
        "portal_token": token,
        "portal_sid": sid,
    }


@pytest.mark.parametrize("portal", PORTALS)
def test_01_valid_recovery_otp_all_portals_active_global_session(client: TestClient, db_session: Session, portal: str):
    """Valid Recovery OTP verification completes across Shopping, College, and Healthcare while global session is active."""
    email = f"recov_active_{portal}@example.com"
    ctx = _create_portal_lock_via_failed_login_otp(client, db_session, email, portal)
    lock = ctx["lock"]

    # Active global session on platform (central dashboard index.html)
    plat_res = _login_app(client, email, PASS_USER, "platform", fingerprint="fp-platform-global")
    assert plat_res.status_code == 200
    global_token = plat_res.json()["access_token"]

    sent_otps = []

    def _capture_email(recipient_email, otp_code, expires_in_minutes=5, challenge_id=None, **kwargs):
        sent_otps.append(otp_code)
        return (True, "captured")

    with patch.object(EmailService, "send_recovery_otp_email", side_effect=_capture_email), \
         patch.object(EmailService, "send_portal_security_notification", return_value=(True, "sent")):
        req_res = client.post(
            "/api/security/portal-lock/recovery-otp/request",
            json={"application": portal, "security_reference_id": lock.security_reference_id},
            headers={"Authorization": f"Bearer {global_token}"},
        )
        assert req_res.status_code == 200, req_res.text
        req_body = req_res.json()
        assert req_body["portal"] == portal
        assert req_body["security_reference_id"] == lock.security_reference_id
        assert len(sent_otps) == 1

        # Verify DB OTPChallenge persists hashed OTP and NEVER stores plaintext OTP
        db_chal = db_session.query(OTPChallenge).filter(OTPChallenge.challenge_id == req_body["challenge_id"]).first()
        assert db_chal is not None
        assert db_chal.purpose == "PORTAL_RECOVERY_OTP"
        assert db_chal.max_attempts == 1
        assert db_chal.is_consumed is False
        assert sent_otps[0] not in (db_chal.otp_hash or "")
        assert sent_otps[0] not in (db_chal.appointment_data or "")

        ver_res = client.post(
            "/api/security/portal-lock/recovery-otp/verify",
            json={
                "application": portal,
                "otp_code": sent_otps[0],
                "challenge_id": req_body["challenge_id"],
                "security_reference_id": lock.security_reference_id,
            },
            headers={"Authorization": f"Bearer {global_token}"},
        )
        assert ver_res.status_code == 200, ver_res.text
        ver_body = ver_res.json()
        assert ver_body["otp_verified"] is True
        assert ver_body["recovery_status"] == "OTP_VERIFIED_AWAITING_ADMIN"
        # Critical invariant: recovery OTP NEVER unlocks the portal
        assert ver_body["locked"] is True
        assert ver_body["lock_status"] == "ACTIVE"

    db_session.refresh(lock)
    assert lock.lock_status == "ACTIVE"
    assert lock.recovery_status == "OTP_VERIFIED_AWAITING_ADMIN"
    assert lock.recovery_otp_verified_at is not None


@pytest.mark.parametrize("portal", PORTALS)
def test_02_recovery_otp_after_logout_or_expired_global_session(client: TestClient, db_session: Session, portal: str):
    """Recovery OTP succeeds when user is logged out / global session expired via /recovery-auth."""
    email = f"recov_loggedout_{portal}@example.com"
    ctx = _create_portal_lock_via_failed_login_otp(client, db_session, email, portal)
    lock = ctx["lock"]

    # Normal login to the locked portal MUST remain blocked with HTTP 423
    blocked_login = _login_app(client, email, PASS_USER, portal, fingerprint="fp-relogin")
    assert blocked_login.status_code == 423

    # Authenticate into the isolated recovery gate with credentials (no DbSession or grant issued)
    auth_res = client.post(
        "/api/security/portal-lock/recovery-auth",
        json={
            "email": email,
            "password": PASS_USER,
            "application": portal,
            "security_reference_id": lock.security_reference_id,
        },
    )
    assert auth_res.status_code == 200, auth_res.text
    rec_token = auth_res.json()["access_token"]
    assert auth_res.json()["recovery_only"] is True

    sent_otps = []
    with patch.object(EmailService, "send_recovery_otp_email", side_effect=lambda **kw: (sent_otps.append(kw["otp_code"]) or (True, "ok"))), \
         patch.object(EmailService, "send_portal_security_notification", return_value=(True, "ok")):
        req_res = client.post(
            "/api/security/portal-lock/recovery-otp/request",
            json={"application": portal, "security_reference_id": lock.security_reference_id},
            headers={"Authorization": f"Bearer {rec_token}"},
        )
        assert req_res.status_code == 200, req_res.text
        chal_id = req_res.json()["challenge_id"]

        ver_res = client.post(
            "/api/security/portal-lock/recovery-otp/verify",
            json={
                "application": portal,
                "otp_code": sent_otps[0],
                "challenge_id": chal_id,
                "security_reference_id": lock.security_reference_id,
            },
            headers={"Authorization": f"Bearer {rec_token}"},
        )
        assert ver_res.status_code == 200, ver_res.text
        assert ver_res.json()["recovery_status"] == "OTP_VERIFIED_AWAITING_ADMIN"
        assert ver_res.json()["lock_status"] == "ACTIVE"

    # Ensure no active portal grants were created
    active_grants = db_session.query(ApplicationGrant).filter(
        ApplicationGrant.user_id == ctx["user"].id,
        ApplicationGrant.application == portal,
        ApplicationGrant.revoked == False,
    ).count()
    assert active_grants == 0


def test_03_single_attempt_policy_wrong_recovery_otp_rejected_and_counter_persisted(client: TestClient, db_session: Session):
    """Incorrect recovery OTP is rejected and enforces the single-attempt Recovery Email OTP policy (limit = 1)."""
    assert PortalLockService.get_max_attempts_for("RECOVERY_OTP", "RECOVERY_EMAIL_OTP") == 1
    email = "recov_single_attempt@example.com"
    ctx = _create_portal_lock_via_failed_login_otp(client, db_session, email, "shopping")
    user = ctx["user"]

    token = create_access_token(subject=user.id, role=user.role, session_id=None)
    captured = []
    with patch.object(EmailService, "send_recovery_otp_email", side_effect=lambda **kw: (captured.append(kw["otp_code"]) or (True, "ok"))):
        req_res = client.post(
            "/api/security/portal-lock/recovery-otp/request",
            json={"application": "shopping"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert req_res.status_code == 200
        chal_id = req_res.json()["challenge_id"]

    # Attempt 1 with wrong OTP -> rejected & single-attempt challenge consumed
    wrong_otp = "999999" if captured[0] != "999999" else "888888"
    bad_res = client.post(
        "/api/security/portal-lock/recovery-otp/verify",
        json={"application": "shopping", "otp_code": wrong_otp, "challenge_id": chal_id},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert bad_res.status_code == 400

    # Even submitting the real OTP against that exhausted single-attempt challenge MUST fail
    second_try = client.post(
        "/api/security/portal-lock/recovery-otp/verify",
        json={"application": "shopping", "otp_code": captured[0], "challenge_id": chal_id},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert second_try.status_code == 400

    # Counter row persisted in DB with max_attempts == 1
    cnt = db_session.query(VerificationAttemptCounter).filter(
        VerificationAttemptCounter.user_id == user.id,
        VerificationAttemptCounter.application == "shopping",
        VerificationAttemptCounter.verification_purpose == "RECOVERY_OTP",
    ).first()
    assert cnt is not None
    assert cnt.max_attempts == 1
    assert cnt.attempts == 1


def test_04_expired_recovery_otp_rejected_without_unlocking(client: TestClient, db_session: Session):
    """Expired recovery OTP is rejected cleanly without consuming a failed attempt or unlocking."""
    email = "recov_expired@example.com"
    ctx = _create_portal_lock_via_failed_login_otp(client, db_session, email, "college")
    user = ctx["user"]
    lock = ctx["lock"]
    token = create_access_token(subject=user.id, role=user.role, session_id=None)

    captured = []
    with patch.object(EmailService, "send_recovery_otp_email", side_effect=lambda **kw: (captured.append(kw["otp_code"]) or (True, "ok"))):
        req_res = client.post(
            "/api/security/portal-lock/recovery-otp/request",
            json={"application": "college"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert req_res.status_code == 200
        chal_id = req_res.json()["challenge_id"]

    # Expire DB challenge in UTC
    db_chal = db_session.query(OTPChallenge).filter(OTPChallenge.challenge_id == chal_id).first()
    db_chal.expires_at = datetime.now(timezone.utc) - timedelta(minutes=2)
    db_session.commit()

    exp_res = client.post(
        "/api/security/portal-lock/recovery-otp/verify",
        json={"application": "college", "otp_code": captured[0], "challenge_id": chal_id},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert exp_res.status_code == 400
    assert "expired" in exp_res.json()["detail"].lower()

    # Expiry must NOT increment wrong-attempt recovery counter or unlock portal
    cnt = db_session.query(VerificationAttemptCounter).filter(
        VerificationAttemptCounter.user_id == user.id,
        VerificationAttemptCounter.verification_purpose == "RECOVERY_OTP",
    ).first()
    assert cnt is None
    db_session.refresh(lock)
    assert lock.lock_status == "ACTIVE"
    assert lock.recovery_status == "PENDING_ADMIN_RECOVERY"


def test_05_reused_recovery_otp_rejected(client: TestClient, db_session: Session):
    """Reused recovery OTP is rejected immediately on replay."""
    email = "recov_reuse@example.com"
    ctx = _create_portal_lock_via_failed_login_otp(client, db_session, email, "healthcare")
    user = ctx["user"]
    token = create_access_token(subject=user.id, role=user.role, session_id=None)

    captured = []
    with patch.object(EmailService, "send_recovery_otp_email", side_effect=lambda **kw: (captured.append(kw["otp_code"]) or (True, "ok"))), \
         patch.object(EmailService, "send_portal_security_notification", return_value=(True, "ok")):
        req_res = client.post(
            "/api/security/portal-lock/recovery-otp/request",
            json={"application": "healthcare"},
            headers={"Authorization": f"Bearer {token}"},
        )
        chal_id = req_res.json()["challenge_id"]

        ok_res = client.post(
            "/api/security/portal-lock/recovery-otp/verify",
            json={"application": "healthcare", "otp_code": captured[0], "challenge_id": chal_id},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert ok_res.status_code == 200

        replay_res = client.post(
            "/api/security/portal-lock/recovery-otp/verify",
            json={"application": "healthcare", "otp_code": captured[0], "challenge_id": chal_id},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert replay_res.status_code == 400


def test_06_resend_invalidates_previous_recovery_otp(client: TestClient, db_session: Session):
    """Resending/retrying recovery OTP invalidates prior code; only newest code works."""
    email = "recov_resend@example.com"
    ctx = _create_portal_lock_via_failed_login_otp(client, db_session, email, "shopping")
    user = ctx["user"]
    token = create_access_token(subject=user.id, role=user.role, session_id=None)

    captured = []
    with patch.object(EmailService, "send_recovery_otp_email", side_effect=lambda **kw: (captured.append(kw["otp_code"]) or (True, "ok"))), \
         patch.object(EmailService, "send_portal_security_notification", return_value=(True, "ok")):
        r1 = client.post(
            "/api/security/portal-lock/recovery-otp/request",
            json={"application": "shopping"},
            headers={"Authorization": f"Bearer {token}"},
        ).json()
        r2 = client.post(
            "/api/security/portal-lock/recovery-otp/request",
            json={"application": "shopping"},
            headers={"Authorization": f"Bearer {token}"},
        ).json()

        old_otp, new_otp = captured[0], captured[1]
        # Submitting old challenge_id + old code fails (superseded)
        res_old_chal = client.post(
            "/api/security/portal-lock/recovery-otp/verify",
            json={"application": "shopping", "otp_code": old_otp, "challenge_id": r1["challenge_id"]},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res_old_chal.status_code == 400

        # Submitting old code without challenge_id fails against newest challenge
        if old_otp != new_otp:
            res_old_code = client.post(
                "/api/security/portal-lock/recovery-otp/verify",
                json={"application": "shopping", "otp_code": old_otp},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert res_old_code.status_code == 400
            # Re-issue since max_attempts=1 consumed the previous attempt
            r3 = client.post(
                "/api/security/portal-lock/recovery-otp/request",
                json={"application": "shopping"},
                headers={"Authorization": f"Bearer {token}"},
            ).json()
            new_otp = captured[2]
            r2 = r3

        # Submitting newest code + newest challenge_id succeeds
        res_new = client.post(
            "/api/security/portal-lock/recovery-otp/verify",
            json={"application": "shopping", "otp_code": new_otp, "challenge_id": r2["challenge_id"]},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res_new.status_code == 200


def test_07_cross_user_cross_portal_and_reference_binding(client: TestClient, db_session: Session):
    """Recovery OTP is strictly bound to user, portal, and security_reference_id."""
    email_a = "recov_bind_a@example.com"
    email_b = "recov_bind_b@example.com"
    ctx_a_shop = _create_portal_lock_via_failed_login_otp(client, db_session, email_a, "shopping")
    ctx_a_col = _create_portal_lock_via_failed_login_otp(client, db_session, email_a, "college")
    ctx_b_shop = _create_portal_lock_via_failed_login_otp(client, db_session, email_b, "shopping")

    user_a = ctx_a_shop["user"]
    user_b = ctx_b_shop["user"]
    tok_a = create_access_token(subject=user_a.id, role=user_a.role, session_id=None)
    tok_b = create_access_token(subject=user_b.id, role=user_b.role, session_id=None)

    captured = []
    with patch.object(EmailService, "send_recovery_otp_email", side_effect=lambda **kw: (captured.append(kw["otp_code"]) or (True, "ok"))):
        r_shop = client.post(
            "/api/security/portal-lock/recovery-otp/request",
            json={"application": "shopping"},
            headers={"Authorization": f"Bearer {tok_a}"},
        ).json()

    # Wrong portal (college) with shopping challenge ID -> rejected
    wrong_portal = client.post(
        "/api/security/portal-lock/recovery-otp/verify",
        json={"application": "college", "otp_code": captured[0], "challenge_id": r_shop["challenge_id"]},
        headers={"Authorization": f"Bearer {tok_a}"},
    )
    assert wrong_portal.status_code == 400

    # Wrong user (User B) with User A's challenge ID -> rejected
    wrong_user = client.post(
        "/api/security/portal-lock/recovery-otp/verify",
        json={"application": "shopping", "otp_code": captured[0], "challenge_id": r_shop["challenge_id"]},
        headers={"Authorization": f"Bearer {tok_b}"},
    )
    assert wrong_user.status_code == 400

    # Wrong security_reference_id (College's ref on Shopping lock) -> rejected
    wrong_ref = client.post(
        "/api/security/portal-lock/recovery-otp/verify",
        json={
            "application": "shopping",
            "otp_code": captured[0],
            "challenge_id": r_shop["challenge_id"],
            "security_reference_id": ctx_a_col["lock"].security_reference_id,
        },
        headers={"Authorization": f"Bearer {tok_a}"},
    )
    assert wrong_ref.status_code == 400


def test_08_non_interchangeability_with_login_and_transactional_otps(client: TestClient, db_session: Session):
    """Login OTP / Exam OTP / Step-Up OTP cannot be used for recovery, and Recovery OTP cannot activate login/exam."""
    email = "recov_no_swap@example.com"
    ctx = _create_portal_lock_via_failed_login_otp(client, db_session, email, "college")
    user = ctx["user"]

    # Also open an unlocked shopping session for login OTP generation
    shop_res = _login_app(client, email, PASS_USER, "shopping", fingerprint="fp-shop-swap").json()
    shop_tok = shop_res["access_token"]
    shop_sid = shop_res["session_id"]
    sess = db_session.query(DbSession).filter(DbSession.id == shop_sid).first()
    sess.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=settings.OBSERVATION_WINDOW_SECONDS + 2)
    db_session.commit()

    captured_login = []
    captured_recov = []
    with patch.object(EmailService, "send_otp_email", side_effect=lambda **kw: (captured_login.append(kw["otp_code"]) or (True, "ok"))):
        l_req = client.post(
            "/api/auth/login-otp/request",
            json={"session_id": shop_sid},
            headers={"Authorization": f"Bearer {shop_tok}"},
        ).json()

    tok_rec = create_access_token(subject=user.id, role=user.role, session_id=None)
    with patch.object(EmailService, "send_recovery_otp_email", side_effect=lambda **kw: (captured_recov.append(kw["otp_code"]) or (True, "ok"))):
        r_req = client.post(
            "/api/security/portal-lock/recovery-otp/request",
            json={"application": "college"},
            headers={"Authorization": f"Bearer {tok_rec}"},
        ).json()

    # Try using Login OTP challenge + code on Recovery endpoint -> REJECTED
    swap_1 = client.post(
        "/api/security/portal-lock/recovery-otp/verify",
        json={"application": "college", "otp_code": captured_login[0], "challenge_id": l_req["challenge_id"]},
        headers={"Authorization": f"Bearer {tok_rec}"},
    )
    assert swap_1.status_code == 400

    # Try using Recovery OTP challenge + code on Login OTP endpoint -> REJECTED
    swap_2 = client.post(
        "/api/auth/login-otp/verify",
        json={"session_id": shop_sid, "otp_code": captured_recov[0], "challenge_id": r_req["challenge_id"]},
        headers={"Authorization": f"Bearer {shop_tok}"},
    )
    assert swap_2.status_code != 200
    assert PortalLockService.get_active_lock(db_session, user.id, "college").lock_status == "ACTIVE"


def test_09_10_11_12_lock_stays_active_reentry_blocked_and_counters_isolated(client: TestClient, db_session: Session):
    """
    Combines invariants 9-12:
    - Successful recovery OTP does NOT unlock portal
    - Direct portal re-entry stays blocked until Admin clearance
    - Failed recovery OTP does not weaken lock or change security_reference_id
    - Recovery OTP verification / failure does not reset unrelated attempt counters (e.g., GESTURE_PATTERN)
    """
    email = "recov_invariants@example.com"
    ctx = _create_portal_lock_via_failed_login_otp(client, db_session, email, "healthcare")
    user = ctx["user"]
    lock = ctx["lock"]
    orig_ref = lock.security_reference_id

    # Seed an unrelated GESTURE_PATTERN counter on a valid shopping session (1 failed gesture attempt)
    PortalLockService.record_verification_failure(
        db=db_session,
        user_id=user.id,
        application="shopping",
        verification_purpose="CONFIDENTIAL_RESOURCE",
        factor_key="GESTURE_PATTERN",
        session_id="unrelated-shop-sess",
        lock_reason="Test gesture drift",
    )

    tok = create_access_token(subject=user.id, role=user.role, session_id=None)
    captured = []
    with patch.object(EmailService, "send_recovery_otp_email", side_effect=lambda **kw: (captured.append(kw["otp_code"]) or (True, "ok"))), \
         patch.object(EmailService, "send_portal_security_notification", return_value=(True, "ok")):
        # 1) Wrong recovery OTP -> lock must stay ACTIVE with same security_reference_id
        r1 = client.post(
            "/api/security/portal-lock/recovery-otp/request",
            json={"application": "healthcare"},
            headers={"Authorization": f"Bearer {tok}"},
        ).json()
        bad = client.post(
            "/api/security/portal-lock/recovery-otp/verify",
            json={"application": "healthcare", "otp_code": "000001" if captured[0] != "000001" else "000002", "challenge_id": r1["challenge_id"]},
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert bad.status_code == 400
        db_session.refresh(lock)
        assert lock.lock_status == "ACTIVE"
        assert lock.security_reference_id == orig_ref

        # 2) Resend + verify correct recovery OTP
        r2 = client.post(
            "/api/security/portal-lock/recovery-otp/request",
            json={"application": "healthcare"},
            headers={"Authorization": f"Bearer {tok}"},
        ).json()
        ok = client.post(
            "/api/security/portal-lock/recovery-otp/verify",
            json={"application": "healthcare", "otp_code": captured[1], "challenge_id": r2["challenge_id"]},
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert ok.status_code == 200
        assert ok.json()["lock_status"] == "ACTIVE"

    # Re-entry MUST STILL BE BLOCKED after Recovery OTP verification
    reentry = client.post(
        "/api/security/portal-lock/reentry",
        json={"application": "healthcare", "source": "TEST_REENTRY_AFTER_OTP"},
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert reentry.status_code == 200
    assert reentry.json()["locked"] is True
    assert reentry.json()["lock_status"] == "ACTIVE"
    assert _login_app(client, email, PASS_USER, "healthcare").status_code == 423

    # Unrelated GESTURE_PATTERN counter MUST remain intact (attempts == 1)
    gesture_cnt = PortalLockService.get_attempt_counter_status(
        db_session, user.id, "shopping", "CONFIDENTIAL_RESOURCE", "GESTURE_PATTERN", session_id="unrelated-shop-sess"
    )
    assert gesture_cnt["attempts_used"] == 1


def test_13_admin_approval_and_rejection_authorization_audit_and_notifications(client: TestClient, db_session: Session):
    """
    Tests Admin/SOC clearance governance:
    - Non-admin user blocked with 403
    - Self-approval / self-rejection blocked with 403
    - Rejection records admin identity, timestamp, decision='REJECTED', notifies owner+admin, keeps lock ACTIVE
    - Approval records admin identity, timestamp, decision='APPROVED', notifies owner+admin, recovers lock
    """
    owner_email = "recov_admin_gov@example.com"
    admin_email = "soc_gov_admin@example.com"
    ctx = _create_portal_lock_via_failed_login_otp(client, db_session, owner_email, "college")
    owner = ctx["user"]
    lock = ctx["lock"]
    sec_ref = lock.security_reference_id

    admin_user = _ensure_user(db_session, admin_email, role="ADMIN", password=PASS_ADMIN)
    admin_tok = create_access_token(subject=admin_user.id, role="ADMIN", session_id=None)
    owner_tok = create_access_token(subject=owner.id, role="USER", session_id=None)

    # Non-admin blocked
    non_admin_res = client.post(
        f"/api/admin/portal-locks/{sec_ref}/recover",
        json={"notes": "bypass"},
        headers={"Authorization": f"Bearer {owner_tok}"},
    )
    assert non_admin_res.status_code == 403

    # Self-approval / self-rejection blocked
    admin_self_ctx = _create_portal_lock_via_failed_login_otp(client, db_session, "soc_self@example.com", "shopping")
    self_admin = admin_self_ctx["user"]
    self_admin.role = "ADMIN"
    db_session.commit()
    self_tok = create_access_token(subject=self_admin.id, role="ADMIN", session_id=None)
    self_app = client.post(
        f"/api/admin/portal-locks/{admin_self_ctx['lock'].security_reference_id}/recover",
        headers={"Authorization": f"Bearer {self_tok}"},
    )
    assert self_app.status_code == 403
    self_rej = client.post(
        f"/api/admin/portal-locks/{admin_self_ctx['lock'].security_reference_id}/reject",
        headers={"Authorization": f"Bearer {self_tok}"},
    )
    assert self_rej.status_code == 403

    sent_notices = []
    with patch.object(
        EmailService,
        "send_portal_security_notification",
        side_effect=lambda **kw: (sent_notices.append(kw) or (True, "sent")),
    ):
        # Explicit Admin rejection first
        rej_res = client.post(
            f"/api/admin/portal-locks/{sec_ref}/reject",
            json={"notes": "Suspicious IP mismatch observed during SOC review."},
            headers={"Authorization": f"Bearer {admin_tok}"},
        )
        assert rej_res.status_code == 200, rej_res.text
        rej_body = rej_res.json()
        assert rej_body["decision"] == "REJECTED"
        assert rej_body["lock_status"] == "ACTIVE"
        assert rej_body["locked"] is True
        assert rej_body["recovery_status"] == "REJECTED_BY_ADMIN"
        assert rej_body["unlocked_by"] == admin_email

        # Rejection notified BOTH owner and Admin/SOC
        rej_events = [n for n in sent_notices if n["event_type"] == "PORTAL_LOCK_RECOVERY_REJECTED"]
        assert len(rej_events) >= 2
        assert any(not n["is_admin_notice"] for n in rej_events)
        assert any(n["is_admin_notice"] for n in rej_events)

        # Verify rejection SecurityEvent recorded
        rej_evt = db_session.query(SecurityEvent).filter(
            SecurityEvent.user_id == owner.id,
            SecurityEvent.event_type == "PORTAL_LOCK_RECOVERY_REJECTED",
        ).order_by(SecurityEvent.id.desc()).first()
        assert rej_evt is not None
        assert "REJECTED" in (rej_evt.details or "")

        # Now Admin approves clearance
        app_res = client.post(
            f"/api/admin/portal-locks/{sec_ref}/recover",
            json={"notes": "Identity verified out-of-band by SOC lead."},
            headers={"Authorization": f"Bearer {admin_tok}"},
        )
        assert app_res.status_code == 200, app_res.text
        app_body = app_res.json()
        assert app_body["decision"] == "APPROVED"
        assert app_body["lock_status"] == "RECOVERED"
        assert app_body["unlocked_by"] == admin_email
        assert app_body["unlocked_at"] is not None

        app_events = [n for n in sent_notices if n["event_type"] == "PORTAL_ACCESS_RESTORED"]
        assert len(app_events) >= 2
        assert any(not n["is_admin_notice"] for n in app_events)
        assert any(n["is_admin_notice"] for n in app_events)


def test_14_15_16_cross_portal_isolation_notification_resilience_and_post_clearance_reentry(client: TestClient, db_session: Session):
    """
    Tests:
    - Recovering Shopping keeps College and Healthcare locked
    - Notification failures do NOT undo recovery OTP verification or admin clearance state
    - Post-clearance portal entry enforces fresh login + 20s behavioral observation + initial Email OTP
    """
    email = "recov_cross_portal@example.com"
    shop_ctx = _create_portal_lock_via_failed_login_otp(client, db_session, email, "shopping")
    _create_portal_lock_via_failed_login_otp(client, db_session, email, "college")
    _create_portal_lock_via_failed_login_otp(client, db_session, email, "healthcare")
    user = shop_ctx["user"]

    admin_user = _ensure_user(db_session, "soc_resilient_admin@example.com", role="ADMIN", password=PASS_ADMIN)
    admin_tok = create_access_token(subject=admin_user.id, role="ADMIN", session_id=None)
    user_tok = create_access_token(subject=user.id, role=user.role, session_id=None)

    captured = []
    with patch.object(EmailService, "send_recovery_otp_email", side_effect=lambda **kw: (captured.append(kw["otp_code"]) or (True, "ok"))):
        r_shop = client.post(
            "/api/security/portal-lock/recovery-otp/request",
            json={"application": "shopping"},
            headers={"Authorization": f"Bearer {user_tok}"},
        ).json()

    # Force NotificationService.notify_portal_security_event to raise -> MUST NOT rollback state
    with patch(
        "app.services.portal_lock_service.NotificationService.notify_portal_security_event",
        side_effect=RuntimeError("Simulated notification outage"),
    ):
        ver_res = client.post(
            "/api/security/portal-lock/recovery-otp/verify",
            json={"application": "shopping", "otp_code": captured[0], "challenge_id": r_shop["challenge_id"]},
            headers={"Authorization": f"Bearer {user_tok}"},
        )
        assert ver_res.status_code == 200
        assert PortalLockService.get_active_lock(db_session, user.id, "shopping").recovery_status == "OTP_VERIFIED_AWAITING_ADMIN"

        clr_res = client.post(
            f"/api/admin/portal-locks/{shop_ctx['lock'].security_reference_id}/recover",
            json={"notes": "Cleared despite notification outage"},
            headers={"Authorization": f"Bearer {admin_tok}"},
        )
        assert clr_res.status_code == 200
        assert PortalLockService.get_active_lock(db_session, user.id, "shopping") is None

    # Cross-portal isolation: College and Healthcare remain ACTIVE locks
    assert PortalLockService.get_active_lock(db_session, user.id, "college").lock_status == "ACTIVE"
    assert PortalLockService.get_active_lock(db_session, user.id, "healthcare").lock_status == "ACTIVE"
    assert _login_app(client, email, PASS_USER, "college").status_code == 423
    assert _login_app(client, email, PASS_USER, "healthcare").status_code == 423

    # Post-clearance re-entry for Shopping requires fresh login -> 20s behavioral observation -> initial Email OTP
    reenter = _login_app(client, email, PASS_USER, "shopping", fingerprint="fp-reenter-fresh")
    assert reenter.status_code == 200, reenter.text
    re_data = reenter.json()
    assert re_data["session_status"] == "PENDING_OBSERVATION"
    re_tok = re_data["access_token"]
    re_sid = re_data["session_id"]

    # Immediate Login OTP before 20s must be blocked
    early_otp = client.post(
        "/api/auth/login-otp/request",
        json={"session_id": re_sid},
        headers={"Authorization": f"Bearer {re_tok}"},
    )
    assert early_otp.status_code == 400

    # Simulate completed 20s behavioral observation + valid initial Email OTP
    re_sess = db_session.query(DbSession).filter(DbSession.id == re_sid).first()
    re_sess.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=settings.OBSERVATION_WINDOW_SECONDS + 2)
    db_session.commit()

    login_otps = []
    with patch.object(EmailService, "send_otp_email", side_effect=lambda **kw: (login_otps.append(kw["otp_code"]) or (True, "ok"))):
        otp_req = client.post(
            "/api/auth/login-otp/request",
            json={"session_id": re_sid},
            headers={"Authorization": f"Bearer {re_tok}"},
        )
        assert otp_req.status_code == 200
        otp_ver = client.post(
            "/api/auth/login-otp/verify",
            json={"session_id": re_sid, "otp_code": login_otps[0]},
            headers={"Authorization": f"Bearer {re_tok}"},
        )
        assert otp_ver.status_code == 200
        assert otp_ver.json()["session_status"] == "ACTIVE"
