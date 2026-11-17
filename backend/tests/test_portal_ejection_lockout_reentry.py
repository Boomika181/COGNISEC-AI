"""
Comprehensive Verification Suite:
Portal-Scoped Authentication Ejection, Central Dashboard Lock Isolation,
Attempt Limits (1 OTP / 3 Gesture / 2 Cognitive), Re-entry Monitoring,
Authorized Admin Recovery, and Critical-Risk Full Session Termination.
"""

import secrets
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.rate_limit import rate_limiter
from app.core.security import create_access_token, get_password_hash, verify_password
from app.models.application_grant import ApplicationGrant
from app.models.password_change import PasswordChangeTransaction
from app.models.portal_lock import PortalSecurityLock, VerificationAttemptCounter
from app.models.security_event import SecurityEvent
from app.models.session import Session as DbSession
from app.models.user import User
from app.services.adaptive_auth_service import AdaptiveAuthService
from app.services.email_service import EmailService
from app.services.portal_lock_service import PortalLockService
from app.services.step_up_service import StepUpService

VALID_GESTURE = [0, 4, 8, 12]
BAD_GESTURE = [0, 1, 2, 3]
VALID_IMG_SEQ = ["img_shield", "img_vault", "img_token"]
BAD_IMG_SEQ = ["img_key", "img_radar", "img_chip"]
PRIV_Q = "What is your backup enclave identifier?"
PRIV_A = "zenith-node-42"
PASS_INIT = "PortalLockTest!2026"


@pytest.fixture(autouse=True)
def clean_stepup():
    StepUpService.reset()
    rate_limiter.reset()
    yield
    StepUpService.reset()
    rate_limiter.reset()


def _create_user_with_factors(db: Session, email: str, role: str = "USER") -> User:
    user = db.query(User).filter(User.email == email).first()
    if not user:
        user = User(
            name="Portal Isolation User",
            email=email,
            password_hash=get_password_hash(PASS_INIT),
            role=role,
            account_status="ACTIVE",
            failed_login_attempts=0,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    if not AdaptiveAuthService.get_factor(db, user.id, "GESTURE_PATTERN"):
        AdaptiveAuthService.enroll_gesture_pattern(db, user.id, VALID_GESTURE, VALID_GESTURE)
    if not AdaptiveAuthService.get_factor(db, user.id, "COGNITIVE_IMAGE_SEQUENCE"):
        AdaptiveAuthService.enroll_image_sequence(db, user.id, VALID_IMG_SEQ, VALID_IMG_SEQ)
    if not AdaptiveAuthService.get_factor(db, user.id, "PRIVATE_RESPONSE"):
        AdaptiveAuthService.enroll_private_response(db, user.id, PRIV_Q, PRIV_A, PRIV_A)
    return user


def _create_admin(db: Session) -> User:
    email = "soc_admin_portal_test@example.com"
    admin = db.query(User).filter(User.email == email).first()
    if not admin:
        admin = User(
            name="SOC Admin",
            email=email,
            password_hash=get_password_hash("AdminPass!1234"),
            role="ADMIN",
            account_status="ACTIVE",
            failed_login_attempts=0,
        )
        db.add(admin)
        db.commit()
        db.refresh(admin)
    return admin


def _login_portal(client: TestClient, db: Session, email: str, portal: str, fast_forward_obs: bool = True):
    res = client.post("/api/auth/login", json={
        "email": email,
        "password": PASS_INIT,
        "application": portal,
        "device_fingerprint": f"fp_iso_{portal}_{secrets.token_hex(3)}",
    })
    assert res.status_code == 200, res.text
    d = res.json()
    sid = d["session_id"]
    headers = {"Authorization": f"Bearer {d['access_token']}"}
    if fast_forward_obs:
        sess = db.query(DbSession).filter(DbSession.id == sid).first()
        sess.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=settings.OBSERVATION_WINDOW_SECONDS + 2)
        db.commit()
    return sid, headers, d


# ==============================================================================
# 1. COLLEGE LOGIN OTP (1 ATTEMPT) -> 423 PORTAL LOCK, GLOBAL SESSION PRESERVED
# ==============================================================================

def test_college_login_otp_single_failure_locks_portal_preserves_global_session_and_other_portals(
    client: TestClient, db_session: Session
):
    email = f"college_otp_iso_{secrets.token_hex(4)}@example.com"
    user = _create_user_with_factors(db_session, email)

    # Active Shopping & Healthcare sessions/grants for the same user BEFORE College fails
    now = datetime.now(timezone.utc)
    shop_sid = f"sess_shop_ok_{secrets.token_hex(4)}"
    hc_sid = f"sess_hc_ok_{secrets.token_hex(4)}"
    for sid, app in ((shop_sid, "shopping"), (hc_sid, "healthcare")):
        db_session.add(DbSession(
            id=sid, user_id=user.id, application=app, status="ACTIVE", current_risk_level="LOW",
            observation_started_at=now - timedelta(seconds=45), observation_completed_at=now - timedelta(seconds=20),
            step_up_verified_at=now, step_up_valid_until=now + timedelta(minutes=15), step_up_factor="EMAIL_OTP",
        ))
    shop_grant = ApplicationGrant(
        session_id=shop_sid, user_id=user.id, application="shopping", resource="financial_vault",
        factor="EMAIL_OTP", expires_at=now + timedelta(minutes=15), revoked=False,
    )
    hc_grant = ApplicationGrant(
        session_id=hc_sid, user_id=user.id, application="healthcare", resource="ehr_vault",
        factor="EMAIL_OTP", expires_at=now + timedelta(minutes=15), revoked=False,
    )
    db_session.add_all([shop_grant, hc_grant])
    db_session.commit()
    shop_headers = {"Authorization": f"Bearer {create_access_token(subject=user.id, role=user.role, session_id=shop_sid)}"}
    hc_headers = {"Authorization": f"Bearer {create_access_token(subject=user.id, role=user.role, session_id=hc_sid)}"}

    # College login + 20s observation + Login OTP request
    col_sid, col_headers, col_login = _login_portal(client, db_session, email, "college")
    assert col_login["session_status"] == "PENDING_OBSERVATION"
    col_grant = ApplicationGrant(
        session_id=col_sid, user_id=user.id, application="college", resource="academic_vault",
        factor="EMAIL_OTP", expires_at=now + timedelta(minutes=15), revoked=False,
    )
    db_session.add(col_grant)
    db_session.commit()

    captured = {}

    def spy_otp(recipient_email, otp_code, **kwargs):
        captured["otp"] = otp_code
        return True, "250 OK"

    with patch.object(EmailService, "send_otp_email", side_effect=spy_otp):
        req = client.post("/api/auth/login-otp/request", headers=col_headers, json={"session_id": col_sid})
    assert req.status_code == 200
    assert req.json()["attempts_remaining"] == 1
    assert req.json()["max_attempts"] == 1
    chal_id = req.json()["challenge_id"]

    # Expired OTP before failure check must NOT lock portal
    chal_obj = StepUpService.get_challenge(col_sid)
    chal_obj["expires_at"] = datetime.now(timezone.utc) - timedelta(seconds=3)
    exp_res = client.post("/api/auth/login-otp/verify", headers=col_headers, json={
        "session_id": col_sid, "otp_code": captured["otp"], "challenge_id": chal_id,
    })
    assert exp_res.status_code == 400
    assert "expired" in exp_res.json()["detail"].lower()
    assert PortalLockService.get_active_lock(db_session, user.id, "college") is None

    # Re-issue OTP -> 1st wrong attempt IMMEDIATELY locks ONLY College (HTTP 423)
    with patch.object(EmailService, "send_otp_email", side_effect=spy_otp):
        req2 = client.post("/api/auth/login-otp/request", headers=col_headers, json={"session_id": col_sid})
    assert req2.status_code == 200
    chal_id_2 = req2.json()["challenge_id"]

    fail1 = client.post("/api/auth/login-otp/verify", headers=col_headers, json={
        "session_id": col_sid, "otp_code": "000000", "challenge_id": chal_id_2,
    })
    assert fail1.status_code == 423
    assert fail1.headers.get("X-Cognisec-Portal-Locked") == "true"
    assert fail1.headers.get("X-Cognisec-Locked-Portal") == "college"
    assert fail1.headers.get("X-Cognisec-Session-Terminated") is None
    assert "SECURITY ACCESS SUSPENDED" in fail1.json()["detail"]
    sec_ref = fail1.headers["X-Cognisec-Security-Ref"]
    assert sec_ref

    db_session.expire_all()
    col_sess = db_session.query(DbSession).filter(DbSession.id == col_sid).first()
    assert col_sess.status == "RESTRICTED"
    assert col_sess.logout_time is None  # Global session preserved (NOT full logout/termination)
    db_session.refresh(col_grant)
    assert col_grant.revoked is True

    # Global session endpoints stay valid for index.html central dashboard
    me_res = client.get("/api/auth/me", headers=col_headers)
    assert me_res.status_code == 200
    assert me_res.json()["email"] == email

    locks_res = client.get(f"/api/security/portal-locks?session_id={col_sid}", headers=col_headers)
    assert locks_res.status_code == 200
    locks_data = locks_res.json()
    assert locks_data["authenticated"] is True
    assert locks_data["global_session"]["valid"] is True
    assert locks_data["global_session"]["portal_auth_completed"] is False
    assert locks_data["portals"]["college"]["locked"] is True
    assert locks_data["portals"]["college"]["lock"]["security_reference_id"] == sec_ref
    assert locks_data["portals"]["shopping"]["locked"] is False
    assert locks_data["portals"]["healthcare"]["locked"] is False

    # College protected endpoints reject with 423
    assert client.get(f"/api/security/vault/academic_vault?session_id={col_sid}", headers=col_headers).status_code == 423
    assert client.post("/api/security/exam-otp/request", headers=col_headers, json={
        "session_id": col_sid, "exam_id": "CS-301", "student_email": email,
    }).status_code == 423
    assert client.post("/api/security/step-up/challenge", headers=col_headers, json={
        "session_id": col_sid, "application": "college", "resource": "academic_vault",
    }).status_code == 423

    # Shopping & Healthcare sessions, grants, and vaults remain completely unaffected & ACTIVE
    db_session.refresh(shop_grant)
    db_session.refresh(hc_grant)
    assert shop_grant.revoked is False
    assert hc_grant.revoked is False
    shop_vault = client.get(f"/api/security/vault/financial_vault?session_id={shop_sid}", headers=shop_headers)
    hc_vault = client.get(f"/api/security/vault/ehr_vault?session_id={hc_sid}", headers=hc_headers)
    assert shop_vault.status_code == 200
    assert hc_vault.status_code == 200


# ==============================================================================
# 2. OTHER OTPs = 1 ATTEMPT (EXAM OTP, PAYMENT OTP, APPOINTMENT OTP, STEP-UP OTP)
# ==============================================================================

def test_exam_otp_and_stepup_otp_lock_on_first_failure(client: TestClient, db_session: Session):
    # Exam OTP (college)
    email1 = f"exam_otp_1att_{secrets.token_hex(4)}@example.com"
    u1 = _create_user_with_factors(db_session, email1)
    now = datetime.now(timezone.utc)
    sid1 = f"sess_ex_{secrets.token_hex(4)}"
    db_session.add(DbSession(
        id=sid1, user_id=u1.id, application="college", status="ACTIVE", current_risk_level="LOW",
        observation_started_at=now - timedelta(seconds=45), observation_completed_at=now - timedelta(seconds=20),
        step_up_verified_at=now, step_up_valid_until=now + timedelta(minutes=15), step_up_factor="EMAIL_OTP",
    ))
    db_session.commit()
    h1 = {"Authorization": f"Bearer {create_access_token(subject=u1.id, role=u1.role, session_id=sid1)}"}

    with patch.object(EmailService, "send_otp_email", return_value=(True, "250 OK")):
        req_ex = client.post("/api/security/exam-otp/request", headers=h1, json={
            "session_id": sid1, "exam_id": "CS-301", "student_email": email1,
        })
    assert req_ex.status_code == 200
    assert req_ex.json()["attempts_remaining"] == 1
    fail_ex = client.post("/api/security/exam-otp/verify", headers=h1, json={
        "session_id": sid1, "challenge_id": req_ex.json()["challenge_id"], "otp": "111111",
    })
    assert fail_ex.status_code == 423
    assert fail_ex.headers.get("X-Cognisec-Locked-Portal") == "college"
    db_session.expire_all()
    assert db_session.query(DbSession).filter(DbSession.id == sid1).first().status == "RESTRICTED"

    # Step-up OTP (shopping)
    email2 = f"stepup_otp_1att_{secrets.token_hex(4)}@example.com"
    u2 = _create_user_with_factors(db_session, email2)
    sid2 = f"sess_su_{secrets.token_hex(4)}"
    db_session.add(DbSession(
        id=sid2, user_id=u2.id, application="shopping", status="ACTIVE", current_risk_level="LOW",
        observation_started_at=now - timedelta(seconds=45), observation_completed_at=now - timedelta(seconds=20),
        step_up_verified_at=now, step_up_valid_until=now + timedelta(minutes=15), step_up_factor="EMAIL_OTP",
    ))
    db_session.commit()
    h2 = {"Authorization": f"Bearer {create_access_token(subject=u2.id, role=u2.role, session_id=sid2)}"}

    with patch.object(EmailService, "send_otp_email", return_value=(True, "250 OK")):
        req_su = client.post("/api/security/step-up/challenge", headers=h2, json={
            "session_id": sid2, "application": "shopping", "resource": "financial_vault",
            "preferred_factor": "EMAIL_OTP",
        })
    assert req_su.status_code == 200
    assert req_su.json()["attempts_remaining"] == 1
    fail_su = client.post("/api/security/step-up/verify", headers=h2, json={
        "session_id": sid2, "application": "shopping", "resource": "financial_vault",
        "challenge_id": req_su.json()["challenge_id"], "challenge_type": "EMAIL_OTP", "challenge_code": "222222",
    })
    assert fail_su.status_code == 423
    assert fail_su.headers.get("X-Cognisec-Locked-Portal") == "shopping"


# ==============================================================================
# 3. GESTURE (3 ATTEMPTS) & COGNITIVE IMAGE/PRIVATE (2 ATTEMPTS EACH)
# ==============================================================================

def test_gesture_three_attempts_locks_only_affected_portal(client: TestClient, db_session: Session):
    email = f"gest_3att_{secrets.token_hex(4)}@example.com"
    user = _create_user_with_factors(db_session, email)
    now = datetime.now(timezone.utc)
    sid_hc = f"sess_g_hc_{secrets.token_hex(4)}"
    sid_col = f"sess_g_col_{secrets.token_hex(4)}"
    for sid, app in ((sid_hc, "healthcare"), (sid_col, "college")):
        db_session.add(DbSession(
            id=sid, user_id=user.id, application=app, status="ACTIVE", current_risk_level="LOW",
            observation_started_at=now - timedelta(seconds=45), observation_completed_at=now - timedelta(seconds=20),
            step_up_verified_at=now, step_up_valid_until=now + timedelta(minutes=15), step_up_factor="EMAIL_OTP",
        ))
    db_session.commit()
    h_hc = {"Authorization": f"Bearer {create_access_token(subject=user.id, role=user.role, session_id=sid_hc)}"}
    h_col = {"Authorization": f"Bearer {create_access_token(subject=user.id, role=user.role, session_id=sid_col)}"}

    ch = client.post("/api/security/step-up/challenge", headers=h_hc, json={
        "session_id": sid_hc, "application": "healthcare", "resource": "ehr_vault",
        "challenge_purpose": "CONFIDENTIAL_RESOURCE", "preferred_factor": "GESTURE_PATTERN",
    }).json()
    assert ch["attempts_remaining"] == 3

    for expected_left in (2, 1):
        res = client.post("/api/security/step-up/verify", headers=h_hc, json={
            "session_id": sid_hc, "application": "healthcare", "resource": "ehr_vault",
            "challenge_id": ch["challenge_id"], "challenge_purpose": "CONFIDENTIAL_RESOURCE",
            "challenge_type": "GESTURE_PATTERN", "gesture_pattern": BAD_GESTURE,
        })
        assert res.status_code == 400
        assert f"{expected_left} attempt" in res.json()["detail"].lower()

    res3 = client.post("/api/security/step-up/verify", headers=h_hc, json={
        "session_id": sid_hc, "application": "healthcare", "resource": "ehr_vault",
        "challenge_id": ch["challenge_id"], "challenge_purpose": "CONFIDENTIAL_RESOURCE",
        "challenge_type": "GESTURE_PATTERN", "gesture_pattern": BAD_GESTURE,
    })
    assert res3.status_code == 423
    assert res3.headers.get("X-Cognisec-Locked-Portal") == "healthcare"

    # College remains unlocked & accessible
    col_locks = client.get(f"/api/security/portal-locks?session_id={sid_col}", headers=h_col).json()
    assert col_locks["portals"]["healthcare"]["locked"] is True
    assert col_locks["portals"]["college"]["locked"] is False
    assert col_locks["global_session"]["valid"] is True


def test_cognitive_two_attempts_each_locks_only_portal_and_keeps_password_unchanged(
    client: TestClient, db_session: Session
):
    # Case A: Image sequence 2 failures -> 423
    email_a = f"cog_img_2att_{secrets.token_hex(4)}@example.com"
    u_a = _create_user_with_factors(db_session, email_a)
    orig_hash_a = u_a.password_hash
    now = datetime.now(timezone.utc)
    sid_a = f"sess_img_{secrets.token_hex(4)}"
    db_session.add(DbSession(
        id=sid_a, user_id=u_a.id, application="shopping", status="ACTIVE", current_risk_level="LOW",
        observation_started_at=now - timedelta(seconds=45), observation_completed_at=now - timedelta(seconds=20),
        step_up_verified_at=now, step_up_valid_until=now + timedelta(minutes=15), step_up_factor="EMAIL_OTP",
    ))
    db_session.commit()
    h_a = {"Authorization": f"Bearer {create_access_token(subject=u_a.id, role=u_a.role, session_id=sid_a)}"}

    init_a = client.post("/api/auth/password-change/initiate", headers=h_a, json={
        "current_password": PASS_INIT, "session_id": sid_a, "application": "shopping",
    }).json()
    assert init_a["image_attempts_remaining"] == 2
    assert init_a["private_attempts_remaining"] == 2
    tx_a = init_a["transaction_id"]

    f1_a = client.post("/api/auth/password-change/verify-image", headers=h_a, json={
        "transaction_id": tx_a, "image_challenge_id": init_a["image_challenge_id"],
        "image_sequence": BAD_IMG_SEQ, "session_id": sid_a, "application": "shopping",
    })
    assert f1_a.status_code == 400 and "1 attempt remaining" in f1_a.json()["detail"].lower()

    f2_a = client.post("/api/auth/password-change/verify-image", headers=h_a, json={
        "transaction_id": tx_a, "image_challenge_id": init_a["image_challenge_id"],
        "image_sequence": BAD_IMG_SEQ, "session_id": sid_a, "application": "shopping",
    })
    assert f2_a.status_code == 423
    assert f2_a.headers.get("X-Cognisec-Locked-Portal") == "shopping"
    db_session.expire_all()
    assert db_session.query(DbSession).filter(DbSession.id == sid_a).first().status == "RESTRICTED"
    assert db_session.query(User).filter(User.id == u_a.id).first().password_hash == orig_hash_a
    tx_a_row = db_session.query(PasswordChangeTransaction).filter(PasswordChangeTransaction.transaction_id == tx_a).first()
    assert tx_a_row.status == "LOCKED"

    # Case B: Private security response has independent 2-attempt counter after 1 image failure
    email_b = f"cog_priv_2att_{secrets.token_hex(4)}@example.com"
    u_b = _create_user_with_factors(db_session, email_b)
    orig_hash_b = u_b.password_hash
    sid_b = f"sess_priv_{secrets.token_hex(4)}"
    db_session.add(DbSession(
        id=sid_b, user_id=u_b.id, application="college", status="ACTIVE", current_risk_level="LOW",
        observation_started_at=now - timedelta(seconds=45), observation_completed_at=now - timedelta(seconds=20),
        step_up_verified_at=now, step_up_valid_until=now + timedelta(minutes=15), step_up_factor="EMAIL_OTP",
    ))
    db_session.commit()
    h_b = {"Authorization": f"Bearer {create_access_token(subject=u_b.id, role=u_b.role, session_id=sid_b)}"}

    init_b = client.post("/api/auth/password-change/initiate", headers=h_b, json={
        "current_password": PASS_INIT, "session_id": sid_b, "application": "college",
    }).json()
    tx_b = init_b["transaction_id"]

    # 1 wrong image, then valid image -> private counter still starts at 2!
    assert client.post("/api/auth/password-change/verify-image", headers=h_b, json={
        "transaction_id": tx_b, "image_challenge_id": init_b["image_challenge_id"],
        "image_sequence": BAD_IMG_SEQ, "session_id": sid_b, "application": "college",
    }).status_code == 400
    assert client.post("/api/auth/password-change/verify-image", headers=h_b, json={
        "transaction_id": tx_b, "image_challenge_id": init_b["image_challenge_id"],
        "image_sequence": VALID_IMG_SEQ, "session_id": sid_b, "application": "college",
    }).status_code == 200

    p1 = client.post("/api/auth/password-change/verify-private", headers=h_b, json={
        "transaction_id": tx_b, "private_challenge_id": init_b["private_challenge_id"],
        "private_response": "wrong-answer", "session_id": sid_b, "application": "college",
    })
    assert p1.status_code == 400 and "1 attempt remaining" in p1.json()["detail"].lower()

    p2 = client.post("/api/auth/password-change/verify-private", headers=h_b, json={
        "transaction_id": tx_b, "private_challenge_id": init_b["private_challenge_id"],
        "private_response": "wrong-answer-2", "session_id": sid_b, "application": "college",
    })
    assert p2.status_code == 423
    assert p2.headers.get("X-Cognisec-Locked-Portal") == "college"
    db_session.expire_all()
    assert verify_password(PASS_INIT, db_session.query(User).filter(User.id == u_b.id).first().password_hash) is True


# ==============================================================================
# 4. RE-ENTRY MONITORING, AUTHORIZED ADMIN RECOVERY, AND CRITICAL TERMINATION
# ==============================================================================

def test_reentry_audit_dedupe_notifications_and_admin_recovery_flow(client: TestClient, db_session: Session):
    email = f"reentry_rec_{secrets.token_hex(4)}@example.com"
    user = _create_user_with_factors(db_session, email)
    admin = _create_admin(db_session)
    admin_headers = {"Authorization": f"Bearer {create_access_token(subject=admin.id, role='ADMIN', session_id=None)}"}

    sid, headers, _ = _login_portal(client, db_session, email, "shopping")
    with patch.object(EmailService, "send_otp_email", return_value=(True, "250 OK")):
        req = client.post("/api/auth/login-otp/request", headers=headers, json={"session_id": sid})
    fail = client.post("/api/auth/login-otp/verify", headers=headers, json={
        "session_id": sid, "otp_code": "000000", "challenge_id": req.json()["challenge_id"],
    })
    assert fail.status_code == 423
    sec_ref = fail.headers["X-Cognisec-Security-Ref"]

    # Re-entry on locked portal from credential login or direct reentry endpoint -> 423 + single deduped event per correlation_id
    corr_id = f"corr_{secrets.token_hex(6)}"
    with patch.object(EmailService, "send_portal_security_notification", return_value=(True, "250 OK")):
        r1 = client.post("/api/security/portal-lock/reentry", headers=headers, json={
            "application": "shopping", "session_id": sid,
            "source": "DIRECT_URL", "reentry_correlation_id": corr_id,
        })
        r2 = client.post("/api/security/portal-lock/reentry", headers=headers, json={
            "application": "shopping", "session_id": sid,
            "source": "DIRECT_URL", "reentry_correlation_id": corr_id,
        })
    assert r1.status_code == 200 and r2.status_code == 200

    reentry_events = db_session.query(SecurityEvent).filter(
        SecurityEvent.user_id == user.id,
        SecurityEvent.event_type == "PORTAL_REENTRY_BLOCKED",
    ).all()
    assert len(reentry_events) == 1

    # Credential login to locked shopping -> 423, while healthcare login -> 200
    cred_shop = client.post("/api/auth/login", json={
        "email": email, "password": PASS_INIT, "application": "shopping",
    })
    assert cred_shop.status_code == 423
    cred_hc = client.post("/api/auth/login", json={
        "email": email, "password": PASS_INIT, "application": "healthcare",
    })
    assert cred_hc.status_code == 200

    # Non-admin cannot recover lock
    non_admin_rec = client.post(f"/api/admin/portal-locks/{sec_ref}/recover", headers=headers, json={"notes": "self"})
    assert non_admin_rec.status_code == 403

    # Authorized Admin recovers ONLY shopping lock
    with patch.object(EmailService, "send_portal_security_notification", return_value=(True, "250 OK")):
        rec_res = client.post(f"/api/admin/portal-locks/{sec_ref}/recover", headers=admin_headers, json={
            "notes": "Verified user ownership via SOC ticket",
        })
    assert rec_res.status_code == 200

    db_session.expire_all()
    lock_row = db_session.query(PortalSecurityLock).filter(
        PortalSecurityLock.security_reference_id == sec_ref
    ).first()
    assert lock_row.lock_status == "RECOVERED"

    # Fresh Shopping login starts cleanly at PENDING_OBSERVATION -> requires 20s obs + OTP
    fresh_sid, fresh_headers, fresh_d = _login_portal(client, db_session, email, "shopping", fast_forward_obs=False)
    assert fresh_d["session_status"] == "PENDING_OBSERVATION"
    before_20s = client.post("/api/auth/login-otp/request", headers=fresh_headers, json={"session_id": fresh_sid})
    assert before_20s.status_code == 400


def test_critical_risk_still_synchronously_terminates_entire_session(client: TestClient, db_session: Session):
    email = f"crit_term_{secrets.token_hex(4)}@example.com"
    user = _create_user_with_factors(db_session, email)
    now = datetime.now(timezone.utc)
    sid = f"sess_crit_{secrets.token_hex(4)}"
    db_session.add(DbSession(
        id=sid, user_id=user.id, application="college", status="ACTIVE", current_risk_level="LOW",
        observation_started_at=now - timedelta(seconds=45), observation_completed_at=now - timedelta(seconds=20),
        step_up_verified_at=now, step_up_valid_until=now + timedelta(minutes=15), step_up_factor="EMAIL_OTP",
    ))
    grant = ApplicationGrant(
        session_id=sid, user_id=user.id, application="college", resource="academic_vault",
        factor="EMAIL_OTP", expires_at=now + timedelta(minutes=15), revoked=False,
    )
    db_session.add(grant)
    db_session.commit()
    headers = {"Authorization": f"Bearer {create_access_token(subject=user.id, role=user.role, session_id=sid)}"}

    PortalLockService.terminate_session_and_revoke_grants(
        db=db_session,
        user_id=user.id,
        application="college",
        session_id=sid,
        verification_purpose="RISK_ENGINE",
        factor_key="CRITICAL_RISK",
        reason="CRITICAL behavioral risk anomaly detected (>=0.85)",
    )
    db_session.expire_all()
    sess = db_session.query(DbSession).filter(DbSession.id == sid).first()
    assert sess.status == "TERMINATED"
    assert sess.logout_time is not None
    db_session.refresh(grant)
    assert grant.revoked is True
    assert client.get("/api/auth/me", headers=headers).status_code == 401
