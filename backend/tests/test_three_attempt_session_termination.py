"""
Comprehensive Verification Suite:
Configured Per-Factor Attempt Limits & Portal-Scoped Ejection across Shopping, College, and Healthcare:
  A. Email OTP (1 unsuccessful attempt -> 423 Portal Lock, global session preserved)
  B. NeuralTrace Gesture (3 unsuccessful attempts -> 423 Portal Lock, global session preserved)
  C. Two-part Cognitive Password Change (2 unsuccessful attempts each -> 423 Portal Lock)
  D. Concurrent atomic enforcement capped strictly at each factor's configured max
"""

import secrets
import threading
from concurrent.futures import ThreadPoolExecutor
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
from app.models.portal_lock import VerificationAttemptCounter
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
PASS_INIT = "ThreeLock!2026"


@pytest.fixture(autouse=True)
def clean_state():
    StepUpService.reset()
    rate_limiter.reset()
    yield
    StepUpService.reset()
    rate_limiter.reset()


def _create_user_with_factors(db: Session, email: str, role: str = "USER") -> User:
    user = db.query(User).filter(User.email == email).first()
    if not user:
        user = User(
            name="Factor Limit Test User",
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


def _login_portal(client: TestClient, db: Session, email: str, portal: str, fast_forward_obs: bool = True):
    res = client.post("/api/auth/login", json={
        "email": email,
        "password": PASS_INIT,
        "application": portal,
        "device_fingerprint": f"fp_limit_{portal}_{secrets.token_hex(3)}",
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


def _assert_portal_locked_preserves_global(
    client: TestClient,
    db: Session,
    sid: str,
    user_id: int,
    portal: str,
    vault: str,
    headers: dict,
):
    db.expire_all()
    sess = db.query(DbSession).filter(DbSession.id == sid).first()
    assert sess is not None
    assert sess.status == "RESTRICTED"
    assert sess.logout_time is None
    assert sess.step_up_valid_until is None

    active_grants = db.query(ApplicationGrant).filter(
        ApplicationGrant.session_id == sid,
        ApplicationGrant.revoked == False,
    ).count()
    assert active_grants == 0

    # Global dashboard identity & lock status remain valid (200 OK); portal-scoped profile is 423
    assert client.get("/api/auth/me", headers=headers).status_code == 200
    assert client.get("/api/users/profile", headers=headers).status_code == 423
    locks = client.get(f"/api/security/portal-locks?session_id={sid}", headers=headers)
    assert locks.status_code == 200
    assert locks.json()["portals"][portal]["locked"] is True

    # Locked portal resources & step-up are blocked with 423
    assert client.get(f"/api/security/vault/{vault}?session_id={sid}", headers=headers).status_code == 423
    assert client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": sid, "application": portal, "resource": vault,
    }).status_code == 423


# ==============================================================================
# A. INITIAL EMAIL OTP (ALL 3 PORTALS): 1 ATTEMPT -> 423 PORTAL LOCK & RECOVERY
# ==============================================================================

@pytest.mark.parametrize("portal,vault", [
    ("shopping", "financial_vault"),
    ("college", "academic_vault"),
    ("healthcare", "ehr_vault"),
])
def test_login_otp_one_attempt_expiry_and_admin_recovery(
    client: TestClient, db_session: Session, portal: str, vault: str
):
    email = f"lim_otp_{portal}_{secrets.token_hex(4)}@example.com"
    user = _create_user_with_factors(db_session, email)
    sid, headers, _ = _login_portal(client, db_session, email, portal)

    grant = ApplicationGrant(
        session_id=sid, user_id=user.id, application=portal, resource=vault,
        factor="EMAIL_OTP", expires_at=datetime.now(timezone.utc) + timedelta(minutes=15), revoked=False,
    )
    db_session.add(grant)
    db_session.commit()

    captured = {}

    def spy_otp(recipient_email, otp_code, **kwargs):
        captured["otp"] = otp_code
        return True, "250 OK"

    with patch.object(EmailService, "send_otp_email", side_effect=spy_otp):
        req1 = client.post("/api/auth/login-otp/request", headers=headers, json={"session_id": sid})
        assert req1.status_code == 200
        chal_id_1 = req1.json()["challenge_id"]
        otp_1 = captured["otp"]

        # Expiry must NOT count as a wrong-attempt failure
        chal_obj = StepUpService.get_challenge(sid)
        chal_obj["expires_at"] = datetime.now(timezone.utc) - timedelta(seconds=5)
        exp_res = client.post("/api/auth/login-otp/verify", headers=headers, json={
            "session_id": sid, "otp_code": otp_1, "challenge_id": chal_id_1
        })
        assert exp_res.status_code == 400
        assert "expired" in exp_res.json()["detail"].lower()

        req2 = client.post("/api/auth/login-otp/request", headers=headers, json={"session_id": sid})
        assert req2.status_code == 200
        assert req2.json()["attempts_remaining"] == 1
        chal_id_2 = req2.json()["challenge_id"]

        # 1st wrong attempt -> immediate HTTP 423 Portal Security Lock (global session preserved)
        f1 = client.post("/api/auth/login-otp/verify", headers=headers, json={
            "session_id": sid, "otp_code": "000001", "challenge_id": chal_id_2
        })
        assert f1.status_code == 423
        assert f1.headers.get("X-Cognisec-Portal-Locked") == "true"
        sec_ref = f1.headers["X-Cognisec-Security-Ref"]

    _assert_portal_locked_preserves_global(client, db_session, sid, user.id, portal, vault, headers)
    db_session.refresh(grant)
    assert grant.revoked is True

    # Recover portal via authorized Admin -> fresh login & OTP succeeds cleanly
    admin_user = _create_user_with_factors(db_session, f"adm_{secrets.token_hex(3)}@example.com", role="ADMIN")
    PortalLockService.admin_recover_portal_lock(
        db_session, sec_ref, admin_user, notes="Authorized test recovery"
    )
    sid_fresh, headers_fresh, fresh_login = _login_portal(client, db_session, email, portal)
    assert sid_fresh != sid
    assert fresh_login["session_status"] == "PENDING_OBSERVATION"
    with patch.object(EmailService, "send_otp_email", side_effect=spy_otp):
        req_ok = client.post("/api/auth/login-otp/request", headers=headers_fresh, json={"session_id": sid_fresh})
        assert req_ok.status_code == 200
        ok_ver = client.post("/api/auth/login-otp/verify", headers=headers_fresh, json={
            "session_id": sid_fresh, "otp_code": captured["otp"], "challenge_id": req_ok.json()["challenge_id"]
        })
        assert ok_ver.status_code == 200
        assert ok_ver.json()["session_status"] == "ACTIVE"


# ==============================================================================
# B. NEURALTRACE GESTURE (ALL 3 PORTALS): 3 ATTEMPTS -> 423 PORTAL LOCK
# ==============================================================================

@pytest.mark.parametrize("portal,vault", [
    ("shopping", "financial_vault"),
    ("college", "academic_vault"),
    ("healthcare", "ehr_vault"),
])
def test_neuraltrace_three_attempts_cross_session_and_replay(
    client: TestClient, db_session: Session, portal: str, vault: str
):
    other_portal = "college" if portal != "college" else "shopping"
    other_vault = "academic_vault" if other_portal == "college" else "financial_vault"

    email = f"lim_gest_{portal}_{secrets.token_hex(4)}@example.com"
    user = _create_user_with_factors(db_session, email)

    sid1 = f"sess_g1_{secrets.token_hex(6)}"
    sid2 = f"sess_g2_{secrets.token_hex(6)}"
    now = datetime.now(timezone.utc)
    db_session.add(DbSession(
        id=sid1, user_id=user.id, application=portal, status="ACTIVE", current_risk_level="LOW",
        observation_started_at=now - timedelta(seconds=40), observation_completed_at=now - timedelta(seconds=15),
        step_up_verified_at=now, step_up_valid_until=now + timedelta(minutes=15), step_up_factor="EMAIL_OTP",
    ))
    db_session.add(DbSession(
        id=sid2, user_id=user.id, application=other_portal, status="ACTIVE", current_risk_level="LOW",
        observation_started_at=now - timedelta(seconds=40), observation_completed_at=now - timedelta(seconds=15),
        step_up_verified_at=now, step_up_valid_until=now + timedelta(minutes=15), step_up_factor="EMAIL_OTP",
    ))
    db_session.add(ApplicationGrant(
        session_id=sid1, user_id=user.id, application=portal, resource=vault,
        factor="GESTURE_PATTERN", expires_at=now + timedelta(minutes=15), revoked=False,
    ))
    db_session.commit()
    h1 = {"Authorization": f"Bearer {create_access_token(subject=user.id, role=user.role, session_id=sid1)}"}
    h2 = {"Authorization": f"Bearer {create_access_token(subject=user.id, role=user.role, session_id=sid2)}"}

    c1 = client.post("/api/security/step-up/challenge", headers=h1, json={
        "session_id": sid1, "application": portal, "resource": vault,
        "challenge_purpose": "CONFIDENTIAL_RESOURCE", "preferred_factor": "GESTURE_PATTERN",
    }).json()
    assert c1["attempts_remaining"] == 3

    # Cross-session submission rejected without consuming sid1's attempt counter
    cross = client.post("/api/security/step-up/verify", headers=h2, json={
        "session_id": sid2, "application": other_portal, "resource": other_vault,
        "challenge_id": c1["challenge_id"], "challenge_purpose": "CONFIDENTIAL_RESOURCE",
        "challenge_type": "GESTURE_PATTERN", "gesture_pattern": BAD_GESTURE,
    })
    assert cross.status_code == 400

    # Failure 1 -> 2 remaining
    f1 = client.post("/api/security/step-up/verify", headers=h1, json={
        "session_id": sid1, "application": portal, "resource": vault,
        "challenge_id": c1["challenge_id"], "challenge_purpose": "CONFIDENTIAL_RESOURCE",
        "challenge_type": "GESTURE_PATTERN", "gesture_pattern": BAD_GESTURE,
    })
    assert f1.status_code == 400
    assert "2 attempts remaining" in f1.json()["detail"].lower()

    # Re-requesting challenge keeps counter = 2 remaining
    c1_reopen = client.post("/api/security/step-up/challenge", headers=h1, json={
        "session_id": sid1, "application": portal, "resource": vault,
        "challenge_purpose": "CONFIDENTIAL_RESOURCE", "preferred_factor": "GESTURE_PATTERN",
    }).json()
    assert c1_reopen["attempts_remaining"] == 2

    # Failure 2 -> 1 remaining
    f2 = client.post("/api/security/step-up/verify", headers=h1, json={
        "session_id": sid1, "application": portal, "resource": vault,
        "challenge_id": c1_reopen["challenge_id"], "challenge_purpose": "CONFIDENTIAL_RESOURCE",
        "challenge_type": "GESTURE_PATTERN", "gesture_pattern": BAD_GESTURE,
    })
    assert f2.status_code == 400
    assert "1 attempt remaining" in f2.json()["detail"].lower()

    # Failure 3 -> 423 Portal Security Lock
    f3 = client.post("/api/security/step-up/verify", headers=h1, json={
        "session_id": sid1, "application": portal, "resource": vault,
        "challenge_id": c1_reopen["challenge_id"], "challenge_purpose": "CONFIDENTIAL_RESOURCE",
        "challenge_type": "GESTURE_PATTERN", "gesture_pattern": BAD_GESTURE,
    })
    assert f3.status_code == 423
    assert f3.headers.get("X-Cognisec-Portal-Locked") == "true"

    _assert_portal_locked_preserves_global(client, db_session, sid1, user.id, portal, vault, h1)

    # Other portal remains unlocked & works on 1st valid gesture attempt
    c2 = client.post("/api/security/step-up/challenge", headers=h2, json={
        "session_id": sid2, "application": other_portal, "resource": other_vault,
        "challenge_purpose": "CONFIDENTIAL_RESOURCE", "preferred_factor": "GESTURE_PATTERN",
    }).json()
    ok2 = client.post("/api/security/step-up/verify", headers=h2, json={
        "session_id": sid2, "application": other_portal, "resource": other_vault,
        "challenge_id": c2["challenge_id"], "challenge_purpose": "CONFIDENTIAL_RESOURCE",
        "challenge_type": "GESTURE_PATTERN", "gesture_pattern": VALID_GESTURE,
    })
    assert ok2.status_code == 200
    assert ok2.json()["decision"] == "ALLOW"


# ==============================================================================
# C. TWO-PART COGNITIVE PASSWORD CHANGE (ALL 3 PORTALS): 2 ATTEMPTS -> 423 LOCK
# ==============================================================================

@pytest.mark.parametrize("portal,vault", [
    ("shopping", "financial_vault"),
    ("college", "academic_vault"),
    ("healthcare", "ehr_vault"),
])
def test_cognitive_password_change_two_attempts_restart_and_lockout(
    client: TestClient, db_session: Session, portal: str, vault: str
):
    email = f"lim_cog_{portal}_{secrets.token_hex(4)}@example.com"
    user = _create_user_with_factors(db_session, email)
    orig_hash = user.password_hash

    sid = f"sess_cp2_{secrets.token_hex(6)}"
    now = datetime.now(timezone.utc)
    db_session.add(DbSession(
        id=sid, user_id=user.id, application=portal, status="ACTIVE", current_risk_level="LOW",
        observation_started_at=now - timedelta(seconds=40), observation_completed_at=now - timedelta(seconds=15),
        step_up_verified_at=now, step_up_valid_until=now + timedelta(minutes=15), step_up_factor="EMAIL_OTP",
    ))
    db_session.add(ApplicationGrant(
        session_id=sid, user_id=user.id, application=portal, resource=vault,
        factor="GESTURE_PATTERN", expires_at=now + timedelta(minutes=15), revoked=False,
    ))
    db_session.commit()
    headers = {"Authorization": f"Bearer {create_access_token(subject=user.id, role=user.role, session_id=sid)}"}

    init1 = client.post("/api/auth/password-change/initiate", headers=headers, json={
        "current_password": PASS_INIT, "session_id": sid, "application": portal
    }).json()
    assert init1["image_attempts_remaining"] == 2
    tx1 = init1["transaction_id"]

    # 1st wrong image -> 1 remaining
    f1 = client.post("/api/auth/password-change/verify-image", headers=headers, json={
        "transaction_id": tx1, "image_challenge_id": init1["image_challenge_id"],
        "image_sequence": BAD_IMG_SEQ, "session_id": sid, "application": portal,
    })
    assert f1.status_code == 400 and "1 attempt remaining" in f1.json()["detail"].lower()

    # Restarting transaction preserves counter = 1 remaining
    init2 = client.post("/api/auth/password-change/initiate", headers=headers, json={
        "current_password": PASS_INIT, "session_id": sid, "application": portal
    }).json()
    assert init2["image_attempts_remaining"] == 1
    tx2 = init2["transaction_id"]

    # 2nd wrong image -> 423 Portal Security Lock, password unchanged
    f2 = client.post("/api/auth/password-change/verify-image", headers=headers, json={
        "transaction_id": tx2, "image_challenge_id": init2["image_challenge_id"],
        "image_sequence": BAD_IMG_SEQ, "session_id": sid, "application": portal,
    })
    assert f2.status_code == 423
    assert f2.headers.get("X-Cognisec-Portal-Locked") == "true"

    _assert_portal_locked_preserves_global(client, db_session, sid, user.id, portal, vault, headers)
    db_session.refresh(user)
    assert user.password_hash == orig_hash
    assert verify_password(PASS_INIT, user.password_hash) is True
    tx2_row = db_session.query(PasswordChangeTransaction).filter(
        PasswordChangeTransaction.transaction_id == tx2
    ).first()
    assert tx2_row.status == "LOCKED" and tx2_row.is_consumed is True


# ==============================================================================
# D. CONCURRENT ATOMIC ENFORCEMENT ACROSS ALL 3 AUTHENTICATION TYPES
# ==============================================================================

@pytest.mark.parametrize("purpose,factor,expected_limit", [
    ("LOGIN_OTP", "EMAIL_OTP", 1),
    ("CONFIDENTIAL_RESOURCE", "GESTURE_PATTERN", 3),
    ("PASSWORD_CHANGE", "PRIVATE_RESPONSE", 2),
])
def test_concurrent_failures_strictly_capped_atomic(
    db_session: Session, purpose: str, factor: str, expected_limit: int
):
    from app.database.connection import SessionLocal

    email = f"conc_lim_{purpose}_{secrets.token_hex(4)}@example.com"
    user = _create_user_with_factors(db_session, email)
    user_id = user.id
    sid = f"sess_conc_l_{secrets.token_hex(6)}"
    db_session.add(DbSession(id=sid, user_id=user_id, application="shopping", status="PENDING_OTP" if purpose == "LOGIN_OTP" else "ACTIVE"))
    db_session.commit()

    results = []
    barrier = threading.Barrier(5)

    def worker():
        db = SessionLocal()
        try:
            barrier.wait(timeout=5)
            out = PortalLockService.record_verification_failure(
                db=db,
                user_id=user_id,
                application="shopping",
                verification_purpose=purpose,
                factor_key=factor,
                session_id=sid,
            )
            results.append(out)
        finally:
            db.close()

    with ThreadPoolExecutor(max_workers=5) as pool:
        futs = [pool.submit(worker) for _ in range(5)]
        for fut in futs:
            fut.result()

    db_session.expire_all()
    cnt = db_session.query(VerificationAttemptCounter).filter(
        VerificationAttemptCounter.user_id == user_id,
        VerificationAttemptCounter.session_id == sid,
        VerificationAttemptCounter.verification_purpose == purpose,
        VerificationAttemptCounter.factor_key == factor,
    ).first()
    assert cnt is not None
    assert cnt.attempts == expected_limit
    sess = db_session.query(DbSession).filter(DbSession.id == sid).first()
    assert sess.status == "RESTRICTED"
    assert sess.logout_time is None
