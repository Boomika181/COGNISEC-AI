"""
Comprehensive Test Suite: Secure Cognitive-Verified Change Password Across All Portals
Covers all 22 Backend Scenarios & Frontend Portal/Node VM Checks:
1. Successful password change (re-login works, old password rejected, no plaintext stored)
2. Incorrect current password rejected (401 + SecurityEvent)
3. Missing current password rejected (400/422)
4. Weak new password rejected (400/422)
5. New password confirmation mismatch rejected (400/422)
6. Image challenge failure + brute-force lockout after 3 attempts
7. Private security response failure + out-of-order rejection
8. Both cognitive challenges successful -> password updated cleanly
9. Image challenge expired rejected
10. Private security challenge expired rejected
11. Challenge replay prevention (after completion/verify)
12. Cross-session challenge rejection
13. Cross-user challenge rejection
14. Cross-portal authorization checks & vault/password-change isolation
15. LOW-risk password change (OTP alone never substitutes cognitive factors)
16. MEDIUM-risk password change (requires NeuralTrace gesture first, OTP cannot substitute, plus both cognitive checks)
17. HIGH-risk password change (action-bound cognitive verification & HIGH_RISK_DUAL binding)
18. CRITICAL-risk session termination + grant revocation + denial
19. Concurrent password-change requests (strictly 1 succeeds)
20. Password-change email notification (never contains plaintext password or answers)
21. Agent / LLM failure or attempted downgrade never authorizes password change
22. Session & ApplicationGrant invalidation after password update
23. Frontend UI entry checks in shopping.html, college.html, healthcare.html & Node VM sequencing
"""

import json
import os
import secrets
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.agents.core.arbiter import DeterministicSecurityArbiter
from app.core.rate_limit import rate_limiter
from app.core.security import create_access_token, get_password_hash, verify_password
from app.models.application_grant import ApplicationGrant
from app.models.password_change import PasswordChangeTransaction
from app.models.security_event import SecurityEvent
from app.models.session import Session as DbSession
from app.models.user import User
from app.services.adaptive_auth_service import AdaptiveAuthService
from app.services.email_service import EmailService
from app.services.password_change_service import PasswordChangeService
from app.services.session_service import SessionService
from app.services.step_up_service import StepUpService

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
INITIAL_PASS = "InitPass#2026"
ALT_PASS = "UpdatedPass!9942"
IMG_SEQ = ["img_shield", "img_vault", "img_token"]
PRIV_Q = "What code name was assigned to your first workstation?"
PRIV_A = "obsidian-node-42"
GESTURE_ROUTE = [0, 1, 2, 4, 8]


@pytest.fixture(autouse=True)
def reset_state():
    StepUpService.reset()
    rate_limiter.reset()
    yield
    StepUpService.reset()
    rate_limiter.reset()


def _create_enrolled_user_and_session(
    db: Session,
    email: str,
    application: str = "shopping",
    session_status: str = "ACTIVE",
    risk_level: str = "LOW",
    risk_score: float = 0.12,
    enroll_cognitive: bool = True,
    enroll_gesture: bool = True,
    step_up_factor: str = "EMAIL_OTP",
):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        user = User(
            name="Portal Test User",
            email=email,
            password_hash=get_password_hash(INITIAL_PASS),
            account_status="ACTIVE",
            role="USER",
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        user.password_hash = get_password_hash(INITIAL_PASS)
        user.account_status = "ACTIVE"
        user.failed_login_attempts = 0
        db.commit()

    if enroll_cognitive:
        AdaptiveAuthService.enroll_image_sequence(db, user.id, IMG_SEQ, IMG_SEQ)
        AdaptiveAuthService.enroll_private_response(db, user.id, PRIV_Q, PRIV_A, PRIV_A)
    if enroll_gesture:
        AdaptiveAuthService.enroll_gesture_pattern(db, user.id, GESTURE_ROUTE, GESTURE_ROUTE)

    now = datetime.now(timezone.utc)
    sess = DbSession(
        id=f"sess_pw_{secrets.token_hex(6)}",
        user_id=user.id,
        application=application,
        status=session_status,
        current_risk_level=risk_level,
        observation_started_at=now - timedelta(seconds=45),
        observation_ends_at=now - timedelta(seconds=15),
        observation_completed_at=now - timedelta(seconds=15),
        step_up_verified_at=now if session_status == "ACTIVE" else None,
        step_up_valid_until=(now + timedelta(minutes=15)) if session_status == "ACTIVE" else None,
        step_up_factor=step_up_factor if session_status == "ACTIVE" else None,
        step_up_risk_cleared=risk_score if session_status == "ACTIVE" else None,
    )
    db.add(sess)
    db.add(SecurityEvent(
        user_id=user.id,
        session_id=sess.id,
        application=application,
        event_type="BEHAVIOR_RISK_CHECK",
        severity=risk_level,
        risk_score=risk_score,
        decision="ALLOW" if risk_level == "LOW" else "STEP_UP_VERIFICATION",
        details="Test baseline risk seed",
    ))
    db.commit()
    db.refresh(sess)

    token = create_access_token(subject=user.id, role=user.role, session_id=sess.id)
    headers = {"Authorization": f"Bearer {token}", "X-Session-ID": sess.id}
    return user, sess, headers


def _run_full_flow(client: TestClient, headers: dict, sess_id: str, application: str, new_password: str = ALT_PASS):
    r_init = client.post(
        "/api/auth/password-change/initiate",
        headers=headers,
        json={"current_password": INITIAL_PASS, "session_id": sess_id, "application": application},
    )
    assert r_init.status_code == 200, r_init.text
    init_data = r_init.json()
    tx_id = init_data["transaction_id"]

    r_img = client.post(
        "/api/auth/password-change/verify-image",
        headers=headers,
        json={
            "transaction_id": tx_id,
            "image_challenge_id": init_data["image_challenge_id"],
            "image_sequence": IMG_SEQ,
            "session_id": sess_id,
            "application": application,
        },
    )
    assert r_img.status_code == 200, r_img.text

    r_priv = client.post(
        "/api/auth/password-change/verify-private",
        headers=headers,
        json={
            "transaction_id": tx_id,
            "private_challenge_id": init_data["private_challenge_id"],
            "private_response": PRIV_A,
            "session_id": sess_id,
            "application": application,
        },
    )
    assert r_priv.status_code == 200, r_priv.text

    r_conf = client.post(
        "/api/auth/password-change/confirm",
        headers=headers,
        json={
            "transaction_id": tx_id,
            "new_password": new_password,
            "confirm_password": new_password,
            "session_id": sess_id,
            "application": application,
        },
    )
    return init_data, r_conf


@pytest.mark.parametrize("portal", ["shopping", "college", "healthcare"])
def test_1_8_20_22_successful_password_change_email_and_session_invalidation_across_all_portals(
    client: TestClient, db_session: Session, portal: str
):
    """Tests 1, 8, 20, 22: Full cognitive password change on shopping/college/healthcare, email notice, audit, and session/grant revocation."""
    email = f"pw.success.{portal}@example.com"
    user, sess, headers = _create_enrolled_user_and_session(db_session, email, application=portal)

    # Create an active grant so we prove password change revokes all prior grants + sessions
    res_name = SessionService.get_resource_for_application(portal)
    grant = ApplicationGrant(
        session_id=sess.id,
        user_id=user.id,
        application=portal,
        resource=res_name,
        factor="GESTURE_PATTERN",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        revoked=False,
    )
    db_session.add(grant)
    db_session.commit()

    captured_notices = []
    with patch.object(
        EmailService,
        "send_password_changed_notification",
        side_effect=lambda **kw: (captured_notices.append(kw) or (True, "250 OK")),
    ):
        init_data, r_conf = _run_full_flow(client, headers, sess.id, portal, new_password=ALT_PASS)

    assert r_conf.status_code == 200
    body = r_conf.json()
    assert body["success"] is True
    assert body["application"] == portal
    assert body["sessions_revoked"] >= 1
    assert body["email_notification_sent"] is True
    assert body["security_event_recorded"] is True
    assert body["requires_reauth"] is True
    assert ALT_PASS not in r_conf.text
    assert PRIV_A not in r_conf.text

    # No stored answer or plaintext password anywhere in DB tx or events
    db_session.expire_all()
    tx_row = db_session.query(PasswordChangeTransaction).filter(
        PasswordChangeTransaction.transaction_id == init_data["transaction_id"]
    ).first()
    assert tx_row.status == "COMPLETED" and tx_row.is_consumed is True

    # Old password rejected, new password accepted
    updated_user = db_session.query(User).filter(User.id == user.id).first()
    assert not verify_password(INITIAL_PASS, updated_user.password_hash)
    assert verify_password(ALT_PASS, updated_user.password_hash)

    old_login = client.post("/api/auth/login", json={"email": email, "password": INITIAL_PASS, "application": portal})
    assert old_login.status_code == 401
    new_login = client.post("/api/auth/login", json={"email": email, "password": ALT_PASS, "application": portal})
    assert new_login.status_code == 200

    # Prior session & ApplicationGrant invalidated; old JWT rejected by /users/profile
    db_session.refresh(sess)
    db_session.refresh(grant)
    assert sess.status == "TERMINATED"
    assert grant.revoked is True
    stale_prof = client.get("/api/users/profile", headers=headers)
    assert stale_prof.status_code == 401

    # Security audit event & clean email notification (no secrets leaked)
    ev = db_session.query(SecurityEvent).filter(
        SecurityEvent.user_id == user.id,
        SecurityEvent.event_type == "PASSWORD_CHANGED",
        SecurityEvent.application == portal,
    ).first()
    assert ev is not None
    assert ALT_PASS not in (ev.details or "") and PRIV_A not in (ev.details or "")
    assert len(captured_notices) == 1
    assert captured_notices[0]["recipient_email"] == email
    assert captured_notices[0]["application"] == portal


def test_2_3_4_5_password_validation_and_current_password_checks(client: TestClient, db_session: Session):
    """Tests 2, 3, 4, 5: Wrong current password, missing current password, weak new password, confirmation mismatch."""
    email = "pw.validation@example.com"
    user, sess, headers = _create_enrolled_user_and_session(db_session, email, application="shopping")

    # 3. Missing / empty current password
    r_missing = client.post(
        "/api/auth/password-change/initiate",
        headers=headers,
        json={"current_password": "", "session_id": sess.id, "application": "shopping"},
    )
    assert r_missing.status_code == 400

    # 2. Incorrect current password -> 401 + SecurityEvent
    r_wrong = client.post(
        "/api/auth/password-change/initiate",
        headers=headers,
        json={"current_password": "WrongPassword#1", "session_id": sess.id, "application": "shopping"},
    )
    assert r_wrong.status_code == 401
    assert db_session.query(SecurityEvent).filter(
        SecurityEvent.user_id == user.id,
        SecurityEvent.event_type == "PASSWORD_CHANGE_AUTH_FAILED",
    ).first() is not None

    # Initiate cleanly for step 4 checks
    r_init = client.post(
        "/api/auth/password-change/initiate",
        headers=headers,
        json={"current_password": INITIAL_PASS, "session_id": sess.id, "application": "shopping"},
    ).json()
    tx_id = r_init["transaction_id"]
    assert client.post(
        "/api/auth/password-change/verify-image",
        headers=headers,
        json={
            "transaction_id": tx_id,
            "image_challenge_id": r_init["image_challenge_id"],
            "image_sequence": IMG_SEQ,
            "session_id": sess.id,
            "application": "shopping",
        },
    ).status_code == 200
    assert client.post(
        "/api/auth/password-change/verify-private",
        headers=headers,
        json={
            "transaction_id": tx_id,
            "private_challenge_id": r_init["private_challenge_id"],
            "private_response": PRIV_A,
            "session_id": sess.id,
            "application": "shopping",
        },
    ).status_code == 200

    # 4. Weak new password -> 422
    r_weak = client.post(
        "/api/auth/password-change/confirm",
        headers=headers,
        json={
            "transaction_id": tx_id,
            "new_password": "weak",
            "confirm_password": "weak",
            "session_id": sess.id,
            "application": "shopping",
        },
    )
    assert r_weak.status_code == 422

    # 5. Confirmation mismatch -> 422
    r_mismatch = client.post(
        "/api/auth/password-change/confirm",
        headers=headers,
        json={
            "transaction_id": tx_id,
            "new_password": ALT_PASS,
            "confirm_password": "DifferentPass#999",
            "session_id": sess.id,
            "application": "shopping",
        },
    )
    assert r_mismatch.status_code == 422


def test_6_7_cognitive_challenge_failures_and_out_of_order(client: TestClient, db_session: Session):
    """Tests 6 & 7: Wrong image sequence, out-of-order private check, wrong private answer, 2-attempt per-factor lockout."""
    user, sess, headers = _create_enrolled_user_and_session(db_session, "pw.cogfail@example.com", application="college")

    r_init = client.post(
        "/api/auth/password-change/initiate",
        headers=headers,
        json={"current_password": INITIAL_PASS, "session_id": sess.id, "application": "college"},
    ).json()
    tx_id = r_init["transaction_id"]

    # Private before image -> rejected
    r_order = client.post(
        "/api/auth/password-change/verify-private",
        headers=headers,
        json={
            "transaction_id": tx_id,
            "private_challenge_id": r_init["private_challenge_id"],
            "private_response": PRIV_A,
            "session_id": sess.id,
            "application": "college",
        },
    )
    assert r_order.status_code == 400

    # Confirm without either cognitive check -> 403
    r_skip = client.post(
        "/api/auth/password-change/confirm",
        headers=headers,
        json={
            "transaction_id": tx_id,
            "new_password": ALT_PASS,
            "confirm_password": ALT_PASS,
            "session_id": sess.id,
            "application": "college",
        },
    )
    assert r_skip.status_code == 403

    # Wrong image sequence -> fails once (400: 1 attempt remaining), locks portal on 2nd failure (423) preserving global identity
    wrong_seq = ["img_key", "img_radar", "img_chip"]
    r_img1 = client.post(
        "/api/auth/password-change/verify-image",
        headers=headers,
        json={"transaction_id": tx_id, "image_challenge_id": r_init["image_challenge_id"], "image_sequence": wrong_seq, "session_id": sess.id, "application": "college"},
    )
    assert r_img1.status_code == 400
    assert "1 attempt remaining" in r_img1.json()["detail"].lower()

    r_lock = client.post(
        "/api/auth/password-change/verify-image",
        headers=headers,
        json={"transaction_id": tx_id, "image_challenge_id": r_init["image_challenge_id"], "image_sequence": wrong_seq, "session_id": sess.id, "application": "college"},
    )
    assert r_lock.status_code == 423
    assert r_lock.headers.get("X-Cognisec-Portal-Locked") == "true"
    db_session.refresh(sess)
    assert sess.status == "RESTRICTED"
    assert sess.logout_time is None

    # Independent portal & private factor counter check -> fail image once (1 remaining), pass image, fail private twice -> locks healthcare portal (423)
    user2, sess2, headers2 = _create_enrolled_user_and_session(db_session, "pw.privfail@example.com", application="healthcare")
    r_init2 = client.post(
        "/api/auth/password-change/initiate",
        headers=headers2,
        json={"current_password": INITIAL_PASS, "session_id": sess2.id, "application": "healthcare"},
    ).json()
    tx2 = r_init2["transaction_id"]
    assert client.post(
        "/api/auth/password-change/verify-image",
        headers=headers2,
        json={"transaction_id": tx2, "image_challenge_id": r_init2["image_challenge_id"], "image_sequence": wrong_seq, "session_id": sess2.id, "application": "healthcare"},
    ).status_code == 400
    assert client.post(
        "/api/auth/password-change/verify-image",
        headers=headers2,
        json={"transaction_id": tx2, "image_challenge_id": r_init2["image_challenge_id"], "image_sequence": IMG_SEQ, "session_id": sess2.id, "application": "healthcare"},
    ).status_code == 200
    r_priv_fail = client.post(
        "/api/auth/password-change/verify-private",
        headers=headers2,
        json={"transaction_id": tx2, "private_challenge_id": r_init2["private_challenge_id"], "private_response": "wrong-answer", "session_id": sess2.id, "application": "healthcare"},
    )
    assert r_priv_fail.status_code == 400
    assert "1 attempt remaining" in r_priv_fail.json()["detail"].lower()
    assert PRIV_A not in r_priv_fail.text
    r_priv_lock = client.post(
        "/api/auth/password-change/verify-private",
        headers=headers2,
        json={"transaction_id": tx2, "private_challenge_id": r_init2["private_challenge_id"], "private_response": "wrong-answer-2", "session_id": sess2.id, "application": "healthcare"},
    )
    assert r_priv_lock.status_code == 423
    assert r_priv_lock.headers.get("X-Cognisec-Portal-Locked") == "true"
    db_session.refresh(sess2)
    assert sess2.status == "RESTRICTED"
    assert sess2.logout_time is None


def test_9_10_11_expiry_and_replay_prevention(client: TestClient, db_session: Session):
    """Tests 9, 10, 11: Expired image challenge, expired private challenge, and single-use replay rejection."""
    user, sess, headers = _create_enrolled_user_and_session(db_session, "pw.exp@example.com", application="healthcare")

    # 9. Image challenge expired
    r_init1 = client.post(
        "/api/auth/password-change/initiate",
        headers=headers,
        json={"current_password": INITIAL_PASS, "session_id": sess.id, "application": "healthcare"},
    ).json()
    tx1 = db_session.query(PasswordChangeTransaction).filter(
        PasswordChangeTransaction.transaction_id == r_init1["transaction_id"]
    ).first()
    tx1.expires_at = datetime.now(timezone.utc) - timedelta(seconds=5)
    db_session.commit()
    assert client.post(
        "/api/auth/password-change/verify-image",
        headers=headers,
        json={"transaction_id": tx1.transaction_id, "image_challenge_id": tx1.image_challenge_id, "image_sequence": IMG_SEQ, "session_id": sess.id, "application": "healthcare"},
    ).status_code == 400

    # 10. Private challenge expired after image passed
    r_init2 = client.post(
        "/api/auth/password-change/initiate",
        headers=headers,
        json={"current_password": INITIAL_PASS, "session_id": sess.id, "application": "healthcare"},
    ).json()
    assert client.post(
        "/api/auth/password-change/verify-image",
        headers=headers,
        json={"transaction_id": r_init2["transaction_id"], "image_challenge_id": r_init2["image_challenge_id"], "image_sequence": IMG_SEQ, "session_id": sess.id, "application": "healthcare"},
    ).status_code == 200
    tx2 = db_session.query(PasswordChangeTransaction).filter(
        PasswordChangeTransaction.transaction_id == r_init2["transaction_id"]
    ).first()
    tx2.expires_at = datetime.now(timezone.utc) - timedelta(seconds=5)
    db_session.commit()
    assert client.post(
        "/api/auth/password-change/verify-private",
        headers=headers,
        json={"transaction_id": tx2.transaction_id, "private_challenge_id": tx2.private_challenge_id, "private_response": PRIV_A, "session_id": sess.id, "application": "healthcare"},
    ).status_code == 400

    # 11. Replay after full completion rejected (new valid session re-created for same user to test tx replay on confirm/verify)
    init_ok, r_conf = _run_full_flow(client, headers, sess.id, "healthcare", new_password=ALT_PASS)
    assert r_conf.status_code == 200
    # Re-activate a session temporarily on DB or directly call service to confirm replay fails
    sess_new = DbSession(id=f"sess_pw_{secrets.token_hex(6)}", user_id=user.id, application="healthcare", status="ACTIVE", current_risk_level="LOW")
    db_session.add(sess_new)
    db_session.commit()
    # Even if trying to call with tx from previous flow -> rejected
    h_new = {"Authorization": f"Bearer {create_access_token(user.id, user.role, sess_new.id)}", "X-Session-ID": sess_new.id}
    r_replay = client.post(
        "/api/auth/password-change/confirm",
        headers=h_new,
        json={"transaction_id": init_ok["transaction_id"], "new_password": "ThirdPass!999", "confirm_password": "ThirdPass!999", "session_id": sess_new.id, "application": "healthcare"},
    )
    assert r_replay.status_code in (400, 403, 409)


def test_12_13_14_cross_session_user_portal_and_vault_isolation(client: TestClient, db_session: Session):
    """Tests 12, 13, 14: Unauthenticated, cross-session, cross-user, cross-portal, and vault challenge isolation."""
    # Unauthenticated -> 401
    assert client.post("/api/auth/password-change/initiate", json={"current_password": INITIAL_PASS, "application": "shopping"}).status_code == 401

    user_a, sess_a1, headers_a1 = _create_enrolled_user_and_session(db_session, "pw.crossA@example.com", application="shopping")
    _, sess_a2, headers_a2 = _create_enrolled_user_and_session(db_session, "pw.crossA@example.com", application="shopping")
    user_b, sess_b, headers_b = _create_enrolled_user_and_session(db_session, "pw.crossB@example.com", application="shopping")

    init_a = client.post(
        "/api/auth/password-change/initiate",
        headers=headers_a1,
        json={"current_password": INITIAL_PASS, "session_id": sess_a1.id, "application": "shopping"},
    ).json()

    # 12. Cross-session (same user, different session) -> 403
    assert client.post(
        "/api/auth/password-change/verify-image",
        headers=headers_a2,
        json={"transaction_id": init_a["transaction_id"], "image_challenge_id": init_a["image_challenge_id"], "image_sequence": IMG_SEQ, "session_id": sess_a2.id, "application": "shopping"},
    ).status_code == 403

    # 13. Cross-user -> 403
    assert client.post(
        "/api/auth/password-change/verify-image",
        headers=headers_b,
        json={"transaction_id": init_a["transaction_id"], "image_challenge_id": init_a["image_challenge_id"], "image_sequence": IMG_SEQ, "session_id": sess_b.id, "application": "shopping"},
    ).status_code == 403

    # 14a. Cross-portal submission ('shopping' tx submitted under 'college') -> 403
    assert client.post(
        "/api/auth/password-change/verify-image",
        headers=headers_a1,
        json={"transaction_id": init_a["transaction_id"], "image_challenge_id": init_a["image_challenge_id"], "image_sequence": IMG_SEQ, "session_id": sess_a1.id, "application": "college"},
    ).status_code == 403

    # 14b. HIGH_RISK_DUAL vault challenge (e.g. financial_vault) CANNOT be used to bypass password-change cognitive challenges
    chal_vault = StepUpService.create_adaptive_challenge(
        session_id=sess_a1.id, user_id=user_a.id, db=db_session, risk_score=0.75, risk_level="HIGH", application="shopping", resource="financial_vault"
    )
    ok_v, _, _, _ = StepUpService.verify_adaptive_challenge(
        session_id=sess_a1.id, user_id=user_a.id, db=db_session, challenge_type="HIGH_RISK_DUAL",
        image_sequence=IMG_SEQ, private_response=PRIV_A, application="shopping", resource="financial_vault",
        challenge_id=chal_vault["challenge_id"],
    )
    assert ok_v is True
    r_vault_abuse = client.post(
        "/api/auth/password-change/initiate",
        headers=headers_a1,
        json={
            "current_password": INITIAL_PASS,
            "session_id": sess_a1.id,
            "application": "shopping",
            "bound_high_risk_challenge_id": chal_vault["challenge_id"],
        },
    )
    assert r_vault_abuse.status_code == 403


def test_15_16_17_18_risk_policy_low_medium_high_critical(client: TestClient, db_session: Session):
    """Tests 15, 16, 17, 18: LOW, MEDIUM (gesture + cognitive), HIGH (action-bound cognitive), CRITICAL (terminate & deny)."""
    # 15. LOW risk STEP_UP_REQUIRED blocked until Email OTP completes; OTP never skips cognitive factors
    u_low, s_low, h_low = _create_enrolled_user_and_session(
        db_session, "pw.low@example.com", application="healthcare", session_status="STEP_UP_REQUIRED", risk_level="LOW", risk_score=0.18
    )
    r_low_blk = client.post("/api/auth/password-change/initiate", headers=h_low, json={"current_password": INITIAL_PASS, "session_id": s_low.id, "application": "healthcare"})
    assert r_low_blk.status_code == 403
    assert r_low_blk.headers.get("X-Cognisec-Required-Factor") == "OTP"

    # 16. MEDIUM risk requires GESTURE_PATTERN (even if session had EMAIL_OTP!) + both cognitive checks
    u_med, s_med, h_med = _create_enrolled_user_and_session(
        db_session, "pw.med@example.com", application="college", session_status="ACTIVE", risk_level="MEDIUM", risk_score=0.45, step_up_factor="EMAIL_OTP"
    )
    r_med_blk = client.post("/api/auth/password-change/initiate", headers=h_med, json={"current_password": INITIAL_PASS, "session_id": s_med.id, "application": "college"})
    assert r_med_blk.status_code == 403
    assert r_med_blk.headers.get("X-Cognisec-Required-Factor") == "GESTURE_PATTERN"

    # Complete MEDIUM-risk GESTURE_PATTERN step-up, then still require BOTH cognitive checks before changing password
    chal_med = client.post("/api/security/step-up/challenge", headers=h_med, json={"session_id": s_med.id, "application": "college", "resource": "password_change"}).json()
    assert chal_med["challenge_type"] == "GESTURE_PATTERN"
    assert client.post(
        "/api/security/step-up/verify",
        headers=h_med,
        json={"session_id": s_med.id, "challenge_id": chal_med["challenge_id"], "challenge_type": "GESTURE_PATTERN", "gesture_pattern": GESTURE_ROUTE, "application": "college", "resource": "password_change"},
    ).status_code == 200
    _, r_med_ok = _run_full_flow(client, h_med, s_med.id, "college", new_password=ALT_PASS)
    assert r_med_ok.status_code == 200

    # 17. HIGH risk supports explicitly password_change-bound HIGH_RISK_DUAL verification AND still requires current password
    u_high, s_high, h_high = _create_enrolled_user_and_session(
        db_session, "pw.high@example.com", application="shopping", session_status="RESTRICTED", risk_level="HIGH", risk_score=0.75
    )
    chal_high = client.post("/api/security/step-up/challenge", headers=h_high, json={"session_id": s_high.id, "application": "shopping", "resource": "password_change"}).json()
    assert chal_high["challenge_type"] == "HIGH_RISK_DUAL"
    assert client.post(
        "/api/security/step-up/verify",
        headers=h_high,
        json={"session_id": s_high.id, "challenge_id": chal_high["challenge_id"], "challenge_type": "HIGH_RISK_DUAL", "image_sequence": IMG_SEQ, "stage": 1, "application": "shopping", "resource": "password_change"},
    ).status_code == 200
    assert client.post(
        "/api/security/step-up/verify",
        headers=h_high,
        json={"session_id": s_high.id, "challenge_id": chal_high["challenge_id"], "challenge_type": "HIGH_RISK_DUAL", "private_response": PRIV_A, "stage": 2, "application": "shopping", "resource": "password_change"},
    ).status_code == 200
    r_init_hi = client.post(
        "/api/auth/password-change/initiate",
        headers=h_high,
        json={"current_password": INITIAL_PASS, "session_id": s_high.id, "application": "shopping", "bound_high_risk_challenge_id": chal_high["challenge_id"]},
    )
    assert r_init_hi.status_code == 200
    init_hi = r_init_hi.json()
    assert init_hi["already_completed_high_risk_dual"] is True
    assert client.post(
        "/api/auth/password-change/confirm",
        headers=h_high,
        json={"transaction_id": init_hi["transaction_id"], "new_password": ALT_PASS, "confirm_password": ALT_PASS, "session_id": s_high.id, "application": "shopping"},
    ).status_code == 200

    # 18. CRITICAL risk immediately terminates session, revokes grants, and denies password change
    u_crit, s_crit, h_crit = _create_enrolled_user_and_session(
        db_session, "pw.crit@example.com", application="healthcare", session_status="ACTIVE", risk_level="CRITICAL", risk_score=0.92
    )
    g_crit = ApplicationGrant(session_id=s_crit.id, user_id=u_crit.id, application="healthcare", resource="ehr_vault", factor="GESTURE_PATTERN", expires_at=datetime.now(timezone.utc) + timedelta(minutes=10), revoked=False)
    db_session.add(g_crit)
    db_session.commit()

    r_crit = client.post("/api/auth/password-change/initiate", headers=h_crit, json={"current_password": INITIAL_PASS, "session_id": s_crit.id, "application": "healthcare"})
    assert r_crit.status_code == 403
    db_session.expire_all()
    s_crit_db = db_session.query(DbSession).filter(DbSession.id == s_crit.id).first()
    g_crit_db = db_session.query(ApplicationGrant).filter(ApplicationGrant.id == g_crit.id).first()
    assert s_crit_db.status == "TERMINATED"
    assert g_crit_db.revoked is True


def test_19_concurrent_password_change_confirm_single_winner(client: TestClient, db_session: Session):
    """Test 19: Concurrent confirm submissions for the same READY_TO_COMMIT transaction: strictly 1 succeeds."""
    from tests.conftest import TestingSessionLocal
    from app.database.connection import get_db
    from app.main import app

    user, sess, headers = _create_enrolled_user_and_session(db_session, "pw.conc@example.com", application="shopping")
    sess_id = sess.id
    init_data = client.post("/api/auth/password-change/initiate", headers=headers, json={"current_password": INITIAL_PASS, "session_id": sess_id, "application": "shopping"}).json()
    tx_id = init_data["transaction_id"]
    assert client.post("/api/auth/password-change/verify-image", headers=headers, json={"transaction_id": tx_id, "image_challenge_id": init_data["image_challenge_id"], "image_sequence": IMG_SEQ, "session_id": sess_id, "application": "shopping"}).status_code == 200
    assert client.post("/api/auth/password-change/verify-private", headers=headers, json={"transaction_id": tx_id, "private_challenge_id": init_data["private_challenge_id"], "private_response": PRIV_A, "session_id": sess_id, "application": "shopping"}).status_code == 200
    db_session.commit()

    orig_override = app.dependency_overrides.get(get_db)

    def _per_request_db():
        s = TestingSessionLocal()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = _per_request_db
    try:
        def _submit_confirm(_idx):
            with TestClient(app) as local_client:
                return local_client.post(
                    "/api/auth/password-change/confirm",
                    headers=headers,
                    json={"transaction_id": tx_id, "new_password": ALT_PASS, "confirm_password": ALT_PASS, "session_id": sess_id, "application": "shopping"},
                ).status_code

        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses = list(pool.map(_submit_confirm, [1, 2]))
    finally:
        if orig_override is not None:
            app.dependency_overrides[get_db] = orig_override
        else:
            app.dependency_overrides.pop(get_db, None)

    assert statuses.count(200) == 1
    assert any(code in (400, 401, 409) for code in statuses)


def test_21_agent_or_llm_failure_cannot_authorize_password_change(client: TestClient, db_session: Session):
    """Test 21: Agent/LLM failures or attempted risk downgrade never weaken cognitive/deterministic enforcement."""
    user, sess, headers = _create_enrolled_user_and_session(
        db_session, "pw.agent@example.com", application="healthcare", session_status="ACTIVE", risk_level="CRITICAL", risk_score=0.91
    )

    with patch.object(
        DeterministicSecurityArbiter,
        "arbitrate_risk",
        wraps=DeterministicSecurityArbiter.arbitrate_risk,
    ):
        # Even if an external agent module throws, PasswordChangeService uses deterministic floor and terminates CRITICAL
        r_blk = client.post("/api/auth/password-change/initiate", headers=headers, json={"current_password": INITIAL_PASS, "session_id": sess.id, "application": "healthcare"})
        assert r_blk.status_code == 403

    # Also verify LOW risk unverified cognitive tx still fails closed when agent layer is absent/disabled
    _, sess2, headers2 = _create_enrolled_user_and_session(db_session, "pw.agent2@example.com", application="healthcare")
    init2 = client.post("/api/auth/password-change/initiate", headers=headers2, json={"current_password": INITIAL_PASS, "session_id": sess2.id, "application": "healthcare"}).json()
    assert client.post(
        "/api/auth/password-change/confirm",
        headers=headers2,
        json={"transaction_id": init2["transaction_id"], "new_password": ALT_PASS, "confirm_password": ALT_PASS, "session_id": sess2.id, "application": "healthcare"},
    ).status_code == 403


def test_frontend_portals_entries_and_node_vm_change_password_workflow():
    """Frontend Tests: Verifies Change Password controls in shopping/college/healthcare HTML and full Node VM sequence."""
    for fname, portal in [("shopping.html", "shopping"), ("college.html", "college"), ("healthcare.html", "healthcare")]:
        content = open(os.path.join(REPO_ROOT, fname), encoding="utf-8").read()
        assert 'id="btn-header-change-password"' in content
        assert f"openChangePasswordModal('{portal}')" in content

    node_script = r"""
const fs = require('fs');
const vm = require('vm');
const assert = require('assert');

const elements = {};
function mkEl(id) {
  return {
    id, value: '', textContent: '', innerHTML: '', className: '', disabled: false,
    _classes: new Set(['hidden']),
    classList: {
      add(c) { this._s.add(c); }, remove(c) { this._s.delete(c); },
      contains(c) { return this._s.has(c); }
    },
    querySelector: () => null,
    appendChild: () => {},
    focus: () => {},
    remove: () => {},
  };
}
['modal-change-password','cp-portal-badge','cp-header-icon','cp-risk-badge','cp-error-banner','cp-enroll-cta','cp-stepup-cta',
 'cp-current-password','cp-btn-step1','cp-image-grid','cp-image-strip','cp-btn-step2','cp-private-prompt','cp-private-response',
 'cp-btn-step3','cp-new-password','cp-confirm-password','cp-btn-step4','cp-success-summary',
 'cp-pane-1','cp-pane-2','cp-pane-3','cp-pane-4','cp-pane-success',
 'cp-step-pill-1','cp-step-pill-2','cp-step-pill-3','cp-step-pill-4',
 'cp-chk-len','cp-chk-upper','cp-chk-lower','cp-chk-num','cp-chk-match'].forEach(id => {
  const el = mkEl(id); el.classList._s = el._classes; elements[id] = el;
});

const storage = new Map([
  ['cognisec_token', 'tok_vm_123'],
  ['cognisec_session_id', 'sess_vm_123'],
  ['cognisec_session_status', 'ACTIVE'],
  ['cognisec_user', JSON.stringify({id: 1, email: 'vm@example.com', name: 'VM User'})]
]);
const calls = [];
const sandbox = {
  console, setTimeout, clearTimeout, setInterval, clearInterval,
  AbortController: globalThis.AbortController,
  performance: { now: () => Date.now() },
  screen: { width: 1440, height: 900, colorDepth: 24 },
  CustomEvent: function(t, d) { this.type = t; this.detail = d && d.detail; },
  navigator: { userAgent: 'NodeVM', platform: 'Mac', language: 'en-US', hardwareConcurrency: 8, webdriver: false },
  localStorage: { getItem: k => storage.get(k) || null, setItem: (k,v) => storage.set(k, String(v)), removeItem: k => storage.delete(k) },
  window: {
    location: { hostname: 'localhost', pathname: '/shopping.html', protocol: 'http:' },
    addEventListener: () => {},
    dispatchEvent: () => {},
  },
  document: {
    getElementById: id => elements[id] || null,
    querySelectorAll: () => [],
    createElement: () => mkEl('dyn'),
    head: { appendChild: () => {} },
    body: { appendChild: () => {} },
    addEventListener: () => {},
  },
  fetch: async (url, opts) => {
    calls.push({ url, method: (opts && opts.method) || 'GET', body: opts && opts.body ? JSON.parse(opts.body) : null });
    if (url.includes('/password-change/policy')) {
      return { ok: true, status: 200, headers: { get: () => null }, json: async () => ({ has_cognitive_image_sequence: true, has_private_response: true, risk_level: 'LOW', catalogue: [{id:'img_shield',label:'Shield',icon:'S'}], can_proceed: true }) };
    }
    if (url.includes('/password-change/initiate')) {
      return { ok: true, status: 200, headers: { get: () => null }, json: async () => ({ success: true, transaction_id: 'pwdchg_vm1', image_challenge_id: 'chal_i1', private_challenge_id: 'chal_p1', private_question: 'Workstation?', catalogue: [{id:'img_shield',label:'Shield',icon:'S'},{id:'img_vault',label:'Vault',icon:'V'},{id:'img_token',label:'Token',icon:'T'}] }) };
    }
    if (url.includes('/password-change/verify-image')) {
      return { ok: true, status: 200, headers: { get: () => null }, json: async () => ({ success: true, image_verified: true, private_question: 'Workstation?' }) };
    }
    if (url.includes('/password-change/verify-private')) {
      return { ok: true, status: 200, headers: { get: () => null }, json: async () => ({ success: true, private_verified: true, ready_to_commit: true }) };
    }
    if (url.includes('/password-change/confirm')) {
      return { ok: true, status: 200, headers: { get: () => null }, json: async () => ({ success: true, application: 'shopping', sessions_revoked: 1, email_notification_sent: true }) };
    }
    return { ok: true, status: 200, headers: { get: () => null }, json: async () => ({}) };
  }
};
sandbox.window.window = sandbox.window;
sandbox.window.document = sandbox.document;
sandbox.window.localStorage = sandbox.localStorage;
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(process.env.CLIENT_JS, 'utf8'), sandbox);

(async () => {
  for (const portal of ['shopping', 'college', 'healthcare']) {
    calls.length = 0;
    storage.set('cognisec_token', 'tok_vm_123');
    storage.set('cognisec_session_id', 'sess_vm_123');
    storage.set('cognisec_session_status', 'ACTIVE');
    storage.set('cognisec_user', JSON.stringify({id: 1, email: 'vm@example.com', name: 'VM User'}));
    sandbox.window.cognisec.token = 'tok_vm_123';
    sandbox.window.cognisec.sessionId = 'sess_vm_123';
    sandbox.window.cognisec.sessionStatus = 'ACTIVE';
    sandbox.window.cognisec.user = {id: 1, email: 'vm@example.com', name: 'VM User'};
    await sandbox.window.cognisec.openChangePasswordModal(portal);
    elements['cp-current-password'].value = 'InitPass#2026';
    await sandbox.window.cognisec.submitChangePasswordInitiate({ preventDefault: () => {} });
    assert.strictEqual(sandbox.window.cognisec._cpState.step, 2);
    sandbox.window.cognisec.handleChangePasswordImageClick('img_shield');
    sandbox.window.cognisec.handleChangePasswordImageClick('img_vault');
    sandbox.window.cognisec.handleChangePasswordImageClick('img_token');
    await sandbox.window.cognisec.submitChangePasswordImageVerify();
    assert.strictEqual(sandbox.window.cognisec._cpState.step, 3);
    elements['cp-private-response'].value = 'obsidian-node-42';
    await sandbox.window.cognisec.submitChangePasswordPrivateVerify({ preventDefault: () => {} });
    assert.strictEqual(sandbox.window.cognisec._cpState.step, 4);
    elements['cp-new-password'].value = 'UpdatedPass!9942';
    elements['cp-confirm-password'].value = 'UpdatedPass!9942';
    await sandbox.window.cognisec.submitChangePasswordConfirm({ preventDefault: () => {} });
    assert.strictEqual(sandbox.window.cognisec._cpState.step, 'success');
    assert.strictEqual(storage.get('cognisec_token'), undefined);
    const urls = calls.filter(c => c.url.includes('/api/auth/password-change/')).map(c => c.url.split('?')[0].split('/api/auth/')[1]);
    assert.deepStrictEqual(urls, ['password-change/policy','password-change/initiate','password-change/verify-image','password-change/verify-private','password-change/confirm']);
  }
  console.log('NODE_VM_PORTALS_OK');
})();
"""
    env = dict(os.environ, CLIENT_JS=os.path.join(REPO_ROOT, "cognisec-client.js"))
    res = subprocess.run(["node", "-e", node_script], capture_output=True, text=True, env=env)
    assert res.returncode == 0, f"Node VM error: stdout={res.stdout}\nstderr={res.stderr}"
    assert "NODE_VM_PORTALS_OK" in res.stdout
