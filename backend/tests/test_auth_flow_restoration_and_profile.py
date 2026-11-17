"""
Comprehensive Regression Suite — Authentication Flow Restoration, Purpose Isolation & Shared Account Profile Bar.
Covers all 28 required regression scenarios across Shopping, College, and Healthcare portals plus frontend Node VM sync.
"""

import json
import os
import secrets
import subprocess
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.rate_limit import rate_limiter
from app.core.security import create_access_token, get_password_hash
from app.models.application_grant import ApplicationGrant
from app.models.password_change import PasswordChangeTransaction
from app.models.security_event import SecurityEvent
from app.models.session import Session as DbSession
from app.models.user import User
from app.services.adaptive_auth_service import AdaptiveAuthService
from app.services.email_service import EmailService
from app.services.session_service import SessionService
from app.services.step_up_service import StepUpService
from app.agents.core.arbiter import DeterministicSecurityArbiter
from app.agents.core.llm_client import LLMClient
from app.agents.execution.orchestrator import SecurityOrchestrator

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
VALID_IMG_SEQ = ["img_shield", "img_vault", "img_token"]
VALID_GESTURE = [0, 1, 2, 4, 8]
VALID_PRIV_Q = "What was the name of your first computer lab?"
VALID_PRIV_A = "turing-enclave-42"


@pytest.fixture(autouse=True)
def reset_state():
    StepUpService.reset()
    rate_limiter.reset()
    yield
    StepUpService.reset()
    rate_limiter.reset()


def _create_enrolled_user(db: Session, email: str, password: str = "StrongPass!123", name: str = "Portal Tester") -> User:
    user = db.query(User).filter(User.email == email).first()
    if not user:
        user = User(
            name=name,
            email=email,
            password_hash=get_password_hash(password),
            role="USER",
            account_status="ACTIVE",
            failed_login_attempts=0,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        user.password_hash = get_password_hash(password)
        user.account_status = "ACTIVE"
        user.failed_login_attempts = 0
        db.commit()

    if not AdaptiveAuthService.get_factor(db, user.id, "GESTURE_PATTERN"):
        AdaptiveAuthService.enroll_gesture_pattern(db, user.id, VALID_GESTURE, VALID_GESTURE)
    if not AdaptiveAuthService.get_factor(db, user.id, "COGNITIVE_IMAGE_SEQUENCE"):
        AdaptiveAuthService.enroll_image_sequence(db, user.id, VALID_IMG_SEQ, VALID_IMG_SEQ)
    if not AdaptiveAuthService.get_factor(db, user.id, "PRIVATE_RESPONSE"):
        AdaptiveAuthService.enroll_private_response(db, user.id, VALID_PRIV_Q, VALID_PRIV_A, VALID_PRIV_A)
    return user


# ==============================================================================
# SCENARIOS 1–7: INITIAL OBSERVATION -> BACKEND CONFIRMATION -> EMAIL OTP
# ==============================================================================

@pytest.mark.parametrize("portal,vault", [
    ("shopping", "financial_vault"),
    ("college", "academic_vault"),
    ("healthcare", "ehr_vault"),
])
def test_1_to_7_observation_completion_to_email_otp_never_gesture(
    client: TestClient, db_session: Session, portal: str, vault: str
):
    email = f"init_{portal}_{secrets.token_hex(3)}@example.com"
    password = "InitialLogin!123"
    _create_enrolled_user(db_session, email, password, name=f"Student {portal.title()}")

    captured_otps = []
    orig_send = EmailService.send_otp_email

    def spy_otp(recipient_email, otp_code, expires_in_minutes=5, challenge_id=None, **kwargs):
        captured_otps.append(otp_code)
        return True, f"Accepted for {recipient_email}"

    with patch.object(EmailService, "send_otp_email", side_effect=spy_otp):
        # 1. Login creates PENDING_OBSERVATION session
        r_login = client.post("/api/auth/login", json={
            "email": email,
            "password": password,
            "application": portal,
            "device_fingerprint": f"fp_init_{portal}",
        })
        assert r_login.status_code == 200, r_login.text
        login_data = r_login.json()
        assert login_data["session_status"] == "PENDING_OBSERVATION"
        assert login_data["observation_seconds_remaining"] == settings.OBSERVATION_WINDOW_SECONDS
        sid = login_data["session_id"]
        headers = {"Authorization": f"Bearer {login_data['access_token']}", "X-Session-ID": sid}

        # 4. Incomplete observation does NOT trigger OTP prematurely and blocks step-up / vaults
        r_obs_early = client.get(f"/api/auth/observation-status/{sid}", headers=headers)
        assert r_obs_early.status_code == 200
        assert r_obs_early.json()["is_completed"] is False
        assert r_obs_early.json()["required_initial_factor"] == "EMAIL_OTP"

        r_otp_early = client.post("/api/auth/login-otp/request", headers=headers, json={"session_id": sid})
        assert r_otp_early.status_code == 400
        assert "incomplete" in r_otp_early.json()["detail"].lower()

        r_step_early = client.post("/api/security/step-up/challenge", headers=headers, json={
            "session_id": sid, "application": portal, "resource": vault,
            "challenge_purpose": "CONFIDENTIAL_RESOURCE"
        })
        assert r_step_early.status_code == 403

        # Telemetry during observation reports observation_completed=False
        r_tel_early = client.post("/api/behavior/events", headers=headers, json={
            "session_id": sid, "application": portal, "typing_speed_wpm": 55.0,
            "sequence_number": 1, "telemetry_nonce": f"n1_{secrets.token_hex(4)}"
        })
        assert r_tel_early.status_code == 200
        assert r_tel_early.json()["observation_completed"] is False

        # Complete 20s window on server clock (and verify MEDIUM risk still routes to EMAIL_OTP, not gesture)
        sess = db_session.query(DbSession).filter(DbSession.id == sid).first()
        sess.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=settings.OBSERVATION_WINDOW_SECONDS + 2)
        sess.current_risk_level = "MEDIUM"
        db_session.commit()

        r_obs_done = client.get(f"/api/auth/observation-status/{sid}", headers=headers)
        assert r_obs_done.status_code == 200
        assert r_obs_done.json()["is_completed"] is True
        assert r_obs_done.json()["required_initial_factor"] == "EMAIL_OTP"

        r_tel_done = client.post("/api/behavior/events", headers=headers, json={
            "session_id": sid, "application": portal, "typing_speed_wpm": 58.0,
            "sequence_number": 2, "telemetry_nonce": f"n2_{secrets.token_hex(4)}"
        })
        assert r_tel_done.status_code == 200
        assert r_tel_done.json()["observation_completed"] is True

        # Check access-decision after 20s before OTP: MUST say EMAIL_OTP, NEVER GESTURE_PATTERN
        r_dec_pre = client.post("/api/security/access-decision", headers=headers, json={
            "session_id": sid, "application": portal, "resource": vault
        })
        assert r_dec_pre.status_code == 200
        assert r_dec_pre.json()["required_factor"] == "EMAIL_OTP"
        assert r_dec_pre.json()["access_granted"] is False

        # Request initial Login Email OTP -> succeeds, challenge_type is LOGIN_OTP
        r_otp = client.post("/api/auth/login-otp/request", headers=headers, json={"session_id": sid})
        assert r_otp.status_code == 200, r_otp.text
        otp_data = r_otp.json()
        assert otp_data["challenge_type"] == "LOGIN_OTP"
        assert len(captured_otps) == 1

        # Access-decision during PENDING_OTP MUST still require EMAIL_OTP, NEVER GESTURE_PATTERN
        r_dec_pending = client.post("/api/security/access-decision", headers=headers, json={
            "session_id": sid, "application": portal, "resource": vault
        })
        assert r_dec_pending.status_code == 200
        assert r_dec_pending.json()["session_status"] == "PENDING_OTP"
        assert r_dec_pending.json()["required_factor"] == "EMAIL_OTP"

        # Calling /step-up/challenge while PENDING_OTP must be rejected (403)
        r_bypass = client.post("/api/security/step-up/challenge", headers=headers, json={
            "session_id": sid, "application": portal, "preferred_factor": "GESTURE_PATTERN"
        })
        assert r_bypass.status_code == 403

        # 6. Valid OTP activates session cleanly
        r_ver = client.post("/api/auth/login-otp/verify", headers=headers, json={
            "session_id": sid, "otp_code": captured_otps[0], "challenge_id": otp_data["challenge_id"]
        })
        assert r_ver.status_code == 200
        assert r_ver.json()["session_status"] == "ACTIVE"

        # 7. Also verify failed OTP in a fresh session terminates & blocks profile/vault access
        r_login2 = client.post("/api/auth/login", json={
            "email": email, "password": password, "application": portal, "device_fingerprint": f"fp_fail_{portal}"
        })
        sid2 = r_login2.json()["session_id"]
        h2 = {"Authorization": f"Bearer {r_login2.json()['access_token']}", "X-Session-ID": sid2}
        sess2 = db_session.query(DbSession).filter(DbSession.id == sid2).first()
        sess2.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=settings.OBSERVATION_WINDOW_SECONDS + 2)
        db_session.commit()
        r_otp2 = client.post("/api/auth/login-otp/request", headers=h2, json={"session_id": sid2})
        assert r_otp2.status_code == 200
        r_bad_otp = client.post("/api/auth/login-otp/verify", headers=h2, json={
            "session_id": sid2, "otp_code": "000000", "challenge_id": r_otp2.json()["challenge_id"]
        })
        assert r_bad_otp.status_code == 423
        r_prof_blocked = client.get("/api/users/profile", headers=h2)
        assert r_prof_blocked.status_code in (401, 403, 423)


# ==============================================================================
# SCENARIOS 8–12: CONFIDENTIAL VAULTS STRICTLY REQUIRE GESTURE, NEVER OTP ALONE
# ==============================================================================

@pytest.mark.parametrize("portal,vault", [
    ("shopping", "financial_vault"),
    ("college", "academic_vault"),
    ("healthcare", "ehr_vault"),
])
def test_8_to_12_confidential_vaults_require_gesture_not_otp(
    client: TestClient, db_session: Session, portal: str, vault: str
):
    email = f"vault_{portal}_{secrets.token_hex(3)}@example.com"
    user = _create_enrolled_user(db_session, email)
    sid = f"sess_v_{secrets.token_hex(6)}"
    now = datetime.now(timezone.utc)
    sess = DbSession(
        id=sid, user_id=user.id, application=portal, status="PENDING_OTP",
        current_risk_level="LOW", observation_started_at=now - timedelta(seconds=25), login_time=now
    )
    db_session.add(sess)
    db_session.commit()

    # Activate session via login OTP helper (mimics scenario 6/12)
    SessionService.activate_session_after_login_otp(db_session, sid)
    token = create_access_token(subject=user.id, role="USER", session_id=sid)
    headers = {"Authorization": f"Bearer {token}", "X-Session-ID": sid}

    # 12. Initial Email OTP alone does NOT unlock confidential vault
    r_dec = client.post("/api/security/access-decision", headers=headers, json={
        "session_id": sid, "application": portal, "resource": vault
    })
    assert r_dec.status_code == 200
    dec = r_dec.json()
    assert dec["access_granted"] is False
    assert dec["required_factor"] == "GESTURE_PATTERN"

    r_vault_locked = client.get(f"/api/security/vault/{vault}?session_id={sid}", headers=headers)
    assert r_vault_locked.status_code == 403

    # Request challenge for confidential resource -> GESTURE_PATTERN
    r_chal = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": sid, "application": portal, "resource": vault,
        "challenge_purpose": "CONFIDENTIAL_RESOURCE", "preferred_factor": "GESTURE_PATTERN"
    })
    assert r_chal.status_code == 200
    chal = r_chal.json()
    assert chal["challenge_type"] == "GESTURE_PATTERN"
    assert chal["challenge_purpose"] == "CONFIDENTIAL_RESOURCE"

    # 11. Wrong gesture denies access
    r_wrong = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sid, "challenge_id": chal["challenge_id"], "challenge_type": "GESTURE_PATTERN",
        "application": portal, "resource": vault, "challenge_purpose": "CONFIDENTIAL_RESOURCE",
        "gesture_pattern": [0, 1, 5, 9]
    })
    assert r_wrong.status_code == 400
    assert client.get(f"/api/security/vault/{vault}?session_id={sid}", headers=headers).status_code == 403

    # Correct gesture unlocks vault
    r_ok = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sid, "challenge_id": chal["challenge_id"], "challenge_type": "GESTURE_PATTERN",
        "application": portal, "resource": vault, "challenge_purpose": "CONFIDENTIAL_RESOURCE",
        "gesture_pattern": VALID_GESTURE
    })
    assert r_ok.status_code == 200
    assert r_ok.json()["decision"] == "ALLOW"
    assert client.get(f"/api/security/vault/{vault}?session_id={sid}", headers=headers).status_code == 200


# ==============================================================================
# SCENARIOS 25–28: RISK POLICY & STRICT CROSS-PURPOSE CHALLENGE ISOLATION
# ==============================================================================

def test_25_to_28_risk_policy_and_cross_purpose_isolation(client: TestClient, db_session: Session):
    email = f"iso_{secrets.token_hex(3)}@example.com"
    user = _create_enrolled_user(db_session, email)
    now = datetime.now(timezone.utc)

    # Active session in college
    sid = f"sess_iso_{secrets.token_hex(6)}"
    sess = DbSession(
        id=sid, user_id=user.id, application="college", status="ACTIVE",
        current_risk_level="LOW", observation_started_at=now - timedelta(seconds=30), login_time=now
    )
    db_session.add(sess)
    db_session.commit()
    token = create_access_token(subject=user.id, role="USER", session_id=sid)
    headers = {"Authorization": f"Bearer {token}", "X-Session-ID": sid}

    # 28A. SESSION_STEP_UP challenge MUST NOT grant academic_vault access or verify with CONFIDENTIAL_RESOURCE
    r_sess_chal = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": sid, "application": "college", "challenge_purpose": "SESSION_STEP_UP",
        "preferred_factor": "GESTURE_PATTERN"
    })
    assert r_sess_chal.status_code == 200
    sc = r_sess_chal.json()
    assert sc["challenge_purpose"] == "SESSION_STEP_UP"
    assert sc["resource"] is None

    r_cross = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sid, "challenge_id": sc["challenge_id"], "challenge_type": "GESTURE_PATTERN",
        "application": "college", "resource": "academic_vault", "challenge_purpose": "CONFIDENTIAL_RESOURCE",
        "gesture_pattern": VALID_GESTURE
    })
    assert r_cross.status_code == 400
    assert "purpose mismatch" in r_cross.json()["detail"].lower()

    # Verifying as SESSION_STEP_UP succeeds for session without creating any vault ApplicationGrant
    r_sess_ok = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sid, "challenge_id": sc["challenge_id"], "challenge_type": "GESTURE_PATTERN",
        "application": "college", "challenge_purpose": "SESSION_STEP_UP", "gesture_pattern": VALID_GESTURE
    })
    assert r_sess_ok.status_code == 200
    vault_grant = db_session.query(ApplicationGrant).filter(
        ApplicationGrant.session_id == sid,
        ApplicationGrant.resource == "academic_vault",
        ApplicationGrant.revoked == False,
    ).first()
    assert vault_grant is None
    assert client.get(f"/api/security/vault/academic_vault?session_id={sid}", headers=headers).status_code == 403

    # 28B. Confidential vault challenge for academic_vault cannot unlock financial_vault (cross-portal/resource)
    r_acad = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": sid, "application": "college", "resource": "academic_vault",
        "challenge_purpose": "CONFIDENTIAL_RESOURCE"
    })
    acad_cid = r_acad.json()["challenge_id"]
    r_cross_vault = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sid, "challenge_id": acad_cid, "challenge_type": "GESTURE_PATTERN",
        "application": "shopping", "resource": "financial_vault", "challenge_purpose": "CONFIDENTIAL_RESOURCE",
        "gesture_pattern": VALID_GESTURE
    })
    assert r_cross_vault.status_code == 400

    # 28C. Password change challenge cannot verify on /security/step-up/verify or unlock vaults
    r_pw_init = client.post("/api/auth/password-change/initiate", headers=headers, json={
        "session_id": sid, "application": "college", "current_password": "StrongPass!123"
    })
    assert r_pw_init.status_code == 200
    pw_img_cid = r_pw_init.json()["image_challenge_id"]
    r_pw_on_stepup = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sid, "challenge_id": pw_img_cid, "challenge_type": "COGNITIVE_IMAGE_SEQUENCE",
        "application": "college", "resource": "academic_vault", "image_sequence": VALID_IMG_SEQ
    })
    assert r_pw_on_stepup.status_code == 400

    # 25. HIGH risk follows compound HIGH_RISK_DUAL cognitive policy (cannot downgrade to OTP or gesture)
    sess.status = "RESTRICTED"
    sess.current_risk_level = "HIGH"
    db_session.commit()
    r_high = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": sid, "application": "college", "resource": "academic_vault",
        "preferred_factor": "OTP"
    })
    assert r_high.status_code == 200
    assert r_high.json()["challenge_type"] == "HIGH_RISK_DUAL"

    # 26. CRITICAL risk terminates synchronously and revokes grants
    SessionService.record_application_grant(db_session, sid, user.id, "college", "academic_vault", "HIGH_RISK_DUAL")
    from app.services.decision_service import DecisionService
    dec, _, st, _ = DecisionService.enforce_zero_trust_decision(
        db=db_session, user_id=user.id, session_id=sid, application="college",
        risk_score=0.92, anomaly_score=0.90, risk_level="CRITICAL", contributing_factors=["Critical test"]
    )
    assert dec == "TERMINATE_SESSION" and st == "TERMINATED"
    assert db_session.query(ApplicationGrant).filter(
        ApplicationGrant.session_id == sid, ApplicationGrant.revoked == False
    ).count() == 0

    # 27. DeterministicSecurityArbiter enforces mandatory HIGH/CRITICAL policies even if LLM/agent attempts downgrade
    eff_score, eff_lvl, accepted, _ = DeterministicSecurityArbiter.arbitrate_risk(
        deterministic_score=0.72, deterministic_level="HIGH", agent_score=0.10, agent_level="LOW"
    )
    assert eff_lvl == "HIGH" and eff_score == 0.72 and accepted is False
    arb_high = DeterministicSecurityArbiter.arbitrate_decision(
        effective_risk_score=0.72, effective_risk_level="HIGH",
        agent_action="ALLOW", agent_factor="EMAIL_OTP"
    )
    assert arb_high.recommended_factor == "COGNITIVE_DUAL" and arb_high.action == "STEP_UP_REQUIRED" and arb_high.is_agent_accepted is False
    arb_crit = DeterministicSecurityArbiter.arbitrate_decision(
        effective_risk_score=0.95, effective_risk_level="CRITICAL",
        agent_action="ALLOW", agent_factor="EMAIL_OTP"
    )
    assert arb_crit.recommended_factor == "TERMINATE" and arb_crit.action == "TERMINATE" and arb_crit.is_agent_accepted is False


# ==============================================================================
# PART 2 BACKEND & FRONTEND: SHARED ACCOUNT PROFILE BAR & EDIT PROFILE SAFETY
# ==============================================================================

def test_shared_profile_api_ownership_and_credential_protection(client: TestClient, db_session: Session):
    email = f"prof_{secrets.token_hex(3)}@example.com"
    user = _create_enrolled_user(db_session, email, name="Original Name")
    sid = f"sess_p_{secrets.token_hex(6)}"
    now = datetime.now(timezone.utc)
    sess = DbSession(id=sid, user_id=user.id, application="college", status="PENDING_OTP", current_risk_level="LOW", login_time=now)
    db_session.add(sess)
    db_session.commit()
    token = create_access_token(subject=user.id, role="USER", session_id=sid)
    headers = {"Authorization": f"Bearer {token}", "X-Session-ID": sid}

    # Edit Profile must be blocked until initial OTP completes
    assert client.put("/api/users/profile", headers=headers, json={"name": "Blocked Name"}).status_code == 403

    SessionService.activate_session_after_login_otp(db_session, sid)
    # Privilege escalation / account_status modification rejected on Edit Profile
    assert client.put("/api/users/profile", headers=headers, json={"name": "Hacker", "role": "ADMIN"}).status_code == 403
    assert client.put("/api/users/profile", headers=headers, json={"name": "Hacker", "account_status": "LOCKED"}).status_code == 403
    assert client.put("/api/users/profile", headers=headers, json={"name": "X"}).status_code == 400

    # Valid name update succeeds and persists without exposing sensitive fields
    r_upd = client.put("/api/users/profile", headers=headers, json={"name": "Updated Student Name"})
    assert r_upd.status_code == 200
    body = r_upd.json()
    assert body["name"] == "Updated Student Name"
    assert "password_hash" not in body


def test_frontend_profile_bar_and_observation_to_otp_sync_node_vm():
    # 1. Verify all 3 portals include the shared Profile Dropdown Bar & all 4 required items
    for fname, portal in [("shopping.html", "shopping"), ("college.html", "college"), ("healthcare.html", "healthcare")]:
        html = open(os.path.join(REPO_ROOT, fname), encoding="utf-8").read()
        for req_id in ['id="btn-header-profile"', 'id="profile-dropdown-menu"', 'id="btn-header-change-password"']:
            assert req_id in html, f"{fname} missing {req_id}"
        for label in ["My Account", "Edit Profile", "Change Password", "Security Settings"]:
            assert label in html, f"{fname} missing dropdown label '{label}'"
        assert f"openAccountProfileModal('account', '{portal}')" in html
        assert f"openAccountProfileModal('edit', '{portal}')" in html
        assert f"openAccountProfileModal('security', '{portal}')" in html

    # 2. Run Node VM verification of backend-confirmed observation -> OTP transition & stale state recovery
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
      toggle(c, f) { if (f === undefined) { this._s.has(c) ? this._s.delete(c) : this._s.add(c); } else if (f) this._s.add(c); else this._s.delete(c); },
      contains(c) { return this._s.has(c); }
    },
    focus() {},
    setAttribute() {},
    querySelector: () => null,
    querySelectorAll: () => [],
    appendChild: () => {},
    contains: () => false,
  };
}
['modal-login-observation','login-otp-dest-email','login-otp-error-banner','login-otp-success-banner',
 'login-otp-code-input','obs-modal-subtitle','login-otp-expiry-timer','btn-login-otp-verify',
 'btn-login-otp-resend','cv-observation-state','cv-status-badge','modal-account-profile',
 'ap-modal-card','ap-modal-header','ap-portal-badge','ap-header-sub','ap-avatar-circle',
 'ap-btn-save-profile','ap-banner-err','ap-banner-ok','ap-pane-account','ap-pane-edit',
 'ap-pane-security','ap-tab-account','ap-tab-edit','ap-tab-security','ap-acc-name',
 'ap-acc-email','ap-acc-role','ap-acc-status','ap-acc-portal','ap-acc-created',
 'ap-portal-specific-detail','ap-edit-email','ap-edit-name'].forEach(id => {
  const el = mkEl(id); el.classList._s = el._classes; elements[id] = el;
});

const storage = new Map([
  ['cognisec_token', 'tok_obs_1'],
  ['cognisec_session_id', 'sess_obs_1'],
  ['cognisec_session_status', 'PENDING_OBSERVATION'],
  ['cognisec_user', JSON.stringify({id: 7, email: 'stu@college.edu', name: 'College Student', role: 'USER'})]
]);
let obsCompletedFlag = false;
let obsRemaining = 5;
const apiCalls = [];

const sandbox = {
  console, setTimeout, clearTimeout, setInterval, clearInterval,
  AbortController: globalThis.AbortController,
  performance: { now: () => Date.now() },
  screen: { width: 1440, height: 900, colorDepth: 24 },
  CustomEvent: function(t, d) { this.type = t; this.detail = d && d.detail; },
  navigator: { userAgent: 'NodeVM', platform: 'Mac', language: 'en-US', hardwareConcurrency: 8, webdriver: false },
  localStorage: { getItem: k => storage.get(k) || null, setItem: (k,v) => storage.set(k, String(v)), removeItem: k => storage.delete(k) },
  window: { location: { hostname: 'localhost', pathname: '/college.html', protocol: 'http:' }, addEventListener: () => {}, dispatchEvent: () => {} },
  document: {
    hidden: false,
    getElementById: id => elements[id] || null,
    querySelectorAll: () => [],
    createElement: () => { const e = mkEl('dyn'); e.classList._s = e._classes; return e; },
    head: { appendChild: () => {} }, body: { appendChild: () => {} }, addEventListener: () => {},
  },
  fetch: async (url, opts) => {
    apiCalls.push(url);
    if (url.includes('/security/status/')) {
      return { ok: true, status: 200, json: async () => ({ session_status: obsCompletedFlag ? 'PENDING_OTP' : 'PENDING_OBSERVATION', risk_level: 'MEDIUM', verification_required: obsCompletedFlag }) };
    }
    if (url.includes('/auth/observation-status/')) {
      return { ok: true, status: 200, json: async () => ({ status: obsCompletedFlag ? 'PENDING_OTP' : 'PENDING_OBSERVATION', observation_seconds_remaining: obsRemaining, is_completed: obsCompletedFlag }) };
    }
    if (url.includes('/behavior/events')) {
      return { ok: true, status: 200, json: async () => ({ decision: 'OBSERVATION_PENDING', session_status: 'PENDING_OBSERVATION', observation_completed: false }) };
    }
    if (url.includes('/auth/login-otp/request')) {
      return { ok: true, status: 200, json: async () => ({ challenge_id: 'chal_login_vm1', challenge_type: 'LOGIN_OTP', masked_email: 's***u@college.edu', expires_in_seconds: 300, risk_level: 'MEDIUM' }) };
    }
    if (url.includes('/auth/me')) {
      return { ok: true, status: 200, json: async () => ({ id: 7, name: 'College Student', email: 'stu@college.edu', role: 'USER', account_status: 'ACTIVE' }) };
    }
    if (url.includes('/users/profile')) {
      const body = JSON.parse(opts.body);
      return { ok: true, status: 200, json: async () => ({ id: 7, name: body.name, email: 'stu@college.edu', role: 'USER', account_status: 'ACTIVE' }) };
    }
    return { ok: true, status: 200, json: async () => ({}) };
  }
};
sandbox.window.window = sandbox.window;
sandbox.window.document = sandbox.document;
sandbox.window.localStorage = sandbox.localStorage;
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(process.env.CLIENT_JS, 'utf8'), sandbox);

(async () => {
  const cs = sandbox.window.cognisec;
  await new Promise(r => setTimeout(r, 30));

  // Case 1: Backend says observation incomplete (5s remaining) -> MUST NOT trigger /login-otp/request or gesture!
  let stepUpOpened = false;
  cs.openStepUpModal = () => { stepUpOpened = true; };
  apiCalls.length = 0;
  await cs.confirmAndExecuteObservationOtp('sess_obs_1');
  assert(!apiCalls.some(u => u.includes('/auth/login-otp/request')), 'Must not call login-otp/request while backend observation incomplete');
  assert(!apiCalls.some(u => u.includes('/security/step-up/challenge')), 'Must not call gesture step-up after observation');
  assert.strictEqual(stepUpOpened, false);
  if (cs._obsCountdownInterval) { clearInterval(cs._obsCountdownInterval); cs._obsCountdownInterval = null; }
  if (cs._obsTimer) { clearTimeout(cs._obsTimer); cs._obsTimer = null; }

  // Case 2: Backend confirms observation complete (even under MEDIUM risk) -> opens Email OTP modal, NEVER gesture
  obsCompletedFlag = true;
  obsRemaining = 0;
  apiCalls.length = 0;
  await cs.confirmAndExecuteObservationOtp('sess_obs_1');
  assert(apiCalls.some(u => u.includes('/auth/login-otp/request')), 'Expected login-otp/request once backend confirms observation complete');
  assert(!apiCalls.some(u => u.includes('/security/step-up/challenge')), 'Gesture challenge must NEVER be requested at end of initial observation');
  assert.strictEqual(stepUpOpened, false);
  assert.strictEqual(cs.sessionStatus, 'PENDING_OTP');
  assert.strictEqual(elements['modal-login-observation'].classList.contains('hidden'), false);
  if (cs._otpExpiryTimer) { clearInterval(cs._otpExpiryTimer); cs._otpExpiryTimer = null; }

  // Case 3: Shared Account Profile Modal + Edit Profile flow
  cs.sessionStatus = 'ACTIVE';
  await cs.openAccountProfileModal('edit', 'college');
  elements['ap-edit-name'].value = 'Updated College Name';
  await cs.submitAccountProfileEdit({ preventDefault() {} });
  assert.strictEqual(cs.user.name, 'Updated College Name');
  cs.stopTelemetryLoop();
  console.log('NODE_VM_RESTORATION_OK');
})();
"""
    proc = subprocess.run(
        ["node", "-e", node_script],
        capture_output=True,
        text=True,
        env=dict(os.environ, CLIENT_JS=os.path.join(REPO_ROOT, "cognisec-client.js")),
        timeout=20,
    )
    assert proc.returncode == 0, f"STDOUT: {proc.stdout}\nSTDERR: {proc.stderr}"
    assert "NODE_VM_RESTORATION_OK" in proc.stdout

