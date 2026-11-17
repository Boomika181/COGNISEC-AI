"""
Regression Suite: Non-Negotiable Risk-to-Factor Policy & Healthcare Appointment Booking Separation
Verifies all 15 security policy invariants:
1. LOW-risk healthcare appointment -> Email OTP.
2. LOW-risk appointment -> no gesture challenge created.
3. LOW-risk appointment -> no cognitive challenge created.
4. MEDIUM-risk healthcare access -> gesture challenge.
5. MEDIUM risk without enrolled gesture -> fail closed.
6. HIGH-risk healthcare access -> cognitive challenge.
7. HIGH risk -> no gesture substitution.
8. CRITICAL risk -> synchronous session termination.
9. CRITICAL risk -> grant revocation.
10. CRITICAL risk -> no appointment creation.
11. Stale previous gesture challenge does not affect a new LOW-risk session.
12. Frontend renders the correct factor returned by the backend (and fails closed on unknown/missing factor).
13. Appointment OTP verifies only the corresponding pending appointment.
14. Appointment OTP cannot authorize unrelated vault access.
15. Agent or LLM failure cannot alter the deterministic factor mapping.
"""

import os
import secrets
import subprocess
from datetime import date, datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.agents.core.arbiter import DeterministicSecurityArbiter
from app.agents.core.llm_client import LLMClient, LLMResponse
from app.agents.execution.orchestrator import SecurityOrchestrator
from app.agents.modules.adaptive_auth_agent import AdaptiveAuthAgent
from app.agents.schemas.agent_schemas import AdaptiveAuthInput
from app.core.security import create_access_token, get_password_hash
from app.models.adaptive_factor import AdaptiveFactor
from app.models.appointment import HealthcareAppointment
from app.models.otp_challenge import OTPChallenge
from app.models.application_grant import ApplicationGrant
from app.models.session import Session as DbSession
from app.models.user import User
from app.services.adaptive_auth_service import AdaptiveAuthService
from app.services.email_service import EmailService
from app.services.healthcare_service import HOSPITAL_DOCTORS
from app.services.session_service import SessionService
from app.services.step_up_service import NEURALTRACE_NOT_ENROLLED_DETAIL, StepUpService

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


@pytest.fixture(autouse=True)
def reset_challenges(db_session: Session):
    StepUpService.reset()
    db_session.query(OTPChallenge).delete()
    db_session.query(HealthcareAppointment).delete()
    db_session.commit()
    yield
    StepUpService.reset()
    db_session.query(OTPChallenge).delete()
    db_session.query(HealthcareAppointment).delete()
    db_session.commit()


def _next_valid_date(doctor_id: str = "doc-2", min_offset: int = 1) -> str:
    doc = next(d for d in HOSPITAL_DOCTORS if d["id"] == doctor_id)
    allowed = set(doc["available_days"])
    candidate = date.today() + timedelta(days=min_offset)
    for _ in range(14):
        if candidate.strftime("%a") in allowed:
            return candidate.isoformat()
        candidate += timedelta(days=1)
    raise AssertionError(f"No valid OPD date for {doctor_id}")


def _make_user_session(
    db: Session,
    email: str,
    status: str = "ACTIVE",
    risk_level: str = "LOW",
    enroll_gesture: bool = False,
    enroll_cognitive: bool = False,
):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        user = User(
            email=email,
            name="Policy Test Patient",
            password_hash=get_password_hash("StrongPass!123"),
            account_status="ACTIVE",
            role="USER",
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    if enroll_gesture and not AdaptiveAuthService.get_factor(db, user.id, "GESTURE_PATTERN"):
        AdaptiveAuthService.enroll_gesture_pattern(db, user.id, [0, 1, 2, 4, 8], [0, 1, 2, 4, 8])
    if enroll_cognitive:
        if not AdaptiveAuthService.get_factor(db, user.id, "COGNITIVE_IMAGE_SEQUENCE"):
            AdaptiveAuthService.enroll_image_sequence(
                db, user.id, ["img_shield", "img_vault", "img_token"], ["img_shield", "img_vault", "img_token"]
            )
        if not AdaptiveAuthService.get_factor(db, user.id, "PRIVATE_RESPONSE"):
            AdaptiveAuthService.enroll_private_response(
                db, user.id, "Favorite hospital ward?", "Cardiology", "Cardiology"
            )

    now = datetime.now(timezone.utc)
    sess = DbSession(
        id=f"sess_pol_{secrets.token_hex(6)}",
        user_id=user.id,
        application="healthcare",
        status=status,
        current_risk_level=risk_level,
        observation_started_at=now - timedelta(seconds=35),
        observation_ends_at=now - timedelta(seconds=15),
        observation_completed_at=now - timedelta(seconds=10),
        login_time=now - timedelta(seconds=35),
    )
    db.add(sess)
    db.commit()
    db.refresh(sess)

    token = create_access_token(subject=user.id, role=user.role, session_id=sess.id)
    headers = {"Authorization": f"Bearer {token}", "X-Session-ID": sess.id}
    return user, sess, headers


def _apt_payload(email: str, session_id: str, slot: str = None, doctor_id: str = "doc-2"):
    doc = next(d for d in HOSPITAL_DOCTORS if d["id"] == doctor_id)
    chosen_slot = slot or doc["available_slots"][0]
    return {
        "session_id": session_id,
        "doctor_id": doctor_id,
        "appointment_date": _next_valid_date(doctor_id),
        "time_slot": chosen_slot,
        "patient_name": "Policy Test Patient",
        "patient_age": 32,
        "patient_gender": "Female",
        "patient_phone": "+919876543210",
        "patient_email": email,
        "reason_for_visit": "Routine cardiac follow-up",
        "department": doc["dept"],
        "consultation_mode": "In-Person OPD",
        "room": doc["room"],
    }


def test_1_2_3_low_risk_healthcare_appointment_uses_email_otp_never_gesture_or_cognitive(
    client: TestClient, db_session: Session
):
    """Scenarios 1, 2, 3: LOW-risk healthcare booking ALWAYS uses Email OTP, never creates gesture or cognitive challenges."""
    user, sess, headers = _make_user_session(
        db_session,
        email="low.booking@example.com",
        status="STEP_UP_REQUIRED",
        risk_level="LOW",
        enroll_gesture=True,
        enroll_cognitive=True,
    )

    # Even with gesture & cognitive enrolled AND a buggy preferred_factor="GESTURE_PATTERN",
    # LOW-risk healthcare booking MUST issue OTP — never GESTURE_PATTERN or HIGH_RISK_DUAL.
    with patch.object(EmailService, "send_otp_email", return_value=(True, "Mocked OTP")):
        res_gest = client.post(
            "/api/security/step-up/challenge",
            headers=headers,
            json={
                "session_id": sess.id,
                "application": "healthcare",
                "resource": "healthcare_booking",
                "preferred_factor": "GESTURE_PATTERN",
            },
        )
        assert res_gest.status_code == 200
        assert res_gest.json()["challenge_type"] == "OTP"

        StepUpService.reset()
        res_cog = client.post(
            "/api/security/step-up/challenge",
            headers=headers,
            json={
                "session_id": sess.id,
                "application": "healthcare",
                "resource": "healthcare_booking",
                "preferred_factor": "HIGH_RISK_DUAL",
            },
        )
        assert res_cog.status_code == 200
        assert res_cog.json()["challenge_type"] == "OTP"

    # Also verify /api/security/status reports LOW risk & EMAIL_OTP
    st_res = client.get(f"/api/security/status/{sess.id}", headers=headers)
    assert st_res.status_code == 200
    assert st_res.json()["risk_level"] == "LOW"
    assert st_res.json()["recommended_factor"] == "EMAIL_OTP"

    # Verify step-up OTP restores session -> ACTIVE, then appointment OTP sends Email OTP
    otp_code = res_cog.json().get("otp")
    ver_res = client.post(
        "/api/security/step-up/verify",
        headers=headers,
        json={
            "session_id": sess.id,
            "application": "healthcare",
            "resource": "healthcare_booking",
            "challenge_type": "OTP",
            "challenge_code": otp_code,
        },
    )
    assert ver_res.status_code == 200
    assert ver_res.json()["session_status"] == "ACTIVE"

    # Verify zero gesture/cognitive challenges remain active for this session
    assert not any(
        c.get("challenge_type") in ("GESTURE_PATTERN", "HIGH_RISK_DUAL", "COGNITIVE_IMAGE_SEQUENCE")
        for c in StepUpService._challenges.values()
        if c.get("session_id") == sess.id
    )

    sent_emails = []
    with patch.object(
        EmailService,
        "send_appointment_otp_email",
        side_effect=lambda recipient_email=None, otp_code=None, **kw: (sent_emails.append(recipient_email) or (True, "OK")),
    ):
        apt_res = client.post(
            "/api/healthcare/appointment-otp/request",
            headers=headers,
            json=_apt_payload(user.email, sess.id),
        )
    assert apt_res.status_code == 200
    assert sent_emails == [user.email]


def test_4_5_medium_risk_healthcare_requires_gesture_and_fails_closed_when_unenrolled(
    client: TestClient, db_session: Session
):
    """Scenarios 4 & 5: MEDIUM risk mandates GESTURE_PATTERN and fails closed (409/403) when unenrolled."""
    # Scenario 4: Enrolled user at MEDIUM risk -> GESTURE_PATTERN (never downgraded to OTP)
    user_ok, sess_ok, headers_ok = _make_user_session(
        db_session,
        email="med.enrolled@example.com",
        status="STEP_UP_REQUIRED",
        risk_level="MEDIUM",
        enroll_gesture=True,
    )
    chal_res = client.post(
        "/api/security/step-up/challenge",
        headers=headers_ok,
        json={
            "session_id": sess_ok.id,
            "application": "healthcare",
            "resource": "healthcare_booking",
            "preferred_factor": "OTP",  # Attempted downgrade MUST be ignored
        },
    )
    assert chal_res.status_code == 200
    assert chal_res.json()["challenge_type"] == "GESTURE_PATTERN"

    # Scenario 5: Unenrolled user at MEDIUM risk -> fails closed (409) & booking blocked (403)
    user_no, sess_no, headers_no = _make_user_session(
        db_session,
        email="med.unenrolled@example.com",
        status="STEP_UP_REQUIRED",
        risk_level="MEDIUM",
        enroll_gesture=False,
    )
    fail_chal = client.post(
        "/api/security/step-up/challenge",
        headers=headers_no,
        json={
            "session_id": sess_no.id,
            "application": "healthcare",
            "resource": "healthcare_booking",
        },
    )
    assert fail_chal.status_code == 409
    assert NEURALTRACE_NOT_ENROLLED_DETAIL in fail_chal.json()["detail"]

    # Appointment OTP must NOT bypass MEDIUM risk verification
    bypass_res = client.post(
        "/api/healthcare/appointment-otp/request",
        headers=headers_no,
        json=_apt_payload(user_no.email, sess_no.id, slot="11:30 AM"),
    )
    assert bypass_res.status_code == 403


def test_6_7_high_risk_healthcare_requires_cognitive_dual_no_gesture_substitution(
    client: TestClient, db_session: Session
):
    """Scenarios 6 & 7: HIGH risk requires HIGH_RISK_DUAL and rejects GESTURE_PATTERN/OTP substitution."""
    user, sess, headers = _make_user_session(
        db_session,
        email="high.risk@example.com",
        status="RESTRICTED",
        risk_level="HIGH",
        enroll_gesture=True,
        enroll_cognitive=True,
    )
    res = client.post(
        "/api/security/step-up/challenge",
        headers=headers,
        json={
            "session_id": sess.id,
            "application": "healthcare",
            "resource": "ehr_vault",
            "preferred_factor": "GESTURE_PATTERN",
        },
    )
    assert res.status_code == 200
    assert res.json()["challenge_type"] == "HIGH_RISK_DUAL"

    # Even for booking resource, HIGH risk blocks appointment creation and cannot downgrade
    apt_blocked = client.post(
        "/api/healthcare/appointment-otp/request",
        headers=headers,
        json=_apt_payload(user.email, sess.id, slot="12:00 PM"),
    )
    assert apt_blocked.status_code == 403


def test_8_9_10_critical_risk_terminates_session_revokes_grants_blocks_appointments(
    client: TestClient, db_session: Session
):
    """Scenarios 8, 9, 10: CRITICAL risk terminates session synchronously, revokes grants, creates zero appointments."""
    user, sess, headers = _make_user_session(
        db_session,
        email="critical.risk@example.com",
        status="ACTIVE",
        risk_level="LOW",
        enroll_gesture=True,
    )
    grant = SessionService.record_application_grant(
        db=db_session,
        session_id=sess.id,
        user_id=user.id,
        application="healthcare",
        resource="ehr_vault",
        factor="GESTURE_PATTERN",
    )
    assert grant is not None and grant.revoked is False

    # Escalate session to CRITICAL
    sess.current_risk_level = "CRITICAL"
    db_session.commit()

    # Step-up refused with 400
    chal_res = client.post(
        "/api/security/step-up/challenge",
        headers=headers,
        json={"session_id": sess.id, "application": "healthcare"},
    )
    assert chal_res.status_code == 400

    # Appointment request rejected with 403, terminates session synchronously, revokes grant, no appointment created
    apt_res = client.post(
        "/api/healthcare/appointment-otp/request",
        headers=headers,
        json=_apt_payload(user.email, sess.id, slot="12:30 PM"),
    )
    assert apt_res.status_code == 403

    db_session.refresh(sess)
    db_session.refresh(grant)
    assert sess.status == "TERMINATED"
    assert grant.revoked is True
    assert (
        db_session.query(HealthcareAppointment)
        .filter(HealthcareAppointment.patient_email == user.email)
        .count()
        == 0
    )


def test_11_stale_gesture_challenge_from_previous_session_purged_for_new_low_session(
    client: TestClient, db_session: Session
):
    """Scenario 11: Stale gesture challenge on an old session never affects a newly created LOW-risk session."""
    user, old_sess, _ = _make_user_session(
        db_session,
        email="stale.chal@example.com",
        status="STEP_UP_REQUIRED",
        risk_level="MEDIUM",
        enroll_gesture=True,
    )
    old_chal = StepUpService.create_adaptive_challenge(
        session_id=old_sess.id,
        user_id=user.id,
        db=db_session,
        risk_score=0.45,
        risk_level="MEDIUM",
        application="healthcare",
        resource="ehr_vault",
    )
    assert old_chal["challenge_type"] == "GESTURE_PATTERN"

    # New login creates a fresh session for same user & app
    new_sess = SessionService.create_session(
        db=db_session,
        user_id=user.id,
        application="healthcare",
        status="ACTIVE",
    )
    new_sess.current_risk_level = "LOW"
    db_session.commit()

    db_session.refresh(old_sess)
    assert old_sess.status == "TERMINATED"
    assert StepUpService.get_challenge(old_sess.id, "healthcare") is None

    new_token = create_access_token(subject=user.id, role=user.role, session_id=new_sess.id)
    new_headers = {"Authorization": f"Bearer {new_token}", "X-Session-ID": new_sess.id}
    with patch.object(EmailService, "send_otp_email", return_value=(True, "Mocked")):
        res = client.post(
            "/api/security/step-up/challenge",
            headers=new_headers,
            json={"session_id": new_sess.id, "application": "healthcare", "resource": "healthcare_booking"},
        )
    assert res.status_code == 200
    assert res.json()["challenge_type"] == "OTP"


def test_12_frontend_renders_backend_factor_and_fails_closed_on_unknown():
    """Scenario 12: Frontend renders authoritative server challenge type and fails closed without defaulting to gesture."""
    node_script = r"""
const fs = require('fs');
const vm = require('vm');
const path = require('path');

const clientCode = fs.readFileSync(path.join(process.env.REPO_ROOT, 'cognisec-client.js'), 'utf8');
const html = fs.readFileSync(path.join(process.env.REPO_ROOT, 'healthcare.html'), 'utf8');

const storageMap = new Map();
const localStorage = {
  getItem: k => storageMap.has(k) ? storageMap.get(k) : null,
  setItem: (k, v) => storageMap.set(k, String(v)),
  removeItem: k => storageMap.delete(k)
};

function makeEl(id) {
  return {
    id, value: '', textContent: '', innerHTML: '', disabled: false,
    style: {},
    dataset: {},
    _classes: new Set(),
    classList: {
      add(c) { this._p._classes.add(c); },
      remove(c) { this._p._classes.delete(c); },
      contains(c) { return this._p._classes.has(c); }
    },
    setAttribute() {},
    getAttribute() { return ''; },
    appendChild() {},
    remove() {},
    getBoundingClientRect() { return { left: 0, top: 0, width: 200, height: 200 }; },
    focus() {}, addEventListener() {}, querySelector() { return null; }, querySelectorAll() { return []; }
  };
}
function attach(el) { el.classList._p = el; return el; }
const elements = {};
for (const id of [
  'modal-stepup', 'stepup-modal-title', 'stepup-modal-subtitle', 'stepup-feedback-banner',
  'stepup-btn-submit', 'stepup-btn-request-new', 'stepup-attempts-info', 'stepup-reason-text',
  'stepup-session-badge', 'stepup-factor-badge', 'stepup-recipient-email', 'stepup-demo-callout',
  'stepup-demo-otp', 'stepup-pane-otp', 'stepup-pane-gesture', 'stepup-pane-image',
  'stepup-pane-private', 'stepup-otp-input', 'stepup-private-input', 'stepup-private-prompt',
  'stepup-gesture-grid', 'stepup-image-grid', 'stepup-countdown-timer'
]) {
  elements[id] = attach(makeEl(id));
}
elements['modal-stepup'].classList.add('hidden');

let nextServerResponse = null;
const ctx = {
  window: {
    location: { hostname: '127.0.0.1', pathname: '/healthcare.html', reload() {} },
    localStorage,
    addEventListener() {},
    dispatchEvent() {},
    showNotificationToast() {}
  },
  document: {
    head: { appendChild() {} },
    body: { appendChild() {} },
    createElement: () => attach(makeEl('dyn')),
    createElementNS: () => attach(makeEl('svg')),
    getElementById: id => elements[id] || null,
    addEventListener() {}
  },
  localStorage,
  navigator: { userAgent: 'Mozilla/5.0' },
  performance: { now: () => Date.now() },
  CustomEvent: class CustomEvent { constructor(t, i = {}) { this.type = t; this.detail = i.detail; } },
  fetch: async () => nextServerResponse,
  console: { log() {}, warn() {}, error() {} },
  setTimeout: () => 1, clearTimeout() {}, setInterval: () => 1, clearInterval() {},
  NeuralTraceAuth: class { constructor() {} reset() {} }
};
ctx.window.document = ctx.document;
vm.createContext(ctx);
vm.runInContext(clientCode.replace('window.cognisec = new CognisecClient();', '') + '\nwindow.CognisecClient = CognisecClient;', ctx);

(async () => {
  const cs = new ctx.window.CognisecClient();
  cs.stopTelemetryLoop();
  cs.token = 'tok';
  cs.sessionId = 'sess_ui_1';
  cs.isStepUpModalOpen = true;
  cs.renderChallengeImageGrid = () => {};
  cs.clearChallengeImageSequence = () => {};
  cs.startStepUpCountdown = () => {};

  // 1. LOW risk backend OTP renders OTP pane cleanly, keeps Gesture pane hidden
  elements['modal-stepup'].classList.add('hidden');
  nextServerResponse = {
    ok: true, status: 200,
    json: async () => ({ challenge_id: 'ch_otp', challenge_type: 'OTP', masked_email: 'u***@example.com', expires_in_seconds: 300 })
  };
  await cs.openStepUpModal({ preferredFactor: null, targetResource: 'healthcare_booking' });
  if (elements['stepup-pane-otp'].classList.contains('hidden') || !elements['stepup-pane-gesture'].classList.contains('hidden')) {
    throw new Error('LOW-risk OTP failed to render OTP pane exclusively');
  }
  if (elements['stepup-factor-badge'].textContent !== 'FACTOR: OTP') {
    throw new Error('Unexpected badge for OTP: ' + elements['stepup-factor-badge'].textContent);
  }

  // 2. MEDIUM risk backend GESTURE_PATTERN renders Gesture pane cleanly
  elements['modal-stepup'].classList.add('hidden');
  nextServerResponse = {
    ok: true, status: 200,
    json: async () => ({ challenge_id: 'ch_gest', challenge_type: 'GESTURE_PATTERN', expires_in_seconds: 300 })
  };
  await cs.openStepUpModal({ preferredFactor: null, targetResource: 'ehr_vault' });
  if (elements['stepup-pane-gesture'].classList.contains('hidden') || !elements['stepup-pane-otp'].classList.contains('hidden')) {
    throw new Error('MEDIUM-risk GESTURE_PATTERN failed to render gesture pane exclusively');
  }

  // 3. Unknown / missing challenge_type fails closed (hides all panes, disables submit, shows error)
  elements['modal-stepup'].classList.add('hidden');
  nextServerResponse = {
    ok: true, status: 200,
    json: async () => ({ challenge_id: 'ch_bad', challenge_type: 'UNKNOWN_FACTOR', expires_in_seconds: 300 })
  };
  await cs.openStepUpModal({ preferredFactor: 'GESTURE_PATTERN' });
  const anyVisible = ['stepup-pane-otp', 'stepup-pane-gesture', 'stepup-pane-image', 'stepup-pane-private']
    .some(id => !elements[id].classList.contains('hidden'));
  if (anyVisible || !elements['stepup-btn-submit'].disabled || !elements['stepup-factor-badge'].textContent.includes('INVALID')) {
    throw new Error('Unknown challenge_type did not fail closed!');
  }

  // 4. executeObservationOtpTransition generic step_up_required does NOT pass preferredFactor='GESTURE_PATTERN'
  let capturedOpenOpts = null;
  cs.openStepUpModal = opts => { capturedOpenOpts = opts; };
  cs.closeObservationOtpModal = () => {};
  nextServerResponse = { ok: false, status: 403, json: async () => ({ detail: 'Step-up required before access.' }) };
  await cs.executeObservationOtpTransition('sess_ui_1');
  if (!capturedOpenOpts || capturedOpenOpts.preferredFactor === 'GESTURE_PATTERN') {
    throw new Error('executeObservationOtpTransition hardcoded GESTURE_PATTERN!');
  }

  console.log('FRONTEND_CHALLENGE_ROUTING_OK');
})();
"""
    proc = subprocess.run(
        ["node", "-e", node_script],
        capture_output=True,
        text=True,
        env=dict(os.environ, REPO_ROOT=REPO_ROOT),
        timeout=20,
    )
    assert proc.returncode == 0, f"STDOUT: {proc.stdout}\nSTDERR: {proc.stderr}"
    assert "FRONTEND_CHALLENGE_ROUTING_OK" in proc.stdout


def test_13_14_appointment_otp_scoped_to_appointment_and_never_unlocks_vaults(
    client: TestClient, db_session: Session
):
    """Scenarios 13 & 14: Appointment OTP confirms only its matching appointment and never authorizes vaults."""
    codes = []
    user, sess, headers = _make_user_session(
        db_session,
        email="scoped.apt1@example.com",
        status="ACTIVE",
        risk_level="LOW",
        enroll_gesture=True,
    )
    user2, sess2, headers2 = _make_user_session(
        db_session,
        email="scoped.apt2@example.com",
        status="ACTIVE",
        risk_level="LOW",
        enroll_gesture=True,
    )

    with patch.object(
        EmailService,
        "send_appointment_otp_email",
        side_effect=lambda recipient_email=None, otp_code=None, **kw: (codes.append(otp_code) or (True, "OK")),
    ):
        r1 = client.post(
            "/api/healthcare/appointment-otp/request",
            headers=headers,
            json=_apt_payload(user.email, sess.id, doctor_id="doc-2"),
        )
        assert r1.status_code == 200
        # Distinct pending appointment for second user/session
        r2 = client.post(
            "/api/healthcare/appointment-otp/request",
            headers=headers2,
            json=_apt_payload(user2.email, sess2.id, doctor_id="doc-1"),
        )
        assert r2.status_code == 200

    d1, d2 = r1.json(), r2.json()
    assert d1["pending_reference_id"] != d2["pending_reference_id"]

    # Wrong challenge_id + OTP pair cannot confirm Appointment 2
    cross_try = client.post(
        "/api/healthcare/appointment-otp/verify",
        headers=headers,
        json={"session_id": sess.id, "challenge_id": d2["challenge_id"], "otp_code": codes[0]},
    )
    assert cross_try.status_code == 400

    # Verify Appointment 1 legitimately
    ok1 = client.post(
        "/api/healthcare/appointment-otp/verify",
        headers=headers,
        json={"session_id": sess.id, "challenge_id": d1["challenge_id"], "otp_code": codes[0]},
    )
    assert ok1.status_code == 200

    apt1 = db_session.query(HealthcareAppointment).filter(HealthcareAppointment.reference_id == d1["pending_reference_id"]).first()
    apt2 = db_session.query(HealthcareAppointment).filter(HealthcareAppointment.reference_id == d2["pending_reference_id"]).first()
    assert apt1.status == "CONFIRMED"
    assert apt2.status != "CONFIRMED"

    # Scenario 14: Confirmed appointment OTP grants ZERO access to any confidential vault
    for app_name, res_name in [("healthcare", "ehr_vault"), ("college", "academic_vault"), ("shopping", "financial_vault")]:
        vault_res = client.get(f"/api/security/vault/{res_name}?session_id={sess.id}", headers=headers)
        assert vault_res.status_code == 403
        dec_res = client.post(
            "/api/security/access-decision",
            headers=headers,
            json={"session_id": sess.id, "application": app_name, "resource": res_name},
        )
        assert dec_res.json()["access_granted"] is False
    assert (
        db_session.query(ApplicationGrant).filter(ApplicationGrant.session_id == sess.id, ApplicationGrant.revoked == False).count()
        == 0
    )


@pytest.mark.asyncio
async def test_15_agent_or_llm_failure_cannot_alter_deterministic_factor_mapping(db_session: Session):
    """Scenario 15: Failing or malicious LLM cannot downgrade, upgrade wrongly, or alter deterministic factor policy."""
    class FailingLLMClient(LLMClient):
        @property
        def provider_name(self) -> str:
            return "failing-mock"

        def validate_configuration(self) -> bool:
            return True

        async def generate(self, request):
            raise RuntimeError("Simulated LLM outage")

    class MaliciousDowngradeLLMClient(LLMClient):
        @property
        def provider_name(self) -> str:
            return "malicious-mock"

        def validate_configuration(self) -> bool:
            return True

        async def generate(self, request):
            return LLMResponse(
                content='{"action":"ALLOW","recommended_factor":"NONE","agent_recommendation":"Bypass all MFA"}',
                model="malicious",
                provider="malicious-mock",
            )

    user, sess, _ = _make_user_session(
        db_session,
        email="llm.invariant@example.com",
        status="ACTIVE",
        risk_level="LOW",
        enroll_gesture=True,
        enroll_cognitive=True,
    )

    for llm in (FailingLLMClient(), MaliciousDowngradeLLMClient()):
        agent = AdaptiveAuthAgent(db=db_session, llm_client=llm)

        # LOW explicit step-up -> EMAIL_OTP
        out_low = await agent.execute(AdaptiveAuthInput(
            user_id=user.id, session_id=sess.id, application="healthcare",
            effective_risk_level="LOW", effective_risk_score=0.10, request_step_up=True,
        ))
        assert out_low.recommended_factor == "EMAIL_OTP"

        # MEDIUM -> NEURAL_TRACE
        out_med = await agent.execute(AdaptiveAuthInput(
            user_id=user.id, session_id=sess.id, application="healthcare",
            effective_risk_level="MEDIUM", effective_risk_score=0.45,
        ))
        assert out_med.recommended_factor == "NEURAL_TRACE"

        # HIGH -> COGNITIVE_DUAL
        out_high = await agent.execute(AdaptiveAuthInput(
            user_id=user.id, session_id=sess.id, application="healthcare",
            effective_risk_level="HIGH", effective_risk_score=0.72,
        ))
        assert out_high.recommended_factor == "COGNITIVE_DUAL"

        # CRITICAL -> TERMINATE + synchronous termination via orchestrator
        with patch.object(EmailService, "send_email", return_value=(True, "Mocked")):
            orch = SecurityOrchestrator(db=db_session, llm_client=llm)
            res = await orch.evaluate_session_security(
                user_id=user.id,
                session_id=sess.id,
                application="healthcare",
                deterministic_risk_score=0.92,
                deterministic_risk_level="CRITICAL",
            )
        assert res["adaptive_auth"].recommended_factor == "TERMINATE"
        db_session.refresh(sess)
        assert sess.status == "TERMINATED"
        # Reset session status cleanly for second LLM pass
        sess.status = "ACTIVE"
        sess.logout_time = None
        db_session.commit()
