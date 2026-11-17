"""
Regression Suite: Healthcare Email OTP Challenge Issuance, Error Handling & Routing
Covers:
- Appointment OTP endpoint routing & API base URL (localhost / 127.0.0.1)
- Valid session auth, invalid session (404/403), missing challenge ID, invalid email (422)
- Challenge + pending_appointment_id DB persistence
- SMTP failure (502 + rollback; no 'OTP sent' claim)
- Network/timeout failures & HTTP 400/401/403/404/422/500/502 handling + Retry restoration + deduplication in Node VM
- Full OTP verification -> CONFIRMED appointment, no gesture at LOW risk, and MEDIUM/HIGH/CRITICAL mapping
"""

import os
import secrets
import subprocess
from datetime import date, datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.security import create_access_token, get_password_hash
from app.models.appointment import HealthcareAppointment
from app.models.otp_challenge import OTPChallenge
from app.models.session import Session as DbSession
from app.models.user import User
from app.services.adaptive_auth_service import AdaptiveAuthService
from app.services.email_service import EmailService
from app.services.healthcare_service import HOSPITAL_DOCTORS
from app.services.step_up_service import StepUpService

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


@pytest.fixture(autouse=True)
def reset_challenges():
    StepUpService.reset()
    yield
    StepUpService.reset()


def _next_valid_date(doctor_id: str = "doc-1") -> str:
    doc = next(d for d in HOSPITAL_DOCTORS if d["id"] == doctor_id)
    allowed = set(doc["available_days"])
    candidate = date.today() + timedelta(days=21)
    for _ in range(14):
        if candidate.strftime("%a") in allowed:
            return candidate.isoformat()
        candidate += timedelta(days=1)
    raise AssertionError(f"No OPD date for {doctor_id}")


def _setup_user(db: Session, email: str, status: str = "ACTIVE", risk_level: str = "LOW", enroll_all: bool = False):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        user = User(
            email=email,
            name="Issuance Patient",
            password_hash=get_password_hash("Issuance!123"),
            account_status="ACTIVE",
            role="USER",
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    if enroll_all:
        if not AdaptiveAuthService.get_factor(db, user.id, "GESTURE_PATTERN"):
            AdaptiveAuthService.enroll_gesture_pattern(db, user.id, [0, 1, 2, 4, 8], [0, 1, 2, 4, 8])
        if not AdaptiveAuthService.get_factor(db, user.id, "COGNITIVE_IMAGE_SEQUENCE"):
            AdaptiveAuthService.enroll_image_sequence(
                db, user.id, ["img_shield", "img_vault", "img_token"], ["img_shield", "img_vault", "img_token"]
            )
        if not AdaptiveAuthService.get_factor(db, user.id, "PRIVATE_RESPONSE"):
            AdaptiveAuthService.enroll_private_response(db, user.id, "What is your pet?", "Max", "Max")

    now = datetime.now(timezone.utc)
    sess = DbSession(
        id=f"sess_iss_{secrets.token_hex(6)}",
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


def _payload(email: str, session_id: str, doctor_id: str = "doc-1"):
    doc = next(d for d in HOSPITAL_DOCTORS if d["id"] == doctor_id)
    return {
        "session_id": session_id,
        "doctor_id": doctor_id,
        "appointment_date": _next_valid_date(doctor_id),
        "time_slot": doc["available_slots"][0],
        "patient_name": "Issuance Patient",
        "patient_age": 30,
        "patient_gender": "Female",
        "patient_phone": "+919876543210",
        "patient_email": email,
        "reason_for_visit": "Outpatient checkup",
        "department": doc["dept"],
        "consultation_mode": "In-Person OPD",
        "room": doc["room"],
    }


def test_appointment_otp_endpoint_persistence_and_confirmation(client: TestClient, db_session: Session):
    """Valid session -> pending appointment + OTPChallenge linked in DB -> OTP verify confirms appointment cleanly."""
    captured = []
    user, sess, headers = _setup_user(db_session, "iss.valid@example.com", status="ACTIVE", risk_level="LOW", enroll_all=True)

    with patch.object(
        EmailService,
        "send_appointment_otp_email",
        side_effect=lambda recipient_email=None, otp_code=None, **kw: (captured.append((recipient_email, otp_code)) or (True, "250 OK")),
    ):
        req_res = client.post("/api/healthcare/appointment-otp/request", headers=headers, json=_payload(user.email, sess.id))

    assert req_res.status_code == 200
    body = req_res.json()
    assert body["challenge_type"] == "HEALTHCARE_APPOINTMENT"
    assert body["delivery_status"] == "SMTP_ACCEPTED"
    assert isinstance(body["pending_appointment_id"], int)
    assert body["pending_reference_id"].startswith("AYU-")
    assert "otp" not in body
    assert captured[0][0] == user.email

    chal = db_session.query(OTPChallenge).filter(OTPChallenge.challenge_id == body["challenge_id"]).first()
    apt = db_session.query(HealthcareAppointment).filter(HealthcareAppointment.id == body["pending_appointment_id"]).first()
    assert chal is not None and apt is not None
    assert chal.appointment_id == apt.id
    assert chal.purpose == "APPOINTMENT_OTP"
    assert apt.status == "PENDING_VERIFICATION"

    ver_res = client.post(
        "/api/healthcare/appointment-otp/verify",
        headers=headers,
        json={"session_id": sess.id, "challenge_id": body["challenge_id"], "otp_code": captured[0][1]},
    )
    assert ver_res.status_code == 200
    assert ver_res.json()["status"] == "CONFIRMED"
    db_session.refresh(apt)
    assert apt.status == "CONFIRMED"


def test_invalid_session_missing_challenge_and_invalid_email_rejected(client: TestClient, db_session: Session):
    """Covers invalid session (404/403), missing challenge ID (400/404), and invalid email (422)."""
    user, sess, headers = _setup_user(db_session, "iss.errors@example.com")
    other_user, _, other_headers = _setup_user(db_session, "iss.other@example.com")

    # Non-existent session -> 404
    r_missing = client.post(
        "/api/healthcare/appointment-otp/request",
        headers=headers,
        json=_payload(user.email, "sess_does_not_exist"),
    )
    assert r_missing.status_code == 404

    # Session owned by another user -> 403
    r_cross = client.post(
        "/api/healthcare/appointment-otp/request",
        headers=other_headers,
        json=_payload(other_user.email, sess.id),
    )
    assert r_cross.status_code == 403

    # Invalid email -> 422
    r_email = client.post(
        "/api/healthcare/appointment-otp/request",
        headers=headers,
        json=_payload("not-an-email", sess.id),
    )
    assert r_email.status_code == 422

    # Missing/non-existent challenge ID on verify -> 400
    r_bad_chal = client.post(
        "/api/healthcare/appointment-otp/verify",
        headers=headers,
        json={"session_id": sess.id, "challenge_id": "chal_missing_999", "otp_code": "123456"},
    )
    assert r_bad_chal.status_code in (400, 404)


def test_smtp_failure_rolls_back_challenge_and_blocks_booking(client: TestClient, db_session: Session):
    """SMTP failure must return 502, mark pending appointment FAILED, delete challenge, and never claim OTP sent."""
    user, sess, headers = _setup_user(db_session, "iss.smtpfail@example.com")

    with patch.object(EmailService, "send_appointment_otp_email", return_value=(False, "SMTP connection refused")):
        res = client.post(
            "/api/healthcare/appointment-otp/request",
            headers=headers,
            json=_payload(user.email, sess.id, doctor_id="doc-2"),
        )

    assert res.status_code == 502
    assert "SMTP connection refused" in res.json()["detail"]
    assert db_session.query(OTPChallenge).filter(OTPChallenge.session_id == sess.id).count() == 0
    apt = db_session.query(HealthcareAppointment).filter(HealthcareAppointment.patient_email == user.email).first()
    assert apt is None or apt.status != "CONFIRMED"


def test_step_up_risk_mapping_low_otp_med_gesture_high_cognitive_critical_terminate(
    client: TestClient, db_session: Session
):
    """Verifies no gesture for LOW risk and exact MEDIUM/HIGH/CRITICAL factor mapping."""
    with patch.object(EmailService, "send_otp_email", return_value=(True, "250 OK")):
        u_low, s_low, h_low = _setup_user(db_session, "map.low@example.com", status="STEP_UP_REQUIRED", risk_level="LOW", enroll_all=True)
        r_low = client.post("/api/security/step-up/challenge", headers=h_low, json={"session_id": s_low.id, "application": "healthcare", "resource": "healthcare_booking"})
        assert r_low.status_code == 200
        assert r_low.json()["challenge_type"] == "OTP"

        u_med, s_med, h_med = _setup_user(db_session, "map.med@example.com", status="STEP_UP_REQUIRED", risk_level="MEDIUM", enroll_all=True)
        r_med = client.post("/api/security/step-up/challenge", headers=h_med, json={"session_id": s_med.id, "application": "healthcare", "resource": "healthcare_booking"})
        assert r_med.status_code == 200
        assert r_med.json()["challenge_type"] == "GESTURE_PATTERN"

        u_high, s_high, h_high = _setup_user(db_session, "map.high@example.com", status="RESTRICTED", risk_level="HIGH", enroll_all=True)
        r_high = client.post("/api/security/step-up/challenge", headers=h_high, json={"session_id": s_high.id, "application": "healthcare", "resource": "healthcare_booking"})
        assert r_high.status_code == 200
        assert r_high.json()["challenge_type"] == "HIGH_RISK_DUAL"

        u_crit, s_crit, h_crit = _setup_user(db_session, "map.crit@example.com", status="ACTIVE", risk_level="CRITICAL", enroll_all=True)
        r_crit = client.post("/api/security/step-up/challenge", headers=h_crit, json={"session_id": s_crit.id, "application": "healthcare"})
        assert r_crit.status_code == 400


def test_frontend_api_url_error_handling_retry_and_dedup_in_node_vm():
    """Verifies API base URL, HTTP 400/401/403/404/422/500/502 error handling, timeout, Retry reset, and deduplication."""
    node_script = r"""
const fs = require('fs');
const vm = require('vm');
const path = require('path');

const clientCode = fs.readFileSync(path.join(process.env.REPO_ROOT, 'cognisec-client.js'), 'utf8');

function runWithHostname(hostname) {
  const storage = new Map();
  const localStorage = { getItem: k => storage.get(k) || null, setItem: (k, v) => storage.set(k, String(v)), removeItem: k => storage.delete(k) };
  function makeEl(id) {
    return {
      id, value: '', textContent: '', innerHTML: '', disabled: false, style: {}, dataset: {},
      _classes: new Set(),
      classList: { add(c){this._p._classes.add(c);}, remove(c){this._p._classes.delete(c);}, contains(c){return this._p._classes.has(c);} },
      setAttribute(){}, getAttribute(){return '';}, appendChild(){}, remove(){},
      getBoundingClientRect(){return {left:0,top:0,width:200,height:200};},
      focus(){}, addEventListener(){}, querySelector(){return null;}, querySelectorAll(){return [];}
    };
  }
  function attach(el){ el.classList._p = el; return el; }
  const elements = {};
  for (const id of [
    'modal-stepup', 'stepup-modal-title', 'stepup-modal-subtitle', 'stepup-feedback-banner',
    'stepup-btn-submit', 'stepup-btn-request-new', 'stepup-attempts-info', 'stepup-reason-text',
    'stepup-session-badge', 'stepup-factor-badge', 'stepup-recipient-email', 'stepup-demo-callout',
    'stepup-demo-otp', 'stepup-pane-otp', 'stepup-pane-gesture', 'stepup-pane-image',
    'stepup-pane-private', 'stepup-otp-input', 'stepup-private-input', 'stepup-private-prompt',
    'stepup-gesture-grid', 'stepup-image-grid', 'stepup-countdown-timer',
    'modal-payment-otp', 'payment-modal-title', 'payment-modal-subtitle', 'payment-stage-badge',
    'payment-modal-desc-heading', 'payment-modal-desc-text', 'payment-otp-order-label',
    'payment-otp-amount-label', 'btn-payment-otp-cancel', 'payment-otp-dest-email',
    'payment-otp-order-id', 'payment-otp-order-amount', 'payment-otp-error-banner',
    'payment-otp-success-banner', 'payment-otp-code-input', 'btn-payment-otp-verify',
    'btn-payment-otp-resend', 'payment-otp-expiry-timer'
  ]) {
    elements[id] = attach(makeEl(id));
  }

  let fetchCalls = [];
  let fetchMock = async (url, opts) => ({ ok: true, status: 200, json: async () => ({}) });

  const ctx = {
    window: { location: { hostname, pathname: '/healthcare.html', reload(){} }, localStorage, addEventListener(){}, dispatchEvent(){}, showNotificationToast(){} },
    document: { head:{appendChild(){}}, body:{appendChild(){}}, createElement:()=>attach(makeEl('d')), createElementNS:()=>attach(makeEl('s')), getElementById:id=>elements[id]||null, addEventListener(){} },
    localStorage, navigator: { userAgent: 'Mozilla/5.0' }, performance: { now: () => Date.now() },
    AbortController,
    CustomEvent: class CustomEvent { constructor(t,i={}){this.type=t;this.detail=i.detail;} },
    fetch: (url, opts) => { fetchCalls.push({ url, opts }); return fetchMock(url, opts); },
    console: { log(){}, warn(){}, error(){} },
    setTimeout, clearTimeout, setInterval: () => 1, clearInterval() {},
  };
  ctx.window.document = ctx.document;
  vm.createContext(ctx);
  vm.runInContext(
    clientCode.replace('window.cognisec = new CognisecClient();', '') + '\nwindow.CognisecClient = CognisecClient; window.COGNISEC_API_BASE = COGNISEC_API_BASE;',
    ctx
  );
  return { ctx, elements, setFetchMock: fn => { fetchMock = fn; }, getFetchCalls: () => fetchCalls, clearCalls: () => { fetchCalls = []; } };
}

(async () => {
  // Verify localhost vs 127.0.0.1 API base URL
  const rLocal = runWithHostname('localhost');
  if (rLocal.ctx.window.COGNISEC_API_BASE !== 'http://localhost:8000/api') throw new Error('Wrong localhost API base');

  const env = runWithHostname('127.0.0.1');
  if (env.ctx.window.COGNISEC_API_BASE !== 'http://127.0.0.1:8000/api') throw new Error('Wrong 127.0.0.1 API base');

  const cs = new env.ctx.window.CognisecClient();
  cs.stopTelemetryLoop();
  cs.token = 'jwt-test';
  cs.sessionId = 'sess_vm_iss';
  cs.isStepUpModalOpen = true;
  cs.startStepUpCountdown = () => {};

  // 1. Network failure MUST NOT stay stuck at Loading Challenge... and MUST enable Retry
  env.setFetchMock(async () => { throw new Error('Failed to fetch'); });
  await cs.triggerNewStepUpChallenge('OTP');
  if (env.elements['stepup-btn-submit'].innerHTML.toLowerCase().includes('loading challenge')) {
    throw new Error('Button remained stuck on Loading Challenge after network error!');
  }
  if (env.elements['stepup-btn-request-new'].disabled !== false) {
    throw new Error('Retry button was not re-enabled after failure!');
  }

  // 2. Distinct handling for HTTP 400, 401, 403, 404, 422, 500, 502
  for (const code of [400, 401, 403, 404, 422, 500, 502]) {
    env.setFetchMock(async () => ({ ok: false, status: code, json: async () => ({}) }));
    const res = await cs.requestStepUpChallenge('OTP');
    if (res.success || res.status !== code || !res.error) {
      throw new Error('Did not distinctly handle HTTP ' + code);
    }
  }

  // 3. Duplicate concurrent calls prevented
  env.clearCalls();
  env.setFetchMock(async () => {
    await new Promise(r => setTimeout(r, 40));
    return { ok: true, status: 200, json: async () => ({ challenge_id: 'ch_1', challenge_type: 'OTP', delivery_status: 'SENT', masked_email: 'p***@example.com', expires_in_seconds: 300 }) };
  });
  await Promise.all([cs.triggerNewStepUpChallenge('OTP'), cs.triggerNewStepUpChallenge('OTP')]);
  if (env.getFetchCalls().length !== 1) {
    throw new Error('Expected deduplication to emit 1 fetch call, got ' + env.getFetchCalls().length);
  }
  if (env.elements['stepup-btn-request-new'].disabled !== false) {
    throw new Error('Fresh code / Retry button stayed disabled after success!');
  }

  // 4. Appointment OTP preserves pending_appointment_id & routes strictly to /healthcare/appointment-otp/request
  env.clearCalls();
  env.setFetchMock(async () => ({
    ok: true, status: 200,
    json: async () => ({
      challenge_id: 'chal_apt_vm', challenge_type: 'HEALTHCARE_APPOINTMENT',
      pending_appointment_id: 77, pending_reference_id: 'AYU-2026-VM1234',
      delivery_status: 'SENT', masked_email: 'p***@example.com', message: 'Dispatched via SMTP'
    })
  }));
  const aptRes = await cs.requestHealthcareAppointmentOtp({
    doctorId: 'doc-1', appointmentDate: '2099-11-12', timeSlot: '09:00 AM',
    patientName: 'Pat', patientPhone: '9876543210', patientEmail: 'p@example.com', department: 'cardiology'
  });
  if (!env.getFetchCalls()[0].url.endsWith('/api/healthcare/appointment-otp/request')) {
    throw new Error('Wrong appointment OTP URL: ' + env.getFetchCalls()[0].url);
  }
  if (aptRes.pending_appointment_id !== 77 || cs._lastPendingAppointmentId !== 77) {
    throw new Error('Did not preserve pending_appointment_id');
  }

  // 5. Failed delivery_status NEVER shows successBanner 'OTP dispatched'
  cs.openAppointmentOtpModal({ ...aptRes, delivery_status: 'FAILED', message: 'SMTP down' });
  if (!env.elements['payment-otp-success-banner'].classList.contains('hidden')) {
    throw new Error('Displayed success banner despite FAILED delivery_status!');
  }

  console.log('NODE_OTP_ISSUANCE_ALL_PASSED');
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
    assert "NODE_OTP_ISSUANCE_ALL_PASSED" in proc.stdout
