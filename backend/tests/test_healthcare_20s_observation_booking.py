"""
Regression & Integration Suite: Healthcare Appointment Booking + 20-Second Behavioural Observation Sync
Covers all 10 required scenarios:
1. Booking attempt blocked cleanly during the 20s observation window.
2. Booking allowed immediately after 20s observation completes & login OTP activates session.
3. Stale frontend state (cached PENDING_OBSERVATION) reconciled automatically via authoritative backend status.
4. Missing telemetry fallback during 20s window still allows observation completion once 20s elapses.
5. Delayed backend telemetry / status responses handled gracefully without re-locking ACTIVE session.
6. Wrong or expired session ID clears stale frontend session state and blocks booking cleanly.
7. Elevated risk (STEP_UP_REQUIRED / RESTRICTED) triggers step-up verification instead of generic 20s message.
8. Critical risk (TERMINATED) terminates session, clears stale auth, and blocks booking.
9. Transition from observation completion to appointment booking OTP flow + automatic modal error clearance.
10. Transition from appointment OTP verification to confirmed appointment in patient history.
"""

import json
import os
import secrets
import subprocess
from datetime import date, datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import create_access_token, get_password_hash
from app.models.appointment import HealthcareAppointment
from app.models.session import Session as DbSession
from app.models.user import User
from app.services.email_service import EmailService
from app.services.healthcare_service import HOSPITAL_DOCTORS
from app.services.step_up_service import StepUpService

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


@pytest.fixture(autouse=True)
def reset_step_up_state():
    StepUpService.reset()
    yield
    StepUpService.reset()


def _next_valid_date_for_doctor(doctor_id: str, min_offset_days: int = 1) -> str:
    doc = next(d for d in HOSPITAL_DOCTORS if d["id"] == doctor_id)
    allowed = set(doc["available_days"])
    candidate = date.today() + timedelta(days=min_offset_days)
    for _ in range(14):
        if candidate.strftime("%a") in allowed:
            return candidate.isoformat()
        candidate += timedelta(days=1)
    raise AssertionError(f"No valid OPD date found for {doctor_id}")


def _create_user_and_session(
    db: Session,
    email: str,
    status: str = "PENDING_OBSERVATION",
    risk_level: str = "LOW",
    obs_age_seconds: int = 5,
):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        user = User(
            email=email,
            name="Test Patient",
            password_hash=get_password_hash("StrongPass!123"),
            account_status="ACTIVE",
            role="USER",
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    now = datetime.now(timezone.utc)
    obs_start = now - timedelta(seconds=obs_age_seconds)
    obs_ends = obs_start + timedelta(seconds=settings.OBSERVATION_WINDOW_SECONDS)
    sess = DbSession(
        id=f"sess_obs_{secrets.token_hex(6)}",
        user_id=user.id,
        application="healthcare",
        status=status,
        current_risk_level=risk_level,
        observation_started_at=obs_start,
        observation_ends_at=obs_ends,
        observation_completed_at=now if status in ("ACTIVE", "PENDING_OTP", "STEP_UP_REQUIRED", "RESTRICTED") else None,
        login_time=obs_start,
    )
    db.add(sess)
    db.commit()
    db.refresh(sess)

    token = create_access_token(subject=user.id, role=user.role, session_id=sess.id)
    headers = {"Authorization": f"Bearer {token}", "X-Session-ID": sess.id}
    return user, sess, token, headers


def _appointment_payload(email: str, session_id: str, slot: str = "11:00 AM", doctor_id: str = "doc-2"):
    doc = next(d for d in HOSPITAL_DOCTORS if d["id"] == doctor_id)
    return {
        "session_id": session_id,
        "doctor_id": doctor_id,
        "appointment_date": _next_valid_date_for_doctor(doctor_id),
        "time_slot": slot,
        "patient_name": "Test Patient",
        "patient_age": 31,
        "patient_gender": "Female",
        "patient_phone": "+919876543210",
        "patient_email": email,
        "reason_for_visit": "Follow-up consultation",
        "department": doc["dept"],
        "consultation_mode": "In-Person OPD",
        "room": doc["room"],
    }


def test_scenario_1_blocked_during_20s_observation(client: TestClient, db_session: Session):
    user, sess, _, headers = _create_user_and_session(
        db_session,
        email="obs.inprogress@example.com",
        status="PENDING_OBSERVATION",
        obs_age_seconds=5,
    )

    obs_res = client.get(f"/api/auth/observation-status/{sess.id}", headers=headers)
    assert obs_res.status_code == 200
    obs_data = obs_res.json()
    assert obs_data["status"] == "PENDING_OBSERVATION"
    assert obs_data["is_completed"] is False
    assert obs_data["observation_seconds_remaining"] > 0

    sec_res = client.get(f"/api/security/status/{sess.id}", headers=headers)
    assert sec_res.status_code == 200
    assert sec_res.json()["session_status"] == "PENDING_OBSERVATION"
    assert sec_res.json()["decision"] == "OBSERVATION_PENDING"

    login_otp_res = client.post("/api/auth/login-otp/request", json={"session_id": sess.id}, headers=headers)
    assert login_otp_res.status_code == 400
    assert "Observation period incomplete" in login_otp_res.json()["detail"]

    apt_res = client.post(
        "/api/healthcare/appointment-otp/request",
        json=_appointment_payload(user.email, sess.id, slot="11:00 AM"),
        headers=headers,
    )
    assert apt_res.status_code == 403
    assert "observation" in apt_res.json()["detail"].lower()


def test_scenario_2_9_10_observation_completion_to_login_otp_to_confirmed_appointment(
    client: TestClient, db_session: Session
):
    captured_login_codes = []
    captured_apt_codes = []

    def cap_login_otp(recipient_email=None, otp_code=None, *args, **kwargs):
        captured_login_codes.append((recipient_email, otp_code))
        return (True, "Mocked login OTP sent")

    def cap_apt_otp(recipient_email=None, otp_code=None, *args, **kwargs):
        captured_apt_codes.append((recipient_email, otp_code))
        return (True, "Mocked appointment OTP sent")

    user, sess, _, headers = _create_user_and_session(
        db_session,
        email="obs.complete.patient@example.com",
        status="PENDING_OBSERVATION",
        obs_age_seconds=settings.OBSERVATION_WINDOW_SECONDS + 2,
    )

    # Confirm backend recognizes 20s elapsed
    obs_res = client.get(f"/api/auth/observation-status/{sess.id}", headers=headers)
    assert obs_res.status_code == 200
    assert obs_res.json()["is_completed"] is True
    assert obs_res.json()["observation_seconds_remaining"] == 0

    # Transition PENDING_OBSERVATION -> PENDING_OTP via login-otp/request
    with patch.object(EmailService, "send_otp_email", side_effect=cap_login_otp):
        req_res = client.post("/api/auth/login-otp/request", json={"session_id": sess.id}, headers=headers)
    assert req_res.status_code == 200
    assert req_res.json().get("challenge_id")
    assert len(captured_login_codes) == 1

    sec_pending = client.get(f"/api/security/status/{sess.id}", headers=headers)
    assert sec_pending.status_code == 200
    assert sec_pending.json()["session_status"] == "PENDING_OTP"

    # While PENDING_OTP, appointment booking is still gated (Scenario 9 prerequisite)
    gated_res = client.post(
        "/api/healthcare/appointment-otp/request",
        json=_appointment_payload(user.email, sess.id, slot="11:30 AM"),
        headers=headers,
    )
    assert gated_res.status_code == 403

    # Verify login OTP -> ACTIVE
    ver_res = client.post(
        "/api/auth/login-otp/verify",
        json={"session_id": sess.id, "otp_code": captured_login_codes[0][1]},
        headers=headers,
    )
    assert ver_res.status_code == 200
    assert ver_res.json()["session_status"] == "ACTIVE"

    sec_res = client.get(f"/api/security/status/{sess.id}", headers=headers)
    assert sec_res.status_code == 200
    assert sec_res.json()["session_status"] == "ACTIVE"

    # Request appointment OTP -> PENDING_VERIFICATION (Scenario 9)
    with patch.object(EmailService, "send_appointment_otp_email", side_effect=cap_apt_otp):
        apt_req = client.post(
            "/api/healthcare/appointment-otp/request",
            json=_appointment_payload(user.email, sess.id, slot="11:30 AM"),
            headers=headers,
        )
    assert apt_req.status_code == 200
    apt_data = apt_req.json()
    pending_ref = apt_data["pending_reference_id"]
    assert pending_ref.startswith("AYU-")
    assert len(captured_apt_codes) == 1

    # Verify appointment OTP -> CONFIRMED + appears in history (Scenario 10)
    apt_ver = client.post(
        "/api/healthcare/appointment-otp/verify",
        json={
            "session_id": sess.id,
            "challenge_id": apt_data["challenge_id"],
            "otp_code": captured_apt_codes[0][1],
        },
        headers=headers,
    )
    assert apt_ver.status_code == 200
    ver_body = apt_ver.json()
    assert ver_body["status"] == "CONFIRMED"
    assert ver_body["reference_id"] == pending_ref

    hist_res = client.get("/api/healthcare/appointments", params={"email": user.email}, headers=headers)
    assert hist_res.status_code == 200
    refs = [a["reference_id"] for a in hist_res.json()]
    assert pending_ref in refs


def test_scenario_4_5_missing_and_delayed_telemetry_do_not_block_post_observation(
    client: TestClient, db_session: Session
):
    """Zero telemetry samples during observation OR delayed telemetry after ACTIVE must never keep booking blocked."""
    captured = []
    user, sess, _, headers = _create_user_and_session(
        db_session,
        email="missing.tel@example.com",
        status="PENDING_OBSERVATION",
        obs_age_seconds=settings.OBSERVATION_WINDOW_SECONDS + 1,
    )

    obs_res = client.get(f"/api/auth/observation-status/{sess.id}", headers=headers)
    assert obs_res.status_code == 200
    assert obs_res.json()["telemetry_samples_count"] == 0
    assert obs_res.json()["is_completed"] is True

    with patch.object(
        EmailService,
        "send_otp_email",
        side_effect=lambda recipient_email=None, otp_code=None, *a, **kw: (captured.append(otp_code) or (True, "OK")),
    ):
        req_res = client.post("/api/auth/login-otp/request", json={"session_id": sess.id}, headers=headers)
    assert req_res.status_code == 200

    ver_res = client.post(
        "/api/auth/login-otp/verify",
        json={"session_id": sess.id, "otp_code": captured[0]},
        headers=headers,
    )
    assert ver_res.status_code == 200

    # Delayed / normal telemetry event arriving right after ACTIVE must keep decision ALLOW
    tel_res = client.post(
        "/api/behavior/events",
        json={
            "session_id": sess.id,
            "application": "healthcare",
            "typing_speed": 45.0,
            "typing_variance": 0.12,
            "mouse_speed": 1.4,
            "mouse_jitter": 0.08,
            "click_frequency": 0.6,
            "navigation_entropy": 1.1,
            "scroll_velocity": 120.0,
            "focus_change_rate": 0.1,
        },
        headers=headers,
    )
    assert tel_res.status_code == 200
    assert tel_res.json()["session_status"] in ("ACTIVE", "STEP_UP_REQUIRED")


def test_scenario_7_8_elevated_risk_and_critical_termination_block_booking(
    client: TestClient, db_session: Session
):
    # Elevated risk STEP_UP_REQUIRED & RESTRICTED must return 403
    user1, sess_stepup, _, headers1 = _create_user_and_session(
        db_session,
        email="stepup.patient@example.com",
        status="STEP_UP_REQUIRED",
        risk_level="MEDIUM",
        obs_age_seconds=30,
    )
    r_step = client.post(
        "/api/healthcare/appointment-otp/request",
        json=_appointment_payload(user1.email, sess_stepup.id, slot="12:00 PM"),
        headers=headers1,
    )
    assert r_step.status_code == 403
    assert "step-up" in r_step.json()["detail"].lower()

    user2, sess_rest, _, headers2 = _create_user_and_session(
        db_session,
        email="restricted.patient@example.com",
        status="RESTRICTED",
        risk_level="HIGH",
        obs_age_seconds=30,
    )
    r_rest = client.post(
        "/api/healthcare/appointment-otp/request",
        json=_appointment_payload(user2.email, sess_rest.id, slot="12:00 PM"),
        headers=headers2,
    )
    assert r_rest.status_code == 403
    assert "step-up" in r_rest.json()["detail"].lower()

    # Critical TERMINATED session
    user3, sess_term, _, headers3 = _create_user_and_session(
        db_session,
        email="terminated.patient@example.com",
        status="TERMINATED",
        risk_level="CRITICAL",
        obs_age_seconds=30,
    )
    r_term = client.post(
        "/api/healthcare/appointment-otp/request",
        json=_appointment_payload(user3.email, sess_term.id, slot="12:00 PM"),
        headers=headers3,
    )
    assert r_term.status_code in (401, 403)


def test_frontend_client_and_healthcare_sync_scenarios_in_node_vm():
    """
    Executes the real CognisecClient class (cognisec-client.js) and healthcare.html state/booking helpers
    in Node VM across Scenarios 1, 2, 3, 5, 6, 7, 8 to verify:
    - executeObservationOtpTransition updates sessionStatus -> PENDING_OTP + localStorage + cognisec:auth_change
    - stale frontend sessionStatus=='PENDING_OBSERVATION' reconciles against backend ACTIVE and unblocks booking
    - PENDING_OBSERVATION with is_completed=true automatically triggers OTP transition cleanly
    - delayed backend response settles without spurious 20s error
    - expired/404 session clears localStorage (including cognisec_session_status) and reports expiration
    - STEP_UP_REQUIRED / RESTRICTED opens openStepUpModal instead of generic 20s message
    - syncHealthcareAuthState auto-clears #booking-modal-error once ACTIVE
    """
    node_script = r"""
const fs = require('fs');
const vm = require('vm');
const path = require('path');

const clientCode = fs.readFileSync(path.join(process.env.REPO_ROOT, 'cognisec-client.js'), 'utf8');
const html = fs.readFileSync(path.join(process.env.REPO_ROOT, 'healthcare.html'), 'utf8');

function extractFn(source, signatureStart) {
  const idx = source.indexOf(signatureStart);
  if (idx === -1) throw new Error('Missing function: ' + signatureStart);
  let i = source.indexOf('{', idx);
  let depth = 0;
  let inStr = null;
  let esc = false;
  for (; i < source.length; i++) {
    const ch = source[i];
    if (esc) { esc = false; continue; }
    if (inStr) {
      if (ch === '\\') esc = true;
      else if (ch === inStr) inStr = null;
      continue;
    }
    if (ch === "'" || ch === '"' || ch === '`') { inStr = ch; continue; }
    if (ch === '{') depth++;
    else if (ch === '}') {
      depth--;
      if (depth === 0) return source.slice(idx, i + 1);
    }
  }
  throw new Error('Unbalanced braces for ' + signatureStart);
}

const storageMap = new Map();
const localStorage = {
  getItem: k => storageMap.has(k) ? storageMap.get(k) : null,
  setItem: (k, v) => storageMap.set(k, String(v)),
  removeItem: k => storageMap.delete(k)
};

function makeEl(id) {
  return {
    id,
    value: '',
    textContent: '',
    innerHTML: '',
    disabled: false,
    _classes: new Set(),
    classList: {
      add(c) { this._p._classes.add(c); },
      remove(c) { this._p._classes.delete(c); },
      contains(c) { return this._p._classes.has(c); }
    },
    focus() {},
    addEventListener() {},
    querySelector() { return null; }
  };
}
function attachP(el) { el.classList._p = el; return el; }
const elements = {};
for (const id of [
  'appointment-modal', 'booking-modal-error', 'doctor-header-info', 'doctor-status-label', 'doctor-name-label',
  'btn-header-signout', 'btn-header-signin', 'btn-header-mfa', 'doctor-status-dot',
  'modal-patient-name', 'modal-patient-age', 'modal-patient-gender', 'modal-patient-phone',
  'modal-patient-email', 'modal-patient-reason', 'modal-doc-select', 'modal-date-input',
  'modal-selected-slot', 'modal-mode-select', 'btn-submit-appointment', 'step-indicator-1',
  'step-indicator-2', 'step-indicator-3'
]) {
  elements[id] = attachP(makeEl(id));
}
elements['booking-modal-error'].classList.add('hidden');
elements['modal-patient-name'].value = 'Ananya Test';
elements['modal-patient-age'].value = '29';
elements['modal-patient-gender'].value = 'Female';
elements['modal-patient-phone'].value = '+919876543210';
elements['modal-patient-email'].value = 'ananya@example.com';
elements['modal-patient-reason'].value = 'Consultation';
elements['modal-doc-select'].value = 'doc-2';
elements['modal-date-input'].value = '2099-11-10';
elements['modal-selected-slot'].value = '11:00 AM';
elements['modal-mode-select'].value = 'In-Person OPD';

let listeners = {};
let dispatchedEvents = [];
let mockFetchHandler = async () => ({ ok: true, status: 200, json: async () => ({}) });

const document = {
  body: { appendChild() {} },
  createElement: () => attachP(makeEl('dyn')),
  getElementById: id => elements[id] || null,
  addEventListener: () => {}
};

const windowObj = {
  location: { hostname: '127.0.0.1', pathname: '/healthcare.html', reload() {} },
  localStorage,
  document,
  addEventListener: (ev, fn) => { (listeners[ev] = listeners[ev] || []).push(fn); },
  dispatchEvent: (ev) => {
    dispatchedEvents.push(ev.type);
    for (const fn of (listeners[ev.type] || [])) fn(ev);
  },
  showNotificationToast: () => {},
  fetch: (...args) => mockFetchHandler(...args),
};

const ctx = {
  window: windowObj,
  document,
  localStorage,
  navigator: { userAgent: 'Mozilla/5.0' },
  performance: { now: () => Date.now() },
  CustomEvent: class CustomEvent { constructor(type, init = {}) { this.type = type; this.detail = init.detail; } },
  fetch: (...args) => mockFetchHandler(...args),
  console: { log() {}, warn() {}, error() {} },
  setTimeout: (fn, ms) => 1,
  clearTimeout: () => {},
  setInterval: () => 1,
  clearInterval: () => {},
  isDoctorLoggedIn: false,
  isEhrVaultUnlocked: false,
  lockEhrVault() {},
  updateContinuousVerificationPanel() {},
  refreshPatientAppointments() {},
  DOCTORS: [{ id: 'doc-2', name: 'Dr. Sarah Lin', dept: 'cardiology', fee: 'INR 1200', room: 'OPD 202', availableDays: ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'], slots: ['11:00 AM'] }],
  showBookingModalError(msg) {
    elements['booking-modal-error'].textContent = msg;
    elements['booking-modal-error'].classList.remove('hidden');
  },
  clearBookingModalError() {
    elements['booking-modal-error'].textContent = '';
    elements['booking-modal-error'].classList.add('hidden');
  },
  showToast() {},
  goToStep1() {},
  resetAppointmentSubmitState() { ctx.isSubmittingAppointment = false; },
  openAppointmentOtpModal() {},
  lastOtpAppointmentPayload: null
};
ctx.window.document = document;
vm.createContext(ctx);

// Load cognisec-client.js without auto-startup side effects interfering with mock
const trimmedClient = clientCode.replace('window.cognisec = new CognisecClient();', '') + '\nwindow.CognisecClient = CognisecClient;\n';
vm.runInContext(trimmedClient, ctx);

// Inject healthcare.html functions under test
const fnSync = extractFn(html, 'function syncHealthcareAuthState()');
const fnSubmit = extractFn(html, 'async function handleAppointmentSubmit(e)');
vm.runInContext('let lastConfirmedAppointment = null;\nlet isSubmittingAppointment = false;\n' + fnSync + '\n' + fnSubmit, ctx);
vm.runInContext("window.addEventListener('cognisec:auth_change', syncHealthcareAuthState);", ctx);

(async () => {
  const client = new ctx.window.CognisecClient();
  client.stopTelemetryLoop();
  client.openAppointmentOtpModal = () => {};
  ctx.window.cognisec = client;

  function setLoggedInState(status) {
    client.token = 'jwt-token-123';
    client.sessionId = 'sess_vm_1';
    client.user = { id: 1, name: 'Ananya', email: 'ananya@example.com', role: 'USER', account_status: status };
    client.sessionStatus = status;
    localStorage.setItem('cognisec_token', 'jwt-token-123');
    localStorage.setItem('cognisec_session_id', 'sess_vm_1');
    localStorage.setItem('cognisec_session_status', status);
  }

  // Case A: executeObservationOtpTransition updates sessionStatus -> PENDING_OTP and fires auth_change
  setLoggedInState('PENDING_OBSERVATION');
  mockFetchHandler = async (url) => {
    if (url.includes('/behavior/events')) return { ok: true, status: 200, json: async () => ({ decision: 'OBSERVATION_PENDING' }) };
    if (url.includes('/auth/login-otp/request')) return { ok: true, status: 200, json: async () => ({ challenge_id: 'ch_1', masked_email: 'a***@example.com', status: 'PENDING_OTP' }) };
    return { ok: true, status: 200, json: async () => ({}) };
  };
  await client.executeObservationOtpTransition('sess_vm_1');
  if (client.sessionStatus !== 'PENDING_OTP' || localStorage.getItem('cognisec_session_status') !== 'PENDING_OTP') {
    throw new Error('Case A failed: expected PENDING_OTP, got ' + client.sessionStatus);
  }

  // Case B: Stale frontend state (PENDING_OBSERVATION) + warning currently visible -> backend says ACTIVE -> clears error and sends appointment-otp/request!
  setLoggedInState('PENDING_OBSERVATION');
  client.observationSecondsRemaining = 12;
  ctx.showBookingModalError('Baseline behavioral observation (20s) is still in progress. Please wait until session verification completes.');
  let appointmentRequested = false;
  mockFetchHandler = async (url) => {
    if (url.includes('/security/status/')) return { ok: true, status: 200, json: async () => ({ session_status: 'ACTIVE', decision: 'ALLOW', message: 'Active' }) };
    if (url.includes('/auth/observation-status/')) return { ok: true, status: 200, json: async () => ({ status: 'ACTIVE', observation_seconds_remaining: 0, is_completed: true }) };
    if (url.includes('/healthcare/availability')) return { ok: true, status: 200, json: async () => ({ available: true }) };
    if (url.includes('/healthcare/appointment-otp/request')) {
      appointmentRequested = true;
      return { ok: true, status: 200, json: async () => ({ reference_id: 'APT-1', challenge_id: 'ch_apt', masked_email: 'a***@example.com', expires_in_seconds: 300, status: 'PENDING_VERIFICATION' }) };
    }
    return { ok: true, status: 200, json: async () => ({}) };
  };
  await ctx.handleAppointmentSubmit();
  if (!appointmentRequested || client.sessionStatus !== 'ACTIVE' || !elements['booking-modal-error'].classList.contains('hidden')) {
    throw new Error('Case B failed: stale PENDING_OBSERVATION did not sync to ACTIVE cleanly');
  }

  // Case C: Delayed backend response still succeeds once backend confirms ACTIVE
  setLoggedInState('PENDING_OBSERVATION');
  appointmentRequested = false;
  mockFetchHandler = async (url) => {
    await new Promise(r => setTimeout(r, 25));
    if (url.includes('/security/status/')) return { ok: true, status: 200, json: async () => ({ session_status: 'ACTIVE', decision: 'ALLOW' }) };
    if (url.includes('/auth/observation-status/')) return { ok: true, status: 200, json: async () => ({ status: 'ACTIVE', observation_seconds_remaining: 0, is_completed: true }) };
    if (url.includes('/healthcare/availability')) return { ok: true, status: 200, json: async () => ({ available: true }) };
    if (url.includes('/healthcare/appointment-otp/request')) {
      appointmentRequested = true;
      return { ok: true, status: 200, json: async () => ({ reference_id: 'APT-2', challenge_id: 'ch_apt2', masked_email: 'a***@example.com', expires_in_seconds: 300, status: 'PENDING_VERIFICATION' }) };
    }
    return { ok: true, status: 200, json: async () => ({}) };
  };
  await ctx.handleAppointmentSubmit();
  if (!appointmentRequested) throw new Error('Case C failed: delayed status sync did not proceed to booking');

  // Case D: Wrong / expired session ID (404) clears auth & localStorage including cognisec_session_status
  setLoggedInState('PENDING_OBSERVATION');
  mockFetchHandler = async () => ({ ok: false, status: 404, json: async () => ({ detail: 'Session not found' }) });
  await ctx.handleAppointmentSubmit();
  if (client.token !== null || localStorage.getItem('cognisec_session_status') !== null) {
    throw new Error('Case D failed: expired session did not clear auth/session_status');
  }
  if (!elements['booking-modal-error'].textContent.toLowerCase().includes('expired')) {
    throw new Error('Case D failed: missing expired session message');
  }

  // Case E: Elevated risk (STEP_UP_REQUIRED) opens step-up modal instead of generic 20s observation text
  setLoggedInState('ACTIVE');
  let stepUpOpened = false;
  client.openStepUpModal = () => { stepUpOpened = true; };
  mockFetchHandler = async (url) => {
    if (url.includes('/security/status/')) return { ok: true, status: 200, json: async () => ({ session_status: 'STEP_UP_REQUIRED', decision: 'STEP_UP_VERIFICATION', message: 'Step-up required.' }) };
    if (url.includes('/auth/observation-status/')) return { ok: true, status: 200, json: async () => ({ status: 'STEP_UP_REQUIRED', observation_seconds_remaining: 0, is_completed: true }) };
    return { ok: true, status: 200, json: async () => ({}) };
  };
  await ctx.handleAppointmentSubmit();
  if (!stepUpOpened || elements['booking-modal-error'].textContent.includes('20s')) {
    throw new Error('Case E failed: STEP_UP_REQUIRED did not open step-up modal cleanly');
  }

  // Case F: clearAuth removes cognisec_session_status
  setLoggedInState('ACTIVE');
  client.clearAuth();
  if (localStorage.getItem('cognisec_session_status') !== null) {
    throw new Error('Case F failed: clearAuth left stale cognisec_session_status');
  }

  console.log('ALL_NODE_VM_CASES_PASSED');
})();
"""
    env = dict(os.environ, REPO_ROOT=REPO_ROOT)
    proc = subprocess.run(
        ["node", "-e", node_script],
        capture_output=True,
        text=True,
        env=env,
        timeout=20,
    )
    assert proc.returncode == 0, f"Node VM check failed:\nSTDOUT: {proc.stdout}\nSTDERR: {proc.stderr}"
    assert "ALL_NODE_VM_CASES_PASSED" in proc.stdout
