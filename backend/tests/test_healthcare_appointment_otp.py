"""
Comprehensive Test Suite: Healthcare Doctor Appointment Booking & Real Email OTP Flow
Covers:
- Every doctor (doc-1 through doc-6) availability, fee, schedule validation, and slot reservation
- PENDING_VERIFICATION appointment creation on OTP request
- OTP generation, HMAC-SHA256 hashing, non-exposure in API responses, EmailService recipient routing
- Invalid/expired/reused OTP prevention & pending/failed status isolation from confirmed history
- Resend cooldown enforcement & resend after cooldown
- Email failure rollback (keeps appointment unconfirmed)
- Both authenticated patient & walk-in outpatient flows, plus restricted session rejection
- Patient appointment history & cross-user isolation
"""

import secrets
from datetime import date, datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.security import get_password_hash, create_access_token
from app.models.appointment import HealthcareAppointment
from app.models.otp_challenge import OTPChallenge
from app.models.session import Session as DbSession
from app.models.user import User
from app.services.email_service import EmailService
from app.services.healthcare_service import HOSPITAL_DOCTORS
from app.services.step_up_service import StepUpService


@pytest.fixture(autouse=True)
def reset_step_up_challenges():
    StepUpService.reset()
    yield
    StepUpService.reset()


def _next_valid_date_for_doctor(doctor_id: str, min_offset_days: int = 1) -> str:
    """Returns the nearest future YYYY-MM-DD falling on a doctor's configured OPD weekday."""
    doc = next(d for d in HOSPITAL_DOCTORS if d["id"] == doctor_id)
    allowed = set(doc["available_days"])
    candidate = date.today() + timedelta(days=min_offset_days)
    for _ in range(14):
        if candidate.strftime("%a") in allowed:
            return candidate.isoformat()
        candidate += timedelta(days=1)
    raise AssertionError(f"No valid OPD day found for {doctor_id}")


def _next_invalid_date_for_doctor(doctor_id: str) -> str:
    """Returns a future YYYY-MM-DD falling on a weekday when the doctor does NOT hold OPD."""
    doc = next(d for d in HOSPITAL_DOCTORS if d["id"] == doctor_id)
    allowed = set(doc["available_days"])
    candidate = date.today() + timedelta(days=1)
    for _ in range(14):
        if candidate.strftime("%a") not in allowed:
            return candidate.isoformat()
        candidate += timedelta(days=1)
    raise AssertionError(f"Doctor {doctor_id} works every day")


def _create_patient_with_session(
    db_session: Session,
    email: str = "patient.appointment@example.com",
    status: str = "ACTIVE",
    risk_level: str = "LOW",
):
    """Helper to create/reuse an active patient user and session."""
    user = db_session.query(User).filter(User.email == email).first()
    if not user:
        user = User(
            email=email,
            name="Ananya Sharma",
            password_hash=get_password_hash("PatientPass123!"),
            account_status="ACTIVE",
            role="USER",
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

    sess_id = f"sess_hc_{secrets.token_hex(6)}"
    now = datetime.now(timezone.utc)
    sess = DbSession(
        id=sess_id,
        user_id=user.id,
        application="healthcare",
        status=status,
        current_risk_level=risk_level,
        observation_started_at=now - timedelta(seconds=30),
        observation_ends_at=now - timedelta(seconds=10),
        observation_completed_at=now - timedelta(seconds=5),
        login_time=now - timedelta(seconds=35),
    )
    db_session.add(sess)
    db_session.commit()
    db_session.refresh(sess)

    token = create_access_token(
        subject=user.id,
        role=user.role,
        session_id=sess.id,
    )
    headers = {"Authorization": f"Bearer {token}"}
    return user, sess, headers


# ==============================================================================
# 1. ALL DOCTORS (doc-1 .. doc-6): METADATA, SLOTS, PENDING -> OTP -> CONFIRMED
# ==============================================================================
def test_every_doctor_booking_workflow_with_pending_state_and_email_otp(
    client: TestClient, db_session: Session
):
    """Verifies booking end-to-end for EVERY doctor listed in HOSPITAL_DOCTORS."""
    docs_resp = client.get("/api/healthcare/doctors")
    assert docs_resp.status_code == 200
    all_docs = docs_resp.json()
    assert len(all_docs) >= 6

    user, sess, headers = _create_patient_with_session(
        db_session, email="portal.user@example.com"
    )

    for idx, doc in enumerate(all_docs):
        StepUpService.reset()
        apt_date = _next_valid_date_for_doctor(doc["id"], min_offset_days=2 + idx)
        slot = doc["available_slots"][0]
        supplied_email = f"Patient.Booker{idx}@Example.com"

        # Slot listing endpoint returns configured doctor schedule
        slots_res = client.get(f"/api/healthcare/doctors/{doc['id']}/slots?date={apt_date}")
        assert slots_res.status_code == 200
        slots_data = slots_res.json()
        assert slots_data["is_opd_day"] is True
        assert any(s["slot"] == slot and s["available"] is True for s in slots_data["slots"])

        captured = {}

        def fake_send_email(**kwargs):
            captured["code"] = kwargs["otp_code"]
            captured["recipient"] = kwargs["recipient_email"]
            captured["doctor_name"] = kwargs["doctor_name"]
            return True, "250 2.0.0 OK Mock SMTP accepted"

        payload = {
            "session_id": sess.id,
            "doctor_id": doc["id"],
            "appointment_date": apt_date,
            "time_slot": slot,
            "patient_name": f"Ananya Patient {idx}",
            "patient_age": 29,
            "patient_gender": "Female",
            "patient_phone": f"987654321{idx}",
            "patient_email": supplied_email,
            "reason_for_visit": "Outpatient specialist checkup",
            "department": doc["dept_label"],
            "consultation_mode": "In-Person Hospital Visit",
        }

        with patch.object(EmailService, "send_appointment_otp_email", side_effect=fake_send_email) as mock_send:
            req_res = client.post("/api/healthcare/appointment-otp/request", json=payload, headers=headers)

        assert req_res.status_code == 200, f"Doctor {doc['id']} failed: {req_res.text}"
        req_data = req_res.json()

        # OTP MUST NOT appear in API response
        assert "otp" not in req_data
        assert req_data["doctor_id"] == doc["id"]
        assert req_data["doctor_name"] == doc["name"]
        assert req_data["consultation_fee"] == doc["fee"]
        pending_ref = req_data["pending_reference_id"]
        assert pending_ref.startswith("AYU-")

        # Email sent strictly to patient's supplied, normalized email
        assert mock_send.call_count == 1
        assert captured["recipient"] == supplied_email.lower()
        assert len(captured["code"]) == 6 and captured["code"].isdigit()

        # Pending appointment exists as PENDING_VERIFICATION (NOT CONFIRMED) before OTP verify
        pending_apt = db_session.query(HealthcareAppointment).filter(
            HealthcareAppointment.reference_id == pending_ref
        ).first()
        assert pending_apt is not None
        assert pending_apt.status == "PENDING_VERIFICATION"
        assert pending_apt.consultation_fee == doc["fee"]

        # Verify Challenge links to pending_apt and stores ONLY hash
        chal_row = db_session.query(OTPChallenge).filter(
            OTPChallenge.challenge_id == req_data["challenge_id"]
        ).first()
        assert chal_row is not None
        assert chal_row.appointment_id == pending_apt.id
        assert chal_row.otp_hash != captured["code"]

        # History endpoint MUST NOT display PENDING_VERIFICATION appointment
        pre_hist = client.get("/api/healthcare/appointments", headers=headers)
        assert pre_hist.status_code == 200
        assert not any(a["reference_id"] == pending_ref for a in pre_hist.json())

        # Verify OTP -> atomically transitions PENDING_VERIFICATION -> CONFIRMED
        ver_res = client.post(
            "/api/healthcare/appointment-otp/verify",
            json={
                "session_id": sess.id,
                "challenge_id": req_data["challenge_id"],
                "otp_code": captured["code"],
            },
            headers=headers,
        )
        assert ver_res.status_code == 200, ver_res.text
        ver_data = ver_res.json()
        assert ver_data["reference_id"] == pending_ref
        assert ver_data["status"] == "CONFIRMED"
        assert ver_data["appointment"]["doctor_id"] == doc["id"]
        assert ver_data["appointment"]["consultation_fee"] == doc["fee"]

        # Confirmed appointment now appears in patient's history
        post_hist = client.get("/api/healthcare/appointments", headers=headers)
        assert post_hist.status_code == 200
        assert any(
            a["reference_id"] == pending_ref and a["status"] == "CONFIRMED"
            for a in post_hist.json()
        )


# ==============================================================================
# 2. GUEST / PUBLIC PATIENT BOOKING FROM DOCTOR CARD (NO PRIOR LOGIN REQUIRED)
# ==============================================================================
def test_walkin_patient_booking_from_doctor_card_with_email_otp(
    client: TestClient, db_session: Session
):
    apt_date = _next_valid_date_for_doctor("doc-4", min_offset_days=8)
    captured = {}

    def capture(**kwargs):
        captured["code"] = kwargs["otp_code"]
        captured["recipient"] = kwargs["recipient_email"]
        return True, "250 2.0.0 OK"

    with patch.object(EmailService, "send_appointment_otp_email", side_effect=capture):
        req_res = client.post(
            "/api/healthcare/appointment-otp/request",
            json={
                "doctor_id": "doc-4",
                "appointment_date": apt_date,
                "time_slot": "11:00 AM",
                "patient_name": "Walkin Patient",
                "patient_age": 42,
                "patient_gender": "Male",
                "patient_phone": "9876543210",
                "patient_email": "walkin.patient@gmail.com",
                "department": "Orthopedics & Joint Replacement",
                "consultation_mode": "In-Person Hospital Visit",
            },
        )
    assert req_res.status_code == 200, req_res.text
    req_data = req_res.json()
    assert "otp" not in req_data
    assert captured["recipient"] == "walkin.patient@gmail.com"

    ver_res = client.post(
        "/api/healthcare/appointment-otp/verify",
        json={
            "challenge_id": req_data["challenge_id"],
            "otp_code": captured["code"],
        },
    )
    assert ver_res.status_code == 200, ver_res.text
    ver_data = ver_res.json()
    assert ver_data["status"] == "CONFIRMED"
    assert ver_data["appointment"]["doctor_name"] == "Dr. Vikramaditya Rao"

    # Patient history lookup by email shows the confirmed booking
    hist = client.get("/api/healthcare/appointments?email=walkin.patient@gmail.com")
    assert hist.status_code == 200
    assert any(a["reference_id"] == ver_data["reference_id"] for a in hist.json())


# ==============================================================================
# 3. INVALID PATIENT INFO, INVALID DOCTOR, OFF-DAY, OR INVALID SLOT REJECTED
# ==============================================================================
def test_appointment_otp_validation_and_doctor_schedule_enforcement(
    client: TestClient, db_session: Session
):
    _, sess, headers = _create_patient_with_session(db_session, email="sched@example.com")
    valid_date = _next_valid_date_for_doctor("doc-4", min_offset_days=2)

    # Blank patient name -> 422
    res_name = client.post(
        "/api/healthcare/appointment-otp/request",
        json={
            "session_id": sess.id,
            "doctor_id": "doc-4",
            "appointment_date": valid_date,
            "time_slot": "11:00 AM",
            "patient_name": "   ",
            "patient_phone": "9876543210",
            "patient_email": "sched@example.com",
            "department": "Orthopedics",
        },
        headers=headers,
    )
    assert res_name.status_code == 422

    # Unknown doctor -> 400
    res_doc = client.post(
        "/api/healthcare/appointment-otp/request",
        json={
            "session_id": sess.id,
            "doctor_id": "doc-unknown",
            "appointment_date": valid_date,
            "time_slot": "11:00 AM",
            "patient_name": "Valid Name",
            "patient_phone": "9876543210",
            "patient_email": "sched@example.com",
            "department": "Orthopedics",
        },
        headers=headers,
    )
    assert res_doc.status_code == 400

    # Doctor off-day rejected (Dr. Vikramaditya Rao works only Mon, Wed, Fri)
    off_date = _next_invalid_date_for_doctor("doc-4")
    res_off_day = client.post(
        "/api/healthcare/appointment-otp/request",
        json={
            "session_id": sess.id,
            "doctor_id": "doc-4",
            "appointment_date": off_date,
            "time_slot": "11:00 AM",
            "patient_name": "Valid Name",
            "patient_phone": "9876543210",
            "patient_email": "sched@example.com",
            "department": "Orthopedics",
        },
        headers=headers,
    )
    assert res_off_day.status_code == 400
    assert "does not hold opd" in res_off_day.json()["detail"].lower()

    # Invalid slot outside doctor's OPD hours rejected
    res_bad_slot = client.post(
        "/api/healthcare/appointment-otp/request",
        json={
            "session_id": sess.id,
            "doctor_id": "doc-4",
            "appointment_date": valid_date,
            "time_slot": "11:55 PM",
            "patient_name": "Valid Name",
            "patient_phone": "9876543210",
            "patient_email": "sched@example.com",
            "department": "Orthopedics",
        },
        headers=headers,
    )
    assert res_bad_slot.status_code == 400
    assert "opd schedule" in res_bad_slot.json()["detail"].lower()

    # Past date -> 422
    res_past = client.post(
        "/api/healthcare/appointment-otp/request",
        json={
            "session_id": sess.id,
            "doctor_id": "doc-4",
            "appointment_date": (date.today() - timedelta(days=1)).isoformat(),
            "time_slot": "11:00 AM",
            "patient_name": "Valid Name",
            "patient_phone": "9876543210",
            "patient_email": "sched@example.com",
            "department": "Orthopedics",
        },
        headers=headers,
    )
    assert res_past.status_code == 422


# ==============================================================================
# 4. ALREADY-BOOKED SLOT CONFLICT & DOUBLE CONFIRMATION RACE PROTECTION
# ==============================================================================
def test_appointment_otp_already_booked_slot_and_race_double_confirm_prevented(
    client: TestClient, db_session: Session
):
    user1, sess1, headers1 = _create_patient_with_session(db_session, email="race1@example.com")
    user2, sess2, headers2 = _create_patient_with_session(db_session, email="race2@example.com")
    apt_date = _next_valid_date_for_doctor("doc-1", min_offset_days=4)

    code1, code2 = {}, {}

    def cap1(**kwargs):
        code1["val"] = kwargs["otp_code"]
        return True, "OK"

    def cap2(**kwargs):
        code2["val"] = kwargs["otp_code"]
        return True, "OK"

    # Both patients simultaneously create PENDING_VERIFICATION for same slot before either verifies
    with patch.object(EmailService, "send_appointment_otp_email", side_effect=cap1):
        r1 = client.post(
            "/api/healthcare/appointment-otp/request",
            json={
                "session_id": sess1.id,
                "doctor_id": "doc-1",
                "appointment_date": apt_date,
                "time_slot": "09:45 AM",
                "patient_name": "Race One",
                "patient_phone": "9876541111",
                "patient_email": "race1@example.com",
                "department": "Cardiology",
            },
            headers=headers1,
        )
    assert r1.status_code == 200

    with patch.object(EmailService, "send_appointment_otp_email", side_effect=cap2):
        r2 = client.post(
            "/api/healthcare/appointment-otp/request",
            json={
                "session_id": sess2.id,
                "doctor_id": "doc-1",
                "appointment_date": apt_date,
                "time_slot": "09:45 AM",
                "patient_name": "Race Two",
                "patient_phone": "9876542222",
                "patient_email": "race2@example.com",
                "department": "Cardiology",
            },
            headers=headers2,
        )
    assert r2.status_code == 200

    # Patient 1 verifies first -> CONFIRMED
    v1 = client.post(
        "/api/healthcare/appointment-otp/verify",
        json={"session_id": sess1.id, "challenge_id": r1.json()["challenge_id"], "otp_code": code1["val"]},
        headers=headers1,
    )
    assert v1.status_code == 200

    # Patient 2 verifies second -> blocked because slot was just confirmed
    v2 = client.post(
        "/api/healthcare/appointment-otp/verify",
        json={"session_id": sess2.id, "challenge_id": r2.json()["challenge_id"], "otp_code": code2["val"]},
        headers=headers2,
    )
    assert v2.status_code == 400
    assert "confirmed by another patient" in v2.json()["detail"].lower()

    # Patient 2's pending appointment marked FAILED, not CONFIRMED
    db_session.expire_all()
    p2_apt = db_session.query(HealthcareAppointment).filter(
        HealthcareAppointment.reference_id == r2.json()["pending_reference_id"]
    ).first()
    assert p2_apt.status == "FAILED"

    # Subsequent booking attempt for that confirmed slot returns 409 Conflict
    _, sess3, headers3 = _create_patient_with_session(db_session, email="race3@example.com")
    r3 = client.post(
        "/api/healthcare/appointment-otp/request",
        json={
            "session_id": sess3.id,
            "doctor_id": "doc-1",
            "appointment_date": apt_date,
            "time_slot": "09:45 AM",
            "patient_name": "Race Three",
            "patient_phone": "9876543333",
            "patient_email": "race3@example.com",
            "department": "Cardiology",
        },
        headers=headers3,
    )
    assert r3.status_code == 409


# ==============================================================================
# 5. DUPLICATE SUBMISSION / COOLDOWN & RESEND LIFECYCLE
# ==============================================================================
def test_appointment_otp_cooldown_and_resend_keeps_pending_appointment(
    client: TestClient, db_session: Session
):
    _, sess, headers = _create_patient_with_session(db_session, email="resend@example.com")
    apt_date = _next_valid_date_for_doctor("doc-3", min_offset_days=5)
    dispatched = []

    def capture(**kwargs):
        dispatched.append(kwargs["otp_code"])
        return True, "OK"

    payload = {
        "session_id": sess.id,
        "doctor_id": "doc-3",
        "appointment_date": apt_date,
        "time_slot": "10:30 AM",
        "patient_name": "Resend Patient",
        "patient_phone": "9876543299",
        "patient_email": "resend@example.com",
        "department": "Pediatrics",
    }

    with patch.object(EmailService, "send_appointment_otp_email", side_effect=capture):
        r1 = client.post("/api/healthcare/appointment-otp/request", json=payload, headers=headers)
        assert r1.status_code == 200
        chal_1 = r1.json()["challenge_id"]
        pending_ref = r1.json()["pending_reference_id"]

        # Immediate duplicate request / resend within 15s blocked -> 429
        assert client.post("/api/healthcare/appointment-otp/request", json=payload, headers=headers).status_code == 429
        assert client.post(
            "/api/healthcare/appointment-otp/resend",
            json={"session_id": sess.id, "challenge_id": chal_1},
            headers=headers,
        ).status_code == 429

        # Advance cooldown past 15s (both DB and in-memory challenge)
        chal_row = db_session.query(OTPChallenge).filter(OTPChallenge.challenge_id == chal_1).first()
        chal_row.cooldown_until = datetime.now(timezone.utc) - timedelta(seconds=5)
        db_session.commit()
        with StepUpService._lock:
            for k in (chal_1, f"apt:{sess.id}"):
                if k in StepUpService._challenges:
                    StepUpService._challenges[k]["cooldown_until"] = (
                        datetime.now(timezone.utc) - timedelta(seconds=5)
                    )

        r2 = client.post(
            "/api/healthcare/appointment-otp/resend",
            json={"session_id": sess.id, "challenge_id": chal_1},
            headers=headers,
        )
        assert r2.status_code == 200
        chal_2 = r2.json()["challenge_id"]
        assert chal_2 != chal_1
        assert r2.json()["pending_reference_id"] == pending_ref

    assert len(dispatched) == 2
    old_code, new_code = dispatched[0], dispatched[1]

    # Old code fails
    assert client.post(
        "/api/healthcare/appointment-otp/verify",
        json={"session_id": sess.id, "challenge_id": chal_1, "otp_code": old_code},
        headers=headers,
    ).status_code == 400

    # New code confirms original pending appointment
    ver = client.post(
        "/api/healthcare/appointment-otp/verify",
        json={"session_id": sess.id, "challenge_id": chal_2, "otp_code": new_code},
        headers=headers,
    )
    assert ver.status_code == 200
    assert ver.json()["reference_id"] == pending_ref


# ==============================================================================
# 6. INVALID / EXPIRED / REUSED OTP LOCKS CHALLENGE & KEEPS APPOINTMENT UNCONFIRMED
# ==============================================================================
def test_appointment_otp_invalid_expired_and_reuse_prevented(
    client: TestClient, db_session: Session
):
    _, sess, headers = _create_patient_with_session(db_session, email="security@example.com")
    apt_date = _next_valid_date_for_doctor("doc-5", min_offset_days=2)
    issued = {}

    def cap(**kwargs):
        issued["val"] = kwargs["otp_code"]
        return True, "OK"

    with patch.object(EmailService, "send_appointment_otp_email", side_effect=cap):
        r1 = client.post(
            "/api/healthcare/appointment-otp/request",
            json={
                "session_id": sess.id,
                "doctor_id": "doc-5",
                "appointment_date": apt_date,
                "time_slot": "03:30 PM",
                "patient_name": "Lockout Test",
                "patient_phone": "9876543288",
                "patient_email": "security@example.com",
                "department": "Dermatology",
            },
            headers=headers,
        )
    assert r1.status_code == 200
    chal_1 = r1.json()["challenge_id"]
    ref_1 = r1.json()["pending_reference_id"]
    wrong_code = "000000" if issued["val"] != "000000" else "999999"

    # 1 wrong attempt locks healthcare portal (423) and marks pending appointment FAILED
    res_bad = client.post(
        "/api/healthcare/appointment-otp/verify",
        json={"session_id": sess.id, "challenge_id": chal_1, "otp_code": wrong_code},
        headers=headers,
    )
    assert res_bad.status_code == 423
    assert res_bad.headers.get("X-Cognisec-Portal-Locked") == "true"

    db_session.expire_all()
    apt1 = db_session.query(HealthcareAppointment).filter(HealthcareAppointment.reference_id == ref_1).first()
    assert apt1.status == "FAILED"

    # Test Expiry cleanly using a second non-locked patient session
    _, sess2, headers2 = _create_patient_with_session(db_session, email="expiry_apt@example.com")
    with patch.object(EmailService, "send_appointment_otp_email", side_effect=cap):
        r2 = client.post(
            "/api/healthcare/appointment-otp/request",
            json={
                "session_id": sess2.id,
                "doctor_id": "doc-5",
                "appointment_date": apt_date,
                "time_slot": "03:30 PM",
                "patient_name": "Expiry Test",
                "patient_phone": "9876543288",
                "patient_email": "expiry_apt@example.com",
                "department": "Dermatology",
            },
            headers=headers2,
        )
    assert r2.status_code == 200
    chal_2 = r2.json()["challenge_id"]
    ref_2 = r2.json()["pending_reference_id"]

    # Force expiry
    c2_row = db_session.query(OTPChallenge).filter(OTPChallenge.challenge_id == chal_2).first()
    c2_row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=5)
    db_session.commit()

    res_exp = client.post(
        "/api/healthcare/appointment-otp/verify",
        json={"session_id": sess2.id, "challenge_id": chal_2, "otp_code": issued["val"]},
        headers=headers2,
    )
    assert res_exp.status_code == 400
    assert "expired" in res_exp.json()["detail"].lower()

    db_session.expire_all()
    apt2 = db_session.query(HealthcareAppointment).filter(HealthcareAppointment.reference_id == ref_2).first()
    assert apt2.status == "EXPIRED"

    # Confirmed appointment OTP cannot be reused
    c2_row.cooldown_until = datetime.now(timezone.utc) - timedelta(seconds=5)
    db_session.commit()
    with patch.object(EmailService, "send_appointment_otp_email", side_effect=cap):
        r3 = client.post(
            "/api/healthcare/appointment-otp/request",
            json={
                "session_id": sess2.id,
                "doctor_id": "doc-5",
                "appointment_date": apt_date,
                "time_slot": "03:30 PM",
                "patient_name": "Reuse Test",
                "patient_phone": "9876543288",
                "patient_email": "expiry_apt@example.com",
                "department": "Dermatology",
            },
            headers=headers2,
        )
    assert r3.status_code == 200
    chal_3 = r3.json()["challenge_id"]

    ok_res = client.post(
        "/api/healthcare/appointment-otp/verify",
        json={"session_id": sess2.id, "challenge_id": chal_3, "otp_code": issued["val"]},
        headers=headers2,
    )
    assert ok_res.status_code == 200

    replay_res = client.post(
        "/api/healthcare/appointment-otp/verify",
        json={"session_id": sess2.id, "challenge_id": chal_3, "otp_code": issued["val"]},
        headers=headers2,
    )
    assert replay_res.status_code == 400
    assert "already been used" in replay_res.json()["detail"].lower()


# ==============================================================================
# 7. EMAIL FAILURE & RESTRICTED SESSION PROTECTION & HISTORY ISOLATION
# ==============================================================================
def test_email_failure_restricted_sessions_and_history_isolation(
    client: TestClient, db_session: Session
):
    apt_date = _next_valid_date_for_doctor("doc-6", min_offset_days=3)

    # Email failure returns 502, removes challenge, marks pending FAILED (never CONFIRMED)
    _, sess, headers = _create_patient_with_session(db_session, email="failmail@example.com")
    with patch.object(EmailService, "send_appointment_otp_email", return_value=(False, "SMTP 535 auth failure")):
        res_fail = client.post(
            "/api/healthcare/appointment-otp/request",
            json={
                "session_id": sess.id,
                "doctor_id": "doc-6",
                "appointment_date": apt_date,
                "time_slot": "09:15 AM",
                "patient_name": "Mail Fail User",
                "patient_phone": "9876543277",
                "patient_email": "failmail@example.com",
                "department": "General Medicine",
            },
            headers=headers,
        )
    assert res_fail.status_code == 502
    assert db_session.query(OTPChallenge).filter(OTPChallenge.session_id == sess.id).first() is None
    failed_apt = db_session.query(HealthcareAppointment).filter(
        HealthcareAppointment.patient_email == "failmail@example.com"
    ).first()
    assert failed_apt is not None and failed_apt.status == "FAILED"

    # PENDING_OBSERVATION session blocked -> 403
    _, sess_obs, headers_obs = _create_patient_with_session(
        db_session, email="obs.only@example.com", status="PENDING_OBSERVATION"
    )
    assert (
        client.post(
            "/api/healthcare/appointment-otp/request",
            json={
                "session_id": sess_obs.id,
                "doctor_id": "doc-6",
                "appointment_date": apt_date,
                "time_slot": "10:00 AM",
                "patient_name": "Obs User",
                "patient_phone": "9876543276",
                "patient_email": "obs.only@example.com",
                "department": "General Medicine",
            },
            headers=headers_obs,
        ).status_code
        == 403
    )

    # TERMINATED session blocked -> 401/403
    _, sess_term, headers_term = _create_patient_with_session(
        db_session, email="term.only@example.com", status="TERMINATED", risk_level="CRITICAL"
    )
    assert (
        client.post(
            "/api/healthcare/appointment-otp/request",
            json={
                "session_id": sess_term.id,
                "doctor_id": "doc-6",
                "appointment_date": apt_date,
                "time_slot": "10:00 AM",
                "patient_name": "Term User",
                "patient_phone": "9876543275",
                "patient_email": "term.only@example.com",
                "department": "General Medicine",
            },
            headers=headers_term,
        ).status_code
        in (401, 403)
    )

    # History isolation across authenticated patients
    user_a, _, headers_a = _create_patient_with_session(db_session, email="hist.a@example.com")
    _, _, headers_b = _create_patient_with_session(db_session, email="hist.b@example.com")
    apt_a = HealthcareAppointment(
        reference_id=f"AYU-2026-{secrets.token_hex(3).upper()}",
        patient_name="Patient A",
        patient_phone="9876501111",
        patient_email=user_a.email,
        department="General Medicine & Diabetology",
        doctor_id="doc-6",
        doctor_name="Dr. Sandeep Verma",
        appointment_date=apt_date,
        time_slot="11:00 AM",
        consultation_mode="In-Person Hospital Visit",
        consultation_fee="₹800",
        status="CONFIRMED",
        user_id=user_a.id,
    )
    db_session.add(apt_a)
    db_session.commit()

    res_b = client.get(f"/api/healthcare/appointments?email={user_a.email}", headers=headers_b)
    assert res_b.status_code == 200
    assert not any(a["reference_id"] == apt_a.reference_id for a in res_b.json())
