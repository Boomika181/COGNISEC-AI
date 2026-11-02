"""
Test Suite: Healthcare Portal Integration & Zero Trust Clinical Security
Verifies:
1. Doctor authentication with valid credentials and doctor role.
2. Doctor login failure with invalid credentials.
3. Unauthorized access rejection for non-doctor accounts attempting doctor sign-in.
4. Normal /api/auth/login endpoint with doctor_required enforcement.
5. Clinical EHR Vault access control and Zero Trust grant verification.
6. Healthcare department catalog and specialist directory retrieval.
7. Patient appointment booking, date validation, conflict prevention, and DB persistence.
8. Appointment retrieval by patient email.
"""

import pytest
from datetime import date, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.appointment import HealthcareAppointment
from app.models.device import Device
from app.core.security import get_password_hash, create_access_token


@pytest.fixture
def test_doctor_user(db_session: Session) -> User:
    """Provides an active DOCTOR user for testing."""
    doctor = db_session.query(User).filter(User.email == "dr.boomika@ayusync.med.in").first()
    if not doctor:
        doctor = User(
            email="dr.boomika@ayusync.med.in",
            name="Dr. Boomika Ram",
            password_hash=get_password_hash("Doctor@123"),
            account_status="ACTIVE",
            role="DOCTOR"
        )
        db_session.add(doctor)
        db_session.commit()
        db_session.refresh(doctor)
    else:
        doctor.role = "DOCTOR"
        doctor.account_status = "ACTIVE"
        doctor.password_hash = get_password_hash("Doctor@123")
        db_session.commit()
        db_session.refresh(doctor)
    return doctor


@pytest.fixture
def test_regular_user(db_session: Session) -> User:
    """Provides an active regular non-doctor user (e.g. patient or student)."""
    user = db_session.query(User).filter(User.email == "patient.user@cognisec.ai").first()
    if not user:
        user = User(
            email="patient.user@cognisec.ai",
            name="Patient Test User",
            password_hash=get_password_hash("Password123!"),
            account_status="ACTIVE",
            role="USER"
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
    else:
        user.role = "USER"
        user.account_status = "ACTIVE"
        user.password_hash = get_password_hash("Password123!")
        db_session.commit()
        db_session.refresh(user)
    return user


def test_doctor_login_success(client: TestClient, test_doctor_user: User):
    """Test 1: Doctor login with valid credentials succeeds and returns JWT."""
    payload = {
        "email": "dr.boomika@ayusync.med.in",
        "password": "Doctor@123",
        "device_fingerprint": "test_doctor_workstation_fp",
        "browser": "Chrome 120",
        "os": "macOS"
    }
    response = client.post("/api/healthcare/doctor/login", json=payload)
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["role"] == "DOCTOR"
    assert data["name"] == "Dr. Boomika Ram"
    assert data["session_status"] in ("ACTIVE", "PENDING_OBSERVATION")


def test_doctor_login_invalid_password(client: TestClient, test_doctor_user: User):
    """Test 2: Doctor login with invalid password returns HTTP 401 Unauthorized."""
    payload = {
        "email": "dr.boomika@ayusync.med.in",
        "password": "WrongPassword123!",
        "device_fingerprint": "test_doctor_workstation_fp"
    }
    response = client.post("/api/healthcare/doctor/login", json=payload)
    assert response.status_code == 401
    assert "Invalid doctor registration credentials" in response.json()["detail"]


def test_unauthorized_user_attempting_doctor_login(client: TestClient, test_regular_user: User):
    """Test 3: Non-doctor account attempting doctor login returns HTTP 403 Forbidden."""
    payload = {
        "email": "patient.user@cognisec.ai",
        "password": "Password123!",
        "device_fingerprint": "test_patient_fp"
    }
    response = client.post("/api/healthcare/doctor/login", json=payload)
    assert response.status_code == 403
    assert "Physician credentials required" in response.json()["detail"]


def test_auth_login_with_doctor_required_flag(client: TestClient, test_doctor_user: User, test_regular_user: User):
    """Test 4: /api/auth/login honors doctor_required flag."""
    # When doctor_required is True and user is not a doctor -> 403
    non_doc_payload = {
        "email": "patient.user@cognisec.ai",
        "password": "Password123!",
        "device_fingerprint": "fp1",
        "application": "healthcare",
        "doctor_required": True
    }
    res_non_doc = client.post("/api/auth/login", json=non_doc_payload)
    assert res_non_doc.status_code == 403
    assert "Doctor credentials" in res_non_doc.json()["detail"]

    # When doctor_required is True and user is a doctor -> 200 OK
    doc_payload = {
        "email": "dr.boomika@ayusync.med.in",
        "password": "Doctor@123",
        "device_fingerprint": "fp2",
        "application": "healthcare",
        "doctor_required": True
    }
    res_doc = client.post("/api/auth/login", json=doc_payload)
    assert res_doc.status_code == 200
    assert res_doc.json()["role"] == "DOCTOR"


def test_clinical_vault_unauthenticated(client: TestClient):
    """Test 5: Accessing EHR vault without authentication returns HTTP 401."""
    response = client.get("/api/security/vault/ehr_vault")
    assert response.status_code == 401


def test_clinical_vault_authorized_access(client: TestClient, test_doctor_user: User, db_session: Session):
    """Test 6: Clinical Vault access with valid doctor grant succeeds and returns clinical data."""
    import datetime
    from app.models.application_grant import ApplicationGrant

    # 1. Login as doctor
    login_res = client.post("/api/healthcare/doctor/login", json={
        "email": "dr.boomika@ayusync.med.in",
        "password": "Doctor@123",
        "device_fingerprint": "doc_fp_vault"
    })
    login_data = login_res.json()
    token = login_data["access_token"]
    session_id = login_data["session_id"]
    headers = {"Authorization": f"Bearer {token}"}

    # Activate session for vault grant testing (simulating observation completion)
    from app.models.session import Session as DBSession
    sess_rec = db_session.query(DBSession).filter(DBSession.id == session_id).first()
    if sess_rec:
        sess_rec.status = "ACTIVE"
        db_session.commit()

    # 2. Before grant: vault access must be rejected with HTTP 403 Forbidden
    vault_unauth = client.get(f"/api/security/vault/ehr_vault?session_id={session_id}", headers=headers)
    assert vault_unauth.status_code == 403

    # 3. Create Zero Trust ApplicationGrant for ehr_vault
    now = datetime.datetime.now(datetime.timezone.utc)
    grant = ApplicationGrant(
        session_id=session_id,
        user_id=test_doctor_user.id,
        application="healthcare",
        resource="ehr_vault",
        factor="GESTURE_PATTERN",
        granted_at=now,
        expires_at=now + datetime.timedelta(minutes=30),
        revoked=False
    )
    db_session.add(grant)
    db_session.commit()

    # 4. Retrieve confidential EHR vault records with authorized grant
    vault_res = client.get(f"/api/security/vault/ehr_vault?session_id={session_id}", headers=headers)
    assert vault_res.status_code == 200
    data = vault_res.json()
    assert data["resource"] == "ehr_vault"
    assert data["access_granted"] is True
    assert data["success"] is True
    assert "data" in data
    assert data["data"]["patient_profile"]["name"] == "Rajesh Kumar"
    assert "vitals" in data["data"]
    assert "medical_history" in data["data"]

    # 5. Revoking the grant must immediately lock vault with HTTP 403 Forbidden
    grant.revoked = True
    db_session.commit()
    vault_revoked = client.get(f"/api/security/vault/ehr_vault?session_id={session_id}", headers=headers)
    assert vault_revoked.status_code == 403


def test_get_departments(client: TestClient):
    """Test 7: Fetching hospital departments returns verified medical institutes."""
    response = client.get("/api/healthcare/departments")
    assert response.status_code == 200
    depts = response.json()
    assert len(depts) >= 6
    dept_ids = [d["id"] for d in depts]
    assert "cardiology" in dept_ids
    assert "neurology" in dept_ids
    assert "pediatrics" in dept_ids
    assert "orthopedics" in dept_ids
    assert "dermatology" in dept_ids
    assert "general_medicine" in dept_ids


def test_get_doctors(client: TestClient):
    """Test 8: Fetching doctors returns verified specialists and allows department filtering."""
    # All doctors
    res_all = client.get("/api/healthcare/doctors")
    assert res_all.status_code == 200
    docs = res_all.json()
    assert len(docs) >= 6

    # Filtered by cardiology
    res_cardio = client.get("/api/healthcare/doctors?dept=cardiology")
    assert res_cardio.status_code == 200
    cardio_docs = res_cardio.json()
    assert len(cardio_docs) >= 1
    assert all(d["dept"] == "cardiology" for d in cardio_docs)


def test_appointment_booking_and_persistence(client: TestClient, db_session: Session):
    """Test 9: Patient appointment booking succeeds, persists in DB, and generates reference ID."""
    tomorrow_str = (date.today() + timedelta(days=2)).isoformat()
    booking_data = {
        "patient_name": "Kavita Sharma",
        "patient_phone": "+91 98765 43210",
        "patient_email": "kavita.sharma@example.com",
        "department": "cardiology",
        "doctor_id": "doc-1",
        "doctor_name": "Dr. Boomika Ram (Cardiology)",
        "appointment_date": tomorrow_str,
        "time_slot": "10:00 AM",
        "consultation_mode": "In-Person Hospital Visit",
        "room": "Room 204, Tower B"
    }

    # 1. Book appointment
    response = client.post("/api/healthcare/appointments", json=booking_data)
    assert response.status_code == 201, f"Expected 201, got {response.status_code}: {response.text}"
    apt = response.json()
    assert apt["reference_id"].startswith("AYU-2026-")
    assert apt["patient_name"] == "Kavita Sharma"
    assert apt["appointment_date"] == tomorrow_str
    assert apt["status"] == "CONFIRMED"

    # 2. Verify database persistence
    persisted = db_session.query(HealthcareAppointment).filter(
        HealthcareAppointment.reference_id == apt["reference_id"]
    ).first()
    assert persisted is not None
    assert persisted.patient_email == "kavita.sharma@example.com"
    assert persisted.doctor_id == "doc-1"

    # 3. Retrieve appointments by patient email
    list_res = client.get(f"/api/healthcare/appointments?email=kavita.sharma@example.com")
    assert list_res.status_code == 200
    patient_apts = list_res.json()
    assert len(patient_apts) >= 1
    assert any(a["reference_id"] == apt["reference_id"] for a in patient_apts)


def test_appointment_booking_past_date_rejected(client: TestClient):
    """Test 10: Appointment booking with past date fails validation with HTTP 422."""
    yesterday_str = (date.today() - timedelta(days=1)).isoformat()
    booking_data = {
        "patient_name": "Test Patient",
        "patient_phone": "+91 98765 43210",
        "patient_email": "test.past@example.com",
        "department": "cardiology",
        "doctor_id": "doc-1",
        "doctor_name": "Dr. Boomika Ram",
        "appointment_date": yesterday_str,
        "time_slot": "11:00 AM",
        "consultation_mode": "In-Person Hospital Visit"
    }
    response = client.post("/api/healthcare/appointments", json=booking_data)
    assert response.status_code == 422
    assert "cannot be in the past" in response.text


def test_appointment_booking_double_booking_conflict(client: TestClient):
    """Test 11: Attempting to double-book the same doctor on the same date and slot returns HTTP 409 Conflict."""
    future_date = (date.today() + timedelta(days=5)).isoformat()
    booking_data_1 = {
        "patient_name": "Patient Alpha",
        "patient_phone": "+91 98765 11111",
        "patient_email": "alpha@example.com",
        "department": "neurology",
        "doctor_id": "doc-2",
        "doctor_name": "Dr. Rajesh K. Nair",
        "appointment_date": future_date,
        "time_slot": "10:30 AM",
        "consultation_mode": "In-Person Hospital Visit"
    }

    # First booking succeeds
    res1 = client.post("/api/healthcare/appointments", json=booking_data_1)
    assert res1.status_code == 201

    # Second booking for identical doctor, date, and slot fails with 409 Conflict
    booking_data_2 = {
        "patient_name": "Patient Beta",
        "patient_phone": "+91 98765 22222",
        "patient_email": "beta@example.com",
        "department": "neurology",
        "doctor_id": "doc-2",
        "doctor_name": "Dr. Rajesh K. Nair",
        "appointment_date": future_date,
        "time_slot": "10:30 AM",
        "consultation_mode": "Video Teleconsultation"
    }
    res2 = client.post("/api/healthcare/appointments", json=booking_data_2)
    assert res2.status_code == 409
    assert "already booked" in res2.json()["detail"]
