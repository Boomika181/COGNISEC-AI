import pytest
from app.models.user import User
from app.models.session import Session as DbSession
from app.services.session_service import SessionService
from app.services.adaptive_auth_service import AdaptiveAuthService


def test_p0_neuraltrace_confidential_vault_authorization_lifecycle(client, user_token, db_session):
    """
    P0 Hotfix Verification Test:
    1. Verify confidential access check returns STEP_UP_VERIFICATION with GESTURE_PATTERN.
    2. Verify requesting step-up challenge issues a GESTURE_PATTERN challenge.
    3. Verify confidential vault endpoint remains locked (HTTP 403) before route verification.
    4. Verify incorrect route submission is rejected.
    5. Verify valid route submission succeeds, restores session, and records GESTURE_PATTERN factor.
    6. Verify confidential vault endpoint unlocks and returns confidential data across all 3 portals.
    """
    # 1. Start active portal session
    sess_res = client.post("/api/sessions/start", headers={"Authorization": f"Bearer {user_token}"}, json={
        "application": "college",
        "device_fingerprint": "fp_hotfix_test_device"
    })
    assert sess_res.status_code == 200
    session_id = sess_res.json()["id"]

    # Retrieve db user and enroll valid gesture route
    user = db_session.query(User).filter(User.id == sess_res.json()["user_id"]).first()
    AdaptiveAuthService.enroll_gesture_pattern(db_session, user.id, [0, 4, 8, 12], [0, 4, 8, 12])

    # 2. Check resource access for academic vault - should require NeuralTrace
    access_res = client.post("/api/security/access-decision", headers={"Authorization": f"Bearer {user_token}"}, json={
        "session_id": session_id,
        "resource": "academic_vault",
        "application": "college"
    })
    assert access_res.status_code == 200
    access_data = access_res.json()
    assert access_data["decision"] == "STEP_UP_VERIFICATION"
    assert access_data["access_granted"] is False
    assert access_data["verification_required"] is True
    assert access_data["required_factor"] == "GESTURE_PATTERN"

    # 3. Confidential vault must be locked
    vault_res = client.get(f"/api/security/vault/academic_vault?session_id={session_id}", headers={"Authorization": f"Bearer {user_token}"})
    assert vault_res.status_code == 403
    assert "NeuralTrace" in vault_res.json()["detail"]

    # 4. Request challenge with preferred_factor=GESTURE_PATTERN
    chal_res = client.post("/api/security/step-up/challenge", headers={"Authorization": f"Bearer {user_token}"}, json={
        "session_id": session_id,
        "preferred_factor": "GESTURE_PATTERN"
    })
    assert chal_res.status_code == 200
    chal_data = chal_res.json()
    assert chal_data["challenge_type"] == "GESTURE_PATTERN"
    assert "challenge_id" in chal_data

    # 5. Submit incorrect route -> rejected
    wrong_res = client.post("/api/security/step-up/verify", headers={"Authorization": f"Bearer {user_token}"}, json={
        "session_id": session_id,
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": [0, 1, 2, 3]  # Invalid route
    })
    assert wrong_res.status_code == 400

    # Vault must remain sealed
    vault_still_locked = client.get(f"/api/security/vault/academic_vault?session_id={session_id}", headers={"Authorization": f"Bearer {user_token}"})
    assert vault_still_locked.status_code == 403

    # 6. Submit correct route -> verified
    correct_res = client.post("/api/security/step-up/verify", headers={"Authorization": f"Bearer {user_token}"}, json={
        "session_id": session_id,
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": [0, 4, 8, 12]  # Default canonical route
    })
    assert correct_res.status_code == 200
    assert correct_res.json()["decision"] == "ALLOW"

    # 7. Access decision now returns ALLOW
    post_verify_check = client.post("/api/security/access-decision", headers={"Authorization": f"Bearer {user_token}"}, json={
        "session_id": session_id,
        "resource": "academic_vault",
        "application": "college"
    })
    assert post_verify_check.status_code == 200
    assert post_verify_check.json()["access_granted"] is True
    assert post_verify_check.json()["step_up_fresh"] is True

    # 8. Vault is now unlocked and accessible
    unlocked_vault = client.get(f"/api/security/vault/academic_vault?session_id={session_id}", headers={"Authorization": f"Bearer {user_token}"})
    assert unlocked_vault.status_code == 200
    vault_payload = unlocked_vault.json()
    assert vault_payload["access_granted"] is True
    assert "cgpa" in vault_payload["data"]


def test_p0_stale_restricted_risk_recalibration(client, user_token, db_session):
    """
    Test that a session marked RESTRICTED from a past transient spike
    is recalibrated and allowed to step-up via NeuralTrace when current behavior is normal.
    """
    # 1. Start session
    sess_res = client.post("/api/sessions/start", headers={"Authorization": f"Bearer {user_token}"}, json={
        "application": "college",
        "device_fingerprint": "fp_stale_test"
    })
    session_id = sess_res.json()["id"]

    # 2. Simulate stale RESTRICTED status in DB
    SessionService.update_session_status(db_session, session_id, status="RESTRICTED", risk_level="HIGH")

    # 3. User submits fresh normal telemetry
    tel_res = client.post("/api/behavior/events", headers={"Authorization": f"Bearer {user_token}"}, json={
        "session_id": session_id,
        "application": "college",
        "typing_speed_wpm": 68.0,
        "avg_flight_time_ms": 115.0,
        "avg_dwell_time_ms": 85.0,
        "mouse_velocity_avg": 650.0,
        "mouse_acceleration_avg": 400.0,
        "click_frequency": 1.2
    })
    assert tel_res.status_code == 200
    tel_data = tel_res.json()
    assert tel_data["decision"] in ["ALLOW", "STEP_UP_VERIFICATION"]
    assert tel_data["session_status"] in ["ACTIVE", "STEP_UP_REQUIRED"]

    # 4. Access decision evaluates dynamically and permits NeuralTrace step-up
    access_res = client.post("/api/security/access-decision", headers={"Authorization": f"Bearer {user_token}"}, json={
        "session_id": session_id,
        "resource": "academic_vault",
        "application": "college"
    })
    assert access_res.status_code == 200
    assert access_res.json()["decision"] == "STEP_UP_VERIFICATION"
    assert access_res.json()["verification_required"] is True
    assert access_res.json()["required_factor"] == "GESTURE_PATTERN"


def test_p0_neuraltrace_shopping_and_healthcare_vaults(client, user_token, db_session):
    """
    Verify NeuralTrace step-up challenge and vault unlocking across Shopping and Healthcare portals.
    """
    for app, resource, payload_key in [
        ("ecommerce", "financial_vault", "saved_cards"),
        ("healthcare", "ehr_vault", "clinical_diagnosis")
    ]:
        # Start session
        sess_res = client.post("/api/sessions/start", headers={"Authorization": f"Bearer {user_token}"}, json={
            "application": app,
            "device_fingerprint": f"fp_{app}_test"
        })
        session_id = sess_res.json()["id"]

        user = db_session.query(User).filter(User.id == sess_res.json()["user_id"]).first()
        AdaptiveAuthService.enroll_gesture_pattern(db_session, user.id, [0, 4, 8, 12], [0, 4, 8, 12])

        # Step 1: Vault initially locked
        vault_locked = client.get(f"/api/security/vault/{resource}?session_id={session_id}", headers={"Authorization": f"Bearer {user_token}"})
        assert vault_locked.status_code == 403

        # Step 2: Access check returns GESTURE_PATTERN requirement
        access_res = client.post("/api/security/access-decision", headers={"Authorization": f"Bearer {user_token}"}, json={
            "session_id": session_id,
            "resource": resource,
            "application": app
        })
        assert access_res.status_code == 200
        assert access_res.json()["verification_required"] is True
        assert access_res.json()["required_factor"] == "GESTURE_PATTERN"

        # Step 3: Challenge issuance
        chal_res = client.post("/api/security/step-up/challenge", headers={"Authorization": f"Bearer {user_token}"}, json={
            "session_id": session_id,
            "preferred_factor": "GESTURE_PATTERN"
        })
        assert chal_res.status_code == 200
        assert chal_res.json()["challenge_type"] == "GESTURE_PATTERN"

        # Step 4: Verification
        ver_res = client.post("/api/security/step-up/verify", headers={"Authorization": f"Bearer {user_token}"}, json={
            "session_id": session_id,
            "challenge_type": "GESTURE_PATTERN",
            "gesture_pattern": [0, 4, 8, 12]
        })
        assert ver_res.status_code == 200

        # Step 5: Vault is unlocked
        vault_unlocked = client.get(f"/api/security/vault/{resource}?session_id={session_id}", headers={"Authorization": f"Bearer {user_token}"})
        assert vault_unlocked.status_code == 200
        assert vault_unlocked.json()["access_granted"] is True
        assert payload_key in vault_unlocked.json()["data"]


def test_p0_genuine_high_risk_prohibits_stepup_and_locks_vault(client, user_token, db_session):
    """
    Verify that genuine HIGH risk correctly prohibits confidential step-up and keeps vault locked.
    """
    sess_res = client.post("/api/sessions/start", headers={"Authorization": f"Bearer {user_token}"}, json={
        "application": "college",
        "device_fingerprint": "fp_attack_device"
    })
    session_id = sess_res.json()["id"]

    # Active attack telemetry: superhuman click frequency and velocity + impossible travel context
    atk_res = client.post("/api/behavior/events", headers={"Authorization": f"Bearer {user_token}"}, json={
        "session_id": session_id,
        "application": "college",
        "typing_speed_wpm": 200.0,
        "avg_flight_time_ms": 5.0,
        "avg_dwell_time_ms": 5.0,
        "mouse_velocity_avg": 9000.0,
        "mouse_acceleration_avg": 25000.0,
        "click_frequency": 35.0,
        "context_signals": {
            "request_flood": True,
            "rapid_click_burst": True,
            "impossible_travel": True,
            "failed_attempts_count": 3
        }
    })
    assert atk_res.status_code == 200
    assert atk_res.json()["decision"] in ["RESTRICT", "TERMINATE_SESSION"]

    # Access decision must return RESTRICT or TERMINATE_SESSION, prohibiting step-up
    access_res = client.post("/api/security/access-decision", headers={"Authorization": f"Bearer {user_token}"}, json={
        "session_id": session_id,
        "resource": "academic_vault",
        "application": "college"
    })
    assert access_res.status_code == 200
    assert access_res.json()["access_granted"] is False
    assert access_res.json()["decision"] in ["RESTRICT", "TERMINATE_SESSION"]
    assert access_res.json()["verification_required"] is False

    # Vault must remain locked
    vault_res = client.get(f"/api/security/vault/academic_vault?session_id={session_id}", headers={"Authorization": f"Bearer {user_token}"})
    assert vault_res.status_code == 403


def test_p0_medium_risk_session_allows_neuraltrace_stepup(client, user_token, db_session):
    """
    Verify Rule 2:
    - MEDIUM risk session must open NeuralTrace modal and request a server-issued challenge.
    - Even if session was marked RESTRICTED, if risk is MEDIUM (not HIGH/CRITICAL) and not hard-locked,
      it must be eligible for NeuralTrace step-up.
    """
    sess_res = client.post("/api/sessions/start", headers={"Authorization": f"Bearer {user_token}"}, json={
        "application": "college",
        "device_fingerprint": "fp_med_risk_test"
    })
    session_id = sess_res.json()["id"]
    user = db_session.query(User).filter(User.id == sess_res.json()["user_id"]).first()
    AdaptiveAuthService.enroll_gesture_pattern(db_session, user.id, [0, 4, 8, 12], [0, 4, 8, 12])

    # Simulate medium risk on session
    SessionService.update_session_status(db_session, session_id, status="RESTRICTED", risk_level="MEDIUM")

    # Access check must return STEP_UP_VERIFICATION, not RESTRICT
    access_res = client.post("/api/security/access-decision", headers={"Authorization": f"Bearer {user_token}"}, json={
        "session_id": session_id,
        "resource": "academic_vault",
        "application": "college"
    })
    assert access_res.status_code == 200
    access_data = access_res.json()
    assert access_data["decision"] == "STEP_UP_VERIFICATION"
    assert access_data["verification_required"] is True
    assert access_data["required_factor"] == "GESTURE_PATTERN"

    # Step-up challenge must be granted
    chal_res = client.post("/api/security/step-up/challenge", headers={"Authorization": f"Bearer {user_token}"}, json={
        "session_id": session_id,
        "preferred_factor": "GESTURE_PATTERN"
    })
    assert chal_res.status_code == 200
    assert chal_res.json()["challenge_type"] == "GESTURE_PATTERN"

    # Verifying correct route unlocks vault
    ver_res = client.post("/api/security/step-up/verify", headers={"Authorization": f"Bearer {user_token}"}, json={
        "session_id": session_id,
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": [0, 4, 8, 12]
    })
    assert ver_res.status_code == 200
    assert ver_res.json()["decision"] == "ALLOW"

    vault_res = client.get(f"/api/security/vault/academic_vault?session_id={session_id}", headers={"Authorization": f"Bearer {user_token}"})
    assert vault_res.status_code == 200
    assert vault_res.json()["access_granted"] is True


def test_p0_brute_force_lockout_prohibits_neuraltrace_stepup(client, user_token, db_session):
    """
    Verify that sessions locked due to brute force (STEP_UP_LOCKED) cannot bypass lockout:
    - Access decision returns RESTRICT
    - Challenge request is rejected (HTTP 403)
    - Vault remains sealed
    """
    sess_res = client.post("/api/sessions/start", headers={"Authorization": f"Bearer {user_token}"}, json={
        "application": "college",
        "device_fingerprint": "fp_lockout_test"
    })
    session_id = sess_res.json()["id"]
    user = db_session.query(User).filter(User.id == sess_res.json()["user_id"]).first()
    AdaptiveAuthService.enroll_gesture_pattern(db_session, user.id, [0, 4, 8, 12], [0, 4, 8, 12])

    # Simulate brute-force lockout event
    SessionService.update_session_status(db_session, session_id, status="RESTRICTED", risk_level="HIGH")
    from app.models.security_event import SecurityEvent
    from datetime import datetime, timezone
    lock_event = SecurityEvent(
        user_id=user.id,
        session_id=session_id,
        application="college",
        event_type="STEP_UP_LOCKED",
        severity="HIGH",
        decision="RESTRICT",
        details="Session locked to RESTRICTED after exceeding maximum verification attempts.",
        timestamp=datetime.now(timezone.utc)
    )
    db_session.add(lock_event)
    db_session.commit()

    # Access decision must strictly deny step-up
    access_res = client.post("/api/security/access-decision", headers={"Authorization": f"Bearer {user_token}"}, json={
        "session_id": session_id,
        "resource": "academic_vault",
        "application": "college"
    })
    assert access_res.status_code == 200
    access_data = access_res.json()
    assert access_data["decision"] == "RESTRICT"
    assert access_data["verification_required"] is False
    assert "restricted" in access_data["message"].lower()

    # Requesting challenge must fail with HTTP 403 Forbidden
    chal_res = client.post("/api/security/step-up/challenge", headers={"Authorization": f"Bearer {user_token}"}, json={
        "session_id": session_id,
        "preferred_factor": "GESTURE_PATTERN"
    })
    assert chal_res.status_code == 403


