import pytest
import datetime
import json
from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.session import Session as DbSession
from app.models.application_grant import ApplicationGrant
from app.models.security_event import SecurityEvent
from app.core.security import get_password_hash, create_access_token
from app.services.session_service import SessionService
from app.services.decision_service import DecisionService
from app.services.risk_service import RiskService
from app.services.adaptive_auth_service import AdaptiveAuthService


def _setup_critical_user(
    db_session: Session,
    email: str,
    application: str = "college",
    risk_level: str = "LOW",
    status: str = "ACTIVE",
    enroll_factors: bool = True
):
    """Creates a user, enrolled factors, and an active session with valid auth headers."""
    user = db_session.query(User).filter(User.email == email).first()
    if not user:
        user = User(
            email=email,
            password_hash=get_password_hash("CriticalSecure123!"),
            name=f"Critical Test User {email}",
            role="USER",
            account_status="ACTIVE"
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

    if enroll_factors:
        AdaptiveAuthService.enroll_gesture_pattern(
            db=db_session,
            user_id=user.id,
            pattern=[0, 3, 7, 11],
            confirm_pattern=[0, 3, 7, 11]
        )
        AdaptiveAuthService.enroll_image_sequence(
            db=db_session,
            user_id=user.id,
            image_sequence=["img_shield", "img_key", "img_lock"],
            confirm_image_sequence=["img_shield", "img_key", "img_lock"]
        )
        AdaptiveAuthService.enroll_private_response(
            db=db_session,
            user_id=user.id,
            question="What is the cryptographic algorithm?",
            response="argon2id-aes-256",
            confirm_response="argon2id-aes-256"
        )

    now = datetime.datetime.now(datetime.timezone.utc)
    session_id = f"sess_step7_{email.split('@')[0]}_{int(now.timestamp() * 1000)}"
    sess = DbSession(
        id=session_id,
        user_id=user.id,
        application=application,
        login_time=now,
        status=status,
        current_risk_level=risk_level
    )
    db_session.add(sess)
    db_session.commit()
    db_session.refresh(sess)

    token = create_access_token(subject=user.id, role=user.role, session_id=session_id)
    headers = {"Authorization": f"Bearer {token}"}
    return user, sess, headers


# =========================================================================
# STEP 7: CRITICAL-RISK TERMINATION & FINAL VERIFICATION TEST SUITE
# =========================================================================

def test_critical_risk_boundary_at_085_and_above(client: TestClient, db_session: Session):
    """
    Requirement 6a: Test CRITICAL boundary at 0.85 and values above it.
    - 0.8499 -> HIGH (RESTRICT, session status RESTRICTED, does not terminate)
    - 0.8500 -> CRITICAL boundary (TERMINATE_SESSION, session status TERMINATED)
    - 0.9500 -> CRITICAL (TERMINATE_SESSION, session status TERMINATED)
    - 1.0000 -> CRITICAL (TERMINATE_SESSION, session status TERMINATED)
    """
    user, sess, headers = _setup_critical_user(db_session, "boundary_test@cognisec.ai")

    # 1. Test 0.8499 -> HIGH risk
    dec_high, _, status_high, _ = DecisionService.enforce_zero_trust_decision(
        db=db_session,
        user_id=user.id,
        session_id=sess.id,
        application="college",
        risk_score=0.8499,
        anomaly_score=0.8499,
        risk_level="HIGH",
        contributing_factors=["High behavioral anomaly"]
    )
    assert dec_high == "RESTRICT"
    assert status_high == "RESTRICTED"
    db_session.refresh(sess)
    assert sess.status == "RESTRICTED"
    assert sess.current_risk_level == "HIGH"

    # Reset session to active for exact boundary test
    sess.status = "ACTIVE"
    sess.current_risk_level = "LOW"
    db_session.commit()

    # 2. Test 0.8500 -> Exactly at CRITICAL threshold
    dec_crit, msg_crit, status_crit, event_id = DecisionService.enforce_zero_trust_decision(
        db=db_session,
        user_id=user.id,
        session_id=sess.id,
        application="college",
        risk_score=0.8500,
        anomaly_score=0.8500,
        risk_level="CRITICAL",
        contributing_factors=["CRITICAL threat threshold exceeded"]
    )
    assert dec_crit == "TERMINATE_SESSION"
    assert status_crit == "TERMINATED"
    assert "terminated" in msg_crit.lower()
    assert event_id is not None

    db_session.refresh(sess)
    assert sess.status == "TERMINATED"
    assert sess.current_risk_level == "CRITICAL"

    # 3. Test values above 0.85 via telemetry route (/api/behavior/events)
    # 0.95 test
    _, sess2, headers2 = _setup_critical_user(db_session, "boundary_095@cognisec.ai")
    telemetry_payload = {
        "session_id": sess2.id,
        "application": "college",
        "avg_flight_time_ms": 130.0,
        "avg_dwell_time_ms": 75.0,
        "typing_speed_wpm": 65.0
    }
    with patch("app.services.risk_service.RiskService.calculate_risk", return_value=(0.95, 0.95, "CRITICAL", ["Impossible travel", "Bot detected"], True, "MODEL_EVALUATED")):
        resp_95 = client.post("/api/behavior/events", headers=headers2, json=telemetry_payload)
        assert resp_95.status_code == 200
        assert resp_95.json()["decision"] == "TERMINATE_SESSION"
        assert resp_95.json()["session_status"] == "TERMINATED"

    db_session.refresh(sess2)
    assert sess2.status == "TERMINATED"
    assert sess2.current_risk_level == "CRITICAL"

    # 1.00 max risk test
    _, sess3, headers3 = _setup_critical_user(db_session, "boundary_100@cognisec.ai")
    with patch("app.services.risk_service.RiskService.calculate_risk", return_value=(1.0, 1.0, "CRITICAL", ["Credential stuffing burst"], True, "MODEL_EVALUATED")):
        resp_100 = client.post("/api/behavior/events", headers=headers3, json=telemetry_payload | {"session_id": sess3.id})
        assert resp_100.status_code == 200
        assert resp_100.json()["decision"] == "TERMINATE_SESSION"
        assert resp_100.json()["session_status"] == "TERMINATED"

    db_session.refresh(sess3)
    assert sess3.status == "TERMINATED"
    assert sess3.current_risk_level == "CRITICAL"


def test_access_denied_across_all_three_portals_after_termination(client: TestClient, db_session: Session):
    """
    Requirement 6b: Access denied across College, Shopping, and Healthcare vaults after termination.
    """
    user, sess, headers = _setup_critical_user(db_session, "portals_denied@cognisec.ai")

    # Issue valid grants for all three portals first
    now = datetime.datetime.now(datetime.timezone.utc)
    for app_name, res_name in [("college", "academic_vault"), ("shopping", "financial_vault"), ("healthcare", "ehr_vault")]:
        g = ApplicationGrant(
            session_id=sess.id,
            user_id=user.id,
            application=app_name,
            resource=res_name,
            factor="GESTURE_PATTERN",
            granted_at=now,
            expires_at=now + datetime.timedelta(minutes=15),
            revoked=False
        )
        db_session.add(g)
    db_session.commit()

    # Elevate to CRITICAL risk and terminate session
    SessionService.terminate_session(db_session, sess.id, risk_level="CRITICAL")
    db_session.refresh(sess)
    assert sess.status == "TERMINATED"
    assert sess.current_risk_level == "CRITICAL"

    # Verify all 3 portals strictly return 403 Forbidden
    portals = [
        ("academic_vault", "cgpa"),
        ("financial_vault", "saved_cards"),
        ("ehr_vault", "prescriptions")
    ]
    for vault_resource, confidential_key in portals:
        resp = client.get(f"/api/security/vault/{vault_resource}?session_id={sess.id}", headers=headers)
        assert resp.status_code in (401, 403)
        assert confidential_key not in resp.json()
        assert "critical" in resp.json()["detail"].lower() or "terminated" in resp.json()["detail"].lower()


def test_existing_grants_cannot_be_used_after_termination(client: TestClient, db_session: Session):
    """
    Requirement 6c: Existing grants are revoked upon termination and cannot be used.
    Even if an unrevoked grant record is manually left in the DB, the terminated/critical session check fails closed.
    """
    user, sess, headers = _setup_critical_user(db_session, "grants_revoked@cognisec.ai")

    # Add active grant
    now = datetime.datetime.now(datetime.timezone.utc)
    grant = ApplicationGrant(
        session_id=sess.id,
        user_id=user.id,
        application="college",
        resource="academic_vault",
        factor="GESTURE_PATTERN",
        granted_at=now,
        expires_at=now + datetime.timedelta(minutes=15),
        revoked=False
    )
    db_session.add(grant)
    db_session.commit()

    # Pre-check: grant allows access
    pre_resp = client.get(f"/api/security/vault/academic_vault?session_id={sess.id}", headers=headers)
    assert pre_resp.status_code == 200
    assert pre_resp.json()["access_granted"] is True

    # Terminate session
    SessionService.terminate_session(db_session, sess.id, risk_level="CRITICAL")

    # Verify grant was revoked in DB
    db_session.refresh(grant)
    assert grant.revoked is True

    # Vault access must now be strictly forbidden (401 session revoked or 403 forbidden)
    post_resp = client.get(f"/api/security/vault/academic_vault?session_id={sess.id}", headers=headers)
    assert post_resp.status_code in (401, 403)

    # Tamper test: manually un-revoke grant in DB to simulate direct DB manipulation
    grant.revoked = False
    db_session.commit()

    # Session is still TERMINATED and CRITICAL -> server must STILL fail closed
    tamper_resp = client.get(f"/api/security/vault/academic_vault?session_id={sess.id}", headers=headers)
    assert tamper_resp.status_code in (401, 403)
    assert "academic_record" not in tamper_resp.json()


def test_new_grants_and_step_up_rejected_for_terminated_sessions(client: TestClient, db_session: Session):
    """
    Requirement 6d: Terminated / CRITICAL sessions cannot obtain new challenges or complete step-up verification.
    """
    user, sess, headers = _setup_critical_user(
        db_session, "no_stepup_after_term@cognisec.ai", risk_level="CRITICAL", status="TERMINATED"
    )

    # 1. Requesting a new challenge must fail with HTTP 400 (endpoint) or 401 (token revocation)
    chal_resp = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": sess.id,
        "application": "college",
        "resource": "academic_vault",
        "preferred_factor": "GESTURE_PATTERN"
    })
    assert chal_resp.status_code in (400, 401)
    assert "terminated" in chal_resp.json()["detail"].lower() or "critical" in chal_resp.json()["detail"].lower()

    # 2. Attempting verification on terminated session must fail with HTTP 400 or 401
    ver_resp = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sess.id,
        "challenge_id": "chal_fake_token",
        "challenge_type": "GESTURE_PATTERN",
        "application": "college",
        "resource": "academic_vault",
        "gesture_pattern": [0, 3, 7, 11]
    })
    assert ver_resp.status_code in (400, 401)
    assert "terminated" in ver_resp.json()["detail"].lower() or "critical" in ver_resp.json()["detail"].lower()

    # 3. Assert zero application grants were created
    grants = db_session.query(ApplicationGrant).filter(ApplicationGrant.session_id == sess.id).all()
    assert len(grants) == 0


def test_replayed_challenges_and_forged_client_claims_cannot_restore_access(client: TestClient, db_session: Session):
    """
    Requirement 6e: Replayed challenges, pre-issued challenge tokens, and client-side forged flags
    cannot restore access or bypass CRITICAL termination.
    """
    user, sess, headers = _setup_critical_user(db_session, "replay_forged@cognisec.ai")

    # Issue challenge while active
    chal_resp = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": sess.id,
        "application": "college",
        "resource": "academic_vault",
        "preferred_factor": "GESTURE_PATTERN"
    })
    cid = chal_resp.json()["challenge_id"]

    # Now terminate session due to CRITICAL risk
    SessionService.terminate_session(db_session, sess.id, risk_level="CRITICAL")

    # Attempt to replay/submit the previously issued challenge ID
    replay_resp = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sess.id,
        "challenge_id": cid,
        "challenge_type": "GESTURE_PATTERN",
        "application": "college",
        "resource": "academic_vault",
        "gesture_pattern": [0, 3, 7, 11]
    })
    assert replay_resp.status_code in (400, 401)
    assert "terminated" in replay_resp.json()["detail"].lower() or "critical" in replay_resp.json()["detail"].lower()

    # Attempt bypass via forged headers
    forged_headers = dict(headers)
    forged_headers["X-Is-Authorized"] = "true"
    forged_headers["X-Step-Up-Verified"] = "true"
    forged_headers["X-Bypass-Grant"] = "true"
    forged_headers["X-Role"] = "ADMIN"

    vault_resp = client.get(
        f"/api/security/vault/academic_vault?session_id={sess.id}&is_authorized=true&bypass=true",
        headers=forged_headers
    )
    assert vault_resp.status_code in (401, 403)

    # Check /api/security/status/{sess.id} returns TERMINATE_SESSION, never ALLOW
    outcome_resp = client.get(f"/api/security/status/{sess.id}", headers=forged_headers)
    if outcome_resp.status_code == 200:
        assert outcome_resp.json()["decision"] == "TERMINATE_SESSION"
        assert outcome_resp.json()["confidential_access_granted"] is False
    else:
        assert outcome_resp.status_code in (401, 403)


def test_security_events_recorded_without_sensitive_secrets(client: TestClient, db_session: Session):
    """
    Requirement 6f: Security events record auditable termination details without logging
    passwords, OTPs, private responses, raw gesture patterns, or sensitive vault records.
    """
    user, sess, headers = _setup_critical_user(db_session, "audit_clean@cognisec.ai")

    # Trigger critical risk termination
    DecisionService.enforce_zero_trust_decision(
        db=db_session,
        user_id=user.id,
        session_id=sess.id,
        application="college",
        risk_score=0.92,
        anomaly_score=0.92,
        risk_level="CRITICAL",
        contributing_factors=["Keystroke velocity deviation 4.2 sigma", "Untrusted subnet"]
    )

    # Attempt unauthorized vault access to trigger VAULT_ACCESS_BLOCKED event
    client.get(f"/api/security/vault/academic_vault?session_id={sess.id}", headers=headers)

    # Fetch all security events for this session
    events = db_session.query(SecurityEvent).filter(SecurityEvent.session_id == sess.id).all()
    assert len(events) >= 1

    forbidden_secrets = [
        "CriticalSecure123!",  # raw password
        "argon2id-aes-256",    # private answer
        "[0, 3, 7, 11]",       # raw gesture pattern
        "4111 2222 3333 4444", # credit card
        "Amoxicillin",         # medical prescription
        "3.88",                # student gpa
    ]

    for ev in events:
        details_str = str(ev.details or "")
        for secret in forbidden_secrets:
            assert secret not in details_str, f"Forbidden secret '{secret}' leaked in SecurityEvent #{ev.id} details!"
        assert ev.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        if ev.event_type == "ZERO_TRUST_KILL_SWITCH":
            assert ev.severity == "CRITICAL"
            assert ev.decision == "TERMINATE_SESSION"


def test_non_critical_regression_behavior_remains_unchanged(client: TestClient, db_session: Session):
    """
    Requirement 6g: Verify that LOW, MEDIUM, and HIGH risk flows continue to function exactly as specified.
    - LOW (< 0.30) -> ALLOW
    - MEDIUM (0.30 - 0.65) -> STEP_UP_VERIFICATION
    - HIGH (0.65 - 0.85) -> RESTRICT
    """
    user, sess, headers = _setup_critical_user(db_session, "regression_non_crit@cognisec.ai")

    # 1. LOW Risk
    dec_low, _, status_low, _ = DecisionService.enforce_zero_trust_decision(
        db=db_session,
        user_id=user.id,
        session_id=sess.id,
        application="college",
        risk_score=0.15,
        anomaly_score=0.10,
        risk_level="LOW",
        contributing_factors=[]
    )
    assert dec_low == "ALLOW"
    assert status_low == "ACTIVE"

    # 2. MEDIUM Risk
    dec_med, _, status_med, _ = DecisionService.enforce_zero_trust_decision(
        db=db_session,
        user_id=user.id,
        session_id=sess.id,
        application="college",
        risk_score=0.45,
        anomaly_score=0.40,
        risk_level="MEDIUM",
        contributing_factors=["Moderate typing deviation"]
    )
    assert dec_med == "STEP_UP_VERIFICATION"
    assert status_med == "STEP_UP_REQUIRED"

    # 3. HIGH Risk
    dec_high, _, status_high, _ = DecisionService.enforce_zero_trust_decision(
        db=db_session,
        user_id=user.id,
        session_id=sess.id,
        application="college",
        risk_score=0.75,
        anomaly_score=0.72,
        risk_level="HIGH",
        contributing_factors=["Elevated mouse velocity anomaly"]
    )
    assert dec_high == "RESTRICT"
    assert status_high == "RESTRICTED"
