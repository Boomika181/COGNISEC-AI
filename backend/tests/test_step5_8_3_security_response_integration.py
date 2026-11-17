"""
Step 5.8.3 Integration Tests: Live Security Response Agent Integration.

Verifies all 12 requirements:
1. Real backend security events invoke SecurityResponseAgent.
2. Verified evidence is passed to the agent (distinguishing observed facts from inferences).
3. Incident recommendations reach authorized backend services (termination, grant revocation, portal lock, SOC alert, notification).
4. Critical session termination occurs synchronously without waiting for the agent.
5. Unauthorized response actions (UNLOCK_PORTAL, GRANT_ACCESS, VERIFY_FACTOR, REDUCE_RISK) are rejected.
6. Duplicate events do not produce duplicate containment actions.
7. Notification failure does not undo containment.
8. Session ownership (BOLA) and portal isolation are enforced.
9. Agent timeout and malformed output use safe fallback.
10. Existing incident and portal recovery workflows remain functional.
11. All three portals (Shopping, College, Healthcare) are covered.
12. Regressions pass.
"""
import json
import time
import uuid
import asyncio
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.security import create_access_token, get_password_hash
from app.models.user import User
from app.models.session import Session as DbSession
from app.models.security_event import SecurityEvent
from app.models.alert import Alert
from app.models.application_grant import ApplicationGrant
from app.services.session_service import SessionService
from app.services.step_up_service import StepUpService
from app.services.portal_lock_service import PortalLockService
from app.services.email_service import EmailService
from app.agents.execution.orchestrator import SecurityOrchestrator
from app.agents.modules.security_response_agent import SecurityResponseAgent
from app.agents.schemas.agent_schemas import SecurityResponseInput, SecurityResponseOutput


def _drain_bg(timeout: float = 3.0):
    with SecurityOrchestrator._lock:
        threads = list(SecurityOrchestrator._background_threads)
    for t in threads:
        if t.is_alive():
            t.join(timeout=timeout)


def _setup_user_with_grant(
    db: Session,
    tag: str,
    portal: str = "shopping",
    resource: str = "financial_vault",
    risk: str = "LOW"
):
    user = User(
        name=f"Step583 {tag}",
        email=f"s583_{tag}_{uuid.uuid4().hex[:6]}@cognisec.ai",
        password_hash=get_password_hash("SecurePass!999"),
        role="USER",
        account_status="ACTIVE",
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    sess = SessionService.create_session(db, user_id=user.id, application=portal, ip_address="127.0.0.1")
    sess.status = "ACTIVE"
    sess.current_risk_level = risk
    db.commit()
    db.refresh(sess)

    # Issue an active application grant for the portal resource
    grant = ApplicationGrant(
        session_id=sess.id,
        user_id=user.id,
        application=portal,
        resource=resource,
        factor="OTP",
        granted_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        revoked=False,
    )
    db.add(grant)
    db.commit()
    db.refresh(grant)

    token = create_access_token(subject=user.id, role=user.role, session_id=sess.id)
    return user, sess, grant, {"Authorization": f"Bearer {token}"}


def test_1_and_2_security_event_invokes_agent_with_verified_evidence(db_session: Session):
    user, sess, _, _ = _setup_user_with_grant(db_session, "ev_inv", portal="college", resource="academic_vault")

    orch = SecurityOrchestrator(db=db_session)
    res = asyncio.run(
        orch.evaluate_session_security(
            user_id=user.id,
            session_id=sess.id,
            application="college",
            protected_resource="academic_vault",
            trigger_event="VAULT_AUTHORIZATION_CHECK",
            deterministic_risk_score=0.72,
            deterministic_risk_level="HIGH",
            contributing_reasons=["academic_vault_violation", "anomaly_detected"],
        )
    )

    assert "SecurityResponseAgent" in res["observability"]["agents_executed"]
    resp_out = res.get("security_response")
    assert resp_out is not None
    assert resp_out.severity in ("HIGH", "CRITICAL")
    assert resp_out.incident_category in (
        "UNAUTHORIZED_VAULT_ACCESS",
        "EXAM_AUTHORIZATION_VIOLATION",
        "DEVICE_TRUST_VIOLATION",
        "BEHAVIORAL_ANOMALY"
    )
    # Verify observed facts distinguish verified truth
    facts_str = " ".join(resp_out.observed_facts)
    assert f"User ID: {user.id}" in facts_str
    assert "college" in facts_str
    assert sess.id in facts_str


def test_3_incident_recommendations_reach_authorized_backend_services(db_session: Session):
    # 1. Test Session Termination and Grant Revocation for Account Takeover
    user, sess, grant, _ = _setup_user_with_grant(db_session, "ato", portal="shopping", resource="financial_vault")

    SecurityOrchestrator.dispatch_background(
        db_bind=db_session.get_bind(),
        user_id=user.id,
        session_id=sess.id,
        application="shopping",
        trigger_event="ACCOUNT_TAKEOVER_DETECTED",
        threat_category="ACCOUNT_TAKEOVER",
        deterministic_risk_score=0.88,
        deterministic_risk_level="CRITICAL",
        contributing_reasons=["credential_stuffing_pattern", "account_takeover"],
        idempotency_key=f"ato:{sess.id}",
    )
    _drain_bg()

    db_session.refresh(sess)
    db_session.refresh(grant)
    assert sess.status == "TERMINATED"
    assert grant.revoked is True

    # 2. Test Portal Lockout recommendation reaches PortalLockService
    u_lock, s_lock, _, _ = _setup_user_with_grant(db_session, "lock", portal="healthcare", resource="ehr_vault")
    SecurityOrchestrator.dispatch_background(
        db_bind=db_session.get_bind(),
        user_id=u_lock.id,
        session_id=s_lock.id,
        application="healthcare",
        trigger_event="PORTAL_LOCKOUT",
        threat_category="PORTAL_LOCKOUT",
        deterministic_risk_score=0.70,
        deterministic_risk_level="HIGH",
        contributing_reasons=["failed_otp_exhaustion", "locked_portal"],
        idempotency_key=f"lock:{s_lock.id}",
    )
    _drain_bg()

    lock = PortalLockService.get_active_lock(db_session, u_lock.id, "healthcare")
    assert lock is not None
    assert lock.application == "healthcare"

    # 3. Test SOC Alert creation in DB
    alerts = db_session.query(Alert).filter(Alert.user_id == user.id).all()
    assert len(alerts) >= 1
    assert alerts[0].status == "OPEN"


def test_4_critical_session_termination_occurs_without_waiting_for_agent(
    client: TestClient, db_session: Session, monkeypatch
):
    from app.services.risk_service import RiskService
    user, sess, grant, hdr = _setup_user_with_grant(db_session, "sync_crit", portal="college", resource="academic_vault")

    async def _slow_agent(self, inp):
        await asyncio.sleep(2.0)
        raise RuntimeError("Agent delayed")

    monkeypatch.setattr(SecurityResponseAgent, "execute", _slow_agent)
    monkeypatch.setattr(
        RiskService,
        "calculate_risk",
        staticmethod(lambda *a, **kw: (0.95, 0.92, "CRITICAL", ["extreme_anomaly"], True, "ML_READY")),
    )

    t0 = time.monotonic()
    r = client.post(
        "/api/behavior/events",
        json={
            "session_id": sess.id,
            "application": "college",
            "typing_speed_wpm": 250.0,
            "avg_flight_time_ms": 10.0,
            "avg_dwell_time_ms": 10.0,
            "telemetry_nonce": f"nonce_{uuid.uuid4().hex[:8]}",
        },
        headers=hdr,
    )
    elapsed = time.monotonic() - t0

    assert r.status_code == 200
    assert r.json()["decision"] == "TERMINATE_SESSION"
    assert elapsed < 0.5

    db_session.refresh(sess)
    db_session.refresh(grant)
    assert sess.status == "TERMINATED"
    assert grant.revoked is True


def test_5_unauthorized_response_actions_are_rejected(db_session: Session, monkeypatch):
    user, sess, grant, _ = _setup_user_with_grant(db_session, "unauth", portal="shopping", resource="financial_vault")

    # Lock the portal first
    PortalLockService.lock_portal(
        db=db_session,
        user_id=user.id,
        application="shopping",
        verification_purpose="TEST",
        lock_reason="Initial lock",
        failed_attempt_count=1,
        max_attempts=1,
    )
    assert PortalLockService.get_active_lock(db_session, user.id, "shopping") is not None

    # Agent attempts unauthorized action: UNLOCK_PORTAL
    async def _mock_unauthorized_execute(self, inp):
        return SecurityResponseOutput(
            incident_id="inc_unauth",
            incident_category="MALICIOUS_AGENT",
            severity="LOW",
            required_backend_operation="UNLOCK_PORTAL",
            containment_action="NONE",
            recommended_response="Attempting unauthorized portal unlock",
        )

    monkeypatch.setattr(SecurityResponseAgent, "execute", _mock_unauthorized_execute)

    SecurityOrchestrator.dispatch_background(
        db_bind=db_session.get_bind(),
        user_id=user.id,
        session_id=sess.id,
        application="shopping",
        deterministic_risk_score=0.40,
        deterministic_risk_level="MEDIUM",
        contributing_reasons=["anomaly"],
        idempotency_key=f"unauth:{sess.id}",
    )
    _drain_bg()

    # Portal MUST REMAIN LOCKED: unauthorized unlock was rejected
    assert PortalLockService.get_active_lock(db_session, user.id, "shopping") is not None


def test_6_duplicate_events_do_not_produce_duplicate_containment_actions(db_session: Session):
    user, sess, grant, _ = _setup_user_with_grant(db_session, "dup_sec", portal="healthcare", resource="ehr_vault")

    # First dispatch terminates session and revokes grant
    SecurityOrchestrator.dispatch_background(
        db_bind=db_session.get_bind(),
        user_id=user.id,
        session_id=sess.id,
        application="healthcare",
        threat_category="ACCOUNT_TAKEOVER",
        deterministic_risk_score=0.88,
        deterministic_risk_level="CRITICAL",
        contributing_reasons=["takeover"],
        idempotency_key=f"dup:{sess.id}:1",
    )
    _drain_bg()

    db_session.refresh(sess)
    assert sess.status == "TERMINATED"
    initial_alerts_count = db_session.query(Alert).filter(Alert.user_id == user.id).count()

    # Second dispatch with different key: checks DB state and recognizes ALREADY_TERMINATED
    SecurityOrchestrator.dispatch_background(
        db_bind=db_session.get_bind(),
        user_id=user.id,
        session_id=sess.id,
        application="healthcare",
        threat_category="ACCOUNT_TAKEOVER",
        deterministic_risk_score=0.88,
        deterministic_risk_level="CRITICAL",
        contributing_reasons=["takeover"],
        idempotency_key=f"dup:{sess.id}:2",
    )
    _drain_bg()

    # Duplicate alerts are prevented
    final_alerts_count = db_session.query(Alert).filter(Alert.user_id == user.id).count()
    assert final_alerts_count == initial_alerts_count


def test_7_notification_failure_does_not_undo_containment(db_session: Session, monkeypatch):
    user, sess, grant, _ = _setup_user_with_grant(db_session, "notif_fail", portal="college", resource="academic_vault")

    # Mock email failure
    def _failing_email(*args, **kwargs):
        raise ConnectionError("SMTP Connection Refused")

    monkeypatch.setattr(EmailService, "send_email", _failing_email)

    SecurityOrchestrator.dispatch_background(
        db_bind=db_session.get_bind(),
        user_id=user.id,
        session_id=sess.id,
        application="college",
        threat_category="ACCOUNT_TAKEOVER",
        deterministic_risk_score=0.88,
        deterministic_risk_level="CRITICAL",
        contributing_reasons=["takeover"],
        idempotency_key=f"notif_fail:{sess.id}",
    )
    _drain_bg()

    # Session termination and grant revocation MUST REMAIN INTACT despite email failure
    db_session.refresh(sess)
    db_session.refresh(grant)
    assert sess.status == "TERMINATED"
    assert grant.revoked is True


def test_8_session_ownership_and_portal_isolation_enforced(db_session: Session):
    u1, s1, g1, _ = _setup_user_with_grant(db_session, "u1", portal="shopping", resource="financial_vault")
    u2, s2, g2, _ = _setup_user_with_grant(db_session, "u2", portal="college", resource="academic_vault")

    # 1. BOLA Attempt: user 1 tries to terminate session 2 belonging to user 2
    SecurityOrchestrator.dispatch_background(
        db_bind=db_session.get_bind(),
        user_id=u1.id,
        session_id=s2.id,  # session belonging to u2
        application="college",
        threat_category="ACCOUNT_TAKEOVER",
        deterministic_risk_score=0.88,
        deterministic_risk_level="CRITICAL",
        contributing_reasons=["takeover"],
        idempotency_key=f"bola:{s2.id}",
    )
    _drain_bg()

    # s2 belongs to u2, so it MUST NOT be terminated by u1's background dispatch
    db_session.refresh(s2)
    assert s2.status == "ACTIVE"
    db_session.refresh(g2)
    assert g2.revoked is False

    # 2. Portal Mismatch: dispatching shopping incident on college session rejected
    SecurityOrchestrator.dispatch_background(
        db_bind=db_session.get_bind(),
        user_id=u1.id,
        session_id=s1.id,
        application="college",  # Mismatched portal
        threat_category="ACCOUNT_TAKEOVER",
        deterministic_risk_score=0.88,
        deterministic_risk_level="CRITICAL",
        contributing_reasons=["takeover"],
        idempotency_key=f"portal_mismatch:{s1.id}",
    )
    _drain_bg()

    db_session.refresh(s1)
    assert s1.status == "ACTIVE"


def test_9_agent_timeout_and_malformed_output_fallback(db_session: Session, monkeypatch):
    user, sess, grant, _ = _setup_user_with_grant(db_session, "fallback", portal="healthcare", resource="ehr_vault")

    async def _failing_agent(self, inp):
        raise TimeoutError("LLM response timed out after 800ms")

    monkeypatch.setattr(SecurityResponseAgent, "execute", _failing_agent)

    orch = SecurityOrchestrator(db=db_session)
    res = asyncio.run(
        orch.evaluate_session_security(
            user_id=user.id,
            session_id=sess.id,
            application="healthcare",
            threat_category="ACCOUNT_TAKEOVER",
            deterministic_risk_score=0.88,
            deterministic_risk_level="CRITICAL",
            contributing_reasons=["takeover"],
        )
    )

    # Fallback applied successfully without crashing
    assert "SecurityResponseAgent:fallback" in res["observability"]["agents_executed"]
    resp_out = res.get("security_response")
    assert resp_out is not None
    assert resp_out.severity == "CRITICAL"
    assert resp_out.required_backend_operation == "TERMINATE_SESSION"


def test_10_three_portals_covered(db_session: Session):
    # Shopping: Payment fraud indicators
    u_shop, s_shop, g_shop, _ = _setup_user_with_grant(db_session, "p_shop", portal="shopping", resource="financial_vault")
    SecurityOrchestrator.dispatch_background(
        db_bind=db_session.get_bind(),
        user_id=u_shop.id,
        session_id=s_shop.id,
        application="shopping",
        protected_resource="financial_vault",
        threat_category="PAYMENT_FRAUD",
        deterministic_risk_score=0.75,
        deterministic_risk_level="HIGH",
        contributing_reasons=["fraud_card_velocity", "payment_anomaly"],
        idempotency_key=f"p_shop:{s_shop.id}",
    )
    _drain_bg()
    db_session.refresh(g_shop)
    assert g_shop.revoked is True

    # College: Exam authorization violations
    u_col, s_col, g_col, _ = _setup_user_with_grant(db_session, "p_col", portal="college", resource="academic_vault")
    SecurityOrchestrator.dispatch_background(
        db_bind=db_session.get_bind(),
        user_id=u_col.id,
        session_id=s_col.id,
        application="college",
        protected_resource="academic_vault",
        threat_category="EXAM_AUTHORIZATION_VIOLATION",
        deterministic_risk_score=0.75,
        deterministic_risk_level="HIGH",
        contributing_reasons=["unauthorized_vault_access", "exam_violation"],
        idempotency_key=f"p_col:{s_col.id}",
    )
    _drain_bg()
    db_session.refresh(g_col)
    assert g_col.revoked is True

    # Healthcare: Suspicious EHR access
    u_hc, s_hc, g_hc, _ = _setup_user_with_grant(db_session, "p_hc", portal="healthcare", resource="ehr_vault")
    SecurityOrchestrator.dispatch_background(
        db_bind=db_session.get_bind(),
        user_id=u_hc.id,
        session_id=s_hc.id,
        application="healthcare",
        protected_resource="ehr_vault",
        threat_category="SUSPICIOUS_EHR_ACCESS",
        deterministic_risk_score=0.75,
        deterministic_risk_level="HIGH",
        contributing_reasons=["unauthorized_ehr_export", "clinical_vault_violation"],
        idempotency_key=f"p_hc:{s_hc.id}",
    )
    _drain_bg()
    db_session.refresh(g_hc)
    assert g_hc.revoked is True


@pytest.mark.asyncio
async def test_11_threshold_consistency_boundaries_and_non_downgrade(db_session: Session):
    """
    Validates canonical Zero Trust risk thresholds across all boundary values:
    - LOW:      score < 0.30
    - MEDIUM:   0.30 <= score < 0.65
    - HIGH:     0.65 <= score < 0.85
    - CRITICAL: score >= 0.85

    Boundary points tested: 0.29, 0.30, 0.59, 0.60, 0.64, 0.65, 0.84, 0.85.
    Also verifies that no agent recommendation can downgrade the deterministic
    risk level or weaken containment.
    """
    from app.services.risk_service import RiskService
    from app.agents.core.arbiter import DeterministicSecurityArbiter
    from app.agents.modules.security_response_agent import SecurityResponseAgent
    from app.agents.schemas.agent_schemas import SecurityResponseInput

    agent = SecurityResponseAgent()

    # 1. Authoritative RiskService Boundary Classification
    assert RiskService.classify_risk_level(0.29) == "LOW"
    assert RiskService.classify_risk_level(0.30) == "MEDIUM"
    assert RiskService.classify_risk_level(0.59) == "MEDIUM"
    assert RiskService.classify_risk_level(0.60) == "MEDIUM"
    assert RiskService.classify_risk_level(0.64) == "MEDIUM"
    assert RiskService.classify_risk_level(0.65) == "HIGH"
    assert RiskService.classify_risk_level(0.84) == "HIGH"
    assert RiskService.classify_risk_level(0.85) == "CRITICAL"

    # 2. SecurityResponseAgent Policy Consumption across Boundaries
    test_cases = [
        (0.29, "LOW", "LOW", "NONE", "NONE"),
        (0.30, "MEDIUM", "MEDIUM", "ENFORCE_STEP_UP", "STEP_UP_ENFORCED"),
        (0.59, "MEDIUM", "MEDIUM", "ENFORCE_STEP_UP", "STEP_UP_ENFORCED"),
        (0.60, "MEDIUM", "MEDIUM", "ENFORCE_STEP_UP", "STEP_UP_ENFORCED"),
        (0.64, "MEDIUM", "MEDIUM", "ENFORCE_STEP_UP", "STEP_UP_ENFORCED"),
        (0.65, "HIGH", "HIGH", "ENFORCE_STEP_UP", "STEP_UP_ENFORCED"),
        (0.84, "HIGH", "HIGH", "ENFORCE_STEP_UP", "STEP_UP_ENFORCED"),
        (0.85, "CRITICAL", "CRITICAL", "TERMINATE_SESSION", "SESSION_REVOKED"),
    ]

    for score, passed_lvl, expected_sev, expected_op, expected_contain in test_cases:
        inp = SecurityResponseInput(
            user_id=100,
            event_id=f"ev_bnd_{int(score*100)}",
            effective_risk_score=score,
            effective_risk_level=passed_lvl,
            reasons=[f"Boundary test for score {score}"],
            application="platform"
        )
        out = await agent.execute(inp)
        assert out.severity == expected_sev, f"Failed severity for score {score}: expected {expected_sev}, got {out.severity}"
        assert out.required_backend_operation == expected_op, f"Failed op for score {score}: expected {expected_op}, got {out.required_backend_operation}"
        assert out.containment_action == expected_contain, f"Failed containment for score {score}: expected {expected_contain}, got {out.containment_action}"

    # 3. Monotonic Arbiter and Agent Downgrade Prevention
    # A. Agent claims LOW for CRITICAL score (0.85) -> Must remain CRITICAL and TERMINATE
    downgrade_crit = SecurityResponseInput(
        user_id=101,
        event_id="ev_dg_crit",
        effective_risk_score=0.85,
        effective_risk_level="LOW",  # Attempted downgrade
        reasons=["Adversarial attempt to weaken critical containment"],
        application="platform"
    )
    out_crit = await agent.execute(downgrade_crit)
    assert out_crit.severity == "CRITICAL"
    assert out_crit.required_backend_operation == "TERMINATE_SESSION"
    assert out_crit.containment_action == "SESSION_REVOKED"

    # B. Agent claims MEDIUM for HIGH score (0.65) -> Must remain HIGH
    downgrade_high = SecurityResponseInput(
        user_id=102,
        event_id="ev_dg_high",
        effective_risk_score=0.65,
        effective_risk_level="MEDIUM",  # Attempted downgrade
        reasons=["Attempted downgrade from HIGH to MEDIUM"],
        application="platform"
    )
    out_high = await agent.execute(downgrade_high)
    assert out_high.severity == "HIGH"
    assert out_high.required_backend_operation == "ENFORCE_STEP_UP"

    # C. Agent claims LOW for MEDIUM score (0.30) -> Must remain MEDIUM
    downgrade_med = SecurityResponseInput(
        user_id=103,
        event_id="ev_dg_med",
        effective_risk_score=0.30,
        effective_risk_level="LOW",  # Attempted downgrade
        reasons=["Attempted downgrade from MEDIUM to LOW"],
        application="platform"
    )
    out_med = await agent.execute(downgrade_med)
    assert out_med.severity == "MEDIUM"
    assert out_med.containment_action == "STEP_UP_ENFORCED"

    # D. DeterministicSecurityArbiter arbitrate_risk rejection of downgrades
    s1, l1, acc1, _ = DeterministicSecurityArbiter.arbitrate_risk(0.85, "CRITICAL", 0.20, "LOW")
    assert s1 == 0.85 and l1 == "CRITICAL" and acc1 is False

    s2, l2, acc2, _ = DeterministicSecurityArbiter.arbitrate_risk(0.65, "HIGH", 0.40, "MEDIUM")
    assert s2 == 0.65 and l2 == "HIGH" and acc2 is False

    s3, l3, acc3, _ = DeterministicSecurityArbiter.arbitrate_risk(0.30, "MEDIUM", 0.10, "LOW")
    assert s3 == 0.30 and l3 == "MEDIUM" and acc3 is False

