"""
Step 5.8.1 & 5.8.1.1 Integration Tests: Non-Blocking Live SecurityOrchestrator Integration.

Verifies:
1. A real backend security event dispatches SecurityOrchestrator asynchronously (while routine LOW telemetry does not).
2. SecurityContextAgent receives verified DB session information.
3. RiskAnalysisAgent receives deterministic risk information.
4. DeterministicSecurityArbiter independently overrides agent downgrade attempts.
5. Step-up challenge creation does NOT wait for Gemini or agent execution.
6. Agent timeout does NOT delay authentication (telemetry or step-up).
7. CRITICAL termination is synchronous and never waits for agent execution.
8. Agent failures do not interrupt deterministic authentication enforcement.
9. Duplicate events do not cause duplicate security actions or duplicate background runs.
10. Cross-portal ownership isolation remains intact across Shopping, College, and Healthcare.
11. Background observability is persisted in SecurityEvent.details without sensitive secrets.
"""
import json
import time
import uuid
import asyncio
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.security import create_access_token, get_password_hash
from app.models.user import User
from app.models.alert import Alert
from app.models.security_event import SecurityEvent
from app.services.session_service import SessionService
from app.services.adaptive_auth_service import AdaptiveAuthService
from app.services.risk_service import RiskService
from app.agents.execution.orchestrator import SecurityOrchestrator


def _drain_background_threads(timeout: float = 3.0):
    with SecurityOrchestrator._lock:
        threads = list(SecurityOrchestrator._background_threads)
    for t in threads:
        if t.is_alive():
            t.join(timeout=timeout)


def _create_user_and_active_session(
    db: Session,
    suffix: str,
    application: str = "shopping",
    risk_level: str = "LOW",
    enroll_factors: bool = True,
):
    email = f"orch_{suffix}_{uuid.uuid4().hex[:6]}@cognisec.ai"
    user = User(
        name=f"Orch User {suffix}",
        email=email,
        password_hash=get_password_hash("StrongPass!123"),
        role="USER",
        account_status="ACTIVE",
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    sess = SessionService.create_session(
        db,
        user_id=user.id,
        application=application,
        ip_address="127.0.0.1",
    )
    sess.status = "ACTIVE"
    sess.current_risk_level = risk_level
    sess.observation_completed = True
    sess.login_otp_verified = True
    db.commit()
    db.refresh(sess)

    if enroll_factors:
        AdaptiveAuthService.enroll_gesture_pattern(db, user.id, [0, 3, 7, 11], [0, 3, 7, 11])
        AdaptiveAuthService.enroll_image_sequence(
            db, user.id, ["img_shield", "img_key", "img_lock"], ["img_shield", "img_key", "img_lock"]
        )
        AdaptiveAuthService.enroll_private_response(
            db, user.id, "What is your favorite city?", "Hyderabad", "Hyderabad"
        )

    token = create_access_token(subject=user.id, role=user.role, session_id=sess.id)
    headers = {"Authorization": f"Bearer {token}"}
    return user, sess, headers


def _telemetry_payload(session_id: str, application: str, seq: int = 1, **ctx):
    return {
        "session_id": session_id,
        "application": application,
        "typing_speed_wpm": 52.0,
        "avg_flight_time_ms": 140.0,
        "avg_dwell_time_ms": 95.0,
        "mouse_velocity_avg": 260.0,
        "mouse_acceleration_avg": 110.0,
        "mouse_curvature_entropy": 0.45,
        "click_frequency": 0.6,
        "scroll_speed_avg": 180.0,
        "idle_duration_sec": 1.0,
        "navigation_entropy": 0.4,
        "observed_modalities": {"keyboard": True, "mouse": True, "scroll": True, "navigation": True},
        "telemetry_nonce": f"nonce_{seq}_{uuid.uuid4().hex[:8]}",
        "sequence_number": seq,
        "timestamp": time.time(),
        "context_signals": ctx,
    }


def test_1_routine_low_telemetry_skips_orchestrator_while_elevated_event_invokes_it(
    client: TestClient, db_session: Session, monkeypatch
):
    user, sess, headers = _create_user_and_active_session(db_session, "t1", application="shopping")
    calls = []
    orig = SecurityOrchestrator.evaluate_session_security

    async def spy_eval(self, **kwargs):
        calls.append(kwargs)
        return await orig(self, **kwargs)

    monkeypatch.setattr(SecurityOrchestrator, "evaluate_session_security", spy_eval)

    # Routine LOW non-anomalous telemetry should NOT invoke SecurityOrchestrator
    r_low = client.post("/api/behavior/events", json=_telemetry_payload(sess.id, "shopping", seq=1), headers=headers)
    assert r_low.status_code == 200
    assert r_low.json()["decision"] == "ALLOW"
    _drain_background_threads()
    assert len(calls) == 0

    # Elevated MEDIUM risk transition MUST invoke SecurityOrchestrator asynchronously
    monkeypatch.setattr(
        RiskService,
        "calculate_risk",
        staticmethod(lambda *args, **kwargs: (0.48, 0.42, "MEDIUM", ["mid_session_ip_shift"], True, "ML_READY")),
    )
    r_med = client.post(
        "/api/behavior/events",
        json=_telemetry_payload(sess.id, "shopping", seq=2, simulated_ip_change=True),
        headers=headers,
    )
    assert r_med.status_code == 200
    assert r_med.json()["decision"] == "STEP_UP_VERIFICATION"
    _drain_background_threads()
    assert len(calls) == 1
    assert calls[0]["user_id"] == user.id
    assert calls[0]["session_id"] == sess.id
    assert calls[0]["application"] == "shopping"
    assert calls[0]["deterministic_risk_level"] == "MEDIUM"


def test_2_and_3_context_and_risk_agents_receive_verified_session_and_deterministic_risk(
    client: TestClient, db_session: Session, monkeypatch
):
    user, sess, headers = _create_user_and_active_session(db_session, "t23", application="college", risk_level="MEDIUM")
    captured = {}

    orig_eval = SecurityOrchestrator.evaluate_session_security

    async def spy_eval(self, **kwargs):
        res = await orig_eval(self, **kwargs)
        captured["kwargs"] = kwargs
        captured["res"] = res
        return res

    monkeypatch.setattr(SecurityOrchestrator, "evaluate_session_security", spy_eval)

    resp = client.post(
        "/api/security/step-up/challenge",
        json={
            "session_id": sess.id,
            "application": "college",
            "resource": "academic_vault",
            "challenge_purpose": "CONFIDENTIAL_RESOURCE",
        },
        headers=headers,
    )
    assert resp.status_code == 200
    _drain_background_threads()

    assert captured["kwargs"]["session_id"] == sess.id
    assert captured["kwargs"]["user_id"] == user.id
    assert captured["kwargs"]["deterministic_risk_level"] == "MEDIUM"
    assert captured["kwargs"]["deterministic_risk_score"] == pytest.approx(0.45, abs=0.01)

    ctx_out = captured["res"]["context"]
    assert ctx_out.user_id == user.id
    assert ctx_out.session_summary.get("session_id") == sess.id
    assert ctx_out.application_context.get("portal") == "college"

    risk_out = captured["res"]["risk_analysis"]
    assert risk_out.deterministic_risk_level in ("MEDIUM", "HIGH", "CRITICAL")
    assert risk_out.deterministic_risk_score >= 0.45


def test_4_arbiter_overrides_downgrade_and_agents_cannot_weaken_factors(
    client: TestClient, db_session: Session, monkeypatch
):
    user, sess, headers = _create_user_and_active_session(db_session, "t4", application="healthcare", risk_level="HIGH")

    from app.agents.modules.risk_analysis_agent import RiskAnalysisAgent
    from app.agents.modules.adaptive_auth_agent import AdaptiveAuthAgent
    from app.agents.schemas.agent_schemas import RiskAnalysisOutput, AdaptiveAuthOutput

    async def malicious_risk_downgrade(self, validated_input):
        return RiskAnalysisOutput(
            deterministic_risk_level="LOW",
            deterministic_risk_score=0.05,
            threat_category="BENIGN_BASELINE",
            identified_risk_indicators=["agent_attempted_downgrade"],
            recommended_risk_level="LOW",
            recommended_risk_score=0.05,
            recommended_action="ALLOW",
            human_readable_explanation="Attempted downgrade.",
        )

    async def malicious_factor_downgrade(self, validated_input):
        return AdaptiveAuthOutput(
            action="ALLOW",
            recommended_factor="NONE",
            rationale="Attempted factor downgrade.",
            step_up_required=False,
            effective_risk_level="LOW",
            effective_risk_score=0.05,
            user_enrolled=True,
            policy_decision="ALLOW",
            agent_recommendation="Bypass MFA.",
        )

    monkeypatch.setattr(RiskAnalysisAgent, "_run_reasoning", malicious_risk_downgrade)
    monkeypatch.setattr(AdaptiveAuthAgent, "_run_reasoning", malicious_factor_downgrade)

    resp = client.post(
        "/api/security/step-up/challenge",
        json={
            "session_id": sess.id,
            "application": "healthcare",
            "resource": "ehr_vault",
            "challenge_purpose": "CONFIDENTIAL_RESOURCE",
        },
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["challenge_type"] == "HIGH_RISK_DUAL"

    _drain_background_threads()

    ev = (
        db_session.query(SecurityEvent)
        .filter(SecurityEvent.session_id == sess.id, SecurityEvent.event_type == "STEP_UP_CHALLENGE_ISSUED")
        .order_by(SecurityEvent.id.desc())
        .first()
    )
    assert ev is not None
    db_session.refresh(ev)
    details = json.loads(ev.details)
    obs = details["agentic_orchestration"]
    assert obs["arbiter_decision"]["effective_risk_level"] == "HIGH"
    assert obs["arbiter_decision"]["is_agent_accepted"] is False
    assert "OVERRIDDEN_DOWNGRADE" in (obs["arbiter_decision"]["override_reason"] or "")


def test_5_step_up_challenge_creation_does_not_wait_for_gemini(
    client: TestClient, db_session: Session, monkeypatch
):
    user, sess, headers = _create_user_and_active_session(db_session, "t5", application="shopping", risk_level="MEDIUM")

    async def slow_eval(self, **kwargs):
        await asyncio.sleep(3.0)
        return {}

    monkeypatch.setattr(SecurityOrchestrator, "evaluate_session_security", slow_eval)

    t0 = time.monotonic()
    resp = client.post(
        "/api/security/step-up/challenge",
        json={
            "session_id": sess.id,
            "application": "shopping",
            "resource": "financial_vault",
            "challenge_purpose": "CONFIDENTIAL_RESOURCE",
        },
        headers=headers,
    )
    elapsed = time.monotonic() - t0

    assert resp.status_code == 200
    assert resp.json()["challenge_type"] == "GESTURE_PATTERN"
    assert elapsed < 0.5  # Must return immediately without waiting for Gemini/agent timeout


def test_6_agent_failure_does_not_interrupt_deterministic_enforcement(
    client: TestClient, db_session: Session, monkeypatch
):
    user, sess, headers = _create_user_and_active_session(db_session, "t6", application="college", risk_level="MEDIUM")

    def boom(*args, **kwargs):
        raise RuntimeError("Simulated orchestrator dispatch crash")

    monkeypatch.setattr(SecurityOrchestrator, "dispatch_background", boom)

    resp = client.post(
        "/api/security/step-up/challenge",
        json={
            "session_id": sess.id,
            "application": "college",
            "resource": "academic_vault",
            "challenge_purpose": "CONFIDENTIAL_RESOURCE",
        },
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["challenge_type"] == "GESTURE_PATTERN"


def test_7_agent_timeout_does_not_delay_authentication_or_critical_termination(
    client: TestClient, db_session: Session, monkeypatch
):
    user, sess, headers = _create_user_and_active_session(db_session, "t7", application="healthcare")

    async def slow_eval(self, **kwargs):
        await asyncio.sleep(3.0)
        return {}

    monkeypatch.setattr(SecurityOrchestrator, "evaluate_session_security", slow_eval)
    monkeypatch.setattr(
        RiskService,
        "calculate_risk",
        staticmethod(lambda *args, **kwargs: (0.95, 0.92, "CRITICAL", ["bot_burst_detected"], True, "ML_READY")),
    )

    t0 = time.monotonic()
    resp = client.post("/api/behavior/events", json=_telemetry_payload(sess.id, "healthcare", seq=1), headers=headers)
    elapsed = time.monotonic() - t0

    assert resp.status_code == 200
    assert resp.json()["decision"] == "TERMINATE_SESSION"
    assert resp.json()["session_status"] == "TERMINATED"
    assert elapsed < 0.5  # CRITICAL termination is synchronous and never waits for 3s timeout

    db_session.refresh(sess)
    assert sess.status == "TERMINATED"


def test_8_duplicate_events_do_not_cause_duplicate_security_actions(
    client: TestClient, db_session: Session, monkeypatch
):
    user, sess, headers = _create_user_and_active_session(db_session, "t8", application="shopping")
    monkeypatch.setattr(
        RiskService,
        "calculate_risk",
        staticmethod(lambda *args, **kwargs: (0.72, 0.70, "HIGH", ["repeated_denial"], True, "ML_READY")),
    )

    r1 = client.post("/api/behavior/events", json=_telemetry_payload(sess.id, "shopping", seq=1), headers=headers)
    r2 = client.post("/api/behavior/events", json=_telemetry_payload(sess.id, "shopping", seq=2), headers=headers)
    assert r1.status_code == 200
    assert r2.status_code == 200
    _drain_background_threads()

    alerts = db_session.query(Alert).filter(Alert.user_id == user.id).all()
    assert len(alerts) == 1  # No duplicate alerts created for repeated HIGH events


def test_9_cross_portal_and_three_portal_isolation_intact(
    client: TestClient, db_session: Session
):
    _, shopping_sess, shopping_headers = _create_user_and_active_session(db_session, "t9a", application="shopping")
    _, college_sess, college_headers = _create_user_and_active_session(db_session, "t9b", application="college")
    _, health_sess, health_headers = _create_user_and_active_session(db_session, "t9c", application="healthcare")

    # Cross-portal mismatch blocked
    r_cross = client.post(
        "/api/behavior/events",
        json=_telemetry_payload(shopping_sess.id, "college", seq=1),
        headers=shopping_headers,
    )
    assert r_cross.status_code == 400

    # Cross-user BOLA blocked
    r_bola = client.post(
        "/api/security/step-up/challenge",
        json={"session_id": college_sess.id, "application": "college"},
        headers=shopping_headers,
    )
    assert r_bola.status_code == 403

    # Each portal's own vault challenge remains intact
    for sess_obj, hdrs, app_name, res_name in (
        (shopping_sess, shopping_headers, "shopping", "financial_vault"),
        (college_sess, college_headers, "college", "academic_vault"),
        (health_sess, health_headers, "healthcare", "ehr_vault"),
    ):
        r_ok = client.post(
            "/api/security/step-up/challenge",
            json={
                "session_id": sess_obj.id,
                "application": app_name,
                "resource": res_name,
                "challenge_purpose": "CONFIDENTIAL_RESOURCE",
            },
            headers=hdrs,
        )
        assert r_ok.status_code == 200
        assert r_ok.json()["challenge_type"] == "GESTURE_PATTERN"
    _drain_background_threads()


def test_10_observability_persisted_without_secrets(
    client: TestClient, db_session: Session
):
    user, sess, headers = _create_user_and_active_session(db_session, "t10", application="college", risk_level="MEDIUM")
    resp = client.post(
        "/api/security/step-up/challenge",
        json={
            "session_id": sess.id,
            "application": "college",
            "resource": "academic_vault",
            "challenge_purpose": "CONFIDENTIAL_RESOURCE",
        },
        headers=headers,
    )
    assert resp.status_code == 200
    _drain_background_threads()

    ev = (
        db_session.query(SecurityEvent)
        .filter(SecurityEvent.session_id == sess.id, SecurityEvent.event_type == "STEP_UP_CHALLENGE_ISSUED")
        .order_by(SecurityEvent.id.desc())
        .first()
    )
    assert ev is not None and ev.details
    db_session.refresh(ev)
    details = json.loads(ev.details)
    obs = details["agentic_orchestration"]

    assert obs["trigger_event"] == "STEP_UP_CHALLENGE_REQUEST"
    assert "SecurityContextAgent" in obs["agents_executed"]
    assert "RiskAnalysisAgent" in obs["agents_executed"]
    assert "DeterministicSecurityArbiter" in obs["agents_executed"]
    assert "AdaptiveAuthAgent" in obs["agents_executed"]
    assert "SecurityResponseAgent" in obs["agents_executed"]
    assert "SOCMonitoringAgent" in obs["agents_executed"]
    assert obs["llm_provider"] == "mock"
    assert isinstance(obs["duration_ms"], (int, float))
    assert "arbiter_decision" in obs

    serialized = json.dumps(obs)
    assert "StrongPass!123" not in serialized
    assert "Hyderabad" not in serialized
