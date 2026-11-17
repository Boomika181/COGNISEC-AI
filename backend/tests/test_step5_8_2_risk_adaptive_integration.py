"""
Step 5.8.2 Integration Tests: Risk Analysis + Adaptive Authentication Live Integration.

Verifies all 15 requirements:
1. A real behavioural event invokes RiskAnalysisAgent.
2. RiskAnalysisAgent receives verified deterministic risk, modality maturity, and Welford deviations.
3. Arbiter rejects risk downgrades.
4. Accepted upward risk escalation reaches DecisionService.
5. AdaptiveAuthAgent receives verified risk assessment.
6. Agent recommendations reach StepUpService in the live async workflow.
7. MEDIUM risk preserves NeuralTrace and protected-vault restrictions.
8. HIGH risk preserves mandatory compound cognitive verification (HIGH_RISK_DUAL).
9. CRITICAL termination remains synchronous.
10. Gemini timeout does not delay authentication.
11. Agent failure does not weaken authentication.
12. Duplicate recommendations do not create duplicate challenges.
13. Expired or terminated sessions cannot receive new challenges.
14. Cross-portal isolation remains intact across Shopping, College, and Healthcare.
15. Actual backend execution traces persisted in SecurityEvent.details.
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
from app.models.security_event import SecurityEvent
from app.services.session_service import SessionService
from app.services.adaptive_auth_service import AdaptiveAuthService
from app.services.step_up_service import StepUpService
from app.services.risk_service import RiskService
from app.services.profile_service import ProfileService
from app.agents.execution.orchestrator import SecurityOrchestrator
from app.agents.modules.risk_analysis_agent import RiskAnalysisAgent
from app.agents.modules.adaptive_auth_agent import AdaptiveAuthAgent
from app.agents.schemas.agent_schemas import RiskAnalysisOutput, AdaptiveAuthOutput


def _drain_bg(timeout: float = 3.0):
    with SecurityOrchestrator._lock:
        threads = list(SecurityOrchestrator._background_threads)
    for t in threads:
        if t.is_alive():
            t.join(timeout=timeout)


def _setup_user(db: Session, tag: str, portal: str = "shopping", risk: str = "LOW", enroll_all: bool = True):
    user = User(
        name=f"Step582 {tag}",
        email=f"s582_{tag}_{uuid.uuid4().hex[:6]}@cognisec.ai",
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
    sess.observation_completed = True
    sess.login_otp_verified = True
    db.commit()
    db.refresh(sess)

    if enroll_all:
        AdaptiveAuthService.enroll_gesture_pattern(db, user.id, [0, 3, 7, 11], [0, 3, 7, 11])
        AdaptiveAuthService.enroll_image_sequence(
            db, user.id, ["img_shield", "img_key", "img_lock"], ["img_shield", "img_key", "img_lock"]
        )
        AdaptiveAuthService.enroll_private_response(
            db, user.id, "What is your birth city?", "Bengaluru", "Bengaluru"
        )

    token = create_access_token(subject=user.id, role=user.role, session_id=sess.id)
    return user, sess, {"Authorization": f"Bearer {token}"}


def _telemetry(session_id: str, portal: str, seq: int = 1, **ctx):
    return {
        "session_id": session_id,
        "application": portal,
        "typing_speed_wpm": 55.0,
        "avg_flight_time_ms": 135.0,
        "avg_dwell_time_ms": 92.0,
        "mouse_velocity_avg": 280.0,
        "mouse_acceleration_avg": 120.0,
        "mouse_curvature_entropy": 0.48,
        "click_frequency": 0.7,
        "scroll_speed_avg": 190.0,
        "idle_duration_sec": 1.2,
        "navigation_entropy": 0.42,
        "observed_modalities": {"keyboard": True, "mouse": True, "scroll": True, "navigation": True},
        "telemetry_nonce": f"n_{seq}_{uuid.uuid4().hex[:8]}",
        "sequence_number": seq,
        "timestamp": time.time(),
        "context_signals": ctx,
    }


def test_1_2_5_6_behavior_event_invokes_risk_and_adaptive_auth_and_reaches_step_up_service(
    client: TestClient, db_session: Session, monkeypatch
):
    user, sess, headers = _setup_user(db_session, "e2e", portal="shopping", risk="LOW")
    # Seed profile with 1 trusted observation so Welford deviations are computed
    import numpy as np
    ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=np.array([50.0, 140.0, 95.0, 250.0, 100.0, 0.45, 0.5, 180.0, 1.0, 0.4]),
        risk_score=0.10,
        session_status="ACTIVE",
        decision="ALLOW",
        observed_modalities={"keyboard": True, "mouse": True, "scroll": True, "navigation": True},
        event_id=f"seed_{uuid.uuid4().hex[:8]}",
    )

    risk_inputs = []
    auth_inputs = []
    orig_risk = RiskAnalysisAgent.execute
    orig_auth = AdaptiveAuthAgent.execute

    async def spy_risk(self, inp):
        risk_inputs.append(inp)
        return await orig_risk(self, inp)

    async def spy_auth(self, inp):
        auth_inputs.append(inp)
        return await orig_auth(self, inp)

    monkeypatch.setattr(RiskAnalysisAgent, "execute", spy_risk)
    monkeypatch.setattr(AdaptiveAuthAgent, "execute", spy_auth)
    monkeypatch.setattr(
        RiskService,
        "calculate_risk",
        staticmethod(lambda *a, **kw: (0.48, 0.44, "MEDIUM", ["behavioral_drift"], True, "ML_READY")),
    )

    resp = client.post("/api/behavior/events", json=_telemetry(sess.id, "shopping", seq=1), headers=headers)
    assert resp.status_code == 200
    assert resp.json()["decision"] == "STEP_UP_VERIFICATION"

    _drain_bg()

    assert len(risk_inputs) == 1
    assert risk_inputs[0].deterministic_score == pytest.approx(0.48, abs=0.01)
    assert risk_inputs[0].deterministic_level == "MEDIUM"
    assert risk_inputs[0].modality_maturity is not None
    assert risk_inputs[0].feature_deviations is not None

    assert len(auth_inputs) == 1
    assert auth_inputs[0].effective_risk_level == "MEDIUM"
    assert auth_inputs[0].application == "shopping"

    # AdaptiveAuthAgent recommendation reached StepUpService and created a real challenge
    chal = StepUpService.get_challenge(sess.id, "shopping")
    assert chal is not None
    assert chal["challenge_type"] == "GESTURE_PATTERN"

    # Trace persisted in SecurityEvent.details
    ev = (
        db_session.query(SecurityEvent)
        .filter(SecurityEvent.session_id == sess.id, SecurityEvent.event_type == "STEP_UP_CHALLENGE")
        .order_by(SecurityEvent.id.desc())
        .first()
    )
    assert ev is not None
    db_session.refresh(ev)
    obs = json.loads(ev.details)["agentic_orchestration"]
    assert obs["step_up_service_outcome"] == "CHALLENGE_CREATED:GESTURE_PATTERN"


def test_3_and_4_arbiter_rejects_downgrade_and_forwards_accepted_escalation_to_decision_service(
    client: TestClient, db_session: Session, monkeypatch
):
    # Part A: Downgrade rejected
    user_a, sess_a, hdr_a = _setup_user(db_session, "down", portal="college", risk="HIGH")

    async def try_downgrade(self, inp):
        return RiskAnalysisOutput(
            deterministic_risk_level="LOW",
            deterministic_risk_score=0.05,
            threat_category="BENIGN_BASELINE",
            recommended_risk_level="LOW",
            recommended_risk_score=0.05,
            recommended_action="ALLOW",
            human_readable_explanation="Downgrade attempt.",
        )

    monkeypatch.setattr(RiskAnalysisAgent, "_run_reasoning", try_downgrade)
    r_a = client.post(
        "/api/security/step-up/challenge",
        json={"session_id": sess_a.id, "application": "college", "resource": "academic_vault", "challenge_purpose": "CONFIDENTIAL_RESOURCE"},
        headers=hdr_a,
    )
    assert r_a.status_code == 200
    assert r_a.json()["challenge_type"] == "HIGH_RISK_DUAL"
    _drain_bg()

    ev_a = db_session.query(SecurityEvent).filter(SecurityEvent.session_id == sess_a.id).order_by(SecurityEvent.id.desc()).first()
    db_session.refresh(ev_a)
    obs_a = json.loads(ev_a.details)["agentic_orchestration"]
    assert obs_a["arbiter_decision"]["effective_risk_level"] == "HIGH"
    assert obs_a["arbiter_decision"]["is_agent_accepted"] is False

    # Part B: Upward escalation (MEDIUM -> HIGH) accepted by arbiter and enforced by DecisionService
    user_b, sess_b, hdr_b = _setup_user(db_session, "esc", portal="healthcare", risk="LOW")

    async def escalate_to_high(self, inp):
        return RiskAnalysisOutput(
            deterministic_risk_level="HIGH",
            deterministic_risk_score=0.74,
            threat_category="SESSION_HIJACKING",
            identified_risk_indicators=["compounding_context_anomaly"],
            recommended_risk_level="HIGH",
            recommended_risk_score=0.74,
            recommended_action="RESTRICT",
            human_readable_explanation="Escalated to HIGH risk.",
        )

    monkeypatch.setattr(RiskAnalysisAgent, "_run_reasoning", escalate_to_high)
    monkeypatch.setattr(
        RiskService,
        "calculate_risk",
        staticmethod(lambda *a, **kw: (0.45, 0.42, "MEDIUM", ["anomaly"], True, "ML_READY")),
    )

    r_b = client.post("/api/behavior/events", json=_telemetry(sess_b.id, "healthcare", seq=1), headers=hdr_b)
    assert r_b.status_code == 200
    _drain_bg()

    db_session.refresh(sess_b)
    assert sess_b.status == "RESTRICTED"
    assert sess_b.current_risk_level == "HIGH"
    chal_b = StepUpService.get_challenge(sess_b.id, "healthcare")
    assert chal_b is not None
    assert chal_b["challenge_type"] == "HIGH_RISK_DUAL"


def test_7_and_8_medium_vault_fail_closed_and_high_cognitive_dual_preserved(
    client: TestClient, db_session: Session
):
    # Unenrolled user under MEDIUM risk for protected vault must fail closed (409), never OTP
    _, sess_med, hdr_med = _setup_user(db_session, "unenr", portal="college", risk="MEDIUM", enroll_all=False)
    r_vault = client.post(
        "/api/security/step-up/challenge",
        json={"session_id": sess_med.id, "application": "college", "resource": "academic_vault", "challenge_purpose": "CONFIDENTIAL_RESOURCE"},
        headers=hdr_med,
    )
    assert r_vault.status_code == 409

    # Enrolled user under HIGH risk gets mandatory HIGH_RISK_DUAL
    _, sess_high, hdr_high = _setup_user(db_session, "high", portal="healthcare", risk="HIGH", enroll_all=True)
    r_high = client.post(
        "/api/security/step-up/challenge",
        json={"session_id": sess_high.id, "application": "healthcare", "resource": "ehr_vault", "challenge_purpose": "CONFIDENTIAL_RESOURCE"},
        headers=hdr_high,
    )
    assert r_high.status_code == 200
    assert r_high.json()["challenge_type"] == "HIGH_RISK_DUAL"


def test_9_10_11_critical_sync_timeout_and_failure_resilience(
    client: TestClient, db_session: Session, monkeypatch
):
    _, sess_crit, hdr_crit = _setup_user(db_session, "crit", portal="shopping")

    async def slow_risk(self, inp):
        await asyncio.sleep(3.0)
        raise RuntimeError("Timeout")

    monkeypatch.setattr(RiskAnalysisAgent, "execute", slow_risk)
    monkeypatch.setattr(
        RiskService,
        "calculate_risk",
        staticmethod(lambda *a, **kw: (0.93, 0.91, "CRITICAL", ["bot_burst"], True, "ML_READY")),
    )

    t0 = time.monotonic()
    r_crit = client.post("/api/behavior/events", json=_telemetry(sess_crit.id, "shopping", seq=1), headers=hdr_crit)
    elapsed = time.monotonic() - t0

    assert r_crit.status_code == 200
    assert r_crit.json()["decision"] == "TERMINATE_SESSION"
    assert elapsed < 0.5
    db_session.refresh(sess_crit)
    assert sess_crit.status == "TERMINATED"


def test_12_duplicate_recommendations_do_not_create_duplicate_challenges(
    client: TestClient, db_session: Session, monkeypatch
):
    _, sess, hdr = _setup_user(db_session, "dup", portal="college", risk="MEDIUM")
    create_calls = []
    orig_create = StepUpService.create_adaptive_challenge

    @classmethod
    def spy_create(cls, *args, **kwargs):
        create_calls.append(kwargs.get("session_id") or (args[0] if args else None))
        return orig_create.__func__(cls, *args, **kwargs)

    monkeypatch.setattr(StepUpService, "create_adaptive_challenge", spy_create)

    r = client.post(
        "/api/security/step-up/challenge",
        json={"session_id": sess.id, "application": "college", "resource": "academic_vault", "challenge_purpose": "CONFIDENTIAL_RESOURCE"},
        headers=hdr,
    )
    assert r.status_code == 200
    _drain_bg()

    # Only 1 challenge created (background sees existing active challenge and preserves it)
    assert len(create_calls) == 1


def test_13_expired_or_terminated_sessions_cannot_receive_new_challenges(
    db_session: Session
):
    user, sess, _ = _setup_user(db_session, "exp", portal="healthcare", risk="MEDIUM")
    sess.status = "EXPIRED"
    db_session.commit()

    SecurityOrchestrator.dispatch_background(
        db_bind=db_session.get_bind(),
        user_id=user.id,
        session_id=sess.id,
        application="healthcare",
        deterministic_risk_score=0.45,
        deterministic_risk_level="MEDIUM",
        contributing_reasons=["anomaly"],
        idempotency_key=f"exp:{sess.id}",
        trigger_event="EXPIRED_SESSION_CHECK",
    )
    _drain_bg()

    assert StepUpService.get_challenge(sess.id, "healthcare") is None


def test_14_three_portal_isolation_preserved(
    client: TestClient, db_session: Session, monkeypatch
):
    for portal, resource in (
        ("shopping", "financial_vault"),
        ("college", "academic_vault"),
        ("healthcare", "ehr_vault"),
    ):
        _, sess, hdr = _setup_user(db_session, f"p_{portal}", portal=portal, risk="LOW")
        monkeypatch.setattr(
            RiskService,
            "calculate_risk",
            staticmethod(lambda *a, **kw: (0.46, 0.43, "MEDIUM", ["anomaly"], True, "ML_READY")),
        )
        r = client.post("/api/behavior/events", json=_telemetry(sess.id, portal, seq=1), headers=hdr)
        assert r.status_code == 200
        _drain_bg()
        chal = StepUpService.get_challenge(sess.id, portal)
        assert chal is not None
        assert chal["application"] == portal
        # Challenge for one portal must not exist under another portal key
        other_portal = "college" if portal != "college" else "shopping"
        assert f"{sess.id}:{other_portal}" not in StepUpService._challenges


def test_15_authoritative_expired_revoked_terminated_sessions_rejected(db_session: Session):
    from app.core.config import settings
    lifetime = getattr(settings, "ACCESS_TOKEN_EXPIRE_MINUTES", 1440)

    # 1. Expired by authoritative login_time + ACCESS_TOKEN_EXPIRE_MINUTES even if status is still ACTIVE
    u_exp, s_exp, _ = _setup_user(db_session, "exp_age", portal="shopping", risk="MEDIUM")
    s_exp.login_time = datetime.now(timezone.utc) - timedelta(minutes=lifetime + 5)
    db_session.commit()
    assert SessionService.is_session_expired(s_exp) is True
    SecurityOrchestrator.dispatch_background(
        db_bind=db_session.get_bind(),
        user_id=u_exp.id,
        session_id=s_exp.id,
        application="shopping",
        deterministic_risk_score=0.45,
        deterministic_risk_level="MEDIUM",
        contributing_reasons=["anomaly"],
        idempotency_key=f"exp_age:{s_exp.id}",
        trigger_event="EXPIRED_AGE_CHECK",
    )
    _drain_bg()
    assert StepUpService.get_challenge(s_exp.id, "shopping") is None

    # 2. Revoked session
    u_rev, s_rev, _ = _setup_user(db_session, "rev", portal="college", risk="MEDIUM")
    s_rev.status = "REVOKED"
    db_session.commit()
    assert SessionService.is_session_expired(s_rev) is True
    SecurityOrchestrator.dispatch_background(
        db_bind=db_session.get_bind(),
        user_id=u_rev.id,
        session_id=s_rev.id,
        application="college",
        deterministic_risk_score=0.45,
        deterministic_risk_level="MEDIUM",
        contributing_reasons=["anomaly"],
        idempotency_key=f"rev:{s_rev.id}",
        trigger_event="REVOKED_SESSION_CHECK",
    )
    _drain_bg()
    assert StepUpService.get_challenge(s_rev.id, "college") is None

    # 3. Terminated session
    u_term, s_term, _ = _setup_user(db_session, "term", portal="healthcare", risk="MEDIUM")
    SessionService.terminate_session(db_session, s_term.id)
    db_session.refresh(s_term)
    assert SessionService.is_session_expired(s_term) is True
    SecurityOrchestrator.dispatch_background(
        db_bind=db_session.get_bind(),
        user_id=u_term.id,
        session_id=s_term.id,
        application="healthcare",
        deterministic_risk_score=0.45,
        deterministic_risk_level="MEDIUM",
        contributing_reasons=["anomaly"],
        idempotency_key=f"term:{s_term.id}",
        trigger_event="TERMINATED_SESSION_CHECK",
    )
    _drain_bg()
    assert StepUpService.get_challenge(s_term.id, "healthcare") is None

    # 4. Valid active session succeeds
    u_ok, s_ok, _ = _setup_user(db_session, "valid_ok", portal="shopping", risk="MEDIUM")
    assert SessionService.is_session_expired(s_ok) is False
    SecurityOrchestrator.dispatch_background(
        db_bind=db_session.get_bind(),
        user_id=u_ok.id,
        session_id=s_ok.id,
        application="shopping",
        deterministic_risk_score=0.45,
        deterministic_risk_level="MEDIUM",
        contributing_reasons=["anomaly"],
        idempotency_key=f"valid_ok:{s_ok.id}",
        trigger_event="VALID_SESSION_CHECK",
    )
    _drain_bg()
    chal_ok = StepUpService.get_challenge(s_ok.id, "shopping")
    assert chal_ok is not None
    assert chal_ok["challenge_type"] == "GESTURE_PATTERN"


def test_16_factor_downgrade_attempts_blocked_by_deterministic_policy(
    db_session: Session, monkeypatch
):
    async def _downgrade_to_otp(self, inp):
        return AdaptiveAuthOutput(
            action="STEP_UP_REQUIRED",
            recommended_factor="EMAIL_OTP",
            rationale="Attempted downgrade to EMAIL_OTP",
            step_up_required=True,
            effective_risk_level=inp.effective_risk_level,
            effective_risk_score=inp.effective_risk_score,
            policy_decision="STEP_UP_REQUIRED",
        )

    monkeypatch.setattr(AdaptiveAuthAgent, "execute", _downgrade_to_otp)

    # 1. MEDIUM risk: EMAIL_OTP recommendation must not weaken mandatory GESTURE_PATTERN
    u_med, s_med, _ = _setup_user(db_session, "dg_med", portal="shopping", risk="MEDIUM")
    SecurityOrchestrator.dispatch_background(
        db_bind=db_session.get_bind(),
        user_id=u_med.id,
        session_id=s_med.id,
        application="shopping",
        deterministic_risk_score=0.48,
        deterministic_risk_level="MEDIUM",
        contributing_reasons=["anomaly"],
        idempotency_key=f"dg_med:{s_med.id}",
        trigger_event="DOWNGRADE_MED",
    )
    _drain_bg()
    c_med = StepUpService.get_challenge(s_med.id, "shopping")
    assert c_med is not None
    assert c_med["challenge_type"] == "GESTURE_PATTERN"

    # 2. HIGH risk: EMAIL_OTP recommendation must not weaken mandatory HIGH_RISK_DUAL
    u_high, s_high, _ = _setup_user(db_session, "dg_high", portal="healthcare", risk="HIGH")
    SecurityOrchestrator.dispatch_background(
        db_bind=db_session.get_bind(),
        user_id=u_high.id,
        session_id=s_high.id,
        application="healthcare",
        deterministic_risk_score=0.75,
        deterministic_risk_level="HIGH",
        contributing_reasons=["high_anomaly"],
        idempotency_key=f"dg_high:{s_high.id}",
        trigger_event="DOWNGRADE_HIGH",
    )
    _drain_bg()
    c_high = StepUpService.get_challenge(s_high.id, "healthcare")
    assert c_high is not None
    assert c_high["challenge_type"] == "HIGH_RISK_DUAL"

    # 3. Protected vault under LOW risk: EMAIL_OTP recommendation must not weaken GESTURE_PATTERN
    u_vault, s_vault, _ = _setup_user(db_session, "dg_vault", portal="college", risk="LOW")
    SecurityOrchestrator.dispatch_background(
        db_bind=db_session.get_bind(),
        user_id=u_vault.id,
        session_id=s_vault.id,
        application="college",
        protected_resource="academic_vault",
        deterministic_risk_score=0.10,
        deterministic_risk_level="LOW",
        contributing_reasons=["vault_access"],
        idempotency_key=f"dg_vault:{s_vault.id}",
        trigger_event="STEP_UP_CHALLENGE_REQUEST",
    )
    _drain_bg()
    c_vault = StepUpService.get_challenge(s_vault.id, "college")
    assert c_vault is not None
    assert c_vault["challenge_type"] == "GESTURE_PATTERN"


