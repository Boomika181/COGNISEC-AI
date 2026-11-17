"""
Comprehensive Test Suite for Phase II Step 5.8 — Multi-Agent Orchestration & End-to-End Integration.
Verifies all 17 required test scenarios:
1. Normal low-risk login.
2. Medium-risk login with enrolled NeuralTrace.
3. Medium-risk protected resource without required factor (fail closed).
4. High-risk cognitive verification requirement (COGNITIVE_DUAL).
5. Critical-risk synchronous termination.
6. Risk Analysis -> Adaptive Authentication integration.
7. Adaptive Authentication -> Security Response integration.
8. Security Response -> SOC event visibility.
9. LLM unavailable during normal authentication (fail-secure fallback).
10. LLM unavailable during critical termination (immediate sync termination).
11. Duplicate event idempotency.
12. Concurrent event execution.
13. Notification failure after successful containment.
14. Malformed agent output recovery.
15. Missing behavioural modalities handling.
16. All three portal contexts (Shopping, College, Healthcare).
17. Agent execution failure without authentication bypass.
"""
import pytest
import asyncio
import uuid
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.user import User
from app.models.session import Session as DbSession
from app.models.application_grant import ApplicationGrant
from app.models.alert import Alert
from app.models.security_event import SecurityEvent
from app.services.session_service import SessionService
from app.services.adaptive_auth_service import AdaptiveAuthService
from app.services.email_service import EmailService

from app.agents.core.mock_client import MockLLMClient
from app.agents.execution.orchestrator import SecurityOrchestrator
from app.agents.schemas.agent_schemas import (
    SecurityContextOutput,
    RiskAnalysisOutput,
    AdaptiveAuthOutput,
    SecurityResponseOutput,
    SOCMonitoringOutput
)


def create_user(db: Session, email_prefix="orch_user", role="USER") -> User:
    uid = uuid.uuid4().hex[:8]
    user = User(
        name=f"Orchestration User {uid}",
        email=f"{email_prefix}_{uid}@example.com",
        password_hash="HashedPass2026!",
        role=role,
        account_status="ACTIVE",
        failed_login_attempts=0
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# -------------------------------------------------------------------------
# 1. Normal Low-Risk Login
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_1_normal_low_risk_login(db_session: Session):
    """
    Verify normal low-risk login results in ALLOW action, no challenge,
    ROUTINE containment, and PERMITTED execution status.
    """
    user = create_user(db_session, "norm_login")
    sess = SessionService.create_session(db_session, user_id=user.id, application="college")

    orchestrator = SecurityOrchestrator(db=db_session)
    res = await orchestrator.evaluate_session_security(
        user_id=user.id,
        session_id=sess.id,
        application="college",
        raw_anomaly_score=0.10,
        deterministic_risk_score=0.15,
        deterministic_risk_level="LOW"
    )

    assert res["adaptive_auth"].action == "ALLOW"
    assert res["adaptive_auth"].recommended_factor == "NONE"
    assert res["security_response"].required_backend_operation == "NONE"
    assert res["execution_status"] == "PERMITTED"


# -------------------------------------------------------------------------
# 2. Medium-Risk Login With Enrolled NeuralTrace
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_2_medium_risk_login_with_enrolled_neuraltrace(db_session: Session):
    """
    Verify medium-risk login when NeuralTrace is enrolled mandates NEURAL_TRACE factor.
    """
    user = create_user(db_session, "med_neural")
    sess = SessionService.create_session(db_session, user_id=user.id, application="college")

    # Enroll user in gesture pattern (valid 4-node NeuralTrace path: 0 -> 1 -> 4 -> 8)
    AdaptiveAuthService.enroll_gesture_pattern(db_session, user_id=user.id, pattern=[0, 1, 4, 8], confirm_pattern=[0, 1, 4, 8])

    orchestrator = SecurityOrchestrator(db=db_session)
    res = await orchestrator.evaluate_session_security(
        user_id=user.id,
        session_id=sess.id,
        application="college",
        raw_anomaly_score=0.52,
        deterministic_risk_score=0.45,
        deterministic_risk_level="MEDIUM",
        contributing_reasons=["Typing speed acceleration"]
    )

    assert res["arbitrated_risk"]["effective_risk_level"] == "MEDIUM"
    assert res["adaptive_auth"].action == "STEP_UP_REQUIRED"
    assert res["adaptive_auth"].recommended_factor == "NEURAL_TRACE"
    assert res["execution_status"] == "CHALLENGED"


# -------------------------------------------------------------------------
# 3. Medium-Risk Protected Resource Without Required Factor (Fail Closed)
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_3_medium_risk_protected_resource_unenrolled_fail_closed(db_session: Session):
    """
    Verify medium-risk access to protected vault (academic_vault) without NeuralTrace
    enrollment fails closed with DENY (downgrade to Email OTP prohibited).
    """
    user = create_user(db_session, "med_vault_unenrolled")
    sess = SessionService.create_session(db_session, user_id=user.id, application="college")

    orchestrator = SecurityOrchestrator(db=db_session)
    res = await orchestrator.evaluate_session_security(
        user_id=user.id,
        session_id=sess.id,
        application="college",
        protected_resource="academic_vault",
        raw_anomaly_score=0.55,
        deterministic_risk_score=0.50,
        deterministic_risk_level="MEDIUM",
        contributing_reasons=["Attempted vault access without verified factor"]
    )

    assert res["adaptive_auth"].action == "DENY"
    assert res["adaptive_auth"].fallback_strategy == "FAIL_CLOSED_PROTECTED_VAULT"


# -------------------------------------------------------------------------
# 4. High-Risk Cognitive Verification Requirement (COGNITIVE_DUAL)
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_4_high_risk_cognitive_verification_requirement(db_session: Session):
    """
    Verify HIGH risk (0.65 <= risk < 0.85) mandates COGNITIVE_DUAL compound verification.
    """
    user = create_user(db_session, "high_dual")
    sess = SessionService.create_session(db_session, user_id=user.id, application="healthcare")

    # Enroll user in compound factors
    AdaptiveAuthService.enroll_image_sequence(
        db_session,
        user_id=user.id,
        image_sequence=["img_shield", "img_key", "img_lock"],
        confirm_image_sequence=["img_shield", "img_key", "img_lock"]
    )
    AdaptiveAuthService.enroll_private_response(
        db_session,
        user_id=user.id,
        question="What is your recovery answer?",
        response="privateAnswer",
        confirm_response="privateAnswer"
    )

    orchestrator = SecurityOrchestrator(db=db_session)
    res = await orchestrator.evaluate_session_security(
        user_id=user.id,
        session_id=sess.id,
        application="healthcare",
        raw_anomaly_score=0.78,
        deterministic_risk_score=0.74,
        deterministic_risk_level="HIGH",
        contributing_reasons=["Sudden mouse entropy anomaly"]
    )

    assert res["arbitrated_risk"]["effective_risk_level"] == "HIGH"
    assert res["adaptive_auth"].recommended_factor == "COGNITIVE_DUAL"
    assert res["adaptive_auth"].step_up_required is True


# -------------------------------------------------------------------------
# 5. Critical-Risk Synchronous Termination
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_5_critical_risk_synchronous_termination(db_session: Session):
    """
    Verify CRITICAL risk (>= 0.85) triggers synchronous termination in DB
    and response containment with status CONTAINED.
    """
    user = create_user(db_session, "crit_sync_term")
    sess = SessionService.create_session(db_session, user_id=user.id, application="shopping")

    orchestrator = SecurityOrchestrator(db=db_session)
    res = await orchestrator.evaluate_session_security(
        user_id=user.id,
        session_id=sess.id,
        application="shopping",
        raw_anomaly_score=0.92,
        deterministic_risk_score=0.90,
        deterministic_risk_level="CRITICAL",
        contributing_reasons=["Zero-Trust kill switch vector"]
    )

    assert res["arbitrated_risk"]["effective_risk_level"] == "CRITICAL"
    assert res["adaptive_auth"].action == "TERMINATE"
    assert res["execution_status"] == "CONTAINED"
    assert res["execution_metadata"]["synchronous_kill_executed"] is True

    # Database session is TERMINATED
    db_session.refresh(sess)
    assert sess.status == "TERMINATED"


# -------------------------------------------------------------------------
# 6. Risk Analysis -> Adaptive Authentication Integration
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_6_risk_analysis_to_adaptive_auth_integration(db_session: Session):
    """
    Verify that compounding risk indicators identified by RiskAnalysisAgent
    flow directly into AdaptiveAuthAgent to dictate factor strength.
    """
    user = create_user(db_session, "risk_to_auth")
    sess = SessionService.create_session(db_session, user_id=user.id, application="college")

    orchestrator = SecurityOrchestrator(db=db_session)
    res = await orchestrator.evaluate_session_security(
        user_id=user.id,
        session_id=sess.id,
        application="college",
        raw_anomaly_score=0.60,
        deterministic_risk_score=0.55,
        deterministic_risk_level="MEDIUM",
        contributing_reasons=["Device drift", "Flight time spike"]
    )

    assert res["risk_analysis"] is not None
    assert res["adaptive_auth"].effective_risk_score == res["arbitrated_risk"]["effective_risk_score"]
    assert res["adaptive_auth"].effective_risk_level == res["arbitrated_risk"]["effective_risk_level"]


# -------------------------------------------------------------------------
# 7. Adaptive Authentication -> Security Response Integration
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_7_adaptive_auth_to_security_response_integration(db_session: Session):
    """
    Verify that AdaptiveAuthAgent step-up requirements map to SecurityResponseAgent
    containment actions and alert priorities.
    """
    user = create_user(db_session, "auth_to_resp")
    sess = SessionService.create_session(db_session, user_id=user.id, application="healthcare")

    orchestrator = SecurityOrchestrator(db=db_session)
    res = await orchestrator.evaluate_session_security(
        user_id=user.id,
        session_id=sess.id,
        application="healthcare",
        raw_anomaly_score=0.50,
        deterministic_risk_score=0.45,
        deterministic_risk_level="MEDIUM"
    )

    assert res["adaptive_auth"].step_up_required is True
    assert res["security_response"].severity == "MEDIUM"
    assert res["security_response"].alert_required is True


# -------------------------------------------------------------------------
# 8. Security Response -> SOC Event Visibility
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_8_security_response_to_soc_event_visibility(db_session: Session):
    """
    Verify that security response alerts and risk tiers are visible to SOCMonitoringAgent
    in real-time posture reporting and observed facts.
    """
    user = create_user(db_session, "resp_to_soc")
    sess = SessionService.create_session(db_session, user_id=user.id, application="shopping")

    orchestrator = SecurityOrchestrator(db=db_session)
    res = await orchestrator.evaluate_session_security(
        user_id=user.id,
        session_id=sess.id,
        application="shopping",
        raw_anomaly_score=0.70,
        deterministic_risk_score=0.68,
        deterministic_risk_level="HIGH",
        contributing_reasons=["Simulated card probing"]
    )

    soc_out = res["soc_monitoring"]
    assert isinstance(soc_out, SOCMonitoringOutput)
    assert soc_out.incident_priority in ("P1", "P2")


# -------------------------------------------------------------------------
# 9. LLM Unavailable During Normal Authentication
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_9_llm_unavailable_during_normal_authentication(db_session: Session):
    """
    Verify that when the LLM provider fails/times out, normal authentication
    still succeeds seamlessly via deterministic zero-trust fallback.
    """
    user = create_user(db_session, "llm_fail_user")
    sess = SessionService.create_session(db_session, user_id=user.id, application="college")

    failing_llm = MockLLMClient(simulate_timeout=True)
    orchestrator = SecurityOrchestrator(db=db_session, llm_client=failing_llm)

    res = await orchestrator.evaluate_session_security(
        user_id=user.id,
        session_id=sess.id,
        application="college",
        raw_anomaly_score=0.10,
        deterministic_risk_score=0.15,
        deterministic_risk_level="LOW"
    )

    assert res["adaptive_auth"].action == "ALLOW"
    assert res["execution_status"] == "PERMITTED"


# -------------------------------------------------------------------------
# 10. LLM Unavailable During Critical Termination
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_10_llm_unavailable_during_critical_termination(db_session: Session):
    """
    Verify that even if all LLMs time out or crash, CRITICAL risk terminates
    the session synchronously without delay.
    """
    user = create_user(db_session, "llm_fail_crit_user")
    sess = SessionService.create_session(db_session, user_id=user.id, application="college")

    failing_llm = MockLLMClient(simulate_timeout=True)
    orchestrator = SecurityOrchestrator(db=db_session, llm_client=failing_llm)

    res = await orchestrator.evaluate_session_security(
        user_id=user.id,
        session_id=sess.id,
        application="college",
        raw_anomaly_score=0.95,
        deterministic_risk_score=0.92,
        deterministic_risk_level="CRITICAL"
    )

    assert res["execution_status"] == "CONTAINED"
    db_session.refresh(sess)
    assert sess.status == "TERMINATED"


# -------------------------------------------------------------------------
# 11. Duplicate Event Idempotency
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_11_duplicate_event_idempotency(db_session: Session):
    """
    Verify that re-evaluating with the same idempotency key returns cached output
    without redundant agent execution.
    """
    user = create_user(db_session, "idemp_orch_user")
    sess = SessionService.create_session(db_session, user_id=user.id, application="shopping")

    orchestrator = SecurityOrchestrator(db=db_session)
    idemp_key = f"key_orch_{uuid.uuid4().hex}"

    res1 = await orchestrator.evaluate_session_security(
        user_id=user.id,
        session_id=sess.id,
        application="shopping",
        deterministic_risk_score=0.20,
        deterministic_risk_level="LOW",
        idempotency_key=idemp_key
    )
    res2 = await orchestrator.evaluate_session_security(
        user_id=user.id,
        session_id=sess.id,
        application="shopping",
        deterministic_risk_score=0.20,
        deterministic_risk_level="LOW",
        idempotency_key=idemp_key
    )

    assert res1["correlation_id"] == res2["correlation_id"]
    assert res1["execution_metadata"]["timestamp"] == res2["execution_metadata"]["timestamp"]


# -------------------------------------------------------------------------
# 12. Concurrent Event Execution
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_12_concurrent_event_execution(db_session: Session):
    """
    Verify that concurrent agent pipeline invocations run safely in parallel
    without race conditions or deadlocks.
    """
    user = create_user(db_session, "concurrent_orch_user")
    sess1 = SessionService.create_session(db_session, user_id=user.id, application="college")
    sess2 = SessionService.create_session(db_session, user_id=user.id, application="shopping")

    orchestrator = SecurityOrchestrator(db=db_session)

    t1 = orchestrator.evaluate_session_security(
        user_id=user.id,
        session_id=sess1.id,
        application="college",
        deterministic_risk_score=0.15,
        deterministic_risk_level="LOW"
    )
    t2 = orchestrator.evaluate_session_security(
        user_id=user.id,
        session_id=sess2.id,
        application="shopping",
        deterministic_risk_score=0.45,
        deterministic_risk_level="MEDIUM"
    )

    res1, res2 = await asyncio.gather(t1, t2)
    assert res1["adaptive_auth"].action == "ALLOW"
    assert res2["adaptive_auth"].step_up_required is True


# -------------------------------------------------------------------------
# 13. Notification Failure After Successful Containment
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_13_notification_failure_after_successful_containment(db_session: Session, monkeypatch):
    """
    Verify that if EmailService fails, session termination and containment remain intact.
    """
    user = create_user(db_session, "email_err_orch_user")
    sess = SessionService.create_session(db_session, user_id=user.id, application="college")

    def broken_email(*args, **kwargs):
        raise RuntimeError("SMTP network down")

    monkeypatch.setattr(EmailService, "send_email", broken_email)

    orchestrator = SecurityOrchestrator(db=db_session)
    res = await orchestrator.evaluate_session_security(
        user_id=user.id,
        session_id=sess.id,
        application="college",
        deterministic_risk_score=0.90,
        deterministic_risk_level="CRITICAL",
        auto_containment=True
    )

    assert res["execution_status"] == "CONTAINED"
    db_session.refresh(sess)
    assert sess.status == "TERMINATED"


# -------------------------------------------------------------------------
# 14. Malformed Agent Output Recovery
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_14_malformed_agent_output_recovery(db_session: Session):
    """
    Verify that an LLM returning garbage JSON is recovered safely by the deterministic fallback.
    """
    user = create_user(db_session, "garbage_llm_user")
    sess = SessionService.create_session(db_session, user_id=user.id, application="healthcare")

    garbage_llm = MockLLMClient(default_response={"corrupt": "bad_syntax", "invalid": 9999})
    orchestrator = SecurityOrchestrator(db=db_session, llm_client=garbage_llm)

    res = await orchestrator.evaluate_session_security(
        user_id=user.id,
        session_id=sess.id,
        application="healthcare",
        deterministic_risk_score=0.40,
        deterministic_risk_level="MEDIUM"
    )

    assert res["arbitrated_risk"]["effective_risk_level"] == "MEDIUM"
    assert res["adaptive_auth"].step_up_required is True


# -------------------------------------------------------------------------
# 15. Missing Behavioural Modalities Handling
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_15_missing_behavioural_modalities_handling(db_session: Session):
    """
    Verify that missing behavioural modalities (e.g. keyboard-only or mouse-only telemetry)
    are handled gracefully by the context and risk agents without crashing.
    """
    user = create_user(db_session, "missing_modalities_user")
    sess = SessionService.create_session(db_session, user_id=user.id, application="college")

    orchestrator = SecurityOrchestrator(db=db_session)
    res = await orchestrator.evaluate_session_security(
        user_id=user.id,
        session_id=sess.id,
        application="college",
        telemetry_features=[45.0, 120.0, 80.0, None, None, None, None, None, None, None],
        raw_anomaly_score=0.20,
        deterministic_risk_score=0.20,
        deterministic_risk_level="LOW"
    )

    assert isinstance(res["context"], SecurityContextOutput)
    assert res["adaptive_auth"].action == "ALLOW"


# -------------------------------------------------------------------------
# 16. All Three Portal Contexts (Shopping, College, Healthcare)
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_16_all_three_portal_contexts(db_session: Session):
    """
    Verify the multi-agent pipeline correctly normalizes and respects
    all three application portals: College, Shopping, and Healthcare.
    """
    user = create_user(db_session, "multi_portal_user")
    s_col = SessionService.create_session(db_session, user_id=user.id, application="college")
    s_shop = SessionService.create_session(db_session, user_id=user.id, application="shopping")
    s_health = SessionService.create_session(db_session, user_id=user.id, application="healthcare")

    orchestrator = SecurityOrchestrator(db=db_session)

    res_col = await orchestrator.evaluate_session_security(user_id=user.id, session_id=s_col.id, application="college")
    res_shop = await orchestrator.evaluate_session_security(user_id=user.id, session_id=s_shop.id, application="shopping")
    res_health = await orchestrator.evaluate_session_security(user_id=user.id, session_id=s_health.id, application="healthcare")

    assert res_col["security_response"].application_portal == "college"
    assert res_shop["security_response"].application_portal == "shopping"
    assert res_health["security_response"].application_portal == "healthcare"


# -------------------------------------------------------------------------
# 17. Agent Execution Failure Without Authentication Bypass
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_17_agent_execution_failure_without_authentication_bypass(db_session: Session):
    """
    Verify that even if an agent throws an unexpected runtime error,
    authentication is NEVER bypassed or weakened: high risk remains high risk.
    """
    user = create_user(db_session, "no_bypass_user")
    sess = SessionService.create_session(db_session, user_id=user.id, application="college")

    # Enroll compound factors so step-up can be recommended
    AdaptiveAuthService.enroll_image_sequence(
        db_session,
        user_id=user.id,
        image_sequence=["img_shield", "img_key", "img_lock"],
        confirm_image_sequence=["img_shield", "img_key", "img_lock"]
    )
    AdaptiveAuthService.enroll_private_response(
        db_session,
        user_id=user.id,
        question="What is your recovery answer?",
        response="privateAnswer",
        confirm_response="privateAnswer"
    )

    orchestrator = SecurityOrchestrator(db=db_session)
    # Monkeypatch risk_agent to raise an unhandled exception
    async def broken_execute(*args, **kwargs):
        raise RuntimeError("Agent core crashed")

    orchestrator.risk_agent.execute = broken_execute

    res = await orchestrator.evaluate_session_security(
        user_id=user.id,
        session_id=sess.id,
        application="college",
        deterministic_risk_score=0.75,
        deterministic_risk_level="HIGH"
    )

    # Risk level cannot be downgraded despite crash
    assert res["arbitrated_risk"]["effective_risk_level"] == "HIGH"
    assert res["adaptive_auth"].step_up_required is True
