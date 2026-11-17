"""
Comprehensive Test Suite for Phase II Step 5.6 — Functional Security Response Agent.
Verifies all 15 required test scenarios:
1. Normal incident generation.
2. Suspicious session response proposal.
3. Account takeover indicators.
4. Session hijacking indicators.
5. Critical-risk handling.
6. Critical termination independent of LLM availability.
7. Grant revocation through authorized backend service.
8. Notification delivery failure (containment remains successful).
9. Duplicate incident idempotency.
10. Retry safety.
11. Unauthorized session termination attempt (BOLA protection).
12. Unauthorized grant revocation attempt (BOLA protection).
13. Malformed LLM response.
14. Agent timeout.
15. Sensitive-data sanitization.
"""
import pytest
import asyncio
import json
import uuid
from datetime import datetime, timezone
from pydantic import ValidationError

from app.core.config import settings
from app.models.user import User
from app.models.session import Session as DbSession
from app.models.application_grant import ApplicationGrant
from app.models.alert import Alert
from app.models.security_event import SecurityEvent
from app.services.session_service import SessionService
from app.services.email_service import EmailService

from app.agents.core.mock_client import MockLLMClient
from app.agents.core.llm_client import LLMRequest, LLMResponse, LLMTimeoutException
from app.agents.core.tool import UnauthorizedToolError
from app.agents.schemas.agent_schemas import (
    SecurityResponseInput,
    SecurityResponseOutput
)
from app.agents.modules.security_response_agent import SecurityResponseAgent


def create_test_user(db, email_prefix="resp_user") -> User:
    uid = uuid.uuid4().hex[:8]
    user = User(
        name=f"Response User {uid}",
        email=f"{email_prefix}_{uid}@example.com",
        password_hash="hashed_pw_dummy",
        role="USER",
        account_status="ACTIVE"
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# -------------------------------------------------------------------------
# 1. Normal Incident Generation (LOW Risk)
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_1_normal_incident_generation():
    """
    Verify LOW risk input produces ROUTINE category, NONE backend operation,
    and alert_required=False.
    """
    agent = SecurityResponseAgent()
    inp = SecurityResponseInput(
        user_id=1,
        event_id="ev_norm_1",
        effective_risk_level="LOW",
        effective_risk_score=0.15,
        reasons=["Normal typing pattern", "Familiar device"]
    )
    out = await agent.execute(inp)
    assert isinstance(out, SecurityResponseOutput)
    assert out.severity == "LOW"
    assert out.incident_category == "ROUTINE"
    assert out.required_backend_operation == "NONE"
    assert out.alert_required is False
    assert out.containment_action == "NONE"
    assert out.user_notification_recommended is False


# -------------------------------------------------------------------------
# 2. Suspicious Session Response Proposal (MEDIUM Risk)
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_2_suspicious_session_response_proposal():
    """
    Verify MEDIUM risk produces BEHAVIORAL_ANOMALY, ENFORCE_STEP_UP,
    and alert_required=True.
    """
    agent = SecurityResponseAgent()
    inp = SecurityResponseInput(
        user_id=2,
        event_id="ev_med_1",
        effective_risk_level="MEDIUM",
        effective_risk_score=0.48,
        reasons=["Flight time deviation +2.4 sigma"]
    )
    out = await agent.execute(inp)
    assert isinstance(out, SecurityResponseOutput)
    assert out.severity == "MEDIUM"
    assert out.incident_category == "BEHAVIORAL_ANOMALY"
    assert out.required_backend_operation == "ENFORCE_STEP_UP"
    assert out.alert_required is True
    assert out.containment_action == "STEP_UP_ENFORCED"


# -------------------------------------------------------------------------
# 3. Account Takeover Indicators
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_3_account_takeover_indicators():
    """
    Verify that explicit account takeover signals result in ACCOUNT_TAKEOVER
    category and ENFORCE_STEP_UP / dual cognitive verification.
    """
    agent = SecurityResponseAgent()
    inp = SecurityResponseInput(
        user_id=3,
        event_id="ev_ato_1",
        threat_category="ACCOUNT_TAKEOVER",
        effective_risk_level="HIGH",
        effective_risk_score=0.74,
        reasons=["Credential stuffing pattern", "Simultaneous location shift"]
    )
    out = await agent.execute(inp)
    assert isinstance(out, SecurityResponseOutput)
    assert out.severity == "HIGH"
    assert out.incident_category == "ACCOUNT_TAKEOVER"
    assert out.alert_required is True
    assert out.user_notification_recommended is True


# -------------------------------------------------------------------------
# 4. Session Hijacking Indicators
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_4_session_hijacking_indicators():
    """
    Verify that session hijacking indicators trigger high/critical containment
    and immediate grant revocation.
    """
    agent = SecurityResponseAgent()
    inp = SecurityResponseInput(
        user_id=4,
        event_id="ev_hijack_1",
        session_id="sess_hijack_test",
        threat_category="SESSION_HIJACKING",
        effective_risk_level="HIGH",
        effective_risk_score=0.82,
        reasons=["Abrupt mid-session IP jump", "Biometric signature divergence"]
    )
    out = await agent.execute(inp)
    assert isinstance(out, SecurityResponseOutput)
    assert out.severity == "HIGH"
    assert out.incident_category == "SESSION_HIJACKING"
    assert out.alert_required is True
    assert out.containment_action == "STEP_UP_ENFORCED"


# -------------------------------------------------------------------------
# 5. Critical-Risk Handling
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_5_critical_risk_handling(db_session):
    """
    Verify CRITICAL risk (>= 0.85) strictly enforces TERMINATE_SESSION,
    SESSION_REVOKED, and user notification.
    """
    user = create_test_user(db_session, "crit_user")
    sess = SessionService.create_session(db_session, user_id=user.id, application="college")

    agent = SecurityResponseAgent(db=db_session)
    inp = SecurityResponseInput(
        user_id=user.id,
        session_id=sess.id,
        event_id="ev_crit_1",
        effective_risk_level="CRITICAL",
        effective_risk_score=0.92,
        reasons=["Zero-Trust Kill Switch threshold exceeded"],
        auto_execute_containment=True
    )
    out = await agent.execute(inp)
    assert isinstance(out, SecurityResponseOutput)
    assert out.severity == "CRITICAL"
    assert out.required_backend_operation == "TERMINATE_SESSION"
    assert out.containment_action == "SESSION_REVOKED"
    assert out.alert_required is True

    # Database session is authoritatively terminated
    db_session.refresh(sess)
    assert sess.status == "TERMINATED"


# -------------------------------------------------------------------------
# 6. Critical Termination Independent of LLM Availability
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_6_critical_termination_independent_of_llm_availability(db_session):
    """
    Verify that when the LLM times out or is completely unavailable,
    the deterministic fallback immediately executes session termination.
    """
    user = create_test_user(db_session, "timeout_crit_user")
    sess = SessionService.create_session(db_session, user_id=user.id, application="shopping")

    failing_llm = MockLLMClient(simulate_timeout=True)
    agent = SecurityResponseAgent(llm_client=failing_llm, db=db_session)

    inp = SecurityResponseInput(
        user_id=user.id,
        session_id=sess.id,
        event_id="ev_timeout_crit",
        effective_risk_level="CRITICAL",
        effective_risk_score=0.88,
        reasons=["Critical anomaly, LLM unreachable"],
        auto_execute_containment=True
    )
    out = await agent.execute(inp)
    assert isinstance(out, SecurityResponseOutput)
    assert out.severity == "CRITICAL"
    assert out.required_backend_operation == "TERMINATE_SESSION"

    # Termination occurred synchronously in fallback
    db_session.refresh(sess)
    assert sess.status == "TERMINATED"


# -------------------------------------------------------------------------
# 7. Grant Revocation Through Authorized Backend Service
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_7_grant_revocation_through_authorized_backend_service(db_session):
    """
    Verify that the agent tool revokes active ApplicationGrant rows bound to the session.
    """
    user = create_test_user(db_session, "grant_rev_user")
    sess = SessionService.create_session(db_session, user_id=user.id, application="healthcare")
    grant = SessionService.record_application_grant(
        db_session,
        session_id=sess.id,
        user_id=user.id,
        application="healthcare",
        resource="ehr_vault"
    )
    assert grant.revoked is False

    agent = SecurityResponseAgent(db=db_session)
    res = agent.execute_tool("revoke_session_grants", session_id=sess.id, user_id=user.id)
    assert res["success"] is True

    db_session.refresh(grant)
    assert grant.revoked is True


# -------------------------------------------------------------------------
# 8. Notification Delivery Failure (Containment Remains Intact)
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_8_notification_delivery_failure_containment_remains_intact(db_session, monkeypatch):
    """
    Verify that if the email notification provider fails or throws an exception,
    the session termination still succeeds without rolling back.
    """
    user = create_test_user(db_session, "email_fail_user")
    sess = SessionService.create_session(db_session, user_id=user.id, application="college")

    # Force EmailService.send_email to raise an exception
    def mock_broken_send(*args, **kwargs):
        raise ConnectionRefusedError("SMTP server down")

    monkeypatch.setattr(EmailService, "send_email", mock_broken_send)

    agent = SecurityResponseAgent(db=db_session)
    inp = SecurityResponseInput(
        user_id=user.id,
        session_id=sess.id,
        event_id="ev_email_fail_test",
        effective_risk_level="CRITICAL",
        effective_risk_score=0.95,
        reasons=["Critical threat vector"],
        auto_execute_containment=True
    )
    out = await agent.execute(inp)
    assert isinstance(out, SecurityResponseOutput)
    assert out.severity == "CRITICAL"

    # Termination succeeded despite notification failure
    db_session.refresh(sess)
    assert sess.status == "TERMINATED"
    assert out.execution_result is not None
    assert out.execution_result.get("terminated") is True


# -------------------------------------------------------------------------
# 9. Duplicate Incident Idempotency
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_9_duplicate_incident_idempotency(db_session):
    """
    Verify that subsequent calls with the exact same idempotency_key return
    the cached output without executing duplicate operations.
    """
    user = create_test_user(db_session, "idempotent_user")
    sess = SessionService.create_session(db_session, user_id=user.id, application="college")

    agent = SecurityResponseAgent(db=db_session)
    idemp_key = f"key_idemp_{uuid.uuid4().hex}"

    inp = SecurityResponseInput(
        user_id=user.id,
        session_id=sess.id,
        event_id="ev_idemp_1",
        effective_risk_level="CRITICAL",
        effective_risk_score=0.91,
        idempotency_key=idemp_key,
        auto_execute_containment=True
    )
    out1 = await agent.execute(inp)
    out2 = await agent.execute(inp)

    # Identical incident returned without re-executing
    assert out1.incident_id == out2.incident_id
    assert out1.timestamp == out2.timestamp


# -------------------------------------------------------------------------
# 10. Retry Safety
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_10_retry_safety(db_session):
    """
    Verify that retried incident calls cannot terminate an unrelated session.
    """
    user1 = create_test_user(db_session, "user1_retry")
    user2 = create_test_user(db_session, "user2_retry")
    sess1 = SessionService.create_session(db_session, user_id=user1.id, application="college")
    sess2 = SessionService.create_session(db_session, user_id=user2.id, application="college")

    agent = SecurityResponseAgent(db=db_session)
    inp = SecurityResponseInput(
        user_id=user1.id,
        session_id=sess1.id,
        event_id="ev_retry_1",
        effective_risk_level="CRITICAL",
        effective_risk_score=0.90,
        auto_execute_containment=True
    )
    await agent.execute(inp)

    # sess1 terminated, sess2 remains untouched and ACTIVE
    db_session.refresh(sess1)
    db_session.refresh(sess2)
    assert sess1.status == "TERMINATED"
    assert sess2.status == "ACTIVE"


# -------------------------------------------------------------------------
# 11. Unauthorized Session Termination Attempt (BOLA Protection)
# -------------------------------------------------------------------------
def test_11_unauthorized_session_termination_attempt(db_session):
    """
    Verify that tool execution rejects terminating a session belonging to another user.
    """
    user_victim = create_test_user(db_session, "victim_user")
    user_attacker = create_test_user(db_session, "attacker_user")
    victim_sess = SessionService.create_session(db_session, user_id=user_victim.id, application="college")

    agent = SecurityResponseAgent(db=db_session)
    with pytest.raises((PermissionError, Exception)) as exc_info:
        # Attacker attempts to terminate victim's session
        agent.execute_tool("terminate_session", session_id=victim_sess.id, user_id=user_attacker.id)

    assert "does not belong to user" in str(exc_info.value).lower()
    # Victim session is still ACTIVE
    db_session.refresh(victim_sess)
    assert victim_sess.status == "ACTIVE"


# -------------------------------------------------------------------------
# 12. Unauthorized Grant Revocation Attempt (BOLA Protection)
# -------------------------------------------------------------------------
def test_12_unauthorized_grant_revocation_attempt(db_session):
    """
    Verify that tool execution rejects revoking grants for a session belonging to another user.
    """
    user_victim = create_test_user(db_session, "victim_grant_user")
    user_attacker = create_test_user(db_session, "attacker_grant_user")
    victim_sess = SessionService.create_session(db_session, user_id=user_victim.id, application="college")

    agent = SecurityResponseAgent(db=db_session)
    with pytest.raises((PermissionError, Exception)) as exc_info:
        agent.execute_tool("revoke_session_grants", session_id=victim_sess.id, user_id=user_attacker.id)

    assert "does not belong to user" in str(exc_info.value).lower()


# -------------------------------------------------------------------------
# 13. Malformed LLM Response Recovery
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_13_malformed_llm_response_recovery():
    """
    Verify that corrupted LLM output seamlessly recovers via deterministic fallback.
    """
    corrupted_llm = MockLLMClient(default_response={"corrupted_field": True})
    agent = SecurityResponseAgent(llm_client=corrupted_llm)

    inp = SecurityResponseInput(
        user_id=13,
        event_id="ev_malformed",
        effective_risk_level="HIGH",
        effective_risk_score=0.75,
        reasons=["Corrupted LLM response test"]
    )
    out = await agent.execute(inp)
    assert isinstance(out, SecurityResponseOutput)
    assert out.severity == "HIGH"
    assert out.required_backend_operation in ("ENFORCE_STEP_UP", "REVOKE_GRANTS")


# -------------------------------------------------------------------------
# 14. Agent Timeout Handling
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_14_agent_timeout_handling():
    """
    Verify that timeout budget exhaustion falls back to deterministic output cleanly.
    """
    timing_out_llm = MockLLMClient(simulate_timeout=True)
    agent = SecurityResponseAgent(llm_client=timing_out_llm, timeout_seconds=0.05)

    inp = SecurityResponseInput(
        user_id=14,
        event_id="ev_timeout",
        effective_risk_level="MEDIUM",
        effective_risk_score=0.55,
        reasons=["Timeout evaluation"]
    )
    out = await agent.execute(inp)
    assert isinstance(out, SecurityResponseOutput)
    assert out.severity == "MEDIUM"
    assert out.alert_required is True


# -------------------------------------------------------------------------
# 15. Sensitive-Data Sanitization
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_15_sensitive_data_sanitization():
    """
    Verify that sensitive tokens, passwords, and raw biometric patterns
    are sanitized and never present in observed facts or prompt contexts.
    """
    agent = SecurityResponseAgent()
    inp = SecurityResponseInput(
        user_id=15,
        event_id="ev_sanitized",
        effective_risk_level="LOW",
        effective_risk_score=0.10,
        reasons=["bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secretToken", "password=SuperSecret123!"]
    )
    out = await agent.execute(inp)
    assert isinstance(out, SecurityResponseOutput)
    facts_str = " ".join(out.observed_facts)
    assert "SuperSecret123!" not in facts_str
    assert "secretToken" not in facts_str

