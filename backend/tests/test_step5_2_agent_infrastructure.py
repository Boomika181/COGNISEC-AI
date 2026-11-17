"""
Unit and Integration Tests for Phase II Step 5.2 — Agent Infrastructure and LLM Integration Foundation.
Tests run hermetically without requiring an active external Gemini API key.
"""
import pytest
import asyncio
from typing import Dict, Any

from app.core.config import settings
from app.agents.core.llm_client import (
    LLMRequest,
    LLMResponse,
    LLMTimeoutException,
    LLMAuthenticationException,
    LLMValidationException,
    LLMException
)
from app.agents.core.mock_client import MockLLMClient
from app.agents.core.gemini_client import GeminiLLMClient
from app.agents.core.factory import get_llm_client
from app.agents.core.sanitization import Sanitizer
from app.agents.core.tool import AgentTool, tool, UnauthorizedToolError, ToolExecutionError
from app.agents.core.arbiter import DeterministicSecurityArbiter, ArbitrationResult
from app.agents.execution.task_runner import run_with_timeout, dispatch_background_task
from app.agents.schemas.agent_schemas import (
    SecurityContextInput,
    SecurityContextOutput,
    RiskAnalysisInput,
    RiskAnalysisOutput,
    AdaptiveAuthInput,
    AdaptiveAuthOutput,
    SecurityResponseInput,
    SecurityResponseOutput,
    SOCMonitoringInput,
    SOCMonitoringOutput
)
from app.agents.modules.security_context_agent import SecurityContextAgent
from app.agents.modules.risk_analysis_agent import RiskAnalysisAgent
from app.agents.modules.adaptive_auth_agent import AdaptiveAuthAgent
from app.agents.modules.security_response_agent import SecurityResponseAgent
from app.agents.modules.soc_monitoring_agent import SOCMonitoringAgent


# -------------------------------------------------------------------------
# 1. Mock LLM Execution
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_1_mock_llm_client_execution():
    """Verify MockLLMClient handles requests and returns structured LLMResponse."""
    mock = MockLLMClient(default_response={"key": "test_value"}, simulated_latency_ms=5)
    assert mock.validate_configuration() is True

    req = LLMRequest(prompt="Hello security agent", temperature=0.0)
    resp = await mock.generate(req)

    assert resp.provider == "mock"
    assert resp.parsed_json == {"key": "test_value"}
    assert len(mock.recorded_requests) == 1
    assert mock.recorded_requests[0].prompt == "Hello security agent"


# -------------------------------------------------------------------------
# 2. Gemini Adapter Configuration
# -------------------------------------------------------------------------
def test_2_gemini_adapter_configuration(monkeypatch):
    """Verify GeminiLLMClient configuration validation with and without API key."""
    from app.core.config import settings
    monkeypatch.setattr(settings, "GEMINI_API_KEY", None)

    # Without API key
    client_no_key = GeminiLLMClient(api_key=None)
    assert client_no_key.validate_configuration() is False

    # With API key
    client_with_key = GeminiLLMClient(api_key="test-gemini-key-12345", model="gemini-1.5-flash")
    assert client_with_key.validate_configuration() is True
    assert client_with_key.model == "gemini-1.5-flash"


# -------------------------------------------------------------------------
# 3. Missing API Key Raises Authentication Exception
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_3_gemini_adapter_missing_api_key_raises_auth_exception():
    """Verify GeminiLLMClient raises LLMAuthenticationException when API key is missing."""
    client = GeminiLLMClient(api_key="")
    req = LLMRequest(prompt="Test prompt without key")
    with pytest.raises(LLMAuthenticationException) as exc_info:
        await client.generate(req)
    assert "GEMINI_API_KEY is missing" in str(exc_info.value)


# -------------------------------------------------------------------------
# 4. Provider Timeout Handling
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_4_provider_timeout_handling():
    """Verify provider timeout raises LLMTimeoutException and triggers fallback in agent."""
    timeout_mock = MockLLMClient(inject_timeout=True)
    req = LLMRequest(prompt="Timeout trigger")
    with pytest.raises(LLMTimeoutException):
        await timeout_mock.generate(req)

    # In an agent, timeout must seamlessly trigger deterministic fallback without raising
    agent = RiskAnalysisAgent(llm_client=timeout_mock, timeout_seconds=0.1)
    inp = RiskAnalysisInput(
        user_id=101,
        deterministic_score=0.45,
        deterministic_level="MEDIUM",
        anomaly_score=0.40,
        is_anomaly=True
    )
    res = await agent.execute(inp)
    assert isinstance(res, RiskAnalysisOutput)
    assert res.risk_level == "MEDIUM"
    assert res.risk_score == 0.45
    assert "Deterministic fallback" in res.rationale


# -------------------------------------------------------------------------
# 5. Invalid LLM Output Handling
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_5_invalid_llm_output_handling():
    """Verify that unparseable or malformed LLM outputs engage deterministic fallback."""
    bad_mock = MockLLMClient(inject_invalid_json=True)
    agent = AdaptiveAuthAgent(llm_client=bad_mock)

    inp = AdaptiveAuthInput(
        user_id=202,
        effective_risk_level="HIGH",
        effective_risk_score=0.72,
        enrolled_factors={"has_gesture_pattern": True}
    )
    res = await agent.execute(inp)
    assert isinstance(res, AdaptiveAuthOutput)
    # Output schema is strictly enforced; fallback guarantees HIGH policy factor
    assert res.action == "STEP_UP_REQUIRED"
    assert res.recommended_factor == "COGNITIVE_DUAL"
    assert "Deterministic fallback" in res.rationale


# -------------------------------------------------------------------------
# 6. Agent Schema Validation
# -------------------------------------------------------------------------
def test_6_agent_schema_validation():
    """Verify strict Pydantic v2 validation on agent input and output schemas."""
    # Valid output
    valid_risk = RiskAnalysisOutput(
        risk_level="HIGH",
        risk_score=0.70,
        confidence=0.85,
        primary_risk_factors=["Mouse jitter"],
        rationale="Elevated risk detected."
    )
    assert valid_risk.risk_level == "HIGH"

    # Invalid risk level must raise ValidationError
    with pytest.raises(Exception):
        RiskAnalysisOutput(
            risk_level="CRITICALLY_DANGEROUS",  # Invalid enum value
            risk_score=0.90,
            confidence=0.9,
            rationale="Invalid level"
        )

    # Invalid risk score bounds (> 1.0) must raise ValidationError
    with pytest.raises(Exception):
        RiskAnalysisOutput(
            risk_level="HIGH",
            risk_score=1.50,  # Exceeds max 1.0
            confidence=0.9,
            rationale="Invalid score"
        )


# -------------------------------------------------------------------------
# 7. Unauthorized Tool Invocation
# -------------------------------------------------------------------------
def test_7_unauthorized_tool_invocation_prevention():
    """Verify that agents cannot execute tools not present in their explicit whitelist."""
    agent = SecurityContextAgent(permitted_tools={"get_user_profile_summary"})

    # Register an unauthorized tool
    unauthorized_tool = AgentTool(
        name="revoke_all_sessions",
        description="Administrative session kill-switch",
        func=lambda: "REVOKED",
        is_read_only=False
    )
    agent.register_tool(unauthorized_tool)

    # Attempting to call unauthorized tool must raise UnauthorizedToolError
    with pytest.raises(UnauthorizedToolError) as exc_info:
        agent.execute_tool("revoke_all_sessions")
    assert "least-privilege violation" in str(exc_info.value)


# -------------------------------------------------------------------------
# 8. Deterministic Fallback Integrity across All 5 Agents
# -------------------------------------------------------------------------
def test_8_deterministic_fallback_across_all_five_agents():
    """Verify every agent's get_deterministic_fallback produces a strictly valid schema instance."""
    # 1. Security Context Agent
    context_agent = SecurityContextAgent()
    c_out = context_agent.get_deterministic_fallback({"user_id": 1, "client_ip": "10.0.0.1"})
    assert isinstance(c_out, SecurityContextOutput)
    assert c_out.profile_status == "COLD_START"

    # 2. Risk Analysis Agent
    risk_agent = RiskAnalysisAgent()
    r_out = risk_agent.get_deterministic_fallback(RiskAnalysisInput(
        user_id=1, deterministic_score=0.25, deterministic_level="LOW"
    ))
    assert isinstance(r_out, RiskAnalysisOutput)
    assert r_out.risk_level == "LOW"
    assert r_out.risk_score == 0.25

    # 3. Adaptive Auth Agent
    auth_agent = AdaptiveAuthAgent()
    a_out = auth_agent.get_deterministic_fallback(AdaptiveAuthInput(
        user_id=1, effective_risk_level="CRITICAL", effective_risk_score=0.92
    ))
    assert isinstance(a_out, AdaptiveAuthOutput)
    assert a_out.action == "TERMINATE"
    assert a_out.recommended_factor == "TERMINATE"

    # 4. Security Response Agent
    resp_agent = SecurityResponseAgent()
    s_out = resp_agent.get_deterministic_fallback(SecurityResponseInput(
        user_id=1, event_id="evt_01", effective_risk_level="HIGH", effective_risk_score=0.75
    ))
    assert isinstance(s_out, SecurityResponseOutput)
    assert s_out.alert_required is True
    assert s_out.alert_severity == "HIGH"

    # 5. SOC Monitoring Agent
    soc_agent = SOCMonitoringAgent()
    soc_out = soc_agent.get_deterministic_fallback(SOCMonitoringInput(
        event_id="evt_01", time_window_minutes=30
    ))
    assert isinstance(soc_out, SOCMonitoringOutput)
    assert soc_out.incident_priority in ("P1", "P2", "P3", "P4")


# -------------------------------------------------------------------------
# 9. Agent Failure Does Not Affect Authentication
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_9_agent_failure_does_not_affect_authentication():
    """Verify that complete LLM failure or exception does not block or crash authentication decisions."""
    failing_mock = MockLLMClient(inject_exception=RuntimeError("Provider catastrophic infrastructure outage"))
    agent = AdaptiveAuthAgent(llm_client=failing_mock)

    inp = AdaptiveAuthInput(
        user_id=303,
        effective_risk_level="MEDIUM",
        effective_risk_score=0.48,
        enrolled_factors={"has_gesture_pattern": True}
    )
    # Must succeed via deterministic fallback without propagating RuntimeError
    out = await agent.execute(inp)
    assert isinstance(out, AdaptiveAuthOutput)
    assert out.action == "STEP_UP_REQUIRED"
    assert out.recommended_factor == "NEURAL_TRACE"
    assert "Deterministic fallback" in out.rationale


# -------------------------------------------------------------------------
# 10. CRITICAL Termination Never Waits for Agents
# -------------------------------------------------------------------------
def test_10_critical_termination_is_immediate_and_authoritative():
    """
    Verify DeterministicSecurityArbiter enforces immediate CRITICAL termination,
    even if an agent erroneously recommends ALLOW or low risk.
    """
    arbiter_result = DeterministicSecurityArbiter.arbitrate_decision(
        effective_risk_score=0.88,
        effective_risk_level="CRITICAL",
        enrolled_factors={"has_gesture_pattern": True},
        agent_action="ALLOW",           # Agent hallucinates ALLOW
        agent_factor="NONE"             # Agent hallucinates NONE
    )
    # Arbiter must override agent and force TERMINATE
    assert arbiter_result.action == "TERMINATE"
    assert arbiter_result.recommended_factor == "TERMINATE"
    assert arbiter_result.is_agent_accepted is False
    assert "CRITICAL risk requires immediate" in arbiter_result.override_reason


# -------------------------------------------------------------------------
# 11. Agent Outputs Cannot Reduce Deterministic Risk
# -------------------------------------------------------------------------
def test_11_agent_outputs_cannot_reduce_deterministic_risk():
    """
    Verify Monotonic Risk Invariant: An agent proposing lower risk is overridden.
    Score: max(det, agent); Level: max(det, agent).
    """
    # Case 1: Deterministic is HIGH (0.75), agent proposes LOW (0.10)
    score, level, accepted, reason = DeterministicSecurityArbiter.arbitrate_risk(
        deterministic_score=0.75,
        deterministic_level="HIGH",
        agent_score=0.10,
        agent_level="LOW"
    )
    assert score == 0.75
    assert level == "HIGH"
    assert accepted is False
    assert "OVERRIDDEN_DOWNGRADE" in reason

    # Case 2: Deterministic is LOW (0.15), agent legitimately escalates to MEDIUM (0.45)
    score_esc, level_esc, accepted_esc, reason_esc = DeterministicSecurityArbiter.arbitrate_risk(
        deterministic_score=0.15,
        deterministic_level="LOW",
        agent_score=0.45,
        agent_level="MEDIUM"
    )
    assert score_esc == 0.45
    assert level_esc == "MEDIUM"
    assert accepted_esc is True
    assert "ACCEPTED_ESCALATION" in reason_esc


# -------------------------------------------------------------------------
# 12. Sanitization Pipeline
# -------------------------------------------------------------------------
def test_12_sanitization_scrubs_secrets_and_masks_pii():
    """Verify Sanitizer redacts secrets (passwords, OTPs, raw keys) and masks emails and IPs."""
    dirty_payload = {
        "user_email": "jane.doe@auraluxe.com",
        "client_ip": "172.16.254.1",
        "password": "SuperSecretPassword123!",
        "otp_code": "984215",
        "private_answer": "Fluffy",
        "gesture_nodes": [0, 1, 2, 5, 8],
        "raw_keystrokes": [115, 101, 99, 114, 101, 116],
        "typing_speed_wpm": 62.5,
        "nested_record": {
            "token": "bearer.eyJh...token",
            "doctor_email": "dr.boomika@ayusync.med.in",
            "diagnosis": "Confidential patient record"
        }
    }

    sanitized = Sanitizer.sanitize_dict(dirty_payload)

    # Secrets completely redacted
    assert sanitized["password"] == "[REDACTED_SECRET]"
    assert sanitized["otp_code"] == "[REDACTED_SECRET]"
    assert sanitized["private_answer"] == "[REDACTED_SECRET]"
    assert sanitized["gesture_nodes"] == "[REDACTED_SECRET]"
    assert sanitized["raw_keystrokes"] == "[REDACTED_SECRET]"
    assert sanitized["nested_record"]["token"] == "[REDACTED_SECRET]"
    assert sanitized["nested_record"]["diagnosis"] == "[REDACTED_SECRET]"

    # PII masked
    assert sanitized["user_email"] == "j***e@auraluxe.com"
    assert sanitized["nested_record"]["doctor_email"] == "d***a@ayusync.med.in"
    assert sanitized["client_ip"] == "172.16.254.***"

    # Legitimate non-secret feature preserved
    assert sanitized["typing_speed_wpm"] == 62.5


# -------------------------------------------------------------------------
# 13. Execution Task Runner
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_13_task_runner_timeout_and_background_dispatch():
    """Verify run_with_timeout returns fallback upon timeout and background task dispatch works."""
    async def slow_operation():
        await asyncio.sleep(0.5)
        return "COMPLETED"

    # Test timeout boundary
    result = await run_with_timeout(slow_operation(), timeout_seconds=0.05, fallback_value="TIMED_OUT")
    assert result == "TIMED_OUT"

    # Test non-blocking background dispatch
    executed = []
    async def bg_work():
        executed.append(True)

    task = dispatch_background_task(bg_work())
    await asyncio.sleep(0.05)
    assert len(executed) == 1


# -------------------------------------------------------------------------
# 14. Factory Provider Resolution
# -------------------------------------------------------------------------
def test_14_factory_provider_resolution():
    """Verify get_llm_client resolves correct provider without silently switching Gemini to mock."""
    mock_client = get_llm_client("mock")
    assert isinstance(mock_client, MockLLMClient)

    # Gemini without API key must still return GeminiLLMClient (with invalid config), never silently MockLLMClient
    gemini_client = get_llm_client("gemini", api_key="")
    assert isinstance(gemini_client, GeminiLLMClient)
    assert gemini_client.validate_configuration() is False

    # Unknown provider falls back to MockLLMClient
    unknown_client = get_llm_client("unknown_llm")
    assert isinstance(unknown_client, MockLLMClient)

