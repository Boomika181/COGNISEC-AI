"""
Comprehensive Test Suite for Phase II Step 5.4 — Functional Risk Analysis Agent.
Tests verify:
1. Monotonic Risk Invariant: Agent attempted downgrade is strictly overridden.
2. Legitimate Risk Escalation on Compounding Evidence (Account Takeover / ATO).
3. Mid-Session Environmental Switch Detection (Session Hijacking).
4. Modality Maturity Dampening & Insufficient Evidence Handling (Cold-Start vs Established).
5. Cross-Modal Behavioral Anomaly Detection.
6. Repeated Failed Challenges / Security Friction Escalation.
7. Protected Portal Sensitive Resource Context (Shopping, College, Healthcare).
8. CRITICAL Risk Immediate Deterministic Termination Safeguard.
9. Separation of Observed Facts, Inferences, and Recommendations.
10. Fail-Secure Deterministic Fallback on LLM Timeout or Invalid Output.
11. End-to-End Pipeline: SecurityContextAgent -> RiskAnalysisAgent Handshake.
"""
import pytest
import asyncio
import json
import uuid

from app.core.config import settings
from app.models.user import User
from app.services.session_service import SessionService
from app.services.device_service import DeviceService
from app.services.profile_service import ProfileService

from app.agents.core.mock_client import MockLLMClient
from app.agents.core.llm_client import LLMRequest, LLMResponse, LLMTimeoutException
from app.agents.core.arbiter import DeterministicSecurityArbiter
from app.agents.schemas.agent_schemas import (
    SecurityContextInput,
    SecurityContextOutput,
    RiskAnalysisInput,
    RiskAnalysisOutput
)
from app.agents.modules.security_context_agent import SecurityContextAgent
from app.agents.modules.risk_analysis_agent import RiskAnalysisAgent


def create_test_user(db, email_prefix="risk_user", role="USER") -> User:
    uid = uuid.uuid4().hex[:8]
    user = User(
        name=f"Risk User {uid}",
        email=f"{email_prefix}_{uid}@example.com",
        password_hash="hashed_pw_dummy",
        role=role,
        account_status="ACTIVE"
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# -------------------------------------------------------------------------
# 1. Monotonic Risk Invariant (Attempted Risk Downgrade Refused)
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_1_monotonic_risk_invariant_downgrade_refused():
    """
    Verify Monotonic Risk Arbiter: If LLM attempts to reduce risk level or score
    below the deterministic floor, the agent strictly overrides and maintains the floor.
    """
    # LLM attempts to downgrade HIGH risk to LOW
    mock_llm = MockLLMClient(default_response={
        "threat_category": "BENIGN_BASELINE",
        "identified_risk_indicators": ["User claims benign action"],
        "confidence": 0.95,
        "recommended_escalation": False,
        "recommended_risk_level": "LOW",
        "recommended_risk_score": 0.10,
        "recommended_action": "ALLOW",
        "human_readable_explanation": "[OBSERVED FACTS]\n- High deterministic risk.\n\n[INFERENCES]\n- Disagree with deterministic.\n\n[RECOMMENDATIONS]\n- Lower to LOW."
    })

    agent = RiskAnalysisAgent(llm_client=mock_llm)
    inp = RiskAnalysisInput(
        user_id=1,
        deterministic_score=0.75,
        deterministic_level="HIGH",
        anomaly_score=0.10,
        is_anomaly=False
    )

    out = await agent.execute(inp)
    assert isinstance(out, RiskAnalysisOutput)
    # The deterministic floor MUST be enforced
    assert out.risk_level == "HIGH"
    assert out.risk_score >= 0.75
    assert out.recommended_risk_level == "HIGH"
    assert out.recommended_risk_score >= 0.75


# -------------------------------------------------------------------------
# 2. Legitimate Risk Escalation on Compounding Evidence (Account Takeover)
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_2_legitimate_risk_escalation_on_compounding_evidence():
    """
    Verify agent escalates risk when compounding evidence is observed:
    Untrusted hardware + Severe behavioral anomaly on established profile -> HIGH / Credential Compromise.
    """
    mock_llm = MockLLMClient(default_response={
        "threat_category": "CREDENTIAL_COMPROMISE",
        "identified_risk_indicators": ["Untrusted device with severe behavioral anomaly"],
        "confidence": 0.95,
        "recommended_escalation": True,
        "recommended_risk_level": "HIGH",
        "recommended_risk_score": 0.76,
        "recommended_action": "STEP_UP_REQUIRED",
        "human_readable_explanation": "[OBSERVED FACTS]\n- Untrusted device.\n- Anomaly score 0.82.\n\n[INFERENCES]\n- Likely Account Takeover.\n\n[RECOMMENDATIONS]\n- Escalate to HIGH and require step-up."
    })

    agent = RiskAnalysisAgent(llm_client=mock_llm)
    inp = RiskAnalysisInput(
        user_id=10,
        deterministic_score=0.20,
        deterministic_level="LOW",
        anomaly_score=0.82,
        is_anomaly=True,
        sanitized_context={
            "device_summary": {"is_trusted": False, "trust_state": "UNTRUSTED"},
            "behavioural_summary": {"maturity_status": "ESTABLISHED", "sample_count": 12}
        }
    )

    out = await agent.execute(inp)
    assert isinstance(out, RiskAnalysisOutput)
    assert out.threat_category == "CREDENTIAL_COMPROMISE"
    assert out.recommended_escalation is True
    assert out.risk_level == "HIGH"
    assert out.risk_score >= 0.75
    assert out.recommended_action == "STEP_UP_REQUIRED"


# -------------------------------------------------------------------------
# 3. Mid-Session Environmental Switch Detection (Session Hijacking)
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_3_mid_session_environmental_switch_detection():
    """
    Verify agent flags session hijacking when mid-session network switch
    is accompanied by interaction physics deviation.
    """
    agent = RiskAnalysisAgent()
    inp = RiskAnalysisInput(
        user_id=20,
        deterministic_score=0.40,
        deterministic_level="MEDIUM",
        anomaly_score=0.68,
        is_anomaly=True,
        sanitized_context={
            "device_summary": {
                "is_trusted": True,
                "changes_detected": True  # Mid-session IP switch flagged
            },
            "behavioural_summary": {
                "maturity_status": "ESTABLISHED",
                "sample_count": 15
            }
        }
    )

    out = agent.get_deterministic_fallback(inp)
    assert isinstance(out, RiskAnalysisOutput)
    assert out.threat_category == "SESSION_HIJACKING"
    assert out.recommended_escalation is True
    assert out.risk_level == "HIGH"
    assert out.recommended_action == "STEP_UP_REQUIRED"
    assert any("Mid-session IP address switch" in ind for ind in out.identified_risk_indicators)


# -------------------------------------------------------------------------
# 4. Modality Maturity Dampening & Insufficient Evidence Handling
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_4_modality_maturity_dampening_insufficient_evidence():
    """
    Verify that when baseline is COLD_START or LEARNING, high behavioral scores
    do NOT trigger standalone risk escalation and confidence is dampened.
    """
    agent = RiskAnalysisAgent()
    inp = RiskAnalysisInput(
        user_id=30,
        deterministic_score=0.20,
        deterministic_level="LOW",
        anomaly_score=0.90,  # High raw score, but cold-start profile!
        is_anomaly=True,
        sanitized_context={
            "device_summary": {"is_trusted": False, "trust_state": "NEW"},
            "behavioural_summary": {"maturity_status": "COLD_START", "sample_count": 0}
        }
    )

    out = agent.get_deterministic_fallback(inp)
    assert isinstance(out, RiskAnalysisOutput)
    # The threat category must be INSUFFICIENT_EVIDENCE
    assert out.threat_category == "INSUFFICIENT_EVIDENCE"
    # Confidence is appropriately dampened
    assert out.confidence <= 0.65
    # Does not escalate based on ungrounded behavioral score alone
    assert out.recommended_escalation is False
    assert out.risk_level == "LOW"
    # Explains missing evidence
    assert any("Immature behavioral baseline" in e for e in out.missing_or_insufficient_evidence)


# -------------------------------------------------------------------------
# 5. Cross-Modal Behavioral Anomaly Detection
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_5_cross_modal_behavioral_anomaly_detection():
    """
    Verify agent flags cross-modal anomalies when multiple mature behavioral
    channels deviate concurrently on an established profile.
    """
    agent = RiskAnalysisAgent()
    inp = RiskAnalysisInput(
        user_id=40,
        deterministic_score=0.55,
        deterministic_level="MEDIUM",
        anomaly_score=0.75,
        is_anomaly=True,
        sanitized_context={
            "behavioural_summary": {"maturity_status": "ESTABLISHED", "sample_count": 20},
            "modality_maturity_breakdown": {
                "keyboard": {"status": "ESTABLISHED", "sample_count": 10, "is_mature": True},
                "mouse": {"status": "ESTABLISHED", "sample_count": 10, "is_mature": True}
            }
        }
    )

    out = agent.get_deterministic_fallback(inp)
    assert isinstance(out, RiskAnalysisOutput)
    assert out.cross_modal_anomaly_detected is True
    assert any("Cross-modal behavioral anomaly" in ind for ind in out.identified_risk_indicators)


# -------------------------------------------------------------------------
# 6. Repeated Failed Challenges / Security Friction Escalation
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_6_repeated_failed_challenges_escalation():
    """
    Verify that repeated failed security challenges or blocks trigger
    escalation due to credential brute-forcing / challenge probing.
    """
    agent = RiskAnalysisAgent()
    inp = RiskAnalysisInput(
        user_id=50,
        deterministic_score=0.25,
        deterministic_level="LOW",
        anomaly_score=0.20,
        is_anomaly=False,
        sanitized_context={
            "security_event_summary": {"failed_attempts_count": 3}
        }
    )

    out = agent.get_deterministic_fallback(inp)
    assert isinstance(out, RiskAnalysisOutput)
    assert out.threat_category == "CREDENTIAL_COMPROMISE"
    assert out.recommended_escalation is True
    assert out.risk_level == "MEDIUM"
    assert out.risk_score >= 0.50
    assert out.recommended_action == "STEP_UP_REQUIRED"


# -------------------------------------------------------------------------
# 7. Protected Portal Sensitive Resource Context (Shopping, College, Healthcare)
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_7_protected_portal_sensitive_resource_context():
    """
    Verify that unverified devices accessing protected application portals
    (e.g., Healthcare / EHR Vault, Shopping / Financial Vault) trigger heightened scrutiny.
    """
    agent = RiskAnalysisAgent()

    for portal in ("healthcare", "shopping", "college"):
        inp = RiskAnalysisInput(
            user_id=60,
            deterministic_score=0.20,
            deterministic_level="LOW",
            sanitized_context={
                "application_context": {"portal": portal},
                "device_summary": {"is_trusted": False, "trust_state": "UNTRUSTED"}
            }
        )
        out = agent.get_deterministic_fallback(inp)
        assert isinstance(out, RiskAnalysisOutput)
        assert out.threat_category == "SUSPICIOUS_ANOMALY"
        assert out.recommended_escalation is True
        assert out.risk_level == "MEDIUM"
        assert any(f"portal '{portal}'" in ind for ind in out.identified_risk_indicators)


# -------------------------------------------------------------------------
# 8. CRITICAL Risk Immediate Deterministic Termination Safeguard
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_8_critical_risk_immediate_deterministic_termination():
    """
    Verify Zero-Trust policy: When deterministic risk is CRITICAL (>= 0.85),
    session termination is immediate, non-negotiable, and cannot be deferred.
    """
    agent = RiskAnalysisAgent()
    inp = RiskAnalysisInput(
        user_id=70,
        deterministic_score=0.92,
        deterministic_level="CRITICAL",
        anomaly_score=0.88,
        is_anomaly=True
    )

    out = agent.get_deterministic_fallback(inp)
    assert isinstance(out, RiskAnalysisOutput)
    assert out.risk_level == "CRITICAL"
    assert out.risk_score >= 0.85
    assert out.recommended_action == "TERMINATE_SESSION"
    assert "TERMINATE_SESSION" in out.human_readable_explanation


# -------------------------------------------------------------------------
# 9. Separation of Observed Facts, Inferences, and Recommendations
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_9_separation_of_facts_inferences_and_recommendations():
    """
    Verify human_readable_explanation strictly separates observed facts,
    inferences, and recommendations, preventing hallucinated assertions.
    """
    agent = RiskAnalysisAgent()
    inp = RiskAnalysisInput(
        user_id=80,
        deterministic_score=0.35,
        deterministic_level="MEDIUM",
        anomaly_score=0.60,
        is_anomaly=True,
        sanitized_context={
            "device_summary": {"is_trusted": True, "trust_state": "TRUSTED"},
            "behavioural_summary": {"maturity_status": "ESTABLISHED", "sample_count": 8}
        }
    )

    out = agent.get_deterministic_fallback(inp)
    assert isinstance(out, RiskAnalysisOutput)
    exp = out.human_readable_explanation

    assert "[OBSERVED FACTS]" in exp
    assert "[INFERENCES]" in exp
    assert "[RECOMMENDATIONS]" in exp

    # Check that observed facts list concrete telemetry
    assert "Deterministic risk evaluated at MEDIUM" in exp
    assert "Device trust state is TRUSTED" in exp
    assert "Profile maturity status is ESTABLISHED" in exp


# -------------------------------------------------------------------------
# 10. Fail-Secure Deterministic Fallback on LLM Timeout / Error
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_10_fail_secure_deterministic_fallback_on_llm_timeout():
    """
    Verify agent respects execution timeout and gracefully engages deterministic
    fallback without crashing or leaking unhandled exceptions.
    """
    slow_mock = MockLLMClient(
        default_response={"threat_category": "BENIGN_BASELINE"},
        simulated_latency_ms=250
    )
    agent = RiskAnalysisAgent(llm_client=slow_mock, timeout_seconds=0.04)

    inp = RiskAnalysisInput(
        user_id=90,
        deterministic_score=0.50,
        deterministic_level="MEDIUM",
        anomaly_score=0.45,
        is_anomaly=False
    )

    out = await agent.execute(inp)
    assert isinstance(out, RiskAnalysisOutput)
    assert out.risk_level == "MEDIUM"
    assert out.risk_score == 0.50
    assert "Deterministic fallback" in out.rationale


# -------------------------------------------------------------------------
# 11. End-to-End Pipeline: SecurityContextAgent -> RiskAnalysisAgent Handshake
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_11_end_to_end_context_to_risk_analysis_handshake(db_session):
    """
    Verify full cognitive pipeline integration:
    SecurityContextAgent collects authoritative facts -> RiskAnalysisAgent analyzes threats.
    """
    user = create_test_user(db_session, "e2e_pipeline_user")
    sess = SessionService.create_session(
        db_session,
        user_id=user.id,
        application="shopping",
        ip_address="198.51.100.25"
    )

    # 1. Execute SecurityContextAgent
    context_agent = SecurityContextAgent(db=db_session)
    ctx_inp = SecurityContextInput(
        user_id=user.id,
        session_id=sess.id,
        application="shopping",
        client_ip="198.51.100.25"
    )
    ctx_out = await context_agent.execute(ctx_inp)
    assert isinstance(ctx_out, SecurityContextOutput)

    # 2. Feed sanitized context directly into RiskAnalysisAgent
    risk_agent = RiskAnalysisAgent(db=db_session)
    risk_inp = RiskAnalysisInput(
        user_id=user.id,
        deterministic_score=0.20,
        deterministic_level="LOW",
        anomaly_score=ctx_out.behavioural_summary.get("recent_anomaly_score", 0.0),
        is_anomaly=False,
        sanitized_context=ctx_out.sanitized_context,
        modality_maturity=ctx_out.modality_maturity_breakdown
    )

    risk_out = await risk_agent.execute(risk_inp)
    assert isinstance(risk_out, RiskAnalysisOutput)
    assert risk_out.deterministic_risk_level == "LOW"
    assert risk_out.deterministic_risk_score == 0.20
    assert risk_out.risk_level in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert risk_out.threat_category in (
        "CREDENTIAL_COMPROMISE", "SESSION_HIJACKING", "BOT_AUTOMATION",
        "INSIDER_THREAT", "SUSPICIOUS_ANOMALY", "BENIGN_BASELINE", "INSUFFICIENT_EVIDENCE"
    )
    assert len(risk_out.supporting_evidence) > 0

