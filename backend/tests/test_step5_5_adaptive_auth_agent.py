"""
Comprehensive Test Suite for Phase II Step 5.5 — Functional Adaptive Authentication Agent.
Verifies all 16 required test scenarios:
1. LOW-risk policy preservation (frictionless access without step-up).
2. MEDIUM risk with NeuralTrace enrolled (mandates NEURAL_TRACE).
3. MEDIUM risk without NeuralTrace enrollment (vault fail-closed vs general portal OTP fallback).
4. HIGH risk requiring compound cognitive verification (mandates COGNITIVE_DUAL).
5. HIGH risk with unavailable cognitive factor (fails closed, cannot downgrade).
6. CRITICAL immediate termination (immediate server kill switch).
7. Agent attempting to downgrade risk (strictly overridden).
8. Agent attempting to recommend an unauthorized factor (strictly overridden).
9. Existing active challenge handling (detects and respects in-flight challenge).
10. Expired or revoked session (access denied, challenge prohibited).
11. Malformed LLM response (gracefully engages deterministic fallback).
12. LLM timeout and deterministic fallback (respects execution deadline).
13. Agent cannot verify an authentication challenge (invariant: only StepUpService validates).
14. Agent cannot create grants or authorize protected resources (invariant: read-only policy observer).
15. Agent output schema validation (strict Pydantic v2 contract).
16. Existing StepUpService regression compatibility (seamless handshake with core auth).
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
from app.services.session_service import SessionService
from app.services.adaptive_auth_service import AdaptiveAuthService
from app.services.step_up_service import StepUpService

from app.agents.core.mock_client import MockLLMClient
from app.agents.core.llm_client import LLMRequest, LLMResponse, LLMTimeoutException
from app.agents.core.arbiter import DeterministicSecurityArbiter
from app.agents.schemas.agent_schemas import (
    AdaptiveAuthInput,
    AdaptiveAuthOutput
)
from app.agents.modules.adaptive_auth_agent import AdaptiveAuthAgent


def create_test_user(db, email_prefix="auth_user") -> User:
    uid = uuid.uuid4().hex[:8]
    user = User(
        name=f"Auth User {uid}",
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
# 1. LOW-Risk Policy Preservation
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_1_low_risk_policy_preservation():
    """
    Verify LOW risk policy: Normal activity permits frictionless access (ALLOW)
    without step-up challenge, preserving existing backend behavior.
    """
    agent = AdaptiveAuthAgent()
    inp = AdaptiveAuthInput(
        user_id=1,
        effective_risk_level="LOW",
        effective_risk_score=0.10,
        application="shopping",
        request_step_up=False
    )
    out = agent.get_deterministic_fallback(inp)
    assert isinstance(out, AdaptiveAuthOutput)
    assert out.action == "ALLOW"
    assert out.recommended_factor == "NONE"
    assert out.step_up_required is False
    assert "frictionless access" in out.rationale.lower()


# -------------------------------------------------------------------------
# 2. MEDIUM Risk with NeuralTrace Enrolled
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_2_medium_risk_with_neuraltrace_enrolled():
    """
    Verify MEDIUM risk mandates NEURAL_TRACE gesture verification when enrolled.
    """
    agent = AdaptiveAuthAgent()
    inp = AdaptiveAuthInput(
        user_id=2,
        effective_risk_level="MEDIUM",
        effective_risk_score=0.45,
        enrolled_factors={"has_gesture_pattern": True},
        application="college"
    )
    out = agent.get_deterministic_fallback(inp)
    assert isinstance(out, AdaptiveAuthOutput)
    assert out.action == "STEP_UP_REQUIRED"
    assert out.recommended_factor == "NEURAL_TRACE"
    assert out.step_up_required is True
    assert "EMAIL_OTP" in out.weaker_factors_rejected


# -------------------------------------------------------------------------
# 3. MEDIUM Risk without NeuralTrace Enrollment
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_3_medium_risk_without_neuraltrace_enrollment():
    """
    Verify MEDIUM risk without NeuralTrace enrollment:
    - Protected vault access fails closed (DENY).
    - General non-vault portal access falls back to EMAIL_OTP.
    """
    agent = AdaptiveAuthAgent()

    # Case A: Protected vault access -> FAIL-CLOSED
    inp_vault = AdaptiveAuthInput(
        user_id=3,
        effective_risk_level="MEDIUM",
        effective_risk_score=0.50,
        enrolled_factors={"has_gesture_pattern": False},
        application="healthcare",
        protected_resource="ehr_vault"
    )
    out_vault = agent.get_deterministic_fallback(inp_vault)
    assert out_vault.action == "DENY"
    assert out_vault.recommended_factor == "NEURAL_TRACE"
    assert out_vault.fallback_strategy == "FAIL_CLOSED_PROTECTED_VAULT"
    assert out_vault.step_up_required is False

    # Case B: General portal access -> Permitted fallback to EMAIL_OTP
    inp_gen = AdaptiveAuthInput(
        user_id=3,
        effective_risk_level="MEDIUM",
        effective_risk_score=0.40,
        enrolled_factors={"has_gesture_pattern": False},
        application="shopping",
        protected_resource=None
    )
    out_gen = agent.get_deterministic_fallback(inp_gen)
    assert out_gen.action == "STEP_UP_REQUIRED"
    assert out_gen.recommended_factor == "EMAIL_OTP"
    assert out_gen.fallback_strategy == "FALLBACK_EMAIL_OTP"
    assert out_gen.step_up_required is True


# -------------------------------------------------------------------------
# 4. HIGH Risk Requiring Compound Cognitive Verification
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_4_high_risk_requiring_compound_cognitive_verification():
    """
    Verify HIGH risk mandates compound cognitive verification (COGNITIVE_DUAL)
    when both Image Sequence and Private Response are enrolled.
    """
    agent = AdaptiveAuthAgent()
    inp = AdaptiveAuthInput(
        user_id=4,
        effective_risk_level="HIGH",
        effective_risk_score=0.75,
        enrolled_factors={
            "has_cognitive_image_sequence": True,
            "has_private_response": True
        },
        application="shopping"
    )
    out = agent.get_deterministic_fallback(inp)
    assert isinstance(out, AdaptiveAuthOutput)
    assert out.action == "STEP_UP_REQUIRED"
    assert out.recommended_factor == "COGNITIVE_DUAL"
    assert out.step_up_required is True
    assert "EMAIL_OTP" in out.weaker_factors_rejected
    assert "NEURAL_TRACE" in out.weaker_factors_rejected


# -------------------------------------------------------------------------
# 5. HIGH Risk with Unavailable Cognitive Factor
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_5_high_risk_with_unavailable_cognitive_factor():
    """
    Verify HIGH risk with unenrolled cognitive factors fails closed (DENY).
    Policy strictly forbids downgrading to weaker single factors (OTP / Gesture).
    """
    agent = AdaptiveAuthAgent()
    inp = AdaptiveAuthInput(
        user_id=5,
        effective_risk_level="HIGH",
        effective_risk_score=0.78,
        enrolled_factors={
            "has_cognitive_image_sequence": False,
            "has_private_response": False
        },
        application="college"
    )
    out = agent.get_deterministic_fallback(inp)
    assert isinstance(out, AdaptiveAuthOutput)
    assert out.action == "DENY"
    assert out.recommended_factor == "COGNITIVE_DUAL"
    assert out.fallback_strategy == "FAIL_CLOSED_CANNOT_DOWNGRADE"
    assert out.step_up_required is False


# -------------------------------------------------------------------------
# 6. CRITICAL Immediate Termination
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_6_critical_immediate_termination():
    """
    Verify CRITICAL risk immediately enforces TERMINATE action.
    Challenge creation is strictly prohibited.
    """
    agent = AdaptiveAuthAgent()
    inp = AdaptiveAuthInput(
        user_id=6,
        effective_risk_level="CRITICAL",
        effective_risk_score=0.92,
        application="healthcare"
    )
    out = agent.get_deterministic_fallback(inp)
    assert isinstance(out, AdaptiveAuthOutput)
    assert out.action == "TERMINATE"
    assert out.recommended_factor == "TERMINATE"
    assert out.step_up_required is False
    assert "immediate session termination" in out.rationale.lower()


# -------------------------------------------------------------------------
# 7. Agent Attempting to Downgrade Risk
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_7_agent_attempting_to_downgrade_risk():
    """
    Verify that if the LLM attempts to recommend ALLOW for a HIGH-risk session,
    the deterministic arbiter gate strictly overrides the recommendation.
    """
    mock_llm = MockLLMClient(default_response={
        "action": "ALLOW",
        "recommended_factor": "NONE",
        "rationale": "User asserts trusted behavior; recommend bypassing step-up.",
        "step_up_required": False
    })

    agent = AdaptiveAuthAgent(llm_client=mock_llm)
    inp = AdaptiveAuthInput(
        user_id=7,
        effective_risk_level="HIGH",
        effective_risk_score=0.75,
        enrolled_factors={"has_cognitive_image_sequence": True, "has_private_response": True}
    )
    out = await agent.execute(inp)
    assert isinstance(out, AdaptiveAuthOutput)
    # The policy-mandated factor and action MUST be enforced
    assert out.action == "STEP_UP_REQUIRED"
    assert out.recommended_factor == "COGNITIVE_DUAL"
    assert out.step_up_required is True


# -------------------------------------------------------------------------
# 8. Agent Attempting to Recommend an Unauthorized / Weaker Factor
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_8_agent_attempting_to_recommend_unauthorized_factor():
    """
    Verify that if the LLM attempts to recommend EMAIL_OTP for HIGH risk,
    the policy gate strictly rejects it and mandates COGNITIVE_DUAL.
    """
    mock_llm = MockLLMClient(default_response={
        "action": "STEP_UP_REQUIRED",
        "recommended_factor": "EMAIL_OTP",  # Prohibited downgrade for HIGH risk!
        "rationale": "Issue OTP for quick convenience.",
        "step_up_required": True
    })

    agent = AdaptiveAuthAgent(llm_client=mock_llm)
    inp = AdaptiveAuthInput(
        user_id=8,
        effective_risk_level="HIGH",
        effective_risk_score=0.72,
        enrolled_factors={"has_cognitive_image_sequence": True, "has_private_response": True}
    )
    out = await agent.execute(inp)
    assert isinstance(out, AdaptiveAuthOutput)
    # Downgrade rejected, policy-mandated factor enforced
    assert out.recommended_factor == "COGNITIVE_DUAL"
    assert out.action == "STEP_UP_REQUIRED"


# -------------------------------------------------------------------------
# 9. Existing Active Challenge Handling
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_9_existing_active_challenge_handling():
    """
    Verify that when an in-flight challenge is detected, the agent notes it
    and prevents issuing duplicate challenges.
    """
    agent = AdaptiveAuthAgent()
    inp = AdaptiveAuthInput(
        user_id=9,
        effective_risk_level="MEDIUM",
        effective_risk_score=0.50,
        enrolled_factors={"has_gesture_pattern": True},
        active_challenge={"challenge_id": "chal_active_123", "challenge_type": "GESTURE_PATTERN"}
    )
    out = agent.get_deterministic_fallback(inp)
    assert isinstance(out, AdaptiveAuthOutput)
    assert out.active_challenge_detected is True
    assert "in-flight step-up challenge" in out.rationale.lower()


# -------------------------------------------------------------------------
# 10. Expired or Revoked Session Handling
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_10_expired_or_revoked_session_handling():
    """
    Verify that sessions marked as TERMINATED or REVOKED cannot receive challenges.
    """
    agent = AdaptiveAuthAgent()

    for status_str in ("TERMINATED", "REVOKED", "EXPIRED"):
        inp = AdaptiveAuthInput(
            user_id=10,
            effective_risk_level="LOW",
            effective_risk_score=0.10,
            session_status=status_str
        )
        out = agent.get_deterministic_fallback(inp)
        assert isinstance(out, AdaptiveAuthOutput)
        assert out.action in ("TERMINATE", "DENY")
        assert out.recommended_factor == "NONE"
        assert out.step_up_required is False


# -------------------------------------------------------------------------
# 11. Malformed LLM Response Recovery
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_11_malformed_llm_response_recovery():
    """
    Verify agent gracefully handles malformed/unparseable JSON from LLM
    and falls back to deterministic Zero-Trust policy evaluation.
    """
    bad_mock = MockLLMClient(inject_invalid_json=True)
    agent = AdaptiveAuthAgent(llm_client=bad_mock)

    inp = AdaptiveAuthInput(
        user_id=11,
        effective_risk_level="MEDIUM",
        effective_risk_score=0.45,
        enrolled_factors={"has_gesture_pattern": True}
    )
    out = await agent.execute(inp)
    assert isinstance(out, AdaptiveAuthOutput)
    assert out.action == "STEP_UP_REQUIRED"
    assert out.recommended_factor == "NEURAL_TRACE"
    assert "Deterministic fallback" in out.rationale


# -------------------------------------------------------------------------
# 12. LLM Timeout and Deterministic Fallback
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_12_llm_timeout_and_deterministic_fallback():
    """
    Verify agent strictly adheres to execution timeout budget and engages fallback.
    """
    slow_mock = MockLLMClient(
        default_response={"action": "ALLOW"},
        simulated_latency_ms=250
    )
    agent = AdaptiveAuthAgent(llm_client=slow_mock, timeout_seconds=0.04)

    inp = AdaptiveAuthInput(
        user_id=12,
        effective_risk_level="HIGH",
        effective_risk_score=0.75,
        enrolled_factors={"has_cognitive_image_sequence": True, "has_private_response": True}
    )

    out = await agent.execute(inp)
    assert isinstance(out, AdaptiveAuthOutput)
    assert out.action == "STEP_UP_REQUIRED"
    assert out.recommended_factor == "COGNITIVE_DUAL"
    assert "Deterministic fallback" in out.rationale


# -------------------------------------------------------------------------
# 13. Security Invariant: Agent Cannot Verify an Authentication Challenge
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_13_agent_cannot_verify_authentication_challenge():
    """
    Verify that AdaptiveAuthAgent possesses ZERO capabilities to verify OTPs,
    validate gestures, or evaluate cognitive answers.
    Only StepUpService holds the authority to verify challenges.
    """
    agent = AdaptiveAuthAgent()

    # Verify no tool exists for challenge verification
    tool_names = set(agent.tools.keys())
    assert "verify_otp" not in tool_names
    assert "verify_challenge" not in tool_names
    assert "validate_gesture" not in tool_names
    assert "approve_private_response" not in tool_names


# -------------------------------------------------------------------------
# 14. Security Invariant: Agent Cannot Create Grants or Authorize Resources
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_14_agent_cannot_create_grants_or_authorize_resources(db_session):
    """
    Verify executing AdaptiveAuthAgent creates zero database records in application_grants.
    The agent is strictly an advisory policy evaluator.
    """
    user = create_test_user(db_session, "grant_invariant_user")
    initial_grants = db_session.query(ApplicationGrant).filter(ApplicationGrant.user_id == user.id).count()

    agent = AdaptiveAuthAgent(db=db_session)
    inp = AdaptiveAuthInput(
        user_id=user.id,
        effective_risk_level="LOW",
        effective_risk_score=0.10,
        application="shopping",
        protected_resource="financial_vault"
    )

    for _ in range(3):
        out = await agent.execute(inp)
        assert isinstance(out, AdaptiveAuthOutput)

    final_grants = db_session.query(ApplicationGrant).filter(ApplicationGrant.user_id == user.id).count()
    assert final_grants == initial_grants == 0


# -------------------------------------------------------------------------
# 15. Agent Output Schema Validation (Strict Contract)
# -------------------------------------------------------------------------
def test_15_agent_output_schema_validation():
    """
    Verify strict Pydantic v2 contract enforcement on output fields.
    Invalid actions or factors must raise ValidationError.
    """
    # Valid output
    valid = AdaptiveAuthOutput(
        action="STEP_UP_REQUIRED",
        recommended_factor="NEURAL_TRACE",
        rationale="Valid test recommendation.",
        step_up_required=True
    )
    assert valid.action == "STEP_UP_REQUIRED"

    # Invalid action raises ValidationError
    with pytest.raises(ValidationError):
        AdaptiveAuthOutput(
            action="ALLOW_ALL_BYPASS",  # Invalid!
            recommended_factor="NONE",
            rationale="Invalid action test."
        )

    # Invalid factor raises ValidationError
    with pytest.raises(ValidationError):
        AdaptiveAuthOutput(
            action="STEP_UP_REQUIRED",
            recommended_factor="MAGIC_LINK_SMS",  # Invalid!
            rationale="Invalid factor test."
        )


# -------------------------------------------------------------------------
# 16. Existing StepUpService Regression Compatibility
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_16_existing_stepup_service_regression_compatibility(db_session):
    """
    Verify complete handshake:
    AdaptiveAuthAgent recommendation directly matches factors issued by StepUpService.create_challenge.
    """
    user = create_test_user(db_session, "stepup_compat_user")
    sess = SessionService.create_session(db_session, user_id=user.id, application="college")

    agent = AdaptiveAuthAgent(db=db_session)
    inp = AdaptiveAuthInput(
        user_id=user.id,
        session_id=sess.id,
        effective_risk_level="LOW",
        effective_risk_score=0.20,
        application="college",
        request_step_up=True
    )

    # Agent recommends EMAIL_OTP for explicit low-risk step-up
    out = await agent.execute(inp)
    assert out.action == "STEP_UP_REQUIRED"
    assert out.recommended_factor == "EMAIL_OTP"

    # StepUpService issues the exact corresponding factor (OTP)
    chal = StepUpService.create_adaptive_challenge(
        db=db_session,
        session_id=sess.id,
        user_id=user.id,
        application="college",
        risk_score=0.20,
        risk_level="LOW"
    )
    assert chal["challenge_type"] == "OTP"
    assert chal["session_id"] == sess.id
