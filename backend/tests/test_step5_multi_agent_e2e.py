"""
End-to-End Multi-Agent Integration Pipeline Test Suite.
Verifies the complete multi-agent Zero-Trust workflow:
SecurityContextAgent -> RiskAnalysisAgent -> DeterministicSecurityArbiter ->
AdaptiveAuthAgent -> SecurityResponseAgent -> SOCMonitoringAgent.
"""
import pytest
import uuid
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.session import Session as DbSession
from app.services.session_service import SessionService
from app.agents.execution.orchestrator import SecurityOrchestrator
from app.agents.schemas.agent_schemas import (
    SecurityContextOutput,
    RiskAnalysisOutput,
    AdaptiveAuthOutput,
    SecurityResponseOutput,
    SOCMonitoringOutput
)


def create_user(db: Session, email_prefix="e2e_user") -> User:
    uid = uuid.uuid4().hex[:8]
    user = User(
        name=f"E2E User {uid}",
        email=f"{email_prefix}_{uid}@example.com",
        password_hash="Hashed1234!",
        role="USER",
        account_status="ACTIVE",
        failed_login_attempts=0
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.mark.asyncio
async def test_e2e_pipeline_low_risk_flow(db_session: Session):
    """
    Verifies end-to-end execution for normal, low-risk session telemetry:
    - Context gathered
    - Low risk classified and arbitrated
    - Frictionless access allowed without step-up
    - Routine monitoring logged
    - SOC priority P4/P3
    """
    user = create_user(db_session, "low_risk_e2e")
    sess = SessionService.create_session(db_session, user_id=user.id, application="college")

    orchestrator = SecurityOrchestrator(db=db_session)
    res = await orchestrator.evaluate_session_security(
        user_id=user.id,
        session_id=sess.id,
        application="college",
        raw_anomaly_score=0.10,
        deterministic_risk_score=0.15,
        deterministic_risk_level="LOW",
        contributing_reasons=["Normal typing cadence"]
    )

    assert isinstance(res["context"], SecurityContextOutput)
    assert isinstance(res["risk_analysis"], RiskAnalysisOutput)
    assert isinstance(res["adaptive_auth"], AdaptiveAuthOutput)
    assert isinstance(res["security_response"], SecurityResponseOutput)
    assert isinstance(res["soc_monitoring"], SOCMonitoringOutput)

    assert res["adaptive_auth"].action == "ALLOW"
    assert res["security_response"].severity == "LOW"
    assert res["security_response"].required_backend_operation == "NONE"


@pytest.mark.asyncio
async def test_e2e_pipeline_medium_risk_flow(db_session: Session):
    """
    Verifies end-to-end execution for medium-risk behavioral anomalies:
    - Context gathered
    - Moderate risk flagged
    - Adaptive auth recommends step-up challenge
    - Security response flags alert and step-up enforcement
    """
    user = create_user(db_session, "med_risk_e2e")
    sess = SessionService.create_session(db_session, user_id=user.id, application="shopping")

    orchestrator = SecurityOrchestrator(db=db_session)
    res = await orchestrator.evaluate_session_security(
        user_id=user.id,
        session_id=sess.id,
        application="shopping",
        raw_anomaly_score=0.55,
        deterministic_risk_score=0.48,
        deterministic_risk_level="MEDIUM",
        contributing_reasons=["Typing velocity drift +2.5 sigma"]
    )

    assert res["arbitrated_risk"]["effective_risk_level"] == "MEDIUM"
    assert res["adaptive_auth"].step_up_required is True
    assert res["security_response"].severity == "MEDIUM"
    assert res["security_response"].required_backend_operation == "ENFORCE_STEP_UP"


@pytest.mark.asyncio
async def test_e2e_pipeline_high_risk_flow(db_session: Session):
    """
    Verifies end-to-end execution for high-risk behavioral anomalies:
    - High risk arbitrated monotonically
    - Adaptive auth mandates compound COGNITIVE_DUAL
    - Security response marks HIGH severity and user notification
    - SOC priority P2
    """
    user = create_user(db_session, "high_risk_e2e")
    sess = SessionService.create_session(db_session, user_id=user.id, application="healthcare")

    orchestrator = SecurityOrchestrator(db=db_session)
    res = await orchestrator.evaluate_session_security(
        user_id=user.id,
        session_id=sess.id,
        application="healthcare",
        raw_anomaly_score=0.75,
        deterministic_risk_score=0.72,
        deterministic_risk_level="HIGH",
        contributing_reasons=["Cross-device token replay", "Severe curvature entropy deviation"],
        protected_resource="ehr_vault"
    )

    assert res["arbitrated_risk"]["effective_risk_level"] == "HIGH"
    assert res["adaptive_auth"].recommended_factor == "COGNITIVE_DUAL"
    assert res["security_response"].severity == "HIGH"
    assert res["security_response"].alert_required is True
    assert res["soc_monitoring"].incident_priority in ("P1", "P2")


@pytest.mark.asyncio
async def test_e2e_pipeline_critical_risk_containment_flow(db_session: Session):
    """
    Verifies end-to-end execution for CRITICAL risk:
    - Authoritative termination enforced
    - Session marked TERMINATED in DB
    - Response agent executes kill switch containment
    - SOC priority P1
    """
    user = create_user(db_session, "crit_risk_e2e")
    sess = SessionService.create_session(db_session, user_id=user.id, application="college")

    orchestrator = SecurityOrchestrator(db=db_session)
    res = await orchestrator.evaluate_session_security(
        user_id=user.id,
        session_id=sess.id,
        application="college",
        raw_anomaly_score=0.95,
        deterministic_risk_score=0.92,
        deterministic_risk_level="CRITICAL",
        contributing_reasons=["Active session hijack detected", "Extreme anomaly score 0.95"],
        auto_containment=True
    )

    assert res["arbitrated_risk"]["effective_risk_level"] == "CRITICAL"
    assert res["adaptive_auth"].action == "TERMINATE"
    assert res["security_response"].required_backend_operation == "TERMINATE_SESSION"
    assert res["security_response"].containment_action == "SESSION_REVOKED"
    assert res["soc_monitoring"].incident_priority == "P1"

    # Database session is terminated
    db_session.refresh(sess)
    assert sess.status == "TERMINATED"

