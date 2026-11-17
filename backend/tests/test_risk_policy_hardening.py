"""
COGNISEC-AI Phase-II Step 3.6: Risk Policy Hardening and Threshold Consolidation Test Suite.

Verifies:
- Scenario A: Medium-Risk Downgrade Rejection (enrolled NeuralTrace ignores preferred_factor="OTP")
- Scenario B: Medium-Risk Unenrolled Protected Access Denial (HTTP 409 Conflict, no silent OTP)
- Scenario C: High-Risk Compound Cognitive Enforcement (HIGH_RISK_DUAL strictly required)
- Scenario D: Critical-Risk Session Termination (HTTP 400, session status TERMINATED)
- Scenario E: Risk Boundary Float Tests (0.299999, 0.30, 0.300001, 0.649999, 0.65, 0.650001, 0.849999, 0.85, 0.850001)
- Scenario F: Missing risk_level parameter (0.20, 0.40, 0.70, 0.90 classified canonically)
- Scenario G: API-Level Downgrade via direct endpoint requests
"""

import time
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.session import Session as DbSession
from app.core.security import get_password_hash, create_access_token
from app.services.step_up_service import StepUpService, NEURALTRACE_NOT_ENROLLED_DETAIL
from app.services.risk_service import RiskService
from app.services.anti_replay_service import AntiReplayService
from app.core.rate_limit import rate_limiter


@pytest.fixture(autouse=True)
def clean_state():
    StepUpService.reset()
    AntiReplayService.reset()
    rate_limiter.reset()
    yield
    StepUpService.reset()
    AntiReplayService.reset()
    rate_limiter.reset()


@pytest.fixture
def make_user_and_session(client: TestClient, db_session: Session):
    """Factory fixture for test users, sessions, and headers."""
    def _create(email_prefix: str, application: str = "shopping", risk_level: str = "MEDIUM"):
        email = f"{email_prefix}_{int(time.time() * 1000)}@example.com"
        user = User(
            email=email,
            password_hash=get_password_hash("Password123!"),
            name="Policy Tester",
            role="USER",
            account_status="ACTIVE"
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        sid = f"sess_policy_{int(time.time() * 1000)}_{user.id}"
        sess = DbSession(
            id=sid,
            user_id=user.id,
            application=application,
            status="ACTIVE",
            current_risk_level=risk_level
        )
        db_session.add(sess)
        db_session.commit()
        db_session.refresh(sess)

        token = create_access_token(subject=user.id, role=user.role, session_id=sid)
        headers = {"Authorization": f"Bearer {token}"}
        return user, sess, headers
    return _create


# ==============================================================================
# SCENARIO A: Medium-Risk Downgrade Rejection
# ==============================================================================
def test_scenario_a_medium_risk_downgrade_rejection(client: TestClient, db_session: Session, make_user_and_session):
    """
    When a user is enrolled in NeuralTrace and the session is MEDIUM risk (or risk_score 0.30 - 0.64),
    a caller-supplied preferred_factor="OTP" must be ignored / rejected, and GESTURE_PATTERN issued.
    """
    user, sess, headers = make_user_and_session("user_a", risk_level="MEDIUM")

    # Enroll user in NeuralTrace (gesture pattern)
    enroll_res = client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": [0, 1, 2, 4],
        "confirm_pattern": [0, 1, 2, 4]
    })
    assert enroll_res.status_code == 200

    # Direct service call requesting downgrade to OTP at risk_score 0.45
    chal = StepUpService.create_adaptive_challenge(
        session_id=sess.id,
        user_id=user.id,
        db=db_session,
        risk_score=0.45,
        risk_level="MEDIUM",
        preferred_factor="OTP"
    )
    assert chal["challenge_type"] == "GESTURE_PATTERN", "Preferred factor OTP must not downgrade medium-risk challenge"

    # Direct service call with preferred_factor="EMAIL_OTP"
    StepUpService.reset()
    chal_email = StepUpService.create_adaptive_challenge(
        session_id=sess.id,
        user_id=user.id,
        db=db_session,
        risk_score=0.35,
        risk_level="MEDIUM",
        preferred_factor="EMAIL_OTP"
    )
    assert chal_email["challenge_type"] == "GESTURE_PATTERN", "Preferred factor EMAIL_OTP must not downgrade medium-risk challenge"


# ==============================================================================
# SCENARIO B: Medium-Risk Unenrolled Protected Access Denial
# ==============================================================================
def test_scenario_b_medium_risk_unenrolled_protected_access_denial(client: TestClient, db_session: Session, make_user_and_session):
    """
    When a user is NOT enrolled in NeuralTrace and attempts medium-risk verification for a protected
    vault operation (e.g. financial_vault, academic_vault), the system must fail closed with HTTP 409
    Conflict and must NOT silently issue an OTP challenge.
    """
    user, sess, headers = make_user_and_session("user_b", application="shopping", risk_level="MEDIUM")

    # 1. Direct service call requesting protected financial_vault access without NeuralTrace
    with pytest.raises(HTTPException) as exc_info:
        StepUpService.create_adaptive_challenge(
            session_id=sess.id,
            user_id=user.id,
            db=db_session,
            risk_score=0.45,
            risk_level="MEDIUM",
            resource="financial_vault"
        )
    assert exc_info.value.status_code == 409
    assert NEURALTRACE_NOT_ENROLLED_DETAIL in exc_info.value.detail

    # 2. Direct service call requesting academic_vault
    with pytest.raises(HTTPException) as exc_academic:
        StepUpService.create_adaptive_challenge(
            session_id=sess.id,
            user_id=user.id,
            db=db_session,
            risk_score=0.50,
            risk_level="MEDIUM",
            resource="academic_vault"
        )
    assert exc_academic.value.status_code == 409

    # 3. API endpoint call requesting protected vault
    res_api = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": sess.id,
        "resource": "financial_vault"
    })
    assert res_api.status_code == 409
    assert "NeuralTrace" in res_api.json()["detail"]


# ==============================================================================
# SCENARIO C: High-Risk Compound Cognitive Enforcement
# ==============================================================================
def test_scenario_c_high_risk_compound_cognitive_enforcement(client: TestClient, db_session: Session, make_user_and_session):
    """
    When risk is HIGH (risk_score >= 0.65 or risk_level="HIGH"), compound cognitive verification
    (HIGH_RISK_DUAL) is strictly required. Caller preferences (OTP, GESTURE_PATTERN) cannot weaken it.
    """
    user, sess, headers = make_user_and_session("user_c", risk_level="HIGH")

    # 1. When cognitive factors are not yet enrolled -> must raise 409 Conflict
    with pytest.raises(HTTPException) as exc_info:
        StepUpService.create_adaptive_challenge(
            session_id=sess.id,
            user_id=user.id,
            db=db_session,
            risk_score=0.75,
            risk_level="HIGH",
            preferred_factor="OTP"
        )
    assert exc_info.value.status_code == 409
    assert "both Cognitive Image Sequence and Private Security Response" in exc_info.value.detail

    # 2. Enroll both required cognitive factors
    client.post("/api/security/adaptive/enroll/image-sequence", headers=headers, json={
        "image_sequence": ["img_shield", "img_vault", "img_token"],
        "confirm_image_sequence": ["img_shield", "img_vault", "img_token"]
    })
    client.post("/api/security/adaptive/enroll/private-response", headers=headers, json={
        "question": "What is the secret word?",
        "response": "Excalibur99",
        "confirm_response": "Excalibur99"
    })

    # 3. Caller sends preferred_factor="OTP" -> MUST still issue HIGH_RISK_DUAL
    chal_otp = StepUpService.create_adaptive_challenge(
        session_id=sess.id,
        user_id=user.id,
        db=db_session,
        risk_score=0.75,
        risk_level="HIGH",
        preferred_factor="OTP"
    )
    assert chal_otp["challenge_type"] == "HIGH_RISK_DUAL"

    # 4. Caller sends preferred_factor="GESTURE_PATTERN" -> MUST still issue HIGH_RISK_DUAL
    StepUpService.reset()
    chal_gest = StepUpService.create_adaptive_challenge(
        session_id=sess.id,
        user_id=user.id,
        db=db_session,
        risk_score=0.70,
        risk_level="HIGH",
        preferred_factor="GESTURE_PATTERN"
    )
    assert chal_gest["challenge_type"] == "HIGH_RISK_DUAL"


# ==============================================================================
# SCENARIO D: Critical-Risk Session Termination
# ==============================================================================
def test_scenario_d_critical_risk_session_termination(client: TestClient, db_session: Session, make_user_and_session):
    """
    When risk is CRITICAL (risk_score >= 0.85 or risk_level="CRITICAL"), any attempt to issue
    a challenge must be rejected with HTTP 400 and the session status must be updated to TERMINATED.
    """
    user, sess, headers = make_user_and_session("user_d", risk_level="LOW")
    assert sess.status == "ACTIVE"

    # Caller attempts challenge creation with risk_score = 0.88
    with pytest.raises(HTTPException) as exc_info:
        StepUpService.create_adaptive_challenge(
            session_id=sess.id,
            user_id=user.id,
            db=db_session,
            risk_score=0.88,
            risk_level="LOW",  # Client attempts to send "LOW" string to mask 0.88 score
            preferred_factor="OTP"
        )
    assert exc_info.value.status_code == 400
    assert "Session terminated due to critical security risk" in exc_info.value.detail

    # Verify session is terminated in database
    db_session.refresh(sess)
    assert sess.status == "TERMINATED"


# ==============================================================================
# SCENARIO E: Risk Boundary Float Tests
# ==============================================================================
def test_scenario_e_canonical_classifier_boundary_floats():
    """
    Verifies canonical classifier at exact boundary floats:
    0.299999 -> LOW
    0.300000 -> MEDIUM
    0.300001 -> MEDIUM
    0.649999 -> MEDIUM
    0.650000 -> HIGH
    0.650001 -> HIGH
    0.849999 -> HIGH
    0.850000 -> CRITICAL
    0.850001 -> CRITICAL
    """
    assert RiskService.classify_risk_level(0.299999) == "LOW"
    assert RiskService.classify_risk_level(0.300000) == "MEDIUM"
    assert RiskService.classify_risk_level(0.300001) == "MEDIUM"

    assert RiskService.classify_risk_level(0.649999) == "MEDIUM"
    assert RiskService.classify_risk_level(0.650000) == "HIGH"
    assert RiskService.classify_risk_level(0.650001) == "HIGH"

    assert RiskService.classify_risk_level(0.849999) == "HIGH"
    assert RiskService.classify_risk_level(0.850000) == "CRITICAL"
    assert RiskService.classify_risk_level(0.850001) == "CRITICAL"


def test_scenario_e_step_up_service_boundary_floats(client: TestClient, db_session: Session, make_user_and_session):
    """
    Verifies step_up_service challenge generation at exact boundary floats for an enrolled user.
    """
    user, sess, headers = make_user_and_session("user_e", risk_level="LOW")

    # Enroll user in all factors (gesture, image-sequence, private-response)
    client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": [0, 1, 2, 4], "confirm_pattern": [0, 1, 2, 4]
    })
    client.post("/api/security/adaptive/enroll/image-sequence", headers=headers, json={
        "image_sequence": ["img_shield", "img_vault", "img_token"],
        "confirm_image_sequence": ["img_shield", "img_vault", "img_token"]
    })
    client.post("/api/security/adaptive/enroll/private-response", headers=headers, json={
        "question": "Security question?", "response": "CorrectAnswer", "confirm_response": "CorrectAnswer"
    })

    # 0.299999 -> LOW tier -> OTP
    StepUpService.reset()
    c_low = StepUpService.create_adaptive_challenge(sess.id, user.id, db_session, risk_score=0.299999, risk_level=None)
    assert c_low["challenge_type"] == "OTP"

    # 0.300000 -> MEDIUM tier -> GESTURE_PATTERN
    StepUpService.reset()
    c_med_exact = StepUpService.create_adaptive_challenge(sess.id, user.id, db_session, risk_score=0.300000, risk_level=None)
    assert c_med_exact["challenge_type"] == "GESTURE_PATTERN"

    # 0.300001 -> MEDIUM tier -> GESTURE_PATTERN
    StepUpService.reset()
    c_med_above = StepUpService.create_adaptive_challenge(sess.id, user.id, db_session, risk_score=0.300001, risk_level=None)
    assert c_med_above["challenge_type"] == "GESTURE_PATTERN"

    # 0.649999 -> MEDIUM tier -> GESTURE_PATTERN
    StepUpService.reset()
    c_med_upper = StepUpService.create_adaptive_challenge(sess.id, user.id, db_session, risk_score=0.649999, risk_level=None)
    assert c_med_upper["challenge_type"] == "GESTURE_PATTERN"

    # 0.650000 -> HIGH tier -> HIGH_RISK_DUAL
    StepUpService.reset()
    c_high_exact = StepUpService.create_adaptive_challenge(sess.id, user.id, db_session, risk_score=0.650000, risk_level=None)
    assert c_high_exact["challenge_type"] == "HIGH_RISK_DUAL"

    # 0.650001 -> HIGH tier -> HIGH_RISK_DUAL
    StepUpService.reset()
    c_high_above = StepUpService.create_adaptive_challenge(sess.id, user.id, db_session, risk_score=0.650001, risk_level=None)
    assert c_high_above["challenge_type"] == "HIGH_RISK_DUAL"

    # 0.849999 -> HIGH tier -> HIGH_RISK_DUAL
    StepUpService.reset()
    c_high_upper = StepUpService.create_adaptive_challenge(sess.id, user.id, db_session, risk_score=0.849999, risk_level=None)
    assert c_high_upper["challenge_type"] == "HIGH_RISK_DUAL"

    # 0.850000 -> CRITICAL tier -> HTTP 400
    StepUpService.reset()
    with pytest.raises(HTTPException) as exc_crit:
        StepUpService.create_adaptive_challenge(sess.id, user.id, db_session, risk_score=0.850000, risk_level=None)
    assert exc_crit.value.status_code == 400

    # 0.850001 -> CRITICAL tier -> HTTP 400
    StepUpService.reset()
    with pytest.raises(HTTPException) as exc_crit2:
        StepUpService.create_adaptive_challenge(sess.id, user.id, db_session, risk_score=0.850001, risk_level=None)
    assert exc_crit2.value.status_code == 400


# ==============================================================================
# SCENARIO F: Missing risk_level Parameter
# ==============================================================================
def test_scenario_f_missing_risk_level_parameter(client: TestClient, db_session: Session, make_user_and_session):
    """
    When risk_level is None, the system relies strictly on canonical classification of risk_score:
    0.20 -> LOW
    0.40 -> MEDIUM
    0.70 -> HIGH
    0.90 -> CRITICAL
    """
    assert RiskService.classify_risk_level(0.20) == "LOW"
    assert RiskService.classify_risk_level(0.40) == "MEDIUM"
    assert RiskService.classify_risk_level(0.70) == "HIGH"
    assert RiskService.classify_risk_level(0.90) == "CRITICAL"

    user, sess, headers = make_user_and_session("user_f", risk_level=None)
    client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": [0, 1, 2, 4], "confirm_pattern": [0, 1, 2, 4]
    })
    client.post("/api/security/adaptive/enroll/image-sequence", headers=headers, json={
        "image_sequence": ["img_shield", "img_vault", "img_token"],
        "confirm_image_sequence": ["img_shield", "img_vault", "img_token"]
    })
    client.post("/api/security/adaptive/enroll/private-response", headers=headers, json={
        "question": "Question?", "response": "Answer", "confirm_response": "Answer"
    })

    # 0.20 -> LOW -> OTP
    StepUpService.reset()
    c20 = StepUpService.create_adaptive_challenge(sess.id, user.id, db_session, risk_score=0.20, risk_level=None)
    assert c20["challenge_type"] == "OTP"

    # 0.40 -> MEDIUM -> GESTURE_PATTERN
    StepUpService.reset()
    c40 = StepUpService.create_adaptive_challenge(sess.id, user.id, db_session, risk_score=0.40, risk_level=None)
    assert c40["challenge_type"] == "GESTURE_PATTERN"

    # 0.70 -> HIGH -> HIGH_RISK_DUAL
    StepUpService.reset()
    c70 = StepUpService.create_adaptive_challenge(sess.id, user.id, db_session, risk_score=0.70, risk_level=None)
    assert c70["challenge_type"] == "HIGH_RISK_DUAL"

    # 0.90 -> CRITICAL -> 400
    StepUpService.reset()
    with pytest.raises(HTTPException) as exc:
        StepUpService.create_adaptive_challenge(sess.id, user.id, db_session, risk_score=0.90, risk_level=None)
    assert exc.value.status_code == 400


# ==============================================================================
# SCENARIO G: API-Level Downgrade via Direct Manipulation
# ==============================================================================
def test_scenario_g_api_level_downgrade_direct_manipulation(client: TestClient, db_session: Session, make_user_and_session):
    """
    Direct HTTP POST requests to /api/security/step-up/challenge attempting to manipulate
    preferred_factor="OTP" on a medium-risk session with enrolled NeuralTrace must be rejected / overridden.
    """
    user, sess, headers = make_user_and_session("user_g", risk_level="MEDIUM")

    # Enroll user in NeuralTrace
    client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": [0, 1, 2, 4], "confirm_pattern": [0, 1, 2, 4]
    })

    # 1. API request attempting preferred_factor="OTP"
    res_otp = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": sess.id,
        "preferred_factor": "OTP"
    })
    assert res_otp.status_code == 200
    assert res_otp.json()["challenge_type"] == "GESTURE_PATTERN", "API must enforce GESTURE_PATTERN and block OTP downgrade"

    # 2. API request attempting preferred_factor="EMAIL_OTP"
    StepUpService.reset()
    res_email_otp = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": sess.id,
        "preferred_factor": "EMAIL_OTP"
    })
    assert res_email_otp.status_code == 200
    assert res_email_otp.json()["challenge_type"] == "GESTURE_PATTERN", "API must enforce GESTURE_PATTERN and block EMAIL_OTP downgrade"

