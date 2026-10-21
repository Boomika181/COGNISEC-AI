"""
CogniSec-AI Step 3 Test Suite: Cognitive Factor Enrollment Verification
Tests:
1. Successful image-sequence enrollment.
2. Invalid sequence length, invalid symbol IDs, and duplicate selections.
3. Mismatched sequence confirmation.
4. Successful private-response enrollment.
5. Mismatched private-response confirmation.
6. Unauthenticated enrollment denial.
7. Cross-user enrollment isolation.
8. Enrollment status without verifier leakage.
9. Password-hash storage and response normalization.
10. Existing NeuralTrace and OTP behavior remaining unchanged.
11. Enrollment alone never creates an application grant or unlocks a portal.
"""

import time
import json
import bcrypt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.adaptive_factor import AdaptiveFactor
from app.models.application_grant import ApplicationGrant
from app.models.session import Session as DbSession
from app.services.step_up_service import StepUpService
from app.core.rate_limit import rate_limiter


@pytest.fixture(autouse=True)
def reset_security_environment():
    StepUpService.reset()
    rate_limiter.reset()
    yield
    StepUpService.reset()
    rate_limiter.reset()


@pytest.fixture
def auth_user_1(client: TestClient):
    ts = time.time_ns()
    email = f"cogni_user1_{ts}@cognisec.ai"
    client.post("/api/auth/register", json={
        "email": email, "password": "Password123!", "name": "Cognitive User 1"
    })
    res = client.post("/api/auth/login", json={
        "email": email, "password": "Password123!", "application": "college"
    })
    data = res.json()
    return {"Authorization": f"Bearer {data['access_token']}"}, data["user_id"], data["session_id"]


@pytest.fixture
def auth_user_2(client: TestClient):
    ts = time.time_ns()
    email = f"cogni_user2_{ts}@cognisec.ai"
    client.post("/api/auth/register", json={
        "email": email, "password": "Password123!", "name": "Cognitive User 2"
    })
    res = client.post("/api/auth/login", json={
        "email": email, "password": "Password123!", "application": "ecommerce"
    })
    data = res.json()
    return {"Authorization": f"Bearer {data['access_token']}"}, data["user_id"], data["session_id"]


def test_1_successful_image_sequence_enrollment(client: TestClient, auth_user_1, db_session: Session):
    """
    1. Successful image-sequence enrollment:
    - User submits 3-5 approved symbols from catalogue with exact confirmation.
    - Server responds with 200 OK and success=True.
    - Verifier is stored as a salted bcrypt hash, never in plaintext.
    """
    headers, user_id, _ = auth_user_1
    sequence = ["img_shield", "img_vault", "img_key"]

    res = client.post("/api/security/adaptive/enroll/image-sequence", headers=headers, json={
        "image_sequence": sequence,
        "confirm_image_sequence": sequence
    })
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["factor_type"] == "COGNITIVE_IMAGE_SEQUENCE"
    assert "successfully enrolled" in data["message"]

    # Verify DB persistence
    factor = db_session.query(AdaptiveFactor).filter(
        AdaptiveFactor.user_id == user_id,
        AdaptiveFactor.factor_type == "COGNITIVE_IMAGE_SEQUENCE"
    ).first()
    assert factor is not None
    assert factor.verifier_hash.startswith("$2")
    assert "img_shield|img_vault|img_key" not in factor.verifier_hash
    meta = json.loads(factor.metadata_json)
    assert meta["sequence_length"] == 3


def test_2_invalid_sequence_length_or_symbol_ids(client: TestClient, auth_user_1):
    """
    2. Rejection of invalid sequence lengths, catalogue symbols, and duplicates:
    - Length < 3 rejected with 400.
    - Length > 5 rejected with 400.
    - Unknown symbol ID rejected with 400.
    - Duplicate symbols in sequence rejected with 400.
    """
    headers, _, _ = auth_user_1

    # Short sequence (2 items)
    res_short = client.post("/api/security/adaptive/enroll/image-sequence", headers=headers, json={
        "image_sequence": ["img_shield", "img_key"],
        "confirm_image_sequence": ["img_shield", "img_key"]
    })
    assert res_short.status_code == 400
    assert "between 3 and 5" in res_short.json()["detail"]

    # Long sequence (6 items)
    res_long = client.post("/api/security/adaptive/enroll/image-sequence", headers=headers, json={
        "image_sequence": ["img_shield", "img_key", "img_lock", "img_radar", "img_vault", "img_token"],
        "confirm_image_sequence": ["img_shield", "img_key", "img_lock", "img_radar", "img_vault", "img_token"]
    })
    assert res_long.status_code == 400
    assert "between 3 and 5" in res_long.json()["detail"]

    # Unknown symbol ID
    res_bad_id = client.post("/api/security/adaptive/enroll/image-sequence", headers=headers, json={
        "image_sequence": ["img_shield", "img_rogue_trojan", "img_key"],
        "confirm_image_sequence": ["img_shield", "img_rogue_trojan", "img_key"]
    })
    assert res_bad_id.status_code == 400
    assert "Invalid image identifier" in res_bad_id.json()["detail"]

    # Duplicate symbols in sequence
    res_dup = client.post("/api/security/adaptive/enroll/image-sequence", headers=headers, json={
        "image_sequence": ["img_shield", "img_shield", "img_key"],
        "confirm_image_sequence": ["img_shield", "img_shield", "img_key"]
    })
    assert res_dup.status_code == 400
    assert "duplicate" in res_dup.json()["detail"].lower()


def test_3_mismatched_sequence_confirmation(client: TestClient, auth_user_1):
    """
    3. Rejection of mismatched sequence confirmation:
    - User submits mismatched confirmation sequence -> 400 Bad Request.
    """
    headers, _, _ = auth_user_1
    res = client.post("/api/security/adaptive/enroll/image-sequence", headers=headers, json={
        "image_sequence": ["img_shield", "img_vault", "img_key"],
        "confirm_image_sequence": ["img_shield", "img_lock", "img_key"]
    })
    assert res.status_code == 400
    assert "confirmation does not match" in res.json()["detail"].lower()


def test_4_successful_private_response_enrollment(client: TestClient, auth_user_1, db_session: Session):
    """
    4. Successful private-response enrollment:
    - Stores prompt in metadata.
    - Stores salted bcrypt hash in verifier_hash.
    - Never stores plaintext answer.
    """
    headers, user_id, _ = auth_user_1
    q = "What was the secret codename of your first neural network project?"
    ans = "Project Bumblebee 2026"

    res = client.post("/api/security/adaptive/enroll/private-response", headers=headers, json={
        "question": q,
        "response": ans,
        "confirm_response": ans
    })
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["factor_type"] == "PRIVATE_RESPONSE"

    factor = db_session.query(AdaptiveFactor).filter(
        AdaptiveFactor.user_id == user_id,
        AdaptiveFactor.factor_type == "PRIVATE_RESPONSE"
    ).first()
    assert factor is not None
    assert factor.verifier_hash.startswith("$2")
    # Verify raw response is NOT in verifier_hash or metadata_json
    assert "Project Bumblebee" not in factor.verifier_hash
    assert "Bumblebee" not in factor.metadata_json
    meta = json.loads(factor.metadata_json)
    assert meta["question"] == q


def test_5_mismatched_private_response_confirmation(client: TestClient, auth_user_1):
    """
    5. Rejection of mismatched private-response confirmation:
    - User submits mismatched answer confirmation -> 400 Bad Request.
    """
    headers, _, _ = auth_user_1
    res = client.post("/api/security/adaptive/enroll/private-response", headers=headers, json={
        "question": "What is your secret offline identity word?",
        "response": "CyberFortress99",
        "confirm_response": "CyberFortress00"
    })
    assert res.status_code == 400
    assert "confirmation does not match" in res.json()["detail"].lower()


def test_6_unauthenticated_enrollment_denial(client: TestClient):
    """
    6. Unauthenticated requests are denied with 401 Unauthorized:
    - Image sequence enrollment without token -> 401.
    - Private response enrollment without token -> 401.
    - Factor status query without token -> 401.
    """
    res_img = client.post("/api/security/adaptive/enroll/image-sequence", json={
        "image_sequence": ["img_shield", "img_vault", "img_key"],
        "confirm_image_sequence": ["img_shield", "img_vault", "img_key"]
    })
    assert res_img.status_code == 401

    res_priv = client.post("/api/security/adaptive/enroll/private-response", json={
        "question": "Valid Question Prompt Here?",
        "response": "ValidResponse",
        "confirm_response": "ValidResponse"
    })
    assert res_priv.status_code == 401

    res_status = client.get("/api/security/adaptive/status")
    assert res_status.status_code == 401


def test_7_cross_user_enrollment_denial(client: TestClient, auth_user_1, auth_user_2, db_session: Session):
    """
    7. Cross-user enrollment isolation:
    - Token binds enrollment exclusively to the authenticated user.
    - User 1's enrollment has zero effect on User 2's factors or status.
    """
    headers_1, uid_1, _ = auth_user_1
    headers_2, uid_2, _ = auth_user_2

    # User 1 enrolls image sequence
    client.post("/api/security/adaptive/enroll/image-sequence", headers=headers_1, json={
        "image_sequence": ["img_shield", "img_vault", "img_key"],
        "confirm_image_sequence": ["img_shield", "img_vault", "img_key"]
    })

    # Verify User 2's status still reports not enrolled
    res_status_2 = client.get("/api/security/adaptive/status", headers=headers_2)
    assert res_status_2.status_code == 200
    data_2 = res_status_2.json()
    assert data_2["user_id"] == uid_2
    assert data_2["has_cognitive_image_sequence"] is False
    assert data_2["has_private_response"] is False

    # Verify User 1's status reports enrolled
    res_status_1 = client.get("/api/security/adaptive/status", headers=headers_1)
    data_1 = res_status_1.json()
    assert data_1["user_id"] == uid_1
    assert data_1["has_cognitive_image_sequence"] is True


def test_8_enrollment_status_without_verifier_leakage(client: TestClient, auth_user_1):
    """
    8. Enrollment status without verifier leakage:
    - Status endpoint exposes booleans and question prompt.
    - Never leaks verifier hash, sequence values, or secret answers.
    """
    headers, _, _ = auth_user_1

    client.post("/api/security/adaptive/enroll/image-sequence", headers=headers, json={
        "image_sequence": ["img_token", "img_chip", "img_firewall"],
        "confirm_image_sequence": ["img_token", "img_chip", "img_firewall"]
    })
    client.post("/api/security/adaptive/enroll/private-response", headers=headers, json={
        "question": "What is the secret test question prompt?",
        "response": "SuperSecretAnswer123",
        "confirm_response": "SuperSecretAnswer123"
    })

    res = client.get("/api/security/adaptive/status", headers=headers)
    assert res.status_code == 200
    data = res.json()
    raw_text = res.text

    assert data["has_cognitive_image_sequence"] is True
    assert data["has_private_response"] is True
    assert data["private_question"] == "What is the secret test question prompt?"

    # Security assertion: No secret or hash leakage
    assert "verifier_hash" not in data
    assert "SuperSecretAnswer123" not in raw_text
    assert "supersecretanswer123" not in raw_text.lower()
    assert "img_token" not in raw_text
    assert "$2b$" not in raw_text


def test_9_password_hash_storage_and_response_normalization(client: TestClient, auth_user_1, db_session: Session):
    """
    9. Password-hash storage and response normalization:
    - Normalizes case, removes leading/trailing spaces, collapses internal multiple spaces.
    - Verified by bcrypt checkpw against normalized form.
    """
    headers, user_id, _ = auth_user_1
    raw_answer = "   Apollo   Eleven   Eagle   "
    expected_normalized = "apollo eleven eagle"

    res = client.post("/api/security/adaptive/enroll/private-response", headers=headers, json={
        "question": "Historical mission lunar module callsign?",
        "response": raw_answer,
        "confirm_response": raw_answer
    })
    assert res.status_code == 200

    factor = db_session.query(AdaptiveFactor).filter(
        AdaptiveFactor.user_id == user_id,
        AdaptiveFactor.factor_type == "PRIVATE_RESPONSE"
    ).first()
    assert factor is not None

    stored_hash = factor.verifier_hash
    assert stored_hash.startswith("$2")

    # Correct normalized string matches bcrypt hash
    assert bcrypt.checkpw(expected_normalized.encode("utf-8"), stored_hash.encode("utf-8")) is True

    # Wrong case or un-normalized raw string without normalization does NOT match bcrypt hash
    assert bcrypt.checkpw(raw_answer.encode("utf-8"), stored_hash.encode("utf-8")) is False
    assert bcrypt.checkpw(b"wrong answer", stored_hash.encode("utf-8")) is False


def test_10_existing_neuraltrace_and_otp_behavior_unchanged(client: TestClient, auth_user_1):
    """
    10. Regression check: NeuralTrace and OTP step-up behaviors remain unchanged:
    - Gesture pattern enrollment still functions with 4+ nodes.
    - Step-up OTP challenge issuance and verification work as expected.
    """
    headers, _, sid = auth_user_1

    # 1. Enroll NeuralTrace route
    res_gest = client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": [0, 1, 2, 4, 8],
        "confirm_pattern": [0, 1, 2, 4, 8]
    })
    assert res_gest.status_code == 200
    assert res_gest.json()["factor_type"] == "GESTURE_PATTERN"

    # 2. Request OTP step-up challenge
    res_chal = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": sid,
        "preferred_factor": "OTP"
    })
    assert res_chal.status_code == 200
    chal_data = res_chal.json()
    assert chal_data["challenge_type"] == "OTP"
    otp = chal_data["otp"]

    # 3. Verify OTP
    res_ver = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sid,
        "challenge_code": otp
    })
    assert res_ver.status_code == 200
    assert res_ver.json()["decision"] == "ALLOW"
    assert res_ver.json()["session_status"] == "ACTIVE"


def test_11_enrollment_alone_never_creates_grant_or_unlocks_portal(client: TestClient, auth_user_1, db_session: Session):
    """
    11. Verification that factor enrollment alone never creates an ApplicationGrant,
    never alters session decision, and never unlocks protected vault resources.
    """
    headers, user_id, sid = auth_user_1

    # Ensure no ApplicationGrant exists prior to enrollment
    pre_grants = db_session.query(ApplicationGrant).filter(
        ApplicationGrant.user_id == user_id
    ).all()
    assert len(pre_grants) == 0

    # Enroll cognitive image sequence
    res_img = client.post("/api/security/adaptive/enroll/image-sequence", headers=headers, json={
        "image_sequence": ["img_shield", "img_vault", "img_key"],
        "confirm_image_sequence": ["img_shield", "img_vault", "img_key"]
    })
    assert res_img.status_code == 200

    # Enroll private response
    res_priv = client.post("/api/security/adaptive/enroll/private-response", headers=headers, json={
        "question": "What is the secret engineering keyword?",
        "response": "QuantumEntanglement",
        "confirm_response": "QuantumEntanglement"
    })
    assert res_priv.status_code == 200

    # Check database: ApplicationGrant count MUST still be 0
    post_grants = db_session.query(ApplicationGrant).filter(
        ApplicationGrant.user_id == user_id
    ).all()
    assert len(post_grants) == 0

    # Check resource access decision for confidential records
    res_access = client.post("/api/security/access-decision", headers=headers, json={
        "session_id": sid,
        "resource": "academic_vault",
        "application": "college"
    })
    assert res_access.status_code == 200
    access_data = res_access.json()
    # Access must NOT be granted merely because the user enrolled factors
    assert access_data["access_granted"] is False
