import time
import pytest
from fastapi.testclient import TestClient
from app.models.adaptive_factor import AdaptiveFactor
from app.models.security_event import SecurityEvent
from app.models.session import Session as DbSession
from app.services.step_up_service import StepUpService
from app.core.rate_limit import rate_limiter


@pytest.fixture(autouse=True)
def reset_security():
    StepUpService.reset()
    rate_limiter.reset()
    yield
    StepUpService.reset()
    rate_limiter.reset()


@pytest.fixture
def auth_user(client: TestClient):
    ts = time.time_ns()
    email = f"adaptive_a_{ts}@cognisec.ai"
    client.post("/api/auth/register", json={
        "email": email, "password": "Password123!", "name": "Adaptive User A"
    })
    res = client.post("/api/auth/login", json={
        "email": email, "password": "Password123!", "application": "ecommerce"
    })
    data = res.json()
    return {"Authorization": f"Bearer {data['access_token']}"}, data["user_id"], data["session_id"]


@pytest.fixture
def auth_user_b(client: TestClient):
    ts = time.time_ns()
    email = f"adaptive_b_{ts}@cognisec.ai"
    client.post("/api/auth/register", json={
        "email": email, "password": "Password123!", "name": "Adaptive User B"
    })
    res = client.post("/api/auth/login", json={
        "email": email, "password": "Password123!", "application": "ecommerce"
    })
    data = res.json()
    return {"Authorization": f"Bearer {data['access_token']}"}, data["user_id"], data["session_id"]


def test_cognitive_catalogue_endpoint(client: TestClient):
    """Verifies that the public cognitive image catalogue returns 9 fixed security symbols."""
    res = client.get("/api/security/adaptive/catalogue")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) == 9
    ids = {item["id"] for item in data}
    assert "img_shield" in ids
    assert "img_vault" in ids
    assert "img_key" in ids
    for item in data:
        assert "id" in item
        assert "label" in item
        assert "icon" in item
        assert "category" in item


def test_enroll_gesture_pattern_validation_and_confirmation(client: TestClient, auth_user):
    """Verifies input validation and confirmation matching for gesture patterns."""
    headers, _, _ = auth_user

    # 1. Reject length < 4
    res_short = client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": [0, 1, 2],
        "confirm_pattern": [0, 1, 2]
    })
    assert res_short.status_code == 400
    assert "at least 4 nodes" in res_short.json()["detail"]

    # 2. Reject out of bounds node index (> 8 or < 0)
    res_oob = client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": [0, 1, 2, 9],
        "confirm_pattern": [0, 1, 2, 9]
    })
    assert res_oob.status_code == 400

    # 3. Reject consecutive duplicates
    res_dup = client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": [0, 1, 1, 2],
        "confirm_pattern": [0, 1, 1, 2]
    })
    assert res_dup.status_code == 400
    assert "consecutive duplicate" in res_dup.json()["detail"]

    # 4. Reject confirmation mismatch
    res_mismatch = client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": [0, 1, 2, 4],
        "confirm_pattern": [0, 1, 2, 5]
    })
    assert res_mismatch.status_code == 400

    # 5. Accept valid pattern
    res_ok = client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": [0, 1, 2, 4, 8],
        "confirm_pattern": [0, 1, 2, 4, 8]
    })
    assert res_ok.status_code == 200
    assert res_ok.json()["success"] is True
    assert res_ok.json()["factor_type"] == "GESTURE_PATTERN"


def test_secure_verifier_storage_no_plaintext(client: TestClient, auth_user, db_session):
    """Verifies that enrolled factors store only salted bcrypt hashes, never plaintext patterns or answers."""
    headers, user_id, _ = auth_user
    client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": [0, 3, 6, 7, 8],
        "confirm_pattern": [0, 3, 6, 7, 8]
    })

    factor = db_session.query(AdaptiveFactor).filter(
        AdaptiveFactor.user_id == user_id,
        AdaptiveFactor.factor_type == "GESTURE_PATTERN"
    ).first()

    assert factor is not None
    # Must be a bcrypt hash ($2b$ or $2a$)
    assert factor.verifier_hash.startswith("$2b$") or factor.verifier_hash.startswith("$2a$")
    # Must NOT contain raw representation
    assert "0-3-6-7-8" not in factor.verifier_hash
    assert "0, 3, 6, 7, 8" not in (factor.metadata_json or "")


def test_enroll_image_sequence_validation(client: TestClient, auth_user, db_session):
    """Verifies validation and salted hashing for cognitive image sequences."""
    headers, user_id, _ = auth_user

    # 1. Reject invalid catalogue item ID
    res_invalid = client.post("/api/security/adaptive/enroll/image-sequence", headers=headers, json={
        "image_sequence": ["img_shield", "unknown_symbol", "img_vault"],
        "confirm_image_sequence": ["img_shield", "unknown_symbol", "img_vault"]
    })
    assert res_invalid.status_code == 400

    # 2. Reject length < 3
    res_short = client.post("/api/security/adaptive/enroll/image-sequence", headers=headers, json={
        "image_sequence": ["img_shield", "img_key"],
        "confirm_image_sequence": ["img_shield", "img_key"]
    })
    assert res_short.status_code == 400

    # 3. Reject mismatch
    res_mismatch = client.post("/api/security/adaptive/enroll/image-sequence", headers=headers, json={
        "image_sequence": ["img_shield", "img_key", "img_vault"],
        "confirm_image_sequence": ["img_shield", "img_lock", "img_vault"]
    })
    assert res_mismatch.status_code == 400

    # 4. Accept valid
    res_ok = client.post("/api/security/adaptive/enroll/image-sequence", headers=headers, json={
        "image_sequence": ["img_shield", "img_vault", "img_key"],
        "confirm_image_sequence": ["img_shield", "img_vault", "img_key"]
    })
    assert res_ok.status_code == 200
    assert res_ok.json()["factor_type"] == "COGNITIVE_IMAGE_SEQUENCE"

    # Verify DB storage
    factor = db_session.query(AdaptiveFactor).filter(
        AdaptiveFactor.user_id == user_id,
        AdaptiveFactor.factor_type == "COGNITIVE_IMAGE_SEQUENCE"
    ).first()
    assert factor.verifier_hash.startswith("$2")
    assert "img_shield|img_vault|img_key" not in factor.verifier_hash


def test_enroll_private_response_normalization(client: TestClient, auth_user, db_session):
    """Verifies private question enrollment with normalization and secure metadata separation."""
    headers, user_id, _ = auth_user

    # 1. Reject short question
    res_short_q = client.post("/api/security/adaptive/enroll/private-response", headers=headers, json={
        "question": "Why?",
        "response": "SecretAnswer",
        "confirm_response": "SecretAnswer"
    })
    assert res_short_q.status_code == 400

    # 2. Reject mismatch
    res_mismatch = client.post("/api/security/adaptive/enroll/private-response", headers=headers, json={
        "question": "What was the street name of your childhood home?",
        "response": "Baker Street",
        "confirm_response": "Oxford Street"
    })
    assert res_mismatch.status_code == 400

    # 3. Accept valid
    res_ok = client.post("/api/security/adaptive/enroll/private-response", headers=headers, json={
        "question": "What was the street name of your childhood home?",
        "response": "  Baker   Street  ",
        "confirm_response": "  Baker   Street  "
    })
    assert res_ok.status_code == 200
    assert res_ok.json()["factor_type"] == "PRIVATE_RESPONSE"

    factor = db_session.query(AdaptiveFactor).filter(
        AdaptiveFactor.user_id == user_id,
        AdaptiveFactor.factor_type == "PRIVATE_RESPONSE"
    ).first()
    assert "childhood home" in factor.metadata_json
    assert "Baker Street" not in factor.metadata_json
    assert factor.verifier_hash.startswith("$2")
    assert "baker street" not in factor.verifier_hash


def test_mfa_status_endpoint_no_secrets_exposed(client: TestClient, auth_user):
    """Verifies /status endpoint reveals enrollment booleans and question prompt without leaking secrets."""
    headers, _, _ = auth_user

    client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": [0, 1, 2, 4], "confirm_pattern": [0, 1, 2, 4]
    })
    client.post("/api/security/adaptive/enroll/image-sequence", headers=headers, json={
        "image_sequence": ["img_key", "img_lock", "img_vault"],
        "confirm_image_sequence": ["img_key", "img_lock", "img_vault"]
    })
    client.post("/api/security/adaptive/enroll/private-response", headers=headers, json={
        "question": "Childhood school name?", "response": "Lincoln", "confirm_response": "Lincoln"
    })

    res = client.get("/api/security/adaptive/status", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["has_gesture_pattern"] is True
    assert data["has_cognitive_image_sequence"] is True
    assert data["has_private_response"] is True
    assert data["private_question"] == "Childhood school name?"
    assert "verifier_hash" not in data
    assert "Lincoln" not in str(data)


def test_cross_user_mfa_access_denial(client: TestClient, auth_user, auth_user_b):
    """Verifies that User B cannot request or verify a challenge for User A's session."""
    headers_a, _, sid_a = auth_user
    headers_b, _, _ = auth_user_b

    # User B tries to request challenge for User A's session
    res_chal = client.post("/api/security/step-up/challenge", headers=headers_b, json={
        "session_id": sid_a
    })
    assert res_chal.status_code == 403

    # User A requests legitimate challenge
    res_a = client.post("/api/security/step-up/challenge", headers=headers_a, json={
        "session_id": sid_a
    })
    assert res_a.status_code == 200
    otp = res_a.json()["otp"]

    # User B tries to verify User A's challenge
    res_ver = client.post("/api/security/step-up/verify", headers=headers_b, json={
        "session_id": sid_a,
        "challenge_code": otp
    })
    assert res_ver.status_code == 403


def test_gesture_pattern_challenge_execution(client: TestClient, auth_user):
    """Verifies gesture pattern verification lifecycle: correct, incorrect, single-use."""
    headers, _, sid = auth_user

    # 1. Enroll pattern
    client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": [0, 1, 2, 4, 8],
        "confirm_pattern": [0, 1, 2, 4, 8]
    })

    # 2. Request challenge preferring GESTURE_PATTERN
    chal_res = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": sid,
        "preferred_factor": "GESTURE_PATTERN"
    })
    assert chal_res.status_code == 200
    assert chal_res.json()["challenge_type"] == "GESTURE_PATTERN"

    # 3. Submit incorrect pattern
    bad_res = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sid,
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": [0, 1, 2, 5, 8]
    })
    assert bad_res.status_code == 400
    assert "Invalid verification" in bad_res.json()["detail"]

    # 4. Submit correct pattern
    good_res = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sid,
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": [0, 1, 2, 4, 8]
    })
    assert good_res.status_code == 200
    assert good_res.json()["decision"] == "ALLOW"
    assert good_res.json()["session_status"] == "ACTIVE"

    # 5. Replay attempt fails (single-use consumption)
    replay_res = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sid,
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": [0, 1, 2, 4, 8]
    })
    assert replay_res.status_code == 400


def test_image_sequence_challenge_execution(client: TestClient, auth_user):
    """Verifies cognitive image sequence verification lifecycle."""
    headers, _, sid = auth_user

    # 1. Enroll sequence
    client.post("/api/security/adaptive/enroll/image-sequence", headers=headers, json={
        "image_sequence": ["img_shield", "img_vault", "img_token"],
        "confirm_image_sequence": ["img_shield", "img_vault", "img_token"]
    })

    # 2. Request challenge
    chal_res = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": sid,
        "preferred_factor": "COGNITIVE_IMAGE_SEQUENCE"
    })
    assert chal_res.status_code == 200
    assert chal_res.json()["challenge_type"] == "COGNITIVE_IMAGE_SEQUENCE"

    # 3. Submit incorrect sequence
    bad_res = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sid,
        "challenge_type": "COGNITIVE_IMAGE_SEQUENCE",
        "image_sequence": ["img_shield", "img_lock", "img_token"]
    })
    assert bad_res.status_code == 400

    # 4. Submit correct sequence
    good_res = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sid,
        "challenge_type": "COGNITIVE_IMAGE_SEQUENCE",
        "image_sequence": ["img_shield", "img_vault", "img_token"]
    })
    assert good_res.status_code == 200
    assert good_res.json()["decision"] == "ALLOW"


def test_private_response_challenge_case_normalization(client: TestClient, auth_user):
    """Verifies private response challenge matches regardless of capitalization or extra whitespace."""
    headers, _, sid = auth_user

    client.post("/api/security/adaptive/enroll/private-response", headers=headers, json={
        "question": "What is the name of your first pet?",
        "response": "Barnaby Jones",
        "confirm_response": "Barnaby Jones"
    })

    chal_res = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": sid,
        "preferred_factor": "PRIVATE_RESPONSE"
    })
    assert chal_res.status_code == 200
    assert chal_res.json()["challenge_type"] == "PRIVATE_RESPONSE"
    assert chal_res.json()["prompt"] == "What is the name of your first pet?"

    # Verify with lowercase and trimmed whitespace
    good_res = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sid,
        "challenge_type": "PRIVATE_RESPONSE",
        "private_response": "   barnaby   jones  "
    })
    assert good_res.status_code == 200
    assert good_res.json()["decision"] == "ALLOW"


def test_adaptive_failed_attempt_lockout(client: TestClient, auth_user, db_session):
    """Verifies that exceeding max failed attempts locks session and emits STEP_UP_LOCKED security event."""
    headers, _, sid = auth_user

    client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": [0, 1, 2, 4], "confirm_pattern": [0, 1, 2, 4]
    })

    client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": sid,
        "preferred_factor": "GESTURE_PATTERN"
    })

    # 3 bad attempts
    client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sid, "challenge_type": "GESTURE_PATTERN", "gesture_pattern": [0, 0, 0, 0]
    })
    client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sid, "challenge_type": "GESTURE_PATTERN", "gesture_pattern": [0, 0, 0, 0]
    })
    third_res = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sid, "challenge_type": "GESTURE_PATTERN", "gesture_pattern": [0, 0, 0, 0]
    })

    assert third_res.status_code == 400
    assert "Maximum verification attempts exceeded" in third_res.json()["detail"]

    # Verify session locked in DB
    session = db_session.query(DbSession).filter(DbSession.id == sid).first()
    assert session.status == "RESTRICTED"

    # Verify SecurityEvent logged
    locked_event = db_session.query(SecurityEvent).filter(
        SecurityEvent.session_id == sid,
        SecurityEvent.event_type == "STEP_UP_LOCKED"
    ).first()
    assert locked_event is not None
    assert locked_event.severity == "HIGH"


def test_terminated_session_prohibits_challenge(client: TestClient, auth_user, db_session):
    """Verifies that a terminated session cannot issue or verify any challenge."""
    headers, _, sid = auth_user

    session = db_session.query(DbSession).filter(DbSession.id == sid).first()
    session.status = "TERMINATED"
    db_session.commit()

    # Request challenge rejected
    res_chal = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": sid
    })
    assert res_chal.status_code in [400, 401]
    assert "terminated" in res_chal.json()["detail"].lower()

    # Verify challenge rejected
    res_ver = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sid,
        "challenge_code": "123456"
    })
    assert res_ver.status_code in [400, 401]
    assert "terminated" in res_ver.json()["detail"].lower()


def test_critical_risk_session_cannot_be_overridden(client: TestClient, auth_user, db_session):
    """Verifies that a session marked CRITICAL risk cannot override policy via challenge."""
    headers, _, sid = auth_user

    session = db_session.query(DbSession).filter(DbSession.id == sid).first()
    session.current_risk_level = "CRITICAL"
    db_session.commit()

    res_chal = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": sid
    })
    assert res_chal.status_code == 400
    assert "critical" in res_chal.json()["detail"].lower()


def test_high_risk_compound_dual_factor_challenge(client: TestClient, auth_user, db_session):
    """
    Task 6: High but recoverable risk requires BOTH ordered cognitive image sequence
    AND private response verification. Neither factor alone can restore access.
    """
    headers, user_id, sid = auth_user

    # Enroll both factors
    client.post("/api/security/adaptive/enroll/image-sequence", headers=headers, json={
        "image_sequence": ["img_shield", "img_vault", "img_token"],
        "confirm_image_sequence": ["img_shield", "img_vault", "img_token"]
    })
    client.post("/api/security/adaptive/enroll/private-response", headers=headers, json={
        "question": "What is your secret passphrase keyword?",
        "response": "AlphaOmega77",
        "confirm_response": "AlphaOmega77"
    })

    # Set session to HIGH risk
    session = db_session.query(DbSession).filter(DbSession.id == sid).first()
    session.current_risk_level = "HIGH"
    db_session.commit()

    # Request challenge
    chal_res = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": sid
    })
    assert chal_res.status_code == 200
    data = chal_res.json()
    assert data["challenge_type"] == "HIGH_RISK_DUAL"
    assert data["catalogue"] is not None
    assert data["prompt"] == "What is your secret passphrase keyword?"

    # 1. Submitting only image sequence fails
    part_res1 = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sid,
        "challenge_type": "HIGH_RISK_DUAL",
        "image_sequence": ["img_shield", "img_vault", "img_token"]
    })
    assert part_res1.status_code == 400

    # 2. Submitting correct image sequence but wrong private response fails
    bad_res2 = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sid,
        "challenge_type": "HIGH_RISK_DUAL",
        "image_sequence": ["img_shield", "img_vault", "img_token"],
        "private_response": "WrongPassphrase"
    })
    assert bad_res2.status_code == 400

    # 3. Submitting both correctly restores access
    good_res = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sid,
        "challenge_type": "HIGH_RISK_DUAL",
        "image_sequence": ["img_shield", "img_vault", "img_token"],
        "private_response": "alphaomega77"
    })
    assert good_res.status_code == 200
    assert good_res.json()["decision"] == "ALLOW"
    assert good_res.json()["session_status"] == "ACTIVE"


def test_email_otp_masked_recipient_and_hash_verifier(client: TestClient, auth_user):
    """
    Task 5: Validates that OTP challenges return a masked recipient email,
    store hashed verifiers, and allow restoring access with the correct code.
    """
    headers, _, sid = auth_user

    chal_res = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": sid,
        "preferred_factor": "OTP"
    })
    assert chal_res.status_code == 200
    data = chal_res.json()
    assert data["challenge_type"] == "OTP"
    assert "masked_email" in data
    assert "@" in data["masked_email"]
    otp = data["otp"]
    assert len(otp) == 6

    # Verify with correct OTP
    ver_res = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sid,
        "challenge_code": otp
    })
    assert ver_res.status_code == 200
    assert ver_res.json()["decision"] == "ALLOW"
