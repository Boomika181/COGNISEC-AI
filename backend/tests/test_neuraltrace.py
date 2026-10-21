import time
import pytest
from fastapi.testclient import TestClient
from fastapi import status
from sqlalchemy.orm import Session
from app.models.adaptive_factor import AdaptiveFactor
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
    email = f"neuraltrace_a_{ts}@cognisec.ai"
    client.post("/api/auth/register", json={
        "email": email, "password": "Password123!", "name": "Neural Operator A"
    })
    res = client.post("/api/auth/login", json={
        "email": email, "password": "Password123!", "application": "ecommerce"
    })
    data = res.json()
    return {"Authorization": f"Bearer {data['access_token']}"}, data["user_id"], data["session_id"]


def test_neuraltrace_valid_route_enrollment(client: TestClient, auth_user, db_session: Session):
    """
    Verifies that a valid 14-node NeuralTrace constellation route
    can be enrolled successfully and produces a salted bcrypt verifier.
    """
    headers, user_id, _ = auth_user
    valid_route = [0, 4, 8, 12]  # Synapse-0 -> Relay-4 -> Nexus-8 -> Core-12

    res = client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": valid_route,
        "confirm_pattern": valid_route
    })
    assert res.status_code == status.HTTP_200_OK
    data = res.json()
    assert data["success"] is True
    assert data["factor_type"] == "GESTURE_PATTERN"

    # Verify database persistence
    factor = db_session.query(AdaptiveFactor).filter(
        AdaptiveFactor.user_id == user_id,
        AdaptiveFactor.factor_type == "GESTURE_PATTERN"
    ).first()
    assert factor is not None
    assert factor.verifier_hash is not None
    assert factor.verifier_hash.startswith("$2b$") or factor.verifier_hash.startswith("$2a$")
    assert "0-4-8-12" not in factor.verifier_hash


def test_neuraltrace_invalid_edge_rejected(client: TestClient, auth_user):
    """
    Verifies that route traversing non-existent graph edges is rejected with HTTP 400.
    Node 0 and Node 13 are at opposite ends with no direct edge.
    """
    headers, _, _ = auth_user
    invalid_route = [0, 13, 2, 11]

    res = client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": invalid_route,
        "confirm_pattern": invalid_route
    })
    assert res.status_code == status.HTTP_400_BAD_REQUEST
    assert "not connected" in res.json()["detail"].lower()


def test_neuraltrace_out_of_bounds_node_rejected(client: TestClient, auth_user):
    """Verifies that nodes exceeding graph bounds (> 15) are rejected."""
    headers, _, _ = auth_user
    oob_route = [0, 4, 8, 17]

    res = client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": oob_route,
        "confirm_pattern": oob_route
    })
    assert res.status_code == status.HTTP_400_BAD_REQUEST
    assert "invalid node index" in res.json()["detail"].lower()


def test_neuraltrace_duplicate_node_rejected(client: TestClient, auth_user):
    """Verifies that adjacent repeated nodes are rejected."""
    headers, _, _ = auth_user
    dup_route = [0, 4, 4, 8, 12]

    res = client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": dup_route,
        "confirm_pattern": dup_route
    })
    assert res.status_code == status.HTTP_400_BAD_REQUEST
    assert "consecutive duplicate" in res.json()["detail"].lower()


def test_neuraltrace_registration_integration(client: TestClient, db_session: Session):
    """
    Verifies that a user can register while atomically enrolling their NeuralTrace secret route.
    """
    neural_route = [1, 5, 9, 13]  # Synapse-1 -> Relay-5 -> Nexus-9 -> Core-13
    reg_payload = {
        "name": "Neural Trace Operator",
        "email": "operator.neural@cognisec.ai",
        "password": "CyberPassword2026!",
        "gesture_pattern": neural_route,
        "confirm_gesture_pattern": neural_route,
        "image_sequence": ["img_shield", "img_vault", "img_chip"],
        "confirm_image_sequence": ["img_shield", "img_vault", "img_chip"],
        "private_question": "What was the name of your first security mentor?",
        "private_response": "Dr. Turing",
        "confirm_private_response": "Dr. Turing"
    }

    res = client.post("/api/auth/register", json=reg_payload)
    assert res.status_code == status.HTTP_201_CREATED
    user_data = res.json()
    assert user_data["email"] == "operator.neural@cognisec.ai"

    # Login to obtain access token
    login_res = client.post("/api/auth/login", json={
        "email": "operator.neural@cognisec.ai",
        "password": "CyberPassword2026!"
    })
    assert login_res.status_code == status.HTTP_200_OK
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Verify factor is enrolled
    status_res = client.get("/api/security/adaptive/status", headers=headers)
    assert status_res.status_code == status.HTTP_200_OK
    assert status_res.json()["has_gesture_pattern"] is True

    # Standalone factor verification: Correct route succeeds
    verify_res = client.post("/api/security/adaptive/verify/gesture", headers=headers, json={
        "gesture_pattern": neural_route
    })
    assert verify_res.status_code == status.HTTP_200_OK
    assert verify_res.json()["success"] is True

    # Standalone factor verification: Wrong route fails with 401
    wrong_route = [0, 3, 7, 11]
    wrong_res = client.post("/api/security/adaptive/verify/gesture", headers=headers, json={
        "gesture_pattern": wrong_route
    })
    assert wrong_res.status_code == status.HTTP_401_UNAUTHORIZED


def test_neuraltrace_step_up_challenge_verification(client: TestClient, auth_user):
    """
    Tests end-to-end step-up challenge verification using the enrolled NeuralTrace route.
    """
    headers, _, session_id = auth_user
    neural_route = [0, 3, 7, 11]

    # 1. Enroll NeuralTrace route
    enroll_res = client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": neural_route,
        "confirm_pattern": neural_route
    })
    assert enroll_res.status_code == status.HTTP_200_OK

    # 2. Request step-up challenge preferring GESTURE_PATTERN
    chal_res = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": session_id,
        "preferred_factor": "GESTURE_PATTERN"
    })
    assert chal_res.status_code == status.HTTP_200_OK
    challenge = chal_res.json()
    assert challenge["challenge_type"] == "GESTURE_PATTERN"

    # 3. Wrong route submission fails
    wrong_verify = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": [1, 5, 9, 13]
    })
    assert wrong_verify.status_code == status.HTTP_400_BAD_REQUEST

    # 4. Correct route submission succeeds and closes challenge
    correct_verify = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": neural_route
    })
    assert correct_verify.status_code == status.HTTP_200_OK
    assert correct_verify.json()["decision"] == "ALLOW"
    assert correct_verify.json()["session_status"] == "ACTIVE"

    # 5. Replaying challenge fails (single-use consumption)
    replay_verify = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": neural_route
    })
    assert replay_verify.status_code == status.HTTP_400_BAD_REQUEST


@pytest.fixture
def auth_user_b(client: TestClient):
    ts = time.time_ns()
    email = f"neuraltrace_b_{ts}@cognisec.ai"
    client.post("/api/auth/register", json={
        "email": email, "password": "Password123!", "name": "Neural Operator B"
    })
    res = client.post("/api/auth/login", json={
        "email": email, "password": "Password123!", "application": "ecommerce"
    })
    data = res.json()
    return {"Authorization": f"Bearer {data['access_token']}"}, data["user_id"], data["session_id"]


def test_neuraltrace_confirmation_mismatch_rejected(client: TestClient, auth_user):
    """Verifies that enrollment with mismatched confirmation route fails."""
    headers, _, _ = auth_user
    res = client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": [0, 4, 8, 12],
        "confirm_pattern": [0, 3, 7, 11]
    })
    assert res.status_code == status.HTTP_400_BAD_REQUEST
    assert "match" in res.json()["detail"].lower()


def test_neuraltrace_insufficient_complexity_rejected(client: TestClient, auth_user):
    """Verifies that routes with fewer than 4 nodes are rejected."""
    headers, _, _ = auth_user
    res = client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": [0, 4, 8],
        "confirm_pattern": [0, 4, 8]
    })
    assert res.status_code == status.HTTP_400_BAD_REQUEST
    assert "at least 4" in res.json()["detail"].lower()


def test_neuraltrace_cross_account_verification_denial(client: TestClient, auth_user, auth_user_b):
    """Verifies that User B cannot request challenge or verify for User A's session."""
    headers_a, _, sid_a = auth_user
    headers_b, _, _ = auth_user_b

    # User A enrolls route
    client.post("/api/security/adaptive/enroll/gesture", headers=headers_a, json={
        "pattern": [0, 4, 8, 12],
        "confirm_pattern": [0, 4, 8, 12]
    })

    # User B tries to request challenge for User A's session
    cross_chal = client.post("/api/security/step-up/challenge", headers=headers_b, json={
        "session_id": sid_a,
        "preferred_factor": "GESTURE_PATTERN"
    })
    assert cross_chal.status_code == status.HTTP_403_FORBIDDEN

    # User A requests legitimate challenge
    chal_a = client.post("/api/security/step-up/challenge", headers=headers_a, json={
        "session_id": sid_a,
        "preferred_factor": "GESTURE_PATTERN"
    })
    assert chal_a.status_code == status.HTTP_200_OK

    # User B attempts to verify User A's challenge
    cross_ver = client.post("/api/security/step-up/verify", headers=headers_b, json={
        "session_id": sid_a,
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": [0, 4, 8, 12]
    })
    assert cross_ver.status_code == status.HTTP_403_FORBIDDEN


def test_neuraltrace_attempt_limit_exhaustion(client: TestClient, auth_user):
    """Verifies that 3 consecutive incorrect route submissions lock out the challenge."""
    headers, _, session_id = auth_user
    route = [0, 3, 7, 11]

    client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": route,
        "confirm_pattern": route
    })

    client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": session_id,
        "preferred_factor": "GESTURE_PATTERN"
    })

    # 1st bad attempt
    r1 = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id, "challenge_type": "GESTURE_PATTERN", "gesture_pattern": [1, 5, 9, 13]
    })
    assert r1.status_code == status.HTTP_400_BAD_REQUEST

    # 2nd bad attempt
    r2 = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id, "challenge_type": "GESTURE_PATTERN", "gesture_pattern": [1, 5, 9, 13]
    })
    assert r2.status_code == status.HTTP_400_BAD_REQUEST

    # 3rd bad attempt (lockout)
    r3 = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id, "challenge_type": "GESTURE_PATTERN", "gesture_pattern": [1, 5, 9, 13]
    })
    assert r3.status_code == status.HTTP_400_BAD_REQUEST
    assert "maximum" in r3.json()["detail"].lower() or "locked" in r3.json()["detail"].lower()


def test_neuraltrace_expired_challenge_rejected(client: TestClient, auth_user):
    """Verifies that submitting a route to an expired challenge fails."""
    headers, _, session_id = auth_user
    route = [0, 4, 8, 12]

    client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": route,
        "confirm_pattern": route
    })

    chal_res = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": session_id,
        "preferred_factor": "GESTURE_PATTERN"
    })
    assert chal_res.status_code == status.HTTP_200_OK

    # Simulate expiry by backdating expires_at in StepUpService
    from app.services.step_up_service import utc_now
    from datetime import timedelta
    with StepUpService._lock:
        if session_id in StepUpService._challenges:
            StepUpService._challenges[session_id]["expires_at"] = utc_now() - timedelta(seconds=10)

    expired_verify = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": route
    })
    assert expired_verify.status_code == status.HTTP_400_BAD_REQUEST
    assert "expired" in expired_verify.json()["detail"].lower()


def test_neuraltrace_protected_resource_authorization(client: TestClient, auth_user, db_session: Session):
    """
    Verifies that a session requiring step-up remains blocked from accessing protected actions
    until the NeuralTrace route is verified server-side.
    """
    from app.models.session import Session as UserSession
    headers, _, session_id = auth_user
    route = [0, 4, 8, 12]

    # Enroll route
    client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": route,
        "confirm_pattern": route
    })

    # Set session status to STEP_UP_REQUIRED
    sess = db_session.query(UserSession).filter(UserSession.id == session_id).first()
    sess.status = "STEP_UP_REQUIRED"
    db_session.commit()

    # Protected resource should reflect step-up required
    status_res = client.get(f"/api/security/status/{session_id}", headers=headers)
    assert status_res.status_code == status.HTTP_200_OK
    assert status_res.json()["session_status"] == "STEP_UP_REQUIRED"
    assert status_res.json()["verification_required"] is True


    # Request challenge
    chal_res = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": session_id,
        "preferred_factor": "GESTURE_PATTERN"
    })
    assert chal_res.status_code == status.HTTP_200_OK

    # Bad route fails and keeps session locked
    bad_res = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": [1, 5, 9, 13]
    })
    assert bad_res.status_code == status.HTTP_400_BAD_REQUEST

    db_session.refresh(sess)
    assert sess.status == "STEP_UP_REQUIRED"

    # Correct route verifies identity and restores session to ACTIVE
    good_res = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": route
    })
    assert good_res.status_code == status.HTTP_200_OK
    assert good_res.json()["decision"] == "ALLOW"
    assert good_res.json()["session_status"] == "ACTIVE"

    db_session.refresh(sess)
    assert sess.status == "ACTIVE"


