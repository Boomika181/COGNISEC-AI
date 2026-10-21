import pytest
from datetime import timedelta
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.adaptive_factor import AdaptiveFactor
from app.models.user import User
from app.services.step_up_service import StepUpService, utc_now


def test_registration_with_mandatory_gesture_enrollment(client: TestClient, db_session: Session):
    """Verifies that registration atomically enrolls and confirms the gesture pattern."""
    email = "gesture_reg_user@cognisec.ai"
    reg_payload = {
        "name": "Gesture Enrolled User",
        "email": email,
        "password": "Password123!",
        "gesture_pattern": [0, 1, 2, 5, 8],
        "confirm_gesture_pattern": [0, 1, 2, 5, 8]
    }
    res = client.post("/api/auth/register", json=reg_payload)
    assert res.status_code == status.HTTP_201_CREATED, res.text
    user_data = res.json()
    assert user_data["email"] == email

    # Verify factor was enrolled and persisted with secure verifier hash
    user = db_session.query(User).filter(User.email == email).first()
    assert user is not None
    factor = db_session.query(AdaptiveFactor).filter(
        AdaptiveFactor.user_id == user.id,
        AdaptiveFactor.factor_type == "GESTURE_PATTERN"
    ).first()
    assert factor is not None
    assert factor.verifier_hash is not None
    # Verifier must NOT be plaintext or contain raw sequence
    assert "0-1-2-5-8" not in factor.verifier_hash
    assert factor.verifier_hash.startswith("$2b$") or factor.verifier_hash.startswith("$2a$")


def test_registration_gesture_mismatch_fails(client: TestClient):
    """Registration fails if confirmation pattern does not match."""
    reg_payload = {
        "name": "Mismatch User",
        "email": "mismatch@cognisec.ai",
        "password": "Password123!",
        "gesture_pattern": [0, 1, 2, 5],
        "confirm_gesture_pattern": [0, 1, 2, 4]
    }
    res = client.post("/api/auth/register", json=reg_payload)
    assert res.status_code == status.HTTP_400_BAD_REQUEST
    assert "confirmation does not match" in res.json()["detail"].lower()


def test_registration_gesture_too_short_fails(client: TestClient):
    """Registration fails if gesture pattern has fewer than 4 distinct nodes."""
    reg_payload = {
        "name": "Short Pattern User",
        "email": "short@cognisec.ai",
        "password": "Password123!",
        "gesture_pattern": [0, 1, 2],
        "confirm_gesture_pattern": [0, 1, 2]
    }
    res = client.post("/api/auth/register", json=reg_payload)
    assert res.status_code == status.HTTP_400_BAD_REQUEST
    assert "at least 4 nodes" in res.json()["detail"].lower()


def test_registration_gesture_consecutive_duplicates_fails(client: TestClient):
    """Registration fails if pattern contains consecutive duplicate nodes."""
    reg_payload = {
        "name": "Duplicate Node User",
        "email": "duplicate@cognisec.ai",
        "password": "Password123!",
        "gesture_pattern": [0, 1, 1, 2, 5],
        "confirm_gesture_pattern": [0, 1, 1, 2, 5]
    }
    res = client.post("/api/auth/register", json=reg_payload)
    assert res.status_code == status.HTTP_400_BAD_REQUEST
    assert "consecutive duplicate" in res.json()["detail"].lower()


def test_gesture_verification_endpoint_authenticated(client: TestClient):
    """Tests the standalone factor verification endpoint POST /api/security/adaptive/verify/gesture."""
    email = "verify_test@cognisec.ai"
    reg_res = client.post("/api/auth/register", json={
        "name": "Verify Tester",
        "email": email,
        "password": "Password123!",
        "gesture_pattern": [0, 3, 6, 7, 8],
        "confirm_gesture_pattern": [0, 3, 6, 7, 8]
    })
    assert reg_res.status_code == status.HTTP_201_CREATED

    login_res = client.post("/api/auth/login", json={
        "email": email,
        "password": "Password123!"
    })
    assert login_res.status_code == status.HTTP_200_OK
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Unauthenticated attempt fails
    unauth_res = client.post("/api/security/adaptive/verify/gesture", json={"gesture_pattern": [0, 3, 6, 7, 8]})
    assert unauth_res.status_code == status.HTTP_401_UNAUTHORIZED

    # 2. Correct pattern succeeds
    correct_res = client.post("/api/security/adaptive/verify/gesture", json={"gesture_pattern": [0, 3, 6, 7, 8]}, headers=headers)
    assert correct_res.status_code == status.HTTP_200_OK
    assert correct_res.json()["success"] is True
    assert correct_res.json()["factor_type"] == "GESTURE_PATTERN"

    # 3. Wrong pattern fails with 401
    wrong_res = client.post("/api/security/adaptive/verify/gesture", json={"gesture_pattern": [0, 1, 2, 5, 8]}, headers=headers)
    assert wrong_res.status_code == status.HTTP_401_UNAUTHORIZED
    assert "verification failed" in wrong_res.json()["detail"].lower()


def test_stepup_challenge_gesture_verification_lifecycle(client: TestClient):
    """Verifies medium-risk gesture step-up challenge creation, verification, anti-replay, and user binding."""
    email = "stepup_gesture@cognisec.ai"
    client.post("/api/auth/register", json={
        "name": "StepUp User",
        "email": email,
        "password": "Password123!",
        "gesture_pattern": [1, 4, 7, 8],
        "confirm_gesture_pattern": [1, 4, 7, 8]
    })

    login_res = client.post("/api/auth/login", json={"email": email, "password": "Password123!"})
    token = login_res.json()["access_token"]
    session_id = login_res.json()["session_id"]
    headers = {"Authorization": f"Bearer {token}"}

    # Request step-up preferring GESTURE_PATTERN
    chal_res = client.post("/api/security/step-up/challenge", json={
        "session_id": session_id,
        "preferred_factor": "GESTURE_PATTERN"
    }, headers=headers)
    assert chal_res.status_code == status.HTTP_200_OK
    assert chal_res.json()["challenge_type"] == "GESTURE_PATTERN"

    # 1. Incorrect pattern submission fails and decrements attempts
    wrong_res = client.post("/api/security/step-up/verify", json={
        "session_id": session_id,
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": [0, 1, 2, 3]
    }, headers=headers)
    assert wrong_res.status_code == status.HTTP_400_BAD_REQUEST
    assert "Invalid verification" in wrong_res.json()["detail"]
    assert "2 attempts remaining" in wrong_res.json()["detail"]

    # 2. Correct pattern succeeds
    correct_res = client.post("/api/security/step-up/verify", json={
        "session_id": session_id,
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": [1, 4, 7, 8]
    }, headers=headers)
    assert correct_res.status_code == status.HTTP_200_OK
    assert correct_res.json()["decision"] == "ALLOW"
    assert correct_res.json()["session_status"] == "ACTIVE"

    # 3. Anti-replay: challenge has been consumed; replaying verification fails
    replay_res = client.post("/api/security/step-up/verify", json={
        "session_id": session_id,
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": [1, 4, 7, 8]
    }, headers=headers)
    assert replay_res.status_code == status.HTTP_400_BAD_REQUEST or replay_res.json().get("decision") != "ALLOW"


def test_cross_user_gesture_isolation(client: TestClient):
    """Ensures User B cannot verify User A's challenge, even with User B's own enrolled pattern."""
    email_a = "user_a@cognisec.ai"
    email_b = "user_b@cognisec.ai"

    # Register User A with pattern [0, 1, 4, 7]
    client.post("/api/auth/register", json={
        "name": "User A",
        "email": email_a,
        "password": "Password123!",
        "gesture_pattern": [0, 1, 4, 7],
        "confirm_gesture_pattern": [0, 1, 4, 7]
    })

    # Register User B with pattern [2, 5, 8, 7]
    client.post("/api/auth/register", json={
        "name": "User B",
        "email": email_b,
        "password": "Password123!",
        "gesture_pattern": [2, 5, 8, 7],
        "confirm_gesture_pattern": [2, 5, 8, 7]
    })

    login_a = client.post("/api/auth/login", json={"email": email_a, "password": "Password123!"}).json()
    login_b = client.post("/api/auth/login", json={"email": email_b, "password": "Password123!"}).json()

    # Issue challenge for User A's session
    client.post("/api/security/step-up/challenge", json={
        "session_id": login_a["session_id"],
        "preferred_factor": "GESTURE_PATTERN"
    }, headers={"Authorization": f"Bearer {login_a['access_token']}"})

    # User B attempts to verify User A's session -> must be rejected (403 or 400)
    cross_res = client.post("/api/security/step-up/verify", json={
        "session_id": login_a["session_id"],
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": [2, 5, 8, 7]
    }, headers={"Authorization": f"Bearer {login_b['access_token']}"})
    assert cross_res.status_code in [status.HTTP_400_BAD_REQUEST, status.HTTP_403_FORBIDDEN]
