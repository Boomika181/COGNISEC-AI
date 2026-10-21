import time
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from fastapi import status
from sqlalchemy.orm import Session

from app.models.adaptive_factor import AdaptiveFactor
from app.models.session import Session as UserSession
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
def registered_user(client: TestClient):
    ts = time.time_ns()
    email = f"neural_operator_{ts}@cognisec.ai"
    reg_res = client.post("/api/auth/register", json={
        "email": email,
        "password": "SecurePassword123!",
        "name": f"Operator {ts}"
    })
    assert reg_res.status_code == status.HTTP_201_CREATED

    login_res = client.post("/api/auth/login", json={
        "email": email,
        "password": "SecurePassword123!",
        "application": "college_portal"
    })
    assert login_res.status_code == status.HTTP_200_OK
    data = login_res.json()
    headers = {"Authorization": f"Bearer {data['access_token']}"}
    return {
        "headers": headers,
        "user_id": data["user_id"],
        "session_id": data["session_id"],
        "email": email
    }


def test_correct_route_accepted_and_authorized_access_granted(client: TestClient, registered_user):
    """
    1. Correct route is accepted during step-up challenge verification.
    2. Authoritative server access decision grants confidential access for active session.
    """
    headers = registered_user["headers"]
    session_id = registered_user["session_id"]
    valid_route = [0, 4, 8, 12]

    # Enroll route
    enroll_res = client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": valid_route,
        "confirm_pattern": valid_route
    })
    assert enroll_res.status_code == status.HTTP_200_OK

    # Check access before step-up: confidential access is NOT granted
    decision_before = client.post("/api/security/access-decision", headers=headers, json={
        "session_id": session_id,
        "resource": "academic_vault"
    })
    assert decision_before.status_code == status.HTTP_200_OK
    assert decision_before.json()["access_granted"] is False

    # Issue step-up challenge
    chal_res = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": session_id,
        "preferred_factor": "GESTURE_PATTERN"
    })
    assert chal_res.status_code == status.HTTP_200_OK
    chal_data = chal_res.json()
    assert chal_data["challenge_type"] == "GESTURE_PATTERN"

    # Verify correct route
    verify_res = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": valid_route
    })
    assert verify_res.status_code == status.HTTP_200_OK
    assert verify_res.json()["decision"] == "ALLOW"

    # Check access decision after successful verification: granted!
    decision_after = client.post("/api/security/access-decision", headers=headers, json={
        "session_id": session_id,
        "resource": "academic_vault"
    })
    assert decision_after.status_code == status.HTTP_200_OK
    assert decision_after.json()["access_granted"] is True
    assert decision_after.json()["step_up_fresh"] is True


def test_incorrect_route_rejected_and_confidential_access_locked(client: TestClient, registered_user):
    """
    Incorrect route rejected and confidential records remain locked.
    """
    headers = registered_user["headers"]
    session_id = registered_user["session_id"]
    enrolled_route = [0, 4, 8, 12]
    wrong_route = [1, 5, 9, 13]

    # Enroll route
    client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": enrolled_route,
        "confirm_pattern": enrolled_route
    })

    # Request challenge
    client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": session_id,
        "preferred_factor": "GESTURE_PATTERN"
    })

    # Verify with wrong route
    verify_res = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": wrong_route
    })
    assert verify_res.status_code == status.HTTP_400_BAD_REQUEST

    # Check authoritative server decision: access remains strictly locked
    decision_res = client.post("/api/security/access-decision", headers=headers, json={
        "session_id": session_id,
        "resource": "academic_vault"
    })
    assert decision_res.status_code == status.HTTP_200_OK
    assert decision_res.json()["access_granted"] is False


def test_reset_neuraltrace_full_lifecycle(client: TestClient, registered_user, db_session: Session):
    """
    Full NeuralTrace reset flow:
    1. Enroll initial route [0, 4, 8, 12].
    2. Request reset -> Email OTP sent to registered email.
    3. Wrong OTP rejected; existing enrollment preserved.
    4. Correct OTP verified -> Single-use reset ticket issued.
    5. Mismatched confirmation route rejected.
    6. Matching valid new route [1, 5, 9, 13] confirmed.
    7. Verifier updated in DB; old challenges invalidated.
    8. Old route rejected; new route accepted.
    """
    headers = registered_user["headers"]
    session_id = registered_user["session_id"]
    user_id = registered_user["user_id"]
    old_route = [0, 4, 8, 12]
    new_route = [1, 5, 9, 13]

    # 1. Enroll initial route
    enroll_res = client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": old_route,
        "confirm_pattern": old_route
    })
    assert enroll_res.status_code == status.HTTP_200_OK

    factor_before = db_session.query(AdaptiveFactor).filter(
        AdaptiveFactor.user_id == user_id,
        AdaptiveFactor.factor_type == "GESTURE_PATTERN"
    ).first()
    old_verifier = factor_before.verifier_hash

    # 2. Request Reset
    req_res = client.post("/api/security/adaptive/neuraltrace/reset-request", headers=headers)
    assert req_res.status_code == status.HTTP_200_OK
    req_data = req_res.json()
    challenge_id = req_data.get("reset_challenge_id") or req_data.get("challenge_id")
    assert challenge_id is not None
    assert req_data["success"] is True

    # Retrieve in-memory challenge to inspect generated OTP for testing
    reset_chal = StepUpService._neuraltrace_resets.get(challenge_id)
    assert reset_chal is not None
    otp_code = reset_chal["otp"]

    # 3. Wrong OTP rejected; existing factor untouched
    bad_verify = client.post("/api/security/adaptive/neuraltrace/reset-verify", headers=headers, json={
        "challenge_id": challenge_id,
        "otp": "000000"
    })
    assert bad_verify.status_code == status.HTTP_400_BAD_REQUEST

    db_session.refresh(factor_before)
    assert factor_before.verifier_hash == old_verifier

    # 4. Correct OTP verified -> returns reset_ticket
    good_verify = client.post("/api/security/adaptive/neuraltrace/reset-verify", headers=headers, json={
        "challenge_id": challenge_id,
        "otp": otp_code
    })
    assert good_verify.status_code == status.HTTP_200_OK
    verify_data = good_verify.json()
    assert verify_data["success"] is True
    reset_ticket = verify_data["reset_ticket"]

    # 5. Mismatched confirmation route rejected
    mismatch_res = client.post("/api/security/adaptive/neuraltrace/reset-confirm", headers=headers, json={
        "reset_ticket": reset_ticket,
        "pattern": new_route,
        "confirm_pattern": [2, 6, 10, 14]
    })
    assert mismatch_res.status_code == status.HTTP_400_BAD_REQUEST
    assert "match" in mismatch_res.json()["detail"].lower()

    # 6. Confirm with matching new route
    confirm_res = client.post("/api/security/adaptive/neuraltrace/reset-confirm", headers=headers, json={
        "reset_ticket": reset_ticket,
        "pattern": new_route,
        "confirm_pattern": new_route
    })
    assert confirm_res.status_code == status.HTTP_200_OK
    assert confirm_res.json()["success"] is True

    # 7. Check DB: verifier hash changed, never contains raw route
    db_session.refresh(factor_before)
    assert factor_before.verifier_hash != old_verifier
    assert "1-5-9-13" not in factor_before.verifier_hash

    # 8. Reset ticket is single use: replaying fails
    replay_res = client.post("/api/security/adaptive/neuraltrace/reset-confirm", headers=headers, json={
        "reset_ticket": reset_ticket,
        "pattern": new_route,
        "confirm_pattern": new_route
    })
    assert replay_res.status_code == status.HTTP_400_BAD_REQUEST

    # 9. Verify step-up with old route fails, new route succeeds
    chal_res = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": session_id,
        "preferred_factor": "GESTURE_PATTERN"
    })
    assert chal_res.status_code == status.HTTP_200_OK

    old_test = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": old_route
    })
    assert old_test.status_code == status.HTTP_400_BAD_REQUEST

    new_test = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": new_route
    })
    assert new_test.status_code == status.HTTP_200_OK
    assert new_test.json()["decision"] == "ALLOW"


def test_cross_user_and_replayed_challenges_rejected(client: TestClient, registered_user):
    """
    Replayed and cross-user challenges are rejected.
    """
    user_a = registered_user
    valid_route = [0, 4, 8, 12]

    # Enroll user A
    client.post("/api/security/adaptive/enroll/gesture", headers=user_a["headers"], json={
        "pattern": valid_route,
        "confirm_pattern": valid_route
    })

    # Register user B
    ts = time.time_ns()
    user_b_res = client.post("/api/auth/register", json={
        "email": f"user_b_{ts}@cognisec.ai",
        "password": "Password123!",
        "name": "User B"
    })
    user_b_login = client.post("/api/auth/login", json={
        "email": f"user_b_{ts}@cognisec.ai",
        "password": "Password123!",
        "application": "shopping_portal"
    })
    user_b_headers = {"Authorization": f"Bearer {user_b_login.json()['access_token']}"}

    # User A creates a challenge
    chal_res = client.post("/api/security/step-up/challenge", headers=user_a["headers"], json={
        "session_id": user_a["session_id"],
        "preferred_factor": "GESTURE_PATTERN"
    })
    chal_data = chal_res.json()

    # User B tries to verify User A's session/challenge -> Rejected
    cross_res = client.post("/api/security/step-up/verify", headers=user_b_headers, json={
        "session_id": user_a["session_id"],
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": valid_route
    })
    assert cross_res.status_code in (status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND, status.HTTP_400_BAD_REQUEST)

    # User A verifies -> Succeeds
    verify_res = client.post("/api/security/step-up/verify", headers=user_a["headers"], json={
        "session_id": user_a["session_id"],
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": valid_route
    })
    assert verify_res.status_code == status.HTTP_200_OK

    # Replay verify -> Rejected (consumed)
    replay_res = client.post("/api/security/step-up/verify", headers=user_a["headers"], json={
        "session_id": user_a["session_id"],
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": valid_route
    })
    assert replay_res.status_code == status.HTTP_400_BAD_REQUEST


def test_cross_portal_confidential_access_authorization(client: TestClient, registered_user):
    """
    Requirement 4: After successful NeuralTrace verification, confidential access
    is recognized across all three demo portals (academic_vault, financial_vault, ehr_vault)
    for the same active session via the authoritative access decision API.
    """
    headers = registered_user["headers"]
    session_id = registered_user["session_id"]
    route = [0, 4, 8, 12]

    # Enroll
    client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": route,
        "confirm_pattern": route
    })

    # Challenge & Verify on College portal
    client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": session_id,
        "application": "college",
        "resource": "academic_vault",
        "preferred_factor": "GESTURE_PATTERN"
    })
    verify_res = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "application": "college",
        "resource": "academic_vault",
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": route
    })
    assert verify_res.status_code == status.HTTP_200_OK

    # Portal 1: College (academic_vault) -> GRANTED
    college_check = client.post("/api/security/access-decision", headers=headers, json={
        "session_id": session_id,
        "resource": "academic_vault",
        "application": "college_portal"
    })
    assert college_check.status_code == status.HTTP_200_OK
    assert college_check.json()["access_granted"] is True

    # Portal 2: Shopping (financial_vault) -> INDEPENDENT: MUST BE LOCKED
    shopping_check = client.post("/api/security/access-decision", headers=headers, json={
        "session_id": session_id,
        "resource": "financial_vault",
        "application": "shopping_portal"
    })
    assert shopping_check.status_code == status.HTTP_200_OK
    assert shopping_check.json()["access_granted"] is False
    assert shopping_check.json()["verification_required"] is True

    # Portal 3: Healthcare (ehr_vault) -> INDEPENDENT: MUST BE LOCKED
    healthcare_check = client.post("/api/security/access-decision", headers=headers, json={
        "session_id": session_id,
        "resource": "ehr_vault",
        "application": "healthcare_portal"
    })
    assert healthcare_check.status_code == status.HTTP_200_OK
    assert healthcare_check.json()["access_granted"] is False
    assert healthcare_check.json()["verification_required"] is True


def test_high_or_critical_risk_policy_blocks_confidential_access(client: TestClient, registered_user, db_session: Session):
    """
    Requirement 4 & 5: If server risk policy escalates to HIGH, CRITICAL, or TERMINATED,
    confidential access is blocked even if step-up had previously succeeded.
    """
    headers = registered_user["headers"]
    session_id = registered_user["session_id"]
    route = [0, 4, 8, 12]

    # Enroll & verify step-up
    client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": route,
        "confirm_pattern": route
    })
    client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": session_id,
        "preferred_factor": "GESTURE_PATTERN"
    })
    client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": route
    })

    # Verify access is granted while risk is LOW/MEDIUM
    ok_res = client.post("/api/security/access-decision", headers=headers, json={
        "session_id": session_id,
        "application": "college",
        "resource": "academic_vault"
    })
    assert ok_res.json()["access_granted"] is True

    # Case A: Risk escalates to CRITICAL on an active session -> Access denied with decision RESTRICT
    db_session.query(UserSession).filter(UserSession.id == session_id).update({
        "current_risk_level": "CRITICAL",
        "status": "ACTIVE"
    })
    db_session.commit()

    denied_res = client.post("/api/security/access-decision", headers=headers, json={
        "session_id": session_id,
        "application": "college",
        "resource": "academic_vault"
    })
    assert denied_res.status_code == status.HTTP_200_OK
    assert denied_res.json()["access_granted"] is False
    assert denied_res.json()["decision"] in ("TERMINATE_SESSION", "RESTRICT", "REQUIRE_STEP_UP")

    # Case B: Session terminated -> Any further access rejected
    db_session.query(UserSession).filter(UserSession.id == session_id).update({
        "status": "TERMINATED"
    })
    db_session.commit()

    term_res = client.post("/api/security/access-decision", headers=headers, json={
        "session_id": session_id,
        "application": "college",
        "resource": "academic_vault"
    })
    assert term_res.status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_200_OK)
    if term_res.status_code == status.HTTP_200_OK:
        assert term_res.json()["access_granted"] is False


def test_newly_logged_in_user_denied_vault_access_before_neuraltrace(client: TestClient, registered_user, db_session: Session):
    """
    Regression Test 1, 2, 3: A newly logged in user cannot see confidential data before NeuralTrace.
    Neither academic_vault, financial_vault, nor ehr_vault can be accessed.
    Protected backend endpoints return 403 Forbidden.
    """
    headers = registered_user["headers"]
    session_id = registered_user["session_id"]

    # 1. Newly logged-in user in baseline observation
    for vault in ["academic_vault", "financial_vault", "ehr_vault"]:
        dec = client.post("/api/security/access-decision", headers=headers, json={
            "session_id": session_id,
            "resource": vault
        })
        assert dec.status_code == status.HTTP_200_OK
        data = dec.json()
        assert data["access_granted"] is False
        assert data["decision"] in ("OBSERVATION_PENDING", "STEP_UP_VERIFICATION")

        vault_res = client.get(f"/api/security/vault/{vault}?session_id={session_id}", headers=headers)
        assert vault_res.status_code == status.HTTP_403_FORBIDDEN

    # 2. Even after general login OTP activates the session to ACTIVE,
    # confidential vaults MUST still require NeuralTrace (GESTURE_PATTERN)
    from app.services.session_service import SessionService
    SessionService.activate_session_after_login_otp(db_session, session_id)

    for vault in ["academic_vault", "financial_vault", "ehr_vault"]:
        dec_active = client.post("/api/security/access-decision", headers=headers, json={
            "session_id": session_id,
            "resource": vault
        })
        assert dec_active.status_code == status.HTTP_200_OK
        data_active = dec_active.json()
        assert data_active["access_granted"] is False
        assert data_active["decision"] == "STEP_UP_VERIFICATION"
        assert data_active["required_factor"] == "GESTURE_PATTERN"

        vault_res_active = client.get(f"/api/security/vault/{vault}?session_id={session_id}", headers=headers)
        assert vault_res_active.status_code == status.HTTP_403_FORBIDDEN


def test_protected_vault_endpoints_require_neuraltrace_and_unmask_on_success(client: TestClient, registered_user):
    """
    Regression Test 5 & 7: Protected vault data endpoint fails closed before NeuralTrace
    and unmasks real confidential data ONLY after server confirms valid NeuralTrace route.
    Manipulating client state without server grant cannot access vault data.
    """
    headers = registered_user["headers"]
    session_id = registered_user["session_id"]
    route = [0, 4, 8, 12]

    # 1. Protected endpoint returns 403 before verification
    res_before = client.get(f"/api/security/vault/academic_vault?session_id={session_id}", headers=headers)
    assert res_before.status_code == status.HTTP_403_FORBIDDEN

    # 2. Enroll & verify NeuralTrace route for College portal
    client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": route,
        "confirm_pattern": route
    })
    client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": session_id,
        "application": "college",
        "resource": "academic_vault",
        "preferred_factor": "GESTURE_PATTERN"
    })
    verify_res = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "application": "college",
        "resource": "academic_vault",
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": route
    })
    assert verify_res.status_code == status.HTTP_200_OK
    assert verify_res.json()["decision"] == "ALLOW"

    # 3. College academic vault is UNLOCKED
    acad_res = client.get(f"/api/security/vault/academic_vault?session_id={session_id}", headers=headers)
    assert acad_res.status_code == status.HTTP_200_OK
    assert "transcripts" in acad_res.json()["data"]

    # 4. Shopping and Healthcare vaults REMAIN SEALED (403 Forbidden)
    fin_res_locked = client.get(f"/api/security/vault/financial_vault?session_id={session_id}", headers=headers)
    assert fin_res_locked.status_code == status.HTTP_403_FORBIDDEN

    ehr_res_locked = client.get(f"/api/security/vault/ehr_vault?session_id={session_id}", headers=headers)
    assert ehr_res_locked.status_code == status.HTTP_403_FORBIDDEN

    # 5. Independently verify Shopping portal
    client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": session_id,
        "application": "shopping",
        "resource": "financial_vault",
        "preferred_factor": "GESTURE_PATTERN"
    })
    verify_fin = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "application": "shopping",
        "resource": "financial_vault",
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": route
    })
    assert verify_fin.status_code == status.HTTP_200_OK

    # Shopping vault is NOW unlocked
    fin_res = client.get(f"/api/security/vault/financial_vault?session_id={session_id}", headers=headers)
    assert fin_res.status_code == status.HTTP_200_OK
    assert "saved_cards" in fin_res.json()["data"]

    # Healthcare STILL remains sealed until verified
    ehr_res_still_locked = client.get(f"/api/security/vault/ehr_vault?session_id={session_id}", headers=headers)
    assert ehr_res_still_locked.status_code == status.HTTP_403_FORBIDDEN


def test_expired_or_revoked_grant_fails_closed(client: TestClient, registered_user, db_session: Session):
    """
    Regression Test 8: Expired or revoked step-up grants fail closed.
    """
    headers = registered_user["headers"]
    session_id = registered_user["session_id"]
    route = [0, 4, 8, 12]

    # Enroll & verify
    client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": route,
        "confirm_pattern": route
    })
    client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": session_id,
        "preferred_factor": "GESTURE_PATTERN"
    })
    client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "challenge_type": "GESTURE_PATTERN",
        "gesture_pattern": route
    })

    # Access is valid
    ok_res = client.get(f"/api/security/vault/academic_vault?session_id={session_id}", headers=headers)
    assert ok_res.status_code == status.HTTP_200_OK

    # Simulate expiration: set step_up_valid_until and ApplicationGrant.expires_at to the past
    past_time = datetime.now(timezone.utc) - timedelta(minutes=5)
    db_session.query(UserSession).filter(UserSession.id == session_id).update({
        "step_up_valid_until": past_time
    })
    from app.models.application_grant import ApplicationGrant
    db_session.query(ApplicationGrant).filter(ApplicationGrant.session_id == session_id).update({
        "expires_at": past_time
    })
    db_session.commit()

    # Access is now blocked (fails closed)
    exp_dec = client.post("/api/security/access-decision", headers=headers, json={
        "session_id": session_id,
        "application": "college",
        "resource": "academic_vault"
    })
    assert exp_dec.json()["access_granted"] is False

    exp_vault = client.get(f"/api/security/vault/academic_vault?session_id={session_id}", headers=headers)
    assert exp_vault.status_code == status.HTTP_403_FORBIDDEN

