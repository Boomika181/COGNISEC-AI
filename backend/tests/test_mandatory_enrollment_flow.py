import uuid
from fastapi.testclient import TestClient
from app.main import app
from app.database.connection import SessionLocal
from app.models.user import User
from app.models.adaptive_factor import AdaptiveFactor


client = TestClient(app)


def test_mandatory_email_otp_and_three_factor_enrollment_flow():
    unique = uuid.uuid4().hex[:8]
    email = f"enroll_flow_{unique}@example.com"
    password = "StrongPassword!123"

    # 1. Register with require_email_verification=True
    reg_res = client.post("/api/auth/register", json={
        "name": f"Enroll User {unique}",
        "email": email,
        "password": password,
        "require_email_verification": True,
    })
    assert reg_res.status_code in (200, 201), reg_res.text
    reg_data = reg_res.json()
    assert reg_data["account_status"] == "PENDING_VERIFICATION"
    assert reg_data["email_verified"] is False
    assert reg_data["security_enrollment_completed"] is False
    assert reg_data["email_verification_required"] is True
    dev_otp = reg_data.get("dev_otp")
    assert dev_otp and len(dev_otp) == 6

    # 2. Login before email verification must be blocked
    pre_login = client.post("/api/auth/login", json={
        "email": email,
        "password": password,
    })
    assert pre_login.status_code == 403
    assert "EMAIL_VERIFICATION_REQUIRED" in pre_login.json()["detail"]

    # 3. Wrong OTP must fail
    bad_verif = client.post("/api/auth/verify-email", json={
        "email": email,
        "verification_code": "000000",
    })
    assert bad_verif.status_code == 400

    # 4. Valid OTP verifies email and returns authenticated token with security_enrollment_completed=False
    verif_res = client.post("/api/auth/verify-email", json={
        "email": email,
        "verification_code": dev_otp,
    })
    assert verif_res.status_code == 200, verif_res.text
    verif_data = verif_res.json()
    assert verif_data["status"] == "ACTIVE"
    assert verif_data["security_enrollment_completed"] is False
    assert set(verif_data["missing_factors"]) == {
        "GESTURE_PATTERN",
        "COGNITIVE_IMAGE_SEQUENCE",
        "PRIVATE_RESPONSE",
    }
    token = verif_data["access_token"]
    session_id = verif_data["session_id"]
    headers = {"Authorization": f"Bearer {token}"}

    # 5. Direct portal/resource access must be blocked until all 3 factors are enrolled
    for method, url, kwargs in [
        ("POST", "/api/security/access-decision", {"json": {"session_id": session_id, "resource": "academic_vault", "application": "college"}}),
        ("GET", f"/api/security/vault/ehr_vault?session_id={session_id}", {}),
        ("GET", "/api/shopping/orders", {}),
        ("GET", "/api/healthcare/appointments", {}),
    ]:
        r = client.request(method, url, headers=headers, **kwargs)
        assert r.status_code == 403, f"Expected 403 for {url}, got {r.status_code}: {r.text}"
        assert "SECURITY_ENROLLMENT_REQUIRED" in r.json()["detail"]

    # 6. Enroll Factor 1: NeuralTrace Route (connected nodes on 14-node graph)
    g_res = client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": [0, 3, 7, 11],
        "confirm_pattern": [0, 3, 7, 11],
    })
    assert g_res.status_code == 200, g_res.text
    assert g_res.json()["success"] is True

    # Cannot complete enrollment with only 1 factor
    comp_fail_1 = client.post("/api/security/adaptive/complete-enrollment", headers=headers)
    assert comp_fail_1.status_code == 400

    # 7. Enroll Factor 2: Cognitive Image Sequence (3-5 images)
    i_res = client.post("/api/security/adaptive/enroll/image-sequence", headers=headers, json={
        "image_sequence": ["img_shield", "img_key", "img_vault"],
        "confirm_image_sequence": ["img_shield", "img_key", "img_vault"],
    })
    assert i_res.status_code == 200, i_res.text
    assert i_res.json()["success"] is True

    # Cannot complete enrollment with only 2 factors
    comp_fail_2 = client.post("/api/security/adaptive/complete-enrollment", headers=headers)
    assert comp_fail_2.status_code == 400

    # 8. Enroll Factor 3: Private Response (stored hashed, never plaintext)
    secret_answer = "fluffy_test_pet_99"
    p_res = client.post("/api/security/adaptive/enroll/private-response", headers=headers, json={
        "question": "What was the name of your first childhood pet?",
        "response": secret_answer,
        "confirm_response": secret_answer,
    })
    assert p_res.status_code == 200, p_res.text
    assert p_res.json()["success"] is True

    # Verify plaintext answer is NOT stored in DB
    db = SessionLocal()
    try:
        u = db.query(User).filter(User.email == email).first()
        priv_factor = db.query(AdaptiveFactor).filter(
            AdaptiveFactor.user_id == u.id,
            AdaptiveFactor.factor_type == "PRIVATE_RESPONSE",
        ).first()
        assert priv_factor is not None
        assert secret_answer not in priv_factor.verifier_hash
        assert secret_answer not in (priv_factor.metadata_json or "")
    finally:
        db.close()

    # 9. Complete enrollment -> marks security_enrollment_completed=True
    comp_ok = client.post("/api/security/adaptive/complete-enrollment", headers=headers)
    assert comp_ok.status_code == 200, comp_ok.text
    assert comp_ok.json()["security_enrollment_completed"] is True

    # 10. Status and portal endpoints are now unblocked (no longer 403 SECURITY_ENROLLMENT_REQUIRED)
    status_res = client.get("/api/security/adaptive/status", headers=headers)
    assert status_res.status_code == 200
    st = status_res.json()
    assert st["has_gesture_pattern"] is True
    assert st["has_cognitive_image_sequence"] is True
    assert st["has_private_response"] is True
    assert st["security_enrollment_completed"] is True
    assert st["missing_factors"] == []

    orders_res = client.get("/api/shopping/orders", headers=headers)
    assert orders_res.status_code == 200
    appts_res = client.get("/api/healthcare/appointments", headers=headers)
    assert appts_res.status_code == 200
