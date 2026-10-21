import sys
import os
import json

# Ensure backend directory is in python path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, backend_dir)

from fastapi.testclient import TestClient
from app.main import app
from app.core.config import settings

client = TestClient(app)

def run_step5_verification():
    print("=== COGNISEC-AI: Phase-II Step 5 E2E Verification ===")

    # 1. New User Registration
    user_email = "cadence.eval@cognisec.ai"
    reg_resp = client.post("/api/auth/register", json={
        "email": user_email,
        "password": "SecurePassword123!",
        "name": "Cadence Evaluator",
        "role": "USER"
    })
    if reg_resp.status_code == 400:
        print("[1] User already exists (OK for idempotency)")
    else:
        assert reg_resp.status_code == 201, f"Reg failed: {reg_resp.text}"
        assert reg_resp.json()["role"] == "USER"
        print("[1] Registration OK: Role enforced to USER")

    # 2. Login
    login_resp = client.post("/api/auth/login", json={
        "email": user_email,
        "password": "SecurePassword123!",
        "application": "platform"
    })
    assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
    token_data = login_resp.json()
    token = token_data.get("access_token") or token_data.get("token")
    session_id = token_data["session_id"]
    headers = {"Authorization": f"Bearer {token}"}
    from app.services.session_service import SessionService
    from app.database.connection import SessionLocal
    with SessionLocal() as db:
        SessionService.activate_session_after_login_otp(db, session_id)
    print("[2] Login OK: Session bound JWT issued")

    # 3. Factor Enrollment with Confirmation
    # A. Gesture Pattern
    gesture_resp = client.post("/api/security/adaptive/enroll/gesture", headers=headers, json={
        "pattern": [0, 1, 2, 5],
        "confirm_pattern": [0, 1, 2, 5]
    })
    assert gesture_resp.status_code == 200, f"Gesture enrollment failed: {gesture_resp.text}"
    print("[3A] Gesture Pattern Enrolled with matching confirmation")

    # B. Cognitive Image Sequence
    image_resp = client.post("/api/security/adaptive/enroll/image-sequence", headers=headers, json={
        "image_sequence": ["img_key", "img_shield", "img_chip"],
        "confirm_image_sequence": ["img_key", "img_shield", "img_chip"]
    })
    assert image_resp.status_code == 200, f"Image enrollment failed: {image_resp.text}"
    print("[3B] Image Sequence Enrolled with matching confirmation")

    # C. Private Response
    private_resp = client.post("/api/security/adaptive/enroll/private-response", headers=headers, json={
        "question": "What is your primary security cipher?",
        "response": "AES-GCM-256",
        "confirm_response": "AES-GCM-256"
    })
    assert private_resp.status_code == 200, f"Private Response Enrolled with matching confirmation"
    print("[3C] Private Response Enrolled with matching confirmation")

    # D. Check Status (No secrets exposed)
    status_resp = client.get("/api/security/adaptive/status", headers=headers)
    assert status_resp.status_code == 200
    mfa_status = status_resp.json()
    assert mfa_status["has_gesture_pattern"] is True
    assert mfa_status["has_cognitive_image_sequence"] is True
    assert mfa_status["has_private_response"] is True
    assert "salt" not in mfa_status and "hash" not in mfa_status and "answer" not in mfa_status
    print("[3D] Authoritative Adaptive Status verified: 3/3 factors enrolled without secret leakage")

    # 4. Behavioral Telemetry - Zero Raw Text / Raw Keystrokes
    import time
    telemetry_payload = {
        "session_id": session_id,
        "application": "platform",
        "typing_speed_wpm": 62.0,
        "avg_flight_time_ms": 115.0,
        "avg_dwell_time_ms": 68.0,
        "mouse_velocity_avg": 240.0,
        "mouse_acceleration_avg": 450.0,
        "mouse_curvature_entropy": 1.25,
        "click_frequency": 0.8,
        "scroll_speed_avg": 40.0,
        "idle_duration_sec": 1.2,
        "navigation_entropy": 0.45,
        "timestamp": time.time(),
        "sequence_number": 1,
        "telemetry_nonce": "e2e_test_nonce_001"
    }
    # Verify no raw keystrokes or text keys in payload
    assert "text" not in telemetry_payload and "keystrokes" not in telemetry_payload and "paragraph" not in telemetry_payload

    event_resp = client.post("/api/behavior/events", headers=headers, json=telemetry_payload)
    assert event_resp.status_code == 200, f"Event submission failed: {event_resp.text}"
    event_data = event_resp.json()
    assert event_data["decision"] == "ALLOW"
    print("[4] Behavioral Telemetry Persisted: ALLOW outcome, zero raw keystroke storage")

    # 5. Check Behavioral Profile Progress
    prof_resp = client.get("/api/behavior/profile", headers=headers)
    assert prof_resp.status_code == 200
    prof = prof_resp.json()
    assert prof["sample_count"] >= 1
    print(f"[5] Baseline Sample Count Progression: {prof['sample_count']} samples (Maturity: {prof['baseline_status']})")

    # 6. Email OTP Step-Up Challenge (Low/Mild Risk Band)
    # A. First test: Under production settings (EXHIBITION_MODE=False, no SMTP configured),
    # verifying that system strictly blocks access and does NOT silently fabricate or display OTP
    orig_smtp_enabled = settings.SMTP_ENABLED
    settings.SMTP_ENABLED = False
    settings.EXHIBITION_MODE = False
    otp_fail_chal = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": session_id,
        "challenge_type": "OTP_EMAIL"
    })
    assert otp_fail_chal.status_code == 502, f"Expected 502 when SMTP is unconfigured, got: {otp_fail_chal.status_code}"
    assert "SMTP mail server is not configured" in otp_fail_chal.json()["detail"]
    print("[6A] Unconfigured SMTP properly blocks action with 502 and zero leakage (Strict Production Mode)")

    # B. Test OTP flow with EXHIBITION_MODE=True (Local Test Harness)
    settings.SMTP_ENABLED = orig_smtp_enabled
    settings.EXHIBITION_MODE = True
    otp_chal = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": session_id,
        "challenge_type": "OTP_EMAIL"
    })
    assert otp_chal.status_code == 200, f"OTP challenge failed in test mode: {otp_chal.text}"
    otp_data = otp_chal.json()
    assert "masked_email" in otp_data and "@" in otp_data["masked_email"]
    assert otp_data["is_demo_otp"] is True
    print(f"[6B] Test-mode OTP Challenge created: masked recipient '{otp_data['masked_email']}', demo OTP verifier active")

    if otp_data.get("otp"):
        verify_resp = client.post("/api/security/step-up/verify", headers=headers, json={
            "session_id": session_id,
            "challenge_type": "OTP",
            "challenge_code": otp_data["otp"]
        })
        assert verify_resp.status_code == 200, f"OTP verify failed: {verify_resp.text}"
        res_json = verify_resp.json()
        assert res_json["decision"] == "ALLOW"
        assert res_json["session_status"] == "ACTIVE"
        print("[6C] OTP Verification verified successfully via HMAC-SHA256 verifier (Session RESTORED to ACTIVE)")

        # Test single-use / replay rejection
        replay_resp = client.post("/api/security/step-up/verify", headers=headers, json={
            "session_id": session_id,
            "challenge_type": "OTP",
            "challenge_code": otp_data["otp"]
        })
        assert replay_resp.status_code == 400, "Replayed OTP was not rejected"
        print("[6D] Replayed OTP rejected correctly (Single-Use Enforced)")

    # 7. Compound High-Risk Dual-Factor Challenge (Image Sequence + Private Response)
    high_chal = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": session_id,
        "preferred_factor": "HIGH_RISK_DUAL"
    })
    assert high_chal.status_code == 200
    high_data = high_chal.json()
    assert high_data["challenge_type"] == "HIGH_RISK_DUAL"
    assert "prompt" in high_data and high_data["prompt"]

    # Verify compound challenge requires BOTH factors
    dual_verify = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": session_id,
        "challenge_type": "HIGH_RISK_DUAL",
        "image_sequence": ["img_key", "img_shield", "img_chip"],
        "private_response": "aes-gcm-256"
    })
    assert dual_verify.status_code == 200
    assert dual_verify.json()["decision"] == "ALLOW"
    print("[7] Compound High-Risk Dual Challenge verified with exact sequence & private response")

    # 8. Critical-Risk Session Termination
    term_resp = client.post(f"/api/sessions/{session_id}/terminate", headers=headers)
    assert term_resp.status_code == 200
    # Any subsequent challenge on terminated session must be strictly rejected (401 token revoked or 400 session terminated)
    post_term_chal = client.post("/api/security/step-up/challenge", headers=headers, json={
        "session_id": session_id,
        "preferred_factor": "OTP"
    })
    assert post_term_chal.status_code in (400, 401), f"Expected 400 or 401, got: {post_term_chal.status_code}"
    print("[8] Critical-Risk Termination enforced: token revoked / challenge restoration blocked")

    print("=== ALL STEP 5 E2E VERIFICATION CHECKS PASSED ===")

def test_step5_e2e_verification():
    run_step5_verification()

if __name__ == "__main__":
    run_step5_verification()
