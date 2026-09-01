def test_step_up_challenge_verification(client, user_token):
    # Start session
    sess_res = client.post("/api/sessions/start", headers={"Authorization": f"Bearer {user_token}"}, json={
        "application": "healthcare",
        "device_fingerprint": "fp_test_device_2"
    })
    session_id = sess_res.json()["id"]

    # Verify step-up challenge
    res = client.post("/api/security/step-up/verify", headers={"Authorization": f"Bearer {user_token}"}, json={
        "session_id": session_id,
        "challenge_code": "123456"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["decision"] == "ALLOW"
    assert "restored" in data["message"] or "verified" in data["message"]


def test_user_session_security_status_endpoint(client, user_token):
    sess_res = client.post("/api/sessions/start", headers={"Authorization": f"Bearer {user_token}"}, json={
        "application": "healthcare",
        "device_fingerprint": "fp_test_device_3"
    })
    session_id = sess_res.json()["id"]

    res = client.get(f"/api/security/status/{session_id}", headers={"Authorization": f"Bearer {user_token}"})
    assert res.status_code == 200
    data = res.json()
    assert "decision" in data
    assert "message" in data
    # Normal user should NOT see internal raw scores
    assert "risk_score" not in data
    assert "anomaly_score" not in data
