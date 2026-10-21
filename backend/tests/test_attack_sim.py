def test_normal_user_blocked_from_attack_simulation(client, user_token):
    res = client.post("/api/demo/simulate", headers={"Authorization": f"Bearer {user_token}"}, json={
        "scenario": "SESSION_HIJACKING",
        "application": "healthcare"
    })
    assert res.status_code == 403
    assert "Administrator privileges required" in res.json()["detail"]


def test_simulate_new_device_scenario(client, admin_token):
    res = client.post("/api/demo/simulate", headers={"Authorization": f"Bearer {admin_token}"}, json={
        "scenario": "NEW_DEVICE",
        "application": "college"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["scenario"] == "NEW_DEVICE"
    assert data["security_decision"] in ["STEP_UP_VERIFICATION", "ALLOW", "RESTRICT"]
    assert data["alert_created"] is True


def test_simulate_abnormal_typing_scenario(client, admin_token):
    res = client.post("/api/demo/simulate", headers={"Authorization": f"Bearer {admin_token}"}, json={
        "scenario": "ABNORMAL_TYPING",
        "application": "ecommerce"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["scenario"] == "ABNORMAL_TYPING"
    assert data["risk_score"] > 0.60
    assert data["risk_level"] in ["HIGH", "CRITICAL"]


def test_simulate_session_hijacking_kill_switch(client, admin_token):
    res = client.post("/api/demo/simulate", headers={"Authorization": f"Bearer {admin_token}"}, json={
        "scenario": "SESSION_HIJACKING",
        "application": "healthcare"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["scenario"] == "SESSION_HIJACKING"
    assert data["risk_level"] == "CRITICAL"
    assert data["security_decision"] == "TERMINATE_SESSION"
    assert data["alert_created"] is True
