def test_admin_metrics_access(client, admin_token):
    res = client.get("/api/admin/metrics", headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 200
    data = res.json()
    assert "live_sessions_count" in data
    assert "trusted_users_count" in data
    assert "blocked_sessions_count" in data
    assert "active_alerts_count" in data


def test_normal_user_blocked_from_admin_metrics(client, user_token):
    res = client.get("/api/admin/metrics", headers={"Authorization": f"Bearer {user_token}"})
    assert res.status_code == 403
    assert "Administrator privileges required" in res.json()["detail"]


def test_admin_view_sessions_and_events(client, admin_token):
    sess_res = client.get("/api/admin/sessions", headers={"Authorization": f"Bearer {admin_token}"})
    assert sess_res.status_code == 200
    assert isinstance(sess_res.json(), list)

    ev_res = client.get("/api/admin/events", headers={"Authorization": f"Bearer {admin_token}"})
    assert ev_res.status_code == 200
    assert isinstance(ev_res.json(), list)


def test_admin_view_and_resolve_alerts(client, admin_token, user_token):
    # Simulate an attack to ensure at least one alert exists
    client.post("/api/demo/simulate", headers={"Authorization": f"Bearer {admin_token}"}, json={
        "scenario": "SESSION_HIJACKING",
        "application": "ecommerce"
    })

    alerts_res = client.get("/api/admin/alerts", headers={"Authorization": f"Bearer {admin_token}"})
    assert alerts_res.status_code == 200
    alerts = alerts_res.json()
    assert len(alerts) > 0

    target_alert_id = alerts[0]["id"]
    resolve_res = client.post(
        f"/api/admin/alerts/{target_alert_id}/resolve",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"status": "RESOLVED", "resolution_notes": "Threat analyzed and neutralized by SOC analyst."}
    )
    assert resolve_res.status_code == 200
    assert resolve_res.json()["status"] == "RESOLVED"
