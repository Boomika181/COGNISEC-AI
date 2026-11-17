"""
Phase II - Step 5.8.6: Simple Agentic AI Dashboard Integration Tests.
Verifies:
- Admin authorization enforcement (401/403) on /api/admin/agents/status & /api/admin/agents/demo-analysis
- All 5 agents & safe provider health returned without exposing GEMINI_API_KEY
- Isolated synthetic demo analysis executes SecurityOrchestrator without touching real sessions/locks/OTPs
- Deterministic assessment, agent recommendations, and arbiter decision returned separately
- Recent Agent Activity reflects real persisted SecurityEvent records
- Frontend Admin Dashboard contains Agentic AI Monitor UI elements
"""
import os
import secrets
from datetime import datetime, timezone
from unittest.mock import patch

from app.core.config import settings
from app.core.security import get_password_hash
from app.models.portal_lock import PortalSecurityLock
from app.models.security_event import SecurityEvent
from app.models.session import Session as DbSession
from app.models.user import User
from app.services.email_service import EmailService


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _create_user_and_login(client, db_session, email: str, role: str):
    user = db_session.query(User).filter(User.email == email).first()
    if not user:
        user = User(
            email=email,
            name=f"{role.title()} Test User",
            password_hash=get_password_hash("StrongPass!123"),
            role=role,
            account_status="ACTIVE",
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

    login_res = client.post(
        "/api/auth/login",
        json={"email": email, "password": "StrongPass!123"},
    )
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    return user, {"Authorization": f"Bearer {token}"}


def test_agentic_dashboard_endpoints_require_admin_auth(client, db_session):
    # Unauthenticated -> 401
    assert client.get("/api/admin/agents/status").status_code == 401
    assert client.post("/api/admin/agents/demo-analysis", json={"scenario": "medium"}).status_code == 401

    # Non-admin user -> 403
    _, user_headers = _create_user_and_login(client, db_session, "nonadmin.agentic@example.com", "USER")
    assert client.get("/api/admin/agents/status", headers=user_headers).status_code == 403
    assert client.post("/api/admin/agents/demo-analysis", headers=user_headers, json={"scenario": "medium"}).status_code == 403


def test_agentic_status_returns_five_agents_and_safe_provider_health(client, db_session, monkeypatch):
    _, admin_headers = _create_user_and_login(client, db_session, "admin.agentic.status@example.com", "ADMIN")
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "AIzaSySecretKeyNeverExpose98765")

    res = client.get("/api/admin/agents/status", headers=admin_headers)
    assert res.status_code == 200
    assert "AIzaSySecretKeyNeverExpose" not in res.text

    data = res.json()
    assert "provider_health" in data
    assert data["provider_health"]["configured_provider"] in ("mock", "gemini")

    agents = data["agents"]
    assert len(agents) == 5
    keys = [a["key"] for a in agents]
    assert keys == [
        "SecurityContextAgent",
        "RiskAnalysisAgent",
        "AdaptiveAuthAgent",
        "SecurityResponseAgent",
        "SOCMonitoringAgent",
    ]
    for a in agents:
        assert a["name"]
        assert a["responsibility"]
        assert "provider_status" in a


def test_agentic_demo_analysis_is_isolated_and_populates_recent_activity(client, db_session):
    admin, admin_headers = _create_user_and_login(client, db_session, "admin.agentic.demo@example.com", "ADMIN")

    # Create a real user with an active session to verify demo does NOT touch it
    real_user = User(
        email="real.protected.user@example.com",
        name="Real Protected User",
        password_hash=get_password_hash("StrongPass!123"),
        role="USER",
        account_status="ACTIVE",
    )
    db_session.add(real_user)
    db_session.commit()
    db_session.refresh(real_user)

    real_sess = DbSession(
        id=f"sess_real_{secrets.token_hex(6)}",
        user_id=real_user.id,
        application="shopping",
        status="ACTIVE",
        current_risk_level="LOW",
    )
    db_session.add(real_sess)
    db_session.commit()

    locks_before = db_session.query(PortalSecurityLock).count()

    with patch.object(EmailService, "send_otp_email") as mock_email:
        res = client.post(
            "/api/admin/agents/demo-analysis",
            headers=admin_headers,
            json={"scenario": "high"},
        )
        assert res.status_code == 200
        mock_email.assert_not_called()

    body = res.json()
    assert body["demo_mode"] is True
    assert body["isolation_verified"] is True

    # Separate deterministic, agent recommendations, and arbiter decision
    assert body["deterministic_assessment"]["risk_level"] == "HIGH"
    assert body["deterministic_assessment"]["risk_score"] == 0.74
    assert "risk_analysis" in body["agent_recommendations"]
    assert "adaptive_auth" in body["agent_recommendations"]
    assert body["agent_recommendations"]["security_response"]["containment_executed"] is False
    assert body["arbiter_decision"]["final_risk_level"] in ("HIGH", "CRITICAL")
    assert body["arbiter_decision"]["final_risk_score"] >= 0.74
    executed = body["execution_result"]["agents_executed"]
    for agent_key in [
        "SecurityContextAgent",
        "RiskAnalysisAgent",
        "AdaptiveAuthAgent",
        "SecurityResponseAgent",
        "SOCMonitoringAgent",
    ]:
        assert any(str(x).startswith(agent_key) for x in executed)

    # Verify real user's session and portal locks are completely untouched
    db_session.refresh(real_sess)
    assert real_sess.status == "ACTIVE"
    assert real_sess.current_risk_level == "LOW"
    assert db_session.query(PortalSecurityLock).count() == locks_before

    # Verify recent activity now reflects the persisted AGENT_DEMO_ANALYSIS event
    status_res = client.get("/api/admin/agents/status", headers=admin_headers)
    assert status_res.status_code == 200
    activity = status_res.json()["recent_activity"]
    assert len(activity) >= 1
    assert any(act["trigger_event"] == "ADMIN_AGENTIC_DEMO_ANALYSIS" for act in activity)


def test_frontend_contains_agentic_ai_monitor_section():
    with open(os.path.join(REPO_ROOT, "index.html"), "r", encoding="utf-8") as f:
        html = f.read()
    with open(os.path.join(REPO_ROOT, "app.js"), "r", encoding="utf-8") as f:
        js = f.read()
    with open(os.path.join(REPO_ROOT, "cognisec-client.js"), "r", encoding="utf-8") as f:
        client_js = f.read()

    assert 'id="dash-tab-agentic"' in html
    assert "Agentic AI Monitor" in html
    assert 'id="dash-content-agentic"' in html
    assert 'id="agentic-run-demo-btn"' in html
    assert "Run Security Analysis" in html
    assert 'id="agentic-agents-grid"' in html
    assert 'id="agentic-recent-activity"' in html
    assert 'id="agentic-verify-provider-btn"' in html
    assert 'id="agentic-open-investigation-btn"' in html
    assert 'id="modal-agentic-investigation"' in html
    assert "loadAgenticMonitorData" in js
    assert "runAgenticDemoAnalysis" in js
    assert "/admin/agents/status" in client_js
    assert "/admin/agents/demo-analysis" in client_js


def test_agentic_critical_scenario_verify_provider_and_prod_vs_demo_separation(client, db_session):
    admin, admin_headers = _create_user_and_login(client, db_session, f"soc.crit.{secrets.token_hex(4)}@cognisec.ai", "ADMIN")
    human, user_headers = _create_user_and_login(client, db_session, f"crit.human.{secrets.token_hex(3)}@gmail.com", "USER")

    # Non-admin rejected from verify-provider
    assert client.post("/api/admin/agents/verify-provider", headers=user_headers).status_code == 403

    # Verify provider endpoint works and rate-limits rapid repeats
    v1 = client.post("/api/admin/agents/verify-provider", headers=admin_headers)
    assert v1.status_code == 200
    v2 = client.post("/api/admin/agents/verify-provider", headers=admin_headers)
    assert v2.status_code == 200
    assert v2.json()["rate_limited"] is True

    # Critical demo scenario returns TERMINATE_SESSION arbiter decision without touching real locks
    locks_before = db_session.query(PortalSecurityLock).count()
    crit_res = client.post("/api/admin/agents/demo-analysis", headers=admin_headers, json={"scenario": "critical"})
    assert crit_res.status_code == 200
    body = crit_res.json()
    assert body["deterministic_assessment"]["risk_level"] == "CRITICAL"
    assert body["deterministic_assessment"]["risk_score"] == 0.89
    assert body["arbiter_decision"]["final_decision"] == "TERMINATE_SESSION"
    assert len(body["execution_result"]["agent_statuses"]) == 5
    assert db_session.query(PortalSecurityLock).count() == locks_before

    # Seed a production AGENTIC_BEHAVIOR_RISK_TRANSITION event and verify DEMO vs PRODUCTION separation
    prod_ev = SecurityEvent(
        user_id=human.id,
        application="shopping",
        event_type="AGENTIC_BEHAVIOR_RISK_TRANSITION",
        severity="LOW",
        risk_score=0.12,
        decision="TIMEOUT_FALLBACK",
        details='{"agentic_orchestration": {"trigger_event": "BEHAVIOR_RISK_TRANSITION", "execution_status": "TIMEOUT_FALLBACK", "agents_executed": ["SecurityContextAgent:fallback"]}}',
    )
    db_session.add(prod_ev)
    db_session.commit()

    st = client.get("/api/admin/agents/status", headers=admin_headers).json()
    env_labels = {a["environment_label"] for a in st["recent_activity"]}
    assert "DEMO" in env_labels and "PRODUCTION" in env_labels
    for ag in st["agents"]:
        assert ag["availability_status"] in ("READY", "COMPLETED", "FALLBACK", "FAILED", "NOT CONFIGURED")
