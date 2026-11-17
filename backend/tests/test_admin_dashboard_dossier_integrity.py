import json
import secrets
from datetime import datetime, timedelta, timezone

from app.core.security import get_password_hash
from app.models.alert import Alert
from app.models.behavior import BehaviorLog, BehaviorProfile
from app.models.device import Device
from app.models.security_event import SecurityEvent
from app.models.session import Session as DbSession
from app.models.user import User


def _make_user(db, email: str, name: str, role: str = "USER", status: str = "ACTIVE") -> User:
    existing = db.query(User).filter(User.email == email).first()
    if existing:
        return existing
    u = User(
        email=email,
        name=name,
        password_hash=get_password_hash("StrongPass!123"),
        role=role,
        account_status=status,
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    return u


def _login(client, email: str) -> dict:
    res = client.post("/api/auth/login", json={"email": email, "password": "StrongPass!123", "application": "platform"})
    assert res.status_code == 200, res.text
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


def test_registered_users_excludes_test_demo_and_admin_accounts(client, db_session):
    admin = _make_user(db_session, f"soc.lead.{secrets.token_hex(4)}@cognisec.ai", "SOC Admin", role="ADMIN")
    # Register genuine human users through the public registration endpoint
    alice_email = f"alice.human.{secrets.token_hex(3)}@gmail.com"
    bob_email = f"bob.human.{secrets.token_hex(3)}@veritas.edu"
    for em, nm in ((alice_email, "Alice Human"), (bob_email, "Bob Human")):
        reg = client.post("/api/auth/register", json={"name": nm, "email": em, "password": "StrongPass!123"})
        assert reg.status_code == 201, reg.text
    human1 = db_session.query(User).filter(User.email == alice_email).first()
    human2 = db_session.query(User).filter(User.email == bob_email).first()
    assert human1.registration_source == "PUBLIC_REGISTRATION"

    # Identifiable test / demo / seeded accounts
    _make_user(db_session, f"e2e_live_{secrets.token_hex(3)}@cognisec.ai", "E2E User")
    _make_user(db_session, f"audit_plat_{secrets.token_hex(3)}@cognisec.ai", "Audit User")
    _make_user(db_session, f"user_{secrets.token_hex(3)}@example.com", "Example Test")
    seeded_1 = _make_user(db_session, f"seeded.jane.{secrets.token_hex(3)}@auraluxe.com", "Jane Doe (VIP)")
    seeded_1.registration_source = "SEED_SCRIPT"
    seeded_2 = _make_user(db_session, f"seeded.student.{secrets.token_hex(3)}@bits-pilani.ac.in", "Student Demo")
    seeded_2.registration_source = "SEED_SCRIPT"
    db_session.commit()
    # Historical unknown-origin user with no registration_source and no verification history
    unknown_hist = _make_user(db_session, f"legacy.unknown.{secrets.token_hex(3)}@external.org", "Legacy Unknown")

    # Give human1 two active sessions across two portals to verify logged_in_users_count (1) != live_sessions_count (2)
    for app_name in ("shopping", "college"):
        db_session.add(DbSession(
            id=f"sess_hum_{app_name}_{secrets.token_hex(4)}",
            user_id=human1.id,
            application=app_name,
            status="ACTIVE",
        ))
    db_session.commit()

    headers = _login(client, admin.email)
    res = client.get("/api/admin/metrics?scope=genuine", headers=headers)
    assert res.status_code == 200
    m = res.json()

    assert m["scope"] == "genuine"
    assert m["registered_users_count"] >= 2
    assert m["email_verified_users_count"] >= 2
    assert m["admin_accounts_count"] >= 1
    assert m["test_and_demo_accounts_count"] >= 5
    assert m["unverified_provenance_accounts_count"] >= 1
    # Production Only filters out admin's own session and counts human1's 2 active sessions
    assert m["live_sessions_count"] >= 2
    assert m["logged_in_users_count"] >= 1
    assert m["live_sessions_count"] >= m["logged_in_users_count"]

    # Default directory (no scope param) must behave as scope=genuine
    default_dir = client.get("/api/admin/users/directory?page_size=100", headers=headers)
    assert default_dir.status_code == 200
    default_payload = default_dir.json()
    default_emails = {row["email"] for row in default_payload["items"]}
    assert human1.email in default_emails
    assert human2.email in default_emails
    assert admin.email not in default_emails
    assert seeded_1.email not in default_emails
    assert seeded_2.email not in default_emails
    assert unknown_hist.email not in default_emails
    assert default_payload["total"] == m["registered_users_count"]

    # Scope=admin must return admin and exclude human/test/seeded
    admin_dir = client.get("/api/admin/users/directory?scope=admin&page_size=100", headers=headers)
    assert admin_dir.status_code == 200
    admin_emails = {row["email"] for row in admin_dir.json()["items"]}
    assert admin.email in admin_emails
    assert human1.email not in admin_emails

    # Scope=test must return test/seeded and exclude human/admin
    test_dir = client.get("/api/admin/users/directory?scope=test&page_size=100", headers=headers)
    assert test_dir.status_code == 200
    test_emails = {row["email"] for row in test_dir.json()["items"]}
    assert seeded_1.email in test_emails
    assert seeded_2.email in test_emails
    assert human1.email not in test_emails
    assert admin.email not in test_emails

    # Scope=all must include all categories and search must respect scope
    all_dir = client.get("/api/admin/users/directory?scope=all&page_size=100", headers=headers)
    assert all_dir.status_code == 200
    all_emails = {row["email"] for row in all_dir.json()["items"]}
    assert {human1.email, admin.email, seeded_1.email, unknown_hist.email}.issubset(all_emails)
    scoped_search = client.get(f"/api/admin/users/directory?scope=genuine&search={admin.email}", headers=headers)
    assert scoped_search.status_code == 200
    assert scoped_search.json()["total"] == 0


def test_incident_dossier_separates_historical_decision_from_current_session_and_honest_baseline(client, db_session):
    admin = _make_user(db_session, f"soc.dossier.{secrets.token_hex(4)}@cognisec.ai", "Dossier Admin", role="ADMIN")
    human = _make_user(db_session, f"carol.human.{secrets.token_hex(3)}@gmail.com", "Carol Human")

    dev = Device(
        user_id=human.id,
        device_id=f"dev_{secrets.token_hex(4)}",
        device_fingerprint=secrets.token_hex(16),
        browser_name="Chrome",
        os_name="macOS",
        trust_state="UNTRUSTED",
        is_trusted=False,
    )
    db_session.add(dev)
    db_session.commit()
    db_session.refresh(dev)

    sess = DbSession(
        id=f"sess_term_{secrets.token_hex(6)}",
        user_id=human.id,
        device_id=dev.id,
        application="healthcare",
        status="TERMINATED",
        current_risk_level="CRITICAL",
        logout_time=datetime.now(timezone.utc),
    )
    db_session.add(sess)
    db_session.commit()

    # Correlated SecurityEvents (chronological)
    now = datetime.now(timezone.utc)
    ev1 = SecurityEvent(
        user_id=human.id,
        session_id=sess.id,
        application="healthcare",
        event_type="LOGIN_SUCCESS",
        severity="LOW",
        anomaly_score=0.05,
        risk_score=0.10,
        decision="ALLOW",
        timestamp=now - timedelta(minutes=5),
    )
    ev2 = SecurityEvent(
        user_id=human.id,
        session_id=sess.id,
        application="healthcare",
        event_type="BEHAVIORAL_ANOMALY",
        severity="HIGH",
        anomaly_score=0.88,
        risk_score=0.91,
        decision="TERMINATE_SESSION",
        details=json.dumps({
            "adaptive_auth_recommendation": "TERMINATE_AND_LOCK",
            "factors": ["behavioral_drift", "untrusted_device"],
        }),
        timestamp=now - timedelta(minutes=2),
    )
    db_session.add_all([ev1, ev2])
    db_session.commit()
    db_session.refresh(ev2)

    # BehaviorLog exists, but BehaviorProfile has 0 samples (no baseline)
    db_session.add(BehaviorLog(
        user_id=human.id,
        session_id=sess.id,
        application="healthcare",
        typing_speed_wpm=62.5,
        avg_flight_time_ms=110.0,
        avg_dwell_time_ms=85.0,
    ))
    db_session.add(BehaviorProfile(user_id=human.id, sample_count=0))

    alert = Alert(
        user_id=human.id,
        security_event_id=ev2.id,
        application="healthcare",
        alert_type="PORTAL_SECURITY_LOCKOUT",
        message="Critical anomaly triggered session termination",
        severity="CRITICAL",
        status="OPEN",
    )
    db_session.add(alert)
    db_session.commit()
    db_session.refresh(alert)

    headers = _login(client, admin.email)
    res = client.get(f"/api/admin/incidents/{alert.id}", headers=headers)
    assert res.status_code == 200
    d = res.json()

    # Historical risk & decision must NOT be replaced with ALLOW/ACCESS_GRANTED
    assert d["risk_assessment"]["risk_score"] == 0.91
    assert d["risk_assessment"]["risk_level"] == "HIGH"
    assert d["risk_assessment"]["risk_decision"] == "TERMINATE_SESSION"
    assert d["risk_assessment"]["enforcement_outcome"] == "TERMINATE_SESSION"
    assert d["risk_assessment"]["adaptive_auth_recommendation"] == "TERMINATE_AND_LOCK"
    assert d["session"]["status"] == "TERMINATED"

    # Missing baseline must be honest
    assert d["behavioral_signals"]["baseline_status"] == "COLD_START"
    assert d["behavioral_signals"]["baseline_samples"] == 0
    assert d["behavioral_signals"]["user_baseline"] == {}
    assert d["behavioral_signals"]["deviation_status"]["typing_speed_wpm"] == "No baseline data available"

    # Timeline chronological & deduplicated
    timeline_ids = [ev["id"] for ev in d["related_timeline"]]
    assert len(timeline_ids) == len(set(timeline_ids))
    assert timeline_ids.index(ev1.id) < timeline_ids.index(ev2.id)

    # Alert with NO security_event_id must report "Not recorded", never ALLOW/ACCESS_GRANTED
    unlinked = Alert(
        user_id=human.id,
        security_event_id=None,
        application="shopping",
        alert_type="POLICY_VIOLATION",
        message="Unlinked alert",
        severity="HIGH",
        status="OPEN",
    )
    db_session.add(unlinked)
    db_session.commit()
    db_session.refresh(unlinked)

    res_u = client.get(f"/api/admin/incidents/{unlinked.id}", headers=headers)
    assert res_u.status_code == 200
    du = res_u.json()
    assert du["risk_assessment"]["risk_decision"] == "Not recorded"
    assert du["risk_assessment"]["enforcement_outcome"] == "Not recorded"
    assert du["risk_assessment"]["risk_score"] is None


def test_incident_lifecycle_transitions_persist_and_audit(client, db_session):
    admin = _make_user(db_session, f"soc.triage.{secrets.token_hex(4)}@cognisec.ai", "Triage Admin", role="ADMIN")
    human = _make_user(db_session, f"dave.human.{secrets.token_hex(3)}@gmail.com", "Dave Human")

    alert = Alert(
        user_id=human.id,
        application="college",
        alert_type="SUSPICIOUS_VELOCITY",
        message="Rapid navigation detected",
        severity="HIGH",
        status="OPEN",
    )
    db_session.add(alert)
    db_session.commit()
    db_session.refresh(alert)

    headers = _login(client, admin.email)

    # Resolve incident
    r_res = client.post(
        f"/api/admin/alerts/{alert.id}/resolve",
        headers=headers,
        json={"status": "RESOLVED", "assigned_to": admin.email, "resolution_reason": "Verified", "notes": "Checked"},
    )
    assert r_res.status_code == 200
    assert r_res.json()["status"] == "RESOLVED"

    # Invalid direct transition RESOLVED -> ACKNOWLEDGED must be rejected
    bad_res = client.post(
        f"/api/admin/alerts/{alert.id}/resolve",
        headers=headers,
        json={"status": "ACKNOWLEDGED"},
    )
    assert bad_res.status_code == 400

    # Valid transition RESOLVED -> REOPENED
    reopen_res = client.post(
        f"/api/admin/alerts/{alert.id}/resolve",
        headers=headers,
        json={"status": "REOPENED", "notes": "New telemetry arrived"},
    )
    assert reopen_res.status_code == 200
    assert reopen_res.json()["status"] == "REOPENED"

    # Verify persistence and audit trail
    db_session.expire_all()
    refreshed = db_session.query(Alert).filter(Alert.id == alert.id).first()
    assert refreshed.status == "REOPENED"
    audit_evs = db_session.query(SecurityEvent).filter(
        SecurityEvent.user_id == human.id,
        SecurityEvent.event_type.in_(["ADMIN_ALERT_RESOLVED", "ADMIN_ALERT_REOPENED"]),
    ).all()
    assert len(audit_evs) >= 2


def test_audit_trail_categories_deduplication_and_sanitized_summary(client, db_session):
    admin = _make_user(db_session, f"soc.audit.{secrets.token_hex(4)}@cognisec.ai", "Audit Admin", role="ADMIN")
    human = _make_user(db_session, f"eve.audit.{secrets.token_hex(3)}@gmail.com", "Eve Audit")
    sess_id = f"sess_aud_{secrets.token_hex(5)}"
    now = datetime.now(timezone.utc)
    db_session.add(DbSession(
        id=sess_id,
        user_id=human.id,
        application="shopping",
        status="ACTIVE",
    ))
    db_session.commit()

    # 3 consecutive identical AGENTIC_BEHAVIOR_RISK_TRANSITION rows within 15 seconds
    for idx in range(3):
        db_session.add(SecurityEvent(
            user_id=human.id,
            session_id=sess_id,
            application="shopping",
            event_type="AGENTIC_BEHAVIOR_RISK_TRANSITION",
            severity="LOW",
            risk_score=0.1,
            decision="TIMEOUT_FALLBACK",
            details=json.dumps({
                "agentic_orchestration": {
                    "trigger_event": "BEHAVIOR_RISK_TRANSITION",
                    "execution_status": "TIMEOUT_FALLBACK",
                    "agents_executed": ["SecurityContextAgent"],
                    "llm_provider": "gemini",
                    "password": "secret_should_be_redacted",
                }
            }),
            timestamp=now - timedelta(seconds=idx * 5),
        ))
    db_session.commit()

    headers = _login(client, admin.email)
    res = client.get(
        f"/api/admin/audit-trail?activity_scope=all&search={sess_id}&category=Agentic%20AI%20Activity&application=shopping&risk_level=LOW",
        headers=headers,
    )
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == 1
    item = body["items"][0]
    assert item["category"] == "Agentic AI Activity"
    assert item["result"] == "Fallback (Timeout)"
    assert item["repeat_count"] == 3
    assert not item["summary"].startswith("{")
    assert "secret_should_be_redacted" not in json.dumps(item)


def test_security_intelligence_overview_detail_adaptive_and_agentic(client, db_session):
    admin = _make_user(db_session, f"soc.intel.{secrets.token_hex(4)}@cognisec.ai", "Intel Admin", role="ADMIN")
    human = _make_user(db_session, f"intel.human.{secrets.token_hex(3)}@gmail.com", "Intel Human")
    human.registration_source = "PUBLIC_REGISTRATION"
    human.email_verified = True
    db_session.commit()
    sess_id = f"sess_int_{secrets.token_hex(5)}"
    now = datetime.now(timezone.utc)

    db_session.add(DbSession(id=sess_id, user_id=human.id, application="healthcare", status="ACTIVE"))
    db_session.add(BehaviorLog(
        user_id=human.id,
        session_id=sess_id,
        application="healthcare",
        timestamp=now,
        typing_speed_wpm=62.0,
        avg_flight_time_ms=110.0,
        avg_dwell_time_ms=85.0,
        mouse_velocity_avg=920.0,
        mouse_acceleration_avg=4100.0,
        mouse_curvature_entropy=0.62,
        click_frequency=0.25,
        scroll_speed_avg=450.0,
        idle_duration_sec=1.5,
        navigation_entropy=1.35,
    ))
    db_session.add(BehaviorProfile(
        user_id=human.id,
        sample_count=25,
        profile_version=2,
        baseline_features=json.dumps({
            "model_version": "IF-v2.0-Welford",
            "means": {
                "typing_speed_wpm": 45.0, "avg_flight_time_ms": 130.0, "avg_dwell_time_ms": 95.0,
                "mouse_velocity_avg": 700.0, "mouse_acceleration_avg": 3000.0, "mouse_curvature_entropy": 0.45,
                "click_frequency": 0.15, "scroll_speed_avg": 350.0, "idle_duration_sec": 3.0, "navigation_entropy": 0.9,
            },
            "stds": {
                "typing_speed_wpm": 5.0, "avg_flight_time_ms": 10.0, "avg_dwell_time_ms": 8.0,
                "mouse_velocity_avg": 50.0, "mouse_acceleration_avg": 200.0, "mouse_curvature_entropy": 0.05,
                "click_frequency": 0.05, "scroll_speed_avg": 40.0, "idle_duration_sec": 1.0, "navigation_entropy": 0.1,
            },
        }),
    ))
    ev_behav = SecurityEvent(
        user_id=human.id,
        session_id=sess_id,
        application="healthcare",
        event_type="AGENTIC_BEHAVIOR_RISK_TRANSITION",
        severity="HIGH",
        anomaly_score=0.78,
        risk_score=0.72,
        decision="STEP_UP_REQUIRED",
        details=json.dumps({
            "agentic_orchestration": {
                "trigger_event": "BEHAVIOR_RISK_TRANSITION",
                "prior_risk_level": "LOW",
                "execution_status": "TIMEOUT_FALLBACK",
                "agents_executed": ["SecurityContextAgent:fallback"],
                "llm_provider": "gemini",
                "fallback_or_error": "TimeoutError",
            }
        }),
        timestamp=now,
    )
    ev_issued = SecurityEvent(
        user_id=human.id,
        session_id=sess_id,
        application="healthcare",
        event_type="STEP_UP_CHALLENGE_ISSUED",
        severity="HIGH",
        risk_score=0.72,
        decision="CHALLENGE",
        details="Adaptive challenge 'GESTURE_PATTERN' issued for application 'healthcare'.",
        timestamp=now + timedelta(seconds=1),
    )
    ev_verified = SecurityEvent(
        user_id=human.id,
        session_id=sess_id,
        application="healthcare",
        event_type="STEP_UP_VERIFIED",
        severity="LOW",
        risk_score=0.18,
        decision="ALLOW",
        details="NeuralTrace gesture pattern verified successfully.",
        timestamp=now + timedelta(seconds=5),
    )
    db_session.add_all([ev_behav, ev_issued, ev_verified])
    db_session.commit()
    db_session.refresh(ev_behav)

    # Non-admin must be rejected
    user_headers = _login(client, human.email)
    assert client.get("/api/admin/security-intelligence/overview", headers=user_headers).status_code == 403

    admin_headers = _login(client, admin.email)

    # Overview counts (activity_scope=all includes agentic + user; default user scope excludes agentic/demo/admin)
    ov_res = client.get(f"/api/admin/security-intelligence/overview?activity_scope=all&application=healthcare&search={human.email}", headers=admin_headers)
    assert ov_res.status_code == 200
    ov = ov_res.json()
    assert ov["risk_transitions_count"] >= 1
    assert ov["step_up_challenges_count"] >= 1
    assert ov["successful_verifications_count"] >= 1
    assert ov["agentic_executions_count"] >= 1

    # Default user-activity scope must exclude AGENT_DEMO_ANALYSIS, ADMIN_RESCAN, and admin user events
    db_session.add(SecurityEvent(
        user_id=admin.id,
        application="healthcare",
        event_type="AGENT_DEMO_ANALYSIS",
        severity="CRITICAL",
        anomaly_score=0.0,
        risk_score=0.89,
        decision="TERMINATE_SESSION",
        details='{"summary": "Synthetic CRITICAL demo"}',
    ))
    db_session.add(SecurityEvent(
        user_id=human.id,
        session_id=sess_id,
        application="healthcare",
        event_type="LOGIN_SUCCESS",
        severity="LOW",
        anomaly_score=0.0,
        risk_score=0.0,
        decision="ALLOW",
        details='{"portal": "healthcare"}',
    ))
    db_session.commit()
    user_tl = client.get(f"/api/admin/audit-trail?user_id={human.id}", headers=admin_headers)
    assert user_tl.status_code == 200
    user_codes = {it["action_code"] for it in user_tl.json()["items"]}
    assert "LOGIN_SUCCESS" in user_codes
    assert "AGENT_DEMO_ANALYSIS" not in user_codes
    assert "AGENTIC_BEHAVIOR_RISK_TRANSITION" not in user_codes

    default_tl = client.get("/api/admin/audit-trail?page_size=50", headers=admin_headers)
    assert default_tl.status_code == 200
    for it in default_tl.json()["items"]:
        assert it["action_code"] != "AGENT_DEMO_ANALYSIS"
        assert not it["action_code"].startswith("ADMIN_")
        assert it["target_user_email"] != admin.email

    # Event detail with 10 canonical features & honest fallback labeling
    det_res = client.get(f"/api/admin/security-intelligence/events/{ev_behav.id}/detail", headers=admin_headers)
    assert det_res.status_code == 200
    det = det_res.json()
    assert det["event"]["previous_risk_level"] == "LOW"
    assert det["event"]["risk_level"] == "HIGH"
    bi = det["behavioural_intelligence"]
    assert bi["telemetry_available"] is True
    assert bi["baseline_available"] is True
    assert bi["sample_count"] == 25
    assert len(bi["features"]) == 10
    assert det["arbiter_decision"]["decision"] == "STEP_UP_REQUIRED"
    assert any(a["analysis_status"] in ("TIMEOUT_FALLBACK", "FALLBACK") for a in det["agent_executions"])

    # Adaptive history distinguishes ISSUED from VERIFIED
    ad_res = client.get(f"/api/admin/security-intelligence/adaptive-history?search={human.email}", headers=admin_headers)
    assert ad_res.status_code == 200
    statuses = {r["challenge_status"] for r in ad_res.json()}
    assert "ISSUED" in statuses and "VERIFIED" in statuses

    # Agentic intelligence view
    ag_res = client.get(f"/api/admin/security-intelligence/agentic-intelligence?search={human.email}", headers=admin_headers)
    assert ag_res.status_code == 200
    assert len(ag_res.json()["executions"]) >= 1

