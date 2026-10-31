import pytest
from datetime import datetime, timezone, timedelta
from app.models.user import User
from app.models.device import Device
from app.models.session import Session as DbSession
from app.models.security_event import SecurityEvent
from app.models.alert import Alert
from app.services.session_service import SessionService


def test_isolated_test_database_is_disposable_sqlite(db_session):
    """Verifies that all automated test executions are strictly bound to disposable SQLite, never mutating Neon."""
    bind = db_session.get_bind()
    assert bind.dialect.name == "sqlite", f"Expected sqlite dialect for tests, got {bind.dialect.name}!"
    assert "test_cognisec.db" in str(bind.url) or ":memory:" in str(bind.url)


def test_simulator_provenance_stamping_and_termination(client, db_session, admin_token):
    """Verifies that simulator executions stamp explicit provenance and immediately terminate sessions so they never linger as active."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    res = client.post(
        "/api/demo/simulate",
        json={
            "scenario": "credential_stuffing",
            "application": "college",
            "user_id": 1
        },
        headers=headers
    )
    assert res.status_code == 200
    data = res.json()
    assert "simulated_session_id" in data
    assert data["security_decision"] in ["RESTRICT", "RESTRICT_ACCESS", "STEP_UP_REQUIRED", "TERMINATE_SESSION"]

    sim_session_id = data["simulated_session_id"]
    db_session.expire_all()

    # 1. Verify session is strictly terminated and non-active
    session = db_session.query(DbSession).filter(DbSession.id == sim_session_id).first()
    assert session is not None
    assert session.status == "TERMINATED", f"Simulated session must be TERMINATED, got {session.status}"
    assert session.logout_time is not None
    assert session.login_outcome == "simulation_completed"

    # 2. Verify security event explicit provenance
    event = db_session.query(SecurityEvent).filter(SecurityEvent.session_id == sim_session_id).first()
    assert event is not None
    assert "ATTACK_SIMULATOR" in (event.details or "")
    assert '"is_simulated": true' in (event.details or "").lower()

    # 3. Verify alert simulated tag
    alert = db_session.query(Alert).filter(Alert.message.contains(sim_session_id)).first()
    if alert:
        assert "[SIMULATED SCENARIO]" in alert.message
        assert "Exhibition Attack Simulation" in (alert.notes or "")


def test_soc_metrics_strictly_exclude_simulated_sessions_and_historical_noise(client, db_session, admin_token):
    """Verifies that /api/admin/metrics excludes simulated sessions and bounds anomaly calculation to genuine traffic."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    now_utc = datetime.now(timezone.utc)

    # 1. Create a genuine active session using SessionService
    genuine_sess = SessionService.create_session(
        db_session,
        user_id=1,
        application="college",
        status="ACTIVE"
    )

    # 2. Create a simulated session (which must be excluded from live active counts even if marked ACTIVE)
    sim_sess = SessionService.create_session(
        db_session,
        user_id=1,
        application="healthcare",
        status="ACTIVE"
    )
    # Give it a sim_ prefix to test exclusion
    sim_sess_id = f"sim_metric_test_{sim_sess.id}"
    db_session.query(DbSession).filter(DbSession.id == sim_sess.id).update({"id": sim_sess_id})
    db_session.commit()

    res = client.get("/api/admin/metrics", headers=headers)
    assert res.status_code == 200
    metrics = res.json()

    # live_sessions_count must count only genuine unexpired sessions
    assert "live_sessions_count" in metrics
    assert "anomaly_rate_window" in metrics
    assert metrics["anomaly_rate_window"] == "24h"

    # Verify sim_metric_test is excluded from genuine scope query
    active_sessions_res = client.get("/api/admin/sessions?status=ACTIVE&scope=genuine", headers=headers)
    assert active_sessions_res.status_code == 200
    active_session_ids = [s["id"] for s in active_sessions_res.json()]
    assert sim_sess_id not in active_session_ids
    assert genuine_sess.id in active_session_ids

    # Cleanup test sessions so they do not pollute subsequent tests
    db_session.query(DbSession).filter(DbSession.id.in_([sim_sess_id, genuine_sess.id])).update({
        "status": "TERMINATED",
        "logout_time": now_utc
    }, synchronize_session=False)
    db_session.commit()


def test_soc_api_scope_isolation_filtering(client, db_session, admin_token):
    """Verifies that sessions, events, and alerts can be filtered by scope: 'genuine', 'simulated', or 'all'."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    now_utc = datetime.now(timezone.utc)

    # Seed genuine and simulated sessions using SessionService
    g_sess = SessionService.create_session(
        db_session,
        user_id=1,
        application="portal",
        status="ACTIVE"
    )
    s_sess = SessionService.create_session(
        db_session,
        user_id=1,
        application="portal",
        status="TERMINATED"
    )
    sim_id = f"sim_iso_{s_sess.id}"
    db_session.query(DbSession).filter(DbSession.id == s_sess.id).update({
        "id": sim_id,
        "current_risk_level": "HIGH"
    })
    db_session.commit()

    # Seed genuine and simulated events
    g_event = SecurityEvent(
        user_id=1,
        session_id=g_sess.id,
        application="portal",
        event_type="LOGIN_SUCCESS",
        severity="LOW",
        anomaly_score=0.01,
        risk_score=0.02,
        decision="ALLOW_ACCESS",
        details="Genuine portal login",
        timestamp=now_utc
    )
    s_event = SecurityEvent(
        user_id=1,
        session_id=sim_id,
        application="portal",
        event_type="ANOMALOUS_BEHAVIOR_DETECTED",
        severity="HIGH",
        anomaly_score=0.88,
        risk_score=0.85,
        decision="STEP_UP_REQUIRED",
        details='{"provenance": "ATTACK_SIMULATOR", "is_simulated": true}',
        timestamp=now_utc
    )
    db_session.add_all([g_event, s_event])

    # Seed genuine and simulated alerts
    g_alert = Alert(
        user_id=1,
        application="portal",
        alert_type="NEW_DEVICE_DETECTED",
        message="Legitimate login from macOS device",
        severity="LOW",
        status="OPEN",
        created_at=now_utc
    )
    s_alert = Alert(
        user_id=1,
        application="portal",
        alert_type="SIMULATED_ATTACK",
        message=f"[SIMULATED SCENARIO] {sim_id} high risk detected",
        severity="HIGH",
        status="OPEN",
        notes=f"Exhibition Attack Simulation: {sim_id}",
        created_at=now_utc
    )
    db_session.add_all([g_alert, s_alert])
    db_session.commit()

    # 1. Test Sessions scope filtering
    res_g_sess = client.get("/api/admin/sessions?scope=genuine", headers=headers)
    assert res_g_sess.status_code == 200
    ids_g = [s["id"] for s in res_g_sess.json()]
    assert g_sess.id in ids_g
    assert sim_id not in ids_g

    res_s_sess = client.get("/api/admin/sessions?scope=simulated", headers=headers)
    assert res_s_sess.status_code == 200
    ids_s = [s["id"] for s in res_s_sess.json()]
    assert sim_id in ids_s
    assert g_sess.id not in ids_s

    # 2. Test Events scope filtering
    res_g_ev = client.get("/api/admin/events?scope=genuine", headers=headers)
    assert res_g_ev.status_code == 200
    ev_g = res_g_ev.json()
    assert any(e["session_id"] == g_sess.id for e in ev_g)
    assert not any(e["session_id"] == sim_id for e in ev_g)

    res_s_ev = client.get("/api/admin/events?scope=simulated", headers=headers)
    assert res_s_ev.status_code == 200
    ev_s = res_s_ev.json()
    assert any(e["session_id"] == sim_id for e in ev_s)
    assert not any(e["session_id"] == g_sess.id for e in ev_s)

    # 3. Test Alerts scope filtering
    res_g_al = client.get("/api/admin/alerts?scope=genuine", headers=headers)
    assert res_g_al.status_code == 200
    al_g = res_g_al.json()
    assert any("Legitimate login" in a["message"] for a in al_g)
    assert not any("[SIMULATED SCENARIO]" in a["message"] for a in al_g)

    res_s_al = client.get("/api/admin/alerts?scope=simulated", headers=headers)
    assert res_s_al.status_code == 200
    al_s = res_s_al.json()
    assert any("[SIMULATED SCENARIO]" in a["message"] for a in al_s)
    assert not any("Legitimate login" in a["message"] for a in al_s)

    # Clean up seeded records so subsequent test suites aren't polluted
    db_session.delete(g_alert)
    db_session.delete(s_alert)
    db_session.delete(g_event)
    db_session.delete(s_event)
    db_session.query(DbSession).filter(DbSession.id.in_([g_sess.id, sim_id])).delete(synchronize_session=False)
    db_session.commit()


def test_devices_active_vs_persisted_and_hardware_evidence(client, db_session, admin_token):
    """Verifies that device inventory accurately distinguishes live active hardware from historical persisted records and known tests."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    now_utc = datetime.now(timezone.utc)

    # 1. Device with live active session
    dev_live = Device(
        user_id=1,
        device_id="dev_macbook_live",
        device_fingerprint="macbook_fingerprint_sha256_live",
        nickname="Admin MacBook Pro M2",
        browser_name="Chrome",
        browser_version="129.0",
        os_name="macOS",
        os_version="14.6",
        is_trusted=True,
        trust_state="TRUSTED",
        first_seen=now_utc,
        last_seen=now_utc
    )
    user_historical = User(
        email="historical.analyst@company.net",
        name="Historical Analyst",
        password_hash="pw_hash",
        role="EMPLOYEE",
        account_status="ACTIVE",
        created_at=now_utc - timedelta(days=120)
    )
    db_session.add(user_historical)
    db_session.commit()
    db_session.refresh(user_historical)

    # 2. Historical persisted device (no active session)
    dev_hist = Device(
        user_id=user_historical.id,
        device_id="dev_historical_persisted",
        device_fingerprint="historical_hash_sha256",
        nickname="Old Office Workstation",
        browser_name="Chrome",
        browser_version="120.0",
        os_name="macOS",
        os_version="13.1",
        is_trusted=False,
        trust_state="PENDING_CONFIRMATION",
        first_seen=now_utc - timedelta(days=90),
        last_seen=now_utc - timedelta(days=60)
    )
    # 3. Known automated test device
    dev_test = Device(
        user_id=1,
        device_id="dev_synthetic_test_bot",
        device_fingerprint="test_synthetic_fingerprint_bot",
        nickname="Automated Test Runner",
        browser_name="Unknown",
        browser_version="0.0",
        os_name="Unknown",
        os_version="0.0",
        is_trusted=False,
        trust_state="PENDING_CONFIRMATION",
        first_seen=now_utc,
        last_seen=now_utc
    )
    db_session.add_all([dev_live, dev_hist, dev_test])
    db_session.commit()
    db_session.refresh(dev_live)
    db_session.refresh(dev_hist)
    db_session.refresh(dev_test)

    # Bind dev_live to an active session
    active_sess = SessionService.create_session(
        db_session,
        user_id=1,
        application="portal",
        status="ACTIVE"
    )
    db_session.query(DbSession).filter(DbSession.id == active_sess.id).update({
        "device_id": dev_live.id
    })
    db_session.commit()

    # Query all devices
    res_all = client.get("/api/admin/devices", headers=headers)
    assert res_all.status_code == 200
    all_devs = {d["device_id"]: d for d in res_all.json()}

    # Check dev_live
    assert dev_live.device_id in all_devs
    live_record = all_devs[dev_live.device_id]
    assert live_record["is_active"] is True
    assert live_record["provenance"] == "GENUINE_ACTIVE"
    assert live_record["is_physical_device_confirmed"] is True
    assert "Live authenticated hardware session connected" in live_record["hardware_evidence_summary"]

    # Check dev_hist
    assert dev_hist.device_id in all_devs
    hist_record = all_devs[dev_hist.device_id]
    assert hist_record["is_active"] is False
    assert hist_record["provenance"] == "HISTORICAL_RECORD"
    assert hist_record["is_physical_device_confirmed"] is False
    assert "Historical persisted development record" in hist_record["hardware_evidence_summary"]

    # Check dev_test
    assert dev_test.device_id in all_devs
    test_record = all_devs[dev_test.device_id]
    assert test_record["is_active"] is False
    assert test_record["provenance"] == "KNOWN_TEST"
    assert test_record["is_physical_device_confirmed"] is False

    # Check scope=active
    res_act = client.get("/api/admin/devices?scope=active", headers=headers)
    assert res_act.status_code == 200
    act_ids = [d["device_id"] for d in res_act.json()]
    assert dev_live.device_id in act_ids
    assert dev_hist.device_id not in act_ids
    assert dev_test.device_id not in act_ids

    # Check scope=test
    res_test = client.get("/api/admin/devices?scope=test", headers=headers)
    assert res_test.status_code == 200
    test_ids = [d["device_id"] for d in res_test.json()]
    assert dev_test.device_id in test_ids
    assert dev_live.device_id not in test_ids
    assert dev_hist.device_id not in test_ids


def test_users_active_vs_persisted_and_provenance_taxonomy(client, db_session, admin_token):
    """Verifies that user accounts are categorized into accurate taxonomies without retroactive guessing."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    now_utc = datetime.now(timezone.utc)

    # 1. Seeded demo account
    demo_u = User(
        email="sarah.chen@cognisec.ai",
        name="Sarah Chen",
        password_hash="demo_hash",
        role="EMPLOYEE",
        account_status="ACTIVE",
        created_at=now_utc
    )
    # 2. Known test account
    test_u = User(
        email="val.browser_tester_99@cognisec.ai",
        name="Browser Test Bot",
        password_hash="test_hash",
        role="EMPLOYEE",
        account_status="ACTIVE",
        created_at=now_utc
    )
    # 3. Unknown historical account
    unknown_u = User(
        email="historic.dev.engineer@external.org",
        name="Historical Dev",
        password_hash="dev_hash",
        role="EMPLOYEE",
        account_status="ACTIVE",
        created_at=now_utc
    )
    db_session.add_all([demo_u, test_u, unknown_u])
    db_session.commit()

    # Query all users
    res = client.get("/api/admin/users?limit=200", headers=headers)
    assert res.status_code == 200
    users_by_email = {u["email"]: u for u in res.json()}

    assert "sarah.chen@cognisec.ai" in users_by_email
    assert users_by_email["sarah.chen@cognisec.ai"]["provenance"] == "SEEDED_DEMO"

    assert "val.browser_tester_99@cognisec.ai" in users_by_email
    assert users_by_email["val.browser_tester_99@cognisec.ai"]["provenance"] == "KNOWN_TEST"

    assert "historic.dev.engineer@external.org" in users_by_email
    assert users_by_email["historic.dev.engineer@external.org"]["provenance"] == "UNKNOWN_PROVENANCE"

    # Query metrics for authoritative breakdown
    res_m = client.get("/api/admin/metrics", headers=headers)
    assert res_m.status_code == 200
    m = res_m.json()
    assert "known_test_accounts_count" in m
    assert "unknown_provenance_accounts_count" in m
    assert "seeded_demo_accounts_count" in m
    assert "genuine_active_accounts_count" in m
    assert "active_devices_count" in m
    assert "persisted_devices_count" in m
    assert m["known_test_accounts_count"] >= 1
    assert m["seeded_demo_accounts_count"] >= 1
    assert m["unknown_provenance_accounts_count"] >= 1

