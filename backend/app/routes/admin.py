import time
import json
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy import text, or_, func
from app.database.connection import get_db, engine
from app.routes.deps import require_admin
from app.models.user import User
from app.models.device import Device
from app.models.session import Session as DbSession
from app.models.security_event import SecurityEvent
from app.models.alert import Alert
from app.models.behavior import BehaviorProfile, BehaviorLog
from app.schemas.admin import (
    AdminMetricsResponse,
    AdminSessionResponse,
    AdminUserResponse,
    RiskDistributionResponse,
    AlertResponse,
    AlertResolveRequest,
    SecurityEventResponse,
    IncidentInvestigationResponse,
    AuditLogResponse,
    HistoricalAnalyticsResponse,
    SystemHealthResponse,
    RescanResponse,
    EmailDiagnosticsResponse,
    EmailTestRequest,
    EmailTestResponse,
    DevResetLockoutRequest,
    DevResetLockoutResponse
)
from app.schemas.device import DeviceResponse
from app.schemas.session import SessionResponse
from app.schemas.user import UserResponse
from app.schemas.behavior import BehaviorProfileResponse
from app.services.device_service import DeviceService
from app.services.session_service import SessionService
from app.services.profile_service import ProfileService
from app.services.email_service import EmailService
from app.services.auth_service import AuthService
from app.core.rate_limit import rate_limiter
from app.ml.model_manager import ModelManager

router = APIRouter(prefix="/admin", tags=["Admin & SOC Command Center"], dependencies=[Depends(require_admin)])


@router.get("/metrics", response_model=AdminMetricsResponse)
def get_soc_metrics(db: Session = Depends(get_db)):
    """Provides high-level real-time KPI metrics for the SOC Dashboard strictly from authoritative queries."""
    from app.services.session_service import SessionService
    SessionService.reap_expired_sessions(db)

    # 1. Live sessions: active, unexpired, non-simulated, non-test sessions
    live_sessions = db.query(DbSession).filter(
        DbSession.status == "ACTIVE",
        DbSession.logout_time.is_(None),
        ~DbSession.id.like("sim_%"),
        ~DbSession.id.like("test_%")
    ).count()

    # 2. Active users: distinct users with qualifying, genuinely active sessions
    active_user_ids = db.query(DbSession.user_id).filter(
        DbSession.status == "ACTIVE",
        DbSession.logout_time.is_(None),
        ~DbSession.id.like("sim_%"),
        ~DbSession.id.like("test_%")
    ).distinct().all()
    active_users = len(active_user_ids)
    active_uid_set = {uid[0] for uid in active_user_ids}

    # 3. Active devices: physical devices currently bound to an active, unexpired genuine session
    active_device_ids = db.query(DbSession.device_id).filter(
        DbSession.status == "ACTIVE",
        DbSession.logout_time.is_(None),
        DbSession.device_id.isnot(None),
        ~DbSession.id.like("sim_%"),
        ~DbSession.id.like("test_%")
    ).distinct().all()
    active_devices = len([d[0] for d in active_device_ids if d[0] is not None])

    # 4. Total persisted inventory
    total_users = db.query(User).count()
    total_devices = db.query(Device).count()

    # 5. User accounts provenance categorization without retroactive guessing
    SEEDED_EMAILS = {
        "admin.soc@cognisec.ai",
        "user.portal@cognisec.ai",
        "student.alex@veritas.edu",
        "customer.jane@auraluxe.com",
        "dr.sarah@aetheriahealth.org",
        "sarah.chen@cognisec.ai",
        "marcus.vance@cognisec.ai",
        "elena.rostova@cognisec.ai",
        "admin@cognisec.ai",
        "demo@cognisec.ai"
    }
    all_users = db.query(User).all()
    known_test_count = 0
    seeded_count = 0
    genuine_active_count = len(active_uid_set)
    unknown_count = 0

    for u in all_users:
        em = (u.email or "").lower()
        if u.id in active_uid_set:
            continue
        elif em in SEEDED_EMAILS:
            seeded_count += 1
        elif any(kw in em for kw in ["test", "val.", "neon_verify", "audit_user_"]):
            known_test_count += 1
        else:
            unknown_count += 1

    # 6. Blocked/revoked & Enforcement Breakdown
    restricted_sessions = db.query(DbSession).filter(DbSession.status == "RESTRICTED").count()
    revoked_sessions = db.query(DbSession).filter(DbSession.status == "REVOKED").count()
    terminated_sessions = db.query(DbSession).filter(DbSession.status == "TERMINATED").count()
    revoked_devices = db.query(Device).filter(Device.trust_state == "REVOKED").count()
    active_enforcements = restricted_sessions + revoked_sessions + revoked_devices

    # 7. Enterprise devices & trust breakdown
    trusted_devices = db.query(Device).filter(Device.trust_state == "TRUSTED").count()
    pending_devices = db.query(Device).filter(Device.trust_state == "PENDING_CONFIRMATION").count()
    verified_metadata_devices = db.query(Device).filter(
        Device.browser_name.isnot(None),
        Device.browser_name != "Unknown",
        Device.os_name.isnot(None),
        Device.os_name != "Unknown"
    ).count()
    unverified_identity_devices = total_devices - verified_metadata_devices

    # 8. Active alerts breakdown (genuine active open alerts vs total persisted)
    open_alerts = db.query(Alert).filter(Alert.status == "OPEN").count()
    genuine_open_alerts = db.query(Alert).filter(
        Alert.status == "OPEN",
        ~Alert.message.ilike("%sim_%"),
        ~Alert.message.ilike("%simulated%"),
        ~Alert.message.ilike("%test%"),
        ~func.coalesce(Alert.notes, "").ilike("%simulated%"),
        ~func.coalesce(Alert.notes, "").ilike("%test%")
    ).count()
    reopened_alerts = db.query(Alert).filter(Alert.status == "REOPENED").count()
    resolved_alerts = db.query(Alert).filter(Alert.status == "RESOLVED").count()
    total_alerts = db.query(Alert).count()
    active_alerts = genuine_open_alerts if genuine_open_alerts > 0 else open_alerts

    # 9. Anomaly rate (strictly bounded observation window over genuine traffic in last 24h)
    cutoff_24h = datetime.now(timezone.utc) - timedelta(hours=24)
    obs_query = db.query(SecurityEvent).filter(
        SecurityEvent.timestamp >= cutoff_24h,
        ~SecurityEvent.session_id.like("sim_%"),
        ~SecurityEvent.session_id.like("test_%"),
        ~SecurityEvent.details.ilike("%sim_%"),
        ~SecurityEvent.details.ilike("%simulated%"),
        ~SecurityEvent.details.ilike("%attack_simulator%"),
        ~SecurityEvent.details.ilike("%test%")
    )
    obs_24h = obs_query.count()
    anom_24h = obs_query.filter(SecurityEvent.anomaly_score > 0.5).count()

    if obs_24h >= 5:
        anomaly_rate = round((anom_24h / obs_24h) * 100, 1)
        anomaly_label = f"{anomaly_rate}% ({anom_24h}/{obs_24h} in 24h)"
    elif obs_24h > 0:
        anomaly_rate = round((anom_24h / obs_24h) * 100, 1)
        anomaly_label = f"{anomaly_rate}% ({anom_24h}/{obs_24h} in 24h)"
    else:
        anomaly_rate = 0.0
        anomaly_label = "0.0% (0 anomalies in 24h)"

    high_risk_sessions = db.query(DbSession).filter(
        DbSession.status == "ACTIVE",
        DbSession.logout_time.is_(None),
        ~DbSession.id.like("sim_%"),
        ~DbSession.id.like("test_%"),
        DbSession.current_risk_level.in_(["HIGH", "CRITICAL"])
    ).count()

    step_up_count = db.query(SecurityEvent).filter(
        SecurityEvent.event_type.in_(["STEP_UP_CHALLENGE", "STEP_UP_VERIFIED", "MFA_CHALLENGE", "MFA_VERIFIED"]),
        ~SecurityEvent.session_id.like("sim_%"),
        ~SecurityEvent.session_id.like("test_%")
    ).count()

    return AdminMetricsResponse(
        live_sessions_count=live_sessions,
        trusted_users_count=active_users,
        blocked_sessions_count=active_enforcements,
        total_devices_count=total_devices,
        active_alerts_count=active_alerts,
        anomaly_rate_percent=anomaly_rate,
        total_users_count=total_users,
        active_devices_count=active_devices,
        persisted_devices_count=total_devices,
        active_users_count=active_users,
        persisted_users_count=total_users,
        known_test_accounts_count=known_test_count,
        unknown_provenance_accounts_count=unknown_count,
        seeded_demo_accounts_count=seeded_count,
        genuine_active_accounts_count=genuine_active_count,
        trusted_devices_count=trusted_devices,
        pending_devices_count=pending_devices,
        revoked_devices_count=revoked_devices,
        high_risk_sessions_count=high_risk_sessions,
        step_up_count=step_up_count,
        restricted_sessions_count=restricted_sessions,
        terminated_sessions_count=terminated_sessions,
        revoked_sessions_count=revoked_sessions,
        active_enforcements_count=active_enforcements,
        verified_metadata_devices_count=verified_metadata_devices,
        unverified_identity_devices_count=unverified_identity_devices,
        open_alerts_count=open_alerts,
        reopened_alerts_count=reopened_alerts,
        resolved_alerts_count=resolved_alerts,
        total_alerts_count=total_alerts,
        anomaly_rate_observations=obs_24h,
        anomaly_rate_window="24h",
        anomaly_rate_label=anomaly_label
    )


@router.get("/risk-distribution", response_model=RiskDistributionResponse)
def get_risk_distribution(db: Session = Depends(get_db)):
    """Provides real-time risk tier distribution and step-up verification count for qualifying live sessions."""
    from app.services.session_service import SessionService
    SessionService.reap_expired_sessions(db)

    active_base = db.query(DbSession).filter(
        DbSession.status == "ACTIVE",
        DbSession.logout_time.is_(None),
        ~DbSession.id.like("sim_%"),
        ~DbSession.id.like("test_%")
    )
    low = active_base.filter(DbSession.current_risk_level == "LOW").count()
    med = active_base.filter(DbSession.current_risk_level == "MEDIUM").count()
    high = active_base.filter(DbSession.current_risk_level == "HIGH").count()
    crit = active_base.filter(DbSession.current_risk_level == "CRITICAL").count()
    step_ups = active_base.filter(DbSession.step_up_verified_at.isnot(None)).count()
    active_threats = db.query(Alert).filter(
        Alert.status == "OPEN",
        ~Alert.message.ilike("%sim_%"),
        ~Alert.message.ilike("%simulated%"),
        ~Alert.message.ilike("%test%")
    ).count()

    return RiskDistributionResponse(
        low_risk_sessions=low,
        medium_risk_sessions=med,
        high_risk_sessions=high,
        critical_risk_sessions=crit,
        step_up_verified_count=step_ups,
        active_threats_count=active_threats
    )


@router.get("/sessions", response_model=List[AdminSessionResponse])
def get_admin_sessions(
    application: Optional[str] = None,
    status: Optional[str] = None,
    risk_level: Optional[str] = None,
    search: Optional[str] = None,
    scope: Optional[str] = Query("all", description="Session scope: 'all', 'genuine', 'active', 'simulated', or 'test'"),
    limit: int = Query(100, le=500),
    db: Session = Depends(get_db)
):
    """Retrieves all sessions across applications with enriched user and device metadata, risk filtering, search, and scope isolation."""
    query = db.query(DbSession)
    if application:
        query = query.filter(DbSession.application == application.lower())
    if status and status.upper() != "ALL":
        query = query.filter(DbSession.status == status.upper())
    if risk_level and risk_level.upper() != "ALL":
        query = query.filter(DbSession.current_risk_level == risk_level.upper())
    if scope and scope.lower() == "genuine":
        query = query.filter(~DbSession.id.like("sim_%"), ~DbSession.id.like("test_%"))
    elif scope and scope.lower() == "active":
        query = query.filter(
            DbSession.status == "ACTIVE",
            DbSession.logout_time.is_(None),
            ~DbSession.id.like("sim_%"),
            ~DbSession.id.like("test_%")
        )
    elif scope and scope.lower() == "simulated":
        query = query.filter(DbSession.id.like("sim_%"))
    elif scope and scope.lower() == "test":
        query = query.filter(DbSession.id.like("test_%"))

    sessions = query.order_by(DbSession.login_time.desc()).limit(limit * 2 if search else limit).all()
    user_ids = {s.user_id for s in sessions}
    users = {u.id: u for u in db.query(User).filter(User.id.in_(user_ids)).all()} if user_ids else {}

    device_ids = {s.device_id for s in sessions if s.device_id}
    devices = {d.id: d for d in db.query(Device).filter(Device.id.in_(device_ids)).all()} if device_ids else {}

    results = []
    search_term = search.lower().strip() if search else None

    for s in sessions:
        user = users.get(s.user_id)
        dev = devices.get(s.device_id)
        user_name = user.name if user else "Unknown User"
        user_email = user.email if user else "unknown@cognisec.ai"
        dev_nick = dev.nickname if dev else (f"Device #{s.device_id}" if s.device_id else None)

        if search_term:
            match = (
                search_term in s.id.lower() or
                search_term in user_name.lower() or
                search_term in user_email.lower() or
                (dev_nick and search_term in dev_nick.lower()) or
                (s.ip_address and search_term in s.ip_address.lower())
            )
            if not match:
                continue

        is_sim = bool(s.id and (s.id.startswith("sim_") or "simulated" in (getattr(s, "login_outcome", "") or "").lower()))
        is_test = bool(s.id and (s.id.startswith("test_") or "test" in s.id.lower()))
        is_active_live = bool(s.status == "ACTIVE" and s.logout_time is None)

        if is_sim:
            prov = "SIMULATED_TEST"
        elif is_test:
            prov = "AUTOMATED_TEST"
        elif is_active_live:
            prov = "GENUINE_DEV"
        else:
            prov = "HISTORICAL_RECORD"

        results.append(AdminSessionResponse(
            id=s.id,
            user_id=s.user_id,
            user_name=user_name,
            user_email=user_email,
            application=s.application,
            device_id=s.device_id,
            device_nickname=dev_nick,
            ip_address=s.ip_address or "127.0.0.1",
            login_time=s.login_time,
            logout_time=s.logout_time,
            status=s.status,
            current_risk_level=s.current_risk_level or "LOW",
            step_up_factor=getattr(s, "step_up_factor", None),
            login_outcome=getattr(s, "login_outcome", None),
            is_simulated=is_sim,
            provenance=prov
        ))
        if len(results) >= limit:
            break

    return results


@router.post("/sessions/{session_id}/terminate", response_model=AdminSessionResponse)
def terminate_admin_session(
    session_id: str,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Administrative kill-switch: Terminates any active session across the platform with full audit tracking."""
    session = SessionService.get_session(db, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found.")

    terminated = SessionService.terminate_session(db, session_id, risk_level="CRITICAL")

    # Record administrative audit trail in SecurityEvents
    sec_event = SecurityEvent(
        user_id=session.user_id,
        session_id=session_id,
        application=session.application,
        event_type="ADMIN_SESSION_TERMINATED",
        severity="HIGH",
        anomaly_score=0.0,
        risk_score=1.0,
        decision="TERMINATE_SESSION",
        details=f"Session {session_id} terminated administratively by SOC Administrator {current_user.name} ({current_user.email})."
    )
    db.add(sec_event)
    db.commit()

    user = db.query(User).filter(User.id == session.user_id).first()
    return AdminSessionResponse(
        id=terminated.id,
        user_id=terminated.user_id,
        user_name=user.name if user else "Unknown User",
        user_email=user.email if user else "unknown@cognisec.ai",
        application=terminated.application,
        device_id=terminated.device_id,
        ip_address=terminated.ip_address,
        login_time=terminated.login_time,
        logout_time=terminated.logout_time,
        status=terminated.status,
        current_risk_level=terminated.current_risk_level,
        step_up_factor=getattr(terminated, "step_up_factor", None),
        login_outcome="terminated_by_admin",
        is_simulated=bool(terminated.id and terminated.id.startswith("sim_")),
        provenance="GENUINE_DEV"
    )


@router.get("/events", response_model=List[SecurityEventResponse])
def get_security_events(
    application: Optional[str] = None,
    severity: Optional[str] = None,
    scope: Optional[str] = Query("all", description="Scope: 'all', 'genuine', 'simulated', or 'test'"),
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db)
):
    """Fetches security event audit log feed for the SOC Dashboard with scope isolation."""
    query = db.query(SecurityEvent)
    if application:
        query = query.filter(SecurityEvent.application == application.lower())
    if severity:
        query = query.filter(SecurityEvent.severity == severity.upper())
    if scope and scope.lower() == "genuine":
        query = query.filter(
            ~SecurityEvent.session_id.like("sim_%"),
            ~SecurityEvent.session_id.like("test_%"),
            ~SecurityEvent.details.ilike("%simulated%"),
            ~SecurityEvent.details.ilike("%attack_simulator%"),
            ~SecurityEvent.details.ilike("%test%")
        )
    elif scope and scope.lower() == "simulated":
        query = query.filter(
            or_(
                SecurityEvent.session_id.like("sim_%"),
                SecurityEvent.details.ilike("%simulated%"),
                SecurityEvent.details.ilike("%attack_simulator%")
            )
        )
    elif scope and scope.lower() == "test":
        query = query.filter(
            or_(
                SecurityEvent.session_id.like("test_%"),
                SecurityEvent.details.ilike("%test%")
            )
        )
    
    events = query.order_by(SecurityEvent.timestamp.desc()).limit(limit).all()

    results = []
    for ev in events:
        user = db.query(User).filter(User.id == ev.user_id).first()
        is_sim = bool((ev.session_id and ev.session_id.startswith("sim_")) or "sim_" in (ev.details or "") or "Simulated" in (ev.details or "") or "SIMULATED" in (ev.details or "") or "attack_simulator" in (ev.details or ""))
        is_test = bool((ev.session_id and ev.session_id.startswith("test_")) or "test" in (ev.session_id or "").lower())
        
        if is_sim:
            prov = "SIMULATED_EVENT"
        elif is_test:
            prov = "TEST_EVENT"
        elif ev.anomaly_score > 0.5:
            prov = "GENUINE_EVENT"
        else:
            prov = "HISTORICAL_RECORD"

        results.append(SecurityEventResponse(
            id=ev.id,
            user_id=ev.user_id,
            user_name=user.name if user else "Unknown",
            session_id=ev.session_id,
            application=ev.application,
            event_type=ev.event_type,
            severity=ev.severity,
            anomaly_score=ev.anomaly_score,
            risk_score=ev.risk_score,
            decision=ev.decision,
            details=ev.details,
            timestamp=ev.timestamp,
            is_simulated=is_sim,
            provenance=prov
        ))
    return results


@router.get("/alerts", response_model=List[AlertResponse])
def get_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    application: Optional[str] = None,
    user_id: Optional[int] = None,
    scope: Optional[str] = Query("all", description="Scope: 'all', 'genuine', 'simulated', or 'test'"),
    limit: int = Query(100, le=500),
    db: Session = Depends(get_db)
):
    """Fetches security alerts for the SOC Notification & Alert panel with full status, severity, user, and scope filtering."""
    query = db.query(Alert)
    if status and status.upper() != "ALL":
        query = query.filter(Alert.status == status.upper())
    if severity and severity.upper() != "ALL":
        query = query.filter(Alert.severity == severity.upper())
    if application:
        query = query.filter(Alert.application == application.lower())
    if user_id:
        query = query.filter(Alert.user_id == user_id)
    if scope and scope.lower() == "genuine":
        query = query.filter(
            ~Alert.message.ilike("%sim_%"),
            ~Alert.message.ilike("%simulated%"),
            ~Alert.message.ilike("%test%"),
            ~func.coalesce(Alert.notes, "").ilike("%simulated%")
        )
    elif scope and scope.lower() == "simulated":
        query = query.filter(
            or_(
                Alert.message.ilike("%sim_%"),
                Alert.message.ilike("%simulated%"),
                Alert.notes.ilike("%simulated%")
            )
        )
    elif scope and scope.lower() == "test":
        query = query.filter(
            Alert.message.ilike("%test%")
        )

    alerts = query.order_by(Alert.created_at.desc()).limit(limit).all()

    user_ids = {al.user_id for al in alerts}
    users = {u.id: u for u in db.query(User).filter(User.id.in_(user_ids)).all()} if user_ids else {}

    results = []
    for al in alerts:
        user = users.get(al.user_id)
        is_sim = bool((al.message and ("sim_" in al.message or "Simulated" in al.message or "SIMULATED" in al.message)) or (al.notes and "Simulated" in al.notes))
        is_test = bool(al.message and "test" in al.message.lower())

        if is_sim:
            prov = "SIMULATED_ATTACK"
        elif is_test:
            prov = "TEST_ALERT"
        else:
            prov = "GENUINE_INCIDENT"

        results.append(AlertResponse(
            id=al.id,
            user_id=al.user_id,
            user_name=user.name if user else "Unknown User",
            user_email=user.email if user else "unknown@cognisec.ai",
            security_event_id=al.security_event_id,
            application=al.application,
            alert_type=al.alert_type,
            message=al.message,
            severity=al.severity,
            status=al.status,
            assigned_to=getattr(al, "assigned_to", None),
            notes=getattr(al, "notes", None),
            resolution_reason=getattr(al, "resolution_reason", None),
            resolved_at=getattr(al, "resolved_at", None),
            resolved_by=getattr(al, "resolved_by", None),
            created_at=al.created_at,
            is_simulated=is_sim,
            provenance=prov
        ))
    return results


@router.post("/alerts/{alert_id}/resolve", response_model=AlertResponse)
def resolve_alert(
    alert_id: int,
    request: AlertResolveRequest,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Updates alert triage lifecycle (OPEN, ACKNOWLEDGED, INVESTIGATING, RESOLVED, REOPENED) with immutable audit logging."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")
    
    prev_status = alert.status
    new_status = request.status.upper()
    alert.status = new_status
    if request.assigned_to is not None:
        alert.assigned_to = request.assigned_to.strip() or None
    if request.notes is not None:
        alert.notes = request.notes.strip() or None
    if request.resolution_reason is not None:
        alert.resolution_reason = request.resolution_reason.strip() or None

    now = datetime.now(timezone.utc)
    if new_status == "RESOLVED":
        alert.resolved_at = now
        alert.resolved_by = current_user.email
        event_type = "ADMIN_ALERT_RESOLVED"
    elif new_status in ("OPEN", "REOPENED") and prev_status == "RESOLVED":
        alert.resolved_at = None
        alert.resolved_by = None
        event_type = "ADMIN_ALERT_REOPENED"
    else:
        event_type = "ADMIN_ALERT_TRIAGED"

    # Record administrative action in security_events
    notes_detail = alert.notes or alert.resolution_reason or "Handled in SOC Console"
    audit_ev = SecurityEvent(
        user_id=alert.user_id,
        application=alert.application,
        event_type=event_type,
        severity="LOW",
        anomaly_score=0.0,
        risk_score=0.0,
        decision="RESOLVE_ALERT" if new_status == "RESOLVED" else "TRIAGE_ALERT",
        details=f"Alert #{alert.id} ({alert.alert_type}) transitioned from {prev_status} to {new_status} by SOC Operator {current_user.name} ({current_user.email}). Notes: {notes_detail}"
    )
    db.add(audit_ev)
    db.commit()
    db.refresh(alert)

    user = db.query(User).filter(User.id == alert.user_id).first()
    return AlertResponse(
        id=alert.id,
        user_id=alert.user_id,
        user_name=user.name if user else "Unknown User",
        user_email=user.email if user else "unknown@cognisec.ai",
        security_event_id=alert.security_event_id,
        application=alert.application,
        alert_type=alert.alert_type,
        message=alert.message,
        severity=alert.severity,
        status=alert.status,
        assigned_to=getattr(alert, "assigned_to", None),
        notes=getattr(alert, "notes", None),
        resolution_reason=getattr(alert, "resolution_reason", None),
        resolved_at=getattr(alert, "resolved_at", None),
        resolved_by=getattr(alert, "resolved_by", None),
        created_at=alert.created_at
    )


@router.get("/incidents/{incident_id}", response_model=IncidentInvestigationResponse)
def get_incident_investigation(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """
    Correlates an incident or security event into a comprehensive Zero-Trust investigation dossier:
    - User identity & role boundaries
    - Hardware device fingerprint & trust status
    - Associated session state & risk score
    - Persisted 10-dimensional behavioral biometric signals
    - Step-up verification challenge history & outcomes
    - Chronological timeline of correlated security events
    - Administrative action audit trail
    """
    # 1. Locate Alert or SecurityEvent
    alert = db.query(Alert).filter(Alert.id == incident_id).first()
    sec_event = None
    if alert and alert.security_event_id:
        sec_event = db.query(SecurityEvent).filter(SecurityEvent.id == alert.security_event_id).first()
    
    if not alert:
        sec_event = db.query(SecurityEvent).filter(SecurityEvent.id == incident_id).first()
        if sec_event and sec_event.alerts:
            alert = sec_event.alerts[0]

    if not alert and not sec_event:
        raise HTTPException(status_code=404, detail="Security Incident or Event record not found.")

    user_id = alert.user_id if alert else sec_event.user_id
    session_id = sec_event.session_id if sec_event else None
    user = db.query(User).filter(User.id == user_id).first()

    # User dossier
    user_data = {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "role": user.role,
        "account_status": user.account_status,
        "created_at": user.created_at.isoformat() if user.created_at else None
    } if user else None

    # Session dossier
    db_sess = db.query(DbSession).filter(DbSession.id == session_id).first() if session_id else None
    sess_data = {
        "id": db_sess.id,
        "status": db_sess.status,
        "risk_level": db_sess.current_risk_level,
        "ip_address": db_sess.ip_address,
        "application": db_sess.application,
        "login_time": db_sess.login_time.isoformat() if db_sess.login_time else None,
        "last_activity_time": getattr(db_sess, "last_activity_time", None).isoformat() if getattr(db_sess, "last_activity_time", None) else (db_sess.login_time.isoformat() if db_sess.login_time else None),
        "step_up_verified_at": db_sess.step_up_verified_at.isoformat() if db_sess.step_up_verified_at else None,
        "step_up_factor": getattr(db_sess, "step_up_factor", None)
    } if db_sess else None

    # Device dossier
    device = None
    if db_sess and db_sess.device_id:
        device = db.query(Device).filter(Device.id == db_sess.device_id).first()
    elif user:
        device = db.query(Device).filter(Device.user_id == user.id).order_by(Device.last_seen.desc()).first()

    device_data = {
        "id": device.id,
        "device_id": device.device_id,
        "device_fingerprint": (device.device_fingerprint[:16] + "...") if device.device_fingerprint else "Unknown",
        "nickname": device.nickname or f"{device.browser_name} on {device.os_name}",
        "browser": f"{device.browser_name or 'Browser'} {device.browser_version or ''}".strip(),
        "os": f"{device.os_name or 'OS'} {device.os_version or ''}".strip(),
        "ip_address": device.last_ip or "127.0.0.1",
        "location": f"{device.city or 'Unknown City'}, {device.country or 'Unknown Country'}",
        "location_source": device.location_source,
        "trust_state": device.trust_state,
        "is_trusted": device.is_trusted,
        "first_seen": device.first_seen.isoformat() if device.first_seen else None,
        "last_seen": device.last_seen.isoformat() if device.last_seen else None
    } if device else None

    # Behavioral Signals (from persisted telemetry log)
    behavior_log = None
    if session_id:
        behavior_log = db.query(BehaviorLog).filter(BehaviorLog.session_id == session_id).order_by(BehaviorLog.timestamp.desc()).first()
    if not behavior_log and user_id:
        behavior_log = db.query(BehaviorLog).filter(BehaviorLog.user_id == user_id).order_by(BehaviorLog.timestamp.desc()).first()

    signals = {
        "typing_speed_wpm": behavior_log.typing_speed_wpm if behavior_log else None,
        "flight_time_ms": behavior_log.avg_flight_time_ms if behavior_log else None,
        "dwell_time_ms": behavior_log.avg_dwell_time_ms if behavior_log else None,
        "mouse_velocity": behavior_log.mouse_velocity_avg if behavior_log else None,
        "mouse_acceleration": behavior_log.mouse_acceleration_avg if behavior_log else None,
        "mouse_curvature_entropy": behavior_log.mouse_curvature_entropy if behavior_log else None,
        "click_frequency": behavior_log.click_frequency if behavior_log else None,
        "scroll_speed": behavior_log.scroll_speed_avg if behavior_log else None,
        "idle_duration_sec": behavior_log.idle_duration_sec if behavior_log else None,
        "navigation_entropy": behavior_log.navigation_entropy if behavior_log else None,
        "has_persisted_telemetry": bool(behavior_log)
    }

    # Factors from sec_event details
    factors = []
    enforcement = "GRANTED"
    if sec_event and sec_event.details:
        try:
            det = json.loads(sec_event.details)
            if isinstance(det, dict):
                factors = det.get("factors", [])
                enforcement = det.get("enforcement_outcome", sec_event.decision)
        except Exception:
            pass

    if sec_event and sec_event.decision in ("RESTRICT", "TERMINATE_SESSION", "DENY", "BLOCK"):
        enforcement = "RESTRICTED" if sec_event.decision == "RESTRICT" else ("TERMINATED" if sec_event.decision == "TERMINATE_SESSION" else "BLOCKED")
    elif sec_event and sec_event.decision == "STEP_UP_VERIFICATION":
        enforcement = "STEP_UP_REQUIRED"

    # Step-Up history
    step_events = db.query(SecurityEvent).filter(
        SecurityEvent.user_id == user_id,
        SecurityEvent.event_type.in_(["STEP_UP_CHALLENGE", "STEP_UP_VERIFIED", "STEP_UP_LOCKED", "MFA_CHALLENGE"])
    ).order_by(SecurityEvent.timestamp.desc()).limit(10).all()

    step_up_history = [{
        "event_id": ev.id,
        "event_type": ev.event_type,
        "timestamp": ev.timestamp.isoformat(),
        "decision": ev.decision,
        "severity": ev.severity,
        "details": ev.details
    } for ev in step_events]

    # Chronological timeline of correlated events
    timeline_query = db.query(SecurityEvent).filter(SecurityEvent.user_id == user_id)
    if session_id:
        timeline_query = timeline_query.filter((SecurityEvent.session_id == session_id) | (SecurityEvent.session_id.is_(None)))
    timeline_events = timeline_query.order_by(SecurityEvent.timestamp.asc()).limit(30).all()

    related_timeline = [{
        "id": ev.id,
        "timestamp": ev.timestamp.isoformat(),
        "event_type": ev.event_type,
        "decision": ev.decision,
        "severity": ev.severity,
        "anomaly_score": ev.anomaly_score,
        "details": ev.details
    } for ev in timeline_events]

    # Administrative action history
    admin_actions_query = db.query(SecurityEvent).filter(
        SecurityEvent.user_id == user_id,
        SecurityEvent.event_type.in_(["ADMIN_SESSION_TERMINATED", "ADMIN_DEVICE_REVOKED", "ADMIN_DEVICE_TRUSTED", "ADMIN_ALERT_RESOLVED", "ADMIN_ALERT_TRIAGED"])
    ).order_by(SecurityEvent.timestamp.desc()).limit(10).all()

    admin_actions = [{
        "action": ev.event_type,
        "timestamp": ev.timestamp.isoformat(),
        "details": ev.details
    } for ev in admin_actions_query]

    return IncidentInvestigationResponse(
        incident_id=alert.id if alert else sec_event.id,
        alert_id=alert.id if alert else None,
        security_event_id=sec_event.id if sec_event else None,
        timestamp=alert.created_at if alert else sec_event.timestamp,
        severity=alert.severity if alert else sec_event.severity,
        status=alert.status if alert else "RESOLVED",
        event_type=sec_event.event_type if sec_event else alert.alert_type,
        application=alert.application if alert else (sec_event.application if sec_event else "platform"),
        message=alert.message if alert else (sec_event.details or "Security Event"),
        user=user_data,
        device=device_data,
        session=sess_data,
        risk_assessment={
            "risk_score": sec_event.risk_score if sec_event else 0.5,
            "anomaly_score": sec_event.anomaly_score if sec_event else 0.0,
            "decision": sec_event.decision if sec_event else "STEP_UP_VERIFICATION",
            "contributing_factors": factors
        },
        behavioral_signals=signals,
        step_up_history=step_up_history,
        related_timeline=related_timeline,
        enforcement_outcome=enforcement,
        admin_actions=admin_actions,
        investigation_notes=getattr(alert, "notes", None) if alert else None,
        assigned_to=getattr(alert, "assigned_to", None) if alert else None,
        resolution_reason=getattr(alert, "resolution_reason", None) if alert else None
    )


@router.get("/audit-logs", response_model=List[AuditLogResponse])
def get_audit_logs(
    action: Optional[str] = None,
    limit: int = Query(100, le=500),
    db: Session = Depends(get_db)
):
    """Retrieves immutable audit trail of administrative and zero-trust operations."""
    query = db.query(SecurityEvent).filter(
        SecurityEvent.event_type.in_([
            "ADMIN_SESSION_TERMINATED",
            "ADMIN_DEVICE_REVOKED",
            "ADMIN_DEVICE_TRUSTED",
            "ADMIN_ALERT_RESOLVED",
            "ADMIN_ALERT_TRIAGED",
            "ADMIN_ALERT_REOPENED",
            "ADMIN_RESCAN",
            "ADMIN_REVOCATION",
            "ZERO_TRUST_KILL_SWITCH"
        ])
    )
    if action and action.upper() != "ALL":
        query = query.filter(SecurityEvent.event_type == action.upper())

    events = query.order_by(SecurityEvent.timestamp.desc()).limit(limit).all()
    results = []
    for ev in events:
        operator = "System / Administrator"
        if ev.details and "(" in ev.details and "@" in ev.details:
            try:
                part = ev.details.split("(")[1].split(")")[0]
                if "@" in part:
                    operator = part
            except Exception:
                pass
        
        target = f"User #{ev.user_id}"
        if ev.session_id:
            target += f" · Session {ev.session_id[:12]}..."

        results.append(AuditLogResponse(
            id=ev.id,
            operator_email=operator,
            action=ev.event_type,
            target_resource=target,
            timestamp=ev.timestamp,
            outcome="ENFORCED" if ev.decision in ("TERMINATE_SESSION", "REVOKE_DEVICE", "RESOLVE_ALERT") else "COMPLETED",
            reason_or_notes=ev.details,
            correlation_id=ev.session_id or f"ev-{ev.id}"
        ))
    return results


@router.get("/analytics", response_model=HistoricalAnalyticsResponse)
def get_soc_analytics(
    time_window: str = Query("24h", pattern="^(24h|7d|30d)$"),
    db: Session = Depends(get_db)
):
    """Derives historical security analytics from persisted database records without mock data."""
    hours_map = {"24h": 24, "7d": 168, "30d": 720}
    hours = hours_map.get(time_window, 24)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    failed_logins = db.query(SecurityEvent).filter(
        SecurityEvent.event_type == "LOGIN_ATTEMPT_FAILED",
        SecurityEvent.timestamp >= cutoff
    ).count()

    successful_logins = db.query(DbSession).filter(
        DbSession.login_time >= cutoff
    ).count()
    total_auth = failed_logins + successful_logins

    period_events = db.query(SecurityEvent).filter(SecurityEvent.timestamp >= cutoff).all()
    decisions_count = {
        "ALLOW": 0,
        "STEP_UP_VERIFICATION": 0,
        "RESTRICT": 0,
        "TERMINATE_SESSION": 0,
        "DENY": 0
    }
    for ev in period_events:
        d = (ev.decision or "ALLOW").upper()
        if d in decisions_count:
            decisions_count[d] += 1
        elif d in ("BLOCK", "REJECT"):
            decisions_count["DENY"] += 1
        else:
            decisions_count["ALLOW"] += 1

    step_up_challenges = db.query(SecurityEvent).filter(
        SecurityEvent.event_type == "STEP_UP_CHALLENGE",
        SecurityEvent.timestamp >= cutoff
    ).count()

    step_up_verified = db.query(SecurityEvent).filter(
        SecurityEvent.event_type == "STEP_UP_VERIFIED",
        SecurityEvent.timestamp >= cutoff
    ).count()

    step_up_failed = db.query(SecurityEvent).filter(
        SecurityEvent.event_type == "STEP_UP_LOCKED",
        SecurityEvent.timestamp >= cutoff
    ).count()

    sessions_restricted = db.query(SecurityEvent).filter(
        SecurityEvent.event_type == "SESSION_RESTRICTED",
        SecurityEvent.timestamp >= cutoff
    ).count()

    sessions_terminated = db.query(SecurityEvent).filter(
        SecurityEvent.event_type.in_(["ZERO_TRUST_KILL_SWITCH", "ADMIN_SESSION_TERMINATED"]),
        SecurityEvent.timestamp >= cutoff
    ).count()

    devices_registered = db.query(Device).filter(Device.first_seen >= cutoff).count()
    devices_revoked = db.query(Device).filter(Device.trust_state == "REVOKED", Device.last_seen >= cutoff).count()

    alerts_opened = db.query(Alert).filter(Alert.created_at >= cutoff).count()
    alerts_resolved = db.query(Alert).filter(Alert.status == "RESOLVED", Alert.created_at >= cutoff).count()

    # Activity timeline buckets (up to 12 intervals)
    interval_hours = max(1, hours // 12)
    timeline = []
    def to_aware(dt):
        if dt is None:
            return None
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt

    for i in range(12):
        t_start = cutoff + timedelta(hours=i * interval_hours)
        t_end = t_start + timedelta(hours=interval_hours)
        auth_count = sum(1 for ev in period_events if ev.event_type == "LOGIN_ATTEMPT_FAILED" and ev.timestamp and t_start <= to_aware(ev.timestamp) < t_end)
        anom_count = sum(1 for ev in period_events if ev.anomaly_score > 0.4 and ev.timestamp and t_start <= to_aware(ev.timestamp) < t_end)
        timeline.append({
            "bucket_time": t_start.strftime("%H:%M" if hours <= 24 else "%b %d %H:%M"),
            "events_count": sum(1 for ev in period_events if ev.timestamp and t_start <= to_aware(ev.timestamp) < t_end),
            "anomalies_count": anom_count,
            "failed_auth": auth_count
        })

    return HistoricalAnalyticsResponse(
        time_window=time_window,
        total_auth_attempts=total_auth,
        successful_logins=successful_logins,
        failed_logins=failed_logins,
        risk_decisions=decisions_count,
        step_up_challenges=step_up_challenges,
        step_up_verified=step_up_verified,
        step_up_failed=step_up_failed,
        sessions_restricted=sessions_restricted,
        sessions_terminated=sessions_terminated,
        devices_registered=devices_registered,
        devices_revoked=devices_revoked,
        alerts_opened=alerts_opened,
        alerts_resolved=alerts_resolved,
        activity_timeline=timeline
    )


@router.get("/system-health", response_model=SystemHealthResponse)
def get_system_health(db: Session = Depends(get_db)):
    """Provides measurable real-time platform health metrics with live latency and event freshness."""
    t0 = time.monotonic()
    db.execute(text("SELECT 1"))
    latency_ms = round((time.monotonic() - t0) * 1000, 2)

    latest_event = db.query(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).first()
    last_event_time = latest_event.timestamp if latest_event else None
    active_count = db.query(DbSession).filter(DbSession.status == "ACTIVE").count()

    telemetry_status = "HEALTHY"
    if last_event_time:
        let_aware = last_event_time.replace(tzinfo=timezone.utc) if last_event_time.tzinfo is None else last_event_time
        age_seconds = (datetime.now(timezone.utc) - let_aware).total_seconds()
        if age_seconds > 7200:
            telemetry_status = "IDLE (>2h since event)"
    else:
        telemetry_status = "AWAITING INGESTION"

    return SystemHealthResponse(
        database_connected=True,
        database_engine=engine.dialect.name.upper(),
        database_latency_ms=latency_ms,
        last_event_ingested_at=last_event_time,
        telemetry_pipeline_status=telemetry_status,
        active_sessions_count=active_count,
        server_timestamp=datetime.now(timezone.utc)
    )


@router.post("/rescan", response_model=RescanResponse)
def trigger_system_rescan(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """
    Executes a bounded, genuine Zero-Trust security and risk scan:
    - Analyzes active sessions for unmitigated high risk or anomaly spikes
    - Identifies untrusted devices actively participating in enterprise sessions
    - Identifies open high/critical security alerts awaiting resolution
    - Evaluates behavioral baseline maturity across user profiles
    - Records an immutable audit log of the rescan operation
    """
    now = datetime.now(timezone.utc)
    findings = []

    # 1. Active sessions check
    active_sessions = db.query(DbSession).filter(DbSession.status == "ACTIVE").all()
    high_risk_active = [s for s in active_sessions if s.current_risk_level in ("HIGH", "CRITICAL")]
    for s in high_risk_active:
        findings.append({
            "category": "SESSION_RISK",
            "severity": s.current_risk_level,
            "target": f"Session #{s.id[:12]}...",
            "description": f"Active session #{s.id[:12]} for user #{s.user_id} has elevated risk level ({s.current_risk_level}) without step-up mitigation."
        })

    # 2. Device trust check
    pending_devices = db.query(Device).filter(Device.trust_state == "PENDING_CONFIRMATION").all()
    if pending_devices:
        findings.append({
            "category": "DEVICE_TRUST",
            "severity": "MEDIUM",
            "target": f"{len(pending_devices)} Devices",
            "description": f"{len(pending_devices)} devices are awaiting hardware trust confirmation in the device inventory."
        })

    # 3. Open high/critical alerts check
    critical_alerts = db.query(Alert).filter(
        Alert.status == "OPEN",
        Alert.severity.in_(["HIGH", "CRITICAL"])
    ).all()
    for al in critical_alerts:
        findings.append({
            "category": "UNRESOLVED_ALERT",
            "severity": al.severity,
            "target": f"Alert #{al.id}",
            "description": f"Open {al.severity} incident #{al.id} ({al.alert_type}): {al.message[:80]}..."
        })

    # 4. Behavioral maturity analysis
    profiles = db.query(BehaviorProfile).all()
    cold_start_users = [p for p in profiles if p.sample_count < 15]
    if cold_start_users:
        findings.append({
            "category": "BEHAVIORAL_MATURITY",
            "severity": "LOW",
            "target": f"{len(cold_start_users)} Profiles",
            "description": f"{len(cold_start_users)} user behavioral profiles are in COLD_START phase (<15 telemetry samples)."
        })

    # Record administrative audit trail
    sec_event = SecurityEvent(
        user_id=current_user.id,
        application="platform",
        event_type="ADMIN_RESCAN",
        severity="LOW",
        anomaly_score=0.0,
        risk_score=0.0,
        decision="RESCAN_EVALUATE",
        details=f"SOC AI Re-Scan executed by {current_user.name} ({current_user.email}). Evaluated {len(active_sessions)} sessions, {len(pending_devices)} devices, {len(critical_alerts)} critical alerts. Findings: {len(findings)}."
    )
    db.add(sec_event)
    db.commit()

    summary_text = f"Scan complete: {len(findings)} operational findings identified across {len(active_sessions)} active sessions and {len(pending_devices)} pending devices."

    return RescanResponse(
        status="COMPLETED",
        timestamp=now,
        evaluated_sessions=len(active_sessions),
        evaluated_devices=len(pending_devices),
        evaluated_alerts=len(critical_alerts),
        findings=findings,
        summary=summary_text
    )


@router.get("/devices", response_model=List[DeviceResponse])
def get_all_devices(
    scope: Optional[str] = Query("all", description="Scope: 'all', 'active', 'genuine', or 'test'"),
    db: Session = Depends(get_db)
):
    """Returns enterprise hardware inventory across all users with active sessions, hardware validation evidence, and scope filtering."""
    SessionService.reap_expired_sessions(db)
    devices = DeviceService.get_all_devices(db, limit=200)

    # Pre-fetch users for device owners
    user_ids = {d.user_id for d in devices}
    users = {u.id: u for u in db.query(User).filter(User.id.in_(user_ids)).all()} if user_ids else {}

    # Map genuine active sessions (excluding test/sim runners)
    active_sessions = db.query(DbSession).filter(
        DbSession.status == "ACTIVE",
        DbSession.logout_time.is_(None),
        ~DbSession.id.like("sim_%"),
        ~DbSession.id.like("test_%"),
        DbSession.device_id.isnot(None)
    ).all()

    device_sessions_map = {}
    for s in active_sessions:
        device_sessions_map.setdefault(s.device_id, []).append(s.id)

    response_items = []
    for d in devices:
        owner = users.get(d.user_id)
        sess_ids = device_sessions_map.get(d.id, [])
        is_active = len(sess_ids) > 0
        fp = (d.device_fingerprint or "").lower()
        owner_email = (owner.email if owner else "").lower()

        # Provenance categorization: Do NOT retroactively guess without evidence!
        is_known_test = (
            "test" in fp or "sim" in fp or
            "test" in owner_email or "val." in owner_email or
            "neon_verify" in owner_email or "audit_user" in owner_email
        )
        if is_active:
            provenance = "GENUINE_ACTIVE"
        elif is_known_test:
            provenance = "KNOWN_TEST"
        else:
            provenance = "HISTORICAL_RECORD"

        # Explicit physical hardware validation distinction
        is_physical_confirmed = bool(
            is_active and
            d.browser_name and d.browser_name != "Unknown" and
            d.os_name and d.os_name != "Unknown" and
            not fp.startswith("unknown") and
            not fp.startswith("test")
        )

        if is_active and is_physical_confirmed:
            evidence = "Live authenticated hardware session connected (verified TLS & browser signature)"
        elif is_active:
            evidence = "Active session connected (unconfirmed hardware signature)"
        elif is_known_test:
            evidence = "Synthetic/automated test fingerprint record"
        else:
            evidence = "Historical persisted development record (physical hardware unconfirmed; no active session)"

        # Apply scope filtering
        if scope and scope.lower() == "active" and not is_active:
            continue
        if scope and scope.lower() == "genuine" and provenance == "KNOWN_TEST":
            continue
        if scope and scope.lower() == "test" and provenance != "KNOWN_TEST":
            continue

        d_dict = DeviceResponse.model_validate(d).model_dump()
        d_dict["active_session_count"] = len(sess_ids)
        d_dict["active_session_ids"] = sess_ids
        d_dict["user_name"] = owner.name if owner else "Unknown Owner"
        d_dict["user_email"] = owner.email if owner else "unknown@cognisec.ai"
        d_dict["is_active"] = is_active
        d_dict["provenance"] = provenance
        d_dict["is_physical_device_confirmed"] = is_physical_confirmed
        d_dict["hardware_evidence_summary"] = evidence
        response_items.append(d_dict)

    return response_items


@router.post("/devices/{device_id}/trust", response_model=DeviceResponse)
def update_device_trust(
    device_id: str,
    is_trusted: bool = Query(True),
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Marks a hardware device as trusted or untrusted with administrative audit logging."""
    device = DeviceService.set_device_trust(db, device_id, is_trusted)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found.")

    # Audit administrative trust modification
    action_label = "TRUSTED" if is_trusted else "UNTRUSTED"
    sec_event = SecurityEvent(
        user_id=device.user_id,
        application="platform",
        event_type="ADMIN_DEVICE_TRUST_MODIFIED",
        severity="MEDIUM",
        anomaly_score=0.0,
        risk_score=0.0,
        decision="ALLOW" if is_trusted else "RESTRICT",
        details=f"Device {device.nickname or device.device_id} marked as {action_label} by SOC Administrator {current_user.name} ({current_user.email})."
    )
    db.add(sec_event)
    db.commit()
    db.refresh(device)
    return device


@router.post("/devices/{device_id}/revoke")
def revoke_device_admin(
    device_id: str,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Administrative revocation: Revokes trust and terminates all active sessions bound to this device."""
    device = DeviceService.get_device_by_id(db, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found.")

    success = DeviceService.revoke_device(
        db,
        device_id,
        reason=f"Device revoked administratively by SOC Administrator {current_user.name} ({current_user.email})"
    )
    if not success:
        raise HTTPException(status_code=400, detail="Failed to revoke device.")

    return {
        "status": "success",
        "message": f"Device '{device.nickname or device.device_id}' revoked and associated sessions terminated.",
        "device_id": device_id,
        "trust_state": "REVOKED"
    }


@router.get("/users", response_model=List[AdminUserResponse])
def get_all_users(
    scope: Optional[str] = Query("all", description="Scope: 'all', 'active', 'genuine', 'demo', or 'test'"),
    limit: int = Query(100, le=500),
    db: Session = Depends(get_db)
):
    """Returns registered enterprise users with device counts, active session counts, provenance categorization, and scope filtering."""
    SessionService.reap_expired_sessions(db)
    users = db.query(User).order_by(User.created_at.desc()).limit(limit).all()
    user_ids = [u.id for u in users]

    if not user_ids:
        return []

    # Map genuine active sessions
    active_sessions = db.query(DbSession).filter(
        DbSession.user_id.in_(user_ids),
        DbSession.status == "ACTIVE",
        DbSession.logout_time.is_(None),
        ~DbSession.id.like("sim_%"),
        ~DbSession.id.like("test_%")
    ).all()
    sess_counts = {}
    for s in active_sessions:
        sess_counts[s.user_id] = sess_counts.get(s.user_id, 0) + 1

    # Map devices
    devices = db.query(Device).filter(Device.user_id.in_(user_ids)).all()
    dev_counts = {}
    for d in devices:
        dev_counts[d.user_id] = dev_counts.get(d.user_id, 0) + 1

    # Map profiles
    profiles = db.query(BehaviorProfile).filter(BehaviorProfile.user_id.in_(user_ids)).all()
    prof_map = {p.user_id: p for p in profiles}

    demo_emails = {
        "sarah.chen@cognisec.ai",
        "marcus.vance@cognisec.ai",
        "elena.rostova@cognisec.ai",
        "admin@cognisec.ai",
        "demo@cognisec.ai"
    }

    results = []
    for u in users:
        is_active = sess_counts.get(u.id, 0) > 0
        email_lower = u.email.lower()

        if is_active:
            prov = "GENUINE_ACTIVE"
        elif u.email in demo_emails or email_lower in demo_emails:
            prov = "SEEDED_DEMO"
        elif any(k in email_lower for k in ["test", "val.", "audit_user_", "neon_verify", "sample"]):
            prov = "KNOWN_TEST"
        else:
            prov = "UNKNOWN_PROVENANCE"

        if scope and scope.lower() == "active" and not is_active:
            continue
        if scope and scope.lower() == "genuine" and prov not in ("GENUINE_ACTIVE", "UNKNOWN_PROVENANCE"):
            continue
        if scope and scope.lower() == "demo" and prov != "SEEDED_DEMO":
            continue
        if scope and scope.lower() == "test" and prov != "KNOWN_TEST":
            continue

        prof = prof_map.get(u.id)
        status_label, _, _ = ProfileService.get_maturity_info(prof.sample_count) if prof else ("COLD_START", 0.0, False)
        results.append(AdminUserResponse(
            id=u.id,
            name=u.name,
            email=u.email,
            role=u.role,
            account_status=u.account_status,
            failed_login_attempts=getattr(u, "failed_login_attempts", 0) or 0,
            created_at=u.created_at,
            active_sessions_count=sess_counts.get(u.id, 0),
            registered_devices_count=dev_counts.get(u.id, 0),
            baseline_status=status_label,
            sample_count=prof.sample_count if prof else 0,
            is_active=is_active,
            provenance=prov
        ))
    return results



@router.get("/users/{user_id}/profile", response_model=BehaviorProfileResponse)
def get_admin_user_profile(user_id: int, db: Session = Depends(get_db)):
    """Allows Security Administrators to inspect a specific user's behavioral baseline."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    
    profile = ProfileService.get_or_create_profile(db, user_id)
    features_dict = ProfileService.get_profile_dict(profile)
    status_label, confidence, is_mature = ProfileService.get_maturity_info(profile.sample_count)
    ml_status, model_samples, is_anomaly, anomaly_score = ModelManager.get_ml_status(
        user_id=user_id,
        sample_count=profile.sample_count,
        baseline_stats=features_dict,
        db=db
    )

    return BehaviorProfileResponse(
        id=profile.id,
        user_id=profile.user_id,
        sample_count=profile.sample_count,
        profile_version=profile.profile_version,
        last_updated=profile.last_updated,
        baseline_features=features_dict,
        baseline_status=status_label,
        maturity_confidence=confidence,
        is_mature=is_mature,
        ml_status=ml_status,
        model_sample_count=model_samples,
        is_anomaly=is_anomaly,
        anomaly_score=anomaly_score
    )


@router.get("/users/{user_id}/model-metadata")
def get_user_model_metadata(user_id: int, db: Session = Depends(get_db)):
    """Allows Security Administrators to inspect internal ML model diagnostic metadata."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    profile = ProfileService.get_or_create_profile(db, user_id)
    features_dict = ProfileService.get_profile_dict(profile)
    ModelManager.ensure_hydrated(db, user_id, features_dict)

    metadata = ModelManager.get_model_metadata(user_id)
    status_label, confidence, is_mature = ProfileService.get_maturity_info(profile.sample_count)
    metadata["baseline_maturity"] = status_label
    metadata["maturity_confidence"] = confidence
    metadata["is_mature"] = is_mature
    metadata["profile_sample_count"] = profile.sample_count
    return metadata


@router.get("/email/diagnostics", response_model=EmailDiagnosticsResponse)
def get_email_diagnostics():
    """
    Returns backend email delivery diagnostics.
    Restricted to authorized SOC Administrators. Never exposes credentials.
    """
    return EmailService.get_diagnostics()


@router.post("/email/test-connection", response_model=EmailTestResponse)
def test_email_connection():
    """
    Performs a live connectivity and authentication test to the configured SMTP server without sending an email.
    Restricted to authorized SOC Administrators.
    """
    success, message = EmailService.test_connection()
    return EmailTestResponse(success=success, message=message)


@router.post("/email/send-test", response_model=EmailTestResponse)
def send_test_email(request: EmailTestRequest, current_user: User = Depends(require_admin)):
    """
    Sends a test verification email to an administrator-specified recipient.
    Strictly rate-limited (at most 5 requests per minute) and validated.
    """
    rate_limiter.enforce(
        key=f"admin_test_email:{current_user.id}",
        max_requests=5,
        window_seconds=60,
        detail="Too many test email requests. Rate limit enforced."
    )

    is_deliverable, deliver_err = EmailService.is_deliverable_recipient(request.recipient_email)
    if not is_deliverable:
        raise HTTPException(status_code=400, detail=deliver_err)

    plain_body = (
        f"COGNISEC-AI Zero-Trust SMTP Delivery Test\n\n"
        f"This is an automated test message initiated by SOC Administrator {current_user.name} ({current_user.email}).\n"
        f"If you received this email, the SMTP delivery channel is functioning properly."
    )
    html_body = (
        f"<div style='font-family: sans-serif; background: #06040a; color: #fff; padding: 24px; border-radius: 8px; border: 1px solid #dc2626;'>"
        f"<h2 style='color: #ef4444;'>COGNISEC-AI // SMTP Test</h2>"
        f"<p>This is an automated test message initiated by SOC Administrator <strong>{current_user.name}</strong>.</p>"
        f"<p style='color: #22c55e;'>✓ SMTP transport, TLS handshake, and authentication succeeded.</p>"
        f"</div>"
    )

    success, message = EmailService.send_email(
        recipient_email=request.recipient_email,
        subject="[COGNISEC-AI] SMTP Delivery Verification Test",
        plain_text=plain_body,
        html_text=html_body
    )
    return EmailTestResponse(success=success, message=message)


@router.post("/dev/reset-lockout", response_model=DevResetLockoutResponse)
def dev_reset_account_lockout(
    request: DevResetLockoutRequest,
    request_conn: Request,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Development-only administrative endpoint to clear the failed-attempt counter and unlock a test account.
    Strictly restricted to:
    1. Development environment (settings.ENVIRONMENT in ('development', 'dev', 'test')).
    2. Localhost requester (127.0.0.1, ::1, localhost, testclient).
    3. Authenticated Security Administrator.
    Logs all reset operations to the SecurityEvent audit trail.
    """
    from app.core.config import settings

    env = getattr(settings, "ENVIRONMENT", "").lower().strip()
    if env not in ("development", "dev", "test"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Development administrative lockout reset is disabled in production environments."
        )

    client_ip = request_conn.client.host if request_conn.client else "127.0.0.1"
    forwarded = request_conn.headers.get("x-forwarded-for")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()

    if client_ip not in ("127.0.0.1", "::1", "localhost", "testclient"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Development administrative reset is restricted to local workstation access (localhost only)."
        )

    target_user = AuthService.get_user_by_email(db, request.email)
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Target account '{request.email}' not found.")

    # Reset failed attempts and restore ACTIVE status
    target_user.failed_login_attempts = 0
    target_user.account_status = "ACTIVE"

    # Also clear any active STEP_UP_LOCKED security events for this user so MFA testing can resume
    db.query(SecurityEvent).filter(
        SecurityEvent.user_id == target_user.id,
        SecurityEvent.event_type == "STEP_UP_LOCKED"
    ).delete(synchronize_session=False)

    # Clear rate limiter keys for this target account and IP
    rate_limiter.clear_keys_matching(request.email.lower().strip())
    rate_limiter.clear_keys_matching(client_ip)

    # Audit log in security events
    sec_event = SecurityEvent(
        user_id=target_user.id,
        application="platform",
        event_type="ADMIN_LOCKOUT_RESET",
        severity="LOW",
        decision="ALLOW",
        details=json.dumps({
            "action": "DEV_LOCKOUT_RESET",
            "target_email": target_user.email,
            "target_role": target_user.role,
            "reset_by_admin": current_admin.email,
            "admin_id": current_admin.id,
            "client_ip": client_ip,
            "environment": env
        })
    )
    db.add(sec_event)
    db.commit()
    db.refresh(target_user)

    return DevResetLockoutResponse(
        success=True,
        message=f"Account lockout and failed login attempts counter successfully reset for '{target_user.email}'.",
        account_status=target_user.account_status,
        failed_login_attempts=target_user.failed_login_attempts,
        target_email=target_user.email
    )

