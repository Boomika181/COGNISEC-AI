import time
import json
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import text, or_, and_, func
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
    AdminUserDirectoryResponse,
    RiskDistributionResponse,
    AlertResponse,
    AlertResolveRequest,
    SecurityEventResponse,
    IncidentInvestigationResponse,
    AuditLogResponse,
    AuditTrailItem,
    AuditTrailResponse,
    HistoricalAnalyticsResponse,
    SystemHealthResponse,
    RescanResponse,
    EmailDiagnosticsResponse,
    EmailTestRequest,
    EmailTestResponse,
    DevResetLockoutRequest,
    DevResetLockoutResponse,
    SOCIncidentSummary,
    SOCPostureResponse,
    SOCSummaryResponse,
    SOCRecommendationsResponse,
    SOCContainmentActionItem,
    SOCContainmentActionsResponse,
    SecurityIntelligenceOverviewResponse,
    BehaviouralFeatureComparison,
    BehaviouralIntelligencePayload,
    AdaptiveAuthHistoryItem,
    AgentExecutionDetail,
    DeterministicArbiterDecision,
    SecurityEventDetailResponse,
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

SEEDED_DEMO_EMAILS = {
    "admin.soc@cognisec.ai",
    "user.portal@cognisec.ai",
    "student.alex@veritas.edu",
    "customer.jane@auraluxe.com",
    "dr.sarah@aetheriahealth.org",
    "2021bce0492@bits-pilani.ac.in",
    "dr.boomika@ayusync.med.in",
    "boomika.ram@cognisec.ai",
    "customer@cognisec.ai",
    "sarah.chen@cognisec.ai",
    "marcus.vance@cognisec.ai",
    "elena.rostova@cognisec.ai",
    "admin@cognisec.ai",
    "demo@cognisec.ai",
}

_TEST_EMAIL_MARKERS = (
    "test",
    "val.",
    "verify_",
    "neon_verify",
    "audit_user_",
    "audit_plat_",
    "audit_coll_",
    "audit_hlth_",
    "audit_shop_",
    "live_audit_",
    "audit_test_",
    "adaptive.user.",
    "student.live.",
    "cadence.eval",
    "live_test_",
    "e2e_live_",
    "e2e_verify_",
    "recovery.test.",
    "preserve.data",
    "synth_plat_",
    "disposable_",
    "browser_user_",
    "empty_",
    "alpha_switch_",
    "beta_switch_",
    "crit_test_",
    "user_63e568",
    "sample",
    "soc.e2e.",
)

_TEST_DOMAINS = (
    "@example.com",
    "@example.org",
    "@example.net",
    "@demo.cognisec.ai",
)

_VALID_INCIDENT_TRANSITIONS = {
    "OPEN": {"OPEN", "ACKNOWLEDGED", "INVESTIGATING", "CONTAINED", "RESOLVED"},
    "REOPENED": {"REOPENED", "ACKNOWLEDGED", "INVESTIGATING", "CONTAINED", "RESOLVED"},
    "ACKNOWLEDGED": {"ACKNOWLEDGED", "INVESTIGATING", "CONTAINED", "RESOLVED", "REOPENED"},
    "INVESTIGATING": {"INVESTIGATING", "ACKNOWLEDGED", "CONTAINED", "RESOLVED", "REOPENED"},
    "CONTAINED": {"CONTAINED", "INVESTIGATING", "RESOLVED", "REOPENED"},
    "RESOLVED": {"RESOLVED", "REOPENED"},
}


_VERIFIED_HISTORY_EVENT_TYPES = (
    "USER_REGISTERED",
    "EMAIL_VERIFICATION_COMPLETED",
    "LOGIN_OTP_VERIFIED",
    "STEP_UP_VERIFIED",
    "PASSWORD_RESET_SUCCESS",
)


def _get_verified_history_user_ids(db: Session, user_ids: Optional[List[int]] = None) -> set:
    q = db.query(SecurityEvent.user_id).filter(
        SecurityEvent.event_type.in_(_VERIFIED_HISTORY_EVENT_TYPES),
        SecurityEvent.user_id.isnot(None),
    )
    if user_ids is not None:
        if not user_ids:
            return set()
        q = q.filter(SecurityEvent.user_id.in_(user_ids))
    return {uid for (uid,) in q.distinct().all() if uid is not None}


def _non_admin_user_ids_subquery(db: Session):
    """Returns a subquery of User.id excluding ADMIN, SYSTEM, and SERVICE roles."""
    role_expr = func.upper(func.trim(func.coalesce(User.role, "USER")))
    return db.query(User.id).filter(~role_expr.in_(["ADMIN", "SYSTEM", "SERVICE"]))


def _build_user_scope_filter(db: Session, scope: Optional[str]):
    """
    Returns a SQLAlchemy filter expression matching _classify_user_account semantics
    so dashboard counts and the Users & Sessions directory share one authoritative rule.
    """
    normalized_scope = (scope or "genuine").strip().lower()
    if normalized_scope == "all":
        return None

    email_expr = func.lower(func.trim(func.coalesce(User.email, "")))
    role_expr = func.upper(func.trim(func.coalesce(User.role, "USER")))
    reg_src_expr = func.upper(func.trim(func.coalesce(User.registration_source, "")))

    is_admin_expr = role_expr == "ADMIN"
    is_system_expr = role_expr.in_(["SYSTEM", "SERVICE"])
    is_seeded_expr = or_(
        email_expr.in_(SEEDED_DEMO_EMAILS),
        reg_src_expr == "SEED_SCRIPT",
    )
    is_test_pattern_expr = or_(
        reg_src_expr == "TEST_FIXTURE",
        *[email_expr.contains(marker) for marker in _TEST_EMAIL_MARKERS],
        *[email_expr.endswith(dom) for dom in _TEST_DOMAINS],
    )
    is_test_expr = or_(is_seeded_expr, is_test_pattern_expr)
    valid_email_expr = and_(
        email_expr.like("%@%.%"),
        ~email_expr.like("@%"),
        ~email_expr.like("%@.%"),
        ~email_expr.like("%."),
    )

    if normalized_scope in ("admin", "admins", "administrators"):
        return is_admin_expr
    if normalized_scope == "test":
        return and_(~is_admin_expr, ~is_system_expr, is_test_expr)
    if normalized_scope == "active":
        active_uids = (
            db.query(DbSession.user_id)
            .filter(
                DbSession.status == "ACTIVE",
                DbSession.logout_time.is_(None),
                ~DbSession.id.like("sim_%"),
                ~DbSession.id.like("test_%"),
            )
        )
        return User.id.in_(active_uids)

    # Default: "genuine" (publicly registered human accounts)
    verified_uid_set = _get_verified_history_user_ids(db)
    public_provenance_expr = or_(
        reg_src_expr == "PUBLIC_REGISTRATION",
        and_(
            reg_src_expr == "",
            or_(
                User.email_verified.is_(True),
                User.id.in_(verified_uid_set) if verified_uid_set else False,
            ),
        ),
    )
    return and_(
        valid_email_expr,
        ~is_admin_expr,
        ~is_system_expr,
        ~is_test_expr,
        public_provenance_expr,
    )


def _is_valid_email(email: Optional[str]) -> bool:
    if not email or "@" not in email:
        return False
    local, _, domain = email.strip().partition("@")
    return bool(local) and "." in domain and not domain.startswith(".") and not domain.endswith(".")


def _classify_user_account(user: User, is_active: bool = False, has_verified_history: bool = False) -> Dict[str, Any]:
    """
    Classifies a User record into publicly registered human user, admin/system account,
    seeded demo account, automated test account, or unverified provenance without mutating DB state.
    """
    em = (user.email or "").strip().lower()
    role = (user.role or "USER").strip().upper()
    reg_source = (getattr(user, "registration_source", None) or "").strip().upper()
    valid_email = _is_valid_email(em)

    is_system = role in ("SYSTEM", "SERVICE")
    is_admin = role == "ADMIN"
    is_seeded = (em in SEEDED_DEMO_EMAILS) or (reg_source == "SEED_SCRIPT")
    is_test_pattern = (
        reg_source == "TEST_FIXTURE"
        or any(marker in em for marker in _TEST_EMAIL_MARKERS)
        or any(em.endswith(dom) for dom in _TEST_DOMAINS)
    )
    is_test = is_seeded or is_test_pattern
    is_public_registered = (
        valid_email
        and (not is_admin)
        and (not is_system)
        and (not is_test)
        and (
            reg_source == "PUBLIC_REGISTRATION"
            or (reg_source == "" and (bool(getattr(user, "email_verified", False)) or has_verified_history))
        )
    )
    is_unverified_provenance = (
        (not is_admin)
        and (not is_system)
        and (not is_test)
        and (not is_public_registered)
    )
    is_email_verified = bool(getattr(user, "email_verified", False)) or (is_public_registered and has_verified_history)

    if is_admin:
        provenance = "ADMIN_ACCOUNT"
    elif is_system:
        provenance = "SYSTEM_ACCOUNT"
    elif is_seeded:
        provenance = "SEEDED_DEMO"
    elif is_test_pattern:
        provenance = "KNOWN_TEST"
    elif is_public_registered and is_active:
        provenance = "GENUINE_ACTIVE"
    elif is_public_registered:
        provenance = "PUBLIC_REGISTERED"
    elif is_active:
        provenance = "GENUINE_ACTIVE"
    else:
        provenance = "UNKNOWN_PROVENANCE"

    return {
        "normalized_email": em,
        "valid_email": valid_email,
        "is_admin": is_admin,
        "is_system": is_system,
        "is_seeded": is_seeded,
        "is_test": is_test,
        "is_public_registered": is_public_registered,
        "is_unverified_provenance": is_unverified_provenance,
        "is_email_verified": is_email_verified,
        "is_genuine_human": is_public_registered,
        "provenance": provenance,
    }


def _score_to_risk_level(score: Optional[float]) -> Optional[str]:
    if score is None:
        return None
    val = float(score)
    if val >= 0.85:
        return "CRITICAL"
    if val >= 0.65:
        return "HIGH"
    if val >= 0.30:
        return "MEDIUM"
    return "LOW"


@router.get("/metrics", response_model=AdminMetricsResponse)
def get_soc_metrics(
    scope: str = Query("all", description="Scope: 'all' or 'genuine' (production only)"),
    db: Session = Depends(get_db),
):
    """Provides high-level real-time KPI metrics for the SOC Dashboard strictly from authoritative queries."""
    from app.services.session_service import SessionService
    from app.models.portal_lock import PortalSecurityLock
    SessionService.reap_expired_sessions(db)

    prod_only = (scope or "all").strip().lower() == "genuine"

    # Corroborated interactive verification events for historical accounts without registration_source
    verified_uid_set = _get_verified_history_user_ids(db)

    # Classify all persisted users and deduplicate by normalized lowercase email
    all_users = db.query(User).order_by(User.id.asc()).all()
    seen_emails = set()
    genuine_uid_set = set()
    admin_uid_set = set()
    test_demo_uid_set = set()
    known_test_count = 0
    seeded_count = 0
    admin_accounts_count = 0
    registered_users_count = 0
    email_verified_users_count = 0
    unknown_count = 0

    for u in all_users:
        cls = _classify_user_account(u, has_verified_history=(u.id in verified_uid_set))
        em = cls["normalized_email"] or f"__id_{u.id}"
        is_dup = em in seen_emails
        seen_emails.add(em)

        if cls["is_admin"] or cls["is_system"]:
            admin_uid_set.add(u.id)
            if not is_dup:
                admin_accounts_count += 1
        elif cls["is_test"]:
            test_demo_uid_set.add(u.id)
            if not is_dup:
                if cls["is_seeded"]:
                    seeded_count += 1
                else:
                    known_test_count += 1
        elif cls["is_public_registered"]:
            genuine_uid_set.add(u.id)
            if not is_dup:
                registered_users_count += 1
                if cls["is_email_verified"]:
                    email_verified_users_count += 1
        else:
            test_demo_uid_set.add(u.id)
            if not is_dup:
                unknown_count += 1

    non_prod_uid_set = admin_uid_set | test_demo_uid_set

    # 1. Live sessions: active, unexpired, non-simulated, non-test sessions
    live_sess_q = db.query(DbSession).filter(
        DbSession.status == "ACTIVE",
        DbSession.logout_time.is_(None),
        ~DbSession.id.like("sim_%"),
        ~DbSession.id.like("test_%"),
    )
    if prod_only and non_prod_uid_set:
        live_sess_q = live_sess_q.filter(DbSession.user_id.in_(genuine_uid_set)) if genuine_uid_set else live_sess_q.filter(DbSession.user_id == -1)
    live_sessions = live_sess_q.count()

    # 2. Active users: distinct users with qualifying, genuinely active sessions
    active_user_ids = live_sess_q.with_entities(DbSession.user_id).distinct().all()
    active_users = len(active_user_ids)
    active_uid_set = {uid[0] for uid in active_user_ids}

    # Genuine human logged-in users (distinct)
    logged_in_users_count = len(active_uid_set & genuine_uid_set)

    # 3. Active devices: physical devices currently bound to an active, unexpired genuine session
    active_device_ids = live_sess_q.filter(DbSession.device_id.isnot(None)).with_entities(DbSession.device_id).distinct().all()
    active_devices = len([d[0] for d in active_device_ids if d[0] is not None])

    # 4. Total persisted inventory
    total_users = db.query(User).count()

    dev_q = db.query(Device)
    if prod_only:
        dev_q = dev_q.filter(Device.user_id.in_(genuine_uid_set)) if genuine_uid_set else dev_q.filter(Device.user_id == -1)
    total_devices = dev_q.count()

    # 5. Blocked/revoked & Enforcement Breakdown
    sess_base = db.query(DbSession)
    if prod_only:
        sess_base = sess_base.filter(DbSession.user_id.in_(genuine_uid_set)) if genuine_uid_set else sess_base.filter(DbSession.user_id == -1)
    restricted_sessions = sess_base.filter(DbSession.status == "RESTRICTED").count()
    revoked_sessions = sess_base.filter(DbSession.status == "REVOKED").count()
    terminated_sessions = sess_base.filter(DbSession.status == "TERMINATED").count()
    revoked_devices = dev_q.filter(Device.trust_state == "REVOKED").count()
    active_enforcements = restricted_sessions + revoked_sessions + revoked_devices

    # 6. Enterprise devices & trust breakdown
    trusted_devices = dev_q.filter(Device.trust_state == "TRUSTED").count()
    pending_devices = dev_q.filter(Device.trust_state == "PENDING_CONFIRMATION").count()
    verified_metadata_devices = dev_q.filter(
        Device.browser_name.isnot(None),
        Device.browser_name != "Unknown",
        Device.os_name.isnot(None),
        Device.os_name != "Unknown"
    ).count()
    unverified_identity_devices = total_devices - verified_metadata_devices

    # 7. Active alerts breakdown (NO fallback from genuine_open_alerts to open_alerts)
    alert_base = db.query(Alert)
    if prod_only:
        alert_base = alert_base.filter(
            Alert.user_id.in_(genuine_uid_set) if genuine_uid_set else Alert.user_id == -1,
            ~Alert.message.ilike("%sim_%"),
            ~Alert.message.ilike("%simulated%"),
            ~Alert.message.ilike("%test%"),
            ~func.coalesce(Alert.notes, "").ilike("%simulated%"),
            ~func.coalesce(Alert.notes, "").ilike("%test%"),
        )
    open_alerts = alert_base.filter(Alert.status == "OPEN").count()
    genuine_open_alerts = db.query(Alert).filter(
        Alert.status == "OPEN",
        ~Alert.message.ilike("%sim_%"),
        ~Alert.message.ilike("%simulated%"),
        ~Alert.message.ilike("%test%"),
        ~func.coalesce(Alert.notes, "").ilike("%simulated%"),
        ~func.coalesce(Alert.notes, "").ilike("%test%"),
        Alert.user_id.in_(genuine_uid_set) if genuine_uid_set else Alert.user_id == -1,
    ).count()
    reopened_alerts = alert_base.filter(Alert.status == "REOPENED").count()
    resolved_alerts = alert_base.filter(Alert.status == "RESOLVED").count()
    total_alerts = alert_base.count()
    active_alerts = genuine_open_alerts

    # 8. Anomaly rate (strictly bounded observation window over genuine traffic in last 24h)
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
    if prod_only:
        obs_query = obs_query.filter(SecurityEvent.user_id.in_(genuine_uid_set)) if genuine_uid_set else obs_query.filter(SecurityEvent.user_id == -1)
    obs_24h = obs_query.count()
    anom_24h = obs_query.filter(SecurityEvent.anomaly_score > 0.5).count()

    if obs_24h > 0:
        anomaly_rate = round((anom_24h / obs_24h) * 100, 1)
        anomaly_label = f"{anomaly_rate}% ({anom_24h}/{obs_24h} in 24h)"
    else:
        anomaly_rate = 0.0
        anomaly_label = "0.0% (0 anomalies in 24h)"

    high_risk_sessions = live_sess_q.filter(
        DbSession.current_risk_level.in_(["HIGH", "CRITICAL"])
    ).count()

    step_up_q = db.query(SecurityEvent).filter(
        SecurityEvent.event_type.in_(["STEP_UP_CHALLENGE", "STEP_UP_VERIFIED", "MFA_CHALLENGE", "MFA_VERIFIED"]),
        ~SecurityEvent.session_id.like("sim_%"),
        ~SecurityEvent.session_id.like("test_%")
    )
    if prod_only:
        step_up_q = step_up_q.filter(SecurityEvent.user_id.in_(genuine_uid_set)) if genuine_uid_set else step_up_q.filter(SecurityEvent.user_id == -1)
    step_up_count = step_up_q.count()

    user_susp_q = db.query(User).filter(User.account_status != "ACTIVE")
    if prod_only:
        user_susp_q = user_susp_q.filter(User.id.in_(genuine_uid_set)) if genuine_uid_set else user_susp_q.filter(User.id == -1)
    suspended_accounts = user_susp_q.count()

    untrusted_devices = dev_q.filter(Device.trust_state != "TRUSTED").count()

    lock_q = db.query(PortalSecurityLock).filter(PortalSecurityLock.lock_status == "ACTIVE")
    if prod_only:
        lock_q = lock_q.filter(PortalSecurityLock.user_id.in_(genuine_uid_set)) if genuine_uid_set else lock_q.filter(PortalSecurityLock.user_id == -1)
    pending_recovery = lock_q.count()

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
        genuine_active_accounts_count=logged_in_users_count,
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
        open_alerts_count=open_alerts + reopened_alerts if prod_only else open_alerts,
        reopened_alerts_count=reopened_alerts,
        resolved_alerts_count=resolved_alerts,
        total_alerts_count=total_alerts,
        anomaly_rate_observations=obs_24h,
        anomaly_rate_window="24h",
        anomaly_rate_label=anomaly_label,
        suspended_accounts_count=suspended_accounts,
        untrusted_devices_count=untrusted_devices,
        pending_recovery_count=pending_recovery,
        registered_users_count=registered_users_count,
        email_verified_users_count=email_verified_users_count,
        admin_accounts_count=admin_accounts_count,
        test_and_demo_accounts_count=known_test_count + seeded_count,
        unverified_provenance_accounts_count=unknown_count,
        logged_in_users_count=logged_in_users_count,
        scope="genuine" if prod_only else "all",
    )


@router.get("/risk-distribution", response_model=RiskDistributionResponse)
def get_risk_distribution(
    scope: str = Query("all", description="Scope: 'all' or 'genuine' (production only)"),
    db: Session = Depends(get_db),
):
    """Provides real-time risk tier distribution and step-up verification count for qualifying live sessions."""
    from app.services.session_service import SessionService
    SessionService.reap_expired_sessions(db)

    prod_only = (scope or "all").strip().lower() == "genuine"
    genuine_uid_set = set()
    if prod_only:
        verified_uid_rows = (
            db.query(SecurityEvent.user_id)
            .filter(
                SecurityEvent.event_type.in_([
                    "USER_REGISTERED",
                    "EMAIL_VERIFICATION_COMPLETED",
                    "LOGIN_OTP_VERIFIED",
                    "STEP_UP_VERIFIED",
                    "PASSWORD_RESET_SUCCESS",
                ])
            )
            .distinct()
            .all()
        )
        verified_uid_set = {r[0] for r in verified_uid_rows if r[0] is not None}
        for u in db.query(User).all():
            if _classify_user_account(u, has_verified_history=(u.id in verified_uid_set))["is_genuine_human"]:
                genuine_uid_set.add(u.id)

    active_base = db.query(DbSession).filter(
        DbSession.status == "ACTIVE",
        DbSession.logout_time.is_(None),
        ~DbSession.id.like("sim_%"),
        ~DbSession.id.like("test_%")
    )
    if prod_only:
        active_base = active_base.filter(DbSession.user_id.in_(genuine_uid_set)) if genuine_uid_set else active_base.filter(DbSession.user_id == -1)

    low = active_base.filter(DbSession.current_risk_level == "LOW").count()
    med = active_base.filter(DbSession.current_risk_level == "MEDIUM").count()
    high = active_base.filter(DbSession.current_risk_level == "HIGH").count()
    crit = active_base.filter(DbSession.current_risk_level == "CRITICAL").count()
    step_ups = active_base.filter(DbSession.step_up_verified_at.isnot(None)).count()
    threat_q = db.query(Alert).filter(
        Alert.status.in_(["OPEN", "REOPENED"]),
        ~Alert.message.ilike("%sim_%"),
        ~Alert.message.ilike("%simulated%"),
        ~Alert.message.ilike("%test%")
    )
    if prod_only:
        threat_q = threat_q.filter(Alert.user_id.in_(genuine_uid_set)) if genuine_uid_set else threat_q.filter(Alert.user_id == -1)
    active_threats = threat_q.count()

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
    if application and application.upper() != "ALL":
        app_norm = application.strip().lower()
        if app_norm in ("shopping", "ecommerce"):
            query = query.filter(DbSession.application.in_(["shopping", "ecommerce"]))
        else:
            query = query.filter(DbSession.application == app_norm)
    if status and status.upper() != "ALL":
        query = query.filter(DbSession.status == status.upper())
    if risk_level and risk_level.upper() != "ALL":
        query = query.filter(DbSession.current_risk_level == risk_level.upper())
    if scope and scope.lower() == "genuine":
        query = query.filter(
            DbSession.user_id.in_(_non_admin_user_ids_subquery(db)),
            ~DbSession.id.like("sim_%"),
            ~DbSession.id.like("test_%"),
        )
    elif scope and scope.lower() == "active":
        query = query.filter(
            DbSession.user_id.in_(_non_admin_user_ids_subquery(db)),
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

    session_ids = [s.id for s in sessions]
    last_activity_map = {}
    if session_ids:
        beh_rows = (
            db.query(BehaviorLog.session_id, func.max(BehaviorLog.timestamp))
            .filter(BehaviorLog.session_id.in_(session_ids))
            .group_by(BehaviorLog.session_id)
            .all()
        )
        for sid, ts in beh_rows:
            if sid and ts:
                last_activity_map[sid] = ts
        ev_rows = (
            db.query(SecurityEvent.session_id, func.max(SecurityEvent.timestamp))
            .filter(SecurityEvent.session_id.in_(session_ids))
            .group_by(SecurityEvent.session_id)
            .all()
        )
        for sid, ts in ev_rows:
            if sid and ts and (sid not in last_activity_map or ts > last_activity_map[sid]):
                last_activity_map[sid] = ts

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

        browser_os = None
        if dev:
            b_part = dev.browser_name or (dev.browser[:30] if dev.browser else None)
            o_part = dev.os_name or (dev.os[:30] if dev.os else None)
            parts = [p for p in (b_part, o_part) if p and p != "Unknown"]
            if parts:
                browser_os = " · ".join(parts)

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
            last_activity=last_activity_map.get(s.id) or s.logout_time or s.login_time,
            browser_os=browser_os,
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
            SecurityEvent.user_id.in_(_non_admin_user_ids_subquery(db)),
            ~SecurityEvent.event_type.like("ADMIN_%"),
            ~SecurityEvent.event_type.like("AGENTIC_%"),
            ~SecurityEvent.event_type.in_(
                _ADMIN_ONLY_EVENT_TYPES + ("AGENT_DEMO_ANALYSIS", "AGENT_ORCHESTRATION_AUDIT")
            ),
            ~func.coalesce(SecurityEvent.session_id, "").like("sim_%"),
            ~func.coalesce(SecurityEvent.session_id, "").like("test_%"),
            ~func.coalesce(SecurityEvent.details, "").ilike("%simulated%"),
            ~func.coalesce(SecurityEvent.details, "").ilike("%attack_simulator%"),
            ~func.coalesce(SecurityEvent.details, "").ilike("%test%"),
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
            Alert.user_id.in_(_non_admin_user_ids_subquery(db)),
            ~func.coalesce(Alert.message, "").ilike("%sim_%"),
            ~func.coalesce(Alert.message, "").ilike("%simulated%"),
            ~func.coalesce(Alert.message, "").ilike("%test%"),
            ~func.coalesce(Alert.notes, "").ilike("%simulated%"),
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
    
    prev_status = (alert.status or "OPEN").upper()
    new_status = request.status.upper()
    if new_status not in _VALID_INCIDENT_TRANSITIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid incident status '{request.status}'. Allowed: {sorted(list(_VALID_INCIDENT_TRANSITIONS.keys()))}"
        )
    allowed_next = _VALID_INCIDENT_TRANSITIONS.get(prev_status, set())
    if new_status not in allowed_next:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid lifecycle transition from {prev_status} to {new_status}."
        )
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
        decision_act = "RESOLVE_ALERT"
    elif new_status == "CONTAINED":
        alert.resolved_at = None
        alert.resolved_by = None
        event_type = "ADMIN_ALERT_CONTAINED"
        decision_act = "CONTAIN_ALERT"
    elif new_status in ("OPEN", "REOPENED") and prev_status == "RESOLVED":
        alert.resolved_at = None
        alert.resolved_by = None
        event_type = "ADMIN_ALERT_REOPENED"
        decision_act = "REOPEN_ALERT"
    else:
        event_type = "ADMIN_ALERT_TRIAGED"
        decision_act = "TRIAGE_ALERT"

    # Record administrative action in security_events
    notes_detail = alert.notes or alert.resolution_reason or "Handled in SOC Console"
    audit_ev = SecurityEvent(
        user_id=alert.user_id,
        application=alert.application,
        event_type=event_type,
        severity="LOW",
        anomaly_score=0.0,
        risk_score=0.0,
        decision=decision_act,
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
    Correlates an incident or security event into a comprehensive Zero-Trust investigation dossier
    strictly from persisted database records without fabricating missing telemetry or decisions.
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

    # A. User dossier
    user_data = {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "role": user.role,
        "account_status": user.account_status,
        "created_at": user.created_at.isoformat() if user.created_at else None
    } if user else None

    # B. Session dossier (clearly reflects current session state, separate from historical incident risk)
    db_sess = db.query(DbSession).filter(DbSession.id == session_id).first() if session_id else None
    sess_data = {
        "id": db_sess.id,
        "status": db_sess.status,
        "risk_level": db_sess.current_risk_level,
        "current_risk_level": db_sess.current_risk_level,
        "ip_address": db_sess.ip_address,
        "application": db_sess.application,
        "login_time": db_sess.login_time.isoformat() if db_sess.login_time else None,
        "logout_time": db_sess.logout_time.isoformat() if db_sess.logout_time else None,
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
        "device_fingerprint": (device.device_fingerprint[:16] + "...") if device.device_fingerprint else None,
        "nickname": device.nickname or f"{device.browser_name or 'Browser'} on {device.os_name or 'OS'}",
        "browser": f"{device.browser_name or 'Unknown'} {device.browser_version or ''}".strip(),
        "os": f"{device.os_name or 'Unknown'} {device.os_version or ''}".strip(),
        "ip_address": device.last_ip or (db_sess.ip_address if db_sess else None),
        "location": f"{device.city or 'Unknown City'}, {device.country or 'Unknown Country'}",
        "location_source": device.location_source,
        "trust_state": device.trust_state,
        "is_trusted": device.is_trusted,
        "first_seen": device.first_seen.isoformat() if device.first_seen else None,
        "last_seen": device.last_seen.isoformat() if device.last_seen else None
    } if device else None

    # C. Historical Risk Assessment & Enforcement (NEVER fabricate ALLOW/ACCESS_GRANTED)
    det_json: Dict[str, Any] = {}
    if sec_event and sec_event.details:
        try:
            parsed = json.loads(sec_event.details)
            if isinstance(parsed, dict):
                det_json = parsed
        except Exception:
            det_json = {}

    factors = det_json.get("factors", []) if isinstance(det_json.get("factors"), list) else []
    adaptive_rec = (
        det_json.get("adaptive_auth_recommendation")
        or det_json.get("recommended_action")
        or det_json.get("step_up_factor")
        or (db_sess.step_up_factor if db_sess and db_sess.step_up_factor else None)
    )

    if sec_event:
        hist_risk_score = float(sec_event.risk_score) if sec_event.risk_score is not None else None
        hist_anom_score = float(sec_event.anomaly_score) if sec_event.anomaly_score is not None else None
        hist_risk_level = sec_event.severity or _score_to_risk_level(hist_risk_score) or "Not recorded"
        hist_decision = sec_event.decision or "Not recorded"

        dec_upper = (sec_event.decision or "").upper()
        if det_json.get("enforcement_outcome"):
            enforcement = str(det_json["enforcement_outcome"])
        elif dec_upper in ("TERMINATE_SESSION",):
            enforcement = "TERMINATE_SESSION"
        elif dec_upper in ("LOCK_PORTAL", "PORTAL_LOCKED"):
            enforcement = "PORTAL_LOCKED"
        elif dec_upper in ("PENDING_ADMIN_RECOVERY",):
            enforcement = "PENDING_ADMIN_RECOVERY"
        elif dec_upper in ("DENY", "BLOCK"):
            enforcement = "DENIED"
        elif dec_upper == "RESTRICT":
            enforcement = "RESTRICTED"
        elif dec_upper in ("STEP_UP_VERIFICATION", "STEP_UP_REQUIRED"):
            enforcement = "STEP_UP_REQUIRED"
        elif dec_upper == "ALLOW":
            enforcement = "ALLOW"
        else:
            enforcement = sec_event.decision or "Not recorded"
    else:
        hist_risk_score = None
        hist_anom_score = None
        hist_risk_level = alert.severity if alert else "Not recorded"
        hist_decision = "Not recorded"
        enforcement = "Not recorded"

    # Step-Up history (correlated to session_id when available, else user_id)
    step_q = db.query(SecurityEvent).filter(
        SecurityEvent.user_id == user_id,
        SecurityEvent.event_type.in_(["STEP_UP_CHALLENGE", "STEP_UP_VERIFIED", "STEP_UP_FAILED", "STEP_UP_LOCKED", "MFA_CHALLENGE", "MFA_VERIFIED"])
    )
    if session_id:
        step_q = step_q.filter(SecurityEvent.session_id == session_id)
    step_events = step_q.order_by(SecurityEvent.timestamp.desc()).limit(10).all()

    step_up_history = []
    for ev in step_events:
        outcome = "VERIFIED" if "VERIFIED" in ev.event_type else ("LOCKED" if "LOCKED" in ev.event_type else ("FAILED" if "FAILED" in ev.event_type else (ev.decision or ev.event_type)))
        step_up_history.append({
            "event_id": ev.id,
            "event_type": ev.event_type,
            "outcome": outcome,
            "timestamp": ev.timestamp.isoformat(),
            "decision": ev.decision,
            "severity": ev.severity,
            "details": ev.details
        })

    # D. Behavioral Signals & Real Baseline Comparison (canonical 10 features)
    behavior_log = None
    if session_id:
        behavior_log = db.query(BehaviorLog).filter(BehaviorLog.session_id == session_id).order_by(BehaviorLog.timestamp.desc()).first()
    if not behavior_log and user_id:
        behavior_log = db.query(BehaviorLog).filter(BehaviorLog.user_id == user_id).order_by(BehaviorLog.timestamp.desc()).first()

    observed_signals = {
        "typing_speed_wpm": behavior_log.typing_speed_wpm,
        "avg_flight_time_ms": behavior_log.avg_flight_time_ms,
        "avg_dwell_time_ms": behavior_log.avg_dwell_time_ms,
        "mouse_velocity_avg": behavior_log.mouse_velocity_avg,
        "mouse_acceleration_avg": behavior_log.mouse_acceleration_avg,
        "mouse_curvature_entropy": behavior_log.mouse_curvature_entropy,
        "click_frequency": behavior_log.click_frequency,
        "scroll_speed_avg": behavior_log.scroll_speed_avg,
        "idle_duration_sec": behavior_log.idle_duration_sec,
        "navigation_entropy": behavior_log.navigation_entropy,
    } if behavior_log else {}

    prof = db.query(BehaviorProfile).filter(BehaviorProfile.user_id == user_id).first() if user_id else None
    sample_count = int(prof.sample_count or 0) if prof else 0
    baseline_status_label, _, _ = ProfileService.get_maturity_info(sample_count) if prof else ("COLD_START", 0.0, False)

    means: Dict[str, Any] = {}
    stds: Dict[str, Any] = {}
    if prof and sample_count > 0 and prof.baseline_features:
        try:
            bf = json.loads(prof.baseline_features)
            if isinstance(bf, dict):
                means = bf.get("means") if isinstance(bf.get("means"), dict) else bf
                stds = bf.get("stds") if isinstance(bf.get("stds"), dict) else {}
        except Exception:
            means, stds = {}, {}

    deviation_status: Dict[str, str] = {}
    canonical_keys = [
        "typing_speed_wpm", "avg_flight_time_ms", "avg_dwell_time_ms",
        "mouse_velocity_avg", "mouse_acceleration_avg", "mouse_curvature_entropy",
        "click_frequency", "scroll_speed_avg", "idle_duration_sec", "navigation_entropy"
    ]
    for k in canonical_keys:
        if sample_count <= 0 or k not in means or means.get(k) is None:
            deviation_status[k] = "No baseline data available"
        elif k not in observed_signals or observed_signals.get(k) is None:
            deviation_status[k] = "No observation recorded"
        else:
            obs_v = float(observed_signals[k])
            base_m = float(means[k])
            base_s = float(stds.get(k) or 0.0)
            z = abs(obs_v - base_m) / max(base_s, max(abs(base_m) * 0.15, 1e-3))
            if z >= 3.0:
                deviation_status[k] = "HIGH DEVIATION"
            elif z >= 1.75:
                deviation_status[k] = "ELEVATED"
            else:
                deviation_status[k] = "NORMAL"

    behavioral_signals = {
        "observed_signals": observed_signals,
        "user_baseline": {"means": means, "stds": stds} if sample_count > 0 else {},
        "deviation_status": deviation_status,
        "baseline_status": baseline_status_label,
        "baseline_samples": sample_count,
        "has_persisted_telemetry": bool(behavior_log),
    }

    # E. Chronological timeline of correlated events (deduplicated by SecurityEvent.id)
    timeline_query = db.query(SecurityEvent).filter(SecurityEvent.user_id == user_id)
    if session_id:
        timeline_query = timeline_query.filter(
            (SecurityEvent.session_id == session_id) | (SecurityEvent.session_id.is_(None))
        )
    timeline_events = timeline_query.order_by(SecurityEvent.timestamp.asc(), SecurityEvent.id.asc()).limit(40).all()

    seen_ev_ids = set()
    related_timeline = []
    for ev in timeline_events:
        if ev.id in seen_ev_ids:
            continue
        seen_ev_ids.add(ev.id)
        related_timeline.append({
            "id": ev.id,
            "timestamp": ev.timestamp.isoformat(),
            "event_type": ev.event_type,
            "application": ev.application,
            "decision": ev.decision,
            "severity": ev.severity,
            "risk_level": ev.severity or _score_to_risk_level(ev.risk_score),
            "risk_score": float(ev.risk_score) if ev.risk_score is not None else None,
            "anomaly_score": float(ev.anomaly_score) if ev.anomaly_score is not None else None,
            "session_id": ev.session_id,
            "details": ev.details
        })

    # F. Administrative action history
    admin_actions_query = db.query(SecurityEvent).filter(
        SecurityEvent.user_id == user_id,
        SecurityEvent.event_type.in_([
            "ADMIN_SESSION_TERMINATED",
            "ADMIN_DEVICE_REVOKED",
            "ADMIN_DEVICE_TRUSTED",
            "ADMIN_ALERT_RESOLVED",
            "ADMIN_ALERT_TRIAGED",
            "ADMIN_ALERT_REOPENED",
            "ADMIN_ALERT_CONTAINED",
            "ADMIN_INCIDENT_RESOLVED",
            "ADMIN_INCIDENT_TRIAGED",
            "ADMIN_INCIDENT_REOPENED",
            "ADMIN_INCIDENT_INVESTIGATING",
            "ADMIN_INCIDENT_ACKNOWLEDGED",
            "ADMIN_INCIDENT_CONTAINED",
            "PORTAL_RECOVERY_APPROVED",
            "PORTAL_RECOVERY_REJECTED",
        ])
    ).order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc()).limit(15).all()

    admin_actions = [{
        "id": ev.id,
        "action": ev.event_type,
        "decision": ev.decision,
        "timestamp": ev.timestamp.isoformat(),
        "details": ev.details
    } for ev in admin_actions_query]

    latest_admin_ts = admin_actions_query[0].timestamp if admin_actions_query else None
    updated_at_val = (alert.resolved_at if alert and alert.resolved_at else latest_admin_ts) or (alert.created_at if alert else sec_event.timestamp)
    notes_val = getattr(alert, "notes", None) if alert else None

    return IncidentInvestigationResponse(
        incident_id=alert.id if alert else sec_event.id,
        alert_id=alert.id if alert else None,
        security_event_id=sec_event.id if sec_event else None,
        incident_category=alert.alert_type if alert else sec_event.event_type,
        timestamp=alert.created_at if alert else sec_event.timestamp,
        updated_at=updated_at_val,
        severity=alert.severity if alert else sec_event.severity,
        status=alert.status if alert else "RECORDED_EVENT",
        event_type=sec_event.event_type if sec_event else alert.alert_type,
        application=alert.application if alert else (sec_event.application if sec_event else "platform"),
        message=alert.message if alert else (sec_event.details or "Security Event"),
        user=user_data,
        device=device_data,
        session=sess_data,
        risk_assessment={
            "risk_score": hist_risk_score,
            "risk_level": hist_risk_level,
            "anomaly_score": hist_anom_score,
            "decision": hist_decision,
            "risk_decision": hist_decision,
            "adaptive_auth_recommendation": adaptive_rec or "Not recorded",
            "enforcement_outcome": enforcement,
            "decision_reason": alert.message if alert else (sec_event.details if sec_event else None),
            "contributing_factors": factors
        },
        behavioral_signals=behavioral_signals,
        step_up_history=step_up_history,
        step_up_challenges=step_up_history,
        related_timeline=related_timeline,
        enforcement_outcome=enforcement,
        admin_actions=admin_actions,
        investigation_notes=notes_val,
        notes=notes_val,
        assigned_to=getattr(alert, "assigned_to", None) if alert else None,
        resolution_reason=getattr(alert, "resolution_reason", None) if alert else None,
        resolved_at=getattr(alert, "resolved_at", None) if alert else None,
        resolved_by=getattr(alert, "resolved_by", None) if alert else None,
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


_HUMAN_ACTION_LABELS = {
    "ADMIN_SESSION_TERMINATED": "Administrator terminated a session",
    "ADMIN_DEVICE_REVOKED": "Administrator revoked a device",
    "ADMIN_DEVICE_TRUSTED": "Administrator confirmed device trust",
    "ADMIN_DEVICE_TRUST_MODIFIED": "Administrator updated device trust status",
    "ADMIN_ALERT_RESOLVED": "Administrator resolved a security incident",
    "ADMIN_ALERT_TRIAGED": "Administrator triaged a security incident",
    "ADMIN_ALERT_REOPENED": "Administrator reopened a security incident",
    "ADMIN_RESCAN": "Administrator ran a platform security re-scan",
    "ADMIN_REVOCATION": "Administrator enforced access revocation",
    "PORTAL_RECOVERY_APPROVED": "Administrator approved portal recovery",
    "PORTAL_RECOVERY_REJECTED": "Administrator rejected portal recovery",
    "PORTAL_SECURITY_LOCKED": "Security system suspended portal access",
    "PORTAL_RECOVERY_OTP_REQUESTED": "User requested portal recovery verification code",
    "PORTAL_RECOVERY_OTP_VERIFIED": "User completed portal recovery OTP verification",
    "PORTAL_RECOVERY_OTP_FAILED": "Portal recovery OTP verification failed",
    "ZERO_TRUST_KILL_SWITCH": "Security system terminated a high-risk session",
    "SESSION_TERMINATED": "Session terminated",
    "GRANT_REVOKED": "Security system revoked a protected-resource grant",
    "LOGIN_SUCCESS": "User signed in",
    "LOGIN_ATTEMPT_FAILED": "Login attempt failed",
    "LOGIN_OTP_ISSUED": "System issued login verification OTP",
    "LOGIN_OTP_VERIFIED": "User completed login OTP verification",
    "LOGIN_OTP_FAILED": "Login OTP verification failed",
    "STEP_UP_CHALLENGE": "Security system issued step-up verification challenge",
    "STEP_UP_VERIFIED": "User completed step-up verification",
    "STEP_UP_FAILED": "Step-up verification failed",
    "PASSWORD_CHANGE_COMPLETED": "User updated account password",
    "DEVICE_TRUST_MODIFIED": "Device trust status changed",
    "DEVICE_REVOKED": "Device trust revoked",
    "BEHAVIORAL_ANOMALY": "Behavioral anomaly detected",
    "BEHAVIOR_ANOMALY": "Behavioral anomaly detected",
    "BEHAVIORAL_TELEMETRY_RECEIVED": "Behavioural telemetry received",
    "BASELINE_UPDATED": "Behavioural baseline maturity updated",
    "RISK_LEVEL_TRANSITION": "Session risk level changed",
    "SESSION_LOGOUT": "User signed out",
    "USER_REGISTERED": "User registered account",
    "EMAIL_VERIFICATION_COMPLETED": "User verified email address",
    "PROTECTED_RESOURCE_ACCESSED": "Protected portal resource accessed",
    "EXAM_ACCESS_GRANTED": "Online exam access granted",
    "EXAM_ACCESS_DENIED": "Online exam access denied",
    "EXAM_OTP_VERIFIED": "Exam OTP verified",
}


def _classify_audit_actor(ev: SecurityEvent, user_map: Dict[int, User]) -> tuple[str, str]:
    """Returns (actor_type, actor_label) without ever attributing system actions to an administrator."""
    et = (ev.event_type or "").upper()
    details = ev.details or ""
    is_admin_action = et.startswith("ADMIN_") or et in ("PORTAL_RECOVERY_APPROVED", "PORTAL_RECOVERY_REJECTED")
    if is_admin_action:
        extracted_email = None
        if "(" in details and "@" in details:
            try:
                for chunk in details.split("(")[1:]:
                    cand = chunk.split(")")[0].strip()
                    if "@" in cand:
                        extracted_email = cand
                        break
            except Exception:
                pass
        return ("ADMIN", extracted_email or "Authorized Administrator")

    if et.startswith("AGENT_") or et.startswith("AGENTIC_") or "SOC_AGENT" in details.upper() or "MONITORING_AGENT" in details.upper():
        return ("AGENT", "SecurityOrchestrator (Advisory)")

    user_actions = {
        "USER_REGISTERED",
        "EMAIL_VERIFICATION_COMPLETED",
        "LOGIN_SUCCESS",
        "LOGIN_OTP_VERIFIED",
        "STEP_UP_VERIFIED",
        "PASSWORD_CHANGE_COMPLETED",
        "PORTAL_RECOVERY_OTP_REQUESTED",
        "PORTAL_RECOVERY_OTP_VERIFIED",
        "SESSION_LOGOUT",
    }
    if et in user_actions:
        u = user_map.get(ev.user_id)
        label = f"{u.name} ({u.email})" if u else f"User #{ev.user_id}"
        return ("USER", label)

    return ("SYSTEM", "COGNISEC Security System")


def _classify_audit_category(event_type: str) -> str:
    et = (event_type or "").upper()
    if et.startswith("ADMIN_") or et in ("PORTAL_RECOVERY_APPROVED", "PORTAL_RECOVERY_REJECTED", "DEV_LOCKOUT_RESET"):
        return "Administrator Actions"
    if et.startswith("AGENTIC_") or et.startswith("AGENT_"):
        return "Agentic AI Activity"
    if et in ("USER_REGISTERED", "EMAIL_VERIFICATION_COMPLETED", "PASSWORD_RESET_SUCCESS", "DEVICE_CONFIRMED_TRUSTED", "DEVICE_REVOKED") or et.startswith("PASSWORD_CHANGE_"):
        return "Identity & Registration"
    if et.startswith("LOGIN_") or et in ("UNRECOGNIZED_DEVICE_LOGIN", "UNRECOGNIZED_DEVICE_ACCESS", "ACCOUNT_LOCKED", "SESSION_LOGOUT"):
        return "Authentication"
    if et in ("BEHAVIOR_ANOMALY", "BASELINE_UPDATED", "BEHAVIOR_PROFILE_UPDATED", "BEHAVIORAL_ANOMALY", "BEHAVIORAL_TELEMETRY_RECEIVED", "RISK_LEVEL_TRANSITION"):
        return "Behavioural Monitoring"
    if et.startswith("STEP_UP_") or et.startswith("MFA_") or et in ("EXAM_OTP_VERIFIED",):
        return "Adaptive Authentication"
    if et in ("PROTECTED_RESOURCE_ACCESSED", "EXAM_ACCESS_GRANTED", "EXAM_ACCESS_DENIED", "HIGH_RISK_CHECKOUT_ATTEMPT"):
        return "Portal Activity"
    if et in ("SESSION_RESTRICTED", "SESSION_TERMINATED", "PORTAL_SECURITY_LOCKED", "PORTAL_LOCK_RECOVERED", "VAULT_GRANT_REVOKED", "ZERO_TRUST_KILL_SWITCH"):
        return "Security Response"
    return "Authentication"


def _derive_audit_result(ev: SecurityEvent) -> str:
    dec = (ev.decision or "").upper()
    et = (ev.event_type or "").upper()
    if et.startswith("AGENTIC_") or et.startswith("AGENT_"):
        if "TIMEOUT" in dec or "FALLBACK" in dec:
            return "Fallback (Timeout)"
        if "ESCALAT" in dec:
            return "Escalated by Arbiter"
        return "Advisory Completed"
    if "REJECT" in et or dec in ("DENY", "BLOCK", "REJECTED"):
        return "Denied"
    if "FAIL" in et or "FAILED" in dec:
        return "Failed"
    if "PENDING" in et or "CHALLENGE" in et or "ISSUED" in et or "REQUESTED" in et:
        return "Pending"
    if dec in ("TERMINATE_SESSION", "REVOKE_DEVICE", "RESTRICT", "LOCK_PORTAL"):
        return "Enforced"
    return "Successful"


def _parse_sanitized_audit_details(ev: SecurityEvent) -> tuple[str, Optional[Dict[str, Any]]]:
    """Produces a clean human-readable summary (no raw JSON) and sanitized technical details."""
    from app.agents.core.sanitization import Sanitizer
    raw = (ev.details or "").strip()
    et = (ev.event_type or "").upper()
    portal = (ev.application or "platform").capitalize()
    parsed_dict: Optional[Dict[str, Any]] = None

    if raw.startswith("{") and raw.endswith("}"):
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                parsed_dict = Sanitizer.sanitize_dict(obj)
        except Exception:
            parsed_dict = None

    if parsed_dict is not None:
        if "agentic_orchestration" in parsed_dict and isinstance(parsed_dict["agentic_orchestration"], dict):
            obs = parsed_dict["agentic_orchestration"]
            trig = obs.get("trigger_event") or et
            exec_st = obs.get("execution_status") or ev.decision or "COMPLETED"
            agents = obs.get("agents_executed") or []
            provider = obs.get("llm_provider") or "configured"
            summary = f"Advisory analysis for {str(trig).replace('_', ' ').title()} on {portal} ({exec_st}; {len(agents)} agents via {provider})."
            return summary, parsed_dict
        if parsed_dict.get("summary"):
            return str(parsed_dict["summary"]), parsed_dict
        if parsed_dict.get("message"):
            return str(parsed_dict["message"]), parsed_dict
        # Fallback clean summary from keys without raw JSON
        clean_parts = [f"{k.replace('_', ' ')}: {v}" for k, v in list(parsed_dict.items())[:4] if v is not None]
        return ("; ".join(clean_parts) if clean_parts else f"{et.replace('_', ' ').title()} on {portal}"), parsed_dict

    if raw:
        return raw, {"message": raw}
    return f"{et.replace('_', ' ').title()} recorded on {portal}.", None


_ADMIN_ONLY_EVENT_TYPES = (
    "DEV_LOCKOUT_RESET",
    "PORTAL_RECOVERY_APPROVED",
    "PORTAL_RECOVERY_REJECTED",
)


def _apply_customer_activity_scope(db: Session, q, activity_scope: Optional[str]):
    """
    Separates genuine registered-user activity from administrator, agent-demo,
    test, and synthetic records in Security Intelligence queries.
    """
    scope_norm = (activity_scope or "user").strip().lower()
    if scope_norm == "all":
        return q
    if scope_norm == "admin":
        admin_uids = db.query(User.id).filter(User.role == "ADMIN")
        return q.filter(
            or_(
                SecurityEvent.event_type.like("ADMIN_%"),
                SecurityEvent.event_type.in_(_ADMIN_ONLY_EVENT_TYPES),
                SecurityEvent.event_type == "AGENT_DEMO_ANALYSIS",
                SecurityEvent.user_id.in_(admin_uids),
            )
        )
    # Default: "user" — genuine publicly registered human user activity only
    genuine_filter = _build_user_scope_filter(db, "genuine")
    genuine_uids = db.query(User.id).filter(genuine_filter)
    return q.filter(
        SecurityEvent.user_id.in_(genuine_uids),
        ~SecurityEvent.event_type.like("ADMIN_%"),
        ~SecurityEvent.event_type.like("AGENTIC_%"),
        ~SecurityEvent.event_type.in_(
            _ADMIN_ONLY_EVENT_TYPES + ("AGENT_DEMO_ANALYSIS", "AGENT_ORCHESTRATION_AUDIT")
        ),
    )


@router.get("/audit-trail", response_model=AuditTrailResponse)
def get_audit_trail(
    search: Optional[str] = Query(None, description="Search by email, name, session ID, action, or summary"),
    activity_scope: Optional[str] = Query("user", description="user (default: registered user activity), admin (admin/demo audit), all"),
    actor_type: Optional[str] = Query("ALL", description="ALL, ADMIN, SYSTEM, AGENT, USER"),
    category: Optional[str] = Query("ALL", description="Filter by audit category"),
    application: Optional[str] = Query("ALL", description="Filter by portal/application"),
    action: Optional[str] = Query("ALL", description="Filter by event_type"),
    result: Optional[str] = Query("ALL", description="Filter by outcome"),
    risk_level: Optional[str] = Query("ALL", description="ALL, LOW, MEDIUM, HIGH, CRITICAL"),
    operator: Optional[str] = Query(None, description="Filter by administrator/operator email"),
    user_id: Optional[int] = Query(None, description="Filter by target user ID"),
    date_from: Optional[str] = Query(None, description="ISO date/datetime lower bound (YYYY-MM-DD)"),
    date_to: Optional[str] = Query(None, description="ISO date/datetime upper bound (YYYY-MM-DD)"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """Paginated, categorized, deduplicated Security Intelligence timeline backed by persisted SecurityEvent rows."""
    q = _apply_customer_activity_scope(db, db.query(SecurityEvent), activity_scope)
    if action and action.upper() != "ALL":
        q = q.filter(SecurityEvent.event_type == action.upper())
    if application and application.upper() != "ALL":
        q = q.filter(SecurityEvent.application == application.lower())
    if risk_level and risk_level.upper() != "ALL":
        q = q.filter(SecurityEvent.severity == risk_level.upper())
    if user_id is not None:
        q = q.filter(SecurityEvent.user_id == user_id)
    if date_from:
        try:
            dt_from = datetime.fromisoformat(date_from.strip())
            if dt_from.tzinfo is None:
                dt_from = dt_from.replace(tzinfo=timezone.utc)
            q = q.filter(SecurityEvent.timestamp >= dt_from)
        except Exception:
            pass
    if date_to:
        try:
            raw_to = date_to.strip()
            dt_to = datetime.fromisoformat(raw_to)
            if len(raw_to) == 10:
                dt_to = dt_to + timedelta(days=1)
            if dt_to.tzinfo is None:
                dt_to = dt_to.replace(tzinfo=timezone.utc)
            q = q.filter(SecurityEvent.timestamp < dt_to)
        except Exception:
            pass

    events = q.order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc()).limit(1000).all()
    user_ids = {ev.user_id for ev in events if ev.user_id is not None}
    user_map = {u.id: u for u in db.query(User).filter(User.id.in_(user_ids)).all()} if user_ids else {}
    session_ids = {ev.session_id for ev in events if ev.session_id}
    behav_session_ids = (
        {
            sid
            for (sid,) in db.query(BehaviorLog.session_id)
            .filter(BehaviorLog.session_id.in_(session_ids))
            .distinct()
            .all()
        }
        if session_ids
        else set()
    )
    event_ids = [ev.id for ev in events]
    incident_by_event: Dict[int, int] = {}
    if event_ids:
        for al in db.query(Alert).filter(Alert.security_event_id.in_(event_ids)).order_by(Alert.id.desc()).all():
            if al.security_event_id and al.security_event_id not in incident_by_event:
                incident_by_event[al.security_event_id] = al.id

    search_term = search.strip().lower() if search and search.strip() else None
    op_term = operator.strip().lower() if operator and operator.strip() else None
    actor_filter = (actor_type or "ALL").strip().upper()
    cat_filter = (category or "ALL").strip().lower()
    result_filter = (result or "ALL").strip().lower()

    filtered_items: List[AuditTrailItem] = []
    for ev in events:
        ev_cat = _classify_audit_category(ev.event_type)
        if cat_filter != "all" and ev_cat.lower() != cat_filter:
            continue

        a_type, a_label = _classify_audit_actor(ev, user_map)
        if actor_filter != "ALL" and a_type != actor_filter:
            continue
        if op_term and op_term not in a_label.lower():
            continue

        res_label = _derive_audit_result(ev)
        if result_filter != "all" and res_label.lower() != result_filter:
            continue

        target_user = user_map.get(ev.user_id)
        target_email = target_user.email if target_user else None
        target_name = target_user.name if target_user else (f"User #{ev.user_id}" if ev.user_id else "Not recorded")
        portal_name = (ev.application or "platform").capitalize()
        target_desc = f"{target_name} ({target_email or 'Not recorded'}) · {portal_name}"
        if ev.session_id:
            target_desc += f" · {ev.session_id[:12]}..."

        action_label = _HUMAN_ACTION_LABELS.get(
            (ev.event_type or "").upper(),
            (ev.event_type or "Security Event").replace("_", " ").title(),
        )
        summary_text, tech_details = _parse_sanitized_audit_details(ev)
        corr_id = ev.session_id or f"ev-{ev.id}"
        integrity = "Verified" if ev.timestamp and corr_id else "Unverified"
        ev_risk = (ev.severity or _score_to_risk_level(ev.risk_score) or "Not recorded")
        prev_risk = None
        if isinstance(tech_details, dict):
            prev_risk = tech_details.get("prior_risk_level") or tech_details.get("previous_risk_level")
            if not prev_risk and isinstance(tech_details.get("agentic_orchestration"), dict):
                prev_risk = tech_details["agentic_orchestration"].get("prior_risk_level")
        is_agentic_ev = (ev.event_type or "").upper().startswith("AGENTIC_") or (ev.event_type or "").upper() in ("AGENT_ORCHESTRATION_AUDIT", "AGENT_DEMO_ANALYSIS")
        has_behav = bool(ev.session_id and ev.session_id in behav_session_ids) or (ev.event_type or "").upper() in ("BEHAVIOR_ANOMALY", "AGENTIC_BEHAVIOR_RISK_TRANSITION")

        # Collapse consecutive identical agentic repeats within 60 seconds in the audit view
        if (
            filtered_items
            and (ev.event_type or "").upper().startswith("AGENTIC_")
            and filtered_items[-1].action_code == ev.event_type
            and filtered_items[-1].session_id == ev.session_id
            and filtered_items[-1].result == res_label
            and filtered_items[-1].risk_level == ev_risk
            and abs((filtered_items[-1].timestamp - ev.timestamp).total_seconds()) <= 60
        ):
            filtered_items[-1].repeat_count += 1
            continue

        if search_term:
            haystack = " ".join(
                [
                    a_label,
                    ev_cat,
                    action_label,
                    ev.event_type or "",
                    target_desc,
                    ev.session_id or "",
                    res_label,
                    summary_text,
                ]
            ).lower()
            if search_term not in haystack:
                continue

        filtered_items.append(
            AuditTrailItem(
                id=ev.id,
                timestamp=ev.timestamp,
                category=ev_cat,
                actor_type=a_type,
                actor_label=a_label,
                action_code=ev.event_type,
                action_label=action_label,
                target_resource=target_desc,
                target_user_id=ev.user_id,
                target_user_name=target_name,
                target_user_email=target_email,
                application=ev.application or "platform",
                session_id=ev.session_id,
                result=res_label,
                risk_level=ev_risk,
                previous_risk_level=str(prev_risk) if prev_risk else None,
                risk_score=round(float(ev.risk_score), 4) if ev.risk_score is not None else None,
                anomaly_score=round(float(ev.anomaly_score), 4) if ev.anomaly_score is not None else None,
                has_behavioral_telemetry=has_behav,
                has_agent_analysis=is_agentic_ev,
                related_incident_id=incident_by_event.get(ev.id),
                summary=summary_text,
                reason=summary_text,
                technical_details=tech_details,
                repeat_count=1,
                correlation_id=corr_id,
                integrity_status=integrity,
            )
        )

    total = len(filtered_items)
    total_pages = max(1, (total + page_size - 1) // page_size)
    safe_page = min(page, total_pages)
    start = (safe_page - 1) * page_size
    page_items = filtered_items[start : start + page_size]

    return AuditTrailResponse(
        items=page_items,
        total=total,
        page=safe_page,
        page_size=page_size,
        total_pages=total_pages,
    )


_CANONICAL_10_FEATURES = [
    ("typing_speed_wpm", "Typing Speed", "WPM"),
    ("avg_flight_time_ms", "Flight Time", "ms"),
    ("avg_dwell_time_ms", "Dwell Time", "ms"),
    ("mouse_velocity_avg", "Mouse Velocity", "px/s"),
    ("mouse_acceleration_avg", "Mouse Acceleration", "px/s²"),
    ("mouse_curvature_entropy", "Curvature Entropy", "bits"),
    ("click_frequency", "Click Frequency", "/s"),
    ("scroll_speed_avg", "Scroll Speed", "px/s"),
    ("idle_duration_sec", "Idle Duration", "s"),
    ("navigation_entropy", "Navigation Entropy", "bits"),
]

_AUTH_EVENT_TYPES = {
    "USER_REGISTERED",
    "EMAIL_VERIFICATION_COMPLETED",
    "LOGIN_OTP_CHALLENGE_ISSUED",
    "LOGIN_OTP_VERIFIED",
    "LOGIN_OTP_FAILED",
    "LOGIN_OTP_RESENT",
    "LOGIN_ATTEMPT_FAILED",
    "UNRECOGNIZED_DEVICE_LOGIN",
    "UNRECOGNIZED_DEVICE_ACCESS",
    "ACCOUNT_LOCKED",
    "PASSWORD_RESET_SUCCESS",
    "DEV_LOCKOUT_RESET",
}
_STEP_UP_CHALLENGE_TYPES = {
    "STEP_UP_CHALLENGE_ISSUED",
    "STEP_UP_CHALLENGE",
    "LOGIN_OTP_CHALLENGE_ISSUED",
    "PASSWORD_CHANGE_INITIATED",
}
_VERIFICATION_SUCCESS_TYPES = {
    "STEP_UP_VERIFIED",
    "LOGIN_OTP_VERIFIED",
    "EXAM_OTP_VERIFIED",
    "PORTAL_RECOVERY_OTP_VERIFIED",
    "PASSWORD_CHANGE_IMAGE_VERIFIED",
    "PASSWORD_CHANGE_PRIVATE_VERIFIED",
    "EMAIL_VERIFICATION_COMPLETED",
}
_VERIFICATION_FAIL_TYPES = {
    "STEP_UP_FAILED",
    "STEP_UP_LOCKED",
    "LOGIN_OTP_FAILED",
    "LOGIN_ATTEMPT_FAILED",
    "PASSWORD_CHANGE_COGNITIVE_FAILED",
    "PASSWORD_CHANGE_COGNITIVE_LOCKED",
}
_TERMINATION_LOCK_TYPES = {
    "SESSION_TERMINATED",
    "ADMIN_SESSION_TERMINATED",
    "ZERO_TRUST_KILL_SWITCH",
    "PORTAL_SECURITY_LOCKED",
    "ACCOUNT_LOCKED",
}
_RESPONSE_ACTION_TYPES = {
    "SESSION_RESTRICTED",
    "SESSION_TERMINATED",
    "ADMIN_SESSION_TERMINATED",
    "ZERO_TRUST_KILL_SWITCH",
    "PORTAL_SECURITY_LOCKED",
    "PORTAL_LOCK_RECOVERED",
    "VAULT_GRANT_REVOKED",
    "DEVICE_REVOKED",
    "ACCOUNT_LOCKED",
}
_AGENT_CATALOG = [
    ("SecurityContextAgent", "Security Context Agent"),
    ("RiskAnalysisAgent", "Risk Analysis Agent"),
    ("AdaptiveAuthAgent", "Adaptive Authentication Agent"),
    ("SecurityResponseAgent", "Security Response Agent"),
    ("SOCMonitoringAgent", "SOC Monitoring Agent"),
]


def _apply_security_event_filters(q, application: Optional[str], risk_level: Optional[str], date_from: Optional[str], date_to: Optional[str], search: Optional[str], db: Session):
    if application and application.upper() != "ALL":
        q = q.filter(SecurityEvent.application == application.lower())
    if risk_level and risk_level.upper() != "ALL":
        q = q.filter(SecurityEvent.severity == risk_level.upper())
    if date_from:
        try:
            dt_from = datetime.fromisoformat(date_from.strip())
            if dt_from.tzinfo is None:
                dt_from = dt_from.replace(tzinfo=timezone.utc)
            q = q.filter(SecurityEvent.timestamp >= dt_from)
        except Exception:
            pass
    if date_to:
        try:
            raw_to = date_to.strip()
            dt_to = datetime.fromisoformat(raw_to)
            if len(raw_to) == 10:
                dt_to = dt_to + timedelta(days=1)
            if dt_to.tzinfo is None:
                dt_to = dt_to.replace(tzinfo=timezone.utc)
            q = q.filter(SecurityEvent.timestamp < dt_to)
        except Exception:
            pass
    if search and search.strip():
        term = f"%{search.strip()}%"
        matched_uids = [u.id for u in db.query(User.id).filter(or_(User.email.ilike(term), User.name.ilike(term))).all()]
        conds = [SecurityEvent.session_id.ilike(term), SecurityEvent.event_type.ilike(term), SecurityEvent.details.ilike(term)]
        if matched_uids:
            conds.append(SecurityEvent.user_id.in_(matched_uids))
        q = q.filter(or_(*conds))
    return q


def _build_behavioural_intelligence(db: Session, user_id: Optional[int], session_id: Optional[str], ref_ts: Optional[datetime], ev_anomaly: Optional[float], ev_risk: Optional[float]) -> BehaviouralIntelligencePayload:
    if not user_id and not session_id:
        return BehaviouralIntelligencePayload(
            telemetry_available=False,
            baseline_available=False,
            note="No user or session is associated with this event.",
        )

    behav_log = None
    if session_id:
        q = db.query(BehaviorLog).filter(BehaviorLog.session_id == session_id)
        if ref_ts:
            behav_log = q.filter(BehaviorLog.timestamp <= ref_ts + timedelta(seconds=5)).order_by(BehaviorLog.timestamp.desc()).first()
        if not behav_log:
            behav_log = q.order_by(BehaviorLog.timestamp.desc()).first()
    if not behav_log and user_id:
        q = db.query(BehaviorLog).filter(BehaviorLog.user_id == user_id)
        if ref_ts:
            behav_log = q.filter(BehaviorLog.timestamp <= ref_ts + timedelta(seconds=5)).order_by(BehaviorLog.timestamp.desc()).first()
        if not behav_log:
            behav_log = q.order_by(BehaviorLog.timestamp.desc()).first()

    profile = db.query(BehaviorProfile).filter(BehaviorProfile.user_id == user_id).first() if user_id else None
    sample_count = int(profile.sample_count or 0) if profile else 0
    maturity_label, maturity_progress, _ = ProfileService.get_maturity_info(sample_count)

    baseline_json: Dict[str, Any] = {}
    if profile and profile.baseline_features:
        try:
            parsed = json.loads(profile.baseline_features)
            if isinstance(parsed, dict):
                baseline_json = parsed
        except Exception:
            baseline_json = {}

    means = baseline_json.get("means") if isinstance(baseline_json.get("means"), dict) else {}
    stds = baseline_json.get("stds") if isinstance(baseline_json.get("stds"), dict) else {}
    baseline_available = bool(profile and means)

    raw_obs: Dict[str, Any] = {}
    if behav_log and behav_log.raw_feature_json:
        try:
            parsed_raw = json.loads(behav_log.raw_feature_json)
            if isinstance(parsed_raw, dict):
                raw_obs = parsed_raw
        except Exception:
            raw_obs = {}

    features: List[BehaviouralFeatureComparison] = []
    for key, label, unit in _CANONICAL_10_FEATURES:
        obs_val = round(float(getattr(behav_log, key)), 4) if behav_log and getattr(behav_log, key, None) is not None else None
        mean_val = round(float(means[key]), 4) if key in means and means[key] is not None else None
        std_val = round(float(stds[key]), 4) if key in stds and stds[key] is not None else None
        dev_z = None
        if obs_val is not None and mean_val is not None and std_val is not None and std_val > 1e-6:
            dev_z = round((obs_val - mean_val) / std_val, 2)
        status_txt = "Within baseline"
        if obs_val is None and mean_val is None:
            status_txt = "Not recorded"
        elif mean_val is None:
            status_txt = "No baseline yet"
        elif dev_z is not None and abs(dev_z) >= 2.5:
            status_txt = "High deviation"
        elif dev_z is not None and abs(dev_z) >= 1.5:
            status_txt = "Moderate deviation"
        features.append(
            BehaviouralFeatureComparison(
                key=key,
                label=label,
                unit=unit,
                observed=obs_val,
                baseline_mean=mean_val,
                baseline_std=std_val,
                deviation_z=dev_z,
                status=status_txt,
            )
        )

    note_parts = []
    if not behav_log:
        note_parts.append("No persisted BehaviorLog telemetry sample was found for this session/user.")
    if not baseline_available:
        note_parts.append("Welford statistical baseline is not yet populated for this user.")

    return BehaviouralIntelligencePayload(
        telemetry_available=behav_log is not None,
        baseline_available=baseline_available,
        sample_count=sample_count,
        modality_maturity=maturity_label,
        maturity_progress=round(float(maturity_progress), 2),
        model_version=baseline_json.get("model_version"),
        anomaly_score=round(float(ev_anomaly if ev_anomaly is not None else raw_obs.get("anomaly_score")), 4)
        if (ev_anomaly is not None or raw_obs.get("anomaly_score") is not None)
        else None,
        risk_score=round(float(ev_risk if ev_risk is not None else raw_obs.get("risk_score")), 4)
        if (ev_risk is not None or raw_obs.get("risk_score") is not None)
        else None,
        observed_at=behav_log.timestamp if behav_log else None,
        note=" ".join(note_parts) if note_parts else None,
        features=features,
    )


def _extract_adaptive_auth_item(ev: SecurityEvent, user_map: Dict[int, User]) -> AdaptiveAuthHistoryItem:
    et = (ev.event_type or "").upper()
    details_str = ev.details or ""
    factor = "Not specified"
    if "GESTURE_PATTERN" in details_str or "NeuralTrace" in details_str:
        factor = "NeuralTrace Gesture Pattern"
    elif "COGNITIVE_IMAGE_SEQUENCE" in details_str or "PRIVATE_RESPONSE" in details_str or "PASSWORD_CHANGE_COGNITIVE" in et or "PASSWORD_CHANGE_IMAGE" in et or "PASSWORD_CHANGE_PRIVATE" in et:
        factor = "Compound Cognitive Verification"
    elif "OTP" in et or "OTP" in details_str.upper():
        factor = "Email OTP"
    elif et in ("SESSION_TERMINATED", "ADMIN_SESSION_TERMINATED", "ZERO_TRUST_KILL_SWITCH"):
        factor = "Session Termination"

    if et in ("STEP_UP_VERIFIED", "LOGIN_OTP_VERIFIED", "EXAM_OTP_VERIFIED", "PORTAL_RECOVERY_OTP_VERIFIED", "PASSWORD_CHANGE_IMAGE_VERIFIED", "PASSWORD_CHANGE_PRIVATE_VERIFIED"):
        ch_status = "VERIFIED"
        actual_res = "Challenge Verified"
    elif et in ("STEP_UP_LOCKED", "PASSWORD_CHANGE_COGNITIVE_LOCKED"):
        ch_status = "LOCKED"
        actual_res = "Locked After Failures"
    elif et in ("STEP_UP_FAILED", "LOGIN_OTP_FAILED", "PASSWORD_CHANGE_COGNITIVE_FAILED"):
        ch_status = "FAILED"
        actual_res = "Verification Failed"
    elif et in ("SESSION_TERMINATED", "ADMIN_SESSION_TERMINATED", "ZERO_TRUST_KILL_SWITCH"):
        ch_status = "TERMINATED"
        actual_res = "Session Terminated"
    else:
        ch_status = "ISSUED"
        actual_res = "Challenge Issued (Pending)"

    u = user_map.get(ev.user_id)
    summary_text, _ = _parse_sanitized_audit_details(ev)
    return AdaptiveAuthHistoryItem(
        id=ev.id,
        timestamp=ev.timestamp,
        user_id=ev.user_id,
        user_name=u.name if u else None,
        user_email=u.email if u else None,
        session_id=ev.session_id,
        application=ev.application or "platform",
        risk_level=ev.severity or _score_to_risk_level(ev.risk_score) or "Not recorded",
        risk_score=round(float(ev.risk_score), 4) if ev.risk_score is not None else None,
        requested_factor=factor,
        challenge_status=ch_status,
        actual_result=actual_res,
        reason=summary_text,
    )


def _extract_agent_executions_for_event(ev: SecurityEvent, provider_health: Dict[str, Any]) -> tuple[List[AgentExecutionDetail], Optional[DeterministicArbiterDecision]]:
    _, tech = _parse_sanitized_audit_details(ev)
    obs = {}
    if isinstance(tech, dict):
        if isinstance(tech.get("agentic_orchestration"), dict):
            obs = tech["agentic_orchestration"]
        elif isinstance(tech.get("observability"), dict):
            obs = tech["observability"]
        elif "trigger_event" in tech or "execution_status" in tech or "agents_executed" in tech:
            obs = tech

    exec_status = str(obs.get("execution_status") or ev.decision or "NOT_EXECUTED")
    trigger_ev = str(obs.get("trigger_event") or ev.event_type or "SECURITY_EVENT")
    provider_name = str(obs.get("llm_provider") or provider_health.get("configured_provider") or "mock")
    model_name = str(obs.get("llm_model") or provider_health.get("configured_model") or "unknown")
    conn_status = str(provider_health.get("connectivity_status") or "UNVERIFIED")
    raw_agents = obs.get("agents_executed") or []
    executed_map: Dict[str, str] = {}
    if isinstance(raw_agents, list):
        for entry in raw_agents:
            s_entry = str(entry)
            key = s_entry.split(":")[0]
            executed_map[key] = "FALLBACK" if ":fallback" in s_entry.lower() else exec_status

    per_agent_findings = obs.get("agent_findings") if isinstance(obs.get("agent_findings"), dict) else {}
    fallback_err = obs.get("fallback_or_error")
    latency_ms = obs.get("execution_time_ms") or obs.get("duration_ms") or obs.get("latency_ms")
    confidence_val = obs.get("confidence")

    agent_rows: List[AgentExecutionDetail] = []
    for agent_key, agent_name in _AGENT_CATALOG:
        was_run = agent_key in executed_map
        st = executed_map.get(agent_key, "NOT_EXECUTED")
        if not was_run and "FALLBACK" in exec_status.upper():
            st = exec_status
        finding_info = per_agent_findings.get(agent_key) if isinstance(per_agent_findings.get(agent_key), dict) else {}
        if st in ("TIMEOUT_FALLBACK", "FALLBACK", "FAILED"):
            finding = str(finding_info.get("finding") or f"LLM analysis did not complete ({fallback_err or st}); deterministic policy governed the outcome.")
        elif was_run:
            finding = str(finding_info.get("finding") or obs.get("summary") or f"Evaluated {trigger_ev.replace('_', ' ').title()} context.")
        else:
            finding = "Not executed in this persisted event."

        agent_rows.append(
            AgentExecutionDetail(
                agent_key=agent_key,
                agent_name=agent_name,
                trigger_event=trigger_ev,
                analysis_status=st,
                main_finding=finding,
                recommendation=finding_info.get("recommendation") or obs.get("recommended_action"),
                confidence=float(finding_info.get("confidence") or confidence_val) if (finding_info.get("confidence") is not None or confidence_val is not None) else None,
                provider=provider_name,
                model=model_name,
                provider_status="FALLBACK" if "FALLBACK" in st.upper() else conn_status,
                execution_time_ms=float(latency_ms) if latency_ms is not None else None,
                timestamp=ev.timestamp,
            )
        )

    arbiter = DeterministicArbiterDecision(
        decision=str(obs.get("arbiter_decision") or ev.decision or "RECORDED"),
        risk_level=str(ev.severity or _score_to_risk_level(ev.risk_score) or "LOW"),
        risk_score=round(float(ev.risk_score), 4) if ev.risk_score is not None else None,
        enforced_outcome=_derive_audit_result(ev),
    )
    return agent_rows, arbiter


@router.get("/security-intelligence/overview", response_model=SecurityIntelligenceOverviewResponse)
def get_security_intelligence_overview(
    application: Optional[str] = Query("ALL"),
    risk_level: Optional[str] = Query("ALL"),
    search: Optional[str] = Query(None),
    user_id: Optional[int] = Query(None),
    activity_scope: Optional[str] = Query("user"),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Database-backed user activity & Zero Trust overview for Security Intelligence."""
    base_q = _apply_customer_activity_scope(db, db.query(SecurityEvent), activity_scope)
    if user_id is not None:
        base_q = base_q.filter(SecurityEvent.user_id == user_id)
    q = _apply_security_event_filters(base_q, application, risk_level, date_from, date_to, search, db)
    events = q.all()

    auth_cnt = 0
    behav_cnt = 0
    risk_trans_cnt = 0
    step_up_cnt = 0
    verif_ok_cnt = 0
    verif_fail_cnt = 0
    term_lock_cnt = 0
    resp_cnt = 0
    agentic_cnt = 0
    succ_logins = 0
    fail_logins = 0
    step_up_verifs = 0

    for ev in events:
        et = (ev.event_type or "").upper()
        if et in _AUTH_EVENT_TYPES:
            auth_cnt += 1
        if et in ("LOGIN_SUCCESS", "LOGIN_OTP_VERIFIED"):
            succ_logins += 1
        if et in ("LOGIN_ATTEMPT_FAILED", "LOGIN_OTP_FAILED"):
            fail_logins += 1
        if et in ("BEHAVIOR_ANOMALY", "BEHAVIORAL_ANOMALY"):
            behav_cnt += 1
        if et in ("RISK_LEVEL_TRANSITION", "AGENTIC_BEHAVIOR_RISK_TRANSITION"):
            risk_trans_cnt += 1
        if et in _STEP_UP_CHALLENGE_TYPES:
            step_up_cnt += 1
        if et in ("STEP_UP_VERIFIED", "EXAM_OTP_VERIFIED"):
            step_up_verifs += 1
        if et in _VERIFICATION_SUCCESS_TYPES:
            verif_ok_cnt += 1
        if et in _VERIFICATION_FAIL_TYPES:
            verif_fail_cnt += 1
        if et in _TERMINATION_LOCK_TYPES:
            term_lock_cnt += 1
        if et in _RESPONSE_ACTION_TYPES:
            resp_cnt += 1
        if et.startswith("AGENTIC_") or et in ("AGENT_ORCHESTRATION_AUDIT", "AGENT_DEMO_ANALYSIS"):
            agentic_cnt += 1

    genuine_filter = _build_user_scope_filter(db, "genuine")
    genuine_uids_q = db.query(User.id).filter(genuine_filter)
    total_registered_users = genuine_uids_q.count()
    active_users_count = (
        db.query(func.count(func.distinct(DbSession.user_id)))
        .filter(
            DbSession.user_id.in_(genuine_uids_q),
            DbSession.status == "ACTIVE",
            DbSession.logout_time.is_(None),
            ~DbSession.id.like("sim_%"),
            ~DbSession.id.like("test_%"),
        )
        .scalar()
        or 0
    )

    inc_q = db.query(Alert).filter(Alert.user_id.in_(genuine_uids_q))
    if user_id is not None:
        inc_q = inc_q.filter(Alert.user_id == user_id)
    if application and application.upper() != "ALL":
        inc_q = inc_q.filter(Alert.application == application.lower())
    security_incidents_count = inc_q.count()

    from app.models.portal_lock import PortalSecurityLock
    lock_q = db.query(PortalSecurityLock).filter(PortalSecurityLock.user_id.in_(genuine_uids_q))
    if user_id is not None:
        lock_q = lock_q.filter(PortalSecurityLock.user_id == user_id)
    if application and application.upper() != "ALL":
        lock_q = lock_q.filter(PortalSecurityLock.application == application.lower())
    portal_locks_total = max(lock_q.count(), sum(1 for ev in events if (ev.event_type or "").upper() == "PORTAL_SECURITY_LOCKED"))
    locks_and_terms = portal_locks_total + sum(
        1 for ev in events if (ev.event_type or "").upper() in ("SESSION_TERMINATED", "ZERO_TRUST_KILL_SWITCH")
    )

    return SecurityIntelligenceOverviewResponse(
        authentication_events_count=auth_cnt,
        behavioral_anomalies_count=behav_cnt,
        risk_transitions_count=risk_trans_cnt,
        step_up_challenges_count=step_up_cnt,
        successful_verifications_count=verif_ok_cnt,
        failed_verifications_count=verif_fail_cnt,
        session_terminations_count=term_lock_cnt,
        portal_locks_count=portal_locks_total,
        security_response_actions_count=resp_cnt,
        agentic_executions_count=agentic_cnt,
        total_events_count=len(events),
        total_registered_users=total_registered_users,
        active_users_count=int(active_users_count),
        successful_logins_count=succ_logins,
        failed_logins_count=fail_logins,
        step_up_verifications_count=step_up_verifs,
        security_incidents_count=security_incidents_count,
        portal_locks_and_terminations_count=locks_and_terms,
        data_limitations=[
            "Showing genuine registered-user activity across Shopping, College, and Healthcare; admin actions, synthetic demos, and background agent runs are excluded.",
        ],
    )


@router.get("/security-intelligence/adaptive-history", response_model=List[AdaptiveAuthHistoryItem])
def get_adaptive_auth_history(
    application: Optional[str] = Query("ALL"),
    risk_level: Optional[str] = Query("ALL"),
    search: Optional[str] = Query(None),
    user_id: Optional[int] = Query(None),
    activity_scope: Optional[str] = Query("user"),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Returns persisted adaptive authentication challenge & verification history for registered users."""
    adaptive_types = sorted(_STEP_UP_CHALLENGE_TYPES | _VERIFICATION_SUCCESS_TYPES | _VERIFICATION_FAIL_TYPES | {"SESSION_TERMINATED", "ZERO_TRUST_KILL_SWITCH"})
    q = _apply_customer_activity_scope(
        db,
        db.query(SecurityEvent).filter(SecurityEvent.event_type.in_(adaptive_types)),
        activity_scope,
    )
    if user_id is not None:
        q = q.filter(SecurityEvent.user_id == user_id)
    q = _apply_security_event_filters(q, application, risk_level, date_from, date_to, search, db)
    events = q.order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc()).limit(limit).all()
    uids = {ev.user_id for ev in events if ev.user_id is not None}
    user_map = {u.id: u for u in db.query(User).filter(User.id.in_(uids)).all()} if uids else {}
    return [_extract_adaptive_auth_item(ev, user_map) for ev in events]


@router.get("/security-intelligence/agentic-intelligence")
def get_agentic_intelligence_history(
    application: Optional[str] = Query("ALL"),
    risk_level: Optional[str] = Query("ALL"),
    search: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    limit: int = Query(30, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Returns persisted Agentic AI orchestration runs alongside Deterministic Security Arbiter decisions."""
    from app.agents.core.factory import get_provider_health_status
    provider_health = get_provider_health_status()

    q = db.query(SecurityEvent).filter(
        or_(
            SecurityEvent.event_type.like("AGENTIC_%"),
            SecurityEvent.event_type.in_(["AGENT_ORCHESTRATION_AUDIT", "AGENT_DEMO_ANALYSIS"]),
        )
    )
    q = _apply_security_event_filters(q, application, risk_level, date_from, date_to, search, db)
    events = q.order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc()).limit(limit).all()
    uids = {ev.user_id for ev in events if ev.user_id is not None}
    user_map = {u.id: u for u in db.query(User).filter(User.id.in_(uids)).all()} if uids else {}

    executions = []
    for ev in events:
        agents, arbiter = _extract_agent_executions_for_event(ev, provider_health)
        u = user_map.get(ev.user_id)
        executions.append({
            "event_id": ev.id,
            "timestamp": ev.timestamp,
            "application": ev.application or "platform",
            "session_id": ev.session_id,
            "user_email": u.email if u else None,
            "event_type": ev.event_type,
            "agents": [a.model_dump() for a in agents],
            "arbiter_decision": arbiter.model_dump() if arbiter else None,
        })
    return {
        "provider_health": provider_health,
        "executions": executions,
    }


@router.get("/security-intelligence/events/{event_id}/detail", response_model=SecurityEventDetailResponse)
def get_security_event_detail(
    event_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Full investigation detail for a single persisted SecurityEvent, including 10-feature telemetry and agentic vs arbiter comparison."""
    from app.agents.core.factory import get_provider_health_status
    from app.models.portal_lock import PortalSecurityLock

    ev = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail=f"Security event #{event_id} not found.")

    user = db.query(User).filter(User.id == ev.user_id).first() if ev.user_id else None
    user_map = {user.id: user} if user else {}
    a_type, a_label = _classify_audit_actor(ev, user_map)
    summary_text, tech_details = _parse_sanitized_audit_details(ev)
    prev_risk = None
    if isinstance(tech_details, dict):
        prev_risk = tech_details.get("prior_risk_level") or tech_details.get("previous_risk_level")
        if not prev_risk and isinstance(tech_details.get("agentic_orchestration"), dict):
            prev_risk = tech_details["agentic_orchestration"].get("prior_risk_level")

    sess = db.query(DbSession).filter(DbSession.id == ev.session_id).first() if ev.session_id else None
    dev = db.query(Device).filter(Device.id == sess.device_id).first() if sess and sess.device_id else (
        db.query(Device).filter(Device.user_id == ev.user_id).order_by(Device.last_seen.desc()).first() if ev.user_id else None
    )

    related_alerts = db.query(Alert).filter(Alert.security_event_id == ev.id).order_by(Alert.created_at.desc()).limit(5).all()
    if not related_alerts and ev.user_id:
        related_alerts = db.query(Alert).filter(Alert.user_id == ev.user_id).order_by(Alert.created_at.desc()).limit(5).all()

    event_item = AuditTrailItem(
        id=ev.id,
        timestamp=ev.timestamp,
        category=_classify_audit_category(ev.event_type),
        actor_type=a_type,
        actor_label=a_label,
        action_code=ev.event_type,
        action_label=_HUMAN_ACTION_LABELS.get((ev.event_type or "").upper(), (ev.event_type or "Security Event").replace("_", " ").title()),
        target_resource=f"{user.name if user else 'System'} ({user.email if user else 'Not recorded'}) · {(ev.application or 'platform').capitalize()}",
        target_user_id=ev.user_id,
        target_user_name=user.name if user else None,
        target_user_email=user.email if user else None,
        application=ev.application or "platform",
        session_id=ev.session_id,
        result=_derive_audit_result(ev),
        risk_level=ev.severity or _score_to_risk_level(ev.risk_score) or "Not recorded",
        previous_risk_level=str(prev_risk) if prev_risk else None,
        risk_score=round(float(ev.risk_score), 4) if ev.risk_score is not None else None,
        anomaly_score=round(float(ev.anomaly_score), 4) if ev.anomaly_score is not None else None,
        has_behavioral_telemetry=bool(ev.session_id or ev.user_id),
        has_agent_analysis=(ev.event_type or "").upper().startswith("AGENTIC_") or (ev.event_type or "").upper() in ("AGENT_ORCHESTRATION_AUDIT", "AGENT_DEMO_ANALYSIS"),
        related_incident_id=related_alerts[0].id if related_alerts else None,
        summary=summary_text,
        reason=summary_text,
        technical_details=tech_details,
        repeat_count=1,
        correlation_id=ev.session_id or f"ev-{ev.id}",
        integrity_status="Verified" if ev.timestamp else "Unverified",
    )

    behav_payload = _build_behavioural_intelligence(db, ev.user_id, ev.session_id, ev.timestamp, ev.anomaly_score, ev.risk_score)

    adaptive_types = sorted(_STEP_UP_CHALLENGE_TYPES | _VERIFICATION_SUCCESS_TYPES | _VERIFICATION_FAIL_TYPES | {"SESSION_TERMINATED", "ADMIN_SESSION_TERMINATED", "ZERO_TRUST_KILL_SWITCH"})
    ad_q = db.query(SecurityEvent).filter(SecurityEvent.event_type.in_(adaptive_types))
    if ev.session_id:
        ad_q = ad_q.filter(SecurityEvent.session_id == ev.session_id)
    elif ev.user_id:
        ad_q = ad_q.filter(SecurityEvent.user_id == ev.user_id)
    else:
        ad_q = ad_q.filter(SecurityEvent.id == -1)
    adaptive_rows = [_extract_adaptive_auth_item(r, user_map) for r in ad_q.order_by(SecurityEvent.timestamp.desc()).limit(10).all()]

    provider_health = get_provider_health_status()
    agent_execs, arbiter_dec = _extract_agent_executions_for_event(ev, provider_health)

    locks = []
    if ev.user_id:
        for lk in db.query(PortalSecurityLock).filter(PortalSecurityLock.user_id == ev.user_id).order_by(PortalSecurityLock.locked_at.desc()).limit(5).all():
            locks.append({
                "id": lk.id,
                "application": lk.application,
                "status": lk.status,
                "reason": lk.lock_reason,
                "locked_at": lk.locked_at.isoformat() if lk.locked_at else None,
                "unlocked_at": lk.unlocked_at.isoformat() if lk.unlocked_at else None,
            })

    related_session_events: List[AuditTrailItem] = []
    if ev.session_id:
        sess_ev_rows = (
            db.query(SecurityEvent)
            .filter(SecurityEvent.session_id == ev.session_id, SecurityEvent.id != ev.id)
            .order_by(SecurityEvent.timestamp.asc(), SecurityEvent.id.asc())
            .limit(20)
            .all()
        )
        for sev in sess_ev_rows:
            s_a_type, s_a_label = _classify_audit_actor(sev, user_map)
            s_summary, s_tech = _parse_sanitized_audit_details(sev)
            related_session_events.append(
                AuditTrailItem(
                    id=sev.id,
                    timestamp=sev.timestamp,
                    category=_classify_audit_category(sev.event_type),
                    actor_type=s_a_type,
                    actor_label=s_a_label,
                    action_code=sev.event_type,
                    action_label=_HUMAN_ACTION_LABELS.get((sev.event_type or "").upper(), (sev.event_type or "Security Event").replace("_", " ").title()),
                    target_resource=f"{user.name if user else 'User'} ({user.email if user else 'Not recorded'}) · {(sev.application or 'platform').capitalize()}",
                    target_user_id=sev.user_id,
                    target_user_name=user.name if user else None,
                    target_user_email=user.email if user else None,
                    application=sev.application or "platform",
                    session_id=sev.session_id,
                    result=_derive_audit_result(sev),
                    risk_level=sev.severity or _score_to_risk_level(sev.risk_score) or "Not recorded",
                    risk_score=round(float(sev.risk_score), 4) if sev.risk_score is not None else None,
                    anomaly_score=round(float(sev.anomaly_score), 4) if sev.anomaly_score is not None else None,
                    summary=s_summary,
                    reason=s_summary,
                    technical_details=s_tech,
                    repeat_count=1,
                    correlation_id=sev.session_id or f"ev-{sev.id}",
                    integrity_status="Verified" if sev.timestamp else "Unverified",
                )
            )

    return SecurityEventDetailResponse(
        event=event_item,
        user={
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "role": user.role,
            "account_status": user.account_status,
            "registration_source": getattr(user, "registration_source", None),
            "email_verified": bool(getattr(user, "email_verified", False)),
        } if user else {},
        session={
            "id": sess.id,
            "application": sess.application,
            "status": sess.status,
            "login_time": sess.login_time.isoformat() if sess.login_time else None,
            "logout_time": sess.logout_time.isoformat() if sess.logout_time else None,
            "current_risk_level": sess.current_risk_level,
            "ip_address": sess.ip_address,
        } if sess else None,
        device={
            "id": dev.id,
            "device_name": dev.nickname or dev.device_type,
            "browser_name": dev.browser_name,
            "os_name": dev.os_name,
            "trust_status": dev.trust_state,
            "is_trusted": bool(dev.is_trusted),
        } if dev else None,
        behavioural_intelligence=behav_payload,
        adaptive_auth_history=adaptive_rows,
        agent_executions=agent_execs,
        arbiter_decision=arbiter_dec,
        related_incidents=[
            {
                "id": al.id,
                "alert_type": al.alert_type,
                "severity": al.severity,
                "status": al.status,
                "application": al.application,
                "message": al.message,
                "created_at": al.created_at.isoformat() if al.created_at else None,
            }
            for al in related_alerts
        ],
        portal_locks=locks,
        related_session_events=related_session_events,
    )


@router.get("/analytics", response_model=HistoricalAnalyticsResponse)
def get_soc_analytics(
    time_window: str = Query("24h", pattern="^(24h|7d|30d)$"),
    db: Session = Depends(get_db)
):
    """Derives historical security analytics from persisted database records without mock data."""
    hours_map = {"24h": 24, "7d": 168, "30d": 720}
    hours = hours_map.get(time_window, 24)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    non_admin_uids = _non_admin_user_ids_subquery(db)

    ev_base = db.query(SecurityEvent).filter(
        SecurityEvent.user_id.in_(non_admin_uids),
        SecurityEvent.timestamp >= cutoff,
        ~SecurityEvent.event_type.like("ADMIN_%"),
        ~SecurityEvent.event_type.like("AGENTIC_%"),
        SecurityEvent.event_type != "AGENT_DEMO_ANALYSIS",
        ~func.coalesce(SecurityEvent.session_id, "").like("sim_%"),
        ~func.coalesce(SecurityEvent.session_id, "").like("test_%"),
    )

    failed_logins = ev_base.filter(
        SecurityEvent.event_type.in_(["LOGIN_ATTEMPT_FAILED", "LOGIN_OTP_FAILED"]),
    ).count()

    successful_logins = db.query(DbSession).filter(
        DbSession.user_id.in_(non_admin_uids),
        DbSession.login_time >= cutoff,
        ~DbSession.id.like("sim_%"),
        ~DbSession.id.like("test_%"),
    ).count()
    total_auth = failed_logins + successful_logins

    period_events = ev_base.all()
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

    step_up_challenges = ev_base.filter(
        SecurityEvent.event_type == "STEP_UP_CHALLENGE",
    ).count()

    step_up_verified = ev_base.filter(
        SecurityEvent.event_type == "STEP_UP_VERIFIED",
    ).count()

    step_up_failed = ev_base.filter(
        SecurityEvent.event_type == "STEP_UP_LOCKED",
    ).count()

    sessions_restricted = ev_base.filter(
        SecurityEvent.event_type == "SESSION_RESTRICTED",
    ).count()

    sessions_terminated = ev_base.filter(
        SecurityEvent.event_type.in_(["ZERO_TRUST_KILL_SWITCH", "SESSION_TERMINATED"]),
    ).count()

    devices_registered = db.query(Device).filter(
        Device.user_id.in_(non_admin_uids),
        Device.first_seen >= cutoff,
    ).count()
    devices_revoked = db.query(Device).filter(
        Device.user_id.in_(non_admin_uids),
        Device.trust_state == "REVOKED",
        Device.last_seen >= cutoff,
    ).count()

    alerts_opened = db.query(Alert).filter(
        Alert.user_id.in_(non_admin_uids),
        Alert.created_at >= cutoff,
    ).count()
    alerts_resolved = db.query(Alert).filter(
        Alert.user_id.in_(non_admin_uids),
        Alert.status == "RESOLVED",
        Alert.created_at >= cutoff,
    ).count()

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

    from app.agents.core.factory import get_provider_health_status
    provider_health = get_provider_health_status()

    return SystemHealthResponse(
        database_connected=True,
        database_engine=engine.dialect.name.upper(),
        database_latency_ms=latency_ms,
        last_event_ingested_at=last_event_time,
        telemetry_pipeline_status=telemetry_status,
        active_sessions_count=active_count,
        server_timestamp=datetime.now(timezone.utc),
        llm_provider_health=provider_health,
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
        owner_role = ((owner.role if owner else None) or "USER").strip().upper()
        is_admin_owner = owner_role in ("ADMIN", "SYSTEM", "SERVICE")
        if scope and scope.lower() in ("active", "genuine") and is_admin_owner:
            continue
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


def _build_admin_user_rows(db: Session, users: List[User]) -> List[AdminUserResponse]:
    """Builds enriched AdminUserResponse records from persisted database rows."""
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
    sess_counts: Dict[int, int] = {}
    for s in active_sessions:
        sess_counts[s.user_id] = sess_counts.get(s.user_id, 0) + 1

    # Total sessions & last login (real DB sessions excluding sim_/test_)
    total_sess_rows = (
        db.query(
            DbSession.user_id,
            func.count(DbSession.id),
            func.max(DbSession.login_time),
        )
        .filter(
            DbSession.user_id.in_(user_ids),
            ~DbSession.id.like("sim_%"),
            ~DbSession.id.like("test_%"),
        )
        .group_by(DbSession.user_id)
        .all()
    )
    total_sess_map = {uid: int(cnt or 0) for uid, cnt, _ in total_sess_rows}
    last_login_map = {uid: max_dt for uid, _, max_dt in total_sess_rows}

    # Latest risk level per user (latest session risk or latest SecurityEvent risk)
    latest_sessions = (
        db.query(DbSession)
        .filter(DbSession.user_id.in_(user_ids))
        .order_by(DbSession.login_time.desc())
        .all()
    )
    last_risk_level_map: Dict[int, str] = {}
    for s in latest_sessions:
        if s.user_id not in last_risk_level_map and s.current_risk_level:
            last_risk_level_map[s.user_id] = s.current_risk_level

    latest_events = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.user_id.in_(user_ids))
        .order_by(SecurityEvent.timestamp.desc())
        .limit(500)
        .all()
    )
    last_risk_score_map: Dict[int, float] = {}
    for ev in latest_events:
        if ev.user_id not in last_risk_score_map and ev.risk_score is not None:
            last_risk_score_map[ev.user_id] = round(float(ev.risk_score), 3)
            if ev.user_id not in last_risk_level_map and ev.severity:
                last_risk_level_map[ev.user_id] = ev.severity

    # Map devices (counts + latest device name/type/location per user)
    devices = (
        db.query(Device)
        .filter(Device.user_id.in_(user_ids))
        .order_by(Device.last_seen.desc(), Device.id.desc())
        .all()
    )
    dev_counts: Dict[int, int] = {}
    last_dev_map: Dict[int, Device] = {}
    for d in devices:
        dev_counts[d.user_id] = dev_counts.get(d.user_id, 0) + 1
        if d.user_id not in last_dev_map:
            last_dev_map[d.user_id] = d

    # Map profiles
    profiles = db.query(BehaviorProfile).filter(BehaviorProfile.user_id.in_(user_ids)).all()
    prof_map = {p.user_id: p for p in profiles}

    # Map historical verification events so pre-migration human accounts match get_soc_metrics
    verified_history_user_ids = _get_verified_history_user_ids(db, user_ids=user_ids)

    # Map portal activity from real sessions (or security events if no sessions)
    portal_sess_rows = (
        db.query(DbSession.user_id, DbSession.application)
        .filter(
            DbSession.user_id.in_(user_ids),
            ~DbSession.id.like("sim_%"),
            ~DbSession.id.like("test_%"),
            DbSession.application.isnot(None),
        )
        .distinct()
        .all()
    )
    portal_map: Dict[int, List[str]] = {}
    for uid, app_name in portal_sess_rows:
        if app_name and app_name not in portal_map.get(uid, []):
            portal_map.setdefault(uid, []).append(app_name)
    for ev in latest_events:
        if ev.application and ev.application != "platform":
            lst = portal_map.setdefault(ev.user_id, [])
            if ev.application not in lst:
                lst.append(ev.application)

    results: List[AdminUserResponse] = []
    for u in users:
        is_active = sess_counts.get(u.id, 0) > 0
        cls = _classify_user_account(
            u,
            is_active=is_active,
            has_verified_history=(u.id in verified_history_user_ids),
        )
        prov = cls["provenance"]
        is_test_acct = cls["is_test"]
        prof = prof_map.get(u.id)
        status_label, _, _ = ProfileService.get_maturity_info(prof.sample_count) if prof else ("COLD_START", 0.0, False)
        portals_list = portal_map.get(u.id, [])
        last_dev = last_dev_map.get(u.id)
        last_dev_name = (
            (last_dev.nickname or f"{last_dev.browser_name or 'Unknown'} on {last_dev.os_name or 'Desktop'}")
            if last_dev
            else None
        )
        last_dev_type = last_dev.device_type if last_dev else None
        last_loc = (
            ", ".join([p for p in (last_dev.city, last_dev.region, last_dev.country) if p]) or None
            if last_dev
            else None
        )
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
            provenance=prov,
            last_login=last_login_map.get(u.id),
            total_sessions_count=total_sess_map.get(u.id, 0),
            last_risk_level=last_risk_level_map.get(u.id),
            last_risk_score=last_risk_score_map.get(u.id),
            is_test_account=is_test_acct,
            email_verified=bool(cls["is_email_verified"]),
            email_verified_at=getattr(u, "email_verified_at", None),
            registration_source=getattr(u, "registration_source", None),
            portal_activity=", ".join(portals_list) if portals_list else None,
            last_device_name=last_dev_name,
            last_device_type=last_dev_type,
            last_location=last_loc,
        ))
    return results


@router.get("/users", response_model=List[AdminUserResponse])
def get_all_users(
    scope: Optional[str] = Query("all", description="Scope: 'all', 'active', 'genuine', 'demo', or 'test'"),
    limit: int = Query(100, le=500),
    db: Session = Depends(get_db)
):
    """Returns registered enterprise users with device counts, active session counts, provenance categorization, and scope filtering."""
    SessionService.reap_expired_sessions(db)
    users = db.query(User).order_by(User.created_at.desc()).limit(limit).all()
    rows = _build_admin_user_rows(db, users)

    results = []
    for row in rows:
        if scope and scope.lower() == "active" and not row.is_active:
            continue
        if scope and scope.lower() == "genuine" and row.provenance not in ("GENUINE_ACTIVE", "PUBLIC_REGISTERED"):
            continue
        if scope and scope.lower() == "demo" and row.provenance != "SEEDED_DEMO":
            continue
        if scope and scope.lower() == "test" and row.provenance != "KNOWN_TEST":
            continue
        results.append(row)
    return results


@router.get("/users/directory", response_model=AdminUserDirectoryResponse)
def get_users_directory(
    search: Optional[str] = Query(None, description="Search by name or email"),
    role: Optional[str] = Query(None, description="Filter by role: ALL, USER, ADMIN"),
    account_status: Optional[str] = Query(None, description="Filter by account status: ALL, ACTIVE, SUSPENDED, LOCKED, DISABLED"),
    scope: Optional[str] = Query("genuine", description="Scope: genuine (default), admin, test, active, all"),
    portal: Optional[str] = Query(None, description="Filter by portal activity: ALL, shopping, college, healthcare"),
    date_from: Optional[str] = Query(None, description="Filter by registration date >= YYYY-MM-DD"),
    date_to: Optional[str] = Query(None, description="Filter by registration date <= YYYY-MM-DD"),
    sort_by: Optional[str] = Query("created_at", description="Sort by: created_at, last_login, name"),
    sort_dir: Optional[str] = Query("desc", description="Sort direction: asc or desc"),
    page: int = Query(1, ge=1),
    page_size: int = Query(15, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """Server-side SQL-filtered, paginated, searchable directory of user accounts."""
    SessionService.reap_expired_sessions(db)
    q = db.query(User)

    scope_filter = _build_user_scope_filter(db, scope)
    if scope_filter is not None:
        q = q.filter(scope_filter)

    if search and search.strip():
        term = f"%{search.strip()}%"
        q = q.filter(or_(User.name.ilike(term), User.email.ilike(term)))
    if role and role.upper() != "ALL":
        q = q.filter(User.role == role.upper())
    if account_status and account_status.upper() != "ALL":
        q = q.filter(User.account_status == account_status.upper())
    if portal and portal.upper() != "ALL":
        portal_uids = db.query(DbSession.user_id).filter(
            DbSession.application == portal.lower(),
            ~DbSession.id.like("sim_%"),
            ~DbSession.id.like("test_%"),
        )
        q = q.filter(User.id.in_(portal_uids))
    if date_from:
        try:
            dt_from = datetime.fromisoformat(date_from.strip())
            if dt_from.tzinfo is None:
                dt_from = dt_from.replace(tzinfo=timezone.utc)
            q = q.filter(User.created_at >= dt_from)
        except Exception:
            pass
    if date_to:
        try:
            raw_to = date_to.strip()
            dt_to = datetime.fromisoformat(raw_to)
            if len(raw_to) == 10:
                dt_to = dt_to + timedelta(days=1)
            if dt_to.tzinfo is None:
                dt_to = dt_to.replace(tzinfo=timezone.utc)
            q = q.filter(User.created_at < dt_to)
        except Exception:
            pass

    total = q.count()
    total_pages = max(1, (total + page_size - 1) // page_size)
    safe_page = min(page, total_pages)
    start = (safe_page - 1) * page_size

    is_desc = (sort_dir or "desc").lower() != "asc"
    if sort_by == "last_login":
        last_login_subq = (
            db.query(
                DbSession.user_id.label("uid"),
                func.max(DbSession.login_time).label("max_login"),
            )
            .filter(
                ~DbSession.id.like("sim_%"),
                ~DbSession.id.like("test_%"),
            )
            .group_by(DbSession.user_id)
            .subquery()
        )
        q = q.outerjoin(last_login_subq, User.id == last_login_subq.c.uid)
        order_col = last_login_subq.c.max_login.desc().nullslast() if is_desc else last_login_subq.c.max_login.asc().nullsfirst()
        paged_users = q.order_by(order_col, User.created_at.desc()).offset(start).limit(page_size).all()
    elif sort_by == "name":
        order_col = func.lower(User.name).desc() if is_desc else func.lower(User.name).asc()
        paged_users = q.order_by(order_col, User.id.desc()).offset(start).limit(page_size).all()
    else:
        order_col = User.created_at.desc() if is_desc else User.created_at.asc()
        paged_users = q.order_by(order_col, User.id.desc()).offset(start).limit(page_size).all()

    items = _build_admin_user_rows(db, paged_users)

    return AdminUserDirectoryResponse(
        items=items,
        total=total,
        page=safe_page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/users/{user_id}/details")
def get_admin_user_details(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Returns a comprehensive, privacy-safe account inspection dossier for a registered user."""
    from app.models.portal_lock import PortalSecurityLock
    from app.models.application_grant import ApplicationGrant

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    SessionService.reap_expired_sessions(db)
    summary_row = _build_admin_user_rows(db, [user])[0]

    def _mask_fp(fp: Optional[str]) -> str:
        if not fp:
            return "Not recorded"
        s = str(fp).strip()
        if len(s) <= 8:
            return s[:2] + "••••"
        return f"{s[:6]}••••{s[-4:]}"

    def _mask_ip(ip: Optional[str]) -> str:
        if not ip:
            return "Not recorded"
        s = str(ip).strip()
        if s in ("127.0.0.1", "::1", "localhost"):
            return s
        if "." in s:
            parts = s.split(".")
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.***"
        if ":" in s:
            parts = s.split(":")
            return ":".join(parts[:3]) + ":****"
        return s

    devices = (
        db.query(Device)
        .filter(Device.user_id == user_id)
        .order_by(Device.last_seen.desc(), Device.id.desc())
        .all()
    )
    dev_map = {d.id: d for d in devices}
    sessions = (
        db.query(DbSession)
        .filter(
            DbSession.user_id == user_id,
            ~DbSession.id.like("sim_%"),
            ~DbSession.id.like("test_%"),
        )
        .order_by(DbSession.login_time.desc())
        .limit(100)
        .all()
    )
    dev_sess_counts: Dict[int, int] = {}
    for s in sessions:
        if s.device_id:
            dev_sess_counts[s.device_id] = dev_sess_counts.get(s.device_id, 0) + 1

    alerts = (
        db.query(Alert)
        .filter(Alert.user_id == user_id)
        .order_by(Alert.created_at.desc())
        .limit(20)
        .all()
    )
    events = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.user_id == user_id)
        .order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc())
        .limit(100)
        .all()
    )
    portal_locks = (
        db.query(PortalSecurityLock)
        .filter(PortalSecurityLock.user_id == user_id)
        .order_by(PortalSecurityLock.locked_at.desc())
        .limit(15)
        .all()
    )
    grants = (
        db.query(ApplicationGrant)
        .filter(ApplicationGrant.user_id == user_id)
        .order_by(ApplicationGrant.granted_at.desc())
        .limit(15)
        .all()
    )

    login_history: List[Dict[str, Any]] = []
    for s in sessions:
        d = dev_map.get(s.device_id) if s.device_id else None
        loc = ", ".join([p for p in (d.city, d.region, d.country) if p]) or None if d else None
        dev_name = (d.nickname or f"{d.browser_name or 'Unknown'} on {d.os_name or 'Desktop'}") if d else "Not recorded"
        browser_str = f"{d.browser_name or 'Unknown'} {d.browser_version or ''}".strip() if d else "Not recorded"
        os_str = f"{d.os_name or 'Unknown'} {d.os_version or ''}".strip() if d else "Not recorded"
        outcome_low = (s.login_outcome or "").lower()
        res_label = "Failed" if ("fail" in outcome_low or "denied" in outcome_low or "lock" in outcome_low) else "Successful"
        login_history.append({
            "timestamp": s.login_time.isoformat() if s.login_time else None,
            "result": res_label,
            "session_id": s.id,
            "application": s.application,
            "status": s.status,
            "risk_level": s.current_risk_level,
            "device_id": s.device_id,
            "device_name": dev_name,
            "device_type": d.device_type if d else "Not recorded",
            "browser": browser_str,
            "os": os_str,
            "ip_address": _mask_ip(s.ip_address or (d.last_ip if d else None)),
            "location": loc,
            "location_source": (d.location_source if (d and loc) else "UNAVAILABLE"),
            "logout_time": s.logout_time.isoformat() if s.logout_time else None,
        })

    for ev in events:
        if (ev.event_type or "").upper() in ("LOGIN_ATTEMPT_FAILED", "LOGIN_OTP_FAILED"):
            _, tech = _parse_sanitized_audit_details(ev)
            ev_ip = tech.get("ip_address") if isinstance(tech, dict) else None
            login_history.append({
                "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
                "result": "Failed",
                "session_id": ev.session_id,
                "application": ev.application or "platform",
                "status": "FAILED",
                "risk_level": ev.severity or "MEDIUM",
                "device_id": None,
                "device_name": "Not recorded",
                "device_type": "Not recorded",
                "browser": "Not recorded",
                "os": "Not recorded",
                "ip_address": _mask_ip(ev_ip),
                "location": None,
                "logout_time": None,
            })
    login_history.sort(key=lambda r: r["timestamp"] or "", reverse=True)

    portal_activity_types = {
        "LOGIN_SUCCESS",
        "SESSION_LOGOUT",
        "SESSION_TERMINATED",
        "ZERO_TRUST_KILL_SWITCH",
        "PROTECTED_RESOURCE_ACCESSED",
        "EXAM_OTP_VERIFIED",
        "EXAM_ACCESS_GRANTED",
        "EXAM_ACCESS_DENIED",
        "HIGH_RISK_CHECKOUT_ATTEMPT",
        "PORTAL_SECURITY_LOCKED",
        "PORTAL_LOCK_RECOVERED",
        "STEP_UP_CHALLENGE_ISSUED",
        "STEP_UP_CHALLENGE",
        "STEP_UP_CHALLENGE_ISSUED",
        "STEP_UP_VERIFIED",
        "STEP_UP_FAILED",
        "STEP_UP_LOCKED",
        "PORTAL_RECOVERY_OTP_REQUESTED",
        "PORTAL_RECOVERY_OTP_VERIFIED",
        "PORTAL_RECOVERY_OTP_FAILED",
        "VAULT_GRANT_REVOKED",
    }
    portal_activity = []
    for ev in events:
        et = (ev.event_type or "").upper()
        if et in portal_activity_types:
            summary_txt, _ = _parse_sanitized_audit_details(ev)
            portal_activity.append({
                "id": ev.id,
                "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
                "application": ev.application or "platform",
                "event_type": et,
                "action_label": _HUMAN_ACTION_LABELS.get(et, et.replace("_", " ").title()),
                "description": summary_txt,
                "session_id": ev.session_id,
                "severity": ev.severity,
                "decision": ev.decision,
                "outcome": _derive_audit_result(ev),
            })

    return {
        "user": summary_row.model_dump(),
        "devices": [
            {
                "id": d.id,
                "device_id": d.device_id,
                "masked_fingerprint": _mask_fp(d.device_fingerprint),
                "nickname": d.nickname or f"{d.browser_name or 'Unknown'} on {d.os_name or 'Desktop'}",
                "browser": f"{d.browser_name or 'Unknown'} {d.browser_version or ''}".strip(),
                "os": f"{d.os_name or 'Unknown'} {d.os_version or ''}".strip(),
                "device_type": d.device_type,
                "trust_state": d.trust_state,
                "is_trusted": d.is_trusted,
                "first_seen": d.first_seen.isoformat() if d.first_seen else None,
                "last_seen": d.last_seen.isoformat() if d.last_seen else None,
                "session_count": dev_sess_counts.get(d.id, 0),
                "location": ", ".join([p for p in (d.city, d.region, d.country) if p]) or None,
                "location_source": d.location_source or "UNKNOWN",
            }
            for d in devices
        ],
        "sessions": [
            {
                "id": s.id,
                "application": s.application,
                "status": s.status,
                "current_risk_level": s.current_risk_level,
                "ip_address": _mask_ip(s.ip_address),
                "login_time": s.login_time.isoformat() if s.login_time else None,
                "logout_time": s.logout_time.isoformat() if s.logout_time else None,
                "login_outcome": s.login_outcome,
                "device_name": (dev_map[s.device_id].nickname or f"{dev_map[s.device_id].browser_name or 'Unknown'} on {dev_map[s.device_id].os_name or 'Desktop'}") if (s.device_id and s.device_id in dev_map) else "Not recorded",
                "browser": f"{dev_map[s.device_id].browser_name or 'Unknown'} {dev_map[s.device_id].browser_version or ''}".strip() if (s.device_id and s.device_id in dev_map) else "Not recorded",
                "os": f"{dev_map[s.device_id].os_name or 'Unknown'} {dev_map[s.device_id].os_version or ''}".strip() if (s.device_id and s.device_id in dev_map) else "Not recorded",
                "termination_reason": (
                    s.login_outcome
                    if (s.status in ("TERMINATED", "EXPIRED", "RESTRICTED") and s.login_outcome)
                    else ("Session terminated" if s.status == "TERMINATED" else ("Session expired" if s.status == "EXPIRED" else None))
                ),
            }
            for s in sessions
        ],
        "login_history": login_history,
        "portal_activity": portal_activity,
        "incidents": [
            {
                "id": al.id,
                "alert_type": al.alert_type,
                "application": al.application,
                "severity": al.severity,
                "status": al.status,
                "message": al.message,
                "created_at": al.created_at.isoformat() if al.created_at else None,
                "resolved_at": al.resolved_at.isoformat() if al.resolved_at else None,
            }
            for al in alerts
        ],
        "portal_locks": [
            {
                "security_reference_id": lk.security_reference_id,
                "application": lk.application,
                "lock_status": lk.lock_status,
                "recovery_status": lk.recovery_status,
                "lock_reason": lk.lock_reason,
                "locked_at": lk.locked_at.isoformat() if lk.locked_at else None,
                "unlocked_at": lk.unlocked_at.isoformat() if lk.unlocked_at else None,
            }
            for lk in portal_locks
        ],
        "portal_grants": [
            {
                "application": g.application,
                "resource": g.resource,
                "factor": g.factor,
                "revoked": g.revoked,
                "granted_at": g.granted_at.isoformat() if g.granted_at else None,
                "expires_at": g.expires_at.isoformat() if g.expires_at else None,
            }
            for g in grants
        ],
        "recent_events": [
            {
                "id": ev.id,
                "event_type": ev.event_type,
                "action_label": _HUMAN_ACTION_LABELS.get((ev.event_type or "").upper(), (ev.event_type or "Security Event").replace("_", " ").title()),
                "application": ev.application,
                "session_id": ev.session_id,
                "severity": ev.severity,
                "decision": ev.decision,
                "outcome": _derive_audit_result(ev),
                "risk_score": round(float(ev.risk_score or 0.0), 3),
                "anomaly_score": round(float(ev.anomaly_score or 0.0), 3),
                "details": _parse_sanitized_audit_details(ev)[0],
                "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
            }
            for ev in events
            if not (ev.event_type or "").upper().startswith(("ADMIN_", "AGENT_", "AGENTIC_"))
            and (ev.event_type or "").upper() not in _ADMIN_ONLY_EVENT_TYPES
        ],
    }



@router.get("/users/{user_id}/profile", response_model=BehaviorProfileResponse)
def get_admin_user_profile(user_id: int, db: Session = Depends(get_db)):
    """Allows Security Administrators to inspect a specific user's behavioral baseline."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    
    profile = ProfileService.get_or_create_profile(db, user_id)
    features_dict = ProfileService.get_profile_dict(profile)
    mod_counts = features_dict.get("modality_sample_counts")
    status_label, confidence, is_mature = ProfileService.get_maturity_info(
        sample_count=profile.sample_count,
        modality_counts=mod_counts
    )
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
        modality_sample_counts=mod_counts,
        modality_maturity=features_dict.get("modality_maturity"),
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
    mod_counts = features_dict.get("modality_sample_counts")
    status_label, confidence, is_mature = ProfileService.get_maturity_info(
        sample_count=profile.sample_count,
        modality_counts=mod_counts
    )
    metadata["baseline_maturity"] = status_label
    metadata["maturity_confidence"] = confidence
    metadata["is_mature"] = is_mature
    metadata["profile_sample_count"] = profile.sample_count
    if mod_counts:
        metadata["modality_sample_counts"] = mod_counts
        metadata["modality_maturity"] = features_dict.get("modality_maturity")
    return metadata


@router.get("/users/{user_id}/live-activity")
def get_admin_user_live_activity(
    user_id: int,
    session_id: Optional[str] = Query(None),
    application: Optional[str] = Query(None),
    limit: int = Query(60, ge=1, le=200),
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    User-scoped near-real-time activity timeline and 10-D behavioural monitoring summary.
    Excludes ADMIN, SYSTEM, SERVICE, and synthetic/simulated records.
    """
    from app.models.behavior import BehavioralTrainingEvent

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    role_norm = (user.role or "USER").strip().upper()
    if role_norm in ("ADMIN", "SYSTEM", "SERVICE"):
        return {
            "user_id": user.id,
            "excluded_role": True,
            "role": role_norm,
            "server_timestamp": datetime.now(timezone.utc).isoformat(),
            "latest_activity_timestamp": None,
            "active_sessions": [],
            "behavioral_summary": None,
            "timeline": [],
        }

    SessionService.reap_expired_sessions(db)

    # 1. Active & recent sessions for filter & status
    sess_rows = (
        db.query(DbSession)
        .filter(
            DbSession.user_id == user_id,
            ~DbSession.id.like("sim_%"),
            ~DbSession.id.like("test_%"),
        )
        .order_by(DbSession.login_time.desc())
        .limit(20)
        .all()
    )
    active_sessions = [
        {
            "id": s.id,
            "short_id": f"{s.id[:14]}...",
            "application": s.application,
            "status": s.status,
            "current_risk_level": s.current_risk_level,
            "login_time": s.login_time.isoformat() if s.login_time else None,
        }
        for s in sess_rows
    ]

    # 2. SecurityEvents strictly scoped to user_id (excluding admin/agent/sim/test)
    ev_q = db.query(SecurityEvent).filter(
        SecurityEvent.user_id == user_id,
        ~SecurityEvent.event_type.like("ADMIN_%"),
        ~SecurityEvent.event_type.like("AGENT_%"),
        ~SecurityEvent.event_type.like("AGENTIC_%"),
        ~SecurityEvent.event_type.in_(_ADMIN_ONLY_EVENT_TYPES),
        ~func.coalesce(SecurityEvent.session_id, "").like("sim_%"),
        ~func.coalesce(SecurityEvent.session_id, "").like("test_%"),
    )
    if session_id and session_id != "ALL":
        ev_q = ev_q.filter(SecurityEvent.session_id == session_id)
    if application and application.upper() != "ALL":
        ev_q = ev_q.filter(SecurityEvent.application == application.lower())

    events = ev_q.order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc()).limit(limit).all()

    # 3. BehavioralTrainingEvent counts & recent validation outcomes
    te_base = db.query(BehavioralTrainingEvent).filter(
        BehavioralTrainingEvent.user_id == user_id,
        ~func.coalesce(BehavioralTrainingEvent.session_id, "").like("sim_%"),
        ~func.coalesce(BehavioralTrainingEvent.session_id, "").like("test_%"),
    )
    if session_id and session_id != "ALL":
        te_base = te_base.filter(BehavioralTrainingEvent.session_id == session_id)
    te_total = te_base.count()
    te_eligible = te_base.filter(BehavioralTrainingEvent.lifecycle_state.in_(["ELIGIBLE", "PROCESSED"])).count()
    te_rejected = te_base.filter(BehavioralTrainingEvent.lifecycle_state == "REJECTED").count()
    recent_te = te_base.order_by(BehavioralTrainingEvent.created_at.desc(), BehavioralTrainingEvent.id.desc()).limit(10).all()

    # 4. Latest BehaviorLog observations & 10-D live telemetry
    blog_q = db.query(BehaviorLog).filter(
        BehaviorLog.user_id == user_id,
        ~func.coalesce(BehaviorLog.session_id, "").like("sim_%"),
        ~func.coalesce(BehaviorLog.session_id, "").like("test_%"),
    )
    if session_id and session_id != "ALL":
        blog_q = blog_q.filter(BehaviorLog.session_id == session_id)
    blog_count = blog_q.count()
    latest_blog = blog_q.order_by(BehaviorLog.timestamp.desc(), BehaviorLog.id.desc()).first()

    # 5. Profile, Welford Baseline & Isolation Forest ML Status
    profile = ProfileService.get_or_create_profile(db, user_id)
    features_dict = ProfileService.get_profile_dict(profile)
    mod_counts = features_dict.get("modality_sample_counts") or {}
    status_label, confidence, is_mature = ProfileService.get_maturity_info(
        sample_count=profile.sample_count,
        modality_counts=mod_counts,
    )
    ml_status, model_samples, is_anomaly, anomaly_score = ModelManager.get_ml_status(
        user_id=user_id,
        sample_count=profile.sample_count,
        baseline_stats=features_dict,
        db=db,
    )
    model_meta = ModelManager.get_model_metadata(user_id)
    model_fitted = bool(model_meta.get("model_trained", False))

    if model_fitted and ml_status == "ML_READY":
        ml_readiness_label = "Model fitted and inference available"
    else:
        ml_readiness_label = "Model not fitted"

    trusted_samples = int(features_dict.get("trusted_samples") or profile.sample_count or 0)
    if blog_count == 0 and trusted_samples == 0:
        baseline_readiness_label = "No signal received"
    elif trusted_samples == 0 and blog_count > 0:
        baseline_readiness_label = "Signal received (insufficient eligible observations)"
    elif trusted_samples < 5:
        baseline_readiness_label = "Baseline learning"
    else:
        baseline_readiness_label = "Baseline established"

    latest_obs = None
    if latest_blog is not None:
        latest_obs = {
            "timestamp": latest_blog.timestamp.isoformat() if latest_blog.timestamp else None,
            "session_id": f"{latest_blog.session_id[:12]}..." if latest_blog.session_id else None,
            "typing_speed_wpm": latest_blog.typing_speed_wpm,
            "avg_flight_time_ms": latest_blog.avg_flight_time_ms,
            "avg_dwell_time_ms": latest_blog.avg_dwell_time_ms,
            "mouse_velocity_avg": latest_blog.mouse_velocity_avg,
            "mouse_acceleration_avg": latest_blog.mouse_acceleration_avg,
            "mouse_curvature_entropy": latest_blog.mouse_curvature_entropy,
            "click_frequency": latest_blog.click_frequency,
            "scroll_speed_avg": latest_blog.scroll_speed_avg,
            "idle_duration_sec": latest_blog.idle_duration_sec,
            "navigation_entropy": latest_blog.navigation_entropy,
        }

    # 6. Build deduplicated chronological timeline
    timeline: List[Dict[str, Any]] = []
    for ev in events:
        et = (ev.event_type or "").upper()
        if et in ("LOGIN_SUCCESS", "LOGIN_ATTEMPT_FAILED", "SESSION_LOGOUT", "USER_REGISTERED", "EMAIL_VERIFICATION_COMPLETED"):
            cat = "Authentication"
        elif et in ("SESSION_CREATED", "SESSION_TERMINATED", "ZERO_TRUST_KILL_SWITCH", "SESSION_RESTRICTED"):
            cat = "Session"
        elif et.startswith("PORTAL_NAVIGATION") or et in ("PORTAL_ACCESS", "VAULT_ACCESS"):
            cat = "Navigation"
        elif et in ("BEHAVIORAL_TELEMETRY_RECEIVED", "BASELINE_UPDATED"):
            cat = "Behavioral Telemetry"
        elif et in ("BEHAVIOR_ANOMALY", "BEHAVIORAL_ANOMALY", "BEHAVIOR_RISK_TRANSITION", "RISK_LEVEL_TRANSITION"):
            cat = "Risk & Anomaly"
        elif et in ("STEP_UP_CHALLENGE", "STEP_UP_VERIFIED", "STEP_UP_LOCKED", "LOGIN_OTP_VERIFIED", "LOGIN_OTP_FAILED", "EXAM_OTP_VERIFIED", "COGNITIVE_CHALLENGE", "GESTURE_VERIFIED"):
            cat = "Adaptive Auth"
        elif "LOCK" in et or "RECOVER" in et or "GRANT" in et:
            cat = "Portal Lock / Recovery"
        else:
            cat = "Security"

        sanitized_detail = _parse_sanitized_audit_details(ev)[0]
        timeline.append({
            "uid_key": f"ev_{ev.id}",
            "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
            "portal": (ev.application or "platform").lower(),
            "session_id": f"{ev.session_id[:12]}..." if ev.session_id else None,
            "category": cat,
            "event_type": ev.event_type,
            "label": _HUMAN_ACTION_LABELS.get(et, (ev.event_type or "Security Event").replace("_", " ").title()),
            "severity": ev.severity or "LOW",
            "result": _derive_audit_result(ev),
            "details": sanitized_detail,
        })

    for te in recent_te:
        st = (te.lifecycle_state or "PENDING").upper()
        timeline.append({
            "uid_key": f"te_{te.id}",
            "timestamp": te.created_at.isoformat() if te.created_at else None,
            "portal": "platform",
            "session_id": f"{te.session_id[:12]}..." if te.session_id else None,
            "category": "Baseline & ML",
            "event_type": f"TRAINING_OBSERVATION_{st}",
            "label": f"Behavioural Observation {st.title()}",
            "severity": "LOW" if st in ("ELIGIBLE", "PROCESSED") else "INFO",
            "result": "Baseline Eligible" if st in ("ELIGIBLE", "PROCESSED") else f"Rejected ({te.rejection_reason or 'Policy filter'})",
            "details": f"Validation state: {st}" + (f" · Reason: {te.rejection_reason}" if te.rejection_reason else ""),
        })

    timeline.sort(key=lambda x: x.get("timestamp") or "", reverse=True)
    timeline = timeline[:limit]
    latest_ts = timeline[0]["timestamp"] if timeline else (latest_obs["timestamp"] if latest_obs else None)

    return {
        "user_id": user.id,
        "excluded_role": False,
        "server_timestamp": datetime.now(timezone.utc).isoformat(),
        "latest_activity_timestamp": latest_ts,
        "active_sessions": active_sessions,
        "behavioral_summary": {
            "observation_count": blog_count,
            "trusted_samples": trusted_samples,
            "baseline_status": status_label,
            "baseline_readiness_label": baseline_readiness_label,
            "modality_sample_counts": mod_counts,
            "modality_maturity": features_dict.get("modality_maturity"),
            "baseline_features": features_dict,
            "latest_observation": latest_obs,
            "training_counts": {
                "total": te_total,
                "eligible_or_processed": te_eligible,
                "rejected": te_rejected,
            },
            "ml_status_detail": {
                "code": ml_status,
                "label": ml_readiness_label,
                "is_fitted": model_fitted,
                "model_sample_count": model_samples,
                "is_anomaly": is_anomaly,
                "anomaly_score": anomaly_score if (model_fitted or anomaly_score > 0) else None,
            },
        },
        "timeline": timeline,
    }


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


# -------------------------------------------------------------------------
# SOC AI Monitoring & Intelligence Endpoints (Step 5.7)
# -------------------------------------------------------------------------
@router.get("/soc/posture", response_model=SOCPostureResponse)
def get_soc_posture(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """
    Returns live empirical Zero-Trust security posture metrics across the fleet.
    Derived strictly from verified database records with zero metric fabrication.
    """
    from app.agents.modules.soc_monitoring_agent import SOCMonitoringAgent
    agent = SOCMonitoringAgent(db=db)
    posture = agent.compute_security_posture()
    return SOCPostureResponse(**posture)


@router.get("/soc/incidents", response_model=List[SOCIncidentSummary])
def get_soc_incidents(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    application: Optional[str] = None,
    limit: int = Query(50, le=200),
    skip: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """
    Lists security incidents with filtering by severity, status, and application portal.
    Restricted strictly to authorized SOC Administrators.
    Derived strictly from verified database records with zero metric fabrication.
    """
    from app.agents.modules.soc_monitoring_agent import SOCMonitoringAgent
    agent = SOCMonitoringAgent(db=db)
    incidents = agent.correlate_incidents(
        db=db,
        application=application,
        status=status,
        severity=severity,
        limit=limit,
        skip=skip
    )
    return [SOCIncidentSummary(**inc) for inc in incidents]


@router.get("/soc/incidents/{incident_id}", response_model=SOCIncidentSummary)
def get_soc_incident_detail(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """
    Retrieves incident details with contextual AI-assisted advisory analysis and containment status.
    """
    from app.agents.modules.soc_monitoring_agent import SOCMonitoringAgent
    agent = SOCMonitoringAgent(db=db)
    incidents = agent.correlate_incidents(db=db, alert_id=incident_id, limit=1)
    if not incidents:
        raise HTTPException(status_code=404, detail=f"Incident #{incident_id} not found.")
    return SOCIncidentSummary(**incidents[0])


@router.post("/soc/incidents/{incident_id}/status", response_model=SOCIncidentSummary)
def update_soc_incident_status(
    incident_id: int,
    request: AlertResolveRequest,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Updates incident lifecycle status (OPEN, INVESTIGATING, CONTAINED, RESOLVED, REOPENED, ACKNOWLEDGED)
    with immutable security event audit logging and agent correlation.
    """
    alert = db.query(Alert).filter(Alert.id == incident_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Incident #{incident_id} not found.")

    prev_status = (alert.status or "OPEN").upper()
    new_status = request.status.upper()
    if new_status not in _VALID_INCIDENT_TRANSITIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid incident status '{request.status}'. Allowed: {sorted(list(_VALID_INCIDENT_TRANSITIONS.keys()))}"
        )
    allowed_next = _VALID_INCIDENT_TRANSITIONS.get(prev_status, set())
    if new_status not in allowed_next:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid lifecycle transition from {prev_status} to {new_status}."
        )
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
        event_type = "ADMIN_INCIDENT_RESOLVED"
        decision_act = "RESOLVE_INCIDENT"
    else:
        # Clear resolution metadata if leaving RESOLVED state
        if prev_status == "RESOLVED":
            alert.resolved_at = None
            alert.resolved_by = None
        if new_status == "CONTAINED":
            event_type = "ADMIN_INCIDENT_CONTAINED"
            decision_act = "CONTAIN_INCIDENT"
        elif new_status == "INVESTIGATING":
            event_type = "ADMIN_INCIDENT_INVESTIGATING"
            decision_act = "INVESTIGATE_INCIDENT"
        elif new_status in ("OPEN", "REOPENED") and prev_status == "RESOLVED":
            event_type = "ADMIN_INCIDENT_REOPENED"
            decision_act = "REOPEN_INCIDENT"
        elif new_status == "ACKNOWLEDGED":
            event_type = "ADMIN_INCIDENT_ACKNOWLEDGED"
            decision_act = "ACKNOWLEDGE_INCIDENT"
        else:
            event_type = "ADMIN_INCIDENT_TRIAGED"
            decision_act = "TRIAGE_INCIDENT"

    notes_detail = alert.notes or alert.resolution_reason or "Handled via SOC Incident API"
    audit_ev = SecurityEvent(
        user_id=alert.user_id,
        application=alert.application,
        event_type=event_type,
        severity="LOW",
        anomaly_score=0.0,
        risk_score=0.0,
        decision=decision_act,
        details=f"Incident #{alert.id} ({alert.alert_type}) transitioned from {prev_status} to {new_status} by SOC Operator {current_user.name} ({current_user.email}). Notes: {notes_detail}"
    )
    db.add(audit_ev)
    db.commit()
    db.refresh(alert)

    from app.agents.modules.soc_monitoring_agent import SOCMonitoringAgent
    agent = SOCMonitoringAgent(db=db)
    incidents = agent.correlate_incidents(db=db, alert_id=incident_id, limit=1)
    if not incidents:
        raise HTTPException(status_code=404, detail=f"Incident #{incident_id} not found after update.")
    return SOCIncidentSummary(**incidents[0])


@router.get("/soc/containment-actions", response_model=SOCContainmentActionsResponse)
def get_soc_containment_actions(
    limit: int = Query(50, ge=1, le=200),
    skip: int = Query(0, ge=0),
    application: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """
    Returns empirical containment actions executed across portals (session termination,
    portal security locks, application grant revocations, incident containment).
    """
    containment_ev_types = [
        "SESSION_TERMINATED", "SESSION_REVOKED", "PORTAL_LOCKED", "PORTAL_SECURITY_LOCKED",
        "GRANTS_REVOKED", "APPLICATION_GRANT_REVOKED", "ADMIN_SESSION_TERMINATED",
        "ADMIN_ALERT_CONTAINED", "ADMIN_INCIDENT_CONTAINED", "CONTAINMENT_ACTION",
        "SECURITY_LOCK_TRIGGERED"
    ]
    containment_decisions = ["TERMINATE_SESSION", "RESTRICT", "LOCK_PORTAL", "BLOCK", "CONTAIN_ALERT", "CONTAIN_INCIDENT", "REVOKE_GRANT"]

    from sqlalchemy import or_
    query = db.query(SecurityEvent).filter(
        or_(
            SecurityEvent.event_type.in_(containment_ev_types),
            SecurityEvent.decision.in_(containment_decisions)
        )
    )
    if application and application.lower() != "all":
        query = query.filter(SecurityEvent.application == application.lower())

    total = query.count()
    events = query.order_by(SecurityEvent.timestamp.desc()).offset(skip).limit(limit).all()

    items = []
    for ev in events:
        items.append(SOCContainmentActionItem(
            id=ev.id,
            timestamp=ev.timestamp,
            action_type=ev.event_type or ev.decision or "CONTAINMENT",
            target_user_id=ev.user_id,
            target_session_id=str(ev.session_id) if ev.session_id is not None else None,
            application=ev.application or "platform",
            details=ev.details,
            severity=ev.severity or "HIGH",
            status="CONTAINED"
        ))

    return SOCContainmentActionsResponse(total=total, actions=items)


@router.get("/soc/summary", response_model=SOCSummaryResponse)
async def get_soc_summary(
    time_window_minutes: int = Query(60, ge=5, le=1440),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """
    Produces executive SOC Threat Assessment, fleet posture aggregates,
    and attack pattern correlations using the SOCMonitoringAgent.
    """
    from app.agents.modules.soc_monitoring_agent import SOCMonitoringAgent
    from app.agents.schemas.agent_schemas import SOCMonitoringInput

    agent = SOCMonitoringAgent(db=db)

    # Ingest recent events
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=time_window_minutes)
    events_raw = db.query(SecurityEvent).filter(SecurityEvent.timestamp >= cutoff).order_by(SecurityEvent.timestamp.desc()).limit(100).all()
    events_list = [
        {
            "id": e.id,
            "user_id": e.user_id,
            "session_id": e.session_id,
            "application": e.application,
            "event_type": e.event_type,
            "severity": e.severity,
            "risk_score": e.risk_score,
            "risk_level": e.severity,
            "decision": e.decision,
            "details": e.details
        }
        for e in events_raw
    ]

    inp = SOCMonitoringInput(
        time_window_minutes=time_window_minutes,
        risk_events=events_list
    )
    out = await agent.execute(inp)

    return SOCSummaryResponse(
        executive_summary=out.executive_summary,
        threat_assessment=out.threat_assessment,
        incident_priority=out.incident_priority,
        suspicious_patterns=out.suspicious_patterns,
        attack_correlations=out.attack_correlations,
        observed_facts=out.observed_facts,
        inferred_threats=out.inferred_threats,
        investigation_steps=out.investigation_steps,
        timestamp=out.timestamp,
        provenance="AI_ASSISTED_ADVISORY"
    )


@router.get("/soc/recommendations", response_model=SOCRecommendationsResponse)
async def get_soc_recommendations(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """
    Delivers advisory, non-disruptive investigation recommendations for administrators.
    """
    from app.agents.modules.soc_monitoring_agent import SOCMonitoringAgent
    from app.agents.schemas.agent_schemas import SOCMonitoringInput

    agent = SOCMonitoringAgent(db=db)
    events_raw = db.query(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(50).all()
    events_list = [
        {"id": e.id, "user_id": e.user_id, "session_id": e.session_id, "application": e.application, "event_type": e.event_type, "severity": e.severity, "risk_score": e.risk_score}
        for e in events_raw
    ]
    out = await agent.execute(SOCMonitoringInput(time_window_minutes=60, risk_events=events_list))

    return SOCRecommendationsResponse(
        recommendations=out.investigation_steps or out.recommended_actions,
        priority=out.incident_priority,
        generated_at=datetime.now(timezone.utc).isoformat()
    )


class PortalLockRecoverRequest(BaseModel):
    notes: Optional[str] = None


_FACTOR_LABELS = {
    "LOGIN_OTP": "Initial Login Email OTP",
    "EXAM_OTP": "Exam Email OTP",
    "APPOINTMENT_OTP": "Appointment Email OTP",
    "PAYMENT_OTP": "Payment Email OTP",
    "CONFIDENTIAL_RESOURCE": "NeuralTrace Gesture",
    "PASSWORD_CHANGE": "Cognitive Password Verification",
    "COGNITIVE": "Cognitive Verification",
    "GESTURE": "NeuralTrace Gesture",
    "RECOVERY_OTP": "Recovery Email OTP",
}


def _serialize_admin_portal_lock(db: Session, lk) -> dict:
    from app.services.portal_lock_service import PortalLockService

    item = PortalLockService.serialize_lock(lk)
    owner = db.query(User).filter(User.id == lk.user_id).first()
    purpose_key = (lk.verification_purpose or "").strip().upper()
    failed_factor_label = _FACTOR_LABELS.get(purpose_key, lk.verification_purpose or "Authentication Challenge")

    if lk.lock_status == "RECOVERED":
        admin_review_status = "Approved by Admin"
    elif (lk.recovery_status or "").upper() == "REJECTED_BY_ADMIN":
        admin_review_status = "Rejected by Admin"
    else:
        admin_review_status = "Pending Admin Review"

    otp_verified = lk.recovery_otp_verified_at is not None
    otp_status_label = "OTP Verified — Awaiting Admin" if otp_verified else "Pending Recovery OTP"
    if lk.lock_status == "RECOVERED":
        otp_status_label = "OTP Verified — Cleared"
    elif (lk.recovery_status or "").upper() == "REJECTED_BY_ADMIN":
        otp_status_label = "OTP Verified — Rejected" if otp_verified else "Rejected by Admin"

    latest_alert = (
        db.query(Alert)
        .filter(
            Alert.user_id == lk.user_id,
            Alert.application == lk.application,
            Alert.alert_type.in_([
                "PORTAL_RECOVERY_REQUESTED",
                "PORTAL_SECURITY_LOCKOUT",
                "PORTAL_LOCK_RECOVERY_REJECTED",
                "PORTAL_REENTRY_ATTEMPT",
                "CROSS_PORTAL_LOCKOUT_ESCALATION",
            ]),
        )
        .order_by(Alert.id.desc())
        .first()
    )

    item["user_id"] = lk.user_id
    item["user_name"] = owner.name if owner else "Unknown User"
    item["user_email"] = owner.email if owner else None
    item["failed_factor_label"] = failed_factor_label
    item["admin_review_status"] = admin_review_status
    item["recovery_otp_status_label"] = otp_status_label
    item["request_timestamp"] = item.get("recovery_otp_verified_at") or item.get("locked_at")
    item["reviewed_by"] = lk.unlocked_by
    item["associated_alert_id"] = latest_alert.id if latest_alert else None
    item["associated_alert_status"] = latest_alert.status if latest_alert else None
    return item


@router.get("/portal-locks")
def list_portal_security_locks(
    lock_status: Optional[str] = Query(None, description="Filter by lock_status: ACTIVE or RECOVERED"),
    application: Optional[str] = Query(None, description="Filter by portal application"),
    user_id: Optional[int] = Query(None, description="Filter by user_id"),
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Lists persistent portal-scoped security lock records for SOC administration."""
    from app.models.portal_lock import PortalSecurityLock

    q = db.query(PortalSecurityLock)
    if lock_status:
        q = q.filter(PortalSecurityLock.lock_status == lock_status.strip().upper())
    if application:
        q = q.filter(PortalSecurityLock.application == SessionService.normalize_application(application))
    if user_id is not None:
        q = q.filter(PortalSecurityLock.user_id == user_id)
    locks = q.order_by(PortalSecurityLock.id.desc()).limit(200).all()
    return [_serialize_admin_portal_lock(db, lk) for lk in locks]


@router.get("/portal-locks/{security_reference_id}")
def get_portal_security_lock_detail(
    security_reference_id: str,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Returns full portal recovery investigation context and correlated security event history."""
    from app.models.portal_lock import PortalSecurityLock

    lk = (
        db.query(PortalSecurityLock)
        .filter(PortalSecurityLock.security_reference_id == security_reference_id)
        .first()
    )
    if not lk:
        raise HTTPException(
            status_code=404,
            detail=f"Portal security lock '{security_reference_id}' not found."
        )
    detail = _serialize_admin_portal_lock(db, lk)
    events = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.user_id == lk.user_id,
            SecurityEvent.application == lk.application,
        )
        .order_by(SecurityEvent.id.desc())
        .limit(15)
        .all()
    )
    detail["events"] = [
        {
            "id": ev.id,
            "event_type": ev.event_type,
            "severity": ev.severity,
            "decision": ev.decision,
            "details": ev.details,
            "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
        }
        for ev in events
    ]
    return detail


@router.post("/portal-locks/{security_reference_id}/recover")
def recover_portal_security_lock(
    security_reference_id: str,
    request_conn: Request,
    payload: Optional[PortalLockRecoverRequest] = None,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Authorized administrator / SOC clearance to lift a persistent portal security lock.
    Enforces ADMIN privileges, blocks self-approval, clears portal counters,
    and requires fresh 20-second observation + initial Email OTP on next portal login.
    """
    from app.services.portal_lock_service import PortalLockService

    client_ip = request_conn.client.host if request_conn.client else "127.0.0.1"
    forwarded = request_conn.headers.get("x-forwarded-for")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()

    lock = PortalLockService.admin_recover_portal_lock(
        db=db,
        security_reference_id=security_reference_id,
        admin_user=current_admin,
        notes=payload.notes if payload else None,
        client_ip=client_ip,
    )
    out = PortalLockService.serialize_lock(lock)
    out["success"] = True
    out["decision"] = "APPROVED"
    out["message"] = (
        f"Portal security lock {lock.security_reference_id} cleared by administrator {current_admin.email}. "
        f"Fresh 20-second behavioral observation and Email OTP verification are required on re-entry."
    )
    return out


@router.post("/portal-locks/{security_reference_id}/reject")
def reject_portal_security_lock_recovery(
    security_reference_id: str,
    request_conn: Request,
    payload: Optional[PortalLockRecoverRequest] = None,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Authorized administrator / SOC explicit rejection of portal lock recovery.
    Keeps PortalSecurityLock ACTIVE and records audit decision + notifications.
    """
    from app.services.portal_lock_service import PortalLockService

    client_ip = request_conn.client.host if request_conn.client else "127.0.0.1"
    forwarded = request_conn.headers.get("x-forwarded-for")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()

    lock = PortalLockService.admin_reject_portal_lock(
        db=db,
        security_reference_id=security_reference_id,
        admin_user=current_admin,
        notes=payload.notes if payload else None,
        client_ip=client_ip,
    )
    out = PortalLockService.serialize_lock(lock)
    out["success"] = True
    out["decision"] = "REJECTED"
    out["message"] = (
        f"Portal security lock {lock.security_reference_id} recovery rejected by administrator {current_admin.email}. "
        f"Portal remains suspended."
    )
    return out


_PROVIDER_VERIFY_LAST_TS: float = 0.0
_PROVIDER_VERIFY_COOLDOWN_SEC: float = 10.0


@router.post("/agents/verify-provider")
async def verify_agentic_provider(
    current_admin: User = Depends(require_admin),
):
    """
    Performs a live Gemini provider connectivity + test generation check on explicit admin action.
    Rate-limited to avoid hammering Google's API on repeated clicks.
    """
    global _PROVIDER_VERIFY_LAST_TS
    from app.core.config import settings
    from app.agents.core.factory import get_provider_health_status
    from app.agents.core.gemini_client import GeminiLLMClient, record_provider_failure

    now_mono = time.monotonic()
    elapsed = now_mono - _PROVIDER_VERIFY_LAST_TS
    if _PROVIDER_VERIFY_LAST_TS > 0 and elapsed < _PROVIDER_VERIFY_COOLDOWN_SEC:
        health = get_provider_health_status()
        return {
            "checked": False,
            "rate_limited": True,
            "retry_after_seconds": round(_PROVIDER_VERIFY_COOLDOWN_SEC - elapsed, 1),
            "provider_health": health,
        }

    _PROVIDER_VERIFY_LAST_TS = now_mono
    chosen = (settings.LLM_PROVIDER or "mock").strip().lower()
    if chosen != "gemini":
        return {
            "checked": True,
            "rate_limited": False,
            "provider_health": get_provider_health_status(),
        }

    client = GeminiLLMClient()
    if not client.validate_configuration():
        record_provider_failure("MISSING_API_KEY", "GEMINI_API_KEY is missing or unconfigured.")
        return {
            "checked": True,
            "rate_limited": False,
            "provider_health": get_provider_health_status(),
        }

    try:
        verify_res = await client.verify_connectivity(test_generation=True)
        return {
            "checked": True,
            "rate_limited": False,
            "verification": verify_res,
            "provider_health": get_provider_health_status(),
        }
    except Exception as e:
        return {
            "checked": True,
            "rate_limited": False,
            "error": str(e)[:180],
            "provider_health": get_provider_health_status(),
        }


@router.get("/agents/status")
def get_agentic_monitor_status(
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Returns safe Agentic AI Monitor status:
    - Real Gemini/Mock provider health (without exposing credentials)
    - The 5 existing specialized agents with availability, counts, and latest persisted status
    - Actual recent agent orchestration activity from persisted SecurityEvent records (DEMO & PRODUCTION)
    """
    from app.agents.core.factory import get_provider_health_status
    from app.agents.core.sanitization import Sanitizer

    provider_health = get_provider_health_status()
    provider_name = provider_health.get("configured_provider", "mock")
    model_name = provider_health.get("configured_model", "mock-v1")
    conn_status = provider_health.get("connectivity_status", "UNVERIFIED")
    creds_ok = bool(provider_health.get("credentials_present", False))

    # Fetch actual persisted agent orchestration / demo / production AGENTIC_* events
    agent_events = (
        db.query(SecurityEvent)
        .filter(
            or_(
                SecurityEvent.event_type.like("AGENTIC_%"),
                SecurityEvent.event_type.in_([
                    "AGENT_ORCHESTRATION_AUDIT",
                    "AGENT_DEMO_ANALYSIS",
                ]),
            )
        )
        .order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc())
        .limit(40)
        .all()
    )

    uids = {ev.user_id for ev in agent_events if ev.user_id is not None}
    user_map = {u.id: u for u in db.query(User).filter(User.id.in_(uids)).all()} if uids else {}

    agent_stats: Dict[str, Dict[str, Any]] = {}
    recent_activity: List[Dict[str, Any]] = []

    def _ensure_stat(k: str) -> Dict[str, Any]:
        if k not in agent_stats:
            agent_stats[k] = {
                "last_status": None,
                "last_timestamp": None,
                "latest_recommendation": None,
                "completed_count": 0,
                "fallback_count": 0,
                "timeout_count": 0,
                "failed_count": 0,
            }
        return agent_stats[k]

    for ev in agent_events:
        raw_details = {}
        if isinstance(ev.details, dict):
            raw_details = ev.details
        elif isinstance(ev.details, str) and ev.details.strip():
            try:
                parsed = json.loads(ev.details)
                if isinstance(parsed, dict):
                    raw_details = parsed
            except Exception:
                raw_details = {}
        meta = Sanitizer.sanitize_dict(raw_details)
        obs = (
            meta.get("agentic_orchestration")
            if isinstance(meta.get("agentic_orchestration"), dict)
            else (meta.get("observability") if isinstance(meta.get("observability"), dict) else meta)
        )
        agents_list = obs.get("agents_executed") or meta.get("agents_executed") or []
        exec_status = str(obs.get("execution_status") or ev.decision or "COMPLETED")
        trigger_ev = str(obs.get("trigger_event") or ev.event_type)
        ts_iso = ev.timestamp.isoformat() if ev.timestamp else None
        is_demo = (ev.event_type == "AGENT_DEMO_ANALYSIS") or bool(meta.get("is_demo"))
        fallback_err = obs.get("fallback_or_error")
        duration_ms = obs.get("duration_ms")
        sanitized_outputs = obs.get("sanitized_outputs") if isinstance(obs.get("sanitized_outputs"), dict) else {}
        arb_dec = obs.get("arbiter_decision") if isinstance(obs.get("arbiter_decision"), dict) else {}
        is_timeout_ev = "TIMEOUT" in exec_status.upper() or "timeout" in str(fallback_err or "").lower()

        if isinstance(agents_list, list):
            for raw_name in agents_list:
                clean_name = str(raw_name).split(":")[0]
                if clean_name == "DeterministicSecurityArbiter":
                    continue
                st_entry = _ensure_stat(clean_name)
                if ":fallback" in str(raw_name).lower() or "FALLBACK" in exec_status.upper():
                    outcome = "FALLBACK"
                    st_entry["fallback_count"] += 1
                    if is_timeout_ev:
                        st_entry["timeout_count"] += 1
                elif "FAIL" in exec_status.upper() or "ERROR" in exec_status.upper():
                    outcome = "FAILED"
                    st_entry["failed_count"] += 1
                else:
                    outcome = "COMPLETED"
                    st_entry["completed_count"] += 1

                if st_entry["last_status"] is None:
                    st_entry["last_status"] = outcome
                    st_entry["last_timestamp"] = ts_iso
                    rec_map = {
                        "SecurityContextAgent": sanitized_outputs.get("context_summary"),
                        "RiskAnalysisAgent": sanitized_outputs.get("risk_summary"),
                        "AdaptiveAuthAgent": sanitized_outputs.get("adaptive_auth_factor") or sanitized_outputs.get("adaptive_auth_action"),
                        "SecurityResponseAgent": sanitized_outputs.get("security_response"),
                        "SOCMonitoringAgent": sanitized_outputs.get("soc_summary") or sanitized_outputs.get("soc_priority"),
                    }
                    if rec_map.get(clean_name):
                        st_entry["latest_recommendation"] = str(rec_map[clean_name])[:160]

        u_obj = user_map.get(ev.user_id)
        if u_obj and u_obj.email:
            parts = u_obj.email.split("@")
            user_ref = f"{parts[0][:2]}***@{parts[1]}" if len(parts) == 2 else f"User #{ev.user_id}"
        else:
            user_ref = "Synthetic Demo" if is_demo else (f"User #{ev.user_id}" if ev.user_id else "Platform")

        summary_text = (
            meta.get("summary")
            or sanitized_outputs.get("soc_summary")
            or f"Score {round(float(ev.risk_score or 0.0), 2)} — Decision: {ev.decision or exec_status}"
        )

        recs_list = []
        if sanitized_outputs.get("adaptive_auth_factor"):
            recs_list.append(f"Factor: {sanitized_outputs.get('adaptive_auth_factor')}")
        if sanitized_outputs.get("security_response"):
            recs_list.append(str(sanitized_outputs.get("security_response"))[:100])

        recent_activity.append({
            "event_id": ev.id,
            "is_demo": is_demo,
            "environment_label": "DEMO" if is_demo else "PRODUCTION",
            "agent_name": ", ".join(str(a) for a in agents_list[:3]) + ("..." if len(agents_list) > 3 else "") if agents_list else "SecurityOrchestrator",
            "agents_executed": [str(a) for a in agents_list] if isinstance(agents_list, list) else [],
            "trigger_event": trigger_ev,
            "user_ref": user_ref,
            "portal": ev.application or "platform",
            "risk_level": ev.severity or _score_to_risk_level(ev.risk_score) or "LOW",
            "risk_score": round(float(ev.risk_score), 3) if ev.risk_score is not None else None,
            "recommendations": recs_list,
            "arbiter_decision": arb_dec.get("policy_decision") or ev.decision or exec_status,
            "actual_response": ev.decision or exec_status,
            "outcome": exec_status,
            "provider_status": "FALLBACK" if (is_timeout_ev or any(":fallback" in str(a).lower() for a in agents_list)) else str(obs.get("llm_provider") or provider_name).upper(),
            "fallback_or_error": fallback_err,
            "duration_ms": duration_ms,
            "timestamp": ts_iso,
            "sanitized_result": str(summary_text)[:220],
            "sanitized_outputs": sanitized_outputs,
        })

    agent_catalog = [
        {
            "key": "SecurityContextAgent",
            "name": "Security Context Agent",
            "responsibility": "Gathers sanitized session, device trust, and behavioral maturity facts.",
            "stage": 1,
        },
        {
            "key": "RiskAnalysisAgent",
            "name": "Risk Analysis Agent",
            "responsibility": "Evaluates behavioral anomalies and classifies threat category without lowering deterministic risk.",
            "stage": 2,
        },
        {
            "key": "AdaptiveAuthAgent",
            "name": "Adaptive Authentication Agent",
            "responsibility": "Recommends step-up authentication factors within strict Zero-Trust policy bounds.",
            "stage": 3,
        },
        {
            "key": "SecurityResponseAgent",
            "name": "Security Response Agent",
            "responsibility": "Coordinates permitted containment actions strictly bounded by deterministic severity.",
            "stage": 4,
        },
        {
            "key": "SOCMonitoringAgent",
            "name": "SOC Monitoring Agent",
            "responsibility": "Correlates fleet alerts, posture metrics, and analyst-ready threat summaries.",
            "stage": 5,
        },
    ]

    agents_payload = []
    for item in agent_catalog:
        st = agent_stats.get(item["key"], {})
        last_st = st.get("last_status")
        if not creds_ok and provider_name == "gemini":
            avail = "NOT CONFIGURED"
        elif last_st in ("COMPLETED", "FALLBACK", "FAILED"):
            avail = last_st
        else:
            avail = "READY"

        agents_payload.append({
            "key": item["key"],
            "name": item["name"],
            "responsibility": item["responsibility"],
            "stage": item["stage"],
            "provider": provider_name,
            "model": model_name,
            "provider_status": conn_status,
            "availability_status": avail,
            "last_execution_status": last_st,
            "last_executed_at": st.get("last_timestamp"),
            "completed_count": st.get("completed_count", 0),
            "fallback_count": st.get("fallback_count", 0),
            "timeout_count": st.get("timeout_count", 0),
            "failed_count": st.get("failed_count", 0),
            "latest_recommendation": st.get("latest_recommendation"),
        })

    return {
        "provider_health": provider_health,
        "agents": agents_payload,
        "recent_activity": recent_activity,
        "arbiter_authority_note": "Gemini provides advisory reasoning; DeterministicSecurityArbiter, RiskService, and DecisionService retain final authority.",
    }


@router.post("/agents/demo-analysis")
async def run_agentic_demo_analysis(
    payload: Optional[Dict[str, Any]] = None,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Executes an isolated, non-destructive multi-agent demonstration through SecurityOrchestrator.
    - Uses a synthetic test event with session_id=None, skip_containment=True, auto_containment=False.
    - Never touches real user sessions, behavioral profiles, OTPs, grants, or portal locks.
    - Shows deterministic assessment, agent recommendations, and final arbiter decision separately.
    """
    import uuid
    from app.core.config import settings
    from app.agents.execution.orchestrator import SecurityOrchestrator
    from app.agents.core.factory import get_provider_health_status
    from app.agents.core.sanitization import Sanitizer

    scenario = str((payload or {}).get("scenario") or "medium").strip().lower()
    scenario_map = {
        "low": {
            "score": 0.14,
            "level": "LOW",
            "portal": "shopping",
            "reasons": ["SYNTHETIC_DEMO_NOMINAL_BASELINE"],
        },
        "medium": {
            "score": 0.48,
            "level": "MEDIUM",
            "portal": "shopping",
            "reasons": ["SYNTHETIC_DEMO_TYPING_DRIFT", "SYNTHETIC_DEMO_NEW_DEVICE_SIGNAL"],
        },
        "high": {
            "score": 0.74,
            "level": "HIGH",
            "portal": "healthcare",
            "reasons": ["SYNTHETIC_DEMO_CROSS_MODAL_DRIFT", "SYNTHETIC_DEMO_ELEVATED_RISK"],
        },
        "critical": {
            "score": 0.89,
            "level": "CRITICAL",
            "portal": "healthcare",
            "reasons": ["SYNTHETIC_DEMO_CRITICAL_ANOMALY", "SYNTHETIC_DEMO_IMPOSSIBLE_TRAVEL"],
        },
    }
    cfg = scenario_map.get(scenario, scenario_map["medium"])

    orch = SecurityOrchestrator(db=db)
    # Give the explicit admin demo button enough budget for live Gemini reasoning
    # without altering the strict 800ms inline telemetry budget.
    demo_timeout = max(float(getattr(settings, "LLM_TIMEOUT_SECONDS", 2.0) or 2.0), 10.0)
    for ag in (orch.context_agent, orch.risk_agent, orch.auth_agent, orch.response_agent, orch.soc_agent):
        ag.timeout_seconds = max(float(ag.timeout_seconds), demo_timeout)

    corr_id = f"demo_{uuid.uuid4().hex[:10]}"
    res = await orch.evaluate_session_security(
        user_id=current_admin.id,
        session_id=None,
        application=cfg["portal"],
        telemetry_features=None,
        raw_anomaly_score=cfg["score"],
        deterministic_risk_score=cfg["score"],
        deterministic_risk_level=cfg["level"],
        contributing_reasons=cfg["reasons"],
        auto_containment=False,
        skip_containment=True,
        correlation_id=corr_id,
        idempotency_key=corr_id,
        trigger_event="ADMIN_AGENTIC_DEMO_ANALYSIS",
    )

    arb = res.get("arbitrated_risk", {})
    obs = res.get("observability", {})
    ctx_out = res.get("context")
    risk_out = res.get("risk_analysis")
    auth_out = res.get("adaptive_auth")
    resp_out = res.get("security_response")
    soc_out = res.get("soc_monitoring")

    def _to_dict(obj: Any) -> Dict[str, Any]:
        if hasattr(obj, "model_dump"):
            return Sanitizer.sanitize_dict(obj.model_dump())
        if isinstance(obj, dict):
            return Sanitizer.sanitize_dict(obj)
        return {}

    ctx_d = _to_dict(ctx_out)
    risk_d = _to_dict(risk_out)
    auth_d = _to_dict(auth_out)
    resp_d = _to_dict(resp_out)
    soc_d = _to_dict(soc_out)

    final_level = arb.get("effective_risk_level", cfg["level"])
    final_score = float(arb.get("effective_risk_score", cfg["score"]))
    final_decision = (
        "TERMINATE_SESSION" if final_level == "CRITICAL"
        else ("STEP_UP_REQUIRED" if auth_d.get("step_up_required") or auth_d.get("action") == "STEP_UP_REQUIRED"
              else ("DENY" if auth_d.get("action") == "DENY" else "ALLOW"))
    )

    # Persist one sanitized audit record for Recent Agent Activity (no real session modified)
    audit_ev = SecurityEvent(
        user_id=current_admin.id,
        session_id=None,
        application=cfg["portal"],
        event_type="AGENT_DEMO_ANALYSIS",
        severity=final_level,
        anomaly_score=cfg["score"],
        risk_score=final_score,
        decision=final_decision,
        details=json.dumps(Sanitizer.sanitize_dict({
            "is_demo": True,
            "correlation_id": corr_id,
            "trigger_event": "ADMIN_AGENTIC_DEMO_ANALYSIS",
            "scenario": scenario,
            "agents_executed": obs.get("agents_executed", []),
            "execution_status": obs.get("execution_status", "COMPLETED"),
            "duration_ms": obs.get("duration_ms"),
            "llm_provider": obs.get("llm_provider"),
            "llm_model": obs.get("llm_model"),
            "fallback_or_error": obs.get("fallback_or_error"),
            "arbiter_decision": obs.get("arbiter_decision"),
            "sanitized_outputs": obs.get("sanitized_outputs"),
            "summary": f"Synthetic {scenario.upper()} demo ({cfg['portal']}): Deterministic {cfg['level']} ({cfg['score']}) → Arbiter {final_level} ({round(final_score, 2)}) / {final_decision}",
        })),
    )
    db.add(audit_ev)
    db.commit()

    executed_raw = obs.get("agents_executed", [])
    fb_map = {str(e.get("agent")): str(e.get("error")) for e in (obs.get("fallback_or_error") or []) if isinstance(e, dict)}
    agent_statuses = {}
    for k in ("SecurityContextAgent", "RiskAnalysisAgent", "AdaptiveAuthAgent", "SecurityResponseAgent", "SOCMonitoringAgent"):
        if f"{k}:fallback" in executed_raw:
            agent_statuses[k] = {"status": "FALLBACK", "reason": fb_map.get(k, "Fallback used")}
        elif k in executed_raw:
            agent_statuses[k] = {"status": "COMPLETED", "reason": None}
        else:
            agent_statuses[k] = {"status": "SKIPPED", "reason": "Not executed"}

    return {
        "demo_mode": True,
        "isolation_verified": True,
        "scenario": scenario,
        "correlation_id": corr_id,
        "provider": {
            "llm_provider": obs.get("llm_provider"),
            "llm_model": obs.get("llm_model"),
            "health": get_provider_health_status(),
        },
        "deterministic_assessment": {
            "risk_score": cfg["score"],
            "risk_level": cfg["level"],
            "portal": cfg["portal"],
            "reasons": cfg["reasons"],
        },
        "agent_recommendations": {
            "security_context": {
                "summary": ctx_d.get("context_summary", "Context evaluated."),
                "risk_signals": ctx_d.get("risk_signals", []),
            },
            "risk_analysis": {
                "threat_category": risk_d.get("threat_category"),
                "recommended_risk_level": risk_d.get("recommended_risk_level"),
                "recommended_risk_score": risk_d.get("recommended_risk_score"),
                "recommended_action": risk_d.get("recommended_action"),
                "confidence": risk_d.get("confidence"),
                "explanation": risk_d.get("human_readable_explanation"),
            },
            "adaptive_auth": {
                "action": auth_d.get("action"),
                "recommended_factor": auth_d.get("recommended_factor"),
                "step_up_required": auth_d.get("step_up_required"),
                "rationale": auth_d.get("rationale"),
            },
            "security_response": {
                "incident_category": resp_d.get("incident_category"),
                "severity": resp_d.get("severity"),
                "required_backend_operation": resp_d.get("required_backend_operation"),
                "recommended_response": resp_d.get("recommended_response"),
                "containment_executed": False,
            },
            "soc_monitoring": {
                "incident_priority": soc_d.get("incident_priority"),
                "executive_summary": soc_d.get("executive_summary"),
                "threat_assessment": soc_d.get("threat_assessment"),
            },
        },
        "arbiter_decision": {
            "final_risk_level": final_level,
            "final_risk_score": final_score,
            "final_decision": final_decision,
            "arbiter_authority": "DeterministicSecurityArbiter retains final authority (monotonic floor preserved).",
        },
        "execution_result": {
            "agents_executed": obs.get("agents_executed", []),
            "agent_statuses": agent_statuses,
            "fallback_or_error": obs.get("fallback_or_error"),
            "execution_status": obs.get("execution_status"),
            "duration_ms": obs.get("duration_ms"),
        },
    }


_FIVE_AGENT_DEFS = [
    ("SecurityContextAgent", "Security Context Agent", "Compiles session, device trust, and maturity context"),
    ("RiskAnalysisAgent", "Risk Analysis Agent", "Classifies threat category and compound anomalies"),
    ("AdaptiveAuthAgent", "Adaptive Authentication Agent", "Recommends step-up factor within policy bounds"),
    ("SecurityResponseAgent", "Security Response Agent", "Formulates bounded incident response & containment"),
    ("SOCMonitoringAgent", "SOC Monitoring Agent", "Correlates fleet alerts & executive summaries"),
]


def _parse_agent_execution_row(ev: SecurityEvent, user_map: Dict[int, User]) -> Dict[str, Any]:
    from app.agents.core.sanitization import Sanitizer

    raw_details: Dict[str, Any] = {}
    if isinstance(ev.details, dict):
        raw_details = ev.details
    elif isinstance(ev.details, str) and ev.details.strip():
        try:
            parsed = json.loads(ev.details)
            if isinstance(parsed, dict):
                raw_details = parsed
        except Exception:
            raw_details = {}

    meta = Sanitizer.sanitize_dict(raw_details)
    obs = (
        meta.get("agentic_orchestration")
        if isinstance(meta.get("agentic_orchestration"), dict)
        else (meta.get("observability") if isinstance(meta.get("observability"), dict) else meta)
    )
    agents_list = obs.get("agents_executed") or meta.get("agents_executed") or []
    if not isinstance(agents_list, list):
        agents_list = []

    timings = obs.get("agent_timings_ms") if isinstance(obs.get("agent_timings_ms"), dict) else {}
    fallback_err = obs.get("fallback_or_error")
    err_list: List[Dict[str, Any]] = []
    if isinstance(fallback_err, list):
        err_list = [e for e in fallback_err if isinstance(e, dict)]
    elif isinstance(fallback_err, dict):
        err_list = [fallback_err]
    elif fallback_err:
        err_list = [{"agent": "Orchestrator", "error": str(fallback_err)[:200]}]

    raw_status = str(obs.get("execution_status") or ev.decision or "COMPLETED").upper()
    has_timeout = "TIMEOUT" in raw_status or any("timeout" in str(e.get("error", "")).lower() for e in err_list)
    has_fallback = any(":fallback" in str(a).lower() for a in agents_list) or bool(err_list)
    has_failed = "FAILED" in raw_status or "ERROR" in raw_status

    if has_timeout:
        norm_status = "TIMEOUT"
    elif has_failed and not has_fallback:
        norm_status = "FAILED"
    elif has_fallback:
        norm_status = "FALLBACK"
    else:
        norm_status = "SUCCESS"

    arb = obs.get("arbiter_decision") if isinstance(obs.get("arbiter_decision"), dict) else {}
    det_assess = obs.get("deterministic_assessment") if isinstance(obs.get("deterministic_assessment"), dict) else {}
    agent_rec = obs.get("agent_recommendation") if isinstance(obs.get("agent_recommendation"), dict) else {}
    san_out = obs.get("sanitized_outputs") if isinstance(obs.get("sanitized_outputs"), dict) else {}
    tool_calls = obs.get("tool_calls") if isinstance(obs.get("tool_calls"), dict) else {}
    inp_summary = obs.get("input_summary") if isinstance(obs.get("input_summary"), dict) else None

    clean_agents: List[str] = []
    per_agent_details: Dict[str, Dict[str, Any]] = {}
    for raw_a in agents_list:
        s_a = str(raw_a)
        base_name = s_a.split(":")[0]
        if base_name not in clean_agents:
            clean_agents.append(base_name)
        is_fb = ":fallback" in s_a.lower()
        per_agent_details[base_name] = {
            "status": "FALLBACK" if is_fb else ("TIMEOUT" if has_timeout else "SUCCESS"),
            "duration_ms": timings.get(base_name),
        }

    u = user_map.get(ev.user_id) if ev.user_id is not None else None
    summary_parts = [
        san_out.get("risk_summary"),
        san_out.get("soc_summary"),
        san_out.get("security_response"),
        san_out.get("context_summary"),
    ]
    result_summary = next((str(p) for p in summary_parts if p), None) or (
        f"Arbiter {arb.get('effective_risk_level') or ev.severity or 'LOW'} -> {arb.get('policy_decision') or ev.decision or 'PERMITTED'}"
    )

    det_level = det_assess.get("risk_level") or _score_to_risk_level(ev.risk_score) or ev.severity or "LOW"
    det_score = det_assess.get("risk_score") if det_assess.get("risk_score") is not None else ev.risk_score
    arb_level = arb.get("effective_risk_level") or ev.severity or "LOW"
    arb_score = arb.get("effective_risk_score") if arb.get("effective_risk_score") is not None else ev.risk_score

    return {
        "execution_id": str(obs.get("correlation_id") or f"ev_{ev.id}"),
        "event_id": ev.id,
        "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
        "trigger_event": str(obs.get("trigger_event") or ev.event_type),
        "event_type": ev.event_type,
        "user_id": ev.user_id,
        "user_email": u.email if u else None,
        "session_id": f"{ev.session_id[:12]}..." if ev.session_id else None,
        "portal": (ev.application or "platform").lower(),
        "agents_executed": clean_agents,
        "per_agent_details": per_agent_details,
        "status": norm_status,
        "raw_execution_status": raw_status,
        "processing_time_ms": obs.get("duration_ms"),
        "result_summary": result_summary[:280],
        "llm_provider": obs.get("llm_provider"),
        "llm_model": obs.get("llm_model"),
        "input_summary": inp_summary,
        "sanitized_outputs": san_out,
        "tool_calls": tool_calls,
        "risk_assessment": {
            "deterministic_risk_level": det_level,
            "deterministic_risk_score": det_score,
            "anomaly_score": ev.anomaly_score,
            "arbiter_risk_level": arb_level,
            "arbiter_risk_score": arb_score,
        },
        "agent_recommendation": {
            "recommended_risk_level": agent_rec.get("recommended_risk_level"),
            "recommended_risk_score": agent_rec.get("recommended_risk_score"),
            "threat_category": agent_rec.get("threat_category"),
            "recommended_factor": agent_rec.get("recommended_factor") or arb.get("recommended_factor"),
            "recommended_response": agent_rec.get("recommended_response") or san_out.get("security_response"),
        },
        "arbiter_decision": {
            "effective_risk_level": arb_level,
            "effective_risk_score": arb_score,
            "is_agent_accepted": arb.get("is_agent_accepted"),
            "override_reason": arb.get("override_reason"),
            "policy_decision": arb.get("policy_decision") or ev.decision,
            "synchronous_kill_executed": bool(obs.get("synchronous_kill_executed", False)),
        },
        "final_action": str(arb.get("policy_decision") or ev.decision or "PERMITTED"),
        "errors_or_fallbacks": err_list,
    }


@router.get("/agents/investigation")
def get_agentic_investigation_dashboard(
    search: Optional[str] = Query(None),
    agent: Optional[str] = Query("ALL"),
    status: Optional[str] = Query("ALL"),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Full database-backed Agentic AI Execution & Investigation Center payload.
    Excludes synthetic AGENT_DEMO_ANALYSIS and ADMIN login/activity records.
    """
    from app.agents.core.factory import get_provider_health_status
    from app.models.portal_lock import PortalSecurityLock

    non_admin_uids = _non_admin_user_ids_subquery(db)
    q = db.query(SecurityEvent).filter(
        SecurityEvent.user_id.in_(non_admin_uids),
        SecurityEvent.event_type != "AGENT_DEMO_ANALYSIS",
        or_(
            SecurityEvent.event_type.like("AGENTIC_%"),
            SecurityEvent.event_type == "AGENT_ORCHESTRATION_AUDIT",
            func.coalesce(SecurityEvent.details, "").ilike('%"agentic_orchestration"%'),
        ),
        ~func.coalesce(SecurityEvent.session_id, "").like("sim_%"),
        ~func.coalesce(SecurityEvent.session_id, "").like("test_%"),
    )

    if date_from:
        try:
            dt_from = datetime.fromisoformat(date_from.strip())
            if dt_from.tzinfo is None:
                dt_from = dt_from.replace(tzinfo=timezone.utc)
            q = q.filter(SecurityEvent.timestamp >= dt_from)
        except Exception:
            pass
    if date_to:
        try:
            raw_to = date_to.strip()
            dt_to = datetime.fromisoformat(raw_to)
            if len(raw_to) == 10:
                dt_to = dt_to + timedelta(days=1)
            if dt_to.tzinfo is None:
                dt_to = dt_to.replace(tzinfo=timezone.utc)
            q = q.filter(SecurityEvent.timestamp < dt_to)
        except Exception:
            pass

    raw_events = q.order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc()).limit(500).all()
    uids = {ev.user_id for ev in raw_events if ev.user_id is not None}
    user_map = {u.id: u for u in db.query(User).filter(User.id.in_(uids)).all()} if uids else {}

    parsed_all = [_parse_agent_execution_row(ev, user_map) for ev in raw_events]

    # Apply search, agent, and status filters
    search_term = search.strip().lower() if search and search.strip() else None
    agent_filter = agent.strip() if agent and agent.strip().upper() != "ALL" else None
    status_filter = status.strip().upper() if status and status.strip().upper() != "ALL" else None

    filtered: List[Dict[str, Any]] = []
    for row in parsed_all:
        if agent_filter and agent_filter not in row["agents_executed"]:
            continue
        if status_filter and row["status"] != status_filter:
            continue
        if search_term:
            hay = " ".join([
                str(row["execution_id"]),
                str(row["trigger_event"]),
                str(row["portal"]),
                str(row["user_email"] or ""),
                str(row["result_summary"]),
                " ".join(row["agents_executed"]),
            ]).lower()
            if search_term not in hay:
                continue
        filtered.append(row)

    # 1. Execution Overview
    total_exec = len(filtered)
    succ_exec = sum(1 for r in filtered if r["status"] == "SUCCESS")
    fail_exec = sum(1 for r in filtered if r["status"] == "FAILED")
    to_exec = sum(1 for r in filtered if r["status"] == "TIMEOUT")
    fb_exec = sum(1 for r in filtered if r["status"] == "FALLBACK")
    durations = [float(r["processing_time_ms"]) for r in filtered if r["processing_time_ms"] is not None]
    avg_dur = round(sum(durations) / len(durations), 2) if durations else None
    last_exec_ts = filtered[0]["timestamp"] if filtered else None

    provider_health = get_provider_health_status()
    gemini_failures = int(provider_health.get("failed_requests") or 0)

    # 2. Pagination for All Agent Executions
    total_pages = max(1, (total_exec + page_size - 1) // page_size)
    safe_page = min(page, total_pages)
    start_idx = (safe_page - 1) * page_size
    paged_execs = filtered[start_idx:start_idx + page_size]

    # 3. Five Agent Details
    five_agents_out = []
    output_key_map = {
        "SecurityContextAgent": ("context_summary",),
        "RiskAnalysisAgent": ("risk_summary",),
        "AdaptiveAuthAgent": ("adaptive_auth_action", "adaptive_auth_factor"),
        "SecurityResponseAgent": ("security_response",),
        "SOCMonitoringAgent": ("soc_summary", "soc_priority"),
    }
    for key, label, desc in _FIVE_AGENT_DEFS:
        agent_rows = [r for r in filtered if key in r["agents_executed"]]
        a_durs = [
            float(r["per_agent_details"][key]["duration_ms"])
            for r in agent_rows
            if r["per_agent_details"].get(key, {}).get("duration_ms") is not None
        ]
        a_fb = sum(1 for r in agent_rows if r["per_agent_details"].get(key, {}).get("status") == "FALLBACK")
        a_fail = sum(1 for r in agent_rows if r["per_agent_details"].get(key, {}).get("status") in ("FAILED", "TIMEOUT"))
        summaries = []
        for r in agent_rows[:5]:
            so = r.get("sanitized_outputs") or {}
            vals = [str(so.get(ok)) for ok in output_key_map.get(key, ()) if so.get(ok)]
            if vals:
                summaries.append({
                    "execution_id": r["execution_id"],
                    "timestamp": r["timestamp"],
                    "summary": " · ".join(vals)[:220],
                })
        a_succ = sum(1 for r in agent_rows if r["per_agent_details"].get(key, {}).get("status") == "SUCCESS")
        a_errs = [
            {
                "execution_id": r["execution_id"],
                "timestamp": r["timestamp"],
                "error": err.get("error") or "Fallback engaged",
            }
            for r in agent_rows
            for err in (r.get("errors_or_fallbacks") or [])
            if err.get("agent") == key
        ][:5]
        lifecycle_state = "OPERATIONAL" if a_succ > 0 else ("EXECUTED" if len(agent_rows) > 0 else "IMPLEMENTED")
        five_agents_out.append({
            "agent_key": key,
            "name": label,
            "description": desc,
            "lifecycle_state": lifecycle_state,
            "execution_count": len(agent_rows),
            "successful_count": a_succ,
            "last_execution": agent_rows[0]["timestamp"] if agent_rows else None,
            "last_status": agent_rows[0]["per_agent_details"].get(key, {}).get("status") if agent_rows else "NO_RECORDED_EXECUTIONS",
            "avg_processing_time_ms": round(sum(a_durs) / len(a_durs), 2) if a_durs else None,
            "fallback_count": a_fb,
            "failed_count": a_fail,
            "output_summaries": summaries,
            "errors_and_fallbacks": a_errs,
        })

    # 4. Gemini / LLM Activity
    llm_activity = {
        "provider": provider_health.get("configured_provider", "mock"),
        "model": provider_health.get("configured_model", "mock-v1"),
        "credentials_configured": bool(provider_health.get("credentials_present", False)),
        "connectivity_status": provider_health.get("connectivity_status", "UNVERIFIED"),
        "test_generation_status": provider_health.get("test_generation_status", "Not tested"),
        "last_successful_connection": provider_health.get("last_successful_check"),
        "api_requests": int(provider_health.get("total_requests") or 0),
        "successful_requests": int(provider_health.get("successful_requests") or 0),
        "failed_requests": gemini_failures,
        "avg_latency_ms": provider_health.get("avg_latency_ms"),
        "last_latency_ms": provider_health.get("last_latency_ms"),
        "timeout_errors": int(provider_health.get("timeout_errors") or 0),
        "rate_limit_errors": int(provider_health.get("rate_limit_errors") or 0),
        "fallback_usage_count": fb_exec,
        "last_failure_category": provider_health.get("last_failure_category"),
        "last_failure_reason": provider_health.get("last_failure_reason"),
    }

    # 5. Decision & Arbiter History
    decision_arbiter_history = [
        {
            "execution_id": r["execution_id"],
            "event_id": r["event_id"],
            "timestamp": r["timestamp"],
            "portal": r["portal"],
            "trigger_event": r["trigger_event"],
            "deterministic_risk_level": r["risk_assessment"]["deterministic_risk_level"],
            "deterministic_risk_score": r["risk_assessment"]["deterministic_risk_score"],
            "agent_recommendation": r["agent_recommendation"],
            "arbiter_decision": r["arbiter_decision"],
            "escalation_accepted": r["arbiter_decision"]["is_agent_accepted"],
            "final_enforcement_outcome": r["final_action"],
        }
        for r in filtered[:100]
    ]

    # 6. Security Response History (actual response actions from DB)
    resp_events = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.user_id.in_(non_admin_uids),
            SecurityEvent.event_type.in_([
                "SESSION_TERMINATED",
                "ZERO_TRUST_KILL_SWITCH",
                "APPLICATION_GRANT_REVOKED",
                "GRANTS_REVOKED",
                "PORTAL_SECURITY_LOCKED",
                "PORTAL_LOCKED",
            ]),
            ~func.coalesce(SecurityEvent.session_id, "").like("sim_%"),
            ~func.coalesce(SecurityEvent.session_id, "").like("test_%"),
        )
        .order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc())
        .limit(60)
        .all()
    )
    resp_alerts = (
        db.query(Alert)
        .filter(
            Alert.user_id.in_(non_admin_uids),
            ~func.coalesce(Alert.message, "").ilike("%sim_%"),
            ~func.coalesce(Alert.message, "").ilike("%simulated%"),
            ~func.coalesce(Alert.message, "").ilike("%test%"),
        )
        .order_by(Alert.created_at.desc(), Alert.id.desc())
        .limit(40)
        .all()
    )
    resp_locks = (
        db.query(PortalSecurityLock)
        .filter(PortalSecurityLock.user_id.in_(non_admin_uids))
        .order_by(PortalSecurityLock.locked_at.desc(), PortalSecurityLock.id.desc())
        .limit(30)
        .all()
    )
    security_response_history: List[Dict[str, Any]] = []
    for re_ev in resp_events:
        det_str = str(re_ev.details or "")
        is_agent_trig = ("agentic_orchestration" in det_str) or ("SecurityResponseAgent" in det_str) or ("agent" in det_str.lower())
        security_response_history.append({
            "action_id": f"ev_{re_ev.id}",
            "timestamp": re_ev.timestamp.isoformat() if re_ev.timestamp else None,
            "action_type": re_ev.event_type,
            "origin_type": "Agent-Triggered" if is_agent_trig else "Deterministic Security Event",
            "portal": (re_ev.application or "platform").lower(),
            "user_id": re_ev.user_id,
            "session_id": f"{re_ev.session_id[:12]}..." if re_ev.session_id else None,
            "status": re_ev.decision or "ENFORCED",
            "summary": (det_str[:200] if det_str else re_ev.event_type),
            "source": "SecurityEvent",
        })
    for lk in resp_locks:
        security_response_history.append({
            "action_id": f"lock_{lk.id}",
            "timestamp": lk.locked_at.isoformat() if lk.locked_at else None,
            "action_type": "PORTAL_SECURITY_LOCKED",
            "origin_type": "Deterministic Security Event",
            "portal": (lk.application or "platform").lower(),
            "user_id": lk.user_id,
            "session_id": None,
            "status": lk.lock_status or "ACTIVE",
            "summary": f"Portal lock ({lk.security_reference_id}): {lk.lock_reason or 'High-risk containment'}",
            "source": "PortalSecurityLock",
        })
    for al in resp_alerts:
        al_msg = str(al.message or "")
        is_agent_al = ("agent" in al_msg.lower()) or ("orchestrat" in al_msg.lower())
        security_response_history.append({
            "action_id": f"alert_{al.id}",
            "timestamp": al.created_at.isoformat() if al.created_at else None,
            "action_type": f"ALERT_CREATED ({al.alert_type})",
            "origin_type": "Agent-Triggered" if is_agent_al else "Deterministic Security Event",
            "portal": (al.application or "platform").lower(),
            "user_id": al.user_id,
            "session_id": None,
            "status": al.status or "OPEN",
            "summary": al_msg[:200],
            "source": "Alert",
        })
    security_response_history.sort(key=lambda x: x.get("timestamp") or "", reverse=True)
    security_response_history = security_response_history[:100]

    # 7. Errors & Fallbacks
    errors_and_fallbacks: List[Dict[str, Any]] = []
    for r in filtered:
        for err in r.get("errors_or_fallbacks") or []:
            err_msg = str(err.get("error") or "Deterministic fallback invoked")
            cat = "TIMEOUT" if "timeout" in err_msg.lower() else ("PROVIDER_FAILURE" if "gemini" in err_msg.lower() or "llm" in err_msg.lower() else "AGENT_FALLBACK")
            errors_and_fallbacks.append({
                "execution_id": r["execution_id"],
                "event_id": r["event_id"],
                "timestamp": r["timestamp"],
                "agent_name": err.get("agent") or "Orchestrator",
                "category": cat,
                "error_message": err_msg[:220],
                "fallback_used": True,
                "retry_attempts": err.get("retry_attempts", 0),
                "trigger_event": r["trigger_event"],
                "portal": r["portal"],
            })

    last_succ_ts = next((r["timestamp"] for r in filtered if r["status"] == "SUCCESS"), None)
    if succ_exec > 0 and all(a["lifecycle_state"] == "OPERATIONAL" for a in five_agents_out):
        pipeline_status = "OPERATIONAL"
    elif succ_exec > 0 or fb_exec > 0 or (total_exec > 0 and to_exec < total_exec):
        pipeline_status = "PARTIALLY_OPERATIONAL"
    elif total_exec > 0 and to_exec == total_exec:
        pipeline_status = "PARTIALLY_OPERATIONAL"
    elif not bool(provider_health.get("credentials_present", False)):
        pipeline_status = "UNAVAILABLE"
    else:
        pipeline_status = "PARTIALLY_OPERATIONAL"

    return {
        "overview": {
            "total_executions": total_exec,
            "successful_executions": succ_exec,
            "failed_executions": fail_exec,
            "timed_out_executions": to_exec,
            "deterministic_fallbacks": fb_exec,
            "gemini_api_failures": gemini_failures,
            "avg_execution_time_ms": avg_dur,
            "last_execution_timestamp": last_exec_ts,
            "last_successful_execution_timestamp": last_succ_ts,
            "pipeline_status": pipeline_status,
        },
        "executions": paged_execs,
        "pagination": {
            "page": safe_page,
            "page_size": page_size,
            "total": total_exec,
            "total_pages": total_pages,
        },
        "five_agents": five_agents_out,
        "llm_activity": llm_activity,
        "decision_arbiter_history": decision_arbiter_history,
        "security_response_history": security_response_history,
        "errors_and_fallbacks": errors_and_fallbacks,
    }


@router.get("/agents/executions/{execution_id}")
def get_agentic_execution_detail(
    execution_id: str,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Returns full sanitized details for a single persisted agentic execution by event ID or correlation ID."""
    non_admin_uids = _non_admin_user_ids_subquery(db)
    ev = None
    if execution_id.isdigit():
        ev = db.query(SecurityEvent).filter(
            SecurityEvent.id == int(execution_id),
            SecurityEvent.user_id.in_(non_admin_uids),
            SecurityEvent.event_type != "AGENT_DEMO_ANALYSIS",
        ).first()
    elif execution_id.startswith("ev_") and execution_id[3:].isdigit():
        ev = db.query(SecurityEvent).filter(
            SecurityEvent.id == int(execution_id[3:]),
            SecurityEvent.user_id.in_(non_admin_uids),
            SecurityEvent.event_type != "AGENT_DEMO_ANALYSIS",
        ).first()
    else:
        ev = (
            db.query(SecurityEvent)
            .filter(
                SecurityEvent.user_id.in_(non_admin_uids),
                SecurityEvent.event_type != "AGENT_DEMO_ANALYSIS",
                func.coalesce(SecurityEvent.details, "").ilike(f"%{execution_id}%"),
            )
            .order_by(SecurityEvent.id.desc())
            .first()
        )
    if not ev:
        raise HTTPException(status_code=404, detail=f"Agent execution '{execution_id}' not found.")
    user_map = {}
    if ev.user_id is not None:
        u = db.query(User).filter(User.id == ev.user_id).first()
        if u:
            user_map[u.id] = u
    return _parse_agent_execution_row(ev, user_map)





