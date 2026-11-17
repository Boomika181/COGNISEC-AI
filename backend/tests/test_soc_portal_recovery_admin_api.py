"""
Automated Verification Suite:
SOC Dashboard Portal Recovery Admin API, Detail Dossier, Duplicate Approval Guard,
Rejection Semantics, and Generic Alert Resolve Isolation.
"""

from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.rate_limit import rate_limiter
from app.core.security import create_access_token, get_password_hash
from app.models.alert import Alert
from app.models.portal_lock import PortalSecurityLock
from app.models.security_event import SecurityEvent
from app.models.user import User
from app.services.portal_lock_service import PortalLockService
from app.services.step_up_service import StepUpService


@pytest.fixture(autouse=True)
def reset_state():
    StepUpService.reset()
    rate_limiter.reset()
    yield


def _create_user_and_token(db: Session, email: str, name: str, role: str = "USER"):
    user = User(
        name=name,
        email=email,
        password_hash=get_password_hash("SocTestPass!2026"),
        role=role,
        account_status="ACTIVE",
        created_at=datetime.now(timezone.utc),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    token = create_access_token(user.id, user.role)
    return user, {"Authorization": f"Bearer {token}"}


def test_soc_portal_locks_list_detail_approve_duplicate_reject_and_alert_isolation(
    client: TestClient, db_session: Session
):
    owner, owner_headers = _create_user_and_token(
        db_session, "soc_ui_owner@cognisec.ai", "Rhea Kapoor", role="USER"
    )
    admin, admin_headers = _create_user_and_token(
        db_session, "soc_ui_admin@cognisec.ai", "SOC Commander", role="ADMIN"
    )

    # Create two active locks for the same user: shopping (OTP verified) and college (pending OTP)
    shop_lock = PortalSecurityLock(
        user_id=owner.id,
        application="shopping",
        lock_status="ACTIVE",
        lock_reason="Exceeded maximum failed login OTP attempts.",
        verification_purpose="LOGIN_OTP",
        failed_attempt_count=1,
        max_attempts=1,
        security_reference_id="LOCK-SHOP-SOCUI-001",
        audit_correlation_id="AUD-SHOP-001",
        recovery_status="OTP_VERIFIED_AWAITING_ADMIN",
        recovery_otp_verified_at=datetime.now(timezone.utc),
        locked_at=datetime.now(timezone.utc),
    )
    college_lock = PortalSecurityLock(
        user_id=owner.id,
        application="college",
        lock_status="ACTIVE",
        lock_reason="Exceeded 3 NeuralTrace gesture verification failures.",
        verification_purpose="CONFIDENTIAL_RESOURCE",
        failed_attempt_count=3,
        max_attempts=3,
        security_reference_id="LOCK-COL-SOCUI-002",
        audit_correlation_id="AUD-COL-002",
        recovery_status="AWAITING_RECOVERY_OTP",
        locked_at=datetime.now(timezone.utc),
    )
    db_session.add_all([shop_lock, college_lock])
    db_session.commit()

    # Correlated event + portal lockout alert
    ev = SecurityEvent(
        user_id=owner.id,
        application="shopping",
        event_type="PORTAL_SECURITY_LOCKOUT",
        severity="HIGH",
        decision="LOCK_PORTAL",
        details="Lockout recorded on shopping",
        timestamp=datetime.now(timezone.utc),
    )
    db_session.add(ev)
    db_session.commit()
    db_session.refresh(ev)

    alert = Alert(
        user_id=owner.id,
        security_event_id=ev.id,
        application="shopping",
        alert_type="PORTAL_SECURITY_LOCKOUT",
        message="Shopping suspended",
        severity="HIGH",
        status="OPEN",
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(alert)
    db_session.commit()
    db_session.refresh(alert)

    # 1. Non-admin cannot access SOC portal-locks endpoints
    assert client.get("/api/admin/portal-locks", headers=owner_headers).status_code == 403
    assert client.get("/api/admin/portal-locks/LOCK-SHOP-SOCUI-001", headers=owner_headers).status_code == 403

    # 2. Enriched list returns user_name, user_email, factor label, OTP status, review status
    list_res = client.get("/api/admin/portal-locks?lock_status=ACTIVE", headers=admin_headers)
    assert list_res.status_code == 200
    items = list_res.json()
    by_ref = {i["security_reference_id"]: i for i in items}
    assert "LOCK-SHOP-SOCUI-001" in by_ref
    assert "LOCK-COL-SOCUI-002" in by_ref

    shop_item = by_ref["LOCK-SHOP-SOCUI-001"]
    assert shop_item["user_name"] == "Rhea Kapoor"
    assert shop_item["user_email"] == "soc_ui_owner@cognisec.ai"
    assert shop_item["failed_factor_label"] == "Initial Login Email OTP"
    assert shop_item["recovery_otp_status_label"] == "OTP Verified — Awaiting Admin"
    assert shop_item["admin_review_status"] == "Pending Admin Review"
    assert shop_item["failed_attempt_count"] == 1
    assert shop_item["max_attempts"] == 1

    # 3. Detail endpoint returns correlated events and owner metadata
    detail_res = client.get("/api/admin/portal-locks/LOCK-SHOP-SOCUI-001", headers=admin_headers)
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["user_name"] == "Rhea Kapoor"
    assert detail["associated_alert_id"] == alert.id
    assert any(e["event_type"] == "PORTAL_SECURITY_LOCKOUT" for e in detail["events"])

    # 4. Generic alert resolve NEVER unlocks PortalSecurityLock
    res_alert = client.post(
        f"/api/admin/alerts/{alert.id}/resolve",
        headers=admin_headers,
        json={"status": "RESOLVED", "resolution_reason": "Triaged alert"},
    )
    assert res_alert.status_code == 200
    db_session.refresh(shop_lock)
    assert shop_lock.lock_status == "ACTIVE"

    # 5. Reject recovery on College keeps lock ACTIVE and updates review status
    rej_res = client.post(
        "/api/admin/portal-locks/LOCK-COL-SOCUI-002/reject",
        headers=admin_headers,
        json={"notes": "Owner has not verified recovery OTP yet"},
    )
    assert rej_res.status_code == 200
    db_session.refresh(college_lock)
    assert college_lock.lock_status == "ACTIVE"
    assert college_lock.recovery_status == "REJECTED_BY_ADMIN"

    col_detail = client.get("/api/admin/portal-locks/LOCK-COL-SOCUI-002", headers=admin_headers).json()
    assert col_detail["admin_review_status"] == "Rejected by Admin"

    # 6. Approve recovery on Shopping lifts ONLY Shopping lock; College remains ACTIVE
    app_res = client.post(
        "/api/admin/portal-locks/LOCK-SHOP-SOCUI-001/recover",
        headers=admin_headers,
        json={"notes": "Verified identity and recovery OTP"},
    )
    assert app_res.status_code == 200
    db_session.refresh(shop_lock)
    db_session.refresh(college_lock)
    assert shop_lock.lock_status == "RECOVERED"
    assert college_lock.lock_status == "ACTIVE"

    # 7. Duplicate approval is safely rejected with 409 Conflict
    dup_res = client.post(
        "/api/admin/portal-locks/LOCK-SHOP-SOCUI-001/recover",
        headers=admin_headers,
        json={"notes": "Duplicate click"},
    )
    assert dup_res.status_code == 409

