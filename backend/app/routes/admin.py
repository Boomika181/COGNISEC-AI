from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.routes.deps import require_admin
from app.models.user import User
from app.models.device import Device
from app.models.session import Session as DbSession
from app.models.security_event import SecurityEvent
from app.models.alert import Alert
from app.schemas.admin import (
    AdminMetricsResponse,
    AlertResponse,
    AlertResolveRequest,
    SecurityEventResponse
)
from app.schemas.device import DeviceResponse
from app.schemas.session import SessionResponse
from app.schemas.user import UserResponse
from app.schemas.behavior import BehaviorProfileResponse
from app.services.device_service import DeviceService
from app.services.session_service import SessionService
from app.services.profile_service import ProfileService
from app.ml.model_manager import ModelManager

router = APIRouter(prefix="/admin", tags=["Admin & SOC Command Center"], dependencies=[Depends(require_admin)])


@router.get("/metrics", response_model=AdminMetricsResponse)
def get_soc_metrics(db: Session = Depends(get_db)):
    """Provides high-level real-time KPI metrics for the SOC Dashboard."""
    live_sessions = db.query(DbSession).filter(DbSession.status == "ACTIVE").count()
    trusted_users = db.query(User).filter(User.account_status == "ACTIVE").count()
    blocked_sessions = db.query(DbSession).filter(DbSession.status.in_(["TERMINATED", "RESTRICTED"])).count()
    total_devices = db.query(Device).count()
    active_alerts = db.query(Alert).filter(Alert.status == "OPEN").count()
    
    total_events = db.query(SecurityEvent).count()
    anomalous_events = db.query(SecurityEvent).filter(SecurityEvent.anomaly_score > 0.5).count()
    anomaly_rate = round((anomalous_events / max(1, total_events)) * 100, 2)

    return AdminMetricsResponse(
        live_sessions_count=live_sessions,
        trusted_users_count=trusted_users,
        blocked_sessions_count=blocked_sessions,
        total_devices_count=total_devices,
        active_alerts_count=active_alerts,
        anomaly_rate_percent=anomaly_rate
    )


@router.get("/sessions", response_model=List[SessionResponse])
def get_admin_sessions(
    application: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db)
):
    """Retrieves all sessions across applications with optional filters."""
    return SessionService.get_all_sessions(db, application=application, status=status, limit=limit)


@router.get("/events", response_model=List[SecurityEventResponse])
def get_security_events(
    application: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db)
):
    """Fetches security event audit log feed for the SOC Dashboard."""
    query = db.query(SecurityEvent)
    if application:
        query = query.filter(SecurityEvent.application == application.lower())
    if severity:
        query = query.filter(SecurityEvent.severity == severity.upper())
    
    events = query.order_by(SecurityEvent.timestamp.desc()).limit(limit).all()

    # Enrich with user details
    results = []
    for ev in events:
        user = db.query(User).filter(User.id == ev.user_id).first()
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
            timestamp=ev.timestamp
        ))
    return results


@router.get("/alerts", response_model=List[AlertResponse])
def get_alerts(
    status: Optional[str] = None,
    application: Optional[str] = None,
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db)
):
    """Fetches security alerts for the SOC Notification & Alert panel."""
    query = db.query(Alert)
    if status:
        query = query.filter(Alert.status == status.upper())
    if application:
        query = query.filter(Alert.application == application.lower())

    alerts = query.order_by(Alert.created_at.desc()).limit(limit).all()

    results = []
    for al in alerts:
        user = db.query(User).filter(User.id == al.user_id).first()
        results.append(AlertResponse(
            id=al.id,
            user_id=al.user_id,
            user_name=user.name if user else "Unknown",
            user_email=user.email if user else "unknown@cognisec.ai",
            security_event_id=al.security_event_id,
            application=al.application,
            alert_type=al.alert_type,
            message=al.message,
            severity=al.severity,
            status=al.status,
            created_at=al.created_at
        ))
    return results


@router.post("/alerts/{alert_id}/resolve", response_model=AlertResponse)
def resolve_alert(
    alert_id: int,
    request: AlertResolveRequest,
    db: Session = Depends(get_db)
):
    """Acknowledges or resolves an open security alert."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")
    
    alert.status = request.status.upper()
    db.commit()
    db.refresh(alert)

    user = db.query(User).filter(User.id == alert.user_id).first()
    return AlertResponse(
        id=alert.id,
        user_id=alert.user_id,
        user_name=user.name if user else "Unknown",
        user_email=user.email if user else "unknown@cognisec.ai",
        security_event_id=alert.security_event_id,
        application=alert.application,
        alert_type=alert.alert_type,
        message=alert.message,
        severity=alert.severity,
        status=alert.status,
        created_at=alert.created_at
    )


@router.get("/devices", response_model=List[DeviceResponse])
def get_all_devices(db: Session = Depends(get_db)):
    """Returns hardware inventory and TPM/fingerprint trust state."""
    return DeviceService.get_all_devices(db)


@router.post("/devices/{device_id}/trust", response_model=DeviceResponse)
def update_device_trust(
    device_id: int,
    is_trusted: bool = Query(True),
    db: Session = Depends(get_db)
):
    """Marks a hardware device as trusted or untrusted."""
    device = DeviceService.set_device_trust(db, device_id, is_trusted)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found.")
    return device


@router.get("/users", response_model=List[UserResponse])
def get_all_users(limit: int = Query(50, le=200), db: Session = Depends(get_db)):
    """Returns all registered users in the platform."""
    return db.query(User).order_by(User.created_at.desc()).limit(limit).all()


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
