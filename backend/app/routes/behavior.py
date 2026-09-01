import json
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.schemas.behavior import BehaviorEventCreate, BehaviorLogResponse, BehaviorProfileResponse
from app.schemas.security import SecurityDecisionResponse
from app.services.behavior_service import BehaviorService
from app.services.profile_service import ProfileService
from app.services.risk_service import RiskService
from app.services.decision_service import DecisionService
from app.services.session_service import SessionService
from app.ml.feature_engineering import FeatureEngineering
from app.ml.model_manager import ModelManager
from app.routes.deps import get_current_user
from app.models.user import User

router = APIRouter(prefix="/behavior", tags=["Behavioral Telemetry"])


@router.post("/events", response_model=SecurityDecisionResponse)
def submit_behavior_event(
    event_data: BehaviorEventCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Ingests passive behavioral telemetry (typing dynamics, mouse velocity, clicks, scrolls, idle time).
    Never stores passwords or raw keystroke contents.
    Evaluates Isolation Forest ML anomaly score, computes multi-factor risk, enforces zero-trust policy decision,
    and adaptively updates the user baseline profile ONLY for legitimate/allowed sessions.
    """
    # Verify active session
    session = SessionService.get_session(db, event_data.session_id)
    if not session or session.status == "TERMINATED":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Active session required for behavior ingestion."
        )

    prior_session_status = session.status

    # 1. Record behavior log
    log = BehaviorService.record_behavior_event(db, current_user.id, event_data)

    # 2. Extract feature vector
    vector = FeatureEngineering.extract_vector(event_data)
    context_signals = event_data.context_signals or {}

    # 3. Calculate dynamic risk & Isolation Forest ML anomaly score
    risk_score, anomaly_score, risk_level, factors, is_anomaly, ml_status = RiskService.calculate_risk(
        db,
        user_id=current_user.id,
        session_id=event_data.session_id,
        application=event_data.application,
        behavior_vector=vector,
        context_signals=context_signals
    )

    # 4. Enforce Zero Trust policy decision
    # If session was already RESTRICTED or STEP_UP_REQUIRED, preserve restriction unless formally verified
    if prior_session_status in ["RESTRICTED", "STEP_UP_REQUIRED"]:
        decision = "RESTRICT" if prior_session_status == "RESTRICTED" else "STEP_UP_VERIFICATION"
        user_msg = "Session is currently restricted or requires step-up verification."
        session_status = prior_session_status
        event_id = None
    else:
        decision, user_msg, session_status, event_id = DecisionService.enforce_zero_trust_decision(
            db,
            user_id=current_user.id,
            session_id=event_data.session_id,
            application=event_data.application,
            risk_score=risk_score,
            anomaly_score=anomaly_score,
            risk_level=risk_level,
            contributing_factors=factors
        )

    # 5. Baseline Profile & ML Model Protection:
    # Only update baseline if prior session was ACTIVE, new status is ACTIVE, decision is ALLOW, and risk_score < 0.30
    if prior_session_status == "ACTIVE" and session_status == "ACTIVE" and decision == "ALLOW" and risk_score < 0.30:
        ProfileService.update_baseline_from_event(
            db,
            user_id=current_user.id,
            event_vector=vector,
            risk_score=risk_score,
            session_status=session_status,
            decision=decision
        )

    return SecurityDecisionResponse(
        decision=decision,
        user_message=user_msg,
        session_status=session_status,
        risk_level=risk_level,
        risk_score=risk_score,
        anomaly_score=anomaly_score,
        is_anomaly=is_anomaly,
        ml_status=ml_status,
        contributing_factors=factors,
        event_id=event_id,
        timestamp=datetime.now(timezone.utc)
    )


@router.get("/profile", response_model=BehaviorProfileResponse)
def get_user_profile(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieves the user's current behavioral baseline statistics and Isolation Forest ML status."""
    profile = ProfileService.get_or_create_profile(db, current_user.id)
    features_dict = ProfileService.get_profile_dict(profile)
    status_label, confidence, is_mature = ProfileService.get_maturity_info(profile.sample_count)
    ml_status, model_samples, is_anomaly, anomaly_score = ModelManager.get_ml_status(
        user_id=current_user.id,
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


@router.get("/logs", response_model=List[BehaviorLogResponse])
def get_recent_behavior_logs(
    limit: int = 20,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieves recent behavior logs for the authenticated user."""
    return BehaviorService.get_user_logs(db, current_user.id, limit=limit)
