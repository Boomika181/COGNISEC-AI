import json
import logging
from datetime import datetime, timezone
from typing import List, Optional, Union
from fastapi import APIRouter, Depends, HTTPException, status

logger = logging.getLogger(__name__)
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.schemas.behavior import (
    BehaviorEventCreate,
    BehaviorLogResponse,
    BehaviorProfileResponse,
    UserBehaviorSummaryResponse,
)
from app.schemas.security import (
    SecurityDecisionResponse,
    AdminSecurityDecisionResponse,
    UserBehaviorEventResponse,
)

from app.services.behavior_service import BehaviorService
from app.services.profile_service import ProfileService
from app.services.risk_service import RiskService
from app.services.decision_service import DecisionService
from app.services.session_service import SessionService
from app.services.anti_replay_service import AntiReplayService
from app.core.rate_limit import rate_limiter
from app.ml.feature_engineering import FeatureEngineering
from app.ml.model_manager import ModelManager
from app.routes.deps import get_current_user
from app.models.user import User
from app.models.behavior import BehaviorLog, BehavioralTrainingEvent, BehaviorProfile
from app.models.security_event import SecurityEvent
from app.models.session import Session as DbSession

router = APIRouter(prefix="/behavior", tags=["Behavioral Telemetry"])


@router.post("/events", response_model=Union[AdminSecurityDecisionResponse, UserBehaviorEventResponse])
def submit_behavior_event(
    event_data: BehaviorEventCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Ingests passive behavioral telemetry (typing dynamics, mouse velocity, clicks, scrolls, idle time).
    Never stores passwords or raw keystroke contents.
    Enforces session ownership, validates application context, anti-replay/anti-tamper integrity,
    and separates user vs admin responses.
    """
    # 0. Enforce telemetry stream rate limiting (120 events / min per session)
    rate_limiter.enforce(
        key=f"telemetry:{event_data.session_id}",
        max_requests=120,
        window_seconds=60,
        detail="Telemetry rate limit exceeded. Excess telemetry frequency suppressed."
    )

    # 1. Verify session exists
    session = SessionService.get_session(db, event_data.session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found."
        )

    if session.status == "TERMINATED":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Active session required for behavior ingestion."
        )

    # 2. Enforce Session Ownership (BOLA Prevention)
    if session.user_id != current_user.id and current_user.role.upper() != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized: Cannot submit telemetry for another user's session."
        )

    # 3. Enforce Application Context Matching
    req_norm_app = SessionService.normalize_application(event_data.application) or event_data.application.lower()
    sess_norm_app = SessionService.normalize_application(session.application) or session.application.lower()
    if req_norm_app != sess_norm_app:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Application mismatch: session registered for '{session.application}', received '{event_data.application}'."
        )

    # 4. Anti-Replay & Anti-Tamper Telemetry Validation
    AntiReplayService.validate_telemetry_integrity(session.id, event_data)

    # 5. Extract and strictly validate feature vector
    vector = FeatureEngineering.extract_vector(event_data)
    is_valid, validation_err = FeatureEngineering.validate_vector(vector)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Malformed behavioral telemetry features: {validation_err}"
        )

    prior_session_status = session.status
    prior_risk_level = (session.current_risk_level or "LOW").upper()

    # 6. Record behavior log under authenticated user
    log = BehaviorService.record_behavior_event(db, current_user.id, event_data)
    context_signals = event_data.context_signals or {}

    # 7. Calculate dynamic risk & Behavioral ML anomaly deviation score
    risk_score, anomaly_score, risk_level, factors, is_anomaly, ml_status = RiskService.calculate_risk(
        db,
        user_id=current_user.id,
        session_id=event_data.session_id,
        application=event_data.application,
        behavior_vector=vector,
        context_signals=context_signals,
        observed_modalities=getattr(event_data, "observed_modalities", None),
        sample_counts=getattr(event_data, "sample_counts", None)
    )

    # 8. Enforce Zero Trust policy decision
    # If session is in PENDING_OBSERVATION or PENDING_OTP, telemetry must not activate session or create step-up challenges
    # (except for CRITICAL risk, which must immediately trigger kill-switch termination)
    is_step_up_fresh = SessionService.is_step_up_fresh(session, current_risk_score=risk_score, current_risk_level=risk_level)
    if risk_level == "CRITICAL":
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
    elif prior_session_status in ["PENDING_OBSERVATION", "PENDING_OTP"]:
        session_status = prior_session_status
        session.current_risk_level = risk_level
        db.commit()
        decision = "OBSERVATION_PENDING" if prior_session_status == "PENDING_OBSERVATION" else "STEP_UP_VERIFICATION"
        user_msg = (
            "Behavioral baseline observation active. Protected access locked until OTP verification."
            if prior_session_status == "PENDING_OBSERVATION"
            else "Mandatory login OTP verification required to activate session."
        )
        event_id = None
    elif prior_session_status == "STEP_UP_REQUIRED" and not is_step_up_fresh:
        decision = "STEP_UP_VERIFICATION"
        user_msg = "Session requires step-up verification."
        session_status = "STEP_UP_REQUIRED"
        event_id = None
    elif prior_session_status == "RESTRICTED" and risk_level in ["HIGH", "CRITICAL"]:
        decision = "RESTRICT" if risk_level == "HIGH" else "TERMINATE_SESSION"
        user_msg = "Access temporarily restricted. Sensitive operations are locked." if risk_level == "HIGH" else "Session terminated due to critical security risk."
        session_status = "RESTRICTED" if risk_level == "HIGH" else "TERMINATED"
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

    logger.info(
        f"[Telemetry] Session {event_data.session_id} evaluated risk {risk_level} (score={risk_score:.2f}). "
        f"Decision: {decision}, SessionStatus: {session_status}."
    )

    # 8b. Event-Driven Non-Blocking Agentic Security Orchestration
    # Deterministic RiskService, DecisionService, and CRITICAL termination have already executed synchronously.
    # Agent orchestration runs asynchronously in the background so LLM/agent latency never delays authentication.
    meaningful_risk_change = (prior_risk_level is not None and risk_level != prior_risk_level)
    should_orchestrate = (
        risk_level in ("HIGH", "CRITICAL")
        or meaningful_risk_change
        or (bool(is_anomaly) and risk_level != "LOW")
    )
    if should_orchestrate:
        try:
            from app.agents.execution.orchestrator import SecurityOrchestrator
            orch_idem_key = f"behavior:{event_data.session_id}:{event_id or f'{risk_level}:{int(bool(is_anomaly))}'}"
            SecurityOrchestrator.dispatch_background(
                db_bind=db.get_bind(),
                event_id=event_id,
                user_id=current_user.id,
                session_id=event_data.session_id,
                application=event_data.application,
                telemetry_features=vector.tolist(),
                raw_anomaly_score=float(anomaly_score),
                deterministic_risk_score=float(risk_score),
                deterministic_risk_level=risk_level,
                contributing_reasons=list(factors or []),
                auto_containment=False,
                skip_containment=True,
                idempotency_key=orch_idem_key,
                trigger_event="BEHAVIOR_CRITICAL_RISK" if risk_level == "CRITICAL" else "BEHAVIOR_RISK_TRANSITION",
            )
        except Exception as orch_err:
            logger.warning(f"Behavior SecurityOrchestrator dispatch failed softly; deterministic decision preserved: {orch_err}")

    # 9. Baseline Profile & ML Model Protection:
    # Evaluate canonical training eligibility so only genuinely observed, active,
    # verified low-risk observations update the baseline and Isolation Forest training buffer.
    behavior_event_id = BehaviorService.derive_event_id(event_data, fallback_log_id=log.id) or f"behavior_log:{log.id}"
    candidate_trusted = bool(
        prior_session_status == "ACTIVE"
        and session_status == "ACTIVE"
        and decision == "ALLOW"
        and risk_score < 0.30
        and not is_anomaly
        and anomaly_score < 0.50
    )

    is_eligible, rejection_reason, resolved_features = FeatureEngineering.evaluate_training_eligibility(
        event_vector=vector,
        user_id=current_user.id,
        event_user_id=log.user_id,
        is_trusted=candidate_trusted,
        session_status=session_status,
        prior_session_status=prior_session_status,
        decision=decision,
        risk_score=risk_score,
        is_anomaly=is_anomaly,
        anomaly_score=anomaly_score,
        anti_replay_verified=True,
        observed_modalities=getattr(event_data, "observed_modalities", None),
        context_signals=context_signals,
        sample_counts=getattr(event_data, "sample_counts", None),
        event_id=behavior_event_id
    )

    persisted_payload = dict(context_signals)
    persisted_payload["event_id"] = behavior_event_id
    persisted_payload["anti_replay_verified"] = True
    persisted_payload["risk_score"] = risk_score
    persisted_payload["anomaly_score"] = anomaly_score
    persisted_payload["is_anomaly"] = bool(is_anomaly)
    persisted_payload["decision"] = decision
    persisted_payload["session_status"] = session_status
    persisted_payload["prior_session_status"] = prior_session_status
    if getattr(event_data, "observed_modalities", None) is not None:
        persisted_payload["observed_modalities"] = event_data.observed_modalities
    if getattr(event_data, "sample_counts", None) is not None:
        persisted_payload["sample_counts"] = event_data.sample_counts
    if getattr(event_data, "telemetry_nonce", None):
        persisted_payload["telemetry_nonce"] = event_data.telemetry_nonce

    if is_eligible and resolved_features is not None:
        prior_profile = db.query(BehaviorProfile).filter(BehaviorProfile.user_id == current_user.id).first()
        prior_maturity = ProfileService.get_maturity_info(prior_profile.sample_count)[0] if prior_profile else "COLD_START"
        # ProfileService.update_baseline_from_event atomically commits BehaviorProfile,
        # BehavioralTrainingEvent (PENDING -> ELIGIBLE -> PROCESSED), and BehaviorLog
        # in the same database transaction, and sets ml_registered=True only after
        # worker-local ModelManager registration succeeds.
        updated_profile = ProfileService.update_baseline_from_event(
            db,
            user_id=current_user.id,
            event_vector=vector,
            risk_score=risk_score,
            session_status=session_status,
            decision=decision,
            observed_modalities=getattr(event_data, "observed_modalities", None),
            context_signals=context_signals,
            sample_counts=getattr(event_data, "sample_counts", None),
            event_id=behavior_event_id,
            is_anomaly=bool(is_anomaly),
            anomaly_score=float(anomaly_score),
            behavior_log=log,
            persisted_context=persisted_payload
        )
        new_maturity = ProfileService.get_maturity_info(updated_profile.sample_count)[0] if updated_profile else prior_maturity
        if new_maturity != prior_maturity:
            db.add(SecurityEvent(
                user_id=current_user.id,
                session_id=event_data.session_id,
                application=event_data.application,
                event_type="BASELINE_UPDATED",
                severity="LOW",
                anomaly_score=float(anomaly_score),
                risk_score=float(risk_score),
                decision=decision,
                details=json.dumps({
                    "prior_maturity": prior_maturity,
                    "new_maturity": new_maturity,
                    "sample_count": int(updated_profile.sample_count) if updated_profile else 0,
                }),
            ))
            db.commit()
    else:
        BehaviorService.mark_event_rejected(
            db=db,
            log=log,
            event_id=behavior_event_id,
            persisted_payload=persisted_payload,
            rejection_reason=rejection_reason
        )

    # Record meaningful risk-level transitions (only when DecisionService did not already emit an event for this transition)
    # or first behavioural telemetry in session (without spamming every poll)
    if meaningful_risk_change and event_id is None:
        db.add(SecurityEvent(
            user_id=current_user.id,
            session_id=event_data.session_id,
            application=event_data.application,
            event_type="RISK_LEVEL_TRANSITION",
            severity=risk_level,
            anomaly_score=float(anomaly_score),
            risk_score=float(risk_score),
            decision=decision,
            details=json.dumps({
                "prior_risk_level": prior_risk_level,
                "new_risk_level": risk_level,
                "new_risk_score": round(float(risk_score), 4),
                "contributing_factors": list(factors or []),
            }),
        ))
        db.commit()
    else:
        prior_telem_ev = (
            db.query(SecurityEvent.id)
            .filter(
                SecurityEvent.session_id == event_data.session_id,
                SecurityEvent.event_type == "BEHAVIORAL_TELEMETRY_RECEIVED",
            )
            .first()
        )
        if not prior_telem_ev:
            db.add(SecurityEvent(
                user_id=current_user.id,
                session_id=event_data.session_id,
                application=event_data.application,
                event_type="BEHAVIORAL_TELEMETRY_RECEIVED",
                severity=risk_level,
                anomaly_score=float(anomaly_score),
                risk_score=float(risk_score),
                decision=decision,
                details=json.dumps({
                    "portal": event_data.application,
                    "ml_status": ml_status,
                    "is_anomaly": bool(is_anomaly),
                }),
            ))
            db.commit()

    now_utc = datetime.now(timezone.utc)
    is_step_up = (session_status == "STEP_UP_REQUIRED" or decision == "STEP_UP_VERIFICATION")
    obs_completed = None
    obs_rem = None
    if session_status in ("PENDING_OBSERVATION", "PENDING_OTP"):
        obs_info = SessionService.get_observation_status(db, event_data.session_id)
        if obs_info:
            obs_completed = bool(obs_info.get("is_completed", False))
            obs_rem = int(obs_info.get("observation_seconds_remaining", 0))

    # 9. Response Separation: Ordinary users receive ONLY outcome; ADMIN receives SOC telemetry intelligence
    if current_user.role.upper() == "ADMIN":
        return AdminSecurityDecisionResponse(
            decision=decision,
            user_message=user_msg,
            session_status=session_status,
            verification_required=is_step_up,
            observation_completed=obs_completed,
            observation_seconds_remaining=obs_rem,
            risk_level=risk_level,
            risk_score=risk_score,
            anomaly_score=anomaly_score,
            is_anomaly=is_anomaly,
            ml_status=ml_status,
            contributing_factors=factors,
            event_id=event_id,
            timestamp=now_utc
        )

    return UserBehaviorEventResponse(
        decision=decision,
        user_message=user_msg,
        session_status=session_status,
        verification_required=is_step_up,
        observation_completed=obs_completed,
        observation_seconds_remaining=obs_rem,
        timestamp=now_utc
    )



@router.get("/user-summary", response_model=UserBehaviorSummaryResponse)
def get_user_behavior_summary(
    session_id: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    User-facing security & behavioral-setup summary.
    Exposes ONLY plain-language session/verification status and calibration readiness,
    keeping risk scores, anomaly scores, Welford baselines, and 10-D telemetry SOC-only.
    """
    profile = ProfileService.get_or_create_profile(db, current_user.id)
    samples = int(profile.sample_count or 0)
    req_samples = int(ProfileService.MIN_MATURE_SAMPLES)
    if samples == 0:
        enrollment_status = "NOT_ENROLLED"
    elif samples < req_samples:
        enrollment_status = "ENROLLMENT_IN_PROGRESS"
    else:
        enrollment_status = "ENROLLED"

    sess = None
    if session_id:
        sess = (
            db.query(DbSession)
            .filter(DbSession.id == session_id, DbSession.user_id == current_user.id)
            .first()
        )
    if not sess:
        sess = (
            db.query(DbSession)
            .filter(DbSession.user_id == current_user.id, ~DbSession.id.like("sim_%"), ~DbSession.id.like("test_%"))
            .order_by(DbSession.login_time.desc())
            .first()
        )

    s_status = sess.status if sess else "ACTIVE"
    verif_req = s_status in ("STEP_UP_REQUIRED", "RESTRICTED")
    if s_status in ("TERMINATED", "EXPIRED"):
        label = "Session expired"
        msg = "Please log in again."
    elif verif_req:
        label = "Verification required"
        msg = "Complete an additional security check."
    elif s_status in ("PENDING_OBSERVATION", "PENDING_OTP"):
        label = "Verification pending"
        msg = "Initial session verification is in progress."
    elif sess and getattr(sess, "step_up_verified_at", None):
        label = "Verification completed"
        msg = "Your identity has been verified. Your session is being monitored."
    else:
        label = "Protected"
        msg = "Your session is being monitored."

    return UserBehaviorSummaryResponse(
        session_status=s_status,
        verification_required=verif_req,
        security_status_label=label,
        security_status_message=msg,
        is_profile_ready=(samples >= req_samples),
        enrollment_status=enrollment_status,
        calibration_samples_collected=min(samples, req_samples),
        calibration_samples_required=req_samples,
        last_checked_at=profile.last_updated,
    )


@router.get("/profile", response_model=BehaviorProfileResponse)
def get_user_profile(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieves the user's current behavioral baseline statistics and Isolation Forest ML status."""
    profile = ProfileService.get_or_create_profile(db, current_user.id)
    features_dict = ProfileService.get_profile_dict(profile)
    mod_counts = features_dict.get("modality_sample_counts")
    status_label, confidence, is_mature = ProfileService.get_maturity_info(
        sample_count=profile.sample_count,
        modality_counts=mod_counts
    )
    ml_status, model_samples, is_anomaly, anomaly_score = ModelManager.get_ml_status(
        user_id=current_user.id,
        sample_count=profile.sample_count,
        baseline_stats=features_dict,
        db=db
    )

    total_observations = db.query(BehaviorLog).filter(BehaviorLog.user_id == current_user.id).count()
    latest_log = (
        db.query(BehaviorLog)
        .filter(BehaviorLog.user_id == current_user.id)
        .order_by(BehaviorLog.timestamp.desc())
        .first()
    )
    last_obs_ts = latest_log.timestamp if latest_log else None

    # Determine enrollment status strictly based on real verified samples
    if profile.sample_count == 0:
        enrollment_status = "NOT_ENROLLED"
    elif profile.sample_count < ProfileService.MIN_MATURE_SAMPLES:
        enrollment_status = "ENROLLMENT_IN_PROGRESS"
    else:
        enrollment_status = "ENROLLED"

    latest_decision = None
    latest_risk_score = None
    latest_risk_level = None

    if latest_log and latest_log.raw_feature_json:
        try:
            extra = json.loads(latest_log.raw_feature_json)
            if "decision" in extra:
                latest_decision = extra["decision"]
            if "risk_score" in extra:
                latest_risk_score = float(extra["risk_score"])
        except Exception:
            pass

    if latest_risk_score is not None:
        latest_session = (
            db.query(DbSession)
            .filter(DbSession.user_id == current_user.id, ~DbSession.id.like("sim_%"))
            .order_by(DbSession.login_time.desc())
            .first()
        )
        if latest_session and latest_session.current_risk_level:
            latest_risk_level = latest_session.current_risk_level
        else:
            latest_risk_level = "LOW" if latest_risk_score < 0.35 else "MEDIUM" if latest_risk_score < 0.70 else "HIGH"

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
        anomaly_score=anomaly_score,
        total_observations=total_observations,
        last_observation_timestamp=last_obs_ts,
        enrollment_status=enrollment_status,
        latest_decision=latest_decision,
        latest_risk_score=latest_risk_score,
        latest_risk_level=latest_risk_level
    )


@router.get("/logs", response_model=List[BehaviorLogResponse])
def get_recent_behavior_logs(
    limit: int = 20,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieves recent behavior logs for the authenticated user."""
    return BehaviorService.get_user_logs(db, current_user.id, limit=limit)

