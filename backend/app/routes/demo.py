import json
import uuid
from datetime import datetime, timezone
import numpy as np
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database.connection import get_db, get_simulator_db
from app.schemas.admin import AttackSimulationRequest, AttackSimulationResponse
from app.models.user import User
from app.models.session import Session as DbSession
from app.models.security_event import SecurityEvent
from app.models.alert import Alert
from app.services.session_service import SessionService
from app.services.risk_service import RiskService
from app.services.decision_service import DecisionService
from app.routes.deps import require_admin

router = APIRouter(prefix="/demo", tags=["Demo Attack Simulator"])


@router.post("/simulate", response_model=AttackSimulationResponse)
def simulate_attack_scenario(
    request: AttackSimulationRequest,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_simulator_db)
):

    """
    Executes controlled exhibition attack scenarios in an isolated simulation sandbox:
    - NEW_DEVICE
    - ABNORMAL_TYPING
    - ABNORMAL_MOUSE
    - IMPOSSIBLE_TRAVEL
    - CREDENTIAL_MISUSE
    - REQUEST_FLOOD
    - SESSION_HIJACKING
    Ensures zero contamination of genuine development SOC inventory, baselines, or metrics.
    """
    target_user_id = request.target_user_id or current_user.id
    target_user = db.query(User).filter(User.id == target_user_id).first()
    if not target_user:
        target_user = User(
            id=target_user_id,
            name=current_user.name or "Simulation Operator",
            email=current_user.email or "sim.operator@cognisec.ai",
            password_hash=getattr(current_user, "password_hash", "sim_hash"),
            role="ADMIN",
            account_status="ACTIVE"
        )
        db.add(target_user)
        try:
            db.commit()
            db.refresh(target_user)
        except Exception:
            db.rollback()
            target_user = db.query(User).filter(User.id == target_user_id).first()

    app_name = (request.application or "ecommerce").lower()
    sim_session_id = f"sim_{uuid.uuid4().hex[:12]}"
    
    # Create temporary simulated session
    sim_session = DbSession(
        id=sim_session_id,
        user_id=target_user_id,
        application=app_name,
        ip_address="198.51.100.42",
        login_time=datetime.now(timezone.utc),
        status="ACTIVE",
        current_risk_level="LOW"
    )
    db.add(sim_session)
    db.commit()

    scenario_upper = request.scenario.upper()

    # Configure scenario vectors and context signals
    if scenario_upper == "NEW_DEVICE":
        vector = np.array([65.0, 120.0, 85.0, 650.0, 420.0, 0.45, 1.2, 350.0, 2.5, 0.35])
        context = {"is_new_device": True, "is_device_trusted": False}
        expected_event = "UNRECOGNIZED_DEVICE_ACCESS"
        desc = "Simulated login from unknown hardware fingerprint."

    elif scenario_upper == "ABNORMAL_TYPING":
        vector = np.array([195.0, 12.0, 15.0, 680.0, 410.0, 0.45, 1.3, 350.0, 0.5, 0.35])
        context = {"is_new_device": False, "rapid_click_burst": True}
        expected_event = "KEYSTROKE_DYNAMICS_ANOMALY"
        desc = "Simulated abnormal keystroke flight rhythm (12ms vs 120ms baseline)."

    elif scenario_upper == "ABNORMAL_MOUSE":
        vector = np.array([60.0, 125.0, 90.0, 2800.0, 3500.0, 0.01, 8.5, 1500.0, 0.1, 0.05])
        context = {"is_new_device": False, "request_flood": True}
        expected_event = "ERRATIC_BOT_CURSOR_TRAJECTORY"
        desc = "Simulated robotic cursor vector with near-zero angular entropy."

    elif scenario_upper == "IMPOSSIBLE_TRAVEL":
        vector = np.array([68.0, 118.0, 88.0, 680.0, 410.0, 0.46, 1.3, 380.0, 2.0, 0.38])
        context = {"is_new_device": True, "impossible_travel": True}
        expected_event = "IMPOSSIBLE_GEO_VELOCITY"
        desc = "Simulated instantaneous IP geolocation jump from Bengaluru to London."

    elif scenario_upper == "CREDENTIAL_MISUSE":
        vector = np.array([55.0, 140.0, 95.0, 500.0, 300.0, 0.40, 1.0, 200.0, 3.5, 0.30])
        context = {"failed_attempts_count": 5, "is_sensitive_action": True}
        expected_event = "BRUTE_FORCE_CREDENTIAL_SPRAY"
        desc = "Simulated 5 consecutive failed authentications followed by sensitive data request."

    elif scenario_upper == "REQUEST_FLOOD":
        vector = np.array([120.0, 40.0, 30.0, 1500.0, 1200.0, 0.20, 15.0, 800.0, 0.05, 0.10])
        context = {"request_flood": True, "rapid_click_burst": True}
        expected_event = "HIGH_FREQUENCY_API_BURST"
        desc = "Simulated automated high-frequency scrap/burst attack."

    else:  # SESSION_HIJACKING / DEFAULT KILL SWITCH
        vector = np.array([220.0, 8.0, 10.0, 3200.0, 4500.0, 0.00, 20.0, 2500.0, 0.0, 0.0])
        context = {"is_new_device": True, "impossible_travel": True, "request_flood": True}
        expected_event = "SESSION_HIJACK_ATTEMPT"
        desc = "Simulated token theft & concurrent active session hijacking."

    # Execute Risk Calculation
    risk_score, anomaly_score, risk_level, factors, is_anomaly, ml_status = RiskService.calculate_risk(
        db,
        user_id=target_user_id,
        session_id=sim_session_id,
        application=app_name,
        behavior_vector=vector,
        context_signals=context
    )

    # In attack simulations, ensure elevated risk profile
    if scenario_upper in ["SESSION_HIJACKING", "IMPOSSIBLE_TRAVEL"]:
        risk_score = max(0.92, risk_score)
        risk_level = "CRITICAL"
    elif scenario_upper in ["ABNORMAL_TYPING", "ABNORMAL_MOUSE", "REQUEST_FLOOD"]:
        risk_score = max(0.78, risk_score)
        risk_level = "HIGH"
    elif scenario_upper in ["NEW_DEVICE", "CREDENTIAL_MISUSE"]:
        risk_score = max(0.55, risk_score)
        risk_level = "MEDIUM"

    # Enforce policy decision
    decision, user_msg, session_status, event_id = DecisionService.enforce_zero_trust_decision(
        db,
        user_id=target_user_id,
        session_id=sim_session_id,
        application=app_name,
        risk_score=risk_score,
        anomaly_score=anomaly_score,
        risk_level=risk_level,
        contributing_factors=factors or [desc]
    )

    # Immediately terminate the temporary simulation session to ensure zero contamination of live active sessions
    now_utc = datetime.now(timezone.utc)
    sim_session = db.query(DbSession).filter(DbSession.id == sim_session_id).first()
    if sim_session:
        sim_session.status = "TERMINATED"
        sim_session.logout_time = now_utc
        sim_session.login_outcome = "simulation_completed"

    # Stamp explicit simulation provenance onto the SecurityEvent
    if event_id:
        sec_event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
        if sec_event:
            try:
                det = json.loads(sec_event.details or "{}")
            except Exception:
                det = {}
            det["is_simulated"] = True
            det["provenance"] = "ATTACK_SIMULATOR"
            det["scenario"] = request.scenario
            sec_event.details = json.dumps(det)

    # Stamp explicit simulation provenance onto the Alert
    alert = db.query(Alert).filter(Alert.security_event_id == event_id).first() if event_id else None
    if alert:
        if not alert.message.startswith("[SIMULATED SCENARIO]"):
            alert.message = f"[SIMULATED SCENARIO] {alert.message}"
        alert.notes = f"Exhibition Attack Simulation: {request.scenario}"

    db.commit()

    return AttackSimulationResponse(
        scenario=request.scenario,
        application=app_name,
        target_user_id=target_user_id,
        simulated_session_id=sim_session_id,
        anomaly_score=anomaly_score,
        risk_score=risk_score,
        risk_level=risk_level,
        security_decision=decision,
        alert_created=(alert is not None),
        alert_id=alert.id if alert else None,
        message=f"Attack scenario '{request.scenario}' simulated: Decision={decision}, Risk={risk_score:.3f}, Level={risk_level}."
    )
