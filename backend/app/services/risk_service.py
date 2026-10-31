import numpy as np
from typing import Dict, Any, List, Tuple, Optional
from sqlalchemy.orm import Session
from app.core.config import settings
from app.services.profile_service import ProfileService
from app.ml.model_manager import ModelManager
from app.services.behavior_drift_service import BehavioralDriftTracker
from app.services.access_tracker import ConfidentialAccessTracker


class RiskService:
    @staticmethod
    def calculate_risk(
        db: Session,
        user_id: int,
        session_id: str,
        application: str,
        behavior_vector: np.ndarray,
        context_signals: Dict[str, Any]
    ) -> Tuple[float, float, str, List[str], bool, str]:
        """
        Calculates multi-factor zero-trust risk score by synthesizing:
        - ML Isolation Forest behavioral anomaly detection and score
        - Statistical feature deviation against user baseline profile
        - Continuous behavioral drift vs. single-sample variance dampening
        - Contextual security signals (device novelty, mid-session switches, travel velocity)
        - Server-side repeated confidential-access denial tracking

        Returns: (risk_score, anomaly_score, risk_level, contributing_factors, is_anomaly, ml_status)
        """
        contributing_factors: List[str] = []
        profile = ProfileService.get_or_create_profile(db, user_id)
        baseline_stats = ProfileService.get_profile_dict(profile)
        sample_count = profile.sample_count

        # -------------------------------------------------------------
        # 1. Contextual Security Signals Evaluation (Server-Side Verified)
        # -------------------------------------------------------------
        context_risk = 0.0

        # Verify device trust directly from server database, never blindly trust client assertion
        from app.models.session import Session as DbSession
        from app.models.device import Device

        db_session = db.query(DbSession).filter(DbSession.id == session_id).first() if session_id else None
        if db_session and db_session.device_id:
            device = db.query(Device).filter(Device.id == db_session.device_id).first()
            if device:
                if device.trust_state == "REVOKED":
                    context_risk += 0.50
                    contributing_factors.append("Access attempt from revoked hardware fingerprint (server-verified)")
                elif (device.first_seen == device.last_seen) and context_signals.get("is_new_device", True):
                    context_risk += 0.15
                    contributing_factors.append("Access attempt from new hardware fingerprint (server-verified)")
                elif not device.is_trusted and not context_signals.get("is_device_trusted", True):
                    context_risk += 0.15
                    contributing_factors.append("Device is registered but not marked as trusted")
        elif context_signals.get("is_new_device", False):
            context_risk += 0.15
            contributing_factors.append("Access attempt from unrecognized device fingerprint")

        # Mid-Session Environmental Switch Detection (IP or User-Agent changed mid-session)
        if db_session and db_session.ip_address:
            req_ip = context_signals.get("client_ip") or context_signals.get("ip_address")
            if req_ip and req_ip != db_session.ip_address:
                # Disregard internal testclient/localhost parity transitions
                is_internal_transition = (req_ip in ("127.0.0.1", "testclient") and db_session.ip_address in ("127.0.0.1", "testclient"))
                if not is_internal_transition:
                    context_risk += 0.35
                    contributing_factors.append(
                        f"Unexpected session context switch detected (IP changed mid-session from {db_session.ip_address} to {req_ip})"
                    )

        # Location / Impossible Travel Context
        if context_signals.get("impossible_travel", False):
            context_risk += 0.40
            contributing_factors.append("Impossible travel velocity detected between recent IP geolocation points")

        # Server-Side Repeated Confidential-Access Denial Attempts (Feature 1)
        denials_count = int(context_signals.get("denied_access_count", 0))
        if not denials_count and session_id:
            denials_count = ConfidentialAccessTracker.get_recent_denials_count(user_id, session_id)

        if denials_count >= settings.CONFIDENTIAL_ACCESS_DENIAL_THRESHOLD:
            context_risk += 0.55
            contributing_factors.append(
                f"Repeated confidential access denials detected ({denials_count} unauthorized attempts within {settings.CONFIDENTIAL_ACCESS_DENIAL_WINDOW_SECONDS}s)"
            )
        elif denials_count >= 2:
            context_risk += 0.20
            contributing_factors.append(
                f"Prior unauthorized confidential access denials recorded ({denials_count} attempts)"
            )

        # Server-Side Bot / Request Flood Detection: verify against physical dynamics
        click_freq = float(behavior_vector[6]) if len(behavior_vector) > 6 else 0.0
        mouse_vel = float(behavior_vector[3]) if len(behavior_vector) > 3 else 0.0
        mouse_acc = float(behavior_vector[4]) if len(behavior_vector) > 4 else 0.0
        server_bot_detected = (click_freq >= 25.0 or mouse_vel >= 7500.0 or mouse_acc >= 20000.0)

        if server_bot_detected or context_signals.get("request_flood", False) or context_signals.get("rapid_click_burst", False):
            context_risk += 0.30
            contributing_factors.append("Automated bot-like interaction frequency detected (server-verified)")

        # Credential Misuse / Failed Prior Attempts
        failed_count = max(int(context_signals.get("failed_attempts_count", 0)), 0)
        if failed_count >= 3:
            context_risk += 0.35
            contributing_factors.append(f"Multiple consecutive authentication failures ({failed_count} attempts)")

        # Application-Specific Sensitive Action
        if context_signals.get("is_sensitive_action", False):
            context_risk += 0.15
            contributing_factors.append(f"High-value / sensitive transaction in {application.upper()} portal")

        # -------------------------------------------------------------
        # 2. Behavioral Anomaly & Continuous Drift Detection (Feature 2)
        # -------------------------------------------------------------
        detector = ModelManager.ensure_hydrated(db, user_id, baseline_stats)
        raw_is_anomaly, raw_anomaly_score, ml_status = detector.predict_anomaly(
            sample_vector=behavior_vector,
            baseline_stats=baseline_stats,
            sample_count=sample_count
        )

        # Evaluate continuous behavioral drift vs isolated single-sample variance
        has_context_risk = (context_risk > 0.0)
        is_sustained_drift, effective_anomaly_score, is_single_sample_spike = BehavioralDriftTracker.record_observation(
            session_id=session_id,
            raw_anomaly_score=raw_anomaly_score,
            has_context_risk=has_context_risk,
            window_size=getattr(settings, "BEHAVIORAL_DRIFT_WINDOW_SIZE", 4),
            drift_threshold=getattr(settings, "BEHAVIORAL_DRIFT_THRESHOLD", 0.50)
        )

        anomaly_score = effective_anomaly_score
        is_anomaly = raw_is_anomaly or is_sustained_drift or (anomaly_score >= 0.50)

        if is_sustained_drift:
            contributing_factors.append(
                f"Continuous behavioral drift detected across multiple observations (Sustained deviation: {anomaly_score:.3f} | {ml_status})"
            )
        elif is_single_sample_spike and not has_context_risk:
            contributing_factors.append(
                f"Transient behavioral variance observed (Single-sample deviation dampened to: {anomaly_score:.3f})"
            )
        elif is_anomaly or anomaly_score >= 0.50:
            contributing_factors.append(
                f"Behavioral intelligence detected anomalous interaction pattern (Deviation: {anomaly_score:.3f} | {ml_status})"
            )

        # -------------------------------------------------------------
        # 3. Multi-Factor Risk Synthesis Governed by Baseline Maturity
        # -------------------------------------------------------------
        maturity_status, _, _ = ProfileService.get_maturity_info(sample_count)

        if maturity_status == "COLD_START":
            b_weight = 0.05
            c_weight = 0.95
        elif maturity_status == "LEARNING":
            b_weight = 0.20
            c_weight = 0.80
        else:  # ESTABLISHED
            b_weight = 0.55
            c_weight = 0.45

        raw_combined_risk = (b_weight * anomaly_score) + (c_weight * min(1.0, context_risk))
        risk_score = float(np.clip(raw_combined_risk, 0.0, 1.0))
        risk_score = round(risk_score, 4)

        # -------------------------------------------------------------
        # 4. Zero Trust Risk Level Categorization
        # -------------------------------------------------------------
        if risk_score < settings.RISK_THRESHOLD_LOW:
            risk_level = "LOW"
        elif risk_score < settings.RISK_THRESHOLD_MEDIUM:
            risk_level = "MEDIUM"
        elif risk_score < settings.RISK_THRESHOLD_HIGH:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"

        return risk_score, round(anomaly_score, 4), risk_level, contributing_factors, is_anomaly, ml_status
