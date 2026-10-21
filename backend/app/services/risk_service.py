import numpy as np
from typing import Dict, Any, List, Tuple
from sqlalchemy.orm import Session
from app.core.config import settings
from app.services.profile_service import ProfileService
from app.ml.model_manager import ModelManager


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
        - Contextual security signals (device, location, time, rate, action)

        Returns: (risk_score, anomaly_score, risk_level, contributing_factors, is_anomaly, ml_status)
        """
        contributing_factors: List[str] = []
        profile = ProfileService.get_or_create_profile(db, user_id)
        baseline_stats = ProfileService.get_profile_dict(profile)
        sample_count = profile.sample_count

        # 1. Behavioral Anomaly Detection (Welford Statistical Baseline + Isolation Forest)
        detector = ModelManager.ensure_hydrated(db, user_id, baseline_stats)
        is_anomaly, anomaly_score, ml_status = detector.predict_anomaly(
            sample_vector=behavior_vector,
            baseline_stats=baseline_stats,
            sample_count=sample_count
        )

        if is_anomaly or anomaly_score >= 0.50:
            contributing_factors.append(
                f"Behavioral intelligence detected anomalous interaction pattern (Deviation: {anomaly_score:.3f} | {ml_status})"
            )

        # 2. Contextual Security Signals Evaluation (Server-Side Verified Truth)
        context_risk = 0.0

        # Verify device trust directly from server database, never blindly trust client assertion
        from app.models.session import Session as DbSession
        from app.models.device import Device

        db_session = db.query(DbSession).filter(DbSession.id == session_id).first()
        if db_session and db_session.device_id:
            device = db.query(Device).filter(Device.id == db_session.device_id).first()
            if device and (device.first_seen == device.last_seen) and context_signals.get("is_new_device", True):
                context_risk += 0.15
                contributing_factors.append("Access attempt from new hardware fingerprint (server-verified)")
            elif device and not device.is_trusted and not context_signals.get("is_device_trusted", True):
                context_risk += 0.15
                contributing_factors.append("Device is registered but not marked as trusted")
        elif context_signals.get("is_new_device", False):
            context_risk += 0.15
            contributing_factors.append("Access attempt from unrecognized device fingerprint")

        # Location / Impossible Travel Context
        if context_signals.get("impossible_travel", False):
            context_risk += 0.40
            contributing_factors.append("Impossible travel velocity detected between recent IP geolocation points")

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

        # 3. Multi-Factor Risk Synthesis Governed by Baseline Maturity
        # Cold start users must not be penalized for lack of history.
        # Learning users gradually increase behavioral weight.
        # Established baseline users utilize full behavioral intelligence.
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

        # 4. Zero Trust Risk Level Categorization
        if risk_score < settings.RISK_THRESHOLD_LOW:
            risk_level = "LOW"
        elif risk_score < settings.RISK_THRESHOLD_MEDIUM:
            risk_level = "MEDIUM"
        elif risk_score < settings.RISK_THRESHOLD_HIGH:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"

        return risk_score, round(anomaly_score, 4), risk_level, contributing_factors, is_anomaly, ml_status
