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

        # 1. Scikit-Learn Isolation Forest Behavioral Anomaly Detection
        detector = ModelManager.ensure_hydrated(db, user_id, baseline_stats)
        is_anomaly, anomaly_score, ml_status = detector.predict_anomaly(
            sample_vector=behavior_vector,
            baseline_stats=baseline_stats,
            sample_count=sample_count
        )

        if is_anomaly or anomaly_score >= 0.50:
            contributing_factors.append(
                f"Isolation Forest ML detected anomalous behavior pattern (Score: {anomaly_score:.3f} | {ml_status})"
            )

        # 2. Contextual Security Signals Evaluation
        context_risk = 0.0

        # Unrecognized / Untrusted Device check
        if context_signals.get("is_new_device", False):
            context_risk += 0.25
            contributing_factors.append("Access attempt from previously unseen hardware fingerprint")
        elif not context_signals.get("is_device_trusted", True):
            context_risk += 0.15
            contributing_factors.append("Device is registered but not marked as trusted")

        # Location / Impossible Travel Context
        if context_signals.get("impossible_travel", False):
            context_risk += 0.40
            contributing_factors.append("Impossible travel velocity detected between recent IP geolocation points")

        # Request Flood / Bot-like Frequency
        if context_signals.get("request_flood", False) or context_signals.get("rapid_click_burst", False):
            context_risk += 0.30
            contributing_factors.append("Automated bot-like interaction frequency detected")

        # Credential Misuse / Failed Prior Attempts
        if context_signals.get("failed_attempts_count", 0) >= 3:
            context_risk += 0.35
            contributing_factors.append(f"Multiple consecutive authentication failures ({context_signals.get('failed_attempts_count')} attempts)")

        # Application-Specific Sensitive Action
        if context_signals.get("is_sensitive_action", False):
            context_risk += 0.15
            contributing_factors.append(f"High-value / sensitive transaction in {application.upper()} portal")

        # 3. Multi-Factor Risk Synthesis
        # Weighting: 55% Behavioral Biometrics & ML Score, 45% Contextual Signals
        behavior_component = anomaly_score
        raw_combined_risk = (0.55 * behavior_component) + (0.45 * min(1.0, context_risk))
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
