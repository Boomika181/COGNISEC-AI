import json
from datetime import datetime, timezone
import numpy as np
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session
from app.ml.anomaly_detector import IsolationForestDetector
from app.ml.feature_engineering import FeatureEngineering
from app.models.behavior import BehaviorLog
from app.core.config import settings


class ModelManager:
    """
    In-memory Model Registry & Lifecycle Manager for Per-User Isolation Forests.
    Supports on-demand database hydration from PostgreSQL upon server restart,
    rebuilding trusted training datasets from historical behavior logs regardless of
    whether their original sessions have expired or been logged out.
    Enforces strict anti-poisoning and a configurable retraining interval.
    """
    MAX_HYDRATION_RECORDS: int = 100  # Bounded to most recent 100 trusted historical samples
    _instances: Dict[int, IsolationForestDetector] = {}
    _user_training_data: Dict[int, List[np.ndarray]] = {}

    @classmethod
    def reset_memory(cls):
        """Clears in-memory model instances and buffers (used for testing and process restart simulation)."""
        cls._instances.clear()
        cls._user_training_data.clear()

    @classmethod
    def get_user_detector(cls, user_id: int) -> IsolationForestDetector:
        if user_id not in cls._instances:
            cls._instances[user_id] = IsolationForestDetector()
        return cls._instances[user_id]

    @classmethod
    def ensure_hydrated(
        cls,
        db: Optional[Session],
        user_id: int,
        baseline_stats: Optional[Dict[str, Any]] = None
    ) -> IsolationForestDetector:
        """
        On-demand hydration: If no in-memory Isolation Forest exists for the user,
        queries the user's historical BehaviorLogs from PostgreSQL, validates vectors,
        filters out any suspicious/poisoned logs, populates the training buffer, and fits
        the model if >= ML_IF_MIN_SAMPLES exist.

        Crucially, does NOT require the original session to still be 'ACTIVE'.
        """
        detector = cls.get_user_detector(user_id)
        if detector.is_fitted or (user_id in cls._user_training_data and len(cls._user_training_data[user_id]) > 0):
            return detector

        if db is None:
            return detector

        try:
            # Query recent logs directly by user_id in descending order
            logs = (
                db.query(BehaviorLog)
                .filter(BehaviorLog.user_id == user_id)
                .order_by(BehaviorLog.timestamp.desc())
                .limit(cls.MAX_HYDRATION_RECORDS)
                .all()
            )

            trusted_vectors = []
            for l in reversed(logs):  # Chronological order
                # Filter out explicitly untrusted or suspicious threat records
                if l.raw_feature_json:
                    try:
                        ctx = json.loads(l.raw_feature_json)
                        # Reject untrusted samples or non-allow decisions
                        if ctx.get("is_trusted") is False:
                            continue
                        if ctx.get("decision") in ["STEP_UP_VERIFICATION", "RESTRICT", "TERMINATE_SESSION"]:
                            continue
                        if float(ctx.get("risk_score", 0.0)) >= 0.30:
                            continue
                        if (
                            ctx.get("impossible_travel", False)
                            or ctx.get("request_flood", False)
                            or ctx.get("rapid_click_burst", False)
                            or ctx.get("failed_attempts_count", 0) >= 3
                        ):
                            continue
                    except Exception:
                        pass

                vec = np.array([
                    float(l.typing_speed_wpm),
                    float(l.avg_flight_time_ms),
                    float(l.avg_dwell_time_ms),
                    float(l.mouse_velocity_avg),
                    float(l.mouse_acceleration_avg),
                    float(l.mouse_curvature_entropy),
                    float(l.click_frequency),
                    float(l.scroll_speed_avg),
                    float(l.idle_duration_sec),
                    float(l.navigation_entropy),
                ], dtype=np.float64)

                # Strict sanity check on vector numbers
                is_valid, _ = FeatureEngineering.validate_vector(vec)
                if not is_valid:
                    continue

                trusted_vectors.append(vec)

            cls._user_training_data[user_id] = trusted_vectors
            if len(trusted_vectors) >= detector.min_samples_for_training:
                train_matrix = np.array(trusted_vectors, dtype=np.float64)
                detector.fit(train_matrix, baseline_stats)
            else:
                detector.trained_sample_count = len(trusted_vectors)

        except Exception:
            pass

        return detector

    @classmethod
    def register_trusted_vector(
        cls,
        user_id: int,
        vector: np.ndarray,
        baseline_stats: Optional[Dict[str, Any]] = None
    ) -> IsolationForestDetector:
        """
        Appends a verified legitimate behavioral vector to the user's training dataset.
        Retrains periodically based on ML_RETRAIN_INTERVAL rather than every single event.
        """
        if user_id not in cls._user_training_data:
            cls._user_training_data[user_id] = []

        cls._user_training_data[user_id].append(vector.copy())

        # Limit memory buffer to most recent 100 trusted samples
        if len(cls._user_training_data[user_id]) > cls.MAX_HYDRATION_RECORDS:
            cls._user_training_data[user_id].pop(0)

        detector = cls.get_user_detector(user_id)
        n = len(cls._user_training_data[user_id])
        min_samples = detector.min_samples_for_training
        retrain_interval = getattr(settings, "ML_RETRAIN_INTERVAL", 10)

        # Train if minimum samples are met and either:
        # 1. Not fitted yet (first training)
        # 2. Reached the configured retrain interval
        if n >= min_samples:
            if not detector.is_fitted:
                train_matrix = np.array(cls._user_training_data[user_id], dtype=np.float64)
                detector.fit(train_matrix, baseline_stats)
            elif (n - detector.trained_sample_count) >= retrain_interval:
                train_matrix = np.array(cls._user_training_data[user_id], dtype=np.float64)
                detector.fit(train_matrix, baseline_stats)
        else:
            detector.trained_sample_count = n

        return detector

    @classmethod
    def train_user_model(
        cls,
        user_id: int,
        training_vectors: np.ndarray,
        baseline_stats: Optional[Dict[str, Any]] = None
    ) -> IsolationForestDetector:
        """Explicitly fits the user's Isolation Forest with a batch of verified vectors."""
        detector = cls.get_user_detector(user_id)
        if len(training_vectors) >= detector.min_samples_for_training:
            detector.fit(training_vectors, baseline_stats)
            cls._user_training_data[user_id] = [v.copy() for v in training_vectors]
        return detector

    @classmethod
    def get_ml_status(
        cls,
        user_id: int,
        sample_count: int,
        baseline_stats: Optional[Dict[str, Any]] = None,
        db: Optional[Session] = None
    ) -> Tuple[str, int, bool, float]:
        """
        Retrieves ML state metadata for debugging and SOC profile inspection.
        Hydrates on demand if db session is provided and model not in memory.
        Returns: (ml_status, model_sample_count, is_anomaly, anomaly_score)
        """
        if db is not None:
            cls.ensure_hydrated(db, user_id, baseline_stats)

        detector = cls.get_user_detector(user_id)
        model_samples = detector.trained_sample_count or len(cls._user_training_data.get(user_id, []))
        effective_samples = max(sample_count, model_samples)

        if effective_samples == 0:
            return "ML_COLD_START", 0, False, 0.0
        elif effective_samples < 5:
            return "ML_LEARNING", model_samples, False, 0.10
        else:
            return "ML_READY", model_samples, False, 0.12

    @classmethod
    def get_model_metadata(cls, user_id: int) -> Dict[str, Any]:
        """
        Returns internal model diagnostic metadata for Admin/SOC inspection.
        Never exposed to standard users.
        """
        detector = cls.get_user_detector(user_id)
        n_samples = len(cls._user_training_data.get(user_id, []))
        return {
            "user_id": user_id,
            "model_version": "if_v2.0_welford",
            "training_sample_count": n_samples,
            "model_trained": detector.is_fitted,
            "trained_sample_count": detector.trained_sample_count,
            "last_trained_at": detector.last_trained_at,
            "retrain_count": detector.retrain_count,
            "n_estimators": detector.n_estimators,
            "contamination": detector.contamination,
            "min_samples_for_training": detector.min_samples_for_training,
            "retrain_interval": getattr(settings, "ML_RETRAIN_INTERVAL", 10),
        }
