import json
import numpy as np
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session
from app.ml.anomaly_detector import IsolationForestDetector
from app.models.behavior import BehaviorLog
from app.models.session import Session as DbSessionModel


class ModelManager:
    """
    In-memory Model Registry & Lifecycle Manager for Per-User Isolation Forests.
    Supports on-demand database hydration from Neon PostgreSQL upon server restart,
    and enforces strict anti-poisoning by accepting only verified trusted behavioral vectors.
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
        queries the user's trusted BehaviorLogs from Neon PostgreSQL, extracts vectors,
        populates the training buffer, and fits the model if >= 5 trusted samples exist.
        """
        detector = cls.get_user_detector(user_id)
        if detector.is_fitted or (user_id in cls._user_training_data and len(cls._user_training_data[user_id]) > 0):
            return detector

        if db is None:
            return detector

        try:
            # Query recent logs joining with sessions to guarantee ACTIVE session status
            logs = (
                db.query(BehaviorLog)
                .join(DbSessionModel, BehaviorLog.session_id == DbSessionModel.id)
                .filter(
                    BehaviorLog.user_id == user_id,
                    DbSessionModel.status == "ACTIVE"
                )
                .order_by(BehaviorLog.timestamp.desc())
                .limit(cls.MAX_HYDRATION_RECORDS)
                .all()
            )

            trusted_vectors = []
            for l in reversed(logs):  # Chronological order
                # Filter out suspicious or contextual threat records
                if l.raw_feature_json:
                    try:
                        ctx = json.loads(l.raw_feature_json)
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
                trusted_vectors.append(vec)

            cls._user_training_data[user_id] = trusted_vectors
            if len(trusted_vectors) >= IsolationForestDetector.MIN_SAMPLES_FOR_TRAINING:
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
        Triggers training when sample count reaches 5, and retrains periodically every 5 samples.
        """
        if user_id not in cls._user_training_data:
            cls._user_training_data[user_id] = []

        cls._user_training_data[user_id].append(vector.copy())
        
        # Limit memory buffer to most recent 100 trusted samples
        if len(cls._user_training_data[user_id]) > cls.MAX_HYDRATION_RECORDS:
            cls._user_training_data[user_id].pop(0)

        detector = cls.get_user_detector(user_id)
        n = len(cls._user_training_data[user_id])

        # Train when minimum required samples are met (n >= 5)
        if n >= IsolationForestDetector.MIN_SAMPLES_FOR_TRAINING and (not detector.is_fitted or n % 5 == 0):
            train_matrix = np.array(cls._user_training_data[user_id], dtype=np.float64)
            detector.fit(train_matrix, baseline_stats)

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
        if len(training_vectors) >= IsolationForestDetector.MIN_SAMPLES_FOR_TRAINING:
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
            return "ML_COLD_START", 0, False, 0.05
        elif effective_samples < IsolationForestDetector.MIN_SAMPLES_FOR_TRAINING or not detector.is_fitted:
            return "ML_LEARNING", model_samples, False, 0.10
        else:
            return "ML_READY", model_samples, False, 0.12
