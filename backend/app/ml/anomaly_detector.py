import math
import numpy as np
from typing import Dict, Any, List, Optional, Tuple
from sklearn.ensemble import IsolationForest
from app.ml.feature_engineering import FEATURE_NAMES


class IsolationForestDetector:
    """
    Per-User Behavioral Anomaly Detection using Scikit-Learn Isolation Forest.
    Standardizes 10-dimensional behavioral features to prevent magnitude bias,
    and maps isolation tree decision metrics into a calibrated [0.0, 1.0] anomaly score.
    """

    MIN_SAMPLES_FOR_TRAINING: int = 5

    def __init__(self, contamination: float = 0.05, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.model = IsolationForest(
            n_estimators=50,
            contamination=self.contamination,
            random_state=self.random_state,
            max_samples="auto",
            n_jobs=1
        )
        self.is_fitted = False
        self.trained_sample_count = 0

    @staticmethod
    def standardize_vector(
        vector: np.ndarray,
        baseline_stats: Optional[Dict[str, Any]] = None
    ) -> np.ndarray:
        """
        Z-score standardizes the 10-dimensional vector using the trusted baseline.
        Ensures high-magnitude features (e.g. mouse velocity ~650) do not overshadow
        bounded features (e.g. curvature entropy ~0.45).
        """
        if not baseline_stats or "means" not in baseline_stats or "stds" not in baseline_stats:
            return vector

        means_dict = baseline_stats.get("means", {})
        stds_dict = baseline_stats.get("stds", {})

        standardized = np.zeros_like(vector, dtype=np.float64)
        for idx, name in enumerate(FEATURE_NAMES):
            x = float(vector[idx])
            mean = float(means_dict.get(name, x))
            std = max(1e-4, float(stds_dict.get(name, 1.0)))
            standardized[idx] = (x - mean) / std

        return standardized

    def fit(
        self,
        training_vectors: np.ndarray,
        baseline_stats: Optional[Dict[str, Any]] = None
    ) -> "IsolationForestDetector":
        """
        Trains the Isolation Forest on standardized legitimate behavioral feature vectors.
        """
        if len(training_vectors) < self.MIN_SAMPLES_FOR_TRAINING:
            self.is_fitted = False
            self.trained_sample_count = len(training_vectors)
            return self

        # Standardize each historical training vector
        scaled_samples = []
        for vec in training_vectors:
            scaled_samples.append(self.standardize_vector(vec, baseline_stats))
        
        X_train = np.array(scaled_samples, dtype=np.float64)
        self.model.fit(X_train)
        self.is_fitted = True
        self.trained_sample_count = len(training_vectors)
        return self

    def predict_anomaly(
        self,
        sample_vector: np.ndarray,
        baseline_stats: Optional[Dict[str, Any]] = None,
        sample_count: int = 0
    ) -> Tuple[bool, float, str]:
        """
        Evaluates behavioral anomaly.
        Returns: (is_anomaly_bool, anomaly_score_0_to_1, ml_status_string)
        
        ML Statuses:
        - ML_COLD_START: 0 trusted samples
        - ML_LEARNING: 1 to 4 trusted samples (insufficient for tree partitioning)
        - ML_READY: >= 5 trusted samples (Isolation Forest is trained and active)
        """
        effective_samples = max(sample_count, self.trained_sample_count)

        # 1. Cold Start State
        if effective_samples == 0:
            return False, 0.05, "ML_COLD_START"

        # 2. Learning State (< 5 samples)
        if not self.is_fitted or effective_samples < self.MIN_SAMPLES_FOR_TRAINING:
            # Dampened statistical baseline z-score distance during early learning
            if baseline_stats and "means" in baseline_stats and "stds" in baseline_stats:
                z_vec = self.standardize_vector(sample_vector, baseline_stats)
                avg_z = float(np.mean(np.abs(z_vec)))
                # Dampen early false positives: map avg_z into [0.05, 0.40]
                stat_score = float(np.clip(1.0 - math.exp(-avg_z / 4.0), 0.05, 0.40))
                return False, round(stat_score, 4), "ML_LEARNING"
            return False, 0.10, "ML_LEARNING"

        # 3. ML Ready State (Active Isolation Forest)
        scaled_sample = self.standardize_vector(sample_vector, baseline_stats).reshape(1, -1)
        
        # Decision function: positive for normal, negative for anomaly
        decision_val = float(self.model.decision_function(scaled_sample)[0])
        is_if_outlier = (self.model.predict(scaled_sample)[0] == -1)

        # Calibrated Sigmoid Mapping:
        # decision_val >= +0.10 -> if_score ~ 0.10 - 0.25 (Normal)
        # decision_val ==  0.00 -> if_score ~ 0.50 (Boundary)
        # decision_val <= -0.15 -> if_score ~ 0.80 - 0.98 (Anomalous)
        calibrated_if_score = 1.0 / (1.0 + math.exp(10.0 * decision_val))

        # Multidimensional statistical distance component
        z_vec = self.standardize_vector(sample_vector, baseline_stats)
        avg_z = float(np.mean(np.abs(z_vec)))
        stat_distance_score = float(1.0 - math.exp(-avg_z / 2.5))

        # Synthesize 65% Isolation Forest + 35% Statistical Distance
        combined_score = (0.65 * calibrated_if_score) + (0.35 * stat_distance_score)
        final_anomaly_score = float(np.clip(combined_score, 0.0, 1.0))

        is_anomaly = bool(final_anomaly_score >= 0.50 or is_if_outlier)

        return is_anomaly, round(final_anomaly_score, 4), "ML_READY"
