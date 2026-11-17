import math
import threading
from datetime import datetime, timezone
import numpy as np
from typing import Dict, Any, List, Optional, Tuple
from sklearn.ensemble import IsolationForest
from app.ml.feature_engineering import FEATURE_NAMES, FeatureEngineering
from app.core.config import settings


class IsolationForestDetector:
    """
    Per-User Behavioral Anomaly Detection using Scikit-Learn Isolation Forest.
    Standardizes 10-dimensional behavioral features using feature-specific sigma floors,
    and maps isolation tree decision metrics into a calibrated [0.0, 1.0] anomaly deviation signal.

    IMPORTANT ANOMALY SCORE SEMANTICS:
    The anomaly score returned is a continuous deviation signal from [0.0, 1.0]:
    - 0.0 = completely normal / consistent with trusted baseline
    - 1.0 = highly anomalous / extreme deviation
    This score is NOT a statistical probability of attack or malicious user intent.
    """

    MIN_SAMPLES_FOR_TRAINING: int = 25

    def __init__(
        self,
        n_estimators: Optional[int] = None,
        contamination: Optional[float] = None,
        random_state: Optional[int] = None,
        min_samples_for_training: Optional[int] = None
    ):
        self.n_estimators = n_estimators or getattr(settings, "ML_IF_N_ESTIMATORS", 100)
        self.contamination = contamination if contamination is not None else getattr(settings, "ML_IF_CONTAMINATION", 0.05)
        self.random_state = random_state if random_state is not None else getattr(settings, "ML_IF_RANDOM_STATE", 42)
        self.min_samples_for_training = (
            min_samples_for_training
            if min_samples_for_training is not None
            else getattr(settings, "ML_IF_MIN_SAMPLES", self.MIN_SAMPLES_FOR_TRAINING)
        )
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            max_samples="auto",
            n_jobs=1
        )
        self._fit_lock = threading.RLock()
        self.is_fitted = False
        self.trained_sample_count = 0
        self.retrain_count = 0
        self.last_trained_at = None
        self.last_fit_succeeded = False

    @staticmethod
    def standardize_vector(
        vector: np.ndarray,
        baseline_stats: Optional[Dict[str, Any]] = None
    ) -> np.ndarray:
        """
        Z-score standardizes the 10-dimensional vector using the trusted baseline.
        Applies feature-specific minimum standard deviation (sigma) floors.
        """
        if not baseline_stats or "means" not in baseline_stats or "stds" not in baseline_stats:
            return vector

        means_dict = baseline_stats.get("means", {})
        stds_dict = baseline_stats.get("stds", {})

        standardized = np.zeros_like(vector, dtype=np.float64)
        for idx, name in enumerate(FEATURE_NAMES):
            x = float(vector[idx])
            mean = float(means_dict.get(name, x))
            sigma_floor = float(settings.FEATURE_MIN_SIGMA.get(name, 1.0))
            raw_std = float(stds_dict.get(name, sigma_floor))
            std = max(sigma_floor, raw_std)
            standardized[idx] = (x - mean) / std

        return standardized

    def fit(
        self,
        training_vectors: np.ndarray,
        baseline_stats: Optional[Dict[str, Any]] = None
    ) -> "IsolationForestDetector":
        """
        Trains a candidate Isolation Forest on standardized legitimate behavioral feature vectors
        and atomically swaps the fitted estimator into place on success.
        Enforces minimum dataset size threshold (MIN_SAMPLES_FOR_TRAINING) to ensure tree stability.
        If fitting fails, any previously fitted estimator and its metadata remain intact.
        """
        if len(training_vectors) < self.min_samples_for_training:
            with self._fit_lock:
                if not self.is_fitted:
                    self.trained_sample_count = len(training_vectors)
                self.last_fit_succeeded = False
            return self

        try:
            # Standardize each historical training vector
            scaled_samples = []
            for vec in training_vectors:
                scaled_samples.append(self.standardize_vector(vec, baseline_stats))

            X_train = np.array(scaled_samples, dtype=np.float64)
            if X_train.ndim != 2 or X_train.shape[1] != len(FEATURE_NAMES) or not np.all(np.isfinite(X_train)):
                with self._fit_lock:
                    self.last_fit_succeeded = False
                return self

            candidate_model = IsolationForest(
                n_estimators=self.n_estimators,
                contamination=self.contamination,
                random_state=self.random_state,
                max_samples="auto",
                n_jobs=1
            )
            candidate_model.fit(X_train)

            with self._fit_lock:
                self.model = candidate_model
                self.is_fitted = True
                self.trained_sample_count = len(training_vectors)
                self.retrain_count += 1
                self.last_trained_at = datetime.now(timezone.utc).isoformat()
                self.last_fit_succeeded = True
        except Exception:
            with self._fit_lock:
                self.last_fit_succeeded = False
        return self

    @staticmethod
    def build_evaluation_vector(
        sample_vector: np.ndarray,
        baseline_stats: Optional[Dict[str, Any]] = None,
        observed_features: Optional[Dict[str, bool]] = None,
        observed_modalities: Optional[Dict[str, bool]] = None,
        context_signals: Optional[Dict[str, Any]] = None,
        sample_counts: Optional[Dict[str, int]] = None
    ) -> Tuple[np.ndarray, Dict[str, bool]]:
        """
        Constructs an isolated evaluation copy of the 10-dimensional sample vector for anomaly
        scoring, imputing missing (unobserved) features from the user's baseline means while
        preserving genuine observed zero values.

        Imputation is strictly scoped to anomaly evaluation and never mutates sample_vector
        or baseline_stats.
        Returns: (evaluation_vector, observed_features_mask)
        """
        eval_vector = np.array(sample_vector, dtype=np.float64, copy=True)
        resolved_mask = (
            {name: bool(observed_features.get(name, False)) for name in FEATURE_NAMES}
            if isinstance(observed_features, dict)
            else FeatureEngineering.resolve_observed_features(
                event_vector=eval_vector,
                observed_modalities=observed_modalities,
                context_signals=context_signals,
                sample_counts=sample_counts
            )
        )

        if not baseline_stats or "means" not in baseline_stats:
            return eval_vector, resolved_mask

        means_dict = baseline_stats.get("means", {})
        for idx, feat_name in enumerate(FEATURE_NAMES):
            # Only impute when the feature is resolved as unobserved AND carries the 0.0 missing placeholder.
            # Genuine observed zeros (resolved_mask[feat_name] == True) and non-zero physical values are preserved.
            if not resolved_mask.get(feat_name, False) and float(eval_vector[idx]) == 0.0:
                if feat_name in means_dict and means_dict[feat_name] is not None:
                    eval_vector[idx] = float(means_dict[feat_name])

        return eval_vector, resolved_mask

    def predict_anomaly(
        self,
        sample_vector: np.ndarray,
        baseline_stats: Optional[Dict[str, Any]] = None,
        sample_count: int = 0,
        observed_features: Optional[Dict[str, bool]] = None,
        observed_modalities: Optional[Dict[str, bool]] = None,
        context_signals: Optional[Dict[str, Any]] = None,
        sample_counts: Optional[Dict[str, int]] = None
    ) -> Tuple[bool, float, str]:
        """
        Evaluates behavioral anomaly deviation.
        Returns: (is_anomaly_bool, anomaly_score_0_to_1, ml_status_string)

        ML Statuses:
        - ML_COLD_START: 0 trusted samples
        - ML_LEARNING: 1 to 4 trusted samples (baseline forming, score dampened)
        - ML_READY: >= 5 trusted samples (baseline established; IF active if >= min_samples)
        """
        effective_samples = max(sample_count, self.trained_sample_count)

        # 1. Cold Start State (0 trusted samples)
        if effective_samples == 0:
            return False, 0.05, "ML_COLD_START"

        # 2. Learning State (1 to 4 trusted samples)
        if effective_samples < 5:
            if baseline_stats and "means" in baseline_stats and "stds" in baseline_stats:
                eval_vector, _ = self.build_evaluation_vector(
                    sample_vector=sample_vector,
                    baseline_stats=baseline_stats,
                    observed_features=observed_features,
                    observed_modalities=observed_modalities,
                    context_signals=context_signals,
                    sample_counts=sample_counts
                )
                z_vec = self.standardize_vector(eval_vector, baseline_stats)
                avg_z = float(np.mean(np.abs(z_vec)))
                # Dampen early false positives: map avg_z into [0.05, 0.35]
                stat_score = float(np.clip(1.0 - math.exp(-avg_z / 4.0), 0.05, 0.35))
                return False, round(stat_score, 4), "ML_LEARNING"
            return False, 0.10, "ML_LEARNING"

        # 3. Established Baseline State (>= 5 samples)
        # Compute Welford statistical distance component if baseline stats exist
        eval_vector, _ = self.build_evaluation_vector(
            sample_vector=sample_vector,
            baseline_stats=baseline_stats,
            observed_features=observed_features,
            observed_modalities=observed_modalities,
            context_signals=context_signals,
            sample_counts=sample_counts
        )
        if baseline_stats and "means" in baseline_stats and "stds" in baseline_stats:
            z_vec = self.standardize_vector(eval_vector, baseline_stats)
            avg_z = float(np.mean(np.abs(z_vec)))
            stat_distance_score = float(np.clip(1.0 - math.exp(-avg_z / 2.5), 0.0, 1.0))
        else:
            stat_distance_score = 0.10

        # Case A: Isolation Forest is NOT yet fitted (< min_samples_for_training)
        # Gracefully fall back to calibrated Welford statistical distance without fabricating scores
        with self._fit_lock:
            is_fitted_snapshot = self.is_fitted
            model_snapshot = self.model

        if not is_fitted_snapshot or model_snapshot is None:
            is_anomaly = bool(stat_distance_score >= 0.50)
            return is_anomaly, round(stat_distance_score, 4), "ML_READY"

        # Case B: Both Welford Baseline and Isolation Forest are mature and active
        scaled_sample = self.standardize_vector(eval_vector, baseline_stats).reshape(1, -1)

        # Decision function: positive for in-distribution, negative for outlier
        decision_val = float(model_snapshot.decision_function(scaled_sample)[0])
        is_if_outlier = bool(model_snapshot.predict(scaled_sample)[0] == -1)

        # Calibrated Sigmoid Mapping to [0.0, 1.0] deviation score:
        # decision_val >= +0.10 -> if_score ~ 0.10 - 0.25 (Normal)
        # decision_val ==  0.00 -> if_score ~ 0.50 (Decision boundary)
        # decision_val <= -0.15 -> if_score ~ 0.80 - 0.98 (Anomalous)
        calibrated_if_score = float(1.0 / (1.0 + math.exp(10.0 * decision_val)))

        # Synthesize: 60% Isolation Forest + 40% Statistical Distance (neither completely dominates)
        combined_score = (0.60 * calibrated_if_score) + (0.40 * stat_distance_score)
        final_anomaly_score = float(np.clip(combined_score, 0.0, 1.0))

        is_anomaly = bool(final_anomaly_score >= 0.50 or is_if_outlier)
        return is_anomaly, round(final_anomaly_score, 4), "ML_READY"
