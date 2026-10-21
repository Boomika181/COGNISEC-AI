import json
import math
import numpy as np
from typing import Dict, Any, List, Optional, Tuple
from app.schemas.behavior import BehaviorEventCreate
from app.core.config import settings


# Feature vector column definitions
FEATURE_NAMES = [
    "typing_speed_wpm",
    "avg_flight_time_ms",
    "avg_dwell_time_ms",
    "mouse_velocity_avg",
    "mouse_acceleration_avg",
    "mouse_curvature_entropy",
    "click_frequency",
    "scroll_speed_avg",
    "idle_duration_sec",
    "navigation_entropy"
]


class FeatureEngineering:
    @staticmethod
    def validate_vector(vector: np.ndarray) -> Tuple[bool, Optional[str]]:
        """
        Strict validation of the 10-dimensional feature vector:
        - Exact dimension count of 10
        - Finite numeric values (no NaN, no Inf)
        - Configured physical/plausible bounds
        """
        if vector is None or len(vector) != len(FEATURE_NAMES):
            return False, f"Feature vector must have exactly {len(FEATURE_NAMES)} dimensions (got {len(vector) if vector is not None else 0})."

        for idx, name in enumerate(FEATURE_NAMES):
            val = vector[idx]
            if not math.isfinite(val) or math.isnan(val):
                return False, f"Feature '{name}' has non-finite or NaN value: {val}."

            bounds = settings.FEATURE_BOUNDS.get(name, {})
            min_bound = bounds.get("min", 0.0)
            max_bound = bounds.get("max", float("inf"))

            if val < min_bound or val > max_bound:
                return False, f"Feature '{name}' value {val} is outside allowed bounds [{min_bound}, {max_bound}]."

        return True, None

    @staticmethod
    def extract_vector(event: BehaviorEventCreate) -> np.ndarray:
        """Extracts a 1D numpy vector from a behavior event."""
        vector = [
            float(event.typing_speed_wpm if event.typing_speed_wpm is not None else 0.0),
            float(event.avg_flight_time_ms if event.avg_flight_time_ms is not None else 0.0),
            float(event.avg_dwell_time_ms if event.avg_dwell_time_ms is not None else 0.0),
            float(event.mouse_velocity_avg if event.mouse_velocity_avg is not None else 0.0),
            float(event.mouse_acceleration_avg if event.mouse_acceleration_avg is not None else 0.0),
            float(event.mouse_curvature_entropy if event.mouse_curvature_entropy is not None else 0.0),
            float(event.click_frequency if event.click_frequency is not None else 0.0),
            float(event.scroll_speed_avg if event.scroll_speed_avg is not None else 0.0),
            float(event.idle_duration_sec if event.idle_duration_sec is not None else 0.0),
            float(event.navigation_entropy if event.navigation_entropy is not None else 0.0)
        ]
        return np.array(vector, dtype=np.float64)

    @staticmethod
    def vector_to_dict(vector: np.ndarray) -> Dict[str, float]:
        """Converts vector back to structured dictionary."""
        return {name: float(val) for name, val in zip(FEATURE_NAMES, vector)}

    @staticmethod
    def compute_statistical_deviations(
        current_vector: np.ndarray,
        baseline_stats: Dict[str, Any]
    ) -> Dict[str, float]:
        """
        Computes z-score distance between current sample and established user baseline.
        Enforces feature-specific minimum standard deviation (sigma) floors.
        """
        deviations = {}
        means = baseline_stats.get("means", {})
        stds = baseline_stats.get("stds", {})

        for idx, name in enumerate(FEATURE_NAMES):
            current_val = float(current_vector[idx])
            mean_val = float(means.get(name, current_val))
            sigma_floor = float(settings.FEATURE_MIN_SIGMA.get(name, 1.0))
            raw_std = float(stds.get(name, sigma_floor))
            effective_std = max(sigma_floor, raw_std)

            z_score = abs(current_val - mean_val) / effective_std
            deviations[name] = round(float(z_score), 4)

        return deviations
