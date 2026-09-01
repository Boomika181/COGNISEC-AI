import json
import numpy as np
from typing import Dict, Any, List, Optional
from app.schemas.behavior import BehaviorEventCreate


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
    def extract_vector(event: BehaviorEventCreate) -> np.ndarray:
        """Extracts a 1D numpy vector from a behavior event."""
        vector = [
            float(event.typing_speed_wpm or 0.0),
            float(event.avg_flight_time_ms or 0.0),
            float(event.avg_dwell_time_ms or 0.0),
            float(event.mouse_velocity_avg or 0.0),
            float(event.mouse_acceleration_avg or 0.0),
            float(event.mouse_curvature_entropy or 0.0),
            float(event.click_frequency or 0.0),
            float(event.scroll_speed_avg or 0.0),
            float(event.idle_duration_sec or 0.0),
            float(event.navigation_entropy or 0.0)
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
        Computes z-score distance or normalized Euclidean deviation
        between current sample and established user baseline.
        """
        deviations = {}
        means = baseline_stats.get("means", {})
        stds = baseline_stats.get("stds", {})

        for idx, name in enumerate(FEATURE_NAMES):
            current_val = float(current_vector[idx])
            mean_val = float(means.get(name, current_val))
            std_val = float(stds.get(name, 1.0))
            if std_val <= 1e-5:
                std_val = 1.0

            z_score = abs(current_val - mean_val) / std_val
            deviations[name] = round(float(z_score), 4)

        return deviations
