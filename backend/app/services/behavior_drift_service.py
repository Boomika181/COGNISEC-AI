import time
import threading
from typing import Dict, List, Tuple, Optional
import numpy as np
from app.core.config import settings


class BehavioralDriftTracker:
    """
    Tracks continuous behavioral deviation across rolling observation windows.
    Distinguishes sustained behavioral drift from isolated, noisy single-sample variations
    (e.g., fatigue, brief distraction, hardware/trackpad change), while combining with
    contextual signals for high-assurance risk escalation.
    """

    _lock = threading.Lock()
    # session_id -> list of (timestamp: float, anomaly_score: float)
    _observation_history: Dict[str, List[Tuple[float, float]]] = {}

    @classmethod
    def record_observation(
        cls,
        session_id: str,
        raw_anomaly_score: float,
        has_context_risk: bool = False,
        window_size: Optional[int] = None,
        drift_threshold: Optional[float] = None
    ) -> Tuple[bool, float, bool]:
        """
        Records an observation and evaluates whether sustained drift is present.

        Returns:
            (is_sustained_drift, effective_anomaly_score, is_single_sample_spike)
        """
        ws = window_size if window_size is not None else getattr(settings, "BEHAVIORAL_DRIFT_WINDOW_SIZE", 4)
        threshold = drift_threshold if drift_threshold is not None else getattr(settings, "BEHAVIORAL_DRIFT_THRESHOLD", 0.50)
        now = time.time()

        if not session_id:
            # Headless or standalone calculation without session context
            is_anomaly = raw_anomaly_score >= threshold
            return is_anomaly, raw_anomaly_score, False

        with cls._lock:
            history = cls._observation_history.get(session_id, [])
            history.append((now, raw_anomaly_score))
            # Keep only the most recent `ws` observations
            if len(history) > ws:
                history = history[-ws:]
            cls._observation_history[session_id] = history

            scores = [score for _, score in history]
            sample_count = len(scores)

            # Case 1: First observation in session
            if sample_count == 1:
                if raw_anomaly_score >= threshold:
                    # Single anomalous observation with no contextual risk
                    if not has_context_risk:
                        # Dampen single-sample spike (e.g. fatigue or temporary hardware pause)
                        dampened = min(raw_anomaly_score, 0.35)
                        return False, round(dampened, 4), True
                    else:
                        # Context risk is present (e.g. unfamiliar device); do not dampen
                        return False, raw_anomaly_score, False
                return False, raw_anomaly_score, False

            # Case 2: Multiple observations in window
            anomalous_samples = [s for s in scores if s >= threshold]
            mean_score = float(np.mean(scores))

            # Sustained drift: at least 2 samples >= threshold OR rolling mean >= threshold
            if len(anomalous_samples) >= 2 or mean_score >= threshold:
                # Sustained deviation across continuous telemetry stream
                effective_score = max(raw_anomaly_score, mean_score)
                return True, round(float(effective_score), 4), False

            # Single isolated spike amidst normal observations (e.g. [0.10, 0.12, 0.70])
            if raw_anomaly_score >= threshold and len(anomalous_samples) == 1:
                if not has_context_risk:
                    # Rolling mean dampens single transient burst
                    effective_score = min(raw_anomaly_score, mean_score)
                    return False, round(float(effective_score), 4), True
                else:
                    return False, raw_anomaly_score, False

            # Normal behavior throughout
            return False, raw_anomaly_score, False

    @classmethod
    def get_session_history(cls, session_id: str) -> List[Tuple[float, float]]:
        """Returns the recent observation history for a session."""
        with cls._lock:
            return list(cls._observation_history.get(session_id, []))

    @classmethod
    def clear_session(cls, session_id: str) -> None:
        """Clears observation history for a session upon termination."""
        with cls._lock:
            cls._observation_history.pop(session_id, None)

    @classmethod
    def reset_all(cls) -> None:
        """Resets tracker for clean test isolation."""
        with cls._lock:
            cls._observation_history.clear()
