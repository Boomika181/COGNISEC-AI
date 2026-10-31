import time
import threading
from typing import Dict, List, Tuple, Optional
from app.core.config import settings


class ConfidentialAccessTracker:
    """
    Server-side tracker for repeated confidential resource access denials.
    Enforces a rolling time window, rapid request deduplication (preventing UI double-clicks
    from inflating counts), and cross-user / cross-session isolation.
    """

    _lock = threading.Lock()
    # Key: f"{user_id}:{session_id}" -> list of (timestamp: float, resource: str)
    _denial_history: Dict[str, List[Tuple[float, str]]] = {}

    @classmethod
    def _make_key(cls, user_id: int, session_id: str) -> str:
        return f"{user_id}:{session_id}"

    @classmethod
    def record_denial(
        cls,
        user_id: int,
        session_id: str,
        resource: str,
        window_seconds: Optional[int] = None,
        dedup_seconds: Optional[float] = None
    ) -> int:
        """
        Records a server-side confidential access denial.
        Deduplicates rapid repeated clicks to the same resource within dedup_seconds.
        Prunes attempts outside window_seconds and returns the active denial count.
        """
        win = window_seconds if window_seconds is not None else settings.CONFIDENTIAL_ACCESS_DENIAL_WINDOW_SECONDS
        dedup = dedup_seconds if dedup_seconds is not None else settings.CONFIDENTIAL_ACCESS_DEDUP_WINDOW_SECONDS
        key = cls._make_key(user_id, session_id)
        now = time.time()
        norm_res = (resource or "unknown_resource").lower().strip()

        with cls._lock:
            history = cls._denial_history.get(key, [])
            cutoff = now - win
            history = [entry for entry in history if entry[0] >= cutoff]

            # Rapid duplicate suppression: if same resource was recorded within dedup window, ignore duplicate
            if history:
                last_ts, last_res = history[-1]
                if last_res == norm_res and (now - last_ts) < dedup:
                    cls._denial_history[key] = history
                    return len(history)

            history.append((now, norm_res))
            cls._denial_history[key] = history
            return len(history)

    @classmethod
    def get_recent_denials_count(
        cls,
        user_id: int,
        session_id: str,
        window_seconds: Optional[int] = None
    ) -> int:
        """
        Returns the number of confidential access denials within the rolling window.
        """
        win = window_seconds if window_seconds is not None else settings.CONFIDENTIAL_ACCESS_DENIAL_WINDOW_SECONDS
        key = cls._make_key(user_id, session_id)
        now = time.time()
        cutoff = now - win

        with cls._lock:
            history = cls._denial_history.get(key, [])
            active = [entry for entry in history if entry[0] >= cutoff]
            if len(active) != len(history):
                cls._denial_history[key] = active
            return len(active)

    @classmethod
    def clear_denials(cls, user_id: int, session_id: str) -> None:
        """
        Clears denial history for a specific session upon verified step-up or termination.
        """
        key = cls._make_key(user_id, session_id)
        with cls._lock:
            cls._denial_history.pop(key, None)

    @classmethod
    def reset_all(cls) -> None:
        """
        Reset method used for isolated testing environments.
        """
        with cls._lock:
            cls._denial_history.clear()
