import time
import hashlib
import json
import threading
from typing import Dict, Set, Optional, Tuple
from fastapi import HTTPException, status
from app.schemas.behavior import BehaviorEventCreate


class AntiReplayService:
    """
    Guards telemetry streams against replay attacks, packet duplication,
    out-of-order injection, and biometric tampering.
    """

    _lock = threading.Lock()
    # session_id -> { "last_seq": int, "seen_nonces": Dict[nonce, timestamp], "payload_hashes": Dict[hash, timestamp] }
    _session_state: Dict[str, Dict] = {}

    MAX_TIMESTAMP_SKEW_SECONDS = 180  # 3 minutes tolerance for clock skew
    PAYLOAD_DEDUP_WINDOW_SECONDS = 30  # Duplicate payload suppression window

    @classmethod
    def validate_telemetry_integrity(
        cls,
        session_id: str,
        event_data: BehaviorEventCreate
    ):
        """
        Validates anti-replay and anti-tamper constraints on incoming behavioral telemetry.
        Raises HTTPException(400) if any violation is detected.
        """
        # 1. Physical Biometric Sanity / Anti-Tamper Check
        cls._verify_biometric_sanity(event_data)

        # 2. Timestamp Freshness Window Check
        now = time.time()
        if event_data.timestamp is not None:
            skew = abs(now - event_data.timestamp)
            if skew > cls.MAX_TIMESTAMP_SKEW_SECONDS:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Telemetry rejected: Timestamp skew too large ({int(skew)}s vs max {cls.MAX_TIMESTAMP_SKEW_SECONDS}s). Possible replay attack or desynchronized clock."
                )

        with cls._lock:
            if session_id not in cls._session_state:
                cls._session_state[session_id] = {
                    "last_seq": 0,
                    "seen_nonces": {},
                    "payload_hashes": {}
                }

            state = cls._session_state[session_id]

            # Clean expired nonces and payload hashes
            cutoff = now - cls.PAYLOAD_DEDUP_WINDOW_SECONDS
            state["seen_nonces"] = {n: ts for n, ts in state["seen_nonces"].items() if ts > cutoff}
            state["payload_hashes"] = {h: ts for h, ts in state["payload_hashes"].items() if ts > cutoff}

            # 3. Monotonic Sequence Number Validation
            if event_data.sequence_number is not None:
                if event_data.sequence_number <= state["last_seq"]:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Replay detected: Sequence number {event_data.sequence_number} is not strictly greater than previous sequence {state['last_seq']}."
                    )
                state["last_seq"] = event_data.sequence_number

            # 4. Telemetry Nonce Validation
            if event_data.telemetry_nonce:
                if event_data.telemetry_nonce in state["seen_nonces"]:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Replay detected: Telemetry nonce has already been processed for this session."
                    )
                state["seen_nonces"][event_data.telemetry_nonce] = now

            # 5. Duplicate Payload Fingerprint Check
            payload_fingerprint = cls._compute_payload_hash(event_data)
            if payload_fingerprint in state["payload_hashes"]:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Replay detected: Identical behavioral telemetry packet already processed within active time window."
                )
            state["payload_hashes"][payload_fingerprint] = now

    @staticmethod
    def _verify_biometric_sanity(data: BehaviorEventCreate):
        """
        Anti-tamper verification: validates that telemetry metrics conform to
        physically possible human-computer interaction boundaries.
        """
        # Negative duration/speed is physically impossible
        if (data.typing_speed_wpm is not None and data.typing_speed_wpm < 0) or \
           (data.avg_flight_time_ms is not None and data.avg_flight_time_ms < 0) or \
           (data.avg_dwell_time_ms is not None and data.avg_dwell_time_ms < 0) or \
           (data.mouse_velocity_avg is not None and data.mouse_velocity_avg < 0) or \
           (data.mouse_acceleration_avg is not None and data.mouse_acceleration_avg < 0) or \
           (data.click_frequency is not None and data.click_frequency < 0) or \
           (data.scroll_speed_avg is not None and data.scroll_speed_avg < 0) or \
           (data.idle_duration_sec is not None and data.idle_duration_sec < 0):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Telemetry tampering detected: Negative biometric or temporal values are physically impossible."
            )

        # Superhuman upper bounds check (e.g. typing over 400 WPM, clicks over 100 Hz)
        if data.typing_speed_wpm is not None and data.typing_speed_wpm > 450:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Telemetry tampering detected: Typing speed exceeds physiological human limits (> 450 WPM)."
            )

        if data.click_frequency is not None and data.click_frequency > 150:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Telemetry tampering detected: Click frequency exceeds physical limits (> 150 clicks/sec)."
            )

    @staticmethod
    def _compute_payload_hash(data: BehaviorEventCreate) -> str:
        # Create deterministic fingerprint of behavioral metrics + context
        elements = [
            f"typ:{data.typing_speed_wpm:.2f}" if data.typing_speed_wpm else "typ:0",
            f"flt:{data.avg_flight_time_ms:.2f}" if data.avg_flight_time_ms else "flt:0",
            f"dwl:{data.avg_dwell_time_ms:.2f}" if data.avg_dwell_time_ms else "dwl:0",
            f"vel:{data.mouse_velocity_avg:.2f}" if data.mouse_velocity_avg else "vel:0",
            f"acc:{data.mouse_acceleration_avg:.2f}" if data.mouse_acceleration_avg else "acc:0",
            f"clk:{data.click_frequency:.2f}" if data.click_frequency else "clk:0",
            f"ts:{data.timestamp}" if data.timestamp is not None else "",
            f"nonce:{data.telemetry_nonce}" if data.telemetry_nonce else ""
        ]
        # Only check payload hash if there is actual telemetry signal or explicit timestamp/nonce
        raw = "|".join(elements)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @classmethod
    def reset(cls):
        """Clears all session replay tracking (for test isolation)."""
        with cls._lock:
            cls._session_state.clear()
