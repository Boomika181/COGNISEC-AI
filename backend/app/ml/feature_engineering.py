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

# Canonical modality grouping for modality-aware observation presence
MODALITY_FEATURE_GROUPS = {
    "keyboard": ["typing_speed_wpm", "avg_flight_time_ms", "avg_dwell_time_ms"],
    "mouse": ["mouse_velocity_avg", "mouse_acceleration_avg", "mouse_curvature_entropy", "click_frequency"],
    "scroll": ["scroll_speed_avg"],
    "navigation": ["navigation_entropy"],
    "inactivity": ["idle_duration_sec"],
}


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

    @staticmethod
    def resolve_observed_features(
        event_vector: np.ndarray,
        observed_modalities: Optional[Dict[str, bool]] = None,
        context_signals: Optional[Dict[str, Any]] = None,
        sample_counts: Optional[Dict[str, int]] = None
    ) -> Dict[str, bool]:
        """
        Determines which of the 10 canonical features were genuinely observed during
        the telemetry collection window. Distinguishes genuine observations (including
        genuine zero values like zero curvature entropy or zero click frequency) from
        unobserved modalities, preventing baseline dilution.

        Zero-Trust Principle:
        Client-supplied metadata (flags and sample counts) is treated as a claim/hint,
        never as unvalidated ground truth. Server-side validation enforces kinematic
        and physical feasibility, rejects unevidenced or contradictory claims, respects
        client-side suppression (e.g. masked password fields), and preserves genuine zero
        observations.
        """
        # Collect explicit modality flags from top-level and context_signals.
        # Fail safe: if either source suppresses (False), suppression wins.
        explicit_modalities: Dict[str, bool] = {}
        for source in [observed_modalities, (context_signals.get("observed_modalities") if context_signals else None)]:
            if isinstance(source, dict):
                for mod, val in source.items():
                    bool_val = bool(val)
                    if mod in explicit_modalities:
                        explicit_modalities[mod] = explicit_modalities[mod] and bool_val
                    else:
                        explicit_modalities[mod] = bool_val

        # Collect raw sample counts. If conflicting counts are supplied, take the minimum to fail safe.
        counts: Dict[str, int] = {}
        for source in [sample_counts, (context_signals.get("sample_counts") if context_signals else None)]:
            if isinstance(source, dict):
                for k, val in source.items():
                    try:
                        int_val = int(val)
                        if k in counts:
                            counts[k] = min(counts[k], int_val)
                        else:
                            counts[k] = int_val
                    except (ValueError, TypeError):
                        counts[k] = 0

        # 1. Keyboard: typing speed, flight time, dwell time.
        # Physical invariant: typing strictly requires non-zero dwell or flight times or typing speed.
        # Client flag alone is never sufficient; unevidenced claims with all zero features are rejected.
        keyboard_suppressed = ("keyboard" in explicit_modalities and not explicit_modalities["keyboard"])
        keyboard_physical = (
            float(event_vector[0]) > 0.0
            or float(event_vector[1]) > 0.0
            or float(event_vector[2]) > 0.0
        )
        keyboard_contradiction = False
        if "keystrokes" in counts:
            if counts["keystrokes"] <= 0 and keyboard_physical:
                keyboard_contradiction = True

        if keyboard_suppressed or keyboard_contradiction or not keyboard_physical:
            keyboard_obs = False
        else:
            keyboard_obs = True

        # 2. Mouse: velocity, acceleration, curvature entropy, click frequency.
        # Pointer motion requires velocity > 0, acceleration > 0, or curvature > 0;
        # static clicking requires click_frequency > 0.
        # Genuine zero observations: linear motion produces curvature_entropy == 0.0;
        # motion without clicking produces click_frequency == 0.0.
        mouse_suppressed = ("mouse" in explicit_modalities and not explicit_modalities["mouse"])
        mouse_motion_physical = (
            float(event_vector[3]) > 0.0
            or float(event_vector[4]) > 0.0
            or float(event_vector[5]) > 0.0
        )
        mouse_click_physical = float(event_vector[6]) > 0.0
        mouse_physical = mouse_motion_physical or mouse_click_physical

        mouse_contradiction = False
        if "mouse_points" in counts or "clicks" in counts:
            pts = counts.get("mouse_points", 0)
            clk = counts.get("clicks", 0)
            if pts <= 0 and clk <= 0 and mouse_physical:
                mouse_contradiction = True

        motion_contradiction = ("mouse_points" in counts and counts["mouse_points"] <= 0 and mouse_motion_physical)
        click_contradiction = (
            "clicks" in counts
            and counts["clicks"] <= 0
            and not mouse_motion_physical
            and mouse_click_physical
        )

        if mouse_suppressed or mouse_contradiction or not mouse_physical:
            mouse_motion_obs = False
            mouse_click_obs = False
            mouse_obs = False
        else:
            mouse_motion_obs = bool(mouse_motion_physical and not motion_contradiction)
            mouse_click_obs = bool(mouse_motion_obs or (mouse_click_physical and not click_contradiction))
            mouse_obs = bool(mouse_motion_obs or mouse_click_obs)

        # 3. Scroll: scroll speed and displacement.
        # Genuine zero: scroll observed (recorded scroll events) but stopped (scroll_speed_avg == 0.0).
        scroll_suppressed = ("scroll" in explicit_modalities and not explicit_modalities["scroll"])
        scroll_physical = float(event_vector[7]) > 0.0
        scroll_has_count = ("scrolls" in counts and counts["scrolls"] > 0)
        scroll_contradiction = ("scrolls" in counts and counts["scrolls"] <= 0 and scroll_physical)

        if scroll_suppressed or scroll_contradiction:
            scroll_obs = False
        elif scroll_physical:
            scroll_obs = True
        elif scroll_has_count and explicit_modalities.get("scroll", True):
            # Server-validated scroll count supports genuine zero scroll speed
            scroll_obs = True
        else:
            scroll_obs = False

        # 4. Navigation: route/category transitions.
        # Genuine zero: direct single-target transition yields navigation_entropy == 0.0.
        nav_suppressed = ("navigation" in explicit_modalities and not explicit_modalities["navigation"])
        nav_physical = float(event_vector[9]) > 0.0
        nav_has_count = ("navigations" in counts and counts["navigations"] >= 2)
        nav_contradiction = ("navigations" in counts and counts["navigations"] < 2 and nav_physical)

        if nav_suppressed or nav_contradiction:
            nav_obs = False
        elif nav_physical:
            nav_obs = True
        elif nav_has_count and explicit_modalities.get("navigation", True):
            # Transitions occurred (>= 2 history states) with single-destination deterministic path
            nav_obs = True
        else:
            nav_obs = False

        # 5. Inactivity: idle duration clock.
        # Active interaction (keyboard, mouse, scroll, or nav) is strictly required to measure genuine idle duration.
        has_observed_interaction = bool(keyboard_obs or mouse_obs or scroll_obs or nav_obs)
        inactivity_suppressed = ("inactivity" in explicit_modalities and not explicit_modalities["inactivity"])
        inactivity_contradiction = ("has_interaction" in counts and not counts["has_interaction"] and has_observed_interaction)

        if inactivity_suppressed or inactivity_contradiction or not has_observed_interaction:
            inactivity_obs = False
        else:
            inactivity_obs = True

        return {
            "typing_speed_wpm": keyboard_obs,
            "avg_flight_time_ms": keyboard_obs,
            "avg_dwell_time_ms": keyboard_obs,
            "mouse_velocity_avg": mouse_motion_obs,
            "mouse_acceleration_avg": mouse_motion_obs,
            "mouse_curvature_entropy": mouse_motion_obs,
            "click_frequency": mouse_click_obs,
            "scroll_speed_avg": scroll_obs,
            "idle_duration_sec": inactivity_obs,
            "navigation_entropy": nav_obs,
        }

    @staticmethod
    def validate_modality_metadata(
        observed_modalities: Any = None,
        context_signals: Any = None,
        sample_counts: Any = None,
        observed_features: Any = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Fail-closed validation of modality presence metadata structures.
        Rejects non-dict containers, non-boolean modality flags, and non-integer or negative sample counts.
        """
        if context_signals is not None and not isinstance(context_signals, dict):
            return False, "context_signals must be a dictionary when provided."

        for mod_source_name, mod_source in [
            ("observed_modalities", observed_modalities),
            ("context_signals.observed_modalities", context_signals.get("observed_modalities") if isinstance(context_signals, dict) else None),
        ]:
            if mod_source is not None:
                if not isinstance(mod_source, dict):
                    return False, f"{mod_source_name} must be a dictionary."
                for k, v in mod_source.items():
                    if not isinstance(k, str) or not isinstance(v, bool):
                        return False, f"{mod_source_name} entry '{k}' must map a string key to a boolean."

        for cnt_source_name, cnt_source in [
            ("sample_counts", sample_counts),
            ("context_signals.sample_counts", context_signals.get("sample_counts") if isinstance(context_signals, dict) else None),
        ]:
            if cnt_source is not None:
                if not isinstance(cnt_source, dict):
                    return False, f"{cnt_source_name} must be a dictionary."
                for k, v in cnt_source.items():
                    if not isinstance(k, str) or isinstance(v, bool) or not isinstance(v, int) or v < 0:
                        return False, f"{cnt_source_name} entry '{k}' must be a non-negative integer."

        if observed_features is not None:
            if not isinstance(observed_features, dict):
                return False, "observed_features must be a dictionary."
            for k, v in observed_features.items():
                if k not in FEATURE_NAMES or not isinstance(v, bool):
                    return False, f"observed_features entry '{k}' must be a canonical feature name mapped to a boolean."

        return True, None

    @staticmethod
    def has_active_behavior(
        event_vector: np.ndarray,
        observed_features: Dict[str, bool]
    ) -> bool:
        """
        Verifies that an observation contains genuine, server-validated active behavioral interaction.
        Idle duration alone (index 8) or all-zero vectors without server-validated active modality
        evidence never qualify as active behavior.
        """
        if event_vector is None or len(event_vector) != len(FEATURE_NAMES) or not isinstance(observed_features, dict):
            return False

        # Positive physical activity in any observed active feature (indices 0..7 or 9)
        active_indices = [0, 1, 2, 3, 4, 5, 6, 7, 9]
        if any(
            bool(observed_features.get(FEATURE_NAMES[idx], False)) and float(event_vector[idx]) > 0.0
            for idx in active_indices
        ):
            return True

        # Genuine zero-valued active interaction supported by server-validated modality evidence
        if bool(observed_features.get("mouse_velocity_avg", False)) and any(
            bool(observed_features.get(feat, False)) for feat in ("mouse_curvature_entropy", "click_frequency")
        ):
            return True

        if bool(observed_features.get("scroll_speed_avg", False)) or bool(observed_features.get("navigation_entropy", False)):
            return True

        return False

    @staticmethod
    def evaluate_training_eligibility(
        event_vector: np.ndarray,
        user_id: int,
        event_user_id: Optional[int] = None,
        is_trusted: Optional[bool] = None,
        session_status: Optional[str] = "ACTIVE",
        prior_session_status: Optional[str] = "ACTIVE",
        decision: Optional[str] = "ALLOW",
        risk_score: Optional[float] = 0.0,
        is_anomaly: Optional[bool] = False,
        anomaly_score: Optional[float] = 0.0,
        anti_replay_verified: Optional[bool] = True,
        observed_modalities: Optional[Dict[str, bool]] = None,
        context_signals: Optional[Dict[str, Any]] = None,
        sample_counts: Optional[Dict[str, int]] = None,
        observed_features: Optional[Dict[str, bool]] = None,
        event_id: Optional[str] = None,
        already_registered_ids: Optional[Any] = None
    ) -> Tuple[bool, Optional[str], Optional[Dict[str, bool]]]:
        """
        Canonical Training-Data Eligibility Rule shared by historical hydration and live registration.
        Fails closed on any missing, malformed, untrusted, idle-only, or duplicate observation.

        Returns: (is_eligible, rejection_reason, resolved_observed_features)
        """
        # 1. User ownership check
        if not isinstance(user_id, int) or isinstance(user_id, bool) or user_id <= 0:
            return False, "Invalid user_id.", None
        if event_user_id is not None and event_user_id != user_id:
            return False, "Event user_id does not match target user_id.", None

        # 2. Explicit persisted trusted status (fail closed if missing, None, or non-bool)
        if not isinstance(is_trusted, bool) or is_trusted is not True:
            return False, "Event does not carry an explicit boolean is_trusted=True status.", None

        # 3. Anti-replay verification check
        if not isinstance(anti_replay_verified, bool) or anti_replay_verified is not True:
            return False, "Event has not passed anti-replay verification.", None

        # 4. Duplicate registration check
        if event_id is not None:
            if not isinstance(event_id, str) or not event_id.strip():
                return False, "Malformed event_id.", None
            if already_registered_ids is not None and event_id in already_registered_ids:
                return False, f"Event '{event_id}' has already been registered.", None

        # 5. Zero-Trust session, decision, and risk gates
        disallowed_statuses = {"RESTRICTED", "STEP_UP_REQUIRED", "TERMINATED", "PENDING_OBSERVATION", "PENDING_OTP"}
        if session_status != "ACTIVE" or session_status in disallowed_statuses:
            return False, f"Ineligible session_status: {session_status}.", None
        if prior_session_status != "ACTIVE" or prior_session_status in disallowed_statuses:
            return False, f"Ineligible prior_session_status: {prior_session_status}.", None
        if decision != "ALLOW":
            return False, f"Ineligible zero-trust decision: {decision}.", None

        try:
            if risk_score is None or isinstance(risk_score, bool):
                return False, "Missing or invalid risk_score.", None
            risk_val = float(risk_score)
            if not math.isfinite(risk_val) or math.isnan(risk_val) or risk_val < 0.0 or risk_val >= 0.30:
                return False, f"risk_score {risk_val} outside trusted threshold [0.0, 0.30).", None
        except (ValueError, TypeError):
            return False, "Non-numeric risk_score.", None

        if not isinstance(is_anomaly, bool) or is_anomaly is True:
            return False, "Anomalous observation is ineligible for training.", None

        try:
            if anomaly_score is None or isinstance(anomaly_score, bool):
                return False, "Missing or invalid anomaly_score.", None
            anom_val = float(anomaly_score)
            if not math.isfinite(anom_val) or math.isnan(anom_val) or anom_val < 0.0 or anom_val >= 0.50:
                return False, f"anomaly_score {anom_val} outside trusted threshold [0.0, 0.50).", None
        except (ValueError, TypeError):
            return False, "Non-numeric anomaly_score.", None

        # 6. Modality & context metadata structure validation
        meta_valid, meta_err = FeatureEngineering.validate_modality_metadata(
            observed_modalities=observed_modalities,
            context_signals=context_signals,
            sample_counts=sample_counts,
            observed_features=observed_features
        )
        if not meta_valid:
            return False, meta_err, None

        if isinstance(context_signals, dict):
            if (
                bool(context_signals.get("impossible_travel", False))
                or bool(context_signals.get("request_flood", False))
                or bool(context_signals.get("rapid_click_burst", False))
            ):
                return False, "Threat context flag present in context_signals.", None
            try:
                failed_cnt = int(context_signals.get("failed_attempts_count", 0) or 0)
                if failed_cnt >= 3:
                    return False, "Excessive failed_attempts_count in context_signals.", None
            except (ValueError, TypeError):
                return False, "Malformed failed_attempts_count in context_signals.", None

        # 7. Feature vector dimensionality, finiteness, and physical bounds validation
        is_valid_vec, vec_err = FeatureEngineering.validate_vector(event_vector)
        if not is_valid_vec:
            return False, vec_err, None

        # 8. Server-validated modality presence resolution
        resolved_features = FeatureEngineering.resolve_observed_features(
            event_vector=event_vector,
            observed_modalities=observed_modalities,
            context_signals=context_signals,
            sample_counts=sample_counts
        )
        if isinstance(observed_features, dict):
            # Intersect with persisted observed_features so persisted metadata can never elevate an unobserved feature
            resolved_features = {
                feat: bool(resolved_features.get(feat, False) and observed_features.get(feat, False))
                for feat in FEATURE_NAMES
            }

        # 9. Genuine active behavioral interaction check (rejects idle-only or all-zero observations)
        if not FeatureEngineering.has_active_behavior(event_vector, resolved_features):
            return False, "Observation contains no genuine active behavioral interaction.", None

        return True, None, resolved_features

    @staticmethod
    def prepare_training_vector(
        event_vector: np.ndarray,
        observed_features: Dict[str, bool],
        baseline_stats: Optional[Dict[str, Any]] = None
    ) -> Tuple[Optional[np.ndarray], Optional[str]]:
        """
        Shared preprocessing path for both historical hydration and live model registration.
        - Validates vector dimensions, finiteness, and bounds.
        - Verifies genuine active behavioral observation presence.
        - Preserves genuine observed values (including genuine observed zeros).
        - Imputes unobserved features from the user's baseline means ONLY when a reliable baseline
          exists for that feature (per-feature sample_count > 0 when counts are tracked, or finite
          mean present in baseline_stats). Never invents synthetic values for cold features.
        """
        is_valid, err = FeatureEngineering.validate_vector(event_vector)
        if not is_valid:
            return None, err

        meta_valid, meta_err = FeatureEngineering.validate_modality_metadata(observed_features=observed_features)
        if not meta_valid or not isinstance(observed_features, dict):
            return None, meta_err or "observed_features must be a valid dictionary."

        if not FeatureEngineering.has_active_behavior(event_vector, observed_features):
            return None, "Cannot prepare training vector without active behavioral observations."

        training_vector = np.array(event_vector, dtype=np.float64, copy=True)

        means_dict: Dict[str, Any] = {}
        counts_dict: Optional[Dict[str, Any]] = None
        if isinstance(baseline_stats, dict):
            if isinstance(baseline_stats.get("means"), dict):
                means_dict = baseline_stats["means"]
            raw_counts = baseline_stats.get("feature_sample_counts")
            if not isinstance(raw_counts, dict):
                raw_counts = baseline_stats.get("sample_counts")
            if isinstance(raw_counts, dict):
                counts_dict = raw_counts

        for idx, feat_name in enumerate(FEATURE_NAMES):
            if bool(observed_features.get(feat_name, False)):
                # Feature was genuinely observed (including genuine observed 0.0): preserve exact value
                continue

            # Feature was NOT observed: impute from baseline mean only if a reliable baseline exists
            has_reliable_baseline = False
            if feat_name in means_dict and means_dict[feat_name] is not None:
                if counts_dict is not None:
                    try:
                        has_reliable_baseline = int(counts_dict.get(feat_name, 0)) > 0
                    except (ValueError, TypeError):
                        has_reliable_baseline = False
                else:
                    has_reliable_baseline = True

            if has_reliable_baseline:
                try:
                    mean_val = float(means_dict[feat_name])
                    if math.isfinite(mean_val) and not math.isnan(mean_val):
                        training_vector[idx] = mean_val
                except (ValueError, TypeError):
                    pass

        is_valid_out, out_err = FeatureEngineering.validate_vector(training_vector)
        if not is_valid_out:
            return None, out_err

        return training_vector, None
