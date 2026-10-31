import json
import math
from datetime import datetime, timezone
import numpy as np
from typing import Optional, Dict, Any, Tuple
from sqlalchemy.orm import Session
from app.models.behavior import BehaviorProfile
from app.ml.feature_engineering import FeatureEngineering, FEATURE_NAMES
from app.ml.model_manager import ModelManager
from app.core.config import settings


class ProfileService:
    MIN_MATURE_SAMPLES: int = 5  # Welford baseline is statistically reliable after 5 trusted samples

    @staticmethod
    def get_or_create_profile(db: Session, user_id: int) -> BehaviorProfile:
        profile = db.query(BehaviorProfile).filter(BehaviorProfile.user_id == user_id).first()
        if not profile:
            now_iso = datetime.now(timezone.utc).isoformat()
            initial_stats = {
                "version": 1,
                "model_version": "IF-v2.0-Welford",
                "enrollment_status": "NOT_ENROLLED",
                "confidence_status": "COLD_START",
                "confidence_score": 0.0,
                "sample_count": 0,
                "created_at": now_iso,
                "last_updated": now_iso,
                "means": {feat: 0.0 for feat in FEATURE_NAMES},
                "stds": {feat: float(settings.FEATURE_MIN_SIGMA.get(feat, 1.0)) for feat in FEATURE_NAMES},
                "m2": {feat: 0.0 for feat in FEATURE_NAMES},
                "trusted_samples": 0,
                "trusted_devices": [],
                "audit_history": [
                    {
                        "event": "BASELINE_INITIALIZED",
                        "timestamp": now_iso,
                        "details": "Behavioral profile initialized during account creation."
                    }
                ]
            }
            profile = BehaviorProfile(
                user_id=user_id,
                sample_count=0,
                profile_version=1,
                last_updated=datetime.now(timezone.utc),
                baseline_features=json.dumps(initial_stats)
            )
            db.add(profile)
            db.commit()
            db.refresh(profile)
        return profile

    @staticmethod
    def enroll_registration_baseline(
        db: Session,
        user_id: int,
        sample_data: Optional[Dict[str, Any]] = None,
        device_info: Optional[Dict[str, Any]] = None
    ) -> Optional[BehaviorProfile]:
        """
        Establishes database-backed behavioral baseline during account creation.
        If non-sensitive interaction telemetry is provided from registration (e.g. typing
        non-sensitive display name, pointer dynamics):
        - Sanitizes inputs to ensure NO password or secret content is processed
        - Derives initial timing statistics
        - Marks initial status as LEARNING (confidence 0.20, never immediately trusted)
        - Persists trusted device metadata and audit log in DB
        If no sample is provided, does not create an artificial profile.
        """
        if not sample_data:
            return None

        profile = ProfileService.get_or_create_profile(db, user_id)
        now_iso = datetime.now(timezone.utc).isoformat()
        current_data = ProfileService.get_profile_dict(profile)

        # Extract only privacy-safe numeric dynamics (timing & physics)
        # Never process passwords, tokens, or raw strings
        typing_speed = float(sample_data.get("typing_speed_wpm", 0.0))
        flight_time = float(sample_data.get("avg_flight_time_ms", 0.0))
        dwell_time = float(sample_data.get("avg_dwell_time_ms", 0.0))
        mouse_vel = float(sample_data.get("mouse_velocity_avg", 0.0))
        mouse_acc = float(sample_data.get("mouse_acceleration_avg", 0.0))
        curvature = float(sample_data.get("mouse_curvature_entropy", 0.0))
        clicks = float(sample_data.get("click_frequency", 0.0))
        scroll = float(sample_data.get("scroll_speed_avg", 0.0))
        idle = float(sample_data.get("idle_duration_sec", 0.0))
        nav_entropy = float(sample_data.get("navigation_entropy", 0.0))

        raw_vec = np.array([
            typing_speed, flight_time, dwell_time,
            mouse_vel, mouse_acc, curvature,
            clicks, scroll, idle, nav_entropy
        ], dtype=np.float64)

        is_valid, _ = FeatureEngineering.validate_vector(raw_vec)
        has_active = any(raw_vec[i] > 0.0 for i in range(8))

        if is_valid and has_active:
            means = {}
            stds = {}
            m2_dict = {}
            for idx, feat in enumerate(FEATURE_NAMES):
                val = float(raw_vec[idx])
                sigma_floor = float(settings.FEATURE_MIN_SIGMA.get(feat, 1.0))
                means[feat] = round(val, 4)
                stds[feat] = round(sigma_floor, 4)
                m2_dict[feat] = 0.0

            trusted_devices = current_data.get("trusted_devices", [])
            if device_info:
                trusted_devices.append({
                    "fingerprint": device_info.get("fingerprint", "unknown"),
                    "browser": device_info.get("browser", "unknown"),
                    "os": device_info.get("os", "unknown"),
                    "enrolled_at": now_iso
                })

            audit_history = current_data.get("audit_history", [])
            audit_history.append({
                "event": "REGISTRATION_SAMPLE_ENROLLED",
                "timestamp": now_iso,
                "details": "Initial behavioral observation recorded from non-sensitive registration interaction."
            })

            profile.sample_count = 1
            profile.last_updated = datetime.now(timezone.utc)
            updated_stats = {
                "version": 1,
                "model_version": "IF-v2.0-Welford",
                "enrollment_status": "ENROLLED",
                "confidence_status": "LEARNING",
                "confidence_score": 0.20,
                "sample_count": 1,
                "created_at": current_data.get("created_at", now_iso),
                "last_updated": now_iso,
                "means": means,
                "stds": stds,
                "m2": m2_dict,
                "trusted_samples": 1,
                "trusted_devices": trusted_devices,
                "audit_history": audit_history
            }
            profile.baseline_features = json.dumps(updated_stats)
            db.commit()
            db.refresh(profile)

            # Register in ModelManager
            ModelManager.register_trusted_vector(user_id, raw_vec, updated_stats)

        return profile

    @staticmethod
    def get_profile_dict(profile: BehaviorProfile) -> Dict[str, Any]:
        if not profile or not profile.baseline_features:
            return {"means": {}, "stds": {}}
        try:
            return json.loads(profile.baseline_features)
        except Exception:
            return {"means": {}, "stds": {}}

    @staticmethod
    def get_maturity_info(sample_count: int) -> Tuple[str, float, bool]:
        """
        Calculates baseline maturity metadata.
        Returns (status_string, confidence_float_0_to_1, is_mature_bool).
        Maturity States:
        - COLD_START: 0 trusted samples
        - LEARNING: 1-4 trusted samples
        - ESTABLISHED: 5+ trusted samples
        """
        if sample_count == 0:
            return "COLD_START", 0.0, False
        elif sample_count < ProfileService.MIN_MATURE_SAMPLES:
            confidence = round(sample_count / float(ProfileService.MIN_MATURE_SAMPLES), 2)
            return "LEARNING", confidence, False
        else:
            return "ESTABLISHED", 1.0, True

    @staticmethod
    def update_baseline_from_event(
        db: Session,
        user_id: int,
        event_vector: np.ndarray,
        risk_score: float = 0.0,
        session_status: str = "ACTIVE",
        decision: str = "ALLOW"
    ) -> BehaviorProfile:
        """
        Incrementally learns the trusted behavioral baseline using Welford's algorithm for online variance,
        and registers the verified vector with the Isolation Forest ModelManager.
        
        Strict Contamination Prevention Guards:
        Baseline updates and ML training are ONLY permitted if:
        1. session_status == "ACTIVE"
        2. decision == "ALLOW"
        3. risk_score < 0.30 (Trusted Low Risk Threshold)
        4. session_status is NOT in ["RESTRICTED", "STEP_UP_REQUIRED", "TERMINATED"]
        5. vector passes sanity validation (finite values, dimension count, bounded ranges)
        """
        disallowed_statuses = {"RESTRICTED", "STEP_UP_REQUIRED", "TERMINATED"}
        if (
            session_status in disallowed_statuses
            or session_status != "ACTIVE"
            or decision != "ALLOW"
            or risk_score >= 0.30
        ):
            # Guard against baseline contamination and ML model poisoning: Return unmodified profile
            return ProfileService.get_or_create_profile(db, user_id)

        # Validate feature vector dimensions and bounded ranges
        is_valid, _ = FeatureEngineering.validate_vector(event_vector)
        if not is_valid:
            return ProfileService.get_or_create_profile(db, user_id)

        # Guard against empty/idle samples contaminating the baseline with zeros:
        # A legitimate baseline update requires active behavioral interaction (typing or pointer dynamics)
        has_active_behavior = any(float(event_vector[idx]) > 0.0 for idx in range(8))
        if not has_active_behavior:
            return ProfileService.get_or_create_profile(db, user_id)

        profile = ProfileService.get_or_create_profile(db, user_id)
        current_data = ProfileService.get_profile_dict(profile)

        means = current_data.get("means", {})
        stds = current_data.get("stds", {})
        m2_dict = current_data.get("m2", {})

        n = profile.sample_count + 1  # New sample count

        new_means = {}
        new_stds = {}
        new_m2 = {}

        for idx, feat_name in enumerate(FEATURE_NAMES):
            x = float(event_vector[idx])
            old_mean = float(means.get(feat_name, x))
            old_m2 = float(m2_dict.get(feat_name, 0.0))
            sigma_floor = float(settings.FEATURE_MIN_SIGMA.get(feat_name, 1.0))

            if n == 1:
                # First legitimate sample initialization
                new_mean = x
                new_m2_val = 0.0
                new_std = sigma_floor  # Enforce minimum sigma floor
            else:
                # Welford online algorithm for numerically stable incremental mean and variance
                delta = x - old_mean
                new_mean = old_mean + delta / n
                delta2 = x - new_mean
                new_m2_val = old_m2 + delta * delta2
                sample_variance = new_m2_val / (n - 1)
                # Apply feature-specific minimum standard deviation floor to avoid zero-variance trap
                raw_std = math.sqrt(max(1e-6, sample_variance))
                new_std = max(sigma_floor, raw_std)

            new_means[feat_name] = round(new_mean, 4)
            new_stds[feat_name] = round(new_std, 4)
            new_m2[feat_name] = round(new_m2_val, 4)

        # Update profile entity
        profile.sample_count = n
        if n % 10 == 0:
            profile.profile_version += 1
        now_iso = datetime.now(timezone.utc).isoformat()
        profile.last_updated = datetime.now(timezone.utc)
        maturity_status, confidence_score, _ = ProfileService.get_maturity_info(n)
        
        audit_entry = {
            "timestamp": now_iso,
            "event": "ONLINE_SAMPLE_UPDATE",
            "sample_count": n,
            "confidence": confidence_score
        }
        existing_history = current_data.get("audit_history", [])
        if not isinstance(existing_history, list):
            existing_history = []
        updated_history = (existing_history + [audit_entry])[-10:]

        updated_stats = {
            "version": current_data.get("version", 1),
            "model_version": current_data.get("model_version", "IF-v2.0-Welford"),
            "enrollment_status": "ENROLLED" if n > 0 else "COLD_START",
            "confidence_status": maturity_status,
            "confidence_score": confidence_score,
            "means": new_means,
            "stds": new_stds,
            "m2": new_m2,
            "trusted_samples": n,
            "trusted_devices": current_data.get("trusted_devices", []),
            "audit_history": updated_history,
            "last_updated": now_iso
        }
        profile.baseline_features = json.dumps(updated_stats)

        db.commit()
        db.refresh(profile)

        # Register verified vector with Isolation Forest Model Manager for per-user ML training
        ModelManager.register_trusted_vector(user_id, event_vector, updated_stats)

        return profile
