import json
import math
from datetime import datetime, timezone
import numpy as np
from typing import Optional, Dict, Any, Tuple
from sqlalchemy.orm import Session
from app.models.behavior import BehaviorProfile
from app.ml.feature_engineering import FEATURE_NAMES
from app.ml.model_manager import ModelManager


class ProfileService:
    MIN_MATURE_SAMPLES: int = 5  # Baseline is considered mature and statistically reliable after 5 trusted samples

    @staticmethod
    def get_or_create_profile(db: Session, user_id: int) -> BehaviorProfile:
        profile = db.query(BehaviorProfile).filter(BehaviorProfile.user_id == user_id).first()
        if not profile:
            initial_stats = {
                "means": {feat: 0.0 for feat in FEATURE_NAMES},
                "stds": {feat: 1.0 for feat in FEATURE_NAMES},
                "m2": {feat: 0.0 for feat in FEATURE_NAMES},
                "trusted_samples": 0
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

            if n == 1:
                # First legitimate sample initialization
                new_mean = x
                new_m2_val = 0.0
                new_std = 1.0  # Default initial standard deviation
            else:
                # Welford online algorithm for numerically stable incremental mean and variance
                delta = x - old_mean
                new_mean = old_mean + delta / n
                delta2 = x - new_mean
                new_m2_val = old_m2 + delta * delta2
                sample_variance = new_m2_val / (n - 1)
                new_std = math.sqrt(max(1e-4, sample_variance))

            new_means[feat_name] = round(new_mean, 4)
            new_stds[feat_name] = round(new_std, 4)
            new_m2[feat_name] = round(new_m2_val, 4)

        # Update profile entity
        profile.sample_count = n
        if n % 10 == 0:
            profile.profile_version += 1
        profile.last_updated = datetime.now(timezone.utc)
        updated_stats = {
            "means": new_means,
            "stds": new_stds,
            "m2": new_m2,
            "trusted_samples": n
        }
        profile.baseline_features = json.dumps(updated_stats)

        db.commit()
        db.refresh(profile)

        # Register verified vector with Isolation Forest Model Manager for per-user ML training
        ModelManager.register_trusted_vector(user_id, event_vector, updated_stats)

        return profile
