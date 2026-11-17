import json
import math
import time
from datetime import datetime, timezone
import numpy as np
from typing import Optional, Dict, Any, Tuple
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session
from app.models.behavior import BehaviorProfile, BehaviorLog, BehavioralTrainingEvent
from app.ml.feature_engineering import FeatureEngineering, FEATURE_NAMES, MODALITY_FEATURE_GROUPS
from app.ml.model_manager import ModelManager
from app.core.config import settings


class ProfileService:
    MIN_MATURE_SAMPLES: int = 5  # Welford baseline is statistically reliable after 5 trusted samples
    MAX_CONCURRENCY_RETRIES: int = 5  # Bounded optimistic concurrency and lock retry limit

    @staticmethod
    def get_or_create_profile(
        db: Session,
        user_id: int,
        for_update: bool = False
    ) -> BehaviorProfile:
        """
        Retrieves or initializes a user's BehaviorProfile safely under concurrency.
        - Uses SELECT ... FOR UPDATE when for_update=True (PostgreSQL row-level lock).
        - Handles simultaneous first-time profile creation races via IntegrityError /
          OperationalError catch, transaction rollback, and reload of the winning profile
          without overwriting existing baseline statistics.
        """
        for attempt in range(ProfileService.MAX_CONCURRENCY_RETRIES):
            query = db.query(BehaviorProfile).filter(BehaviorProfile.user_id == user_id)
            if for_update:
                query = query.populate_existing().with_for_update()
            profile = query.first()
            if profile:
                return profile

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
                "sample_counts": {feat: 0 for feat in FEATURE_NAMES},
                "feature_sample_counts": {feat: 0 for feat in FEATURE_NAMES},
                "modality_sample_counts": {mod: 0 for mod in MODALITY_FEATURE_GROUPS},
                "modality_maturity": {
                    mod: {
                        "sample_count": 0,
                        "status": "COLD_START",
                        "confidence": 0.0,
                        "is_mature": False
                    }
                    for mod in MODALITY_FEATURE_GROUPS
                },
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
            new_profile = BehaviorProfile(
                user_id=user_id,
                sample_count=0,
                profile_version=1,
                last_updated=datetime.now(timezone.utc),
                baseline_features=json.dumps(initial_stats)
            )
            try:
                db.add(new_profile)
                db.commit()
                db.refresh(new_profile)
                if for_update:
                    locked = (
                        db.query(BehaviorProfile)
                        .populate_existing()
                        .filter(BehaviorProfile.user_id == user_id)
                        .with_for_update()
                        .first()
                    )
                    if locked:
                        return locked
                return new_profile
            except IntegrityError:
                # Another concurrent request/worker inserted the profile first:
                # Roll back failed insert and reload the winning profile without overwriting it.
                db.rollback()
                reload_query = db.query(BehaviorProfile).populate_existing().filter(BehaviorProfile.user_id == user_id)
                if for_update:
                    reload_query = reload_query.with_for_update()
                existing = reload_query.first()
                if existing:
                    return existing
                if attempt == ProfileService.MAX_CONCURRENCY_RETRIES - 1:
                    raise
            except OperationalError:
                db.rollback()
                reload_query = db.query(BehaviorProfile).populate_existing().filter(BehaviorProfile.user_id == user_id)
                if for_update:
                    reload_query = reload_query.with_for_update()
                existing = reload_query.first()
                if existing:
                    return existing
                if attempt < ProfileService.MAX_CONCURRENCY_RETRIES - 1:
                    time.sleep(0.01 * (attempt + 1))
                    continue
                raise

        raise RuntimeError(f"Failed to get or create BehaviorProfile for user_id={user_id} after retries.")

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

        is_eligible, _, observed_features = FeatureEngineering.evaluate_training_eligibility(
            event_vector=raw_vec,
            user_id=user_id,
            event_user_id=user_id,
            is_trusted=True,
            session_status="ACTIVE",
            prior_session_status="ACTIVE",
            decision="ALLOW",
            risk_score=0.0,
            is_anomaly=False,
            anomaly_score=0.0,
            anti_replay_verified=True,
            event_id=f"registration_baseline:{user_id}"
        )

        if is_eligible and observed_features is not None:
            reg_event_id = f"registration_baseline:{user_id}"
            existing_reg_ids = current_data.get("registered_event_ids", [])
            if isinstance(existing_reg_ids, list) and reg_event_id in existing_reg_ids:
                return profile

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

            now_dt = datetime.now(timezone.utc)
            profile.sample_count = 1
            profile.last_updated = now_dt
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
                "sample_counts": {feat: 1 for feat in FEATURE_NAMES},
                "feature_sample_counts": {feat: 1 for feat in FEATURE_NAMES},
                "trusted_samples": 1,
                "trusted_devices": trusted_devices,
                "audit_history": audit_history,
                "registered_event_ids": [reg_event_id],
            }
            profile.baseline_features = json.dumps(updated_stats)

            training_vec, prep_err = FeatureEngineering.prepare_training_vector(
                event_vector=raw_vec,
                observed_features=observed_features,
                baseline_stats=updated_stats
            )
            vec_for_model = training_vec if (training_vec is not None and prep_err is None) else raw_vec

            existing_evt = (
                db.query(BehavioralTrainingEvent)
                .filter(BehavioralTrainingEvent.event_id == reg_event_id)
                .first()
            )
            if existing_evt is None:
                db.add(BehavioralTrainingEvent(
                    event_id=reg_event_id,
                    user_id=user_id,
                    session_id="registration",
                    lifecycle_state="PROCESSED",
                    eligibility_status="ELIGIBLE",
                    is_trusted=1,
                    profile_version=1,
                    raw_vector_json=json.dumps([float(x) for x in raw_vec]),
                    training_vector_json=json.dumps([float(x) for x in vec_for_model]),
                    observed_features_json=json.dumps(observed_features),
                    created_at=now_dt,
                    updated_at=now_dt,
                ))

            db.commit()
            db.refresh(profile)

            # Register in ModelManager with canonical event_id
            ModelManager.register_trusted_vector(user_id, vec_for_model, updated_stats, event_id=reg_event_id)

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
    def get_maturity_info(
        sample_count: int,
        modality_counts: Optional[Dict[str, int]] = None,
        modality: Optional[str] = None
    ) -> Tuple[str, float, bool]:
        """
        Calculates baseline maturity metadata.
        Returns (status_string, confidence_float_0_to_1, is_mature_bool).

        Maturity States:
        - COLD_START: 0 trusted samples
        - LEARNING: 1-4 trusted samples
        - ESTABLISHED: 5+ trusted samples

        Modality-Specific Behavior:
        - When modality is specified: evaluates maturity strictly for that single modality.
        - When modality_counts is provided: evaluates independent maturity across all modalities.
          A profile cannot be ESTABLISHED based on global sample_count alone; every monitored
          modality must reach at least MIN_MATURE_SAMPLES (5). A modality with insufficient
          observations remains immature even if other modalities have many samples.
        - When only sample_count is provided: preserves backward compatibility for legacy callers.
        """
        if modality and modality_counts:
            mod_count = int(modality_counts.get(modality, 0))
            if mod_count == 0:
                return "COLD_START", 0.0, False
            elif mod_count < ProfileService.MIN_MATURE_SAMPLES:
                conf = round(mod_count / float(ProfileService.MIN_MATURE_SAMPLES), 2)
                return "LEARNING", conf, False
            else:
                return "ESTABLISHED", 1.0, True

        if modality_counts is not None and isinstance(modality_counts, dict) and len(modality_counts) > 0:
            all_mods = list(MODALITY_FEATURE_GROUPS.keys())
            counts = {m: int(modality_counts.get(m, 0)) for m in all_mods}
            confidences = {
                m: (1.0 if counts[m] >= ProfileService.MIN_MATURE_SAMPLES
                    else round(counts[m] / float(ProfileService.MIN_MATURE_SAMPLES), 2))
                for m in all_mods
            }
            all_mature = all(counts[m] >= ProfileService.MIN_MATURE_SAMPLES for m in all_mods)
            any_observed = any(counts[m] > 0 for m in all_mods)

            if all_mature:
                return "ESTABLISHED", 1.0, True
            elif not any_observed and sample_count == 0:
                return "COLD_START", 0.0, False
            else:
                avg_confidence = round(sum(confidences.values()) / float(len(all_mods)), 2)
                return "LEARNING", avg_confidence, False

        # Fallback to scalar sample_count for legacy / single-modality callers
        if sample_count == 0:
            return "COLD_START", 0.0, False
        elif sample_count < ProfileService.MIN_MATURE_SAMPLES:
            confidence = round(sample_count / float(ProfileService.MIN_MATURE_SAMPLES), 2)
            return "LEARNING", confidence, False
        else:
            return "ESTABLISHED", 1.0, True

    @staticmethod
    def get_modality_maturity_breakdown(
        modality_counts: Optional[Dict[str, int]] = None
    ) -> Dict[str, Dict[str, Any]]:
        """
        Returns independent maturity evaluation for all 5 modalities:
        - keyboard
        - mouse
        - scroll
        - navigation
        - inactivity
        """
        safe_counts = modality_counts if isinstance(modality_counts, dict) else {}
        breakdown = {}
        for mod in MODALITY_FEATURE_GROUPS.keys():
            cnt = int(safe_counts.get(mod, 0))
            status, conf, is_mat = ProfileService.get_maturity_info(
                sample_count=cnt,
                modality_counts=safe_counts,
                modality=mod
            )
            breakdown[mod] = {
                "sample_count": cnt,
                "status": status,
                "confidence": conf,
                "is_mature": is_mat
            }
        return breakdown

    @staticmethod
    def update_baseline_from_event(
        db: Session,
        user_id: int,
        event_vector: np.ndarray,
        risk_score: float = 0.0,
        session_status: str = "ACTIVE",
        decision: str = "ALLOW",
        observed_modalities: Optional[Dict[str, bool]] = None,
        context_signals: Optional[Dict[str, Any]] = None,
        sample_counts: Optional[Dict[str, int]] = None,
        event_id: Optional[str] = None,
        is_anomaly: bool = False,
        anomaly_score: float = 0.0,
        behavior_log: Optional[BehaviorLog] = None,
        persisted_context: Optional[Dict[str, Any]] = None
    ) -> BehaviorProfile:
        """
        Incrementally learns the trusted behavioral baseline using Welford's algorithm for online variance,
        and registers the verified vector with the Isolation Forest ModelManager.
        
        Strict Contamination Prevention & Modality-Aware Dilution Protection:
        1. Baseline updates and ML training are ONLY permitted if:
           - session_status == "ACTIVE"
           - decision == "ALLOW"
           - risk_score < 0.30 (Trusted Low Risk Threshold)
           - session_status is NOT in ["RESTRICTED", "STEP_UP_REQUIRED", "TERMINATED"]
           - vector passes sanity validation (finite values, dimension count, bounded ranges)
        2. Modality-Aware Baseline Updates:
           - Only genuinely observed modalities update baseline statistics.
           - Unobserved modalities (e.g. keyboard during mouse-only browsing, or mouse during
             typing-only forms) maintain their historical means, variances, and sample counts
             without being diluted toward zero.
           - Genuine zero observations (e.g. zero curvature entropy or zero click frequency)
             are correctly updated when their parent modality was active.
        """
        effective_event_id = event_id or (
            context_signals.get("event_id") if isinstance(context_signals, dict) else None
        )

        is_eligible, rejection_reason, observed_features = FeatureEngineering.evaluate_training_eligibility(
            event_vector=event_vector,
            user_id=user_id,
            event_user_id=user_id,
            is_trusted=True,
            session_status=session_status,
            prior_session_status=session_status,
            decision=decision,
            risk_score=risk_score,
            is_anomaly=is_anomaly,
            anomaly_score=anomaly_score,
            anti_replay_verified=True,
            observed_modalities=observed_modalities,
            context_signals=context_signals,
            sample_counts=sample_counts,
            event_id=effective_event_id
        )
        if not is_eligible or observed_features is None:
            if effective_event_id or behavior_log is not None:
                from app.services.behavior_service import BehaviorService
                BehaviorService.mark_event_rejected(
                    db=db,
                    log=behavior_log,
                    event_id=effective_event_id or (f"behavior_log:{behavior_log.id}" if behavior_log else "rejected_event"),
                    persisted_payload=dict(persisted_context or context_signals or {}),
                    rejection_reason=rejection_reason
                )
            # Guard against baseline contamination and ML model poisoning: Return unmodified profile
            return ProfileService.get_or_create_profile(db, user_id)

        # Ensure the BehaviorProfile row exists before entering the locked/optimistic update loop
        ProfileService.get_or_create_profile(db, user_id)

        for attempt in range(ProfileService.MAX_CONCURRENCY_RETRIES):
            try:
                # 1. Load the latest committed BehaviorProfile row with SELECT ... FOR UPDATE
                #    (acquires row-level lock in PostgreSQL) and populate_existing() so SQLAlchemy
                #    never uses a stale cached ORM instance from the session identity map.
                profile = (
                    db.query(BehaviorProfile)
                    .populate_existing()
                    .filter(BehaviorProfile.user_id == user_id)
                    .with_for_update()
                    .first()
                )
                if not profile:
                    profile = ProfileService.get_or_create_profile(db, user_id, for_update=True)

                expected_version = int(profile.profile_version if profile.profile_version is not None else 1)
                expected_sample_count = int(profile.sample_count if profile.sample_count is not None else 0)

                current_data = ProfileService.get_profile_dict(profile)

                existing_reg_ids = current_data.get("registered_event_ids", [])
                if not isinstance(existing_reg_ids, list):
                    existing_reg_ids = []

                existing_evt = None
                if effective_event_id:
                    existing_evt = (
                        db.query(BehavioralTrainingEvent)
                        .filter(BehavioralTrainingEvent.event_id == effective_event_id)
                        .first()
                    )

                already_durably_processed = bool(
                    (effective_event_id and effective_event_id in existing_reg_ids)
                    or (existing_evt is not None and existing_evt.lifecycle_state == "PROCESSED")
                )

                if already_durably_processed:
                    # Event was already committed to BehaviorProfile / BehavioralTrainingEvent;
                    # prevent duplicate Welford updates and recover worker-local ModelManager state if needed.
                    if effective_event_id not in ModelManager.get_registered_event_ids(user_id):
                        training_vector, prep_err = FeatureEngineering.prepare_training_vector(
                            event_vector=event_vector,
                            observed_features=observed_features,
                            baseline_stats=current_data
                        )
                        if training_vector is not None and prep_err is None:
                            ModelManager.register_trusted_vector(
                                user_id,
                                training_vector,
                                current_data,
                                event_id=effective_event_id
                            )

                    if behavior_log is not None:
                        is_reg_now = ModelManager.is_event_registered(user_id, effective_event_id)
                        log_payload = dict(persisted_context or {})
                        if not log_payload and behavior_log.raw_feature_json:
                            try:
                                log_payload = json.loads(behavior_log.raw_feature_json)
                            except Exception:
                                log_payload = {}
                        log_payload["event_id"] = effective_event_id
                        log_payload["is_trusted"] = True
                        log_payload["eligibility_status"] = "ELIGIBLE"
                        log_payload["lifecycle_state"] = "PROCESSED"
                        log_payload["observed_features"] = observed_features
                        log_payload["ml_registered"] = bool(is_reg_now)
                        log_payload["worker_hydrated"] = bool(is_reg_now)
                        behavior_log.raw_feature_json = json.dumps(log_payload)
                        db.commit()
                    return profile

                means = current_data.get("means", {})
                stds = current_data.get("stds", {})
                m2_dict = current_data.get("m2", {})
                existing_sample_counts = current_data.get("feature_sample_counts") or current_data.get("sample_counts")
                if not isinstance(existing_sample_counts, dict):
                    existing_sample_counts = {feat: expected_sample_count for feat in FEATURE_NAMES}

                new_means = {}
                new_stds = {}
                new_m2 = {}
                new_feature_counts = {}

                any_feature_updated = False

                for idx, feat_name in enumerate(FEATURE_NAMES):
                    old_mean = float(means.get(feat_name, 0.0))
                    old_m2 = float(m2_dict.get(feat_name, 0.0))
                    sigma_floor = float(settings.FEATURE_MIN_SIGMA.get(feat_name, 1.0))
                    old_std = float(stds.get(feat_name, sigma_floor))
                    n_feat = int(existing_sample_counts.get(feat_name, expected_sample_count))

                    is_observed = observed_features.get(feat_name, False)

                    if not is_observed:
                        # Modality was unobserved: Preserve historical statistics without dilution
                        new_means[feat_name] = old_mean
                        new_stds[feat_name] = old_std
                        new_m2[feat_name] = old_m2
                        new_feature_counts[feat_name] = n_feat
                        continue

                    # Feature was genuinely observed during this window
                    any_feature_updated = True
                    n_feat += 1
                    x = float(event_vector[idx])

                    if n_feat == 1:
                        # First legitimate sample initialization for this feature
                        new_mean = x
                        new_m2_val = 0.0
                        new_std = sigma_floor  # Enforce minimum sigma floor
                    else:
                        # Welford online algorithm for numerically stable incremental mean and variance
                        delta = x - old_mean
                        new_mean = old_mean + delta / n_feat
                        delta2 = x - new_mean
                        new_m2_val = old_m2 + delta * delta2
                        sample_variance = new_m2_val / (n_feat - 1)
                        # Apply feature-specific minimum standard deviation floor to avoid zero-variance trap
                        raw_std = math.sqrt(max(1e-6, sample_variance))
                        new_std = max(sigma_floor, raw_std)

                    new_means[feat_name] = round(new_mean, 4)
                    new_stds[feat_name] = round(new_std, 4)
                    new_m2[feat_name] = round(new_m2_val, 4)
                    new_feature_counts[feat_name] = n_feat

                if not any_feature_updated:
                    return profile

                # Calculate new sample count and atomically incremented profile_version
                n = expected_sample_count + 1
                new_version = expected_version + 1
                now_dt = datetime.now(timezone.utc)
                now_iso = now_dt.isoformat()

                # Modality-specific sample count and maturity calculation
                existing_modality_counts = current_data.get("modality_sample_counts")
                if not isinstance(existing_modality_counts, dict):
                    existing_modality_counts = {}

                new_modality_counts = {}
                for mod_name, mod_feats in MODALITY_FEATURE_GROUPS.items():
                    old_mod_cnt = int(existing_modality_counts.get(
                        mod_name,
                        max([int(existing_sample_counts.get(f, 0)) for f in mod_feats] or [0])
                    ))
                    # Modality is observed only if at least one constituent feature was genuinely observed (never imputed)
                    mod_observed = any(bool(observed_features.get(f, False)) for f in mod_feats)
                    if mod_observed:
                        new_modality_counts[mod_name] = old_mod_cnt + 1
                    else:
                        new_modality_counts[mod_name] = old_mod_cnt

                modality_maturity = ProfileService.get_modality_maturity_breakdown(new_modality_counts)
                maturity_status, confidence_score, is_mature = ProfileService.get_maturity_info(
                    sample_count=n,
                    modality_counts=new_modality_counts
                )

                audit_entry = {
                    "timestamp": now_iso,
                    "event": "ONLINE_SAMPLE_UPDATE",
                    "sample_count": n,
                    "profile_version": new_version,
                    "confidence": confidence_score
                }
                existing_history = current_data.get("audit_history", [])
                if not isinstance(existing_history, list):
                    existing_history = []
                updated_history = (existing_history + [audit_entry])[-10:]

                reg_id_to_store = effective_event_id or f"profile_ver:{user_id}:{new_version}"
                updated_reg_ids = (existing_reg_ids + [reg_id_to_store])[-200:]

                updated_stats = {
                    "version": new_version,
                    "model_version": current_data.get("model_version", "IF-v2.0-Welford"),
                    "enrollment_status": "ENROLLED" if n > 0 else "COLD_START",
                    "confidence_status": maturity_status,
                    "confidence_score": confidence_score,
                    "is_mature": is_mature,
                    "sample_count": n,
                    "means": new_means,
                    "stds": new_stds,
                    "m2": new_m2,
                    "sample_counts": new_feature_counts,
                    "feature_sample_counts": new_feature_counts,
                    "modality_sample_counts": new_modality_counts,
                    "modality_maturity": modality_maturity,
                    "trusted_samples": n,
                    "trusted_devices": current_data.get("trusted_devices", []),
                    "audit_history": updated_history,
                    "registered_event_ids": updated_reg_ids,
                    "last_updated": now_iso
                }
                serialized_stats = json.dumps(updated_stats)

                # 2. Optimistic Concurrency Conditional Update:
                #    Execute an atomic conditional UPDATE verifying that neither profile_version
                #    nor sample_count changed since the row was read.
                rows_updated = (
                    db.query(BehaviorProfile)
                    .filter(
                        BehaviorProfile.id == profile.id,
                        BehaviorProfile.user_id == user_id,
                        BehaviorProfile.profile_version == expected_version,
                        BehaviorProfile.sample_count == expected_sample_count,
                    )
                    .update(
                        {
                            BehaviorProfile.sample_count: n,
                            BehaviorProfile.profile_version: new_version,
                            BehaviorProfile.last_updated: now_dt,
                            BehaviorProfile.baseline_features: serialized_stats,
                        },
                        synchronize_session=False,
                    )
                )

                if rows_updated == 0:
                    # Optimistic version/count conflict detected: another transaction updated
                    # the profile concurrently. Rollback snapshot and retry safely.
                    db.rollback()
                    if attempt < ProfileService.MAX_CONCURRENCY_RETRIES - 1:
                        time.sleep(0.005 * (attempt + 1))
                        continue
                    raise RuntimeError(
                        f"Concurrent baseline update conflict for user_id={user_id}: "
                        f"optimistic version check (expected profile_version={expected_version}, "
                        f"sample_count={expected_sample_count}) failed after "
                        f"{ProfileService.MAX_CONCURRENCY_RETRIES} retries."
                    )

                training_vector, prep_err = FeatureEngineering.prepare_training_vector(
                    event_vector=event_vector,
                    observed_features=observed_features,
                    baseline_stats=updated_stats
                )

                # Persist durable training-event state (PENDING -> ELIGIBLE -> PROCESSED)
                # and BehaviorLog durable markers in the EXACT SAME transaction as BehaviorProfile.
                raw_vec_list = [float(x) for x in event_vector]
                train_vec_list = [float(x) for x in training_vector] if training_vector is not None else raw_vec_list

                if existing_evt is not None:
                    existing_evt.lifecycle_state = "PROCESSED"
                    existing_evt.eligibility_status = "ELIGIBLE"
                    existing_evt.is_trusted = 1
                    existing_evt.profile_version = new_version
                    existing_evt.raw_vector_json = json.dumps(raw_vec_list)
                    existing_evt.training_vector_json = json.dumps(train_vec_list)
                    existing_evt.observed_features_json = json.dumps(observed_features)
                    if behavior_log is not None and existing_evt.behavior_log_id is None:
                        existing_evt.behavior_log_id = behavior_log.id
                    existing_evt.updated_at = now_dt
                else:
                    existing_evt = BehavioralTrainingEvent(
                        event_id=reg_id_to_store,
                        user_id=user_id,
                        session_id=behavior_log.session_id if behavior_log is not None else None,
                        behavior_log_id=behavior_log.id if behavior_log is not None else None,
                        lifecycle_state="PROCESSED",
                        eligibility_status="ELIGIBLE",
                        is_trusted=1,
                        profile_version=new_version,
                        raw_vector_json=json.dumps(raw_vec_list),
                        training_vector_json=json.dumps(train_vec_list),
                        observed_features_json=json.dumps(observed_features),
                        created_at=now_dt,
                        updated_at=now_dt,
                    )
                    db.add(existing_evt)

                target_log = behavior_log
                if target_log is None and existing_evt is not None and existing_evt.behavior_log_id is not None:
                    target_log = db.query(BehaviorLog).filter(BehaviorLog.id == existing_evt.behavior_log_id).first()

                log_payload = None
                if target_log is not None:
                    log_payload = dict(persisted_context or {})
                    if not log_payload and target_log.raw_feature_json:
                        try:
                            log_payload = json.loads(target_log.raw_feature_json)
                        except Exception:
                            log_payload = {}
                    log_payload["event_id"] = reg_id_to_store
                    log_payload["is_trusted"] = True
                    log_payload["eligibility_status"] = "ELIGIBLE"
                    log_payload["lifecycle_state"] = "PROCESSED"
                    log_payload["observed_features"] = observed_features
                    # Do NOT set ml_registered=True until worker-local ModelManager registration succeeds
                    log_payload["ml_registered"] = False
                    log_payload["worker_hydrated"] = False
                    target_log.raw_feature_json = json.dumps(log_payload)

                db.commit()
                db.refresh(profile)

                # 3. Register verified vector with Isolation Forest ModelManager ONLY AFTER
                #    the database transaction has committed successfully, using the shared
                #    modality-aware preprocessing path.
                if training_vector is not None and prep_err is None:
                    ModelManager.register_trusted_vector(
                        user_id,
                        training_vector,
                        updated_stats,
                        event_id=reg_id_to_store
                    )
                    if target_log is not None and log_payload is not None:
                        if ModelManager.is_event_registered(user_id, reg_id_to_store):
                            try:
                                log_payload["ml_registered"] = True
                                log_payload["worker_hydrated"] = True
                                target_log.raw_feature_json = json.dumps(log_payload)
                                db.commit()
                            except Exception:
                                db.rollback()
                return profile

            except OperationalError:
                db.rollback()
                if attempt < ProfileService.MAX_CONCURRENCY_RETRIES - 1:
                    time.sleep(0.01 * (attempt + 1))
                    continue
                raise
            except Exception:
                db.rollback()
                raise

        raise RuntimeError(f"Concurrent baseline update failed for user_id={user_id} after retries.")
