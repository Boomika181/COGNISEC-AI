import json
import logging
import threading
from datetime import datetime, timezone
import numpy as np
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.ml.anomaly_detector import IsolationForestDetector
from app.ml.feature_engineering import FeatureEngineering
from app.models.behavior import BehaviorLog, BehaviorProfile, BehavioralTrainingEvent
from app.core.config import settings

logger = logging.getLogger(__name__)


class ModelManager:
    """
    In-memory Model Registry & Lifecycle Manager for Per-User Isolation Forests.
    Supports on-demand and watermark-aware incremental database hydration from durable
    training events and historical behavior logs, preserving consistency across restarts,
    concurrent requests, and multiple application workers.
    Enforces strict fail-closed anti-poisoning, sliding-window retraining beyond the
    100-sample buffer cap, and strict isolation of simulator state.
    """
    MAX_HYDRATION_RECORDS: int = 100  # Bounded sliding window of most recent 100 trusted samples
    _lock = threading.RLock()
    _user_locks: Dict[Tuple[str, int], threading.RLock] = {}

    # Production namespace state (preserved as direct class attributes for compatibility)
    _instances: Dict[int, IsolationForestDetector] = {}
    _user_training_data: Dict[int, List[np.ndarray]] = {}
    _user_event_order: Dict[int, List[str]] = {}
    _registered_event_ids: Dict[int, set] = {}
    _samples_since_retrain: Dict[int, int] = {}
    _cumulative_trusted_samples: Dict[int, int] = {}
    _hydrated_profile_version: Dict[int, int] = {}
    _hydrated_sample_count: Dict[int, int] = {}
    _hydrated_event_watermark: Dict[int, int] = {}
    _has_hydrated_from_db: Dict[int, bool] = {}

    # Isolated simulator namespace state (F-03G)
    _sim_instances: Dict[int, IsolationForestDetector] = {}
    _sim_user_training_data: Dict[int, List[np.ndarray]] = {}
    _sim_user_event_order: Dict[int, List[str]] = {}
    _sim_registered_event_ids: Dict[int, set] = {}
    _sim_samples_since_retrain: Dict[int, int] = {}
    _sim_cumulative_trusted_samples: Dict[int, int] = {}
    _sim_hydrated_profile_version: Dict[int, int] = {}
    _sim_hydrated_sample_count: Dict[int, int] = {}
    _sim_hydrated_event_watermark: Dict[int, int] = {}
    _sim_has_hydrated_from_db: Dict[int, bool] = {}

    @classmethod
    def _resolve_namespace(cls, db: Optional[Session] = None, namespace: Optional[str] = None) -> str:
        if namespace in ("simulator", "sim"):
            return "simulator"
        if namespace == "prod":
            return "prod"
        if db is not None:
            try:
                from app.database.connection import simulator_engine
                if getattr(db, "bind", None) is simulator_engine:
                    return "simulator"
            except Exception:
                pass
        return "prod"

    @classmethod
    def _get_state_maps(cls, namespace: str = "prod"):
        if namespace in ("simulator", "sim"):
            return (
                cls._sim_instances,
                cls._sim_user_training_data,
                cls._sim_user_event_order,
                cls._sim_registered_event_ids,
                cls._sim_samples_since_retrain,
                cls._sim_cumulative_trusted_samples,
                cls._sim_hydrated_profile_version,
                cls._sim_hydrated_sample_count,
                cls._sim_hydrated_event_watermark,
                cls._sim_has_hydrated_from_db,
            )
        return (
            cls._instances,
            cls._user_training_data,
            cls._user_event_order,
            cls._registered_event_ids,
            cls._samples_since_retrain,
            cls._cumulative_trusted_samples,
            cls._hydrated_profile_version,
            cls._hydrated_sample_count,
            cls._hydrated_event_watermark,
            cls._has_hydrated_from_db,
        )

    @classmethod
    def _get_user_lock(cls, user_id: int, namespace: str = "prod") -> threading.RLock:
        key = (namespace, int(user_id))
        with cls._lock:
            if key not in cls._user_locks:
                cls._user_locks[key] = threading.RLock()
            return cls._user_locks[key]

    @classmethod
    def reset_memory(cls, namespace: Optional[str] = None):
        """Clears in-memory model instances and buffers (used for testing and process restart simulation)."""
        with cls._lock:
            if namespace in (None, "prod"):
                cls._instances.clear()
                cls._user_training_data.clear()
                cls._user_event_order.clear()
                cls._registered_event_ids.clear()
                cls._samples_since_retrain.clear()
                cls._cumulative_trusted_samples.clear()
                cls._hydrated_profile_version.clear()
                cls._hydrated_sample_count.clear()
                cls._hydrated_event_watermark.clear()
                cls._has_hydrated_from_db.clear()
            if namespace in (None, "simulator", "sim"):
                cls._sim_instances.clear()
                cls._sim_user_training_data.clear()
                cls._sim_user_event_order.clear()
                cls._sim_registered_event_ids.clear()
                cls._sim_samples_since_retrain.clear()
                cls._sim_cumulative_trusted_samples.clear()
                cls._sim_hydrated_profile_version.clear()
                cls._sim_hydrated_sample_count.clear()
                cls._sim_hydrated_event_watermark.clear()
                cls._sim_has_hydrated_from_db.clear()

    @classmethod
    def get_registered_event_ids(cls, user_id: int, namespace: str = "prod") -> set:
        _, _, _, reg_ids, _, _, _, _, _, _ = cls._get_state_maps(namespace)
        with cls._lock:
            return set(reg_ids.get(user_id, set()))

    @classmethod
    def get_user_detector(cls, user_id: int, namespace: str = "prod") -> IsolationForestDetector:
        instances, _, _, _, _, _, _, _, _, _ = cls._get_state_maps(namespace)
        with cls._lock:
            if user_id not in instances:
                instances[user_id] = IsolationForestDetector()
            return instances[user_id]

    @classmethod
    def is_worker_stale(
        cls,
        db: Optional[Session],
        user_id: int,
        baseline_stats: Optional[Dict[str, Any]] = None,
        namespace: str = "prod"
    ) -> bool:
        """
        Determines whether this worker's in-memory model state is stale relative to durable
        database state (BehaviorProfile version/sample_count or BehavioralTrainingEvent watermark).
        """
        eff_ns = cls._resolve_namespace(db, namespace)
        (
            _,
            training_data,
            _,
            reg_ids,
            _,
            _,
            hyd_ver,
            hyd_cnt,
            hyd_evt_wm,
            has_hyd,
        ) = cls._get_state_maps(eff_ns)

        if not has_hyd.get(user_id, False):
            return True

        durable_ver = 0
        durable_cnt = 0
        latest_durable_evt_id = 0
        durable_evt_count = 0

        if isinstance(baseline_stats, dict):
            durable_ver = int(baseline_stats.get("version") or 0)
            durable_cnt = int(baseline_stats.get("sample_count") or 0)

        if db is not None and eff_ns == "prod":
            try:
                if durable_ver == 0 and durable_cnt == 0:
                    profile = db.query(BehaviorProfile).filter(BehaviorProfile.user_id == user_id).first()
                    if profile is not None:
                        durable_ver = int(profile.profile_version or 0)
                        durable_cnt = int(profile.sample_count or 0)

                latest_evt = (
                    db.query(BehavioralTrainingEvent.id)
                    .filter(
                        BehavioralTrainingEvent.user_id == user_id,
                        BehavioralTrainingEvent.is_trusted == 1,
                        BehavioralTrainingEvent.lifecycle_state.in_(["ELIGIBLE", "PROCESSED"])
                    )
                    .order_by(BehavioralTrainingEvent.id.desc())
                    .first()
                )
                latest_durable_evt_id = int(latest_evt[0]) if latest_evt else 0

                durable_evt_count = (
                    db.query(func.count(BehavioralTrainingEvent.id))
                    .filter(
                        BehavioralTrainingEvent.user_id == user_id,
                        BehavioralTrainingEvent.is_trusted == 1,
                        BehavioralTrainingEvent.lifecycle_state.in_(["ELIGIBLE", "PROCESSED"])
                    )
                    .scalar() or 0
                )
            except Exception as e:
                logger.warning(f"[ModelManager] is_worker_stale DB check error for user_id={user_id}: {type(e).__name__}")
                return False

        if latest_durable_evt_id > hyd_evt_wm.get(user_id, 0):
            return True
        if durable_evt_count > hyd_cnt.get(user_id, 0):
            return True
        if durable_cnt > hyd_cnt.get(user_id, 0):
            return True
        if durable_ver > hyd_ver.get(user_id, 0):
            return True
        return False

    @classmethod
    def ensure_hydrated(
        cls,
        db: Optional[Session],
        user_id: int,
        baseline_stats: Optional[Dict[str, Any]] = None,
        namespace: Optional[str] = None
    ) -> IsolationForestDetector:
        """
        On-demand, reliable, and watermark-aware incremental hydration:
        - Replaces single bounded scan with deterministic keyset pagination.
        - Preserves watermark integrity: never swallows exceptions, never advances
          watermarks past unprocessed events or failed batches.
        - Handles out-of-order event commits and ensures multi-worker consistency.
        - Keeps previous valid model operational if hydration fails.
        """
        eff_ns = cls._resolve_namespace(db, namespace)
        detector = cls.get_user_detector(user_id, namespace=eff_ns)
        if db is None:
            return detector

        user_lock = cls._get_user_lock(user_id, namespace=eff_ns)
        with user_lock:
            (
                _,
                training_data,
                event_order,
                reg_ids,
                samples_since_retrain,
                cumulative_samples,
                hyd_ver,
                hyd_cnt,
                hyd_evt_wm,
                has_hyd,
            ) = cls._get_state_maps(eff_ns)

            # Fast path if already hydrated from DB and worker watermark matches durable state
            if has_hyd.get(user_id, False) and not cls.is_worker_stale(db, user_id, baseline_stats, namespace=eff_ns):
                return detector

            # Read durable baseline profile metadata
            durable_ver = 0
            durable_cnt = 0
            try:
                profile = db.query(BehaviorProfile).filter(BehaviorProfile.user_id == user_id).first()
                if profile is not None:
                    durable_ver = int(profile.profile_version or 0)
                    durable_cnt = int(profile.sample_count or 0)
                    if baseline_stats is None and profile.baseline_features:
                        try:
                            parsed_profile = json.loads(profile.baseline_features)
                            if isinstance(parsed_profile, dict):
                                baseline_stats = parsed_profile
                        except Exception:
                            baseline_stats = None

                if isinstance(baseline_stats, dict):
                    durable_ver = max(durable_ver, int(baseline_stats.get("version") or 0))
                    durable_cnt = max(durable_cnt, int(baseline_stats.get("sample_count") or 0))

                if eff_ns == "prod":
                    durable_evt_count = (
                        db.query(func.count(BehavioralTrainingEvent.id))
                        .filter(
                            BehavioralTrainingEvent.user_id == user_id,
                            BehavioralTrainingEvent.is_trusted == 1,
                            BehavioralTrainingEvent.lifecycle_state.in_(["ELIGIBLE", "PROCESSED"])
                        )
                        .scalar() or 0
                    )
                    durable_cnt = max(durable_cnt, durable_evt_count)
            except Exception as e:
                logger.warning(f"[ModelManager] Failed reading profile for user_id={user_id}: {type(e).__name__}")
                return detector

            # Snapshot existing in-memory state before reading DB rows
            with cls._lock:
                existing_ids = set(reg_ids.get(user_id, set()))
                existing_vectors = list(training_data.get(user_id, []))
                existing_order = list(event_order.get(user_id, []))
                was_already_hydrated = has_hyd.get(user_id, False)
                initial_evt_wm = hyd_evt_wm.get(user_id, 0)

            discovered_pairs: List[Tuple[str, np.ndarray]] = []
            seen_in_scan = set(existing_ids)
            highest_processed_evt_id = initial_evt_wm
            hydration_failed = False
            BATCH_SIZE = 100

            # 1. Deterministic keyset pagination through BehavioralTrainingEvent
            if eff_ns == "prod":
                try:
                    cursor_id = initial_evt_wm
                    while True:
                        batch = (
                            db.query(BehavioralTrainingEvent)
                            .filter(
                                BehavioralTrainingEvent.user_id == user_id,
                                BehavioralTrainingEvent.is_trusted == 1,
                                BehavioralTrainingEvent.lifecycle_state.in_(["ELIGIBLE", "PROCESSED"]),
                                BehavioralTrainingEvent.id > cursor_id
                            )
                            .order_by(BehavioralTrainingEvent.id.asc())
                            .limit(BATCH_SIZE)
                            .all()
                        )
                        if not batch:
                            break

                        for evt in batch:
                            cursor_id = int(evt.id)
                            if evt.session_id and str(evt.session_id).startswith("sim_"):
                                highest_processed_evt_id = max(highest_processed_evt_id, cursor_id)
                                continue

                            evt_id = str(evt.event_id or "").strip()
                            if not evt_id or evt_id in seen_in_scan:
                                highest_processed_evt_id = max(highest_processed_evt_id, cursor_id)
                                continue

                            raw_vec = None
                            if evt.raw_vector_json:
                                try:
                                    raw_vec = np.array(json.loads(evt.raw_vector_json), dtype=np.float64)
                                except Exception:
                                    raw_vec = None
                            if raw_vec is None:
                                continue

                            obs_features = None
                            if evt.observed_features_json:
                                try:
                                    obs_features = json.loads(evt.observed_features_json)
                                except Exception:
                                    obs_features = None

                            is_eligible, _, resolved_features = FeatureEngineering.evaluate_training_eligibility(
                                event_vector=raw_vec,
                                user_id=user_id,
                                event_user_id=evt.user_id,
                                is_trusted=bool(evt.is_trusted == 1),
                                session_status="ACTIVE",
                                prior_session_status="ACTIVE",
                                decision="ALLOW",
                                risk_score=0.0,
                                is_anomaly=False,
                                anomaly_score=0.0,
                                anti_replay_verified=True,
                                observed_features=obs_features,
                                event_id=evt_id,
                                already_registered_ids=seen_in_scan
                            )
                            if not is_eligible or resolved_features is None:
                                highest_processed_evt_id = max(highest_processed_evt_id, cursor_id)
                                continue

                            training_vec, prep_err = FeatureEngineering.prepare_training_vector(
                                event_vector=raw_vec,
                                observed_features=resolved_features,
                                baseline_stats=baseline_stats
                            )
                            if training_vec is None or prep_err is not None:
                                highest_processed_evt_id = max(highest_processed_evt_id, cursor_id)
                                continue

                            seen_in_scan.add(evt_id)
                            discovered_pairs.append((evt_id, training_vec))
                            highest_processed_evt_id = max(highest_processed_evt_id, cursor_id)

                    # 2. Out-of-order catch-up scan:
                    # If this worker was already hydrated, check if any earlier events committed out of order (id <= initial_evt_wm)
                    if was_already_hydrated and initial_evt_wm > 0:
                        total_known = len(seen_in_scan)
                        if total_known < durable_cnt:
                            ooo_cursor = 0
                            while True:
                                ooo_batch = (
                                    db.query(BehavioralTrainingEvent)
                                    .filter(
                                        BehavioralTrainingEvent.user_id == user_id,
                                        BehavioralTrainingEvent.is_trusted == 1,
                                        BehavioralTrainingEvent.lifecycle_state.in_(["ELIGIBLE", "PROCESSED"]),
                                        BehavioralTrainingEvent.id > ooo_cursor,
                                        BehavioralTrainingEvent.id <= initial_evt_wm
                                    )
                                    .order_by(BehavioralTrainingEvent.id.asc())
                                    .limit(BATCH_SIZE)
                                    .all()
                                )
                                if not ooo_batch:
                                    break

                                for evt in ooo_batch:
                                    ooo_cursor = int(evt.id)
                                    if evt.session_id and str(evt.session_id).startswith("sim_"):
                                        continue
                                    evt_id = str(evt.event_id or "").strip()
                                    if not evt_id or evt_id in seen_in_scan:
                                        continue

                                    raw_vec = None
                                    if evt.raw_vector_json:
                                        try:
                                            raw_vec = np.array(json.loads(evt.raw_vector_json), dtype=np.float64)
                                        except Exception:
                                            raw_vec = None
                                    if raw_vec is None:
                                        continue

                                    obs_features = None
                                    if evt.observed_features_json:
                                        try:
                                            obs_features = json.loads(evt.observed_features_json)
                                        except Exception:
                                            obs_features = None

                                    is_eligible, _, resolved_features = FeatureEngineering.evaluate_training_eligibility(
                                        event_vector=raw_vec,
                                        user_id=user_id,
                                        event_user_id=evt.user_id,
                                        is_trusted=bool(evt.is_trusted == 1),
                                        session_status="ACTIVE",
                                        prior_session_status="ACTIVE",
                                        decision="ALLOW",
                                        risk_score=0.0,
                                        is_anomaly=False,
                                        anomaly_score=0.0,
                                        anti_replay_verified=True,
                                        observed_features=obs_features,
                                        event_id=evt_id,
                                        already_registered_ids=seen_in_scan
                                    )
                                    if not is_eligible or resolved_features is None:
                                        continue

                                    training_vec, prep_err = FeatureEngineering.prepare_training_vector(
                                        event_vector=raw_vec,
                                        observed_features=resolved_features,
                                        baseline_stats=baseline_stats
                                    )
                                    if training_vec is None or prep_err is not None:
                                        continue

                                    seen_in_scan.add(evt_id)
                                    discovered_pairs.append((evt_id, training_vec))

                except Exception as exc:
                    logger.error(f"[ModelManager] BehavioralTrainingEvent hydration error for user_id={user_id}: {type(exc).__name__}: {exc}")
                    hydration_failed = True

            # If hydration failed halfway, DO NOT advance watermarks, DO NOT mark hydrated!
            # Keep previous valid model operational!
            if hydration_failed:
                return detector

            # 3. Fallback scan on BehaviorLog rows for historical/direct legacy log records
            try:
                logs = (
                    db.query(BehaviorLog)
                    .filter(BehaviorLog.user_id == user_id)
                    .order_by(BehaviorLog.timestamp.desc(), BehaviorLog.id.desc())
                    .limit(cls.MAX_HYDRATION_RECORDS)
                    .all()
                )

                seen_nonces: set = set()
                for l in reversed(logs):  # Chronological order
                    # Isolate production hydration from simulated sessions
                    if eff_ns == "prod" and l.session_id and str(l.session_id).startswith("sim_"):
                        continue

                    # Fail closed on missing, empty, or malformed raw_feature_json
                    if not l.raw_feature_json or not isinstance(l.raw_feature_json, str):
                        continue
                    try:
                        ctx = json.loads(l.raw_feature_json)
                    except Exception:
                        continue
                    if not isinstance(ctx, dict):
                        continue

                    if eff_ns == "prod" and ctx.get("simulated") is True:
                        continue

                    # Reject pending in-flight rows or explicitly rejected rows
                    elig_status = ctx.get("eligibility_status")
                    lifecycle_state = ctx.get("lifecycle_state")
                    if elig_status in ("PENDING", "INELIGIBLE", "REJECTED"):
                        continue
                    if lifecycle_state in ("PENDING", "REJECTED", "INELIGIBLE"):
                        continue

                    # Accept rows that either completed worker registration (ml_registered=True)
                    # OR completed durable training-event processing (lifecycle_state in ELIGIBLE/PROCESSED)
                    if "ml_registered" in ctx and ctx.get("ml_registered") is not True:
                        if lifecycle_state not in ("ELIGIBLE", "PROCESSED"):
                            continue

                    event_id = str(ctx.get("event_id") or f"behavior_log:{l.id}")
                    if event_id in seen_in_scan:
                        continue

                    nonce = ctx.get("telemetry_nonce")
                    if isinstance(nonce, str) and nonce.strip():
                        nonce_key = nonce.strip()
                        if nonce_key in seen_nonces or f"nonce:{l.session_id}:{nonce_key}" in seen_in_scan:
                            continue

                    raw_vec = np.array([
                        float(l.typing_speed_wpm),
                        float(l.avg_flight_time_ms),
                        float(l.avg_dwell_time_ms),
                        float(l.mouse_velocity_avg),
                        float(l.mouse_acceleration_avg),
                        float(l.mouse_curvature_entropy),
                        float(l.click_frequency),
                        float(l.scroll_speed_avg),
                        float(l.idle_duration_sec),
                        float(l.navigation_entropy),
                    ], dtype=np.float64)

                    is_eligible, _, resolved_features = FeatureEngineering.evaluate_training_eligibility(
                        event_vector=raw_vec,
                        user_id=user_id,
                        event_user_id=l.user_id,
                        is_trusted=ctx.get("is_trusted"),
                        session_status=ctx.get("session_status", "ACTIVE"),
                        prior_session_status=ctx.get("prior_session_status", "ACTIVE"),
                        decision=ctx.get("decision", "ALLOW"),
                        risk_score=ctx.get("risk_score", 0.0),
                        is_anomaly=ctx.get("is_anomaly", False),
                        anomaly_score=ctx.get("anomaly_score", 0.0),
                        anti_replay_verified=ctx.get("anti_replay_verified", True),
                        observed_modalities=ctx.get("observed_modalities"),
                        context_signals=ctx,
                        sample_counts=ctx.get("sample_counts"),
                        observed_features=ctx.get("observed_features"),
                        event_id=event_id,
                        already_registered_ids=seen_in_scan
                    )
                    if not is_eligible or resolved_features is None:
                        continue

                    training_vec, prep_err = FeatureEngineering.prepare_training_vector(
                        event_vector=raw_vec,
                        observed_features=resolved_features,
                        baseline_stats=baseline_stats
                    )
                    if training_vec is None or prep_err is not None:
                        continue

                    seen_in_scan.add(event_id)
                    if isinstance(nonce, str) and nonce.strip():
                        seen_nonces.add(nonce.strip())
                    discovered_pairs.append((event_id, training_vec))

            except Exception as exc:
                logger.error(f"[ModelManager] BehaviorLog fallback hydration error for user_id={user_id}: {type(exc).__name__}: {exc}")
                hydration_failed = True

            if hydration_failed:
                return detector

            # 4. Synchronized merge with any live vectors registered before or during hydration
            with cls._lock:
                current_vectors = list(training_data.get(user_id, []))
                current_order = list(event_order.get(user_id, []))
                current_reg_ids = set(reg_ids.get(user_id, set()))

                if not was_already_hydrated:
                    # Initial hydration: place historical DB vectors first, followed by any
                    # live vectors registered in memory before/during hydration that weren't in DB
                    merged_vectors: List[np.ndarray] = []
                    merged_order: List[str] = []
                    merged_ids: set = set()

                    for evt_id, vec in discovered_pairs:
                        if evt_id not in merged_ids:
                            merged_ids.add(evt_id)
                            merged_order.append(evt_id)
                            merged_vectors.append(vec)

                    for idx, vec in enumerate(current_vectors):
                        evt_id = current_order[idx] if idx < len(current_order) else f"live_mem:{idx}"
                        if evt_id not in merged_ids:
                            merged_ids.add(evt_id)
                            merged_order.append(evt_id)
                            merged_vectors.append(vec)
                    newly_added_count = len(merged_vectors)
                else:
                    # Incremental multi-worker catch-up: append newly discovered durable vectors
                    merged_vectors = list(current_vectors)
                    merged_order = list(current_order)
                    merged_ids = set(current_reg_ids)
                    newly_added_count = 0

                    for evt_id, vec in discovered_pairs:
                        if evt_id not in merged_ids:
                            merged_ids.add(evt_id)
                            merged_order.append(evt_id)
                            merged_vectors.append(vec)
                            newly_added_count += 1

                # Enforce sliding window cap of MAX_HYDRATION_RECORDS (100)
                if len(merged_vectors) > cls.MAX_HYDRATION_RECORDS:
                    merged_vectors = merged_vectors[-cls.MAX_HYDRATION_RECORDS:]
                    merged_order = merged_order[-cls.MAX_HYDRATION_RECORDS:]

                training_data[user_id] = merged_vectors
                event_order[user_id] = merged_order
                reg_ids[user_id] = merged_ids | current_reg_ids
                cumulative_samples[user_id] = max(
                    cumulative_samples.get(user_id, 0) + newly_added_count,
                    len(merged_vectors),
                    durable_cnt
                )
                if was_already_hydrated and newly_added_count > 0:
                    samples_since_retrain[user_id] = samples_since_retrain.get(user_id, 0) + newly_added_count

                n = len(merged_vectors)
                retrain_interval = getattr(settings, "ML_RETRAIN_INTERVAL", 10)
                should_fit = (
                    n >= detector.min_samples_for_training
                    and (
                        not detector.is_fitted
                        or (was_already_hydrated and samples_since_retrain.get(user_id, 0) >= retrain_interval)
                    )
                )
                train_matrix = np.array(merged_vectors, dtype=np.float64) if should_fit else None

            if should_fit and train_matrix is not None:
                detector.fit(train_matrix, baseline_stats)
                with cls._lock:
                    if detector.last_fit_succeeded:
                        samples_since_retrain[user_id] = 0
            else:
                with cls._lock:
                    if not detector.is_fitted:
                        detector.trained_sample_count = len(training_data.get(user_id, []))

            # Only advance watermarks upon successful hydration
            with cls._lock:
                has_hyd[user_id] = True
                hyd_ver[user_id] = max(hyd_ver.get(user_id, 0), durable_ver)
                hyd_cnt[user_id] = max(hyd_cnt.get(user_id, 0), durable_cnt, len(reg_ids.get(user_id, set())))
                hyd_evt_wm[user_id] = max(hyd_evt_wm.get(user_id, 0), highest_processed_evt_id)

            return detector

    @classmethod
    def register_trusted_vector(
        cls,
        user_id: int,
        vector: np.ndarray,
        baseline_stats: Optional[Dict[str, Any]] = None,
        event_id: Optional[str] = None,
        durable_event_id: Optional[int] = None,
        profile_version: Optional[int] = None,
        namespace: str = "prod"
    ) -> IsolationForestDetector:
        """
        Appends a verified legitimate behavioral vector to the user's training dataset.
        Tracks samples-since-last-retrain independently of the 100-sample sliding buffer
        so periodic retraining continues every ML_RETRAIN_INTERVAL (10) samples indefinitely.
        Preserves safe incremental watermark tracking without jumping watermarks ahead of
        actual registered worker state.
        """
        eff_ns = cls._resolve_namespace(None, namespace)
        detector = cls.get_user_detector(user_id, namespace=eff_ns)
        is_valid, _ = FeatureEngineering.validate_vector(vector)
        if not is_valid:
            return detector

        user_lock = cls._get_user_lock(user_id, namespace=eff_ns)
        with user_lock:
            (
                _,
                training_data,
                event_order,
                reg_ids,
                samples_since_retrain,
                cumulative_samples,
                hyd_ver,
                hyd_cnt,
                hyd_evt_wm,
                _,
            ) = cls._get_state_maps(eff_ns)

            with cls._lock:
                if user_id not in reg_ids:
                    reg_ids[user_id] = set()

                if event_id is not None:
                    if not isinstance(event_id, str) or not event_id.strip():
                        return detector
                    norm_event_id = event_id.strip()
                    if norm_event_id in reg_ids[user_id]:
                        return detector
                    reg_ids[user_id].add(norm_event_id)
                else:
                    norm_event_id = f"anon:{user_id}:{cumulative_samples.get(user_id, 0) + 1}"

                if user_id not in training_data:
                    training_data[user_id] = []
                if user_id not in event_order:
                    event_order[user_id] = []

                training_data[user_id].append(vector.copy())
                event_order[user_id].append(norm_event_id)

                # Limit memory buffer to most recent 100 trusted samples (FIFO sliding window)
                if len(training_data[user_id]) > cls.MAX_HYDRATION_RECORDS:
                    training_data[user_id].pop(0)
                if len(event_order[user_id]) > cls.MAX_HYDRATION_RECORDS:
                    event_order[user_id].pop(0)

                cumulative_samples[user_id] = cumulative_samples.get(user_id, 0) + 1
                samples_since_retrain[user_id] = samples_since_retrain.get(user_id, 0) + 1

                # Local worker registered count increases:
                local_count = max(len(training_data[user_id]), cumulative_samples.get(user_id, 0), len(reg_ids.get(user_id, set())))
                hyd_cnt[user_id] = max(hyd_cnt.get(user_id, 0), local_count)

                # Only advance durable event watermark if durable_event_id is strictly contiguous with current watermark
                if durable_event_id is not None:
                    current_wm = hyd_evt_wm.get(user_id, 0)
                    if durable_event_id == current_wm + 1 or current_wm == 0:
                        hyd_evt_wm[user_id] = durable_event_id

                # Only advance hyd_ver if worker has registered all events up to that profile sample count
                if profile_version is not None:
                    if isinstance(baseline_stats, dict) and baseline_stats.get("sample_count"):
                        if hyd_cnt.get(user_id, 0) >= int(baseline_stats["sample_count"]):
                            hyd_ver[user_id] = max(hyd_ver.get(user_id, 0), int(profile_version))
                    else:
                        hyd_ver[user_id] = max(hyd_ver.get(user_id, 0), int(profile_version))
                elif isinstance(baseline_stats, dict) and baseline_stats.get("version"):
                    if baseline_stats.get("sample_count") and hyd_cnt.get(user_id, 0) >= int(baseline_stats["sample_count"]):
                        hyd_ver[user_id] = max(hyd_ver.get(user_id, 0), int(baseline_stats["version"]))

                n = len(training_data[user_id])
                min_samples = detector.min_samples_for_training
                retrain_interval = getattr(settings, "ML_RETRAIN_INTERVAL", 10)
                pending_new = samples_since_retrain[user_id]

                should_fit = (
                    n >= min_samples
                    and (not detector.is_fitted or pending_new >= retrain_interval)
                )
                train_matrix = np.array(training_data[user_id], dtype=np.float64) if should_fit else None

            if should_fit and train_matrix is not None:
                detector.fit(train_matrix, baseline_stats)
                with cls._lock:
                    if detector.last_fit_succeeded:
                        samples_since_retrain[user_id] = 0
            else:
                with cls._lock:
                    if not detector.is_fitted:
                        detector.trained_sample_count = len(training_data.get(user_id, []))

            return detector

    @classmethod
    def is_event_registered(cls, user_id: int, event_id: str, namespace: str = "prod") -> bool:
        _, _, _, reg_ids, _, _, _, _, _, _ = cls._get_state_maps(namespace)
        with cls._lock:
            return bool(event_id and event_id in reg_ids.get(user_id, set()))

    @classmethod
    def train_user_model(
        cls,
        user_id: int,
        training_vectors: np.ndarray,
        baseline_stats: Optional[Dict[str, Any]] = None,
        namespace: str = "prod"
    ) -> IsolationForestDetector:
        """Explicitly fits the user's Isolation Forest with a batch of verified vectors."""
        eff_ns = cls._resolve_namespace(None, namespace)
        user_lock = cls._get_user_lock(user_id, namespace=eff_ns)
        with user_lock:
            (
                _,
                training_data,
                event_order,
                _,
                samples_since_retrain,
                cumulative_samples,
                _,
                _,
                _,
                _,
            ) = cls._get_state_maps(eff_ns)
            detector = cls.get_user_detector(user_id, namespace=eff_ns)
            if len(training_vectors) >= detector.min_samples_for_training:
                detector.fit(training_vectors, baseline_stats)
                if detector.last_fit_succeeded:
                    with cls._lock:
                        bounded = [v.copy() for v in training_vectors[-cls.MAX_HYDRATION_RECORDS:]]
                        training_data[user_id] = bounded
                        event_order[user_id] = [f"batch:{user_id}:{i}" for i in range(len(bounded))]
                        samples_since_retrain[user_id] = 0
                        cumulative_samples[user_id] = max(
                            cumulative_samples.get(user_id, 0),
                            len(training_vectors)
                        )
            return detector

    @classmethod
    def get_ml_status(
        cls,
        user_id: int,
        sample_count: int,
        baseline_stats: Optional[Dict[str, Any]] = None,
        db: Optional[Session] = None,
        namespace: Optional[str] = None
    ) -> Tuple[str, int, bool, float]:
        """
        Retrieves ML state metadata for debugging and SOC profile inspection.
        Hydrates on demand if db session is provided and model not in memory or stale.
        Returns: (ml_status, model_sample_count, is_anomaly, anomaly_score)
        """
        eff_ns = cls._resolve_namespace(db, namespace)
        if db is not None:
            cls.ensure_hydrated(db, user_id, baseline_stats, namespace=eff_ns)

        _, training_data, _, _, _, _, _, _, _, _ = cls._get_state_maps(eff_ns)
        detector = cls.get_user_detector(user_id, namespace=eff_ns)
        model_samples = detector.trained_sample_count or len(training_data.get(user_id, []))
        effective_samples = max(sample_count, model_samples)

        if detector.is_fitted and model_samples >= detector.min_samples_for_training:
            ml_status = "ML_READY"
        elif effective_samples == 0:
            ml_status = "ML_COLD_START"
        else:
            ml_status = "ML_LEARNING"

        is_anomaly = False
        anomaly_score = 0.0
        if db is not None:
            try:
                latest_log = (
                    db.query(BehaviorLog)
                    .filter(
                        BehaviorLog.user_id == user_id,
                        ~func.coalesce(BehaviorLog.session_id, "").like("sim_%"),
                    )
                    .order_by(BehaviorLog.timestamp.desc(), BehaviorLog.id.desc())
                    .first()
                )
                if latest_log is not None and detector.is_fitted:
                    raw_vec = FeatureEngineering.extract_feature_vector(latest_log)
                    inf_vec, _ = FeatureEngineering.prepare_inference_vector(raw_vec, baseline_stats)
                    if inf_vec is not None:
                        is_anomaly, anomaly_score = detector.predict(inf_vec)
                        anomaly_score = round(float(anomaly_score), 4)
                else:
                    from app.models.security_event import SecurityEvent
                    latest_ev = (
                        db.query(SecurityEvent)
                        .filter(
                            SecurityEvent.user_id == user_id,
                            SecurityEvent.event_type.in_([
                                "BEHAVIORAL_TELEMETRY_RECEIVED",
                                "BEHAVIOR_ANOMALY",
                                "BEHAVIORAL_ANOMALY",
                                "BEHAVIOR_RISK_TRANSITION",
                            ]),
                            ~func.coalesce(SecurityEvent.session_id, "").like("sim_%"),
                        )
                        .order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc())
                        .first()
                    )
                    if latest_ev is not None and latest_ev.anomaly_score is not None:
                        anomaly_score = round(float(latest_ev.anomaly_score), 4)
                        is_anomaly = bool(anomaly_score > 0.5)
            except Exception as err:
                logger.debug(f"[ModelManager] Failed real anomaly lookup for user_id={user_id}: {err}")

        return ml_status, model_samples, is_anomaly, anomaly_score

    @classmethod
    def get_model_metadata(cls, user_id: int, namespace: str = "prod") -> Dict[str, Any]:
        """
        Returns internal model diagnostic metadata for Admin/SOC inspection.
        Never exposed to standard users.
        """
        (
            _,
            training_data,
            _,
            _,
            samples_since_retrain,
            cumulative_samples,
            hyd_ver,
            hyd_cnt,
            hyd_evt_wm,
            has_hyd,
        ) = cls._get_state_maps(namespace)
        detector = cls.get_user_detector(user_id, namespace=namespace)
        n_samples = len(training_data.get(user_id, []))
        return {
            "user_id": user_id,
            "namespace": namespace,
            "model_version": "if_v2.0_welford",
            "training_sample_count": n_samples,
            "cumulative_trusted_samples": cumulative_samples.get(user_id, n_samples),
            "samples_since_retrain": samples_since_retrain.get(user_id, 0),
            "model_trained": detector.is_fitted,
            "trained_sample_count": detector.trained_sample_count,
            "last_trained_at": detector.last_trained_at,
            "retrain_count": detector.retrain_count,
            "n_estimators": detector.n_estimators,
            "contamination": detector.contamination,
            "min_samples_for_training": detector.min_samples_for_training,
            "retrain_interval": getattr(settings, "ML_RETRAIN_INTERVAL", 10),
            "worker_hydrated": has_hyd.get(user_id, False),
            "hydrated_profile_version": hyd_ver.get(user_id, 0),
            "hydrated_sample_count": hyd_cnt.get(user_id, 0),
            "hydrated_event_watermark": hyd_evt_wm.get(user_id, 0),
        }
