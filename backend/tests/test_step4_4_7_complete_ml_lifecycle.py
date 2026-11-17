"""
COGNISEC-AI — Phase II, Step 4.4.7
Complete ML Training Lifecycle and Model Consistency Regression Suite

Covers:
- Phase B (D-02, D-03): Durable training-event lifecycle (PENDING -> ELIGIBLE -> PROCESSED, or REJECTED),
  atomic transaction boundaries between BehaviorProfile, BehavioralTrainingEvent, and BehaviorLog,
  honest ml_registered vs durable lifecycle_state semantics, crash recovery, and stable telemetry_nonce idempotency.
- Phase C (F-03B): Shared modality-aware preprocessing across live registration, enrollment, and hydration.
- Phase D (F-03C): Retraining beyond the 100-sample sliding buffer cap (25, 35, ..., 95, 105, 115) and
  failed-fit counter preservation.
- Phase E (F-03D): Deterministic concurrency across hydration, live vector registration, and anomaly prediction
  with atomic candidate estimator swapping.
- Phase F (F-03F): Multi-worker staleness detection and incremental watermark-driven catch-up from durable DB state.
- Phase G (F-03G): Attack simulator ML isolation from production user models/buffers and canonical registration baseline enrollment.
"""

import json
import threading
from datetime import datetime, timezone
import numpy as np
import pytest
from sqlalchemy.orm import Session
from sklearn.ensemble import IsolationForest

from app.database.connection import SessionLocal
from app.ml.feature_engineering import FeatureEngineering
from app.ml.model_manager import ModelManager
from app.services.profile_service import ProfileService
from app.services.behavior_service import BehaviorService
from app.services.risk_service import RiskService
from app.models.user import User
from app.models.session import Session as DbSession
from app.models.behavior import BehaviorLog, BehaviorProfile, BehavioralTrainingEvent
from app.schemas.behavior import BehaviorEventCreate
from app.core.security import get_password_hash


FULL_ACTIVE_VEC = np.array(
    [65.0, 115.0, 85.0, 420.0, 540.0, 1.25, 0.85, 180.0, 2.0, 0.90],
    dtype=np.float64,
)


def _ensure_session(db: Session, user_id: int, session_id: str) -> None:
    existing = db.query(DbSession).filter(DbSession.id == session_id).first()
    if not existing:
        db.add(
            DbSession(
                id=session_id,
                user_id=user_id,
                application="E-Commerce Portal",
                status="ACTIVE",
                current_risk_level="LOW",
            )
        )
        db.commit()


def _create_isolated_user(db: Session, email: str) -> User:
    user = db.query(User).filter(User.email == email).first()
    if user:
        db.query(BehavioralTrainingEvent).filter(BehavioralTrainingEvent.user_id == user.id).delete()
        db.query(BehaviorLog).filter(BehaviorLog.user_id == user.id).delete()
        db.query(BehaviorProfile).filter(BehaviorProfile.user_id == user.id).delete()
        db.commit()
    else:
        user = User(
            name="Step 4.4.7 Test User",
            email=email,
            password_hash=get_password_hash("ValidPass123!"),
            role="USER",
            account_status="ACTIVE",
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    _ensure_session(db, user.id, f"sess_step447_{user.id}")
    ModelManager.reset_memory()
    return user


# ------------------------------------------------------------------------------
# 1. Durable Lifecycle: PENDING event created in BehaviorLog + BehavioralTrainingEvent
#    cannot be hydrated before risk/eligibility evaluation completes
# ------------------------------------------------------------------------------
def test_1_durable_pending_event_rejected_by_hydration(db_session: Session):
    user = _create_isolated_user(db_session, "step447.pending@cognisec.ai")
    sess_id = f"sess_step447_{user.id}"

    payload = BehaviorEventCreate(
        session_id=sess_id,
        application="E-Commerce Portal",
        typing_speed_wpm=65.0,
        avg_flight_time_ms=115.0,
        avg_dwell_time_ms=85.0,
        mouse_velocity_avg=420.0,
        mouse_acceleration_avg=540.0,
        mouse_curvature_entropy=1.25,
        click_frequency=0.85,
        scroll_speed_avg=180.0,
        idle_duration_sec=2.0,
        navigation_entropy=0.90,
        telemetry_nonce="nonce_pending_001",
    )
    log = BehaviorService.record_behavior_event(db_session, user.id, payload)
    ctx = json.loads(log.raw_feature_json)
    expected_event_id = f"nonce:{sess_id}:nonce_pending_001"

    assert ctx["event_id"] == expected_event_id
    assert ctx["is_trusted"] is False
    assert ctx["eligibility_status"] == "PENDING"
    assert ctx["lifecycle_state"] == "PENDING"
    assert ctx["ml_registered"] is False

    durable_evt = (
        db_session.query(BehavioralTrainingEvent)
        .filter(BehavioralTrainingEvent.event_id == expected_event_id)
        .first()
    )
    assert durable_evt is not None
    assert durable_evt.lifecycle_state == "PENDING"
    assert durable_evt.eligibility_status == "PENDING"
    assert durable_evt.is_trusted == 0

    ModelManager.reset_memory()
    detector = ModelManager.ensure_hydrated(db_session, user.id)
    assert len(ModelManager._user_training_data.get(user.id, [])) == 0
    assert detector.trained_sample_count == 0


# ------------------------------------------------------------------------------
# 2. Durable Lifecycle: Rejected/ineligible event reaches terminal REJECTED state
#    and is never loaded during hydration
# ------------------------------------------------------------------------------
def test_2_rejected_event_reaches_terminal_rejected_state(db_session: Session):
    user = _create_isolated_user(db_session, "step447.rejected@cognisec.ai")
    sess_id = f"sess_step447_{user.id}"

    payload = BehaviorEventCreate(
        session_id=sess_id,
        application="E-Commerce Portal",
        typing_speed_wpm=0.0,
        avg_flight_time_ms=0.0,
        avg_dwell_time_ms=0.0,
        mouse_velocity_avg=0.0,
        mouse_acceleration_avg=0.0,
        mouse_curvature_entropy=0.0,
        click_frequency=0.0,
        scroll_speed_avg=0.0,
        idle_duration_sec=19.0,
        navigation_entropy=0.0,
        telemetry_nonce="nonce_reject_002",
    )
    log = BehaviorService.record_behavior_event(db_session, user.id, payload)
    event_id = f"nonce:{sess_id}:nonce_reject_002"
    idle_vec = FeatureEngineering.extract_vector(payload)

    # Attempt baseline update with ineligible idle-only vector
    profile = ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=idle_vec,
        risk_score=0.05,
        session_status="ACTIVE",
        decision="ALLOW",
        event_id=event_id,
        behavior_log=log,
    )
    assert profile.sample_count == 0

    db_session.refresh(log)
    ctx = json.loads(log.raw_feature_json)
    assert ctx["is_trusted"] is False
    assert ctx["eligibility_status"] == "INELIGIBLE"
    assert ctx["lifecycle_state"] == "REJECTED"
    assert ctx["ml_registered"] is False

    durable_evt = (
        db_session.query(BehavioralTrainingEvent)
        .filter(BehavioralTrainingEvent.event_id == event_id)
        .first()
    )
    assert durable_evt is not None
    assert durable_evt.lifecycle_state == "REJECTED"
    assert durable_evt.eligibility_status == "REJECTED"
    assert durable_evt.is_trusted == 0

    ModelManager.reset_memory()
    ModelManager.ensure_hydrated(db_session, user.id)
    assert len(ModelManager._user_training_data.get(user.id, [])) == 0


# ------------------------------------------------------------------------------
# 3. Crash Window & Honest Marker (D-02, D-03):
#    - BehaviorProfile, BehavioralTrainingEvent(PROCESSED), and BehaviorLog(PROCESSED)
#      commit in a single atomic transaction.
#    - If ModelManager registration fails/crashes after the durable commit,
#      ml_registered stays False (honest marker), while post-restart hydration and
#      subsequent retry recover the event without double-counting Welford stats!
# ------------------------------------------------------------------------------
def test_3_crash_after_durable_commit_before_model_manager_recovers_safely(db_session: Session):
    user = _create_isolated_user(db_session, "step447.crashrecover@cognisec.ai")
    sess_id = f"sess_step447_{user.id}"

    payload = BehaviorEventCreate(
        session_id=sess_id,
        application="E-Commerce Portal",
        typing_speed_wpm=65.0,
        avg_flight_time_ms=115.0,
        avg_dwell_time_ms=85.0,
        mouse_velocity_avg=420.0,
        mouse_acceleration_avg=540.0,
        mouse_curvature_entropy=1.25,
        click_frequency=0.85,
        scroll_speed_avg=180.0,
        idle_duration_sec=2.0,
        navigation_entropy=0.90,
        telemetry_nonce="nonce_crash_003",
    )
    log = BehaviorService.record_behavior_event(db_session, user.id, payload)
    event_id = f"nonce:{sess_id}:nonce_crash_003"

    # Simulate a crash/failure in ModelManager.register_trusted_vector right after DB commit
    orig_register = ModelManager.register_trusted_vector
    ModelManager.register_trusted_vector = classmethod(
        lambda cls, uid, vec, stats=None, event_id=None: cls.get_user_detector(uid)
    )
    try:
        profile = ProfileService.update_baseline_from_event(
            db=db_session,
            user_id=user.id,
            event_vector=FULL_ACTIVE_VEC,
            risk_score=0.08,
            session_status="ACTIVE",
            decision="ALLOW",
            event_id=event_id,
            behavior_log=log,
        )
    finally:
        ModelManager.register_trusted_vector = orig_register

    # 1. Durable state committed atomically in T3, but worker-local ml_registered is honestly False!
    assert profile.sample_count == 1
    db_session.refresh(log)
    ctx_after_crash = json.loads(log.raw_feature_json)
    assert ctx_after_crash["is_trusted"] is True
    assert ctx_after_crash["eligibility_status"] == "ELIGIBLE"
    assert ctx_after_crash["lifecycle_state"] == "PROCESSED"
    assert ctx_after_crash["ml_registered"] is False
    assert len(ModelManager._user_training_data.get(user.id, [])) == 0

    # 2. Post-restart hydration recovers the durable PROCESSED event even though ml_registered was False
    ModelManager.reset_memory()
    ModelManager.ensure_hydrated(db_session, user.id)
    assert len(ModelManager._user_training_data.get(user.id, [])) == 1
    np.testing.assert_allclose(ModelManager._user_training_data[user.id][0], FULL_ACTIVE_VEC, rtol=1e-6)

    # 3. Retry of the same event after crash does NOT double-count Welford baseline and sets ml_registered=True
    ModelManager.reset_memory()
    retried_profile = ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=FULL_ACTIVE_VEC,
        risk_score=0.08,
        session_status="ACTIVE",
        decision="ALLOW",
        event_id=event_id,
        behavior_log=log,
    )
    assert retried_profile.sample_count == 1
    assert len(ModelManager._user_training_data.get(user.id, [])) == 1
    db_session.refresh(log)
    ctx_after_retry = json.loads(log.raw_feature_json)
    assert ctx_after_retry["ml_registered"] is True
    assert ctx_after_retry["worker_hydrated"] is True


# ------------------------------------------------------------------------------
# 4. Stable Event Identity (D-02):
#    Retries with the same telemetry_nonce reuse the same BehaviorLog and
#    BehavioralTrainingEvent without creating duplicate rows or double-training.
# ------------------------------------------------------------------------------
def test_4_stable_telemetry_nonce_idempotency_across_retries(db_session: Session):
    user = _create_isolated_user(db_session, "step447.nonceidem@cognisec.ai")
    sess_id = f"sess_step447_{user.id}"

    payload = BehaviorEventCreate(
        session_id=sess_id,
        application="E-Commerce Portal",
        typing_speed_wpm=65.0,
        avg_flight_time_ms=115.0,
        avg_dwell_time_ms=85.0,
        mouse_velocity_avg=420.0,
        mouse_acceleration_avg=540.0,
        mouse_curvature_entropy=1.25,
        click_frequency=0.85,
        scroll_speed_avg=180.0,
        idle_duration_sec=2.0,
        navigation_entropy=0.90,
        telemetry_nonce="nonce_stable_447",
    )
    log1 = BehaviorService.record_behavior_event(db_session, user.id, payload)
    log2 = BehaviorService.record_behavior_event(db_session, user.id, payload)
    assert log1.id == log2.id

    event_id = BehaviorService.derive_event_id(payload, fallback_log_id=log1.id)
    assert event_id == f"nonce:{sess_id}:nonce_stable_447"

    p1 = ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=FULL_ACTIVE_VEC,
        risk_score=0.05,
        session_status="ACTIVE",
        decision="ALLOW",
        event_id=event_id,
        behavior_log=log1,
    )
    p2 = ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=FULL_ACTIVE_VEC * 1.10,
        risk_score=0.05,
        session_status="ACTIVE",
        decision="ALLOW",
        event_id=event_id,
        behavior_log=log2,
    )
    assert p1.sample_count == 1
    assert p2.sample_count == 1
    assert len(ModelManager._user_training_data[user.id]) == 1

    evt_count = (
        db_session.query(BehavioralTrainingEvent)
        .filter(BehavioralTrainingEvent.user_id == user.id)
        .count()
    )
    assert evt_count == 1


# ------------------------------------------------------------------------------
# 5. Retraining Beyond 100-Sample Buffer Cap (F-03C):
#    Verifies initial fit at 25, periodic retraining every 10 samples (35..95),
#    and continued retraining at 105 and 115 after the buffer caps at 100!
# ------------------------------------------------------------------------------
def test_5_retraining_continues_past_100_sample_buffer_cap(db_session: Session):
    user = _create_isolated_user(db_session, "step447.retrain115@cognisec.ai")
    rng = np.random.default_rng(123)

    expected_retrain_points = {25: 1, 35: 2, 45: 3, 55: 4, 65: 5, 75: 6, 85: 7, 95: 8, 105: 9, 115: 10}

    for i in range(1, 116):
        vec = np.clip(FULL_ACTIVE_VEC + rng.normal(0.0, 0.4, size=10), 0.1, None)
        detector = ModelManager.register_trusted_vector(
            user.id,
            vec,
            event_id=f"retrain_evt_{i}"
        )

        if i < 25:
            assert detector.is_fitted is False
            assert detector.retrain_count == 0
        elif i in expected_retrain_points:
            assert detector.is_fitted is True
            assert detector.retrain_count == expected_retrain_points[i], f"Failed at sample {i}"
            assert ModelManager._samples_since_retrain[user.id] == 0

        if i == 100:
            assert len(ModelManager._user_training_data[user.id]) == 100
            assert detector.retrain_count == 8
            assert ModelManager._samples_since_retrain[user.id] == 5
        elif i == 105:
            assert len(ModelManager._user_training_data[user.id]) == 100
            assert detector.retrain_count == 9
            assert ModelManager._samples_since_retrain[user.id] == 0
        elif i == 110:
            assert len(ModelManager._user_training_data[user.id]) == 100
            assert detector.retrain_count == 9
            assert ModelManager._samples_since_retrain[user.id] == 5
        elif i == 115:
            assert len(ModelManager._user_training_data[user.id]) == 100
            assert detector.retrain_count == 10
            assert ModelManager._samples_since_retrain[user.id] == 0
            assert ModelManager._cumulative_trusted_samples[user.id] == 115
            # Verify sliding window kept most recent 100 events (retrain_evt_16 .. retrain_evt_115)
            assert ModelManager._user_event_order[user.id][0] == "retrain_evt_16"
            assert ModelManager._user_event_order[user.id][-1] == "retrain_evt_115"


# ------------------------------------------------------------------------------
# 6. Failed Fit Preservation (F-03C & F-03D):
#    If IsolationForest.fit raises an exception during retraining, the previous
#    fitted estimator remains intact and _samples_since_retrain is NOT reset,
#    so the next sample retries retraining.
# ------------------------------------------------------------------------------
def test_6_failed_fit_preserves_prior_model_and_retries_on_next_sample(
    db_session: Session, monkeypatch
):
    user = _create_isolated_user(db_session, "step447.failedfit@cognisec.ai")
    rng = np.random.default_rng(77)

    for i in range(1, 35):
        vec = np.clip(FULL_ACTIVE_VEC + rng.normal(0.0, 0.3, size=10), 0.1, None)
        ModelManager.register_trusted_vector(user.id, vec, event_id=f"ff_evt_{i}")

    detector = ModelManager.get_user_detector(user.id)
    assert detector.is_fitted is True
    assert detector.retrain_count == 1
    assert ModelManager._samples_since_retrain[user.id] == 9
    prior_estimator = detector.model

    # Inject a transient failure into IsolationForest.fit for sample 35
    orig_if_fit = IsolationForest.fit

    def failing_if_fit(self, X, y=None, sample_weight=None):
        raise RuntimeError("Simulated sklearn IsolationForest.fit failure")

    monkeypatch.setattr(IsolationForest, "fit", failing_if_fit)
    vec35 = np.clip(FULL_ACTIVE_VEC + rng.normal(0.0, 0.3, size=10), 0.1, None)
    ModelManager.register_trusted_vector(user.id, vec35, event_id="ff_evt_35")

    # Previous model must still be fitted and intact, and counter must be 10 (not reset to 0)
    assert detector.is_fitted is True
    assert detector.model is prior_estimator
    assert detector.retrain_count == 1
    assert ModelManager._samples_since_retrain[user.id] == 10

    # Restore IsolationForest.fit and register sample 36 -> should immediately retry and succeed
    monkeypatch.setattr(IsolationForest, "fit", orig_if_fit)
    vec36 = np.clip(FULL_ACTIVE_VEC + rng.normal(0.0, 0.3, size=10), 0.1, None)
    ModelManager.register_trusted_vector(user.id, vec36, event_id="ff_evt_36")

    assert detector.is_fitted is True
    assert detector.model is not prior_estimator
    assert detector.retrain_count == 2
    assert ModelManager._samples_since_retrain[user.id] == 0


# ------------------------------------------------------------------------------
# 7. Deterministic Concurrency (F-03D):
#    Concurrent hydration, live vector registration, and anomaly prediction
#    preserve all historical + live vectors and never read a partially mutated model.
# ------------------------------------------------------------------------------
def test_7_concurrent_hydration_live_registration_and_prediction():
    db_seed = SessionLocal()
    try:
        user = _create_isolated_user(db_seed, "step447.concurrency@cognisec.ai")
        rng = np.random.default_rng(99)
        for i in range(25):
            vec = np.clip(FULL_ACTIVE_VEC + rng.normal(0.0, 0.3, size=10), 0.1, None)
            ProfileService.update_baseline_from_event(
                db=db_seed,
                user_id=user.id,
                event_vector=vec,
                risk_score=0.06,
                session_status="ACTIVE",
                decision="ALLOW",
                event_id=f"hist_conc_{i}",
            )
        profile = ProfileService.get_or_create_profile(db_seed, user.id)
        baseline_stats = ProfileService.get_profile_dict(profile)
        user_id = user.id
    finally:
        db_seed.close()

    # Reset memory so hydration must load the 25 historical events from DB
    ModelManager.reset_memory()
    barrier = threading.Barrier(3)
    errors = []
    prediction_results = []

    def worker_hydrate():
        db_h = SessionLocal()
        try:
            barrier.wait(timeout=5.0)
            ModelManager.ensure_hydrated(db_h, user_id, baseline_stats)
        except Exception as e:
            errors.append(e)
        finally:
            db_h.close()

    def worker_live_register():
        try:
            barrier.wait(timeout=5.0)
            for j in range(5):
                live_vec = FULL_ACTIVE_VEC * (1.0 + 0.01 * (j + 1))
                ModelManager.register_trusted_vector(
                    user_id,
                    live_vec,
                    baseline_stats,
                    event_id=f"live_conc_{j}",
                )
        except Exception as e:
            errors.append(e)

    def worker_predict():
        try:
            barrier.wait(timeout=5.0)
            det = ModelManager.get_user_detector(user_id)
            for _ in range(20):
                is_anom, score, status = det.predict_anomaly(
                    sample_vector=FULL_ACTIVE_VEC,
                    baseline_stats=baseline_stats,
                    sample_count=25,
                )
                prediction_results.append((is_anom, score, status))
        except Exception as e:
            errors.append(e)

    t1 = threading.Thread(target=worker_hydrate)
    t2 = threading.Thread(target=worker_live_register)
    t3 = threading.Thread(target=worker_predict)
    t1.start()
    t2.start()
    t3.start()
    t1.join(timeout=10.0)
    t2.join(timeout=10.0)
    t3.join(timeout=10.0)

    assert len(errors) == 0, f"Concurrent errors: {errors}"
    assert len(prediction_results) == 20
    for is_anom, score, status in prediction_results:
        assert isinstance(is_anom, bool)
        assert 0.0 <= score <= 1.0
        assert status == "ML_READY"

    # Both the 25 historical DB events and the 5 concurrent live events must be present (total 30)
    reg_ids = ModelManager.get_registered_event_ids(user_id)
    for i in range(25):
        assert f"hist_conc_{i}" in reg_ids
    for j in range(5):
        assert f"live_conc_{j}" in reg_ids
    assert len(ModelManager._user_training_data[user_id]) == 30
    assert ModelManager.get_user_detector(user_id).is_fitted is True


# ------------------------------------------------------------------------------
# 8. Multi-Worker Consistency (F-03F):
#    Worker A detects when durable training events were committed by Worker B,
#    catches up incrementally without duplicating events, and retrains at 35 samples.
# ------------------------------------------------------------------------------
def test_8_multi_worker_staleness_detection_and_incremental_catchup(db_session: Session):
    user = _create_isolated_user(db_session, "step447.multiworker@cognisec.ai")
    rng = np.random.default_rng(55)

    # Worker 1 processes 25 events
    for i in range(25):
        vec = np.clip(FULL_ACTIVE_VEC + rng.normal(0.0, 0.3, size=10), 0.1, None)
        ProfileService.update_baseline_from_event(
            db=db_session,
            user_id=user.id,
            event_vector=vec,
            risk_score=0.06,
            session_status="ACTIVE",
            decision="ALLOW",
            event_id=f"mw_evt_{i}",
        )

    # Simulate Worker 2 starting up and hydrating at 25 events
    ModelManager.reset_memory()
    detector_w2 = ModelManager.ensure_hydrated(db_session, user.id)
    assert detector_w2.is_fitted is True
    assert detector_w2.retrain_count == 1
    assert len(ModelManager._user_training_data[user.id]) == 25
    assert ModelManager.is_worker_stale(db_session, user.id) is False

    # Snapshot Worker 2's in-memory state, then let Worker 1 commit 10 more durable events (25..34)
    w2_vectors_snapshot = list(ModelManager._user_training_data[user.id])
    w2_order_snapshot = list(ModelManager._user_event_order[user.id])
    w2_reg_snapshot = set(ModelManager._registered_event_ids[user.id])
    w2_ver_snapshot = ModelManager._hydrated_profile_version[user.id]
    w2_cnt_snapshot = ModelManager._hydrated_sample_count[user.id]
    w2_wm_snapshot = ModelManager._hydrated_event_watermark[user.id]

    for i in range(25, 35):
        vec = np.clip(FULL_ACTIVE_VEC + rng.normal(0.0, 0.3, size=10), 0.1, None)
        ProfileService.update_baseline_from_event(
            db=db_session,
            user_id=user.id,
            event_vector=vec,
            risk_score=0.06,
            session_status="ACTIVE",
            decision="ALLOW",
            event_id=f"mw_evt_{i}",
        )

    # Restore Worker 2's pre-catchup memory state (still at 25 samples, retrain_count=1)
    ModelManager._user_training_data[user.id] = w2_vectors_snapshot
    ModelManager._user_event_order[user.id] = w2_order_snapshot
    ModelManager._registered_event_ids[user.id] = w2_reg_snapshot
    ModelManager._hydrated_profile_version[user.id] = w2_ver_snapshot
    ModelManager._hydrated_sample_count[user.id] = w2_cnt_snapshot
    ModelManager._hydrated_event_watermark[user.id] = w2_wm_snapshot
    ModelManager._samples_since_retrain[user.id] = 0
    detector_w2.retrain_count = 1
    detector_w2.trained_sample_count = 25

    # Worker 2 must detect that its local model is stale relative to durable DB state
    assert ModelManager.is_worker_stale(db_session, user.id) is True

    # Next request on Worker 2 calls ensure_hydrated -> incrementally catches up to 35 and retrains!
    ModelManager.ensure_hydrated(db_session, user.id)
    assert ModelManager.is_worker_stale(db_session, user.id) is False
    assert len(ModelManager._user_training_data[user.id]) == 35
    assert detector_w2.retrain_count == 2
    assert detector_w2.trained_sample_count == 35


# ------------------------------------------------------------------------------
# 9. Simulator Isolation & Registration Baseline (F-03G):
#    - Attack simulations use isolated simulator namespace and never pollute
#      production user models or buffers.
#    - Registration baseline enrollment uses canonical validation and idempotent event_id.
# ------------------------------------------------------------------------------
def test_9_simulator_isolation_and_registration_baseline_idempotency(db_session: Session):
    user = _create_isolated_user(db_session, "step447.simisolation@cognisec.ai")

    # 1. Enroll registration baseline twice -> idempotent (sample_count=1, buffer=1)
    sample_data = {
        "typing_speed_wpm": 64.0,
        "avg_flight_time_ms": 112.0,
        "avg_dwell_time_ms": 84.0,
        "mouse_velocity_avg": 410.0,
        "mouse_acceleration_avg": 530.0,
        "mouse_curvature_entropy": 1.20,
        "click_frequency": 0.80,
        "scroll_speed_avg": 170.0,
        "idle_duration_sec": 1.5,
        "navigation_entropy": 0.85,
    }
    p1 = ProfileService.enroll_registration_baseline(db_session, user.id, sample_data)
    p2 = ProfileService.enroll_registration_baseline(db_session, user.id, sample_data)
    assert p1.sample_count == 1
    assert p2.sample_count == 1
    assert len(ModelManager._user_training_data[user.id]) == 1
    assert f"registration_baseline:{user.id}" in ModelManager.get_registered_event_ids(user.id)

    # 2. Simulate attack evaluation via RiskService with sim_ session and simulated=True
    sim_vec = np.array([290.0, 12.0, 15.0, 3400.0, 8900.0, 0.05, 18.5, 2400.0, 0.1, 4.2], dtype=np.float64)
    RiskService.calculate_risk(
        db=db_session,
        user_id=user.id,
        session_id="sim_attack_999",
        application="E-Commerce Portal",
        behavior_vector=sim_vec,
        context_signals={"simulated": True, "request_flood": True, "rapid_click_burst": True},
    )

    # Production training buffer and registered event IDs must remain completely untouched
    assert len(ModelManager._user_training_data[user.id]) == 1
    assert ModelManager.get_registered_event_ids(user.id) == {f"registration_baseline:{user.id}"}

