"""
backend/tests/test_step4_4_9_multi_worker_hydration.py

Phase II, Step 4.4.9 — Multi-Worker ML Hydration and Event Consistency Remediation.

Test suite covering:
1. Hydration with more than 1,000 durable events.
2. Pagination while new events are being committed.
3. Failure halfway through a hydration batch.
4. Retry after partial hydration without duplicate model registration.
5. Watermark preservation after hydration failure.
6. Two workers receiving out-of-order committed events.
7. Worker restart with an empty in-memory model.
8. Concurrent identical-nonce requests using separate database sessions.
9. A duplicate request after the original event is already PROCESSED.
10. An unrelated database IntegrityError still propagates correctly.
11. Existing simulator namespace isolation.
12. Existing training eligibility and feature-vector integrity.
"""

import json
import time
import threading
import concurrent.futures
from datetime import datetime, timezone
import numpy as np
import pytest
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from fastapi.testclient import TestClient

from app.database.connection import SessionLocal
from app.models.user import User
from app.models.session import Session as DbSession
from app.models.behavior import BehaviorLog, BehaviorProfile, BehavioralTrainingEvent
from app.schemas.behavior import BehaviorEventCreate
from app.services.behavior_service import BehaviorService
from app.services.profile_service import ProfileService
from app.core.security import get_password_hash
from app.ml.model_manager import ModelManager
from app.ml.anomaly_detector import IsolationForestDetector
from app.ml.feature_engineering import FeatureEngineering, FEATURE_NAMES
from app.main import app

client = TestClient(app)

FULL_ACTIVE_VEC = np.array(
    [45.0, 110.0, 85.0, 420.0, 1200.0, 0.45, 1.8, 220.0, 0.8, 3.2],
    dtype=np.float64
)

ACTIVE_OBSERVED_MODALITIES = {
    "keystroke": True,
    "mouse": True,
    "scroll": True,
    "timing": True
}


def _create_isolated_user(db: Session, email: str) -> User:
    user = db.query(User).filter(User.email == email).first()
    if user:
        db.query(BehavioralTrainingEvent).filter(BehavioralTrainingEvent.user_id == user.id).delete()
        db.query(BehaviorLog).filter(BehaviorLog.user_id == user.id).delete()
        db.query(BehaviorProfile).filter(BehaviorProfile.user_id == user.id).delete()
        db.commit()
    else:
        user = User(
            name="Step 4.4.9 Test User",
            email=email,
            password_hash=get_password_hash("ValidPass123!"),
            role="USER",
            account_status="ACTIVE",
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    return user


@pytest.fixture(autouse=True)
def clean_memory():
    ModelManager.reset_memory()
    yield
    ModelManager.reset_memory()


# ------------------------------------------------------------------------------
# 1. Hydration with more than 1,000 durable events (L-01)
# ------------------------------------------------------------------------------
def test_1_hydration_with_more_than_1000_durable_events(db_session: Session):
    user = _create_isolated_user(db_session, "step449.over1000@cognisec.ai")
    now_utc = datetime.now(timezone.utc)
    rng = np.random.default_rng(1001)

    # Insert 1,050 durable eligible BehavioralTrainingEvent records
    TOTAL_EVENTS = 1050
    events_to_add = []
    for i in range(TOTAL_EVENTS):
        vec = np.clip(FULL_ACTIVE_VEC + rng.normal(0.0, 0.2, size=10), 0.1, None)
        events_to_add.append(BehavioralTrainingEvent(
            event_id=f"bulk_evt_{user.id}_{i}",
            user_id=user.id,
            session_id=f"sess_bulk_{i}",
            lifecycle_state="PROCESSED",
            eligibility_status="ELIGIBLE",
            is_trusted=1,
            profile_version=i + 1,
            raw_vector_json=json.dumps([float(x) for x in vec]),
            training_vector_json=json.dumps([float(x) for x in vec]),
            observed_features_json=json.dumps({feat: True for feat in FEATURE_NAMES}),
            created_at=now_utc,
            updated_at=now_utc
        ))

    db_session.bulk_save_objects(events_to_add)
    db_session.commit()

    # Hydrate on a fresh worker
    detector = ModelManager.ensure_hydrated(db_session, user.id)

    # Keyset pagination must handle all 1,050 records in bounded batches
    assert detector.is_fitted is True
    assert len(ModelManager._user_training_data[user.id]) == ModelManager.MAX_HYDRATION_RECORDS  # Capped at 100
    assert ModelManager._hydrated_event_watermark[user.id] >= TOTAL_EVENTS
    assert ModelManager.is_worker_stale(db_session, user.id) is False


# ------------------------------------------------------------------------------
# 2. Pagination while new events are being committed (L-01)
# ------------------------------------------------------------------------------
def test_2_pagination_while_new_events_committed(db_session: Session):
    user = _create_isolated_user(db_session, "step449.livecommits@cognisec.ai")
    now_utc = datetime.now(timezone.utc)
    rng = np.random.default_rng(2002)

    # Initial batch of 120 events
    for i in range(120):
        vec = np.clip(FULL_ACTIVE_VEC + rng.normal(0.0, 0.2, size=10), 0.1, None)
        db_session.add(BehavioralTrainingEvent(
            event_id=f"live_p1_{user.id}_{i}",
            user_id=user.id,
            session_id=f"sess_live_{i}",
            lifecycle_state="PROCESSED",
            eligibility_status="ELIGIBLE",
            is_trusted=1,
            profile_version=i + 1,
            raw_vector_json=json.dumps([float(x) for x in vec]),
            training_vector_json=json.dumps([float(x) for x in vec]),
            observed_features_json=json.dumps({feat: True for feat in FEATURE_NAMES}),
            created_at=now_utc,
            updated_at=now_utc
        ))
    db_session.commit()

    # First hydration: covers 120 events
    ModelManager.ensure_hydrated(db_session, user.id)
    wm1 = ModelManager._hydrated_event_watermark[user.id]

    # While system is running, 40 new events are committed
    for i in range(120, 160):
        vec = np.clip(FULL_ACTIVE_VEC + rng.normal(0.0, 0.2, size=10), 0.1, None)
        db_session.add(BehavioralTrainingEvent(
            event_id=f"live_p2_{user.id}_{i}",
            user_id=user.id,
            session_id=f"sess_live_{i}",
            lifecycle_state="PROCESSED",
            eligibility_status="ELIGIBLE",
            is_trusted=1,
            profile_version=i + 1,
            raw_vector_json=json.dumps([float(x) for x in vec]),
            training_vector_json=json.dumps([float(x) for x in vec]),
            observed_features_json=json.dumps({feat: True for feat in FEATURE_NAMES}),
            created_at=now_utc,
            updated_at=now_utc
        ))
    db_session.commit()

    # Worker detects new events
    assert ModelManager.is_worker_stale(db_session, user.id) is True

    # Next hydration catches up seamlessly
    ModelManager.ensure_hydrated(db_session, user.id)
    wm2 = ModelManager._hydrated_event_watermark[user.id]
    assert wm2 > wm1
    assert ModelManager.is_worker_stale(db_session, user.id) is False


# ------------------------------------------------------------------------------
# 3. Failure halfway through a hydration batch (L-02)
# ------------------------------------------------------------------------------
def test_3_failure_halfway_through_hydration_batch(db_session: Session, monkeypatch):
    user = _create_isolated_user(db_session, "step449.batchfail3@cognisec.ai")
    now_utc = datetime.now(timezone.utc)
    rng = np.random.default_rng(3003)

    for i in range(25):
        vec = np.clip(FULL_ACTIVE_VEC + rng.normal(0.0, 0.2, size=10), 0.1, None)
        db_session.add(BehavioralTrainingEvent(
            event_id=f"f3_init_{user.id}_{i}",
            user_id=user.id,
            session_id=f"sess_f3_{i}",
            lifecycle_state="PROCESSED",
            eligibility_status="ELIGIBLE",
            is_trusted=1,
            profile_version=i + 1,
            raw_vector_json=json.dumps([float(x) for x in vec]),
            training_vector_json=json.dumps([float(x) for x in vec]),
            observed_features_json=json.dumps({feat: True for feat in FEATURE_NAMES}),
            created_at=now_utc,
            updated_at=now_utc
        ))
    db_session.commit()

    detector = ModelManager.ensure_hydrated(db_session, user.id)
    assert detector.is_fitted is True

    # Inject failure during next query
    orig_query = db_session.query
    query_call_count = {"count": 0}

    def failing_query(*args, **kwargs):
        query_call_count["count"] += 1
        if len(args) == 1 and args[0] is BehavioralTrainingEvent and query_call_count["count"] > 1:
            raise RuntimeError("Simulated mid-batch database error")
        return orig_query(*args, **kwargs)

    monkeypatch.setattr(db_session, "query", failing_query)

    det_after = ModelManager.ensure_hydrated(db_session, user.id)
    assert det_after is detector
    assert det_after.is_fitted is True  # Prior operational model preserved!


# ------------------------------------------------------------------------------
# 4. Retry after partial hydration without duplicate model registration (L-02)
# ------------------------------------------------------------------------------
def test_4_retry_after_partial_hydration_without_duplicate_registration(db_session: Session, monkeypatch):
    user = _create_isolated_user(db_session, "step449.retry4@cognisec.ai")
    now_utc = datetime.now(timezone.utc)
    rng = np.random.default_rng(4004)

    for i in range(25):
        vec = np.clip(FULL_ACTIVE_VEC + rng.normal(0.0, 0.2, size=10), 0.1, None)
        db_session.add(BehavioralTrainingEvent(
            event_id=f"r4_init_{user.id}_{i}",
            user_id=user.id,
            session_id=f"sess_r4_{i}",
            lifecycle_state="PROCESSED",
            eligibility_status="ELIGIBLE",
            is_trusted=1,
            profile_version=i + 1,
            raw_vector_json=json.dumps([float(x) for x in vec]),
            training_vector_json=json.dumps([float(x) for x in vec]),
            observed_features_json=json.dumps({feat: True for feat in FEATURE_NAMES}),
            created_at=now_utc,
            updated_at=now_utc
        ))
    db_session.commit()

    ModelManager.ensure_hydrated(db_session, user.id)

    # Add 10 new events
    for i in range(25, 35):
        vec = np.clip(FULL_ACTIVE_VEC + rng.normal(0.0, 0.2, size=10), 0.1, None)
        db_session.add(BehavioralTrainingEvent(
            event_id=f"r4_new_{user.id}_{i}",
            user_id=user.id,
            session_id=f"sess_r4_{i}",
            lifecycle_state="PROCESSED",
            eligibility_status="ELIGIBLE",
            is_trusted=1,
            profile_version=i + 1,
            raw_vector_json=json.dumps([float(x) for x in vec]),
            training_vector_json=json.dumps([float(x) for x in vec]),
            observed_features_json=json.dumps({feat: True for feat in FEATURE_NAMES}),
            created_at=now_utc,
            updated_at=now_utc
        ))
    db_session.commit()

    # Transient failure on first attempt
    orig_query = db_session.query
    query_call_count = {"count": 0}

    def failing_query(*args, **kwargs):
        query_call_count["count"] += 1
        if len(args) == 1 and args[0] is BehavioralTrainingEvent and query_call_count["count"] > 1:
            raise RuntimeError("Transient connection drop")
        return orig_query(*args, **kwargs)

    monkeypatch.setattr(db_session, "query", failing_query)
    ModelManager.ensure_hydrated(db_session, user.id)

    # Undo failure and retry
    monkeypatch.undo()
    ModelManager.ensure_hydrated(db_session, user.id)

    # Must have exactly 35 distinct registered events, zero duplicates
    assert len(ModelManager._user_training_data[user.id]) == 35
    assert len(ModelManager._registered_event_ids[user.id]) == 35


# ------------------------------------------------------------------------------
# 5. Watermark preservation after hydration failure (L-02)
# ------------------------------------------------------------------------------
def test_5_watermark_preservation_after_hydration_failure(db_session: Session, monkeypatch):
    user = _create_isolated_user(db_session, "step449.wmpres5@cognisec.ai")
    now_utc = datetime.now(timezone.utc)
    rng = np.random.default_rng(5005)

    for i in range(20):
        vec = np.clip(FULL_ACTIVE_VEC + rng.normal(0.0, 0.2, size=10), 0.1, None)
        db_session.add(BehavioralTrainingEvent(
            event_id=f"w5_init_{user.id}_{i}",
            user_id=user.id,
            session_id=f"sess_w5_{i}",
            lifecycle_state="PROCESSED",
            eligibility_status="ELIGIBLE",
            is_trusted=1,
            profile_version=i + 1,
            raw_vector_json=json.dumps([float(x) for x in vec]),
            training_vector_json=json.dumps([float(x) for x in vec]),
            observed_features_json=json.dumps({feat: True for feat in FEATURE_NAMES}),
            created_at=now_utc,
            updated_at=now_utc
        ))
    db_session.commit()

    ModelManager.ensure_hydrated(db_session, user.id)
    initial_wm = ModelManager._hydrated_event_watermark[user.id]
    initial_cnt = ModelManager._hydrated_sample_count[user.id]
    initial_ver = ModelManager._hydrated_profile_version[user.id]

    # Commit 10 more events
    for i in range(20, 30):
        vec = np.clip(FULL_ACTIVE_VEC + rng.normal(0.0, 0.2, size=10), 0.1, None)
        db_session.add(BehavioralTrainingEvent(
            event_id=f"w5_more_{user.id}_{i}",
            user_id=user.id,
            session_id=f"sess_w5_{i}",
            lifecycle_state="PROCESSED",
            eligibility_status="ELIGIBLE",
            is_trusted=1,
            profile_version=i + 1,
            raw_vector_json=json.dumps([float(x) for x in vec]),
            training_vector_json=json.dumps([float(x) for x in vec]),
            observed_features_json=json.dumps({feat: True for feat in FEATURE_NAMES}),
            created_at=now_utc,
            updated_at=now_utc
        ))
    db_session.commit()

    # Induce failure
    orig_query = db_session.query
    query_call_count = {"count": 0}

    def failing_query(*args, **kwargs):
        query_call_count["count"] += 1
        if len(args) == 1 and args[0] is BehavioralTrainingEvent and query_call_count["count"] > 1:
            raise RuntimeError("Simulated failure")
        return orig_query(*args, **kwargs)

    monkeypatch.setattr(db_session, "query", failing_query)
    ModelManager.ensure_hydrated(db_session, user.id)

    # Watermarks must remain strictly unchanged!
    assert ModelManager._hydrated_event_watermark[user.id] == initial_wm
    assert ModelManager._hydrated_sample_count[user.id] == initial_cnt
    assert ModelManager._hydrated_profile_version[user.id] == initial_ver


# ------------------------------------------------------------------------------
# 6. Two workers receiving out-of-order committed events (L-03)
# ------------------------------------------------------------------------------
def test_6_out_of_order_committed_events_between_two_workers(db_session: Session):
    user = _create_isolated_user(db_session, "step449.ooo@cognisec.ai")
    now_utc = datetime.now(timezone.utc)
    rng = np.random.default_rng(6006)

    # Worker 1 processes event with ID = 2 first
    vec_2 = np.clip(FULL_ACTIVE_VEC + rng.normal(0.0, 0.2, size=10), 0.1, None)
    evt_2 = BehavioralTrainingEvent(
        event_id=f"ooo_evt_2_{user.id}",
        user_id=user.id,
        session_id="sess_ooo_2",
        lifecycle_state="PROCESSED",
        eligibility_status="ELIGIBLE",
        is_trusted=1,
        profile_version=2,
        raw_vector_json=json.dumps([float(x) for x in vec_2]),
        training_vector_json=json.dumps([float(x) for x in vec_2]),
        observed_features_json=json.dumps({feat: True for feat in FEATURE_NAMES}),
        created_at=now_utc,
        updated_at=now_utc
    )
    db_session.add(evt_2)
    db_session.commit()
    db_session.refresh(evt_2)

    # Worker 1 hydrates Event 2
    ModelManager.ensure_hydrated(db_session, user.id)
    assert f"ooo_evt_2_{user.id}" in ModelManager.get_registered_event_ids(user.id)
    w1_reg_ids_initial = set(ModelManager.get_registered_event_ids(user.id))

    # Worker 2 concurrently commits Event with earlier ID = 1 (or out-of-order)
    vec_1 = np.clip(FULL_ACTIVE_VEC + rng.normal(0.0, 0.2, size=10), 0.1, None)
    evt_1 = BehavioralTrainingEvent(
        event_id=f"ooo_evt_1_{user.id}",
        user_id=user.id,
        session_id="sess_ooo_1",
        lifecycle_state="PROCESSED",
        eligibility_status="ELIGIBLE",
        is_trusted=1,
        profile_version=1,
        raw_vector_json=json.dumps([float(x) for x in vec_1]),
        training_vector_json=json.dumps([float(x) for x in vec_1]),
        observed_features_json=json.dumps({feat: True for feat in FEATURE_NAMES}),
        created_at=now_utc,
        updated_at=now_utc
    )
    db_session.add(evt_1)
    # Also update profile to reflect total count of 2
    profile = ProfileService.get_or_create_profile(db_session, user.id)
    profile.sample_count = 2
    profile.profile_version = 3
    db_session.commit()

    # Worker 1 must detect that it is stale because an earlier out-of-order event is missing!
    assert ModelManager.is_worker_stale(db_session, user.id) is True

    # Worker 1 hydrates again: must NOT skip evt_1 even though evt_2 was already registered!
    ModelManager.ensure_hydrated(db_session, user.id)
    w1_reg_ids_final = ModelManager.get_registered_event_ids(user.id)

    assert f"ooo_evt_1_{user.id}" in w1_reg_ids_final
    assert f"ooo_evt_2_{user.id}" in w1_reg_ids_final
    assert len(w1_reg_ids_final) == 2
    assert ModelManager.is_worker_stale(db_session, user.id) is False


# ------------------------------------------------------------------------------
# 7. Worker restart with an empty in-memory model (L-01 / L-02)
# ------------------------------------------------------------------------------
def test_7_worker_restart_with_empty_memory(db_session: Session):
    user = _create_isolated_user(db_session, "step449.restart@cognisec.ai")
    now_utc = datetime.now(timezone.utc)
    rng = np.random.default_rng(7007)

    # Populate 30 durable events in database
    for i in range(30):
        vec = np.clip(FULL_ACTIVE_VEC + rng.normal(0.0, 0.2, size=10), 0.1, None)
        db_session.add(BehavioralTrainingEvent(
            event_id=f"restart_evt_{user.id}_{i}",
            user_id=user.id,
            session_id=f"sess_rst_{i}",
            lifecycle_state="PROCESSED",
            eligibility_status="ELIGIBLE",
            is_trusted=1,
            profile_version=i + 1,
            raw_vector_json=json.dumps([float(x) for x in vec]),
            training_vector_json=json.dumps([float(x) for x in vec]),
            observed_features_json=json.dumps({feat: True for feat in FEATURE_NAMES}),
            created_at=now_utc,
            updated_at=now_utc
        ))
    db_session.commit()

    # Simulate fresh worker process boot
    ModelManager.reset_memory()
    assert len(ModelManager._user_training_data) == 0

    # Ensure hydration reconstructs model
    detector = ModelManager.ensure_hydrated(db_session, user.id)
    assert detector.is_fitted is True
    assert len(ModelManager._user_training_data[user.id]) == 30
    assert len(ModelManager._registered_event_ids[user.id]) == 30


# ------------------------------------------------------------------------------
# 8. Concurrent identical-nonce requests using separate DB sessions (L-04)
# ------------------------------------------------------------------------------
def test_8_concurrent_identical_nonce_requests():
    db_main = SessionLocal()
    try:
        user = _create_isolated_user(db_main, "step449.concurrentnonce@cognisec.ai")
        # Create an active session
        session = DbSession(
            id="sess_step449_concurrent",
            user_id=user.id,
            application="PORTAL",
            status="ACTIVE",
            login_time=datetime.now(timezone.utc)
        )
        db_main.add(session)
        db_main.commit()
        db_main.refresh(session)
        session_id = session.id
        user_id = int(user.id)
    finally:
        db_main.close()

    event_data = BehaviorEventCreate(
        session_id=session_id,
        application="PORTAL",
        telemetry_nonce="concurrent_nonce_abc123",
        typing_speed_wpm=45.0,
        avg_flight_time_ms=110.0,
        avg_dwell_time_ms=85.0,
        mouse_velocity_avg=420.0,
        mouse_acceleration_avg=1200.0,
        mouse_curvature_entropy=0.45,
        click_frequency=1.8,
        scroll_speed_avg=220.0,
        idle_duration_sec=0.8,
        navigation_entropy=3.2,
        observed_modalities=ACTIVE_OBSERVED_MODALITIES,
        context_signals={"sample_counts": {"clicks": 3, "keystrokes": 12}}
    )

    results = []
    errors = []

    def submit_task():
        db = SessionLocal()
        try:
            log = BehaviorService.record_behavior_event(db, user_id, event_data)
            results.append(log.id)
        except Exception as e:
            errors.append(e)
        finally:
            db.close()

    # Launch two genuinely concurrent threads submitting the exact same nonce and session
    t1 = threading.Thread(target=submit_task)
    t2 = threading.Thread(target=submit_task)

    t1.start()
    t2.start()

    t1.join()
    t2.join()

    # Neither request must crash with an unhandled exception
    assert len(errors) == 0, f"Concurrent submission failed: {errors}"
    assert len(results) == 2

    # Exactly one BehavioralTrainingEvent row must exist in the database for this event_id
    db_verify = SessionLocal()
    try:
        canonical_id = f"nonce:{session_id}:concurrent_nonce_abc123"
        evts = db_verify.query(BehavioralTrainingEvent).filter(
            BehavioralTrainingEvent.event_id == canonical_id
        ).all()
        assert len(evts) == 1
    finally:
        db_verify.close()


# ------------------------------------------------------------------------------
# 9. A duplicate request after the original event is already PROCESSED (L-04)
# ------------------------------------------------------------------------------
def test_9_duplicate_request_after_already_processed(db_session: Session):
    user = _create_isolated_user(db_session, "step449.dup_processed@cognisec.ai")
    session = DbSession(
        id="sess_step449_dup_proc",
        user_id=user.id,
        application="PORTAL",
        status="ACTIVE",
        login_time=datetime.now(timezone.utc)
    )
    db_session.add(session)
    db_session.commit()
    db_session.refresh(session)

    canonical_event_id = f"nonce:{session.id}:processed_nonce_999"

    # Pre-populate event in PROCESSED state
    now_utc = datetime.now(timezone.utc)
    log = BehaviorLog(
        user_id=user.id,
        session_id=session.id,
        timestamp=now_utc,
        application="PORTAL",
        typing_speed_wpm=45.0,
        mouse_velocity_avg=420.0,
        raw_feature_json=json.dumps({
            "event_id": canonical_event_id,
            "decision": "ALLOW",
            "risk_score": 0.05,
            "anomaly_score": 0.02,
            "risk_level": "LOW",
            "session_status": "ACTIVE",
            "is_trusted": True
        })
    )
    db_session.add(log)
    db_session.flush()

    evt = BehavioralTrainingEvent(
        event_id=canonical_event_id,
        user_id=user.id,
        session_id=session.id,
        behavior_log_id=log.id,
        lifecycle_state="PROCESSED",
        eligibility_status="ELIGIBLE",
        is_trusted=1,
        profile_version=1,
        raw_vector_json=json.dumps([float(x) for x in FULL_ACTIVE_VEC]),
        training_vector_json=json.dumps([float(x) for x in FULL_ACTIVE_VEC]),
        observed_features_json=json.dumps({feat: True for feat in FEATURE_NAMES}),
        created_at=now_utc,
        updated_at=now_utc
    )
    db_session.add(evt)
    db_session.commit()

    # Now simulate duplicate submission of the already-processed event
    duplicate_data = BehaviorEventCreate(
        session_id=session.id,
        application="PORTAL",
        telemetry_nonce="processed_nonce_999",
        typing_speed_wpm=45.0,
        avg_flight_time_ms=110.0,
        avg_dwell_time_ms=85.0,
        mouse_velocity_avg=420.0,
        mouse_acceleration_avg=1200.0,
        mouse_curvature_entropy=0.45,
        click_frequency=1.8,
        scroll_speed_avg=220.0,
        idle_duration_sec=0.8,
        navigation_entropy=3.2,
        observed_modalities=ACTIVE_OBSERVED_MODALITIES
    )

    returned_log = BehaviorService.record_behavior_event(db_session, user.id, duplicate_data)
    assert returned_log.id == log.id

    # BehavioralTrainingEvent must remain exactly 1 row, in PROCESSED state
    evts = db_session.query(BehavioralTrainingEvent).filter(
        BehavioralTrainingEvent.event_id == canonical_event_id
    ).all()
    assert len(evts) == 1
    assert evts[0].lifecycle_state == "PROCESSED"


# ------------------------------------------------------------------------------
# 10. An unrelated database IntegrityError still propagates correctly (L-04)
# ------------------------------------------------------------------------------
def test_10_unrelated_integrity_error_propagates(db_session: Session):
    # Pass non-existent user_id (e.g. 9999999) to violate foreign key constraint
    invalid_data = BehaviorEventCreate(
        session_id="sess_fk_viol",
        application="PORTAL",
        telemetry_nonce="nonce_fk_viol",
        typing_speed_wpm=45.0,
        avg_flight_time_ms=110.0,
        avg_dwell_time_ms=85.0,
        mouse_velocity_avg=420.0,
        mouse_acceleration_avg=1200.0,
        mouse_curvature_entropy=0.45,
        click_frequency=1.8,
        scroll_speed_avg=220.0,
        idle_duration_sec=0.8,
        navigation_entropy=3.2,
        observed_modalities=ACTIVE_OBSERVED_MODALITIES
    )

    with pytest.raises(IntegrityError):
        BehaviorService.record_behavior_event(db_session, user_id=99999999, event_data=invalid_data)


# ------------------------------------------------------------------------------
# 11. Existing simulator namespace isolation (F-03G)
# ------------------------------------------------------------------------------
def test_11_simulator_isolation(db_session: Session):
    user = _create_isolated_user(db_session, "step449.simiso@cognisec.ai")
    now_utc = datetime.now(timezone.utc)

    # Insert a simulated event
    db_session.add(BehavioralTrainingEvent(
        event_id=f"sim_evt_{user.id}_1",
        user_id=user.id,
        session_id="sim_attack_session",
        lifecycle_state="PROCESSED",
        eligibility_status="ELIGIBLE",
        is_trusted=1,
        profile_version=1,
        raw_vector_json=json.dumps([float(x) for x in FULL_ACTIVE_VEC]),
        training_vector_json=json.dumps([float(x) for x in FULL_ACTIVE_VEC]),
        observed_features_json=json.dumps({feat: True for feat in FEATURE_NAMES}),
        created_at=now_utc,
        updated_at=now_utc
    ))
    db_session.commit()

    # Hydrate in simulator namespace
    sim_detector = ModelManager.ensure_hydrated(db_session, user.id, namespace="simulator")
    assert sim_detector is not None

    # Production memory must remain completely clean
    assert user.id not in ModelManager._user_training_data
    assert user.id not in ModelManager._registered_event_ids


# ------------------------------------------------------------------------------
# 12. Existing training eligibility and feature-vector integrity
# ------------------------------------------------------------------------------
def test_12_training_eligibility_and_vector_integrity():
    # 9-dimensional vector must be rejected
    invalid_9d = np.array([45.0, 110.0, 85.0, 420.0, 1200.0, 0.45, 1.8, 220.0, 0.8], dtype=np.float64)
    is_valid, err = FeatureEngineering.validate_vector(invalid_9d)
    assert is_valid is False
    assert "10 dimensions" in str(err)

    # Vector containing NaN must be rejected
    nan_vec = FULL_ACTIVE_VEC.copy()
    nan_vec[0] = np.nan
    is_valid, err = FeatureEngineering.validate_vector(nan_vec)
    assert is_valid is False

    # Untrusted / high-risk event must be rejected from training
    is_eligible, reason, resolved = FeatureEngineering.evaluate_training_eligibility(
        event_vector=FULL_ACTIVE_VEC,
        user_id=1,
        event_user_id=1,
        is_trusted=False,
        session_status="ACTIVE",
        prior_session_status="ACTIVE",
        decision="ALLOW",
        risk_score=0.85,
        is_anomaly=True,
        anomaly_score=0.90,
        anti_replay_verified=True,
        observed_modalities=ACTIVE_OBSERVED_MODALITIES,
        event_id="malicious_evt"
    )
    assert is_eligible is False
    assert resolved is None
