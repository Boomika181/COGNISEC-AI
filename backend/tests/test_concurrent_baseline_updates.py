import json
import math
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import numpy as np
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from app.main import app
from app.database.connection import SessionLocal, get_db, get_simulator_db, simulator_engine
from app.services.profile_service import ProfileService
from app.services.session_service import SessionService
from app.ml.feature_engineering import FeatureEngineering, FEATURE_NAMES
from app.ml.model_manager import ModelManager
from app.models.user import User
from app.models.behavior import BehaviorProfile
from app.core.security import get_password_hash, create_access_token
from app.core.config import settings


def compute_independent_welford_sequence(vectors_and_modalities):
    """
    Independently computes exact Welford means, M2, stds (with sigma floors),
    and per-feature sample counts for a sequence of (vector, observed_features) pairs.
    """
    means = {feat: 0.0 for feat in FEATURE_NAMES}
    m2 = {feat: 0.0 for feat in FEATURE_NAMES}
    stds = {feat: float(settings.FEATURE_MIN_SIGMA.get(feat, 1.0)) for feat in FEATURE_NAMES}
    counts = {feat: 0 for feat in FEATURE_NAMES}

    for vec, obs in vectors_and_modalities:
        for idx, feat in enumerate(FEATURE_NAMES):
            if not obs.get(feat, False):
                continue
            counts[feat] += 1
            n_feat = counts[feat]
            x = float(vec[idx])
            sigma_floor = float(settings.FEATURE_MIN_SIGMA.get(feat, 1.0))
            if n_feat == 1:
                new_mean = x
                new_m2 = 0.0
                new_std = sigma_floor
            else:
                delta = x - means[feat]
                new_mean = means[feat] + delta / n_feat
                delta2 = x - new_mean
                new_m2 = m2[feat] + delta * delta2
                sample_var = new_m2 / (n_feat - 1)
                new_std = max(sigma_floor, math.sqrt(max(1e-6, sample_var)))
            # Match ProfileService per-step rounding
            means[feat] = round(new_mean, 4)
            m2[feat] = round(new_m2, 4)
            stds[feat] = round(new_std, 4)

    return means, m2, stds, counts


def _create_isolated_user(db: Session, email: str) -> User:
    user = db.query(User).filter(User.email == email).first()
    if user:
        db.query(BehaviorProfile).filter(BehaviorProfile.user_id == user.id).delete()
        db.commit()
    else:
        user = User(
            name="Concurrency Test User",
            email=email,
            password_hash=get_password_hash("ValidPass123!"),
            role="USER",
            account_status="ACTIVE",
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    ModelManager.reset_memory()
    return user


# -----------------------------------------------------------------------------
# 1 & 7. Two simultaneous updates to the same profile + exact Welford verification
# -----------------------------------------------------------------------------
def test_two_simultaneous_updates_preserve_both_and_match_exact_welford(db_session: Session):
    user = _create_isolated_user(db_session, "conc.simul@cognisec.ai")

    # Seed 3 initial full observations so Welford variance is active
    seed_vecs = [
        np.array([60.0, 110.0, 80.0, 400.0, 500.0, 1.10, 0.6, 150.0, 1.5, 0.70], dtype=np.float64),
        np.array([64.0, 115.0, 84.0, 420.0, 530.0, 1.20, 0.8, 170.0, 1.8, 0.80], dtype=np.float64),
        np.array([68.0, 120.0, 88.0, 440.0, 560.0, 1.30, 1.0, 190.0, 2.1, 0.90], dtype=np.float64),
    ]
    for v in seed_vecs:
        ProfileService.update_baseline_from_event(
            db=db_session,
            user_id=user.id,
            event_vector=v,
            risk_score=0.10,
            session_status="ACTIVE",
            decision="ALLOW",
        )

    vec_a = np.array([72.0, 105.0, 78.0, 460.0, 590.0, 1.40, 1.2, 210.0, 2.4, 1.00], dtype=np.float64)
    vec_b = np.array([76.0, 100.0, 75.0, 480.0, 620.0, 1.50, 1.4, 230.0, 2.7, 1.10], dtype=np.float64)

    start_barrier = threading.Barrier(2)
    target_user_id = int(user.id)

    def worker_update(vec):
        local_db = SessionLocal()
        try:
            start_barrier.wait(timeout=5.0)
            return ProfileService.update_baseline_from_event(
                db=local_db,
                user_id=target_user_id,
                event_vector=vec,
                risk_score=0.10,
                session_status="ACTIVE",
                decision="ALLOW",
            )
        finally:
            local_db.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(worker_update, vec_a)
        f2 = pool.submit(worker_update, vec_b)
        f1.result()
        f2.result()

    db_session.expire_all()
    profile = ProfileService.get_or_create_profile(db_session, user.id)
    persisted = ProfileService.get_profile_dict(profile)

    # Global sample count and profile_version must reflect all 5 updates (initial version=1 + 5 updates = 6)
    assert profile.sample_count == 5
    assert profile.profile_version == 6
    assert persisted["sample_count"] == 5

    # Compute exact expected Welford statistics for both orderings (A then B, or B then A)
    all_obs_a = [(v, FeatureEngineering.resolve_observed_features(v)) for v in (seed_vecs + [vec_a, vec_b])]
    all_obs_b = [(v, FeatureEngineering.resolve_observed_features(v)) for v in (seed_vecs + [vec_b, vec_a])]
    means_ab, m2_ab, stds_ab, counts_ab = compute_independent_welford_sequence(all_obs_a)
    means_ba, m2_ba, stds_ba, counts_ba = compute_independent_welford_sequence(all_obs_b)

    for feat in FEATURE_NAMES:
        assert persisted["sample_counts"][feat] == 5
        assert persisted["feature_sample_counts"][feat] == 5
        assert persisted["means"][feat] == pytest.approx(means_ab[feat], abs=1e-3) or persisted["means"][feat] == pytest.approx(means_ba[feat], abs=1e-3)
        assert persisted["m2"][feat] == pytest.approx(m2_ab[feat], abs=1e-2) or persisted["m2"][feat] == pytest.approx(m2_ba[feat], abs=1e-2)
        assert persisted["stds"][feat] == pytest.approx(stds_ab[feat], abs=1e-3) or persisted["stds"][feat] == pytest.approx(stds_ba[feat], abs=1e-3)

    # ModelManager must have exactly 5 registered vectors (no lost or duplicate registrations)
    meta = ModelManager.get_model_metadata(user.id)
    assert meta["training_sample_count"] == 5


# -----------------------------------------------------------------------------
# 2. Two different sessions updating one user's shared profile concurrently via API
# -----------------------------------------------------------------------------
def test_two_different_sessions_updating_one_shared_profile(db_session: Session):
    """
    Genuinely concurrent API test:
    - Creates an isolated user with an existing seeded BehaviorProfile (sample_count=3, profile_version=4).
    - Starts two active sessions (college and ecommerce) for that same user.
    - Configures per-request independent database sessions (SessionLocal) on the FastAPI app.
    - Uses two worker threads, each with its own TestClient instance, synchronized at both:
      (a) request_barrier right before dispatching POST /api/behavior/events, and
      (b) baseline_select_barrier inside ProfileService.update_baseline_from_event() right after
          both sessions read the initial BehaviorProfile snapshot on Attempt 0.
    - Verifies both HTTP requests succeed (200 OK, ALLOW), no update is lost (sample_count=5,
      profile_version=6), and all 10 Welford means, M2, stds, and sample_counts match independent
      calculations.
    """
    user = _create_isolated_user(db_session, "conc.dual.api@cognisec.ai")

    # Seed 3 initial trusted observations on the user's shared profile
    seed_vecs = [
        np.array([60.0, 110.0, 80.0, 400.0, 500.0, 1.10, 0.6, 150.0, 1.5, 0.70], dtype=np.float64),
        np.array([62.0, 114.0, 82.0, 410.0, 510.0, 1.15, 0.7, 160.0, 1.6, 0.75], dtype=np.float64),
        np.array([66.0, 116.0, 84.0, 420.0, 530.0, 1.20, 0.8, 170.0, 1.7, 0.80], dtype=np.float64),
    ]
    for v in seed_vecs:
        ProfileService.update_baseline_from_event(
            db=db_session,
            user_id=user.id,
            event_vector=v,
            risk_score=0.10,
            session_status="ACTIVE",
            decision="ALLOW",
        )

    db_session.expire_all()
    profile_before = ProfileService.get_or_create_profile(db_session, user.id)
    assert profile_before.sample_count == 3
    assert profile_before.profile_version == 4

    # Create two independent active sessions (college and ecommerce) for the same user
    s1 = SessionService.create_session(db_session, user.id, "college", None, "127.0.0.1")
    s2 = SessionService.create_session(db_session, user.id, "ecommerce", None, "127.0.0.1")
    SessionService.activate_session_after_login_otp(db_session, s1.id)
    SessionService.activate_session_after_login_otp(db_session, s2.id)
    sid_1, sid_2 = s1.id, s2.id

    token_1 = create_access_token(subject=user.id, role=user.role, session_id=sid_1)
    token_2 = create_access_token(subject=user.id, role=user.role, session_id=sid_2)

    vec_1 = np.array([64.0, 112.0, 82.0, 430.0, 520.0, 1.15, 0.7, 140.0, 1.2, 0.65], dtype=np.float64)
    vec_2 = np.array([68.0, 108.0, 86.0, 450.0, 540.0, 1.25, 0.9, 160.0, 1.6, 0.75], dtype=np.float64)

    payload_1 = {
        "session_id": sid_1,
        "application": "college",
        "typing_speed_wpm": float(vec_1[0]),
        "avg_flight_time_ms": float(vec_1[1]),
        "avg_dwell_time_ms": float(vec_1[2]),
        "mouse_velocity_avg": float(vec_1[3]),
        "mouse_acceleration_avg": float(vec_1[4]),
        "mouse_curvature_entropy": float(vec_1[5]),
        "click_frequency": float(vec_1[6]),
        "scroll_speed_avg": float(vec_1[7]),
        "idle_duration_sec": float(vec_1[8]),
        "navigation_entropy": float(vec_1[9]),
        "telemetry_nonce": f"nonce_s1_{time.time_ns()}",
        "timestamp": time.time(),
        "sequence_number": 1,
    }
    payload_2 = {
        "session_id": sid_2,
        "application": "ecommerce",
        "typing_speed_wpm": float(vec_2[0]),
        "avg_flight_time_ms": float(vec_2[1]),
        "avg_dwell_time_ms": float(vec_2[2]),
        "mouse_velocity_avg": float(vec_2[3]),
        "mouse_acceleration_avg": float(vec_2[4]),
        "mouse_curvature_entropy": float(vec_2[5]),
        "click_frequency": float(vec_2[6]),
        "scroll_speed_avg": float(vec_2[7]),
        "idle_duration_sec": float(vec_2[8]),
        "navigation_entropy": float(vec_2[9]),
        "telemetry_nonce": f"nonce_s2_{time.time_ns()}",
        "timestamp": time.time(),
        "sequence_number": 1,
    }

    # Ensure each HTTP request gets its own independent SQLAlchemy Session
    prev_overrides = dict(app.dependency_overrides)
    opened_sessions = []
    sessions_lock = threading.Lock()

    def independent_get_db():
        req_db = SessionLocal()
        with sessions_lock:
            opened_sessions.append(req_db)
        try:
            yield req_db
        finally:
            req_db.close()

    app.dependency_overrides[get_db] = independent_get_db
    app.dependency_overrides[get_simulator_db] = independent_get_db

    # Synchronize both threads at request dispatch AND inside update_baseline_from_event()
    # immediately after reading the initial BehaviorProfile snapshot on Attempt 0.
    request_barrier = threading.Barrier(2)
    baseline_select_barrier = threading.Barrier(2)
    orig_get_maturity_info = ProfileService.get_maturity_info
    seen_threads = set()
    barrier_hits = {"count": 0}
    hits_lock = threading.Lock()

    def synced_get_maturity_info(sample_count: int, *args, **kwargs):
        # get_maturity_info is called inside update_baseline_from_event() after SELECT ... FOR UPDATE
        # and Welford calculation, right before the conditional UPDATE.
        tid = threading.get_ident()
        should_wait = False
        with hits_lock:
            if tid not in seen_threads and barrier_hits["count"] < 2:
                seen_threads.add(tid)
                barrier_hits["count"] += 1
                should_wait = True
        if should_wait:
            baseline_select_barrier.wait(timeout=5.0)
        return orig_get_maturity_info(sample_count, *args, **kwargs)

    ProfileService.get_maturity_info = staticmethod(synced_get_maturity_info)

    def dispatch_concurrent_telemetry(payload, tok):
        with TestClient(app) as local_client:
            request_barrier.wait(timeout=5.0)
            resp = local_client.post(
                "/api/behavior/events",
                headers={"Authorization": f"Bearer {tok}"},
                json=payload,
            )
            return resp.status_code, resp.json()

    try:
        with ThreadPoolExecutor(max_workers=2, thread_name_prefix="DualSessionAPIWorker") as pool:
            f1 = pool.submit(dispatch_concurrent_telemetry, payload_1, token_1)
            f2 = pool.submit(dispatch_concurrent_telemetry, payload_2, token_2)
            status_1, body_1 = f1.result()
            status_2, body_2 = f2.result()
    finally:
        ProfileService.get_maturity_info = staticmethod(orig_get_maturity_info)
        app.dependency_overrides.clear()
        app.dependency_overrides.update(prev_overrides)
        for s in opened_sessions:
            try:
                s.close()
            except Exception:
                pass

    # Verify both requests genuinely overlapped at the in-flight barrier and used separate DB sessions
    assert barrier_hits["count"] == 2
    assert len(opened_sessions) >= 2
    assert opened_sessions[0] is not opened_sessions[1]

    assert status_1 == 200, f"Request 1 failed: {body_1}"
    assert status_2 == 200, f"Request 2 failed: {body_2}"
    assert body_1["decision"] == "ALLOW"
    assert body_2["decision"] == "ALLOW"

    db_session.expire_all()
    profile_after = ProfileService.get_or_create_profile(db_session, user.id)
    persisted = ProfileService.get_profile_dict(profile_after)

    assert profile_after.sample_count == 5
    assert profile_after.profile_version == 6
    assert persisted["sample_count"] == 5

    # Verify all 10 Welford statistics against independent calculations for both valid commit orders
    seq_12 = [(v, FeatureEngineering.resolve_observed_features(v)) for v in (seed_vecs + [vec_1, vec_2])]
    seq_21 = [(v, FeatureEngineering.resolve_observed_features(v)) for v in (seed_vecs + [vec_2, vec_1])]
    means_12, m2_12, stds_12, counts_12 = compute_independent_welford_sequence(seq_12)
    means_21, m2_21, stds_21, counts_21 = compute_independent_welford_sequence(seq_21)

    for feat in FEATURE_NAMES:
        assert persisted["sample_counts"][feat] == 5
        assert persisted["feature_sample_counts"][feat] == 5
        assert (
            persisted["means"][feat] == pytest.approx(means_12[feat], abs=1e-3)
            or persisted["means"][feat] == pytest.approx(means_21[feat], abs=1e-3)
        )
        assert (
            persisted["m2"][feat] == pytest.approx(m2_12[feat], abs=1e-2)
            or persisted["m2"][feat] == pytest.approx(m2_21[feat], abs=1e-2)
        )
        assert (
            persisted["stds"][feat] == pytest.approx(stds_12[feat], abs=1e-3)
            or persisted["stds"][feat] == pytest.approx(stds_21[feat], abs=1e-3)
        )

    meta = ModelManager.get_model_metadata(user.id)
    assert meta["training_sample_count"] == 5


# -----------------------------------------------------------------------------
# 3. Concurrent first-time profile creation
# -----------------------------------------------------------------------------
def test_concurrent_first_time_profile_creation_handles_race_safely(db_session: Session):
    user = _create_isolated_user(db_session, "conc.init@cognisec.ai")
    # Confirm zero profiles exist initially
    assert db_session.query(BehaviorProfile).filter(BehaviorProfile.user_id == user.id).count() == 0

    create_barrier = threading.Barrier(4)
    target_user_id = int(user.id)

    def worker_create():
        local_db = SessionLocal()
        try:
            create_barrier.wait(timeout=5.0)
            prof = ProfileService.get_or_create_profile(local_db, target_user_id)
            prof_dict = ProfileService.get_profile_dict(prof)
            return prof.id, prof.user_id, prof.sample_count, prof.profile_version, prof_dict
        finally:
            local_db.close()

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(worker_create) for _ in range(4)]
        results = [f.result() for f in futures]

    # All 4 concurrent calls must return the exact same winning BehaviorProfile row
    profile_ids = {r[0] for r in results}
    assert len(profile_ids) == 1
    for r_id, r_uid, r_sc, r_pv, r_dict in results:
        assert r_uid == user.id
        assert r_sc == 0
        assert r_pv == 1
        assert r_dict["enrollment_status"] == "NOT_ENROLLED"
        assert r_dict["confidence_status"] == "COLD_START"
        assert r_dict["sample_count"] == 0
        for feat in FEATURE_NAMES:
            assert r_dict["means"][feat] == 0.0
            assert r_dict["m2"][feat] == 0.0
            assert r_dict["stds"][feat] == float(settings.FEATURE_MIN_SIGMA.get(feat, 1.0))
            assert r_dict["sample_counts"][feat] == 0
            assert r_dict["feature_sample_counts"][feat] == 0

    db_session.expire_all()
    all_rows = db_session.query(BehaviorProfile).filter(BehaviorProfile.user_id == user.id).all()
    assert len(all_rows) == 1

    # Also deterministically verify IntegrityError recovery without overwriting existing profile data
    winning_profile = all_rows[0]
    vec = np.array([65.0, 110.0, 82.0, 420.0, 510.0, 1.20, 0.8, 150.0, 1.5, 0.80], dtype=np.float64)
    ProfileService.update_baseline_from_event(db_session, user.id, vec, risk_score=0.10, session_status="ACTIVE", decision="ALLOW")
    db_session.refresh(winning_profile)
    assert winning_profile.sample_count == 1

    # Simulate a stale session that saw query.first() == None and hit IntegrityError on commit
    state = {"first_query_done": False}
    orig_query = db_session.query

    class SimulatedRaceQuery:
        def __init__(self, q):
            self._q = q

        def filter(self, *args, **kwargs):
            return SimulatedRaceQuery(self._q.filter(*args, **kwargs))

        def populate_existing(self):
            return SimulatedRaceQuery(self._q.populate_existing())

        def with_for_update(self):
            return SimulatedRaceQuery(self._q.with_for_update())

        def first(self):
            if not state["first_query_done"]:
                state["first_query_done"] = True
                return None  # Simulate stale pre-insert read
            return self._q.first()

    def simulated_query(model):
        return SimulatedRaceQuery(orig_query(model))

    db_session.query = simulated_query
    try:
        recovered = ProfileService.get_or_create_profile(db_session, user.id)
        # Must recover the existing profile with sample_count == 1 without overwriting it with 0!
        assert recovered.id == winning_profile.id
        assert recovered.sample_count == 1
    finally:
        db_session.query = orig_query


# -----------------------------------------------------------------------------
# 4. Optimistic version conflict detection and bounded retry
# -----------------------------------------------------------------------------
def test_optimistic_version_conflict_triggers_safe_retry_and_bounded_failure(db_session: Session):
    user = _create_isolated_user(db_session, "conc.optimistic@cognisec.ai")
    seed_vec = np.array([62.0, 112.0, 82.0, 410.0, 510.0, 1.15, 0.7, 160.0, 1.5, 0.75], dtype=np.float64)
    ProfileService.update_baseline_from_event(db_session, user.id, seed_vec, risk_score=0.10, session_status="ACTIVE", decision="ALLOW")

    ModelManager.reset_memory()

    # Intercept the conditional update on attempt 0 to simulate a concurrent writer committing
    # an intervening update after our SELECT ... FOR UPDATE but before our conditional UPDATE.
    intervening_vec = np.array([66.0, 116.0, 86.0, 430.0, 530.0, 1.25, 0.9, 180.0, 1.9, 0.85], dtype=np.float64)
    target_vec = np.array([70.0, 120.0, 90.0, 450.0, 550.0, 1.35, 1.1, 200.0, 2.3, 0.95], dtype=np.float64)

    conflict_injected = {"done": False, "attempts": 0}
    orig_query = db_session.query

    class ConflictInjectingQuery:
        def __init__(self, q):
            self._q = q

        def filter(self, *args, **kwargs):
            return ConflictInjectingQuery(self._q.filter(*args, **kwargs))

        def populate_existing(self):
            return ConflictInjectingQuery(self._q.populate_existing())

        def with_for_update(self):
            return ConflictInjectingQuery(self._q.with_for_update())

        def first(self):
            return self._q.first()

        def update(self, values, synchronize_session=False):
            conflict_injected["attempts"] += 1
            if not conflict_injected["done"]:
                conflict_injected["done"] = True
                # Commit intervening_vec on a separate DB session so expected_version becomes stale!
                other_db = SessionLocal()
                try:
                    ProfileService.update_baseline_from_event(
                        other_db, user.id, intervening_vec, risk_score=0.10, session_status="ACTIVE", decision="ALLOW"
                    )
                finally:
                    other_db.close()
            return self._q.update(values, synchronize_session=synchronize_session)

    db_session.query = lambda model: ConflictInjectingQuery(orig_query(model))
    try:
        updated = ProfileService.update_baseline_from_event(
            db_session, user.id, target_vec, risk_score=0.10, session_status="ACTIVE", decision="ALLOW"
        )
    finally:
        db_session.query = orig_query

    # Attempt 1 failed conditional update (rowcount=0), Attempt 2 reloaded sample_count=2 and succeeded!
    assert conflict_injected["attempts"] == 2
    assert updated.sample_count == 3
    assert updated.profile_version == 4  # initial 1 + 3 updates = 4

    # Verify exact Welford math matches [seed_vec, intervening_vec, target_vec]
    persisted = ProfileService.get_profile_dict(updated)
    expected_seq = [(v, FeatureEngineering.resolve_observed_features(v)) for v in [seed_vec, intervening_vec, target_vec]]
    exp_means, exp_m2, exp_stds, _ = compute_independent_welford_sequence(expected_seq)
    for feat in FEATURE_NAMES:
        assert persisted["means"][feat] == pytest.approx(exp_means[feat], abs=1e-4)
        assert persisted["m2"][feat] == pytest.approx(exp_m2[feat], abs=1e-4)
        assert persisted["stds"][feat] == pytest.approx(exp_stds[feat], abs=1e-4)

    # Verify no duplicate trusted-vector registration occurred during the retry
    # (1 from intervening_vec + 1 from target_vec = 2 vectors since reset_memory)
    meta = ModelManager.get_model_metadata(user.id)
    assert meta["training_sample_count"] == 2


# -----------------------------------------------------------------------------
# 5 & 6. Failed transaction rollback + NO trusted-vector registration on failure
# -----------------------------------------------------------------------------
def test_failed_commit_rolls_back_and_does_not_register_trusted_vector(db_session: Session):
    user = _create_isolated_user(db_session, "conc.rollback@cognisec.ai")
    seed_vec = np.array([64.0, 114.0, 84.0, 420.0, 520.0, 1.20, 0.8, 170.0, 1.6, 0.80], dtype=np.float64)
    profile = ProfileService.update_baseline_from_event(
        db_session, user.id, seed_vec, risk_score=0.10, session_status="ACTIVE", decision="ALLOW"
    )
    before_stats = ProfileService.get_profile_dict(profile)
    before_version = profile.profile_version
    before_count = profile.sample_count
    before_ml_count = ModelManager.get_model_metadata(user.id)["training_sample_count"]
    assert before_ml_count == 1

    # Simulate a database commit failure during the next baseline update
    def failing_commit():
        raise RuntimeError("Simulated database commit failure")

    orig_commit = db_session.commit
    db_session.commit = failing_commit
    try:
        new_vec = np.array([75.0, 102.0, 76.0, 490.0, 610.0, 1.45, 1.3, 220.0, 2.5, 1.05], dtype=np.float64)
        with pytest.raises(RuntimeError, match="Simulated database commit failure"):
            ProfileService.update_baseline_from_event(
                db_session, user.id, new_vec, risk_score=0.10, session_status="ACTIVE", decision="ALLOW"
            )
    finally:
        db_session.commit = orig_commit

    # Verify DB transaction rolled back cleanly and profile statistics are untouched
    db_session.expire_all()
    reloaded = ProfileService.get_or_create_profile(db_session, user.id)
    after_stats = ProfileService.get_profile_dict(reloaded)
    assert reloaded.sample_count == before_count
    assert reloaded.profile_version == before_version
    assert after_stats["means"] == before_stats["means"]
    assert after_stats["m2"] == before_stats["m2"]
    assert after_stats["stds"] == before_stats["stds"]

    # Verify ModelManager did NOT register the vector from the failed transaction
    after_ml_count = ModelManager.get_model_metadata(user.id)["training_sample_count"]
    assert after_ml_count == before_ml_count


# -----------------------------------------------------------------------------
# 8. Mouse-only and typing-only updates remain isolated under concurrency
# -----------------------------------------------------------------------------
def test_concurrent_mouse_only_and_typing_only_updates_preserve_both_modalities(db_session: Session):
    user = _create_isolated_user(db_session, "conc.modality@cognisec.ai")

    # Seed 5 complete observations
    seed_vec = np.array([65.0, 115.0, 85.0, 420.0, 550.0, 1.25, 0.8, 180.0, 2.0, 0.90], dtype=np.float64)
    for _ in range(5):
        ProfileService.update_baseline_from_event(
            db_session, user.id, seed_vec, risk_score=0.10, session_status="ACTIVE", decision="ALLOW"
        )

    # Mouse-only observation (keyboard features 0.0)
    mouse_only_vec = np.array([0.0, 0.0, 0.0, 480.0, 610.0, 1.45, 1.4, 210.0, 1.5, 1.10], dtype=np.float64)
    # Typing-only observation (mouse, scroll, nav features 0.0)
    typing_only_vec = np.array([77.0, 97.0, 73.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0], dtype=np.float64)

    modality_barrier = threading.Barrier(2)
    user_id = int(user.id)

    def run_modality_update(vec, modalities):
        local_db = SessionLocal()
        try:
            modality_barrier.wait(timeout=5.0)
            return ProfileService.update_baseline_from_event(
                db=local_db,
                user_id=user_id,
                event_vector=vec,
                risk_score=0.10,
                session_status="ACTIVE",
                decision="ALLOW",
                observed_modalities=modalities,
            )
        finally:
            local_db.close()

    mouse_mods = {"keyboard": False, "mouse": True, "scroll": True, "navigation": True, "inactivity": True}
    typing_mods = {"keyboard": True, "mouse": False, "scroll": False, "navigation": False, "inactivity": True}

    with ThreadPoolExecutor(max_workers=2) as pool:
        f_mouse = pool.submit(run_modality_update, mouse_only_vec, mouse_mods)
        f_typing = pool.submit(run_modality_update, typing_only_vec, typing_mods)
        f_mouse.result()
        f_typing.result()

    db_session.expire_all()
    final_profile = ProfileService.get_or_create_profile(db_session, user.id)
    final_data = ProfileService.get_profile_dict(final_profile)

    # Global sample count incremented twice (5 -> 7)
    assert final_profile.sample_count == 7
    assert final_profile.profile_version == 8

    # Keyboard features were observed in 5 seeds + 1 typing_only = 6 samples
    # Mouse features were observed in 5 seeds + 1 mouse_only = 6 samples
    for kbd_feat in ["typing_speed_wpm", "avg_flight_time_ms", "avg_dwell_time_ms"]:
        assert final_data["sample_counts"][kbd_feat] == 6
    for mouse_feat in ["mouse_velocity_avg", "mouse_acceleration_avg", "mouse_curvature_entropy", "click_frequency"]:
        assert final_data["sample_counts"][mouse_feat] == 6

    # Neither modality diluted or overwrote the other:
    # Expected keyboard WPM mean = (5 * 65.0 + 77.0) / 6 = 67.0
    # Expected mouse velocity mean = (5 * 420.0 + 480.0) / 6 = 430.0
    assert final_data["means"]["typing_speed_wpm"] == pytest.approx(67.0, abs=1e-4)
    assert final_data["means"]["mouse_velocity_avg"] == pytest.approx(430.0, abs=1e-4)

    # Verify all 10 features against independent Welford calculation
    seed_obs = FeatureEngineering.resolve_observed_features(seed_vec)
    mouse_obs = FeatureEngineering.resolve_observed_features(mouse_only_vec, observed_modalities=mouse_mods)
    typing_obs = FeatureEngineering.resolve_observed_features(typing_only_vec, observed_modalities=typing_mods)
    seq_mt = [(seed_vec, seed_obs)] * 5 + [(mouse_only_vec, mouse_obs), (typing_only_vec, typing_obs)]
    seq_tm = [(seed_vec, seed_obs)] * 5 + [(typing_only_vec, typing_obs), (mouse_only_vec, mouse_obs)]
    means_mt, m2_mt, stds_mt, counts_mt = compute_independent_welford_sequence(seq_mt)
    means_tm, m2_tm, stds_tm, counts_tm = compute_independent_welford_sequence(seq_tm)

    for feat in FEATURE_NAMES:
        assert final_data["sample_counts"][feat] == counts_mt[feat]
        assert (
            final_data["means"][feat] == pytest.approx(means_mt[feat], abs=1e-3)
            or final_data["means"][feat] == pytest.approx(means_tm[feat], abs=1e-3)
        )
        assert (
            final_data["m2"][feat] == pytest.approx(m2_mt[feat], abs=1e-2)
            or final_data["m2"][feat] == pytest.approx(m2_tm[feat], abs=1e-2)
        )
        assert (
            final_data["stds"][feat] == pytest.approx(stds_mt[feat], abs=1e-3)
            or final_data["stds"][feat] == pytest.approx(stds_tm[feat], abs=1e-3)
        )


# -----------------------------------------------------------------------------
# 9. Existing replay, ownership, and risk gates remain effective
# -----------------------------------------------------------------------------
def test_replay_ownership_and_risk_gates_prevent_baseline_contamination(client, user_token, db_session: Session):
    user = db_session.query(User).filter(User.email == "test.user@cognisec.ai").first()
    profile_before = ProfileService.get_or_create_profile(db_session, user.id)
    count_before = profile_before.sample_count

    sess_res = client.post(
        "/api/sessions/start",
        headers={"Authorization": f"Bearer {user_token}"},
        json={"application": "college", "device_fingerprint": "conc_gate_fp"},
    )
    assert sess_res.status_code == 200
    session_id = sess_res.json()["id"]

    # Log in as a different standard user to test BOLA session ownership gate
    other_login = client.post(
        "/api/auth/login",
        json={"email": "student.alex@veritas.edu", "password": "Student@123", "application": "college"},
    )
    other_sid = other_login.json()["session_id"]
    SessionService.activate_session_after_login_otp(db_session, other_sid)
    other_user_token = other_login.json()["access_token"]

    # 1. Ownership gate: Another user attempting to submit telemetry for user's session -> 403
    forbid_res = client.post(
        "/api/behavior/events",
        headers={"Authorization": f"Bearer {other_user_token}"},
        json={
            "session_id": session_id,
            "application": "college",
            "typing_speed_wpm": 65.0,
            "avg_flight_time_ms": 110.0,
            "avg_dwell_time_ms": 80.0,
        },
    )
    assert forbid_res.status_code == 403

    # 2. High-risk / suspicious event gate: Does not update baseline
    suspicious_res = client.post(
        "/api/behavior/events",
        headers={"Authorization": f"Bearer {user_token}"},
        json={
            "session_id": session_id,
            "application": "college",
            "typing_speed_wpm": 65.0,
            "avg_flight_time_ms": 110.0,
            "avg_dwell_time_ms": 80.0,
            "context_signals": {"impossible_travel": True, "denied_access_count": 5},
            "telemetry_nonce": f"nonce_gate_susp_{time.time_ns()}",
            "timestamp": time.time(),
            "sequence_number": 1,
        },
    )
    assert suspicious_res.status_code == 200
    assert suspicious_res.json()["decision"] != "ALLOW"

    db_session.expire_all()
    profile_after = ProfileService.get_or_create_profile(db_session, user.id)
    assert profile_after.sample_count == count_before


# -----------------------------------------------------------------------------
# 10. Persistent optimistic conflict exceeding retries raises RuntimeError
# -----------------------------------------------------------------------------
def test_persistent_optimistic_conflict_exceeding_retries_never_silently_drops_update(db_session: Session):
    user = _create_isolated_user(db_session, "conc.exhaust@cognisec.ai")
    seed_vec = np.array([62.0, 112.0, 82.0, 410.0, 510.0, 1.15, 0.7, 160.0, 1.5, 0.75], dtype=np.float64)
    ProfileService.update_baseline_from_event(db_session, user.id, seed_vec, risk_score=0.10, session_status="ACTIVE", decision="ALLOW")
    ModelManager.reset_memory()

    orig_query = db_session.query

    class AlwaysConflictingQuery:
        def __init__(self, q):
            self._q = q

        def filter(self, *args, **kwargs):
            return AlwaysConflictingQuery(self._q.filter(*args, **kwargs))

        def populate_existing(self):
            return AlwaysConflictingQuery(self._q.populate_existing())

        def with_for_update(self):
            return AlwaysConflictingQuery(self._q.with_for_update())

        def first(self):
            return self._q.first()

        def update(self, values, synchronize_session=False):
            return 0  # Simulate persistent concurrent version conflict

    db_session.query = lambda model: AlwaysConflictingQuery(orig_query(model))
    try:
        with pytest.raises(RuntimeError, match="Concurrent baseline update conflict"):
            ProfileService.update_baseline_from_event(
                db_session, user.id, seed_vec, risk_score=0.10, session_status="ACTIVE", decision="ALLOW"
            )
    finally:
        db_session.query = orig_query

    # Ensure ModelManager was not polluted when retries were exhausted
    assert ModelManager.get_model_metadata(user.id)["training_sample_count"] == 0


# -----------------------------------------------------------------------------
# 11. Runtime SQLite pragma verification across primary/test and simulator engines
# -----------------------------------------------------------------------------
def test_sqlite_runtime_pragmas_and_simulator_busy_timeout(db_session: Session):
    """
    Verifies the actual runtime SQLite pragmas on both the primary/test engine and
    the isolated simulator engine:
    - PRAGMA foreign_keys == 1
    - PRAGMA busy_timeout == 5000
    - PRAGMA journal_mode == 'delete' (WAL is intentionally not required for the
      optimistic conditional UPDATE + bounded retry concurrency strategy).
    """
    conn = db_session.connection()
    fk = conn.exec_driver_sql("PRAGMA foreign_keys;").scalar()
    bt = conn.exec_driver_sql("PRAGMA busy_timeout;").scalar()
    jm = conn.exec_driver_sql("PRAGMA journal_mode;").scalar()
    assert fk == 1
    assert bt == 5000
    assert str(jm).lower() == "delete"

    with simulator_engine.connect() as sim_conn:
        sim_fk = sim_conn.exec_driver_sql("PRAGMA foreign_keys;").scalar()
        sim_bt = sim_conn.exec_driver_sql("PRAGMA busy_timeout;").scalar()
        assert sim_fk == 1
        assert sim_bt == 5000


