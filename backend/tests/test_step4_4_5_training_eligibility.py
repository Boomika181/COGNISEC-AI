"""
COGNISEC-AI — Phase II, Step 4.4.5
Focused Verification and Regression Suite for:
- F-03A: Fail-closed historical hydration eligibility (rejecting missing/empty/malformed raw_feature_json,
  missing is_trusted, pending in-flight rows, idle-only vectors, all-zero vectors, anomalous observations,
  and non-ALLOW decisions).
- F-03B: Shared modality-aware preprocessing (FeatureEngineering.prepare_training_vector) across live
  registration and post-restart hydration, preserving genuine observed zeros while imputing unobserved
  modalities from reliable baseline means.
- F-03E: Duplicate training-vector registration prevention across identical event_ids, optimistic retry loops,
  and hydration deduplication.
"""

import json
import math
from datetime import datetime, timezone
import numpy as np
import pytest
from sqlalchemy.orm import Session

from app.database.connection import SessionLocal
from app.ml.feature_engineering import FeatureEngineering, FEATURE_NAMES
from app.ml.model_manager import ModelManager
from app.services.profile_service import ProfileService
from app.services.behavior_service import BehaviorService
from app.services.session_service import SessionService
from app.models.user import User
from app.models.session import Session as DbSession
from app.models.behavior import BehaviorLog, BehaviorProfile, BehavioralTrainingEvent
from app.schemas.behavior import BehaviorEventCreate
from app.core.security import get_password_hash


def _ensure_db_session_row(db: Session, user_id: int, session_id: str) -> None:
    existing = db.query(DbSession).filter(DbSession.id == session_id).first()
    if not existing:
        sess = DbSession(
            id=session_id,
            user_id=user_id,
            application="E-Commerce Portal",
            status="ACTIVE",
            current_risk_level="LOW",
        )
        db.add(sess)
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
            name="Step 4.4.5 Test User",
            email=email,
            password_hash=get_password_hash("ValidPass123!"),
            role="USER",
            account_status="ACTIVE",
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    _ensure_db_session_row(db, user.id, f"sess_step445_{user.id}")
    _ensure_db_session_row(db, user.id, "sess_inflight_445")
    ModelManager.reset_memory()
    return user


def _insert_behavior_log(
    db: Session,
    user_id: int,
    vec: np.ndarray,
    raw_feature_json: str | None,
    session_id: str | None = None
) -> BehaviorLog:
    eff_session_id = session_id or f"sess_step445_{user_id}"
    _ensure_db_session_row(db, user_id, eff_session_id)
    log = BehaviorLog(
        user_id=user_id,
        session_id=eff_session_id,
        application="E-Commerce Portal",
        timestamp=datetime.now(timezone.utc),
        typing_speed_wpm=float(vec[0]),
        avg_flight_time_ms=float(vec[1]),
        avg_dwell_time_ms=float(vec[2]),
        mouse_velocity_avg=float(vec[3]),
        mouse_acceleration_avg=float(vec[4]),
        mouse_curvature_entropy=float(vec[5]),
        click_frequency=float(vec[6]),
        scroll_speed_avg=float(vec[7]),
        idle_duration_sec=float(vec[8]),
        navigation_entropy=float(vec[9]),
        raw_feature_json=raw_feature_json,
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    return log


FULL_ACTIVE_VEC = np.array(
    [65.0, 115.0, 85.0, 420.0, 540.0, 1.25, 0.85, 180.0, 2.0, 0.90],
    dtype=np.float64,
)


# ------------------------------------------------------------------------------
# 1. Historical row with raw_feature_json = None is rejected during hydration
# ------------------------------------------------------------------------------
def test_1_hydration_rejects_none_raw_feature_json(db_session: Session):
    user = _create_isolated_user(db_session, "step445.nonejson@cognisec.ai")
    _insert_behavior_log(db_session, user.id, FULL_ACTIVE_VEC, raw_feature_json=None)

    ModelManager.reset_memory()
    detector = ModelManager.ensure_hydrated(db_session, user.id)
    assert len(ModelManager._user_training_data.get(user.id, [])) == 0
    assert detector.trained_sample_count == 0


# ------------------------------------------------------------------------------
# 2. Historical row with raw_feature_json = "{}" is rejected during hydration
# ------------------------------------------------------------------------------
def test_2_hydration_rejects_empty_dict_raw_feature_json(db_session: Session):
    user = _create_isolated_user(db_session, "step445.emptyjson@cognisec.ai")
    _insert_behavior_log(db_session, user.id, FULL_ACTIVE_VEC, raw_feature_json="{}")

    ModelManager.reset_memory()
    detector = ModelManager.ensure_hydrated(db_session, user.id)
    assert len(ModelManager._user_training_data.get(user.id, [])) == 0
    assert detector.trained_sample_count == 0


# ------------------------------------------------------------------------------
# 3. Historical row with malformed JSON is rejected during hydration
# ------------------------------------------------------------------------------
def test_3_hydration_rejects_malformed_raw_feature_json(db_session: Session):
    user = _create_isolated_user(db_session, "step445.badjson@cognisec.ai")
    _insert_behavior_log(db_session, user.id, FULL_ACTIVE_VEC, raw_feature_json="{malformed_json:")

    ModelManager.reset_memory()
    detector = ModelManager.ensure_hydrated(db_session, user.id)
    assert len(ModelManager._user_training_data.get(user.id, [])) == 0
    assert detector.trained_sample_count == 0


# ------------------------------------------------------------------------------
# 4. Historical row with missing is_trusted or is_trusted != True is rejected
# ------------------------------------------------------------------------------
def test_4_hydration_rejects_missing_or_non_true_is_trusted(db_session: Session):
    user = _create_isolated_user(db_session, "step445.untrusted@cognisec.ai")
    # Row A: missing is_trusted
    _insert_behavior_log(
        db_session,
        user.id,
        FULL_ACTIVE_VEC,
        raw_feature_json=json.dumps({"decision": "ALLOW", "risk_score": 0.10}),
    )
    # Row B: is_trusted = False
    _insert_behavior_log(
        db_session,
        user.id,
        FULL_ACTIVE_VEC,
        raw_feature_json=json.dumps({"is_trusted": False, "decision": "ALLOW", "risk_score": 0.10}),
    )
    # Row C: is_trusted = "true" (string, not boolean True)
    _insert_behavior_log(
        db_session,
        user.id,
        FULL_ACTIVE_VEC,
        raw_feature_json=json.dumps({"is_trusted": "true", "decision": "ALLOW", "risk_score": 0.10}),
    )

    ModelManager.reset_memory()
    detector = ModelManager.ensure_hydrated(db_session, user.id)
    assert len(ModelManager._user_training_data.get(user.id, [])) == 0
    assert detector.trained_sample_count == 0


# ------------------------------------------------------------------------------
# 5. Historical row created before risk evaluation completes cannot be hydrated as trusted
# ------------------------------------------------------------------------------
def test_5_pending_inflight_behavior_log_rejected_by_hydration(db_session: Session):
    user = _create_isolated_user(db_session, "step445.inflight@cognisec.ai")
    event_payload = BehaviorEventCreate(
        session_id="sess_inflight_445",
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
        context_signals={"device": "desktop"},
    )
    # Simulate Step 6 of submit_behavior_event (before risk calculation completes)
    log = BehaviorService.record_behavior_event(db_session, user.id, event_payload)
    parsed = json.loads(log.raw_feature_json)
    assert parsed["is_trusted"] is False
    assert parsed["eligibility_status"] == "PENDING"
    assert parsed["ml_registered"] is False

    # Hydration triggered concurrently or after an interrupted request must reject this row
    ModelManager.reset_memory()
    detector = ModelManager.ensure_hydrated(db_session, user.id)
    assert len(ModelManager._user_training_data.get(user.id, [])) == 0
    assert detector.trained_sample_count == 0


# ------------------------------------------------------------------------------
# 6. Idle-only observation (idle_duration_sec > 0, all active modalities 0) is rejected
#    in both live training and hydration
# ------------------------------------------------------------------------------
def test_6_idle_only_observation_rejected_in_live_and_hydration(db_session: Session):
    user = _create_isolated_user(db_session, "step445.idleonly@cognisec.ai")
    idle_vec = np.array([0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 18.5, 0.0], dtype=np.float64)

    # Check canonical eligibility directly
    eligible, reason, _ = FeatureEngineering.evaluate_training_eligibility(
        event_vector=idle_vec,
        user_id=user.id,
        event_user_id=user.id,
        is_trusted=True,
        session_status="ACTIVE",
        prior_session_status="ACTIVE",
        decision="ALLOW",
        risk_score=0.05,
        is_anomaly=False,
        anomaly_score=0.05,
    )
    assert eligible is False
    assert "active behavioral interaction" in (reason or "")

    # Live registration via ProfileService must reject
    profile = ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=idle_vec,
        risk_score=0.05,
        session_status="ACTIVE",
        decision="ALLOW",
    )
    assert profile.sample_count == 0
    assert len(ModelManager._user_training_data.get(user.id, [])) == 0

    # Even if persisted in DB with is_trusted=True, hydration must reject idle-only row
    _insert_behavior_log(
        db_session,
        user.id,
        idle_vec,
        raw_feature_json=json.dumps({
            "is_trusted": True,
            "ml_registered": True,
            "decision": "ALLOW",
            "risk_score": 0.05,
            "anomaly_score": 0.05,
            "is_anomaly": False,
        }),
    )
    ModelManager.reset_memory()
    ModelManager.ensure_hydrated(db_session, user.id)
    assert len(ModelManager._user_training_data.get(user.id, [])) == 0


# ------------------------------------------------------------------------------
# 7. All-zero observation is rejected in both live training and hydration
# ------------------------------------------------------------------------------
def test_7_all_zero_observation_rejected_in_live_and_hydration(db_session: Session):
    user = _create_isolated_user(db_session, "step445.allzero@cognisec.ai")
    zero_vec = np.zeros(10, dtype=np.float64)

    profile = ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=zero_vec,
        risk_score=0.05,
        session_status="ACTIVE",
        decision="ALLOW",
    )
    assert profile.sample_count == 0
    assert len(ModelManager._user_training_data.get(user.id, [])) == 0

    _insert_behavior_log(
        db_session,
        user.id,
        zero_vec,
        raw_feature_json=json.dumps({
            "is_trusted": True,
            "ml_registered": True,
            "decision": "ALLOW",
            "risk_score": 0.05,
            "anomaly_score": 0.05,
            "is_anomaly": False,
        }),
    )
    ModelManager.reset_memory()
    ModelManager.ensure_hydrated(db_session, user.id)
    assert len(ModelManager._user_training_data.get(user.id, [])) == 0


# ------------------------------------------------------------------------------
# 8. Partial-modality mouse-only trusted observation:
#    - does not train keyboard features as raw zero when baseline exists,
#    - produces identical training vector in live registration and post-restart hydration
# ------------------------------------------------------------------------------
def test_8_mouse_only_live_and_hydrated_vectors_match_and_impute_keyboard(db_session: Session):
    user = _create_isolated_user(db_session, "step445.mouseonly@cognisec.ai")

    # Seed 1 full observation so keyboard baseline mean is established (68.0, 118.0, 88.0)
    seed_vec = np.array([68.0, 118.0, 88.0, 410.0, 520.0, 1.20, 0.75, 160.0, 1.5, 0.85], dtype=np.float64)
    ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=seed_vec,
        risk_score=0.08,
        session_status="ACTIVE",
        decision="ALLOW",
        event_id="behavior_log:seed_1",
    )

    # Now record a mouse-only observation (keyboard features = 0.0 because keyboard was not used)
    mouse_only_vec = np.array([0.0, 0.0, 0.0, 440.0, 560.0, 1.30, 0.90, 190.0, 2.0, 0.95], dtype=np.float64)
    obs_mod = {"keyboard": False, "mouse": True, "scroll": True, "navigation": True}
    samp_cnt = {"keystrokes": 0, "mouse_points": 25, "clicks": 3, "scrolls": 4, "navigations": 2}

    ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=mouse_only_vec,
        risk_score=0.10,
        session_status="ACTIVE",
        decision="ALLOW",
        observed_modalities=obs_mod,
        sample_counts=samp_cnt,
        event_id="behavior_log:mouse_2",
    )

    live_vectors = [v.copy() for v in ModelManager._user_training_data[user.id]]
    assert len(live_vectors) == 2
    live_mouse_vec = live_vectors[1]

    # Keyboard features in the live training vector must be imputed to baseline means (68, 118, 88), NOT raw 0.0
    assert live_mouse_vec[0] == pytest.approx(68.0)
    assert live_mouse_vec[1] == pytest.approx(118.0)
    assert live_mouse_vec[2] == pytest.approx(88.0)
    # Observed mouse features must match the event values
    assert live_mouse_vec[3] == pytest.approx(440.0)
    assert live_mouse_vec[4] == pytest.approx(560.0)

    # Persist both rows to BehaviorLog as submit_behavior_event does, then reset memory and hydrate
    _, _, resolved_seed = FeatureEngineering.evaluate_training_eligibility(
        event_vector=seed_vec, user_id=user.id, is_trusted=True
    )
    _, _, resolved_mouse = FeatureEngineering.evaluate_training_eligibility(
        event_vector=mouse_only_vec,
        user_id=user.id,
        is_trusted=True,
        observed_modalities=obs_mod,
        sample_counts=samp_cnt,
    )
    _insert_behavior_log(
        db_session,
        user.id,
        seed_vec,
        raw_feature_json=json.dumps({
            "event_id": "behavior_log:seed_1",
            "is_trusted": True,
            "ml_registered": True,
            "decision": "ALLOW",
            "risk_score": 0.08,
            "anomaly_score": 0.05,
            "is_anomaly": False,
            "observed_features": resolved_seed,
        }),
    )
    _insert_behavior_log(
        db_session,
        user.id,
        mouse_only_vec,
        raw_feature_json=json.dumps({
            "event_id": "behavior_log:mouse_2",
            "is_trusted": True,
            "ml_registered": True,
            "decision": "ALLOW",
            "risk_score": 0.10,
            "anomaly_score": 0.05,
            "is_anomaly": False,
            "observed_modalities": obs_mod,
            "sample_counts": samp_cnt,
            "observed_features": resolved_mouse,
        }),
    )

    ModelManager.reset_memory()
    ModelManager.ensure_hydrated(db_session, user.id)
    hydrated_vectors = ModelManager._user_training_data[user.id]
    assert len(hydrated_vectors) == 2
    np.testing.assert_allclose(hydrated_vectors[0], live_vectors[0], rtol=1e-6, atol=1e-6)
    np.testing.assert_allclose(hydrated_vectors[1], live_vectors[1], rtol=1e-6, atol=1e-6)


# ------------------------------------------------------------------------------
# 9. Partial-modality typing-only trusted observation:
#    - does not train mouse features as raw zero when baseline exists,
#    - produces identical training vector in live registration and post-restart hydration
# ------------------------------------------------------------------------------
def test_9_typing_only_live_and_hydrated_vectors_match_and_impute_mouse(db_session: Session):
    user = _create_isolated_user(db_session, "step445.typingonly@cognisec.ai")

    seed_vec = np.array([62.0, 112.0, 82.0, 450.0, 580.0, 1.35, 0.95, 175.0, 1.8, 0.88], dtype=np.float64)
    ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=seed_vec,
        risk_score=0.08,
        session_status="ACTIVE",
        decision="ALLOW",
        event_id="behavior_log:seed_t1",
    )

    typing_only_vec = np.array([70.0, 108.0, 80.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.2, 0.0], dtype=np.float64)
    obs_mod = {"keyboard": True, "mouse": False, "scroll": False, "navigation": False}
    samp_cnt = {"keystrokes": 32, "mouse_points": 0, "clicks": 0, "scrolls": 0, "navigations": 0}

    ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=typing_only_vec,
        risk_score=0.09,
        session_status="ACTIVE",
        decision="ALLOW",
        observed_modalities=obs_mod,
        sample_counts=samp_cnt,
        event_id="behavior_log:typing_t2",
    )

    live_vectors = [v.copy() for v in ModelManager._user_training_data[user.id]]
    assert len(live_vectors) == 2
    live_typing_vec = live_vectors[1]

    # Observed keyboard features preserved
    assert live_typing_vec[0] == pytest.approx(70.0)
    assert live_typing_vec[1] == pytest.approx(108.0)
    assert live_typing_vec[2] == pytest.approx(80.0)
    # Unobserved mouse/scroll/nav features imputed from baseline means, NOT raw 0.0
    assert live_typing_vec[3] == pytest.approx(450.0)
    assert live_typing_vec[4] == pytest.approx(580.0)
    assert live_typing_vec[5] == pytest.approx(1.35)
    assert live_typing_vec[6] == pytest.approx(0.95)
    assert live_typing_vec[7] == pytest.approx(175.0)
    assert live_typing_vec[9] == pytest.approx(0.88)

    _, _, resolved_seed = FeatureEngineering.evaluate_training_eligibility(
        event_vector=seed_vec, user_id=user.id, is_trusted=True
    )
    _, _, resolved_typing = FeatureEngineering.evaluate_training_eligibility(
        event_vector=typing_only_vec,
        user_id=user.id,
        is_trusted=True,
        observed_modalities=obs_mod,
        sample_counts=samp_cnt,
    )
    _insert_behavior_log(
        db_session,
        user.id,
        seed_vec,
        raw_feature_json=json.dumps({
            "event_id": "behavior_log:seed_t1",
            "is_trusted": True,
            "ml_registered": True,
            "decision": "ALLOW",
            "risk_score": 0.08,
            "anomaly_score": 0.05,
            "is_anomaly": False,
            "observed_features": resolved_seed,
        }),
    )
    _insert_behavior_log(
        db_session,
        user.id,
        typing_only_vec,
        raw_feature_json=json.dumps({
            "event_id": "behavior_log:typing_t2",
            "is_trusted": True,
            "ml_registered": True,
            "decision": "ALLOW",
            "risk_score": 0.09,
            "anomaly_score": 0.05,
            "is_anomaly": False,
            "observed_modalities": obs_mod,
            "sample_counts": samp_cnt,
            "observed_features": resolved_typing,
        }),
    )

    ModelManager.reset_memory()
    ModelManager.ensure_hydrated(db_session, user.id)
    hydrated_vectors = ModelManager._user_training_data[user.id]
    assert len(hydrated_vectors) == 2
    np.testing.assert_allclose(hydrated_vectors[1], live_typing_vec, rtol=1e-6, atol=1e-6)


# ------------------------------------------------------------------------------
# 10. Genuine observed zero (e.g., mouse motion with 0 clicks or 0 curvature)
#     is preserved as 0.0 in both live registration and hydration
# ------------------------------------------------------------------------------
def test_10_genuine_observed_zero_preserved_in_live_and_hydration(db_session: Session):
    user = _create_isolated_user(db_session, "step445.genuinezero@cognisec.ai")

    # Seed baseline with non-zero curvature (1.40) and click_frequency (1.10)
    seed_vec = np.array([64.0, 114.0, 84.0, 430.0, 550.0, 1.40, 1.10, 165.0, 1.5, 0.85], dtype=np.float64)
    ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=seed_vec,
        risk_score=0.07,
        session_status="ACTIVE",
        decision="ALLOW",
        event_id="behavior_log:gz_1",
    )

    # Second event: active mouse motion (mouse_points=20, velocity=400, accel=510) with genuine 0 clicks and 0 curvature
    zero_click_curv_vec = np.array([66.0, 116.0, 86.0, 400.0, 510.0, 0.0, 0.0, 170.0, 1.6, 0.80], dtype=np.float64)
    obs_mod = {"keyboard": True, "mouse": True, "scroll": True, "navigation": True}
    samp_cnt = {"keystrokes": 18, "mouse_points": 20, "clicks": 0, "scrolls": 3, "navigations": 2}

    ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=zero_click_curv_vec,
        risk_score=0.08,
        session_status="ACTIVE",
        decision="ALLOW",
        observed_modalities=obs_mod,
        sample_counts=samp_cnt,
        event_id="behavior_log:gz_2",
    )

    live_vec = ModelManager._user_training_data[user.id][1].copy()
    # Genuine observed 0.0 for mouse_curvature_entropy (index 5) and click_frequency (index 6) MUST be preserved as 0.0
    assert live_vec[5] == 0.0
    assert live_vec[6] == 0.0

    _, _, resolved_1 = FeatureEngineering.evaluate_training_eligibility(
        event_vector=seed_vec, user_id=user.id, is_trusted=True
    )
    _, _, resolved_2 = FeatureEngineering.evaluate_training_eligibility(
        event_vector=zero_click_curv_vec,
        user_id=user.id,
        is_trusted=True,
        observed_modalities=obs_mod,
        sample_counts=samp_cnt,
    )
    _insert_behavior_log(
        db_session,
        user.id,
        seed_vec,
        raw_feature_json=json.dumps({
            "event_id": "behavior_log:gz_1",
            "is_trusted": True,
            "ml_registered": True,
            "decision": "ALLOW",
            "risk_score": 0.07,
            "anomaly_score": 0.05,
            "is_anomaly": False,
            "observed_features": resolved_1,
        }),
    )
    _insert_behavior_log(
        db_session,
        user.id,
        zero_click_curv_vec,
        raw_feature_json=json.dumps({
            "event_id": "behavior_log:gz_2",
            "is_trusted": True,
            "ml_registered": True,
            "decision": "ALLOW",
            "risk_score": 0.08,
            "anomaly_score": 0.05,
            "is_anomaly": False,
            "observed_modalities": obs_mod,
            "sample_counts": samp_cnt,
            "observed_features": resolved_2,
        }),
    )

    ModelManager.reset_memory()
    ModelManager.ensure_hydrated(db_session, user.id)
    hydrated_vec = ModelManager._user_training_data[user.id][1]
    assert hydrated_vec[5] == 0.0
    assert hydrated_vec[6] == 0.0
    np.testing.assert_allclose(hydrated_vec, live_vec, rtol=1e-6, atol=1e-6)


# ------------------------------------------------------------------------------
# 11. Duplicate registration of the same event ID is prevented
# ------------------------------------------------------------------------------
def test_11_duplicate_event_id_registration_prevented(db_session: Session):
    user = _create_isolated_user(db_session, "step445.dupevent@cognisec.ai")

    # Direct ModelManager duplicate event_id call
    ModelManager.register_trusted_vector(user.id, FULL_ACTIVE_VEC, event_id="behavior_log:9991")
    ModelManager.register_trusted_vector(user.id, FULL_ACTIVE_VEC, event_id="behavior_log:9991")
    assert len(ModelManager._user_training_data[user.id]) == 1

    # Duplicate ProfileService.update_baseline_from_event with the same event_id
    ModelManager.reset_memory()
    p1 = ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=FULL_ACTIVE_VEC,
        risk_score=0.08,
        session_status="ACTIVE",
        decision="ALLOW",
        event_id="behavior_log:5001",
    )
    assert p1.sample_count == 1
    assert len(ModelManager._user_training_data[user.id]) == 1

    p2 = ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=FULL_ACTIVE_VEC * 1.05,
        risk_score=0.08,
        session_status="ACTIVE",
        decision="ALLOW",
        event_id="behavior_log:5001",
    )
    assert p2.sample_count == 1
    assert len(ModelManager._user_training_data[user.id]) == 1

    # Duplicate rows in DB with the same event_id or telemetry_nonce during hydration
    _, _, resolved = FeatureEngineering.evaluate_training_eligibility(
        event_vector=FULL_ACTIVE_VEC, user_id=user.id, is_trusted=True
    )
    payload_str = json.dumps({
        "event_id": "behavior_log:5001",
        "telemetry_nonce": "nonce_unique_5001",
        "is_trusted": True,
        "ml_registered": True,
        "decision": "ALLOW",
        "risk_score": 0.08,
        "anomaly_score": 0.05,
        "is_anomaly": False,
        "observed_features": resolved,
    })
    _insert_behavior_log(db_session, user.id, FULL_ACTIVE_VEC, raw_feature_json=payload_str)
    _insert_behavior_log(db_session, user.id, FULL_ACTIVE_VEC, raw_feature_json=payload_str)

    ModelManager.reset_memory()
    ModelManager.ensure_hydrated(db_session, user.id)
    assert len(ModelManager._user_training_data[user.id]) == 1


# ------------------------------------------------------------------------------
# 12. Retried baseline update after transient DB conflict registers the training vector only once
# ------------------------------------------------------------------------------
def test_12_retried_baseline_update_after_conflict_registers_vector_once():
    db1 = SessionLocal()
    db2 = SessionLocal()
    try:
        user = _create_isolated_user(db1, "step445.retryonce@cognisec.ai")
        ProfileService.get_or_create_profile(db1, user.id)

        # Simulate optimistic conflict on attempt 0 by bumping profile_version in db2 mid-flight
        orig_register = ModelManager.register_trusted_vector
        register_calls = []

        def tracked_register(uid, vec, stats=None, event_id=None):
            register_calls.append((uid, event_id))
            return orig_register(uid, vec, stats, event_id=event_id)

        conflict_injected = {"done": False}
        orig_get_dict = ProfileService.get_profile_dict

        def conflict_on_first_attempt(profile_obj):
            res = orig_get_dict(profile_obj)
            if not conflict_injected["done"]:
                conflict_injected["done"] = True
                # Concurrent session updates profile_version so attempt 0's conditional UPDATE returns 0 rows
                db2.query(BehaviorProfile).filter(BehaviorProfile.user_id == user.id).update(
                    {
                        BehaviorProfile.profile_version: BehaviorProfile.profile_version + 1,
                        BehaviorProfile.sample_count: BehaviorProfile.sample_count + 1,
                    },
                    synchronize_session=False,
                )
                db2.commit()
            return res

        ProfileService.get_profile_dict = staticmethod(conflict_on_first_attempt)
        ModelManager.register_trusted_vector = classmethod(
            lambda cls, uid, vec, stats=None, event_id=None: tracked_register(uid, vec, stats, event_id)
        )
        try:
            updated = ProfileService.update_baseline_from_event(
                db=db1,
                user_id=user.id,
                event_vector=FULL_ACTIVE_VEC,
                risk_score=0.10,
                session_status="ACTIVE",
                decision="ALLOW",
                event_id="behavior_log:retry_777",
            )
            assert conflict_injected["done"] is True
            assert updated.sample_count == 2
            assert len(register_calls) == 1
            assert len(ModelManager._user_training_data[user.id]) == 1
        finally:
            ProfileService.get_profile_dict = staticmethod(orig_get_dict)
            ModelManager.register_trusted_vector = orig_register
    finally:
        db1.close()
        db2.close()


# ------------------------------------------------------------------------------
# 13. Anomalous / step-up / restricted / terminated observations never enter
#     live training or hydration
# ------------------------------------------------------------------------------
def test_13_anomalous_and_non_allow_events_rejected_in_live_and_hydration(db_session: Session):
    user = _create_isolated_user(db_session, "step445.anomalous@cognisec.ai")

    ineligible_cases = [
        {"session_status": "STEP_UP_REQUIRED", "decision": "STEP_UP_VERIFICATION", "risk_score": 0.45, "is_anomaly": False, "anomaly_score": 0.30},
        {"session_status": "RESTRICTED", "decision": "RESTRICT", "risk_score": 0.72, "is_anomaly": True, "anomaly_score": 0.75},
        {"session_status": "TERMINATED", "decision": "TERMINATE_SESSION", "risk_score": 0.91, "is_anomaly": True, "anomaly_score": 0.92},
        {"session_status": "ACTIVE", "decision": "ALLOW", "risk_score": 0.20, "is_anomaly": True, "anomaly_score": 0.65},
        {"session_status": "ACTIVE", "decision": "ALLOW", "risk_score": 0.35, "is_anomaly": False, "anomaly_score": 0.20},
    ]

    for idx, case in enumerate(ineligible_cases):
        eligible, _, _ = FeatureEngineering.evaluate_training_eligibility(
            event_vector=FULL_ACTIVE_VEC,
            user_id=user.id,
            event_user_id=user.id,
            is_trusted=True,
            session_status=case["session_status"],
            prior_session_status="ACTIVE",
            decision=case["decision"],
            risk_score=case["risk_score"],
            is_anomaly=case["is_anomaly"],
            anomaly_score=case["anomaly_score"],
            event_id=f"behavior_log:bad_{idx}",
        )
        assert eligible is False

        ProfileService.update_baseline_from_event(
            db=db_session,
            user_id=user.id,
            event_vector=FULL_ACTIVE_VEC,
            risk_score=case["risk_score"],
            session_status=case["session_status"],
            decision=case["decision"],
            event_id=f"behavior_log:bad_{idx}",
            is_anomaly=case["is_anomaly"],
            anomaly_score=case["anomaly_score"],
        )

        _insert_behavior_log(
            db_session,
            user.id,
            FULL_ACTIVE_VEC,
            raw_feature_json=json.dumps({
                "event_id": f"behavior_log:bad_{idx}",
                "is_trusted": True,
                "ml_registered": True,
                "session_status": case["session_status"],
                "decision": case["decision"],
                "risk_score": case["risk_score"],
                "is_anomaly": case["is_anomaly"],
                "anomaly_score": case["anomaly_score"],
            }),
        )

    assert len(ModelManager._user_training_data.get(user.id, [])) == 0
    ModelManager.reset_memory()
    ModelManager.ensure_hydrated(db_session, user.id)
    assert len(ModelManager._user_training_data.get(user.id, [])) == 0


# ------------------------------------------------------------------------------
# 14. 25 valid trusted observations still fit Isolation Forest and preserve existing lifecycle behavior
# ------------------------------------------------------------------------------
def test_14_twenty_five_trusted_observations_fit_isolation_forest_and_hydrate(db_session: Session):
    user = _create_isolated_user(db_session, "step445.fit25@cognisec.ai")
    rng = np.random.default_rng(42)

    for i in range(25):
        jitter = rng.normal(0.0, 0.5, size=10)
        vec = np.clip(FULL_ACTIVE_VEC + jitter, 0.1, None)
        event_id = f"behavior_log:fit25_{i}"
        ProfileService.update_baseline_from_event(
            db=db_session,
            user_id=user.id,
            event_vector=vec,
            risk_score=0.08,
            session_status="ACTIVE",
            decision="ALLOW",
            event_id=event_id,
        )
        _, _, resolved = FeatureEngineering.evaluate_training_eligibility(
            event_vector=vec, user_id=user.id, is_trusted=True
        )
        _insert_behavior_log(
            db_session,
            user.id,
            vec,
            raw_feature_json=json.dumps({
                "event_id": event_id,
                "is_trusted": True,
                "ml_registered": True,
                "decision": "ALLOW",
                "risk_score": 0.08,
                "anomaly_score": 0.05,
                "is_anomaly": False,
                "observed_features": resolved,
            }),
        )

    detector = ModelManager.get_user_detector(user.id)
    assert detector.is_fitted is True
    assert detector.trained_sample_count == 25
    assert len(ModelManager._user_training_data[user.id]) == 25

    # Simulate server restart and verify hydration reconstructs all 25 vectors and fits the IF model
    ModelManager.reset_memory()
    hydrated_detector = ModelManager.ensure_hydrated(db_session, user.id)
    assert hydrated_detector.is_fitted is True
    assert hydrated_detector.trained_sample_count == 25
    assert len(ModelManager._user_training_data[user.id]) == 25
