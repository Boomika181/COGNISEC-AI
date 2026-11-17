"""
COGNISEC-AI — Phase II, Step 4.4.1
Focused Verification and Regression Suite for:
- F-01: Click metadata ordering in cognisec-client.js (computeTelemetrySnapshot)
- F-02: Missing-feature imputation consistency in IsolationForestDetector.predict_anomaly()
"""

import json
import math
import shutil
import subprocess
from pathlib import Path
import numpy as np
import pytest
from sqlalchemy.orm import Session

from app.ml.feature_engineering import FeatureEngineering, FEATURE_NAMES
from app.ml.anomaly_detector import IsolationForestDetector
from app.services.profile_service import ProfileService
from app.services.risk_service import RiskService
from app.models.user import User
from app.core.security import get_password_hash


REPO_ROOT = Path(__file__).resolve().parents[2]
CLIENT_JS_PATH = REPO_ROOT / "cognisec-client.js"


BASELINE_MEANS = {
    "typing_speed_wpm": 65.0,
    "avg_flight_time_ms": 115.0,
    "avg_dwell_time_ms": 85.0,
    "mouse_velocity_avg": 420.0,
    "mouse_acceleration_avg": 550.0,
    "mouse_curvature_entropy": 1.25,
    "click_frequency": 0.80,
    "scroll_speed_avg": 180.0,
    "idle_duration_sec": 2.0,
    "navigation_entropy": 0.90,
}

BASELINE_STDS = {
    "typing_speed_wpm": 5.0,
    "avg_flight_time_ms": 15.0,
    "avg_dwell_time_ms": 10.0,
    "mouse_velocity_avg": 50.0,
    "mouse_acceleration_avg": 50.0,
    "mouse_curvature_entropy": 0.05,
    "click_frequency": 0.25,
    "scroll_speed_avg": 50.0,
    "idle_duration_sec": 1.0,
    "navigation_entropy": 0.05,
}


def make_baseline_stats() -> dict:
    return {
        "means": dict(BASELINE_MEANS),
        "stds": dict(BASELINE_STDS),
        "m2": {feat: 0.0 for feat in FEATURE_NAMES},
        "sample_counts": {feat: 10 for feat in FEATURE_NAMES},
    }


def expected_welford_score(eval_vec: np.ndarray, baseline_stats: dict, learning: bool = False) -> float:
    z_vec = IsolationForestDetector.standardize_vector(eval_vec, baseline_stats)
    avg_z = float(np.mean(np.abs(z_vec)))
    if learning:
        return round(float(np.clip(1.0 - math.exp(-avg_z / 4.0), 0.05, 0.35)), 4)
    return round(float(np.clip(1.0 - math.exp(-avg_z / 2.5), 0.0, 1.0)), 4)


# ==============================================================================
# PART 1: F-01 — CLICK METADATA ORDERING IN cognisec-client.js
# ==============================================================================

def test_f01_client_js_captures_window_clicks_before_reset():
    """
    Verifies in cognisec-client.js source and via Node.js execution of
    computeTelemetrySnapshot() that:
    1. windowClicks is captured before this.clickCount = 0.
    2. A click-only observation sets sample_counts.clicks > 0 and observed_modalities.mouse = true.
    3. A zero-click mouse trajectory observation sets sample_counts.clicks = 0 and observed_modalities.mouse = true.
    4. Clicks do not accumulate across subsequent observation windows.
    """
    js_source = CLIENT_JS_PATH.read_text(encoding="utf-8")
    start_idx = js_source.index("computeTelemetrySnapshot() {")
    end_idx = js_source.index("// --- TELEMETRY DISPATCH TO FASTAPI ---", start_idx)
    method_body = js_source[start_idx:end_idx]

    # Verify ordering in source: windowClicks captured and assigned to snapshot structures before reset
    assert "const windowClicks = this.clickCount || 0;" in method_body
    assert "clicks: windowClicks" in method_body
    assert "mouse: (this.mousePoints || []).length >= 4 || windowClicks > 0" in method_body
    assert method_body.index("const windowClicks = this.clickCount || 0;") < method_body.index("this.clickCount = 0;")
    assert method_body.index("clicks: windowClicks") < method_body.index("this.clickCount = 0;")

    node_bin = shutil.which("node")
    if node_bin:
        harness = f"""
        const fs = require('fs');
        const src = fs.readFileSync({json.dumps(str(CLIENT_JS_PATH))}, 'utf8');
        const start = src.indexOf('computeTelemetrySnapshot() {{');
        const end = src.indexOf('// --- TELEMETRY DISPATCH TO FASTAPI ---', start);
        const methodCode = src.slice(start, end);
        const ObjClass = new Function('return class DummyClient {{ ' + methodCode + ' }}')();
        const client = new ObjClass();
        const nowPerf = performance.now();
        const nowEpoch = Date.now();

        // Window 1: Click-only observation (3 stationary clicks, 0 mouse points)
        client.sessionId = 'sess_f01';
        client.application = 'shopping';
        client.keyPressTimings = [];
        client.dwellTimings = [];
        client.mousePoints = [];
        client.scrollSpeeds = [];
        client.navigationHistory = [];
        client.hasRealInteraction = true;
        client.lastInteractionTime = nowEpoch - 1000;
        client.lastTelemetryDispatchTime = nowEpoch - 6000;
        client.clickCount = 3;
        client.sequenceNumber = 0;

        const snap1 = client.computeTelemetrySnapshot();

        // Window 2: Subsequent idle/no-click window (verifies no click accumulation)
        client.lastTelemetryDispatchTime = Date.now() - 6000;
        const snap2 = client.computeTelemetrySnapshot();

        // Window 3: Genuine zero-click mouse movement (5 mouse points, 0 clicks)
        const t0 = performance.now();
        client.mousePoints = [
          {{ x: 10, y: 10, t: t0 - 400, dt: 50 }},
          {{ x: 40, y: 20, t: t0 - 300, dt: 100 }},
          {{ x: 80, y: 35, t: t0 - 200, dt: 100 }},
          {{ x: 130, y: 50, t: t0 - 100, dt: 100 }},
          {{ x: 190, y: 70, t: t0 - 10, dt: 90 }}
        ];
        client.clickCount = 0;
        client.lastTelemetryDispatchTime = Date.now() - 5000;
        const snap3 = client.computeTelemetrySnapshot();

        // Window 4: 2 new clicks in a fresh window (verifies exact count = 2, not 3+2=5)
        client.mousePoints = [];
        client.clickCount = 2;
        client.lastTelemetryDispatchTime = Date.now() - 4000;
        const snap4 = client.computeTelemetrySnapshot();

        console.log(JSON.stringify({{ snap1, snap2, snap3, snap4, finalClickCount: client.clickCount }}));
        """
        proc = subprocess.run([node_bin, "-e", harness], capture_output=True, text=True, check=True)
        out = json.loads(proc.stdout.strip())

        # 1. Click-only observation
        snap1 = out["snap1"]
        assert snap1["click_frequency"] > 0.0
        assert snap1["sample_counts"]["clicks"] == 3
        assert snap1["context_signals"]["sample_counts"]["clicks"] == 3
        assert snap1["sample_counts"]["mouse_points"] == 0
        assert snap1["observed_modalities"]["mouse"] is True
        assert snap1["context_signals"]["observed_modalities"]["mouse"] is True

        # 2. Subsequent window with no clicks -> counter was reset to 0, does not accumulate
        snap2 = out["snap2"]
        assert snap2["click_frequency"] == 0.0
        assert snap2["sample_counts"]["clicks"] == 0
        assert snap2["context_signals"]["sample_counts"]["clicks"] == 0
        assert snap2["observed_modalities"]["mouse"] is False

        # 3. Genuine zero-click mouse movement -> mouse=True via trajectory points, clicks=0
        snap3 = out["snap3"]
        assert snap3["mouse_velocity_avg"] > 0.0
        assert snap3["click_frequency"] == 0.0
        assert snap3["sample_counts"]["clicks"] == 0
        assert snap3["sample_counts"]["mouse_points"] == 5
        assert snap3["observed_modalities"]["mouse"] is True

        # 4. Fresh window with 2 clicks -> reports 2, not accumulated 5
        snap4 = out["snap4"]
        assert snap4["sample_counts"]["clicks"] == 2
        assert snap4["observed_modalities"]["mouse"] is True
        assert out["finalClickCount"] == 0


def test_f01_click_only_observation_updates_click_baseline_without_diluting_trajectory(db_session: Session):
    """
    Verifies end-to-end backend handling of a click-only snapshot produced after the F-01 fix:
    - click_frequency > 0, sample_counts={'clicks': 3, 'mouse_points': 0}, observed_modalities={'mouse': True}
    - click_frequency and idle_duration_sec update in the Welford baseline
    - Unobserved mouse trajectory features (velocity, acceleration, curvature) and keyboard features are NOT diluted with zeros.
    """
    user = User(
        name="Click Only User",
        email="click.only.step441@cognisec.ai",
        password_hash=get_password_hash("ValidPass123!"),
        role="USER",
        account_status="ACTIVE"
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    profile = ProfileService.get_or_create_profile(db_session, user.id)
    seed_vec = np.array([65.0, 115.0, 85.0, 420.0, 550.0, 1.25, 0.80, 180.0, 2.0, 0.90], dtype=np.float64)
    for _ in range(5):
        ProfileService.update_baseline_from_event(
            db=db_session,
            user_id=user.id,
            event_vector=seed_vec,
            risk_score=0.10,
            session_status="ACTIVE",
            decision="ALLOW"
        )

    db_session.refresh(profile)
    before = ProfileService.get_profile_dict(profile)

    # Stationary click-only observation (3 clicks in 6s -> 0.5 clicks/s, 0 mouse_points)
    click_only_vec = np.array([0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.50, 0.0, 1.0, 0.0], dtype=np.float64)
    sample_counts = {"keystrokes": 0, "mouse_points": 0, "clicks": 3, "scrolls": 0, "navigations": 0}
    observed_modalities = {
        "keyboard": False,
        "mouse": True,
        "scroll": False,
        "navigation": False,
        "inactivity": True
    }

    obs_mask = FeatureEngineering.resolve_observed_features(
        click_only_vec,
        observed_modalities=observed_modalities,
        sample_counts=sample_counts
    )
    assert obs_mask == {
        "typing_speed_wpm": False,
        "avg_flight_time_ms": False,
        "avg_dwell_time_ms": False,
        "mouse_velocity_avg": False,
        "mouse_acceleration_avg": False,
        "mouse_curvature_entropy": False,
        "click_frequency": True,
        "scroll_speed_avg": False,
        "idle_duration_sec": True,
        "navigation_entropy": False,
    }

    updated = ProfileService.update_baseline_from_event(
        db=db_session,
        user_id=user.id,
        event_vector=click_only_vec,
        risk_score=0.10,
        session_status="ACTIVE",
        decision="ALLOW",
        observed_modalities=observed_modalities,
        sample_counts=sample_counts
    )
    after = ProfileService.get_profile_dict(updated)

    # click_frequency and idle_duration_sec updated (sample count 5 -> 6)
    assert after["sample_counts"]["click_frequency"] == 6
    assert after["sample_counts"]["idle_duration_sec"] == 6
    assert math.isclose(after["means"]["click_frequency"], (5 * 0.80 + 0.50) / 6.0, rel_tol=1e-6)

    # Mouse trajectory and keyboard statistics untouched (sample count remains 5, means unchanged)
    for untouched_feat in [
        "typing_speed_wpm",
        "avg_flight_time_ms",
        "avg_dwell_time_ms",
        "mouse_velocity_avg",
        "mouse_acceleration_avg",
        "mouse_curvature_entropy",
        "scroll_speed_avg",
        "navigation_entropy",
    ]:
        assert after["sample_counts"][untouched_feat] == 5
        assert after["means"][untouched_feat] == before["means"][untouched_feat]


# ==============================================================================
# PART 2: F-02 — MISSING-FEATURE IMPUTATION IN ANOMALY SCORING
# ==============================================================================

def test_f02_keyboard_only_observation_imputes_all_missing_features():
    """
    1. Keyboard-only observation:
    Verifies that indices 3, 4, 5, 6 (all 4 mouse features, including curvature & click_frequency),
    index 7 (scroll_speed_avg), and index 9 (navigation_entropy) are imputed from baseline means,
    while observed keyboard features (0, 1, 2) and idle_duration_sec (8) are preserved.
    """
    detector = IsolationForestDetector()
    baseline = make_baseline_stats()

    # Input: keyboard active, idle=2.0, all mouse/scroll/navigation features missing (0.0)
    input_vec = np.array([68.0, 112.0, 83.0, 0.0, 0.0, 0.0, 0.0, 0.0, 2.0, 0.0], dtype=np.float64)

    eval_vec, mask = detector.build_evaluation_vector(input_vec, baseline)

    assert len(eval_vec) == 10
    assert mask == {
        "typing_speed_wpm": True,
        "avg_flight_time_ms": True,
        "avg_dwell_time_ms": True,
        "mouse_velocity_avg": False,
        "mouse_acceleration_avg": False,
        "mouse_curvature_entropy": False,
        "click_frequency": False,
        "scroll_speed_avg": False,
        "idle_duration_sec": True,
        "navigation_entropy": False,
    }

    expected_eval = np.array([
        68.0,   # observed typing_speed_wpm
        112.0,  # observed avg_flight_time_ms
        83.0,   # observed avg_dwell_time_ms
        420.0,  # imputed mouse_velocity_avg
        550.0,  # imputed mouse_acceleration_avg
        1.25,   # imputed mouse_curvature_entropy (F-02 fix!)
        0.80,   # imputed click_frequency (F-02 fix!)
        180.0,  # imputed scroll_speed_avg (F-02 fix!)
        2.0,    # observed idle_duration_sec
        0.90,   # imputed navigation_entropy (F-02 fix!)
    ], dtype=np.float64)
    np.testing.assert_allclose(eval_vec, expected_eval)

    # Input vector and baseline must never be mutated
    assert input_vec[5] == 0.0 and input_vec[6] == 0.0
    assert baseline["means"]["mouse_curvature_entropy"] == 1.25

    expected_score = expected_welford_score(expected_eval, baseline, learning=False)
    is_ano, actual_score, status = detector.predict_anomaly(input_vec, baseline, sample_count=10)
    assert status == "ML_READY"
    assert actual_score == expected_score
    assert actual_score == 0.0392  # avg_z = (0.6 + 0.2 + 0.2 + 0)/10 = 0.10 -> 1 - exp(-0.10/2.5) = 0.0392
    assert is_ano is False


def test_f02_mouse_only_observation_imputes_all_missing_features():
    """
    2. Mouse-only observation:
    Verifies that indices 0, 1, 2 (keyboard), 7 (scroll), and 9 (navigation) are imputed
    from baseline means while observed mouse features (3, 4, 5, 6) and idle (8) are preserved.
    """
    detector = IsolationForestDetector()
    baseline = make_baseline_stats()

    input_vec = np.array([0.0, 0.0, 0.0, 445.0, 575.0, 1.28, 0.90, 0.0, 1.5, 0.0], dtype=np.float64)
    eval_vec, mask = detector.build_evaluation_vector(input_vec, baseline)

    assert mask == {
        "typing_speed_wpm": False,
        "avg_flight_time_ms": False,
        "avg_dwell_time_ms": False,
        "mouse_velocity_avg": True,
        "mouse_acceleration_avg": True,
        "mouse_curvature_entropy": True,
        "click_frequency": True,
        "scroll_speed_avg": False,
        "idle_duration_sec": True,
        "navigation_entropy": False,
    }

    expected_eval = np.array([
        65.0,   # imputed typing_speed_wpm
        115.0,  # imputed avg_flight_time_ms
        85.0,   # imputed avg_dwell_time_ms
        445.0,  # observed mouse_velocity_avg
        575.0,  # observed mouse_acceleration_avg
        1.28,   # observed mouse_curvature_entropy
        0.90,   # observed click_frequency
        180.0,  # imputed scroll_speed_avg
        1.5,    # observed idle_duration_sec
        0.90,   # imputed navigation_entropy
    ], dtype=np.float64)
    np.testing.assert_allclose(eval_vec, expected_eval)

    expected_score = expected_welford_score(expected_eval, baseline, learning=False)
    is_ano, actual_score, status = detector.predict_anomaly(input_vec, baseline, sample_count=10)
    assert status == "ML_READY"
    assert actual_score == expected_score
    assert actual_score == 0.0952  # avg_z = (0.5 + 0.5 + 0.6 + 0.4 + 0.5)/10 = 0.25 -> 1 - exp(-0.25/2.5) = 0.0952
    assert is_ano is False


def test_f02_scroll_only_observation_imputes_all_missing_features():
    """
    3. Scroll-only observation:
    Verifies that indices 0..6 (keyboard + mouse) and 9 (navigation) are imputed from baseline means
    while observed scroll_speed_avg (7) and idle_duration_sec (8) are preserved.
    """
    detector = IsolationForestDetector()
    baseline = make_baseline_stats()

    input_vec = np.array([0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 230.0, 1.5, 0.0], dtype=np.float64)
    eval_vec, mask = detector.build_evaluation_vector(input_vec, baseline)

    assert mask == {
        "typing_speed_wpm": False,
        "avg_flight_time_ms": False,
        "avg_dwell_time_ms": False,
        "mouse_velocity_avg": False,
        "mouse_acceleration_avg": False,
        "mouse_curvature_entropy": False,
        "click_frequency": False,
        "scroll_speed_avg": True,
        "idle_duration_sec": True,
        "navigation_entropy": False,
    }

    expected_eval = np.array([
        65.0, 115.0, 85.0, 420.0, 550.0, 1.25, 0.80, 230.0, 1.5, 0.90
    ], dtype=np.float64)
    np.testing.assert_allclose(eval_vec, expected_eval)

    expected_score = expected_welford_score(expected_eval, baseline, learning=False)
    is_ano, actual_score, status = detector.predict_anomaly(input_vec, baseline, sample_count=10)
    assert status == "ML_READY"
    assert actual_score == expected_score
    assert actual_score == 0.0582  # avg_z = (1.0 + 0.5)/10 = 0.15 -> 1 - exp(-0.15/2.5) = 0.0582
    assert is_ano is False


def test_f02_navigation_only_observation_imputes_all_missing_features():
    """
    4. Navigation-only observation:
    Verifies that indices 0..7 (keyboard, mouse, scroll) are imputed from baseline means
    while observed idle_duration_sec (8) and navigation_entropy (9) are preserved.
    """
    detector = IsolationForestDetector()
    baseline = make_baseline_stats()

    input_vec = np.array([0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.95], dtype=np.float64)
    eval_vec, mask = detector.build_evaluation_vector(input_vec, baseline)

    assert mask == {
        "typing_speed_wpm": False,
        "avg_flight_time_ms": False,
        "avg_dwell_time_ms": False,
        "mouse_velocity_avg": False,
        "mouse_acceleration_avg": False,
        "mouse_curvature_entropy": False,
        "click_frequency": False,
        "scroll_speed_avg": False,
        "idle_duration_sec": True,
        "navigation_entropy": True,
    }

    expected_eval = np.array([
        65.0, 115.0, 85.0, 420.0, 550.0, 1.25, 0.80, 180.0, 1.0, 0.95
    ], dtype=np.float64)
    np.testing.assert_allclose(eval_vec, expected_eval)

    expected_score = expected_welford_score(expected_eval, baseline, learning=False)
    is_ano, actual_score, status = detector.predict_anomaly(input_vec, baseline, sample_count=10)
    assert status == "ML_READY"
    assert actual_score == expected_score
    assert actual_score == 0.0769  # avg_z = (1.0 + 1.0)/10 = 0.20 -> 1 - exp(-0.20/2.5) = 0.0769
    assert is_ano is False


def test_f02_mixed_modalities_keyboard_and_scroll():
    """
    5. Mixed modalities (Keyboard + Scroll active; Mouse + Navigation missing):
    Verifies selective imputation of only the unobserved modalities (indices 3..6 and 9).
    """
    detector = IsolationForestDetector()
    baseline = make_baseline_stats()

    input_vec = np.array([70.0, 100.0, 80.0, 0.0, 0.0, 0.0, 0.0, 205.0, 2.0, 0.0], dtype=np.float64)
    eval_vec, mask = detector.build_evaluation_vector(input_vec, baseline)

    assert mask == {
        "typing_speed_wpm": True,
        "avg_flight_time_ms": True,
        "avg_dwell_time_ms": True,
        "mouse_velocity_avg": False,
        "mouse_acceleration_avg": False,
        "mouse_curvature_entropy": False,
        "click_frequency": False,
        "scroll_speed_avg": True,
        "idle_duration_sec": True,
        "navigation_entropy": False,
    }

    expected_eval = np.array([
        70.0, 100.0, 80.0, 420.0, 550.0, 1.25, 0.80, 205.0, 2.0, 0.90
    ], dtype=np.float64)
    np.testing.assert_allclose(eval_vec, expected_eval)

    expected_score = expected_welford_score(expected_eval, baseline, learning=False)
    is_ano, actual_score, status = detector.predict_anomaly(input_vec, baseline, sample_count=10)
    assert status == "ML_READY"
    assert actual_score == expected_score
    assert actual_score == 0.1131  # avg_z = (1.0 + 1.0 + 0.5 + 0.5 + 0.0)/10 = 0.30 -> 1 - exp(-0.30/2.5) = 0.1131
    assert is_ano is False


def test_f02_genuine_zero_valued_observed_features_are_preserved_not_imputed():
    """
    6. Genuine zero-valued observed features:
    - Straight-line mouse movement without clicking produces genuine 0.0 for
      mouse_curvature_entropy (index 5) and click_frequency (index 6).
    - Stopped scroll with sample_counts={'scrolls': 3} produces genuine 0.0 for scroll_speed_avg (index 7).
    - Continuous active interaction produces genuine 0.0 for idle_duration_sec (index 8).
    - Single-category navigation with sample_counts={'navigations': 2} produces genuine 0.0 for navigation_entropy (index 9).
    None of these genuine observed zeros may be overwritten with baseline means!
    """
    detector = IsolationForestDetector()
    baseline = make_baseline_stats()

    # Mouse moving in a straight line (vel=420, acc=550), curv=0.0, click=0.0, scroll=0.0 (with 3 scroll events),
    # idle=0.0, nav=0.0 (with 2 nav events); keyboard missing (0.0)
    input_vec = np.array([0.0, 0.0, 0.0, 420.0, 550.0, 0.0, 0.0, 0.0, 0.0, 0.0], dtype=np.float64)
    counts = {"keystrokes": 0, "mouse_points": 12, "clicks": 0, "scrolls": 3, "navigations": 2}
    modalities = {"keyboard": False, "mouse": True, "scroll": True, "navigation": True, "inactivity": True}

    eval_vec, mask = detector.build_evaluation_vector(
        input_vec,
        baseline,
        observed_modalities=modalities,
        sample_counts=counts
    )

    assert mask == {
        "typing_speed_wpm": False,
        "avg_flight_time_ms": False,
        "avg_dwell_time_ms": False,
        "mouse_velocity_avg": True,
        "mouse_acceleration_avg": True,
        "mouse_curvature_entropy": True,
        "click_frequency": True,
        "scroll_speed_avg": True,
        "idle_duration_sec": True,
        "navigation_entropy": True,
    }

    # Keyboard (0..2) is imputed from baseline; indices 5, 6, 7, 8, 9 MUST remain 0.0!
    expected_eval = np.array([
        65.0,   # imputed typing_speed_wpm
        115.0,  # imputed avg_flight_time_ms
        85.0,   # imputed avg_dwell_time_ms
        420.0,  # observed mouse_velocity_avg
        550.0,  # observed mouse_acceleration_avg
        0.0,    # GENUINE OBSERVED ZERO mouse_curvature_entropy (preserved!)
        0.0,    # GENUINE OBSERVED ZERO click_frequency (preserved!)
        0.0,    # GENUINE OBSERVED ZERO scroll_speed_avg (preserved!)
        0.0,    # GENUINE OBSERVED ZERO idle_duration_sec (preserved!)
        0.0,    # GENUINE OBSERVED ZERO navigation_entropy (preserved!)
    ], dtype=np.float64)
    np.testing.assert_allclose(eval_vec, expected_eval)

    expected_score = expected_welford_score(expected_eval, baseline, learning=False)
    is_ano, actual_score, status = detector.predict_anomaly(
        input_vec,
        baseline,
        sample_count=10,
        observed_modalities=modalities,
        sample_counts=counts
    )
    assert status == "ML_READY"
    assert actual_score == expected_score
    # |z_5|=25.0, |z_6|=3.2, |z_7|=3.6, |z_8|=2.0, |z_9|=18.0 -> avg_z = 5.18 -> 1 - exp(-5.18/2.5) = 0.8741
    assert actual_score == 0.8741
    assert is_ano is True


def test_f02_learning_state_and_hybrid_if_scoring_with_missing_features():
    """
    7. Missing values with nonzero baseline means across both ML_LEARNING (n < 5)
    and hybrid Isolation Forest + Welford (n >= 25), plus dimension & order consistency.
    """
    baseline = make_baseline_stats()
    detector = IsolationForestDetector(min_samples_for_training=25, random_state=42)

    # Keyboard-only sample matching baseline means exactly
    kb_exact_vec = np.array([65.0, 115.0, 85.0, 0.0, 0.0, 0.0, 0.0, 0.0, 2.0, 0.0], dtype=np.float64)
    eval_vec, mask = detector.build_evaluation_vector(kb_exact_vec, baseline)

    # All 10 features in eval_vec now match BASELINE_MEANS exactly -> z = 0 across all 10 dimensions
    expected_full_means = np.array([BASELINE_MEANS[name] for name in FEATURE_NAMES], dtype=np.float64)
    np.testing.assert_allclose(eval_vec, expected_full_means)
    assert list(mask.keys()) == FEATURE_NAMES

    # In ML_LEARNING (sample_count=3): avg_z = 0.0 -> clipped to minimum 0.05
    is_ano_learn, score_learn, status_learn = detector.predict_anomaly(kb_exact_vec, baseline, sample_count=3)
    assert status_learn == "ML_LEARNING"
    assert is_ano_learn is False
    assert score_learn == 0.05

    # Fit Isolation Forest on 25 normal samples around BASELINE_MEANS
    rng = np.random.RandomState(42)
    means_arr = expected_full_means
    stds_arr = np.array([BASELINE_STDS[name] for name in FEATURE_NAMES], dtype=np.float64)
    train_matrix = np.array([means_arr + rng.normal(0.0, 0.25, size=10) * stds_arr for _ in range(25)], dtype=np.float64)
    detector.fit(train_matrix, baseline)
    assert detector.is_fitted is True

    # Score keyboard-only sample with fitted IF (sample_count=25)
    is_ano_if, score_if, status_if = detector.predict_anomaly(kb_exact_vec, baseline, sample_count=25)
    assert status_if == "ML_READY"
    assert is_ano_if is False
    assert score_if < 0.30

