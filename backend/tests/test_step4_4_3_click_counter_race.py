"""
COGNISEC-AI — Phase II, Step 4.4.3
Focused Verification and Regression Suite for:
- Click counter in-flight HTTP request race condition fix in cognisec-client.js
"""

import json
import shutil
import subprocess
from pathlib import Path
import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
CLIENT_JS_PATH = REPO_ROOT / "cognisec-client.js"


def _extract_js_methods_source() -> str:
    """
    Extracts computeTelemetrySnapshot() and sendBehaviorTelemetry() verbatim
    from cognisec-client.js so tests execute the actual production JavaScript.
    """
    js_source = CLIENT_JS_PATH.read_text(encoding="utf-8")
    start_idx = js_source.index("computeTelemetrySnapshot() {")
    end_idx = js_source.index("startTelemetryLoop() {", start_idx)
    return js_source[start_idx:end_idx]


def test_step4_4_3_send_behavior_telemetry_has_no_post_await_click_reset():
    """
    Verifies in cognisec-client.js source that:
    1. computeTelemetrySnapshot() atomically captures windowClicks and resets this.clickCount = 0 synchronously.
    2. sendBehaviorTelemetry() does NOT reset this.clickCount after awaiting fetch() / res.json().
    """
    js_source = CLIENT_JS_PATH.read_text(encoding="utf-8")

    snap_start = js_source.index("computeTelemetrySnapshot() {")
    send_start = js_source.index("async sendBehaviorTelemetry() {", snap_start)
    loop_start = js_source.index("startTelemetryLoop() {", send_start)

    snap_body = js_source[snap_start:send_start]
    send_body = js_source[send_start:loop_start]

    # computeTelemetrySnapshot must capture windowClicks before resetting this.clickCount = 0
    assert "const windowClicks = this.clickCount || 0;" in snap_body
    assert "this.clickCount = 0;" in snap_body
    assert snap_body.index("const windowClicks = this.clickCount || 0;") < snap_body.index("this.clickCount = 0;")

    # sendBehaviorTelemetry must NOT contain any post-request this.clickCount = 0 reset
    assert "this.clickCount = 0" not in send_body


def test_step4_4_3_in_flight_request_preserves_concurrent_clicks():
    """
    Reproduces the exact 5-step sequence from Step 4.4.3 using a controlled
    deferred Promise for fetch() (no timers or sleeps):
    1. Three clicks occur before a telemetry snapshot.
    2. The snapshot captures three clicks and resets its window counter.
    3. The HTTP request remains in flight.
    4. Two additional clicks occur.
    5. The HTTP request completes.
    Verifies the next observation contains the two new clicks, not zero.
    """
    node_bin = shutil.which("node")
    assert node_bin is not None, "Node.js is required to execute JavaScript telemetry regression tests"

    methods_code = _extract_js_methods_source()

    harness = f"""
    const methodsCode = {json.dumps(methods_code)};

    const pendingRequests = [];
    global.COGNISEC_API_BASE = 'http://127.0.0.1:8000/api';
    global.localStorage = {{
      _store: {{}},
      setItem(k, v) {{ this._store[k] = String(v); }},
      getItem(k) {{ return Object.prototype.hasOwnProperty.call(this._store, k) ? this._store[k] : null; }},
      removeItem(k) {{ delete this._store[k]; }}
    }};
    global.CustomEvent = class CustomEvent {{
      constructor(type, init) {{
        this.type = type;
        this.detail = init ? init.detail : undefined;
      }}
    }};
    global.window = {{
      dispatchEvent() {{}}
    }};
    global.fetch = function(url, options) {{
      let resolveFetch, rejectFetch;
      const promise = new Promise((resolve, reject) => {{
        resolveFetch = resolve;
        rejectFetch = reject;
      }});
      pendingRequests.push({{
        url,
        options,
        payload: JSON.parse(options.body),
        resolve: resolveFetch,
        reject: rejectFetch
      }});
      return promise;
    }};

    const ClientClass = new Function(
      'return class TestCognisecClient {{\\n' +
      '  constructor() {{\\n' +
      '    this.token = "test_jwt_token";\\n' +
      '    this.sessionId = "sess_race_test";\\n' +
      '    this.application = "shopping";\\n' +
      '    this.keyPressTimings = [];\\n' +
      '    this.dwellTimings = [];\\n' +
      '    this.mousePoints = [];\\n' +
      '    this.scrollSpeeds = [];\\n' +
      '    this.navigationHistory = [];\\n' +
      '    this.hasRealInteraction = true;\\n' +
      '    this.lastInteractionTime = Date.now() - 500;\\n' +
      '    this.lastTelemetryDispatchTime = Date.now() - 6000;\\n' +
      '    this.clickCount = 0;\\n' +
      '    this.scrollDeltaSum = 0;\\n' +
      '    this.sequenceNumber = 0;\\n' +
      '  }}\\n' +
      '  getHeaders() {{\\n' +
      '    return {{ "Content-Type": "application/json", "Authorization": "Bearer " + this.token }};\\n' +
      '  }}\\n' +
      '  recordClick() {{\\n' +
      '    this.clickCount++;\\n' +
      '    this.hasRealInteraction = true;\\n' +
      '    this.lastInteractionTime = Date.now();\\n' +
      '  }}\\n' +
      methodsCode + '\\n}}'
    )();

    (async () => {{
      const client = new ClientClass();

      // Step 1: Three clicks occur before a telemetry snapshot.
      client.recordClick();
      client.recordClick();
      client.recordClick();
      const clicksBeforeSnap1 = client.clickCount;

      // Step 2: Start sendBehaviorTelemetry(); snapshot captures 3 clicks and resets window counter.
      const inFlightPromise1 = client.sendBehaviorTelemetry();
      const clicksImmediatelyAfterSnap1 = client.clickCount;

      // Step 3: Verify HTTP request 1 is currently in flight (unresolved).
      if (pendingRequests.length !== 1) {{
        throw new Error('Expected exactly 1 in-flight request, got ' + pendingRequests.length);
      }}

      // Step 4: Two additional clicks occur while request 1 is in flight.
      client.recordClick();
      client.recordClick();
      const clicksWhileInFlight = client.clickCount;

      // Step 5: Complete the in-flight HTTP request 1.
      pendingRequests[0].resolve({{
        ok: true,
        status: 200,
        json: async () => ({{
          status: 'recorded',
          risk_score: 0.08,
          risk_level: 'LOW',
          decision: 'ALLOW',
          session_status: 'ACTIVE'
        }})
      }});
      const res1 = await inFlightPromise1;
      const clicksAfterReq1Completed = client.clickCount;

      // Next observation: dispatch second telemetry snapshot and inspect captured payload.
      client.lastTelemetryDispatchTime = Date.now() - 6000;
      const inFlightPromise2 = client.sendBehaviorTelemetry();
      pendingRequests[1].resolve({{
        ok: true,
        status: 200,
        json: async () => ({{
          status: 'recorded',
          risk_score: 0.08,
          risk_level: 'LOW',
          decision: 'ALLOW',
          session_status: 'ACTIVE'
        }})
      }});
      const res2 = await inFlightPromise2;

      console.log('TEST_JSON_OUT:' + JSON.stringify({{
        clicksBeforeSnap1,
        clicksImmediatelyAfterSnap1,
        clicksWhileInFlight,
        clicksAfterReq1Completed,
        finalClickCount: client.clickCount,
        res1Success: res1.success,
        res2Success: res2.success,
        payload1: pendingRequests[0].payload,
        payload2: pendingRequests[1].payload
      }}));
    }})().catch(err => {{
      console.error(err);
      process.exit(1);
    }});
    """

    proc = subprocess.run([node_bin, "-e", harness], capture_output=True, text=True, check=True)
    json_line = [line for line in proc.stdout.splitlines() if line.startswith("TEST_JSON_OUT:")][-1]
    out = json.loads(json_line.removeprefix("TEST_JSON_OUT:"))

    # Verify exact state transitions across the 5 steps
    assert out["clicksBeforeSnap1"] == 3
    assert out["clicksImmediatelyAfterSnap1"] == 0
    assert out["clicksWhileInFlight"] == 2
    assert out["clicksAfterReq1Completed"] == 2, (
        "Clicks recorded while HTTP request was in flight must not be erased when the request completes"
    )
    assert out["finalClickCount"] == 0
    assert out["res1Success"] is True
    assert out["res2Success"] is True

    # Verify Snapshot 1 captured the 3 pre-snapshot clicks
    p1 = out["payload1"]
    assert p1["sample_counts"]["clicks"] == 3
    assert p1["context_signals"]["sample_counts"]["clicks"] == 3
    assert p1["observed_modalities"]["mouse"] is True
    assert p1["context_signals"]["observed_modalities"]["mouse"] is True
    assert p1["click_frequency"] > 0.0

    # Verify Snapshot 2 captured the 2 in-flight clicks (not 0 and not 5)
    p2 = out["payload2"]
    assert p2["sample_counts"]["clicks"] == 2
    assert p2["context_signals"]["sample_counts"]["clicks"] == 2
    assert p2["observed_modalities"]["mouse"] is True
    assert p2["context_signals"]["observed_modalities"]["mouse"] is True
    assert p2["click_frequency"] > 0.0


def test_step4_4_3_consecutive_windows_failures_and_retries_lose_or_duplicate_zero_clicks():
    """
    Tests:
    - Clicks before snapshot, during in-flight request, and after request completion.
    - Multiple consecutive snapshots.
    - Failed HTTP request (both HTTP 500 response and network exception).
    - Retry behaviour after failure.
    - Conservation invariant: every recorded click is accounted for in exactly one snapshot
      (no lost clicks, no duplicated clicks).
    """
    node_bin = shutil.which("node")
    assert node_bin is not None, "Node.js is required to execute JavaScript telemetry regression tests"

    methods_code = _extract_js_methods_source()

    harness = f"""
    const methodsCode = {json.dumps(methods_code)};

    const pendingRequests = [];
    global.COGNISEC_API_BASE = 'http://127.0.0.1:8000/api';
    global.localStorage = {{
      _store: {{}},
      setItem(k, v) {{ this._store[k] = String(v); }},
      getItem(k) {{ return Object.prototype.hasOwnProperty.call(this._store, k) ? this._store[k] : null; }},
      removeItem(k) {{ delete this._store[k]; }}
    }};
    global.CustomEvent = class CustomEvent {{
      constructor(type, init) {{
        this.type = type;
        this.detail = init ? init.detail : undefined;
      }}
    }};
    global.window = {{
      dispatchEvent() {{}}
    }};
    global.fetch = function(url, options) {{
      let resolveFetch, rejectFetch;
      const promise = new Promise((resolve, reject) => {{
        resolveFetch = resolve;
        rejectFetch = reject;
      }});
      pendingRequests.push({{
        url,
        options,
        payload: JSON.parse(options.body),
        resolve: resolveFetch,
        reject: rejectFetch
      }});
      return promise;
    }};

    const ClientClass = new Function(
      'return class TestCognisecClient {{\\n' +
      '  constructor() {{\\n' +
      '    this.token = "test_jwt_token";\\n' +
      '    this.sessionId = "sess_lifecycle_test";\\n' +
      '    this.application = "college";\\n' +
      '    this.keyPressTimings = [];\\n' +
      '    this.dwellTimings = [];\\n' +
      '    this.mousePoints = [];\\n' +
      '    this.scrollSpeeds = [];\\n' +
      '    this.navigationHistory = [];\\n' +
      '    this.hasRealInteraction = true;\\n' +
      '    this.lastInteractionTime = Date.now() - 500;\\n' +
      '    this.lastTelemetryDispatchTime = Date.now() - 6000;\\n' +
      '    this.clickCount = 0;\\n' +
      '    this.scrollDeltaSum = 0;\\n' +
      '    this.sequenceNumber = 0;\\n' +
      '  }}\\n' +
      '  getHeaders() {{\\n' +
      '    return {{ "Content-Type": "application/json", "Authorization": "Bearer " + this.token }};\\n' +
      '  }}\\n' +
      '  recordClicks(n) {{\\n' +
      '    for (let i = 0; i < n; i++) {{\\n' +
      '      this.clickCount++;\\n' +
      '    }}\\n' +
      '    if (n > 0) {{\\n' +
      '      this.hasRealInteraction = true;\\n' +
      '      this.lastInteractionTime = Date.now();\\n' +
      '    }}\\n' +
      '  }}\\n' +
      methodsCode + '\\n}}'
    )();

    (async () => {{
      const client = new ClientClass();
      let totalClicksGenerated = 0;

      // --- Window 1: 4 clicks before snapshot, 2 clicks during in-flight, 1 click after completion ---
      client.recordClicks(4);
      totalClicksGenerated += 4;

      const w1Promise = client.sendBehaviorTelemetry();
      // 2 clicks while W1 is in flight
      client.recordClicks(2);
      totalClicksGenerated += 2;

      pendingRequests[0].resolve({{
        ok: true,
        status: 200,
        json: async () => ({{ status: 'recorded', risk_level: 'LOW', risk_score: 0.05 }})
      }});
      const w1Res = await w1Promise;

      // 1 click after W1 completed, before W2 snapshot
      client.recordClicks(1);
      totalClicksGenerated += 1;

      // --- Window 2: Should capture 2 (in-flight from W1) + 1 (post-W1) = 3 clicks ---
      // Suppose W2 fails with HTTP 500 while 2 new clicks occur during W2's in-flight request.
      client.lastTelemetryDispatchTime = Date.now() - 6000;
      const w2Promise = client.sendBehaviorTelemetry();

      client.recordClicks(2);
      totalClicksGenerated += 2;

      pendingRequests[1].resolve({{
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        json: async () => ({{ detail: 'Simulated server error' }})
      }});
      const w2Res = await w2Promise;

      // --- Window 3 (Retry / next dispatch after HTTP 500):
      // Should capture ONLY the 2 in-flight clicks from W2 (NOT duplicating W2's 3 clicks!).
      // Suppose W3 fails with a network rejection while 0 clicks happen in flight.
      client.lastTelemetryDispatchTime = Date.now() - 6000;
      const w3Promise = client.sendBehaviorTelemetry();
      pendingRequests[2].reject(new Error('Simulated network disconnect'));
      const w3Res = await w3Promise;

      // --- Window 4 (Immediate retry after network failure with 0 new clicks):
      // Should capture 0 clicks (no duplication of W3's 2 clicks) and mouse=false.
      client.lastTelemetryDispatchTime = Date.now() - 6000;
      const w4Promise = client.sendBehaviorTelemetry();
      pendingRequests[3].resolve({{
        ok: true,
        status: 200,
        json: async () => ({{ status: 'recorded', risk_level: 'LOW', risk_score: 0.05 }})
      }});
      const w4Res = await w4Promise;

      const capturedClicksPerWindow = pendingRequests.map(r => r.payload.sample_counts.clicks);
      const capturedMouseModality = pendingRequests.map(r => r.payload.observed_modalities.mouse);
      const sumCapturedClicks = capturedClicksPerWindow.reduce((a, b) => a + b, 0);

      console.log('TEST_JSON_OUT:' + JSON.stringify({{
        totalClicksGenerated,
        sumCapturedClicks,
        capturedClicksPerWindow,
        capturedMouseModality,
        results: [w1Res, w2Res, w3Res, w4Res],
        finalClickCount: client.clickCount
      }}));
    }})().catch(err => {{
      console.error(err);
      process.exit(1);
    }});
    """

    proc = subprocess.run([node_bin, "-e", harness], capture_output=True, text=True, check=True)
    json_line = [line for line in proc.stdout.splitlines() if line.startswith("TEST_JSON_OUT:")][-1]
    out = json.loads(json_line.removeprefix("TEST_JSON_OUT:"))

    # Window 1: 4 pre-snapshot clicks
    # Window 2 (HTTP 500): 2 in-flight + 1 post-completion = 3 clicks
    # Window 3 (Network error): 2 in-flight clicks from Window 2 (no duplication of Window 2's 3 clicks)
    # Window 4 (Immediate retry with no new clicks): 0 clicks (no duplication of Window 3's 2 clicks)
    assert out["capturedClicksPerWindow"] == [4, 3, 2, 0]
    assert out["capturedMouseModality"] == [True, True, True, False]
    assert out["totalClicksGenerated"] == 9
    assert out["sumCapturedClicks"] == 9
    assert out["finalClickCount"] == 0

    assert out["results"][0]["success"] is True
    assert out["results"][1]["success"] is False
    assert "Simulated server error" in out["results"][1]["error"]
    assert out["results"][2]["success"] is False
    assert "Simulated network disconnect" in out["results"][2]["error"]
    assert out["results"][3]["success"] is True
