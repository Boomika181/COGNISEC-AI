/**
 * COGNISEC-AI Client Telemetry & Integration Engine
 * Connects frontend portals to the FastAPI Zero-Trust Backend.
 * Endpoint: POST http://127.0.0.1:8000/api/behavior/events
 * Captures passive behavioral features (Privacy-safe: NO raw passwords/sensitive keystrokes).
 */

const COGNISEC_API_BASE = 'http://127.0.0.1:8000/api';

class CognisecClient {
  constructor() {
    this.token = localStorage.getItem('cognisec_token') || null;
    this.user = JSON.parse(localStorage.getItem('cognisec_user') || 'null');
    this.sessionId = localStorage.getItem('cognisec_session_id') || null;
    this.application = 'platform';

    // Telemetry capture buffers (non-sensitive metrics)
    this.keyPressTimings = [];
    this.mousePoints = [];
    this.lastInteractionTime = Date.now();
    this.clickCount = 0;
    this.scrollDeltaSum = 0;
    this.telemetryInterval = null;

    this.initPassiveCollectors();
    this.validateSessionOnStartup();
  }

  setApplication(app) {
    this.application = app;
  }

  getHeaders() {
    const headers = { 'Content-Type': 'application/json' };
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }
    return headers;
  }

  isAuthenticated() {
    return Boolean(this.token && this.user);
  }

  isAdmin() {
    return Boolean(this.isAuthenticated() && this.user && this.user.role === 'ADMIN');
  }

  getUser() {
    return this.user;
  }

  // --- SESSION INITIALIZATION & VERIFICATION ---
  async validateSessionOnStartup() {
    if (this.token && this.sessionId) {
      try {
        const res = await fetch(`${COGNISEC_API_BASE}/auth/me`, {
          headers: this.getHeaders()
        });
        if (res.ok) {
          const userProfile = await res.json();
          this.user = {
            id: userProfile.id,
            name: userProfile.name,
            email: userProfile.email,
            role: userProfile.role,
            account_status: userProfile.account_status
          };
          localStorage.setItem('cognisec_user', JSON.stringify(this.user));
          this.startTelemetryLoop();
          window.dispatchEvent(new CustomEvent('cognisec:auth_change', { detail: { isAuthenticated: true, user: this.user } }));
          return;
        } else {
          // Token expired or invalid
          this.clearAuth();
        }
      } catch (e) {
        // Backend offline or network error, keep local session if offline
        this.startTelemetryLoop();
      }
    } else {
      this.clearAuth();
    }
  }

  async ensureActiveSession() {
    if (this.isAuthenticated()) {
      this.startTelemetryLoop();
    }
  }

  clearAuth() {
    this.token = null;
    this.sessionId = null;
    this.user = null;
    localStorage.removeItem('cognisec_token');
    localStorage.removeItem('cognisec_session_id');
    localStorage.removeItem('cognisec_user');
    this.stopTelemetryLoop();
    window.dispatchEvent(new CustomEvent('cognisec:auth_change', { detail: { isAuthenticated: false, user: null } }));
  }

  // --- AUTHENTICATION ---
  async login(email, password, application = 'platform', fingerprint = 'browser_canvas_fp_01') {
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: email.trim(),
          password: password,
          application: application,
          device_fingerprint: fingerprint,
          browser: navigator.userAgent,
          os: navigator.platform
        })
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `Authentication failed with status ${res.status}`);
      }

      const data = await res.json();
      this.token = data.access_token;
      this.sessionId = data.session_id;
      this.user = {
        id: data.user_id,
        name: data.name,
        email: data.email,
        role: data.role,
        account_status: 'ACTIVE'
      };

      localStorage.setItem('cognisec_token', this.token);
      localStorage.setItem('cognisec_session_id', this.sessionId);
      localStorage.setItem('cognisec_user', JSON.stringify(this.user));

      this.startTelemetryLoop();
      window.dispatchEvent(new CustomEvent('cognisec:auth_change', { detail: { isAuthenticated: true, user: this.user } }));
      return { success: true, data };
    } catch (error) {
      console.warn('[COGNISEC-AI] Login error:', error.message);
      return { success: false, error: error.message };
    }
  }

  async register(name, email, password, role = 'USER') {
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, password, role })
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `Registration failed with status ${res.status}`);
      }
      return { success: true, data: await res.json() };
    } catch (error) {
      console.error('[COGNISEC-AI] Registration error:', error.message);
      return { success: false, error: error.message };
    }
  }

  async logout() {
    if (this.sessionId && this.token) {
      try {
        await fetch(`${COGNISEC_API_BASE}/auth/logout?session_id=${this.sessionId}`, {
          method: 'POST',
          headers: this.getHeaders()
        });
      } catch (e) {
        // silent cleanup
      }
    }
    this.clearAuth();
  }

  // --- PASSIVE BEHAVIORAL COLLECTORS ---
  initPassiveCollectors() {
    // 1. Keystroke timing dynamics (Privacy-safe: records ONLY interval deltas, NEVER characters, NEVER passwords)
    let lastKeyTime = 0;
    window.addEventListener('keydown', (e) => {
      // Explicit Privacy Safeguard: Never monitor or capture keystroke events inside password inputs
      if (e.target && (e.target.type === 'password' || e.target.getAttribute('autocomplete') === 'current-password')) {
        return;
      }

      const now = performance.now();
      if (lastKeyTime > 0) {
        const flightTime = now - lastKeyTime;
        if (flightTime < 3000) {
          this.keyPressTimings.push({ flight: flightTime, down: now });
          if (this.keyPressTimings.length > 50) this.keyPressTimings.shift();
        }
      }
      lastKeyTime = now;
      this.lastInteractionTime = Date.now();
    }, { passive: true });

    // 2. Mouse trajectory vectors & velocities
    let lastMouseTime = performance.now();
    window.addEventListener('mousemove', (e) => {
      const now = performance.now();
      const dt = Math.max(1, now - lastMouseTime);
      this.mousePoints.push({ x: e.clientX, y: e.clientY, t: now, dt });
      if (this.mousePoints.length > 60) this.mousePoints.shift();
      lastMouseTime = now;
      this.lastInteractionTime = Date.now();
    }, { passive: true });

    // 3. Clicks & Scrolls
    window.addEventListener('click', () => {
      this.clickCount++;
      this.lastInteractionTime = Date.now();
    }, { passive: true });

    window.addEventListener('scroll', () => {
      this.scrollDeltaSum += 10;
      this.lastInteractionTime = Date.now();
    }, { passive: true });
  }

  computeTelemetrySnapshot() {
    // Keystroke timing statistics
    let avgFlight = 120.0;
    let avgDwell = 85.0;
    let wpm = 65.0;
    if (this.keyPressTimings.length >= 3) {
      const flights = this.keyPressTimings.map(k => k.flight);
      avgFlight = flights.reduce((a, b) => a + b, 0) / flights.length;
      wpm = Math.min(180, Math.max(15, Math.round((60000 / (avgFlight * 5)))));
    }

    // Mouse trajectory & velocity statistics
    let avgVel = 650.0;
    let avgAcc = 400.0;
    let curvatureEntropy = 0.45;
    if (this.mousePoints.length >= 4) {
      let velSum = 0;
      for (let i = 1; i < this.mousePoints.length; i++) {
        const p1 = this.mousePoints[i - 1];
        const p2 = this.mousePoints[i];
        const dist = Math.hypot(p2.x - p1.x, p2.y - p1.y);
        const v = (dist / p2.dt) * 1000;
        velSum += v;
      }
      avgVel = Math.min(3000, velSum / (this.mousePoints.length - 1));
      avgAcc = avgVel * 0.6;
    }

    const idleSeconds = Math.max(0, (Date.now() - this.lastInteractionTime) / 1000);

    return {
      session_id: this.sessionId || 'sess_demo_default',
      application: this.application,
      typing_speed_wpm: Number(wpm.toFixed(1)),
      avg_flight_time_ms: Number(avgFlight.toFixed(1)),
      avg_dwell_time_ms: Number(avgDwell.toFixed(1)),
      mouse_velocity_avg: Number(avgVel.toFixed(1)),
      mouse_acceleration_avg: Number(avgAcc.toFixed(1)),
      mouse_curvature_entropy: Number(curvatureEntropy.toFixed(2)),
      click_frequency: Number(Math.min(10.0, this.clickCount * 0.2).toFixed(2)),
      scroll_speed_avg: Number(Math.min(1000.0, this.scrollDeltaSum * 2.5).toFixed(1)),
      idle_duration_sec: Number((Math.round(idleSeconds * 10) / 10).toFixed(1)),
      navigation_entropy: 0.38,
      context_signals: { is_new_device: false }
    };
  }

  // --- TELEMETRY DISPATCH TO FASTAPI ---
  async sendBehaviorTelemetry() {
    if (!this.token || !this.sessionId) {
      await this.ensureActiveSession();
    }
    if (!this.token || !this.sessionId) {
      return { success: false, error: 'No active session token available' };
    }

    const payload = this.computeTelemetrySnapshot();

    try {
      const res = await fetch(`${COGNISEC_API_BASE}/behavior/events`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify(payload)
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        console.error(`[COGNISEC-AI] Telemetry HTTP ${res.status}:`, err.detail || res.statusText);
        return { success: false, error: err.detail || `HTTP ${res.status}` };
      }

      const result = await res.json();
      console.log('[COGNISEC-AI] Telemetry POST /api/behavior/events SUCCESS:', result);

      // Reset short-term event buffers
      this.clickCount = 0;
      this.scrollDeltaSum = 0;

      return { success: true, data: result };
    } catch (e) {
      console.error('[COGNISEC-AI] Network error sending telemetry:', e.message);
      return { success: false, error: e.message };
    }
  }

  startTelemetryLoop() {
    if (this.telemetryInterval) clearInterval(this.telemetryInterval);
    // 6-Second periodic buffering telemetry dispatch
    this.telemetryInterval = setInterval(() => {
      this.sendBehaviorTelemetry();
    }, 6000);
  }

  stopTelemetryLoop() {
    if (this.telemetryInterval) {
      clearInterval(this.telemetryInterval);
      this.telemetryInterval = null;
    }
  }

  // --- SOC ADMIN ENDPOINTS ---
  async fetchSocMetrics() {
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/admin/metrics`, {
        headers: this.getHeaders()
      });
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn('[COGNISEC-AI] Failed to fetch metrics:', e);
    }
    return null;
  }

  async fetchSocEvents(limit = 20) {
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/admin/events?limit=${limit}`, {
        headers: this.getHeaders()
      });
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn('[COGNISEC-AI] Failed to fetch events:', e);
    }
    return [];
  }

  async fetchSocAlerts(limit = 20) {
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/admin/alerts?limit=${limit}`, {
        headers: this.getHeaders()
      });
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn('[COGNISEC-AI] Failed to fetch alerts:', e);
    }
    return [];
  }

  async fetchSocSessions(limit = 20) {
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/admin/sessions?limit=${limit}`, {
        headers: this.getHeaders()
      });
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn('[COGNISEC-AI] Failed to fetch sessions:', e);
    }
    return [];
  }

  async fetchSocDevices() {
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/admin/devices`, {
        headers: this.getHeaders()
      });
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn('[COGNISEC-AI] Failed to fetch devices:', e);
    }
    return [];
  }

  async fetchSocUsers(limit = 20) {
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/admin/users?limit=${limit}`, {
        headers: this.getHeaders()
      });
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn('[COGNISEC-AI] Failed to fetch users:', e);
    }
    return [];
  }

  async fetchUserProfile(userId) {
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/admin/users/${userId}/profile`, {
        headers: this.getHeaders()
      });
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn('[COGNISEC-AI] Failed to fetch user profile:', e);
    }
    return null;
  }

  async fetchMyProfile() {
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/behavior/profile`, {
        headers: this.getHeaders()
      });
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn('[COGNISEC-AI] Failed to fetch my profile:', e);
    }
    return null;
  }

  async resolveAlert(alertId, status = 'RESOLVED', notes = '') {
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/admin/alerts/${alertId}/resolve`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({ status, resolution_notes: notes || 'Handled in SOC Console' })
      });
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn('[COGNISEC-AI] Failed to resolve alert:', e);
    }
    return null;
  }

  async updateDeviceTrust(deviceId, isTrusted) {
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/admin/devices/${deviceId}/trust?is_trusted=${isTrusted}`, {
        method: 'POST',
        headers: this.getHeaders()
      });
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn('[COGNISEC-AI] Failed to update device trust:', e);
    }
    return null;
  }

  async simulateAttack(scenario, application = 'ecommerce') {
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/demo/simulate`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({ scenario, application })
      });
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn('[COGNISEC-AI] Attack sim error:', e);
    }
    return null;
  }
}

// Global Singleton
window.cognisec = new CognisecClient();

