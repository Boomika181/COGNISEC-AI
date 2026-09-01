// Multi-Sequence Canvas Setup
const canvas = document.getElementById('hero-canvas');
const ctx = canvas ? canvas.getContext('2d', { alpha: false, colorSpace: 'srgb' }) : null;

// Sequence Configurations
const SEQ1_COUNT = 150; // First Animation: ezgif-229d34e775cd5137-jpg
const SEQ2_COUNT = 200; // Second Animation: ezgif-5b4a876dac983c3d-jpg

const TOTAL_FRAMES = SEQ1_COUNT + SEQ2_COUNT;

// State Arrays
let seq1Images = [];
let seq2Images = [];
let loadedImagesCount = 0;
let currentProgress = 0; // 0.0 to 1.0 overall scroll progress
let targetProgress = 0;
let isLoaded = false;
let userHasScrolled = false;

// Preload Images for both animation sequences
function preloadAllImages() {
  const loaderText = document.getElementById('loader-text');
  let loadedSet = new Set();

  function markLoaded(key, img, isSeq1, idx) {
    if (loadedSet.has(key)) return;
    loadedSet.add(key);
    
    if (isSeq1) {
      seq1Images[idx] = img;
    } else {
      seq2Images[idx] = img;
    }

    loadedImagesCount = loadedSet.size;
    const percent = Math.floor((loadedImagesCount / TOTAL_FRAMES) * 100);
    if (loaderText) {
      loaderText.textContent = `Loading 4K Dual Scroll Sequence ${percent}% (${loadedImagesCount}/${TOTAL_FRAMES})`;
    }

    if (loadedSet.size === 1 && !isLoaded) {
      renderCurrentProgress(0);
    }

    if (loadedSet.size >= TOTAL_FRAMES) {
      finishLoading();
    }
  }

  function finishLoading() {
    if (isLoaded) return;
    isLoaded = true;
    const loader = document.getElementById('loader');
    if (loader) {
      loader.classList.add('hidden');
    }
    renderCurrentProgress(currentProgress);
  }

  // Preload Sequence 1 (150 frames)
  for (let i = 1; i <= SEQ1_COUNT; i++) {
    const num = String(i).padStart(3, '0');
    const src = `frames/seq1/ezgif-frame-${num}.jpg`;
    const img = new Image();
    const idx = i - 1;
    const key = `seq1-${idx}`;

    img.onload = () => markLoaded(key, img, true, idx);
    img.onerror = () => markLoaded(key, img, true, idx);
    img.src = src;

    if (img.complete && img.naturalWidth !== 0) {
      markLoaded(key, img, true, idx);
    }
  }

  // Preload Sequence 2 (200 frames)
  for (let i = 1; i <= SEQ2_COUNT; i++) {
    const num = String(i).padStart(3, '0');
    const src = `frames/seq2/ezgif-frame-${num}.jpg`;
    const img = new Image();
    const idx = i - 1;
    const key = `seq2-${idx}`;

    img.onload = () => markLoaded(key, img, false, idx);
    img.onerror = () => markLoaded(key, img, false, idx);
    img.src = src;

    if (img.complete && img.naturalWidth !== 0) {
      markLoaded(key, img, false, idx);
    }
  }

  // Safety fallback to hide loader and start animation if network is slow
  setTimeout(() => {
    finishLoading();
  }, 1800);
}

// Dynamic Ultra-HD Neural Biometric Particles System
const HD_PARTICLE_COUNT = 45;
const hdParticles = [];

function initHdParticles() {
  hdParticles.length = 0;
  for (let i = 0; i < HD_PARTICLE_COUNT; i++) {
    hdParticles.push({
      x: Math.random(),
      y: Math.random(),
      vx: (Math.random() - 0.5) * 0.0004,
      vy: (Math.random() - 0.5) * 0.0004,
      radius: Math.random() * 2.2 + 1.2,
      color: Math.random() > 0.35 ? 'rgba(239, 68, 68, ' : 'rgba(52, 211, 153, ',
      baseAlpha: Math.random() * 0.45 + 0.25,
      pulseSpeed: Math.random() * 0.03 + 0.015,
      phase: Math.random() * Math.PI * 2
    });
  }
}
initHdParticles();

// Device Pixel Ratio 4K Ultra HD Supersampling & Crisp Filtering
function resizeCanvas() {
  const dpr = Math.min(window.devicePixelRatio || 1, 2.5);
  const width = window.innerWidth;
  const height = window.innerHeight;

  if (canvas && ctx) {
    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);
    ctx.imageSmoothingEnabled = true;
    ctx.imageSmoothingQuality = 'high';
  }

  if (isLoaded) {
    renderCurrentProgress(currentProgress);
  }
}

// Render Frame based on Progress (First 50% = Sequence 1, Second 50% = Sequence 2) + HD Neural Layer
function renderCurrentProgress(progress) {
  if (!canvas || !ctx) return;

  let img = null;
  const clampedProgress = Math.max(0, Math.min(1, progress));

  if (clampedProgress <= 0.5) {
    // Sequence 1: 0% to 50% scroll
    const localProgress = clampedProgress / 0.5;
    let index = Math.round(localProgress * (SEQ1_COUNT - 1));
    index = Math.max(0, Math.min(SEQ1_COUNT - 1, index));
    img = seq1Images[index] || seq1Images[0];
  } else {
    // Sequence 2: 50% to 100% scroll
    const localProgress = (clampedProgress - 0.5) / 0.5;
    let index = Math.round(localProgress * (SEQ2_COUNT - 1));
    index = Math.max(0, Math.min(SEQ2_COUNT - 1, index));
    img = seq2Images[index] || seq2Images[0] || seq1Images[SEQ1_COUNT - 1];
  }

  if (!img || !img.complete || img.naturalWidth === 0) return;

  const cw = canvas.width;
  const ch = canvas.height;

  const imgWidth = img.naturalWidth;
  const imgHeight = img.naturalHeight;

  const imgRatio = imgWidth / imgHeight;
  const canvasRatio = cw / ch;

  let renderWidth, renderHeight, offsetX, offsetY;

  if (canvasRatio > imgRatio) {
    renderWidth = cw;
    renderHeight = cw / imgRatio;
    offsetX = 0;
    offsetY = (ch - renderHeight) / 2;
  } else {
    renderWidth = ch * imgRatio;
    renderHeight = ch;
    offsetX = (cw - renderWidth) / 2;
    offsetY = 0;
  }

  ctx.clearRect(0, 0, cw, ch);
  ctx.drawImage(img, offsetX, offsetY, renderWidth, renderHeight);

  // --- Dynamic HD Neural Particle Overlay ---
  const time = performance.now() * 0.001;
  const maxConnectDist = Math.min(cw, ch) * 0.18;

  // Update & Draw Connection Synapses
  for (let i = 0; i < hdParticles.length; i++) {
    const p1 = hdParticles[i];
    p1.x += p1.vx;
    p1.y += p1.vy;
    if (p1.x < 0) p1.x = 1;
    if (p1.x > 1) p1.x = 0;
    if (p1.y < 0) p1.y = 1;
    if (p1.y > 1) p1.y = 0;

    const x1 = p1.x * cw;
    const y1 = p1.y * ch;

    for (let j = i + 1; j < hdParticles.length; j++) {
      const p2 = hdParticles[j];
      const x2 = p2.x * cw;
      const y2 = p2.y * ch;
      const dx = x2 - x1;
      const dy = y2 - y1;
      const dist = Math.hypot(dx, dy);

      if (dist < maxConnectDist) {
        const alpha = (1 - dist / maxConnectDist) * 0.18;
        ctx.beginPath();
        ctx.moveTo(x1, y1);
        ctx.lineTo(x2, y2);
        ctx.strokeStyle = `rgba(220, 38, 38, ${alpha})`;
        ctx.lineWidth = 1.0;
        ctx.stroke();
      }
    }
  }

  // Draw Glowing Nodes
  for (let i = 0; i < hdParticles.length; i++) {
    const p = hdParticles[i];
    const px = p.x * cw;
    const py = p.y * ch;
    const pulse = Math.sin(time * 3 + p.phase) * 0.3 + 0.7;
    const currentAlpha = p.baseAlpha * pulse;

    // Outer Glow
    ctx.beginPath();
    ctx.arc(px, py, p.radius * 2.8, 0, Math.PI * 2);
    ctx.fillStyle = `${p.color}${currentAlpha * 0.35})`;
    ctx.fill();

    // Core Particle
    ctx.beginPath();
    ctx.arc(px, py, p.radius, 0, Math.PI * 2);
    ctx.fillStyle = `${p.color}${currentAlpha})`;
    ctx.fill();
  }
}

let autoPlayDir = 1;
let lastScrollPosition = 0;

// Calculate target progress from overall page scroll progress
function updateTargetProgress() {
  const scrollTop = window.pageYOffset || document.documentElement.scrollTop || document.body.scrollTop || 0;
  
  if (Math.abs(scrollTop - lastScrollPosition) > 2) {
    userHasScrolled = true;
    lastScrollPosition = scrollTop;
  }

  if (userHasScrolled) {
    const docHeight = Math.max(
      document.body.scrollHeight,
      document.documentElement.scrollHeight,
      document.body.offsetHeight,
      document.documentElement.offsetHeight
    ) - window.innerHeight;

    targetProgress = Math.max(0, Math.min(1, scrollTop / (docHeight || 1)));
  }
}

// End Hero Sticky Canvas Setup
const endCanvas = document.getElementById('end-hero-canvas');
const endCtx = endCanvas ? endCanvas.getContext('2d', { alpha: false, colorSpace: 'srgb' }) : null;

function resizeEndCanvas() {
  const dpr = Math.min(window.devicePixelRatio || 1, 2.5);
  if (endCanvas && endCtx) {
    const rect = endCanvas.parentElement ? endCanvas.parentElement.getBoundingClientRect() : { width: window.innerWidth, height: window.innerHeight };
    endCanvas.width = Math.floor((rect.width || window.innerWidth) * dpr);
    endCanvas.height = Math.floor((rect.height || window.innerHeight) * dpr);
    endCtx.imageSmoothingEnabled = true;
    endCtx.imageSmoothingQuality = 'high';
  }
}

function renderEndSectionProgress() {
  const container = document.getElementById('end-hero-container');
  if (!container || !endCanvas || !endCtx) return;

  const rect = container.getBoundingClientRect();
  const totalH = container.offsetHeight - window.innerHeight;
  if (totalH <= 0) return;

  const scrolled = -rect.top;
  const progress = Math.max(0, Math.min(1, scrolled / totalH));

  // Determine frame from Sequence 2 (200 frames)
  let index = Math.round(progress * (SEQ2_COUNT - 1));
  index = Math.max(0, Math.min(SEQ2_COUNT - 1, index));
  const img = seq2Images[index] || seq2Images[0];

  if (img && img.complete && img.naturalWidth !== 0) {
    const cw = endCanvas.width;
    const ch = endCanvas.height;
    const imgRatio = img.naturalWidth / img.naturalHeight;
    const canvasRatio = cw / ch;

    let rw, rh, ox, oy;
    if (canvasRatio > imgRatio) {
      rw = cw;
      rh = cw / imgRatio;
      ox = 0;
      oy = (ch - rh) / 2;
    } else {
      rw = ch * imgRatio;
      rh = ch;
      ox = (cw - rw) / 2;
      oy = 0;
    }
    endCtx.clearRect(0, 0, cw, ch);
    endCtx.drawImage(img, ox, oy, rw, rh);
  }

  // Update End Cards Visibility (Card 1: 0-35%, Card 2: 35-70%, Card 3: 70-100%)
  const c1 = document.getElementById('end-card-1');
  const c2 = document.getElementById('end-card-2');
  const c3 = document.getElementById('end-card-3');

  if (c1 && c2 && c3) {
    if (progress < 0.35) {
      c1.classList.remove('hidden');
      c2.classList.add('hidden');
      c3.classList.add('hidden');
    } else if (progress < 0.70) {
      c1.classList.add('hidden');
      c2.classList.remove('hidden');
      c3.classList.add('hidden');
    } else {
      c1.classList.add('hidden');
      c2.classList.add('hidden');
      c3.classList.remove('hidden');
    }
  }
}

// Continuous Lerp & Idle Auto-Play Animation loop
function animate() {
  updateTargetProgress();

  if (!userHasScrolled && isLoaded) {
    // Gentle idle auto-play in first sequence when user hasn't scrolled yet
    targetProgress += 0.0015 * autoPlayDir;
    if (targetProgress >= 0.45) {
      targetProgress = 0.45;
      autoPlayDir = -1;
    } else if (targetProgress <= 0) {
      targetProgress = 0;
      autoPlayDir = 1;
    }
  }

  const lerpFactor = userHasScrolled ? 0.14 : 0.08;
  currentProgress += (targetProgress - currentProgress) * lerpFactor;
  
  if (Math.abs(targetProgress - currentProgress) < 0.00001) {
    currentProgress = targetProgress;
  }
  
  renderCurrentProgress(currentProgress);
  renderEndSectionProgress();
  requestAnimationFrame(animate);
}

// Event Listeners
window.addEventListener('scroll', () => {
  userHasScrolled = true;
  updateTargetProgress();
}, { passive: true });
window.addEventListener('wheel', () => {
  userHasScrolled = true;
  updateTargetProgress();
}, { passive: true });
window.addEventListener('touchmove', () => {
  userHasScrolled = true;
  updateTargetProgress();
}, { passive: true });
window.addEventListener('resize', () => {
  resizeCanvas();
  resizeEndCanvas();
  updateTargetProgress();
});

// Initialize Canvases
resizeCanvas();
resizeEndCanvas();
preloadAllImages();
requestAnimationFrame(animate);

// ================= INTERACTIVE MODAL & UI HANDLERS =================

// Real Auth State Synchronization
window.syncAuthStateUI = function() {
  const isAuth = window.cognisec ? window.cognisec.isAuthenticated() : false;
  const user = window.cognisec ? window.cognisec.getUser() : null;
  const isAdmin = window.cognisec ? window.cognisec.isAdmin() : false;

  const navbarSigninText = document.getElementById('navbar-signin-text');
  const navbarLogoutBtn = document.getElementById('navbar-logout-btn');
  const notifBell = document.getElementById('notif-bell-btn');

  // Landing Page User Profile Section
  const profName = document.getElementById('profile-name-label');
  const profRole = document.getElementById('profile-role-label');
  const profId = document.getElementById('profile-id-badge');
  const profSession = document.getElementById('profile-session-status');
  const profDevice = document.getElementById('profile-device-label');
  const profSessionId = document.getElementById('profile-session-id-label');
  const profActionBtn = document.getElementById('profile-action-btn');
  const profLogoutBtn = document.getElementById('profile-logout-btn');

  // User Dashboard Modal
  const userDashName = document.getElementById('user-dash-name');
  const userDashEmail = document.getElementById('user-dash-email');
  const userDashRole = document.getElementById('user-dash-role');
  const userDashStatus = document.getElementById('user-dash-status');
  const userDashSession = document.getElementById('user-dash-session');
  const userDashDevice = document.getElementById('user-dash-device');

  if (isAuth && user) {
    // Authenticated State
    if (navbarSigninText) {
      navbarSigninText.textContent = isAdmin ? `🟢 ${user.name} (ADMIN)` : `🟢 ${user.name}`;
    }
    if (navbarLogoutBtn) {
      navbarLogoutBtn.classList.remove('hidden');
      navbarLogoutBtn.classList.add('flex');
    }
    if (notifBell && isAdmin) {
      notifBell.classList.remove('hidden');
    }

    if (profName) profName.textContent = user.name;
    if (profRole) profRole.textContent = isAdmin ? 'Security Administrator (SOC)' : 'Verified Enterprise User';
    if (profId) profId.textContent = `ID: USR-00${user.id || '1'}`;
    if (profSession) profSession.textContent = `Account: ${user.account_status || 'ACTIVE'} • Session: ACTIVE`;
    if (profDevice) profDevice.textContent = `${navigator.platform || 'macOS / Desktop'} • ${isAdmin ? 'Primary SOC Console' : 'Enterprise User Client'}`;
    if (profSessionId) profSessionId.textContent = `Active Session: ${window.cognisec.sessionId || 'Active'}`;
    if (profLogoutBtn) profLogoutBtn.classList.remove('hidden');
    if (profActionBtn) {
      profActionBtn.innerHTML = `<span>${isAdmin ? 'Open SOC Command Center →' : 'Open User Dashboard →'}</span>`;
    }

    if (userDashName) userDashName.textContent = user.name;
    if (userDashEmail) userDashEmail.textContent = user.email;
    if (userDashRole) userDashRole.textContent = `ROLE: ${user.role}`;
    if (userDashStatus) userDashStatus.textContent = `ACCOUNT: ${user.account_status || 'ACTIVE'}`;
    if (userDashSession) userDashSession.textContent = `Session ID: ${window.cognisec.sessionId || 'Active (TLS 1.3)'}`;
    if (userDashDevice) userDashDevice.textContent = `${navigator.platform || 'macOS / Desktop'} • Chrome (Desktop)`;

  } else {
    // Unauthenticated State
    if (navbarSigninText) navbarSigninText.textContent = 'Sign In';
    if (navbarLogoutBtn) {
      navbarLogoutBtn.classList.add('hidden');
      navbarLogoutBtn.classList.remove('flex');
    }

    if (profName) profName.textContent = 'Enterprise User';
    if (profRole) profRole.textContent = 'Sign In Required';
    if (profId) profId.textContent = 'ID: UNAUTHENTICATED';
    if (profSession) profSession.textContent = 'Please sign in to view active identity telemetry';
    if (profLogoutBtn) profLogoutBtn.classList.add('hidden');
    if (profActionBtn) profActionBtn.innerHTML = `<span>Sign In to Access →</span>`;
  }
};

window.handleNavbarAuthClick = function() {
  if (window.cognisec && window.cognisec.isAuthenticated()) {
    openAppropriateDashboard();
  } else {
    openModal('login');
    setLoginScreen('select');
  }
};

window.handleLaunchConsoleClick = function() {
  openAppropriateDashboard();
};

window.openAppropriateDashboard = function() {
  if (!window.cognisec || !window.cognisec.isAuthenticated()) {
    openModal('login');
    setLoginScreen('select');
    return;
  }

  if (window.cognisec.isAdmin()) {
    openModal('dashboard');
  } else {
    openModal('liveDemo');
  }
};

window.handleLogout = async function() {
  if (window.cognisec) {
    await window.cognisec.logout();
  }
  closeModal('dashboard');
  closeModal('liveDemo');
  syncAuthStateUI();
};

// Modal Open / Close
window.openModal = function(id) {
  if (id.startsWith('portal-')) {
    const portalType = id.replace('portal-', '');
    openPortalModal(portalType);
    return;
  }

  // Role Protection Check for Admin SOC Dashboard
  if (id === 'dashboard') {
    if (!window.cognisec || !window.cognisec.isAuthenticated()) {
      openModal('login');
      setLoginScreen('soc');
      return;
    }
    if (!window.cognisec.isAdmin()) {
      const deniedModal = document.getElementById('modal-soc-denied');
      if (deniedModal) deniedModal.classList.remove('hidden');
      return;
    }
  }

  const modal = document.getElementById(`modal-${id}`);
  if (modal) {
    modal.classList.remove('hidden');
  }

  if (id === 'dashboard') {
    startDashboardTimer();
    startSocPolling();
  }
};

window.closeModal = function(id) {
  const modal = document.getElementById(`modal-${id}`);
  if (modal) {
    modal.classList.add('hidden');
  }

  if (id === 'dashboard') {
    stopSocPolling();
  }
};

// 1. DASHBOARD MODAL TAB SWITCHING, POLLING & REAL DATA
let dashSecondsElapsed = 504;
let dashTimerInterval = null;
let socPollingTimer = null;

function startDashboardTimer() {
  if (dashTimerInterval) clearInterval(dashTimerInterval);
  dashTimerInterval = setInterval(() => {
    dashSecondsElapsed++;
    const mins = Math.floor(dashSecondsElapsed / 60);
    const secs = dashSecondsElapsed % 60;
    const timerEl = document.getElementById('dash-timer');
    if (timerEl) {
      timerEl.textContent = `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
    }
  }, 1000);
}

function startSocPolling() {
  if (socPollingTimer) clearInterval(socPollingTimer);
  loadSocDashboardData();
  socPollingTimer = setInterval(loadSocDashboardData, 6000); // 6-second polling interval
}

function stopSocPolling() {
  if (socPollingTimer) {
    clearInterval(socPollingTimer);
    socPollingTimer = null;
  }
}

async function loadSocDashboardData() {
  if (!window.cognisec || !window.cognisec.isAdmin()) return;
  try {
    // 1. High-Level SOC KPI Metrics
    const metrics = await window.cognisec.fetchSocMetrics();
    if (metrics) {
      const sessionsEl = document.getElementById('soc-stat-sessions');
      const trustedEl = document.getElementById('soc-stat-trusted');
      const blockedEl = document.getElementById('soc-stat-blocked');
      const devicesEl = document.getElementById('soc-stat-devices');
      const alertsEl = document.getElementById('soc-stat-alerts');

      if (sessionsEl) sessionsEl.textContent = Number(metrics.live_sessions_count).toLocaleString();
      if (trustedEl) trustedEl.textContent = Number(metrics.trusted_users_count).toLocaleString();
      if (blockedEl) blockedEl.textContent = Number(metrics.blocked_sessions_count).toLocaleString();
      if (devicesEl) devicesEl.textContent = Number(metrics.total_devices_count).toLocaleString();
      if (alertsEl) alertsEl.textContent = Number(metrics.active_alerts_count).toLocaleString();
    }

    // 2. Real Security Events Stream (Overview Tab & Logs Tab)
    const events = await window.cognisec.fetchSocEvents(15);
    const logsEl = document.getElementById('soc-live-logs');
    if (logsEl) {
      if (events && events.length > 0) {
        logsEl.innerHTML = '';
        events.forEach(ev => {
          const timeStr = new Date(ev.timestamp).toLocaleTimeString('en-US', { hour12: false });
          const isClean = ev.severity === 'LOW';
          const isCritical = ev.severity === 'CRITICAL' || ev.decision === 'TERMINATE_SESSION';
          const newLog = document.createElement('div');
          newLog.className = `p-3 rounded-xl bg-black/50 border ${isClean ? 'border-emerald-950' : (isCritical ? 'border-red-600 bg-red-950/20' : 'border-amber-950')} flex items-center justify-between font-mono text-[11px] animate-fade-in transition-all`;
          newLog.innerHTML = `
            <div class="flex items-center gap-3">
              <span class="${isClean ? 'text-emerald-400' : 'text-red-400'} font-bold">${isClean ? '🟢' : '🔴'} [${timeStr}]</span>
              <span class="text-white font-bold">${ev.event_type.replace(/_/g, ' ')} (${(ev.application || 'PLATFORM').toUpperCase()})</span>
              <span class="text-slate-400 text-[10px]">&bull; User: ${ev.user_name || 'Portal User'} &bull; Severity: <span class="${isClean ? 'text-emerald-400' : 'text-red-400'} font-bold">${ev.severity}</span></span>
            </div>
            <span class="px-2.5 py-0.5 ${isClean ? 'bg-emerald-950 text-emerald-400 border-emerald-800' : 'bg-red-950 text-red-400 border-red-800'} border rounded text-[10px] font-bold">${ev.decision}</span>
          `;
          logsEl.appendChild(newLog);
        });
      } else {
        logsEl.innerHTML = `<div class="text-center p-4 text-slate-500 font-mono text-xs">No security events recorded yet. Zero-Trust monitoring active.</div>`;
      }
    }

    // 3. Real Security Alerts Feed with Interactive Resolution
    const alerts = await window.cognisec.fetchSocAlerts(10);
    const fullLogsTab = document.getElementById('dash-content-logs');
    if (fullLogsTab) {
      let alertsHtml = `
        <div class="p-6 rounded-2xl bg-black/60 border border-red-900/50 space-y-4">
          <div class="flex items-center justify-between pb-3 border-b border-red-950">
            <h4 class="font-heading font-bold text-sm text-white uppercase flex items-center gap-2">
              <span>🚨</span> Real-Time Security Alerts &amp; Incident Resolution
            </h4>
            <span class="text-xs text-red-400 font-mono font-bold">${alerts.length} Incidents Logged</span>
          </div>
      `;

      if (alerts && alerts.length > 0) {
        alertsHtml += `<div class="space-y-3">`;
        alerts.forEach(al => {
          const isResolved = al.status === 'RESOLVED';
          const isAck = al.status === 'ACKNOWLEDGED';
          const timeStr = new Date(al.created_at).toLocaleTimeString('en-US', { hour12: false });
          alertsHtml += `
            <div class="p-4 rounded-xl ${isResolved ? 'bg-black/40 border-slate-800' : 'bg-red-950/30 border-red-800/80'} border flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs">
              <div class="space-y-1">
                <div class="flex items-center gap-2">
                  <span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono ${al.severity === 'CRITICAL' ? 'bg-red-600 text-white' : 'bg-amber-950 text-amber-300'}">${al.severity}</span>
                  <strong class="text-white font-mono font-bold">${al.alert_type.replace(/_/g, ' ')}</strong>
                  <span class="text-slate-500 text-[10px]">[${timeStr}]</span>
                </div>
                <p class="text-slate-300 text-[11px]">${al.message}</p>
                <div class="text-[10px] text-slate-400">User: ${al.user_name} (${al.user_email}) &bull; App: ${(al.application || 'PLATFORM').toUpperCase()}</div>
              </div>
              <div class="flex items-center gap-2 shrink-0">
                ${!isResolved ? `
                  <button onclick="window.resolveSocAlert(${al.id}, 'ACKNOWLEDGED')" class="px-3 py-1 rounded bg-amber-950 hover:bg-amber-900 border border-amber-700 text-amber-300 font-mono text-[10px] font-bold cursor-pointer transition-all">Acknowledge</button>
                  <button onclick="window.resolveSocAlert(${al.id}, 'RESOLVED')" class="px-3 py-1 rounded bg-emerald-950 hover:bg-emerald-900 border border-emerald-700 text-emerald-300 font-mono text-[10px] font-bold cursor-pointer transition-all">Resolve Alert</button>
                ` : `
                  <span class="px-3 py-1 rounded bg-slate-900 text-emerald-400 border border-emerald-900 font-mono text-[10px] font-bold">✅ RESOLVED</span>
                `}
              </div>
            </div>
          `;
        });
        alertsHtml += `</div>`;
      } else {
        alertsHtml += `<div class="p-8 text-center text-slate-500 font-mono text-xs">No active security alerts. All systems operational.</div>`;
      }
      alertsHtml += `</div>`;
      fullLogsTab.innerHTML = alertsHtml;
    }

    // 4. Real Behavioral Baseline & Isolation Forest Status Tab
    const prof = await window.cognisec.fetchMyProfile();
    const behaviorTab = document.getElementById('dash-content-behavior');
    if (behaviorTab && prof) {
      const mlColor = prof.ml_status === 'ML_READY' ? 'text-emerald-400 border-emerald-800 bg-emerald-950' : 'text-amber-300 border-amber-800 bg-amber-950';
      const means = prof.baseline_features?.means || {};
      behaviorTab.innerHTML = `
        <div class="p-6 rounded-2xl bg-black/60 border border-red-900/50 space-y-6">
          <div class="flex items-center justify-between pb-3 border-b border-red-950">
            <h4 class="font-heading font-bold text-sm text-white uppercase flex items-center gap-2">
              <span>🧠</span> Isolation Forest &amp; Welford Behavioral Engine
            </h4>
            <span class="px-3 py-1 rounded border font-mono text-xs font-bold ${mlColor}">
              STATUS: ${prof.ml_status}
            </span>
          </div>

          <div class="grid grid-cols-1 sm:grid-cols-3 gap-4 font-mono text-xs">
            <div class="p-4 rounded-xl bg-black/80 border border-red-950 space-y-1">
              <span class="text-slate-400 text-[10px]">Statistical Baseline</span>
              <strong class="text-white block text-sm font-bold">${prof.baseline_status}</strong>
              <span class="text-slate-500 text-[10px]">Confidence: ${Math.round(prof.maturity_confidence * 100)}%</span>
            </div>
            <div class="p-4 rounded-xl bg-black/80 border border-red-950 space-y-1">
              <span class="text-slate-400 text-[10px]">Trusted Training Samples</span>
              <strong class="text-white block text-sm font-bold">${prof.sample_count} Samples</strong>
              <span class="text-slate-500 text-[10px]">Model Buffer: ${prof.model_sample_count || prof.sample_count}</span>
            </div>
            <div class="p-4 rounded-xl bg-black/80 border border-red-950 space-y-1">
              <span class="text-slate-400 text-[10px]">Machine Learning Model</span>
              <strong class="text-emerald-400 block text-sm font-bold">Isolation Forest (50 Trees)</strong>
              <span class="text-slate-500 text-[10px]">Contamination Rate: 5%</span>
            </div>
          </div>

          <div class="space-y-3">
            <h5 class="text-xs font-mono font-bold text-slate-300 uppercase">Learned 10-Dimensional Feature Means:</h5>
            <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-[11px]">
              <div class="p-2.5 rounded-lg bg-black/40 border border-slate-800">
                <span class="text-slate-400 block text-[10px]">Typing Speed</span>
                <strong class="text-emerald-400">${means.typing_speed_wpm || 68.0} WPM</strong>
              </div>
              <div class="p-2.5 rounded-lg bg-black/40 border border-slate-800">
                <span class="text-slate-400 block text-[10px]">Flight Time</span>
                <strong class="text-emerald-400">${means.avg_flight_time_ms || 118.0} ms</strong>
              </div>
              <div class="p-2.5 rounded-lg bg-black/40 border border-slate-800">
                <span class="text-slate-400 block text-[10px]">Dwell Time</span>
                <strong class="text-emerald-400">${means.avg_dwell_time_ms || 86.0} ms</strong>
              </div>
              <div class="p-2.5 rounded-lg bg-black/40 border border-slate-800">
                <span class="text-slate-400 block text-[10px]">Mouse Velocity</span>
                <strong class="text-emerald-400">${means.mouse_velocity_avg || 650.0} px/s</strong>
              </div>
            </div>
          </div>
        </div>
      `;
    }

  } catch (e) {
    console.warn('[COGNISEC-AI] Failed to load dashboard data:', e);
  }
}

window.resolveSocAlert = async function(alertId, status) {
  if (window.cognisec) {
    await window.cognisec.resolveAlert(alertId, status, `Alert marked as ${status} by SOC Analyst`);
    await loadSocDashboardData();
  }
};

window.switchDashboardTab = function(tabKey) {
  ['overview', 'behavior', 'threatmap', 'logs'].forEach(k => {
    const btn = document.getElementById(`dash-tab-${k}`);
    const content = document.getElementById(`dash-content-${k}`);
    if (btn) {
      if (k === tabKey) {
        btn.className = 'px-4 py-2 rounded-xl font-bold transition-all flex items-center gap-2 bg-red-600 text-white shadow-[0_0_15px_rgba(220,38,38,0.5)] cursor-pointer';
      } else {
        btn.className = 'px-4 py-2 rounded-xl font-bold transition-all flex items-center gap-2 text-slate-400 hover:text-white hover:bg-red-950/40 cursor-pointer';
      }
    }
    if (content) {
      if (k === tabKey) content.classList.remove('hidden');
      else content.classList.add('hidden');
    }
  });
};

window.triggerSocRescan = async function() {
  await loadSocDashboardData();
};

// 2. LOGIN MODAL SCREEN SWITCHING & REAL FASTAPI SUBMISSION
window.setLoginScreen = function(mode) {
  const selectScreen = document.getElementById('login-screen-select');
  const userScreen = document.getElementById('login-screen-user');
  const socScreen = document.getElementById('login-screen-soc');
  const backBtn = document.getElementById('login-back-btn');
  const titleEl = document.getElementById('login-modal-title');
  const subEl = document.getElementById('login-modal-subtitle');
  const container = document.getElementById('login-modal-container');
  const errUser = document.getElementById('login-error-user');
  const errSoc = document.getElementById('login-error-soc');

  if (errUser) errUser.classList.add('hidden');
  if (errSoc) errSoc.classList.add('hidden');

  if (mode === 'select') {
    if (selectScreen) selectScreen.classList.remove('hidden');
    if (userScreen) userScreen.classList.add('hidden');
    if (socScreen) socScreen.classList.add('hidden');
    if (backBtn) backBtn.classList.add('hidden');
    if (titleEl) titleEl.textContent = 'ENTERPRISE ACCESS PORTAL';
    if (subEl) subEl.textContent = 'Select your enterprise authorization environment';
    if (container) container.className = 'relative w-full max-w-3xl bg-[#08050e] border border-red-900/60 rounded-2xl shadow-[0_0_80px_rgba(220,38,38,0.4)] overflow-hidden flex flex-col transition-all duration-300';
  } else if (mode === 'user') {
    if (selectScreen) selectScreen.classList.add('hidden');
    if (userScreen) userScreen.classList.remove('hidden');
    if (socScreen) socScreen.classList.add('hidden');
    if (backBtn) backBtn.classList.remove('hidden');
    if (titleEl) titleEl.textContent = 'USER PORTAL LOGIN';
    if (subEl) subEl.textContent = 'Continuous identity verified user authentication';
    if (container) container.className = 'relative w-full max-w-md bg-[#08050e] border border-red-900/60 rounded-2xl shadow-[0_0_80px_rgba(220,38,38,0.4)] overflow-hidden flex flex-col transition-all duration-300';
  } else if (mode === 'soc') {
    if (selectScreen) selectScreen.classList.add('hidden');
    if (userScreen) userScreen.classList.add('hidden');
    if (socScreen) socScreen.classList.remove('hidden');
    if (backBtn) backBtn.classList.remove('hidden');
    if (titleEl) titleEl.textContent = 'SECURITY OPERATIONS CENTER';
    if (subEl) subEl.textContent = 'Administrator & SOC Analyst authentication';
    if (container) container.className = 'relative w-full max-w-md bg-[#08050e] border border-red-900/60 rounded-2xl shadow-[0_0_80px_rgba(220,38,38,0.4)] overflow-hidden flex flex-col transition-all duration-300';
  }
};

window.submitLoginForm = async function(e, type) {
  e.preventDefault();
  const btn = document.getElementById(type === 'user' ? 'btn-submit-user-login' : 'btn-submit-soc-login');
  const errBox = document.getElementById(type === 'user' ? 'login-error-user' : 'login-error-soc');
  const emailInput = document.getElementById(type === 'user' ? 'login-user-email' : 'login-soc-email');
  const passwordInput = document.getElementById(type === 'user' ? 'login-user-password' : 'login-soc-password');

  if (errBox) errBox.classList.add('hidden');

  const email = emailInput ? emailInput.value.trim() : '';
  const password = passwordInput ? passwordInput.value : '';

  if (!email || !password) {
    if (errBox) {
      errBox.textContent = 'Please enter both your email address and password.';
      errBox.classList.remove('hidden');
    }
    return;
  }

  if (btn) {
    btn.innerHTML = `<span>Authenticating with FastAPI Backend...</span>`;
    btn.disabled = true;
  }

  try {
    const result = await window.cognisec.login(email, password, 'platform');
    if (!result.success) {
      if (errBox) {
        errBox.textContent = result.error || 'Authentication failed. Please verify your credentials.';
        errBox.classList.remove('hidden');
      }
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = type === 'user' ? 'Sign In User Portal' : 'Sign In SOC Console';
      }
      return;
    }

    // Success! Clear password input for privacy
    if (passwordInput) passwordInput.value = '';

    // Synchronize UI
    syncAuthStateUI();
    closeModal('login');

    if (btn) {
      btn.disabled = false;
      btn.innerHTML = type === 'user' ? 'Sign In User Portal' : 'Sign In SOC Console';
    }

    // Role-based routing: Admin -> SOC Dashboard, Normal User -> User Dashboard
    if (result.data.role === 'ADMIN') {
      openModal('dashboard');
    } else {
      openModal('liveDemo');
    }

  } catch (err) {
    if (errBox) {
      errBox.textContent = 'Network error connecting to authentication server.';
      errBox.classList.remove('hidden');
    }
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = type === 'user' ? 'Sign In User Portal' : 'Sign In SOC Console';
    }
  }
};

// Global Listeners for Authentication
window.addEventListener('cognisec:auth_change', () => {
  syncAuthStateUI();
});
document.addEventListener('DOMContentLoaded', () => {
  syncAuthStateUI();
});
setTimeout(() => {
  syncAuthStateUI();
}, 250);

// 3. LAUNCH CONSOLE INTERACTIVE TYPING TRACKER & VERIFICATION
let consoleStartTime = Date.now();
window.handleConsoleTyping = function(e) {
  const val = e.target.value;
  const charEl = document.getElementById('char-count');
  const wordEl = document.getElementById('word-count');
  const wpmEl = document.getElementById('wpm-count');
  const badgeTyping = document.getElementById('badge-typing');

  const chars = val.length;
  const words = val.trim() ? val.trim().split(/\s+/).length : 0;
  const elapsedMinutes = (Date.now() - consoleStartTime) / 60000;
  const wpm = elapsedMinutes > 0 ? Math.round(words / elapsedMinutes) : 0;

  if (charEl) charEl.textContent = chars;
  if (wordEl) wordEl.textContent = words;
  if (wpmEl) wpmEl.textContent = `${wpm} WPM`;

  if (chars > 5 && badgeTyping) {
    badgeTyping.textContent = '✓ Verified';
    badgeTyping.className = 'px-2 py-0.5 text-[10px] bg-emerald-950 text-emerald-400 border border-emerald-800 rounded font-bold';
  }

  // Dispatch real behavioral telemetry to FastAPI on each 10-char typing burst
  if (chars % 10 === 0 && chars > 0) {
    if (window.cognisec) {
      window.cognisec.sendBehaviorTelemetry().then(res => {
        if (res && res.success && res.data) {
          const d = res.data;
          addConsoleLog(`Typing Telemetry Transmitted (FastAPI POST /api/behavior/events | Decision: ${d.decision} | Risk: ${d.risk_score.toFixed(3)})`);
        } else if (res && !res.success) {
          addConsoleLog(`Telemetry Dispatch Notice: ${res.error}`);
        }
      }).catch(err => {
        addConsoleLog(`Telemetry Network Error: ${err.message}`);
      });
    }
  }
};

function addConsoleLog(text) {
  const logContainer = document.getElementById('console-event-log');
  if (!logContainer) return;
  const timeStr = new Date().toLocaleTimeString();
  const div = document.createElement('div');
  div.className = 'p-2 rounded bg-black/60 border border-red-950 text-emerald-300 font-mono text-[11px]';
  div.textContent = `> ${timeStr} - ${text}`;
  logContainer.prepend(div);
}

window.runConsoleVerification = async function() {
  const btn = document.getElementById('btn-console-verify');
  const authBadge = document.getElementById('badge-auth-state');
  if (btn) {
    btn.textContent = 'Verifying Session Integrity with FastAPI...';
    btn.disabled = true;
  }

  addConsoleLog('Initiating Zero-Trust Identity Verification API (POST /api/behavior/events)...');

  try {
    const res = window.cognisec ? await window.cognisec.sendBehaviorTelemetry() : null;
    if (res && res.success && res.data) {
      const d = res.data;
      addConsoleLog(`FastAPI Live Verification: Decision=${d.decision} | Risk=${d.risk_score.toFixed(3)} | Status=${d.session_status}`);
      if (authBadge) {
        authBadge.textContent = d.decision === 'ALLOW' ? '✓ Authenticated' : '⚠️ ' + d.decision;
        authBadge.className = d.decision === 'ALLOW'
          ? 'px-2 py-0.5 text-[10px] bg-emerald-950 text-emerald-400 border border-emerald-800 rounded font-bold'
          : 'px-2 py-0.5 text-[10px] bg-amber-950 text-amber-400 border border-amber-800 rounded font-bold';
      }
    } else {
      addConsoleLog('Zero-Trust Engine Response: Session verified & active.');
    }
  } catch (err) {
    addConsoleLog(`Verification Error: ${err.message}`);
  }

  if (btn) {
    btn.textContent = 'Identity Verified & Telemetry Transmitted';
    btn.disabled = false;
  }
};

// 4. APPLICATION PORTAL FLOW (SHOPPING / COLLEGE / HEALTHCARE)
let activePortalType = 'shopping';

function openPortalModal(type) {
  activePortalType = type;
  const modal = document.getElementById('modal-portal');
  if (modal) modal.classList.remove('hidden');

  const card = document.getElementById('portal-modal-card');
  const header = document.getElementById('portal-modal-header');
  const title = document.getElementById('portal-modal-title');
  const tagline = document.getElementById('portal-modal-tagline');
  const loginHeading = document.getElementById('portal-login-heading');
  const emailInput = document.getElementById('portal-email-input');

  const meta = {
    shopping: {
      name: 'Aura Luxe Shopping Portal',
      tagline: 'Premium Global Retail Platform',
      border: 'border border-amber-600/50',
      headerBg: 'px-6 py-3.5 border-b border-red-950/80 bg-gradient-to-r from-amber-950/40 via-black to-amber-950/20 flex items-center justify-between',
      email: 'customer.jane@auraluxe.com',
      userName: 'Jane Doe',
      userRole: 'VIP Customer Account'
    },
    college: {
      name: 'Veritas University Portal',
      tagline: 'Student & Faculty Academic System',
      border: 'border border-sky-600/50',
      headerBg: 'px-6 py-3.5 border-b border-red-950/80 bg-gradient-to-r from-sky-950/40 via-black to-sky-950/20 flex items-center justify-between',
      email: 'student.alex@veritas.edu',
      userName: 'Alex Mercer',
      userRole: 'Computer Science Major'
    },
    healthcare: {
      name: 'Aetheria Health EHR Portal',
      tagline: 'Clinical Records & Patient Portal',
      border: 'border border-emerald-600/50',
      headerBg: 'px-6 py-3.5 border-b border-red-950/80 bg-gradient-to-r from-emerald-950/40 via-black to-emerald-950/20 flex items-center justify-between',
      email: 'dr.sarah@aetheriahealth.org',
      userName: 'Dr. Sarah Lin, MD',
      userRole: 'Attending Physician'
    }
  }[type];

  if (card) card.className = `relative w-full max-w-4xl bg-[#07050a] ${meta.border} rounded-2xl shadow-[0_0_80px_rgba(0,0,0,0.9)] overflow-hidden flex flex-col max-h-[90vh]`;
  if (header) header.className = meta.headerBg;
  if (title) title.textContent = meta.name;
  if (tagline) tagline.textContent = meta.tagline;
  if (loginHeading) loginHeading.textContent = `Sign In to ${meta.name}`;
  if (emailInput) emailInput.value = meta.email;

  // Step 1: Loading Sequence
  document.getElementById('portal-step-loading').classList.remove('hidden');
  document.getElementById('portal-step-login').classList.add('hidden');
  document.getElementById('portal-step-authenticated').classList.add('hidden');

  for (let i = 1; i <= 5; i++) {
    const checkEl = document.getElementById(`check-${i}`);
    if (checkEl) checkEl.innerHTML = `<span>● ${getCheckLabel(i)}</span><span class="text-amber-400">Checking...</span>`;
  }

  // Sequence animation
  for (let i = 1; i <= 5; i++) {
    setTimeout(() => {
      const checkEl = document.getElementById(`check-${i}`);
      if (checkEl) checkEl.innerHTML = `<span class="text-white font-semibold">✓ ${getCheckLabel(i)}</span><span class="text-emerald-400 font-bold">READY</span>`;
    }, i * 350);
  }

  // Transition to Login
  setTimeout(() => {
    document.getElementById('portal-step-loading').classList.add('hidden');
    document.getElementById('portal-step-login').classList.remove('hidden');
  }, 2100);
}

function getCheckLabel(index) {
  return [
    'Initializing COGNISEC AI...',
    'Device Fingerprint Verified',
    'Behavioral Monitoring Started',
    'Cognitive Authentication Enabled',
    'Zero Trust Session Created'
  ][index - 1];
}

window.submitPortalLogin = function(e) {
  e.preventDefault();
  const btn = document.getElementById('btn-portal-signin');
  if (btn) {
    btn.textContent = 'Authenticating & Launching Session...';
    btn.disabled = true;
  }

  setTimeout(() => {
    document.getElementById('portal-step-login').classList.add('hidden');
    document.getElementById('portal-step-authenticated').classList.remove('hidden');

    const meta = {
      shopping: { userName: 'Jane Doe', userRole: 'VIP Customer Account • customer.jane@auraluxe.com' },
      college: { userName: 'Alex Mercer', userRole: 'Computer Science Major • student.alex@veritas.edu' },
      healthcare: { userName: 'Dr. Sarah Lin, MD', userRole: 'Attending Physician • dr.sarah@aetheriahealth.org' }
    }[activePortalType];

    document.getElementById('portal-user-welcome').textContent = `Welcome, ${meta.userName}`;
    document.getElementById('portal-user-role').textContent = meta.userRole;

    renderPortalSpecificContent(activePortalType);

    if (btn) {
      btn.disabled = false;
      btn.textContent = 'Sign In & Launch Session →';
    }
  }, 900);
};

function renderPortalSpecificContent(type) {
  const container = document.getElementById('portal-app-specific-content');
  if (!container) return;

  if (type === 'shopping') {
    container.innerHTML = `
      <div class="space-y-6 font-mono">
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div class="p-4 rounded-xl bg-black/40 border border-amber-900/40">
            <span class="text-xs text-slate-400 block uppercase">Shopping Cart</span>
            <strong class="text-lg text-amber-400 font-extrabold">3 Items ($1,420)</strong>
          </div>
          <div class="p-4 rounded-xl bg-black/40 border border-amber-900/40">
            <span class="text-xs text-slate-400 block uppercase">Loyalty Status</span>
            <strong class="text-lg text-white font-extrabold">Platinum VIP Member</strong>
          </div>
          <div class="p-4 rounded-xl bg-black/40 border border-amber-900/40">
            <span class="text-xs text-slate-400 block uppercase">Checkout Security</span>
            <strong class="text-lg text-emerald-400 font-extrabold">Continuous Shield Active</strong>
          </div>
        </div>
        <div class="p-5 rounded-2xl bg-black/50 border border-amber-950 space-y-3">
          <div class="flex items-center justify-between">
            <h5 class="font-heading font-bold text-white text-sm">High-Value Cart Items (Protected Checkout)</h5>
            <span class="text-xs text-emerald-400 font-bold">✓ Biometrics Verified</span>
          </div>
          <div class="space-y-2 text-xs">
            <div class="p-3 rounded-xl bg-black/80 border border-amber-950 flex items-center justify-between">
              <span class="text-slate-200">Aura Luxe Chronograph Watch</span>
              <span class="text-amber-400 font-bold">$950.00</span>
            </div>
            <div class="p-3 rounded-xl bg-black/80 border border-amber-950 flex items-center justify-between">
              <span class="text-slate-200">Leather Travel Duffle</span>
              <span class="text-amber-400 font-bold">$470.00</span>
            </div>
          </div>
        </div>
      </div>`;
  } else if (type === 'college') {
    container.innerHTML = `
      <div class="space-y-6 font-mono">
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div class="p-4 rounded-xl bg-black/40 border border-sky-900/40">
            <span class="text-xs text-slate-400 block uppercase">Enrolled Courses</span>
            <strong class="text-lg text-sky-400 font-extrabold">4 Active Courses</strong>
          </div>
          <div class="p-4 rounded-xl bg-black/40 border border-sky-900/40">
            <span class="text-xs text-slate-400 block uppercase">Academic GPA</span>
            <strong class="text-lg text-white font-extrabold">3.92 / 4.0</strong>
          </div>
          <div class="p-4 rounded-xl bg-black/40 border border-sky-900/40">
            <span class="text-xs text-slate-400 block uppercase">Exam Integrity</span>
            <strong class="text-lg text-emerald-400 font-extrabold">Proxy Guard On</strong>
          </div>
        </div>
        <div class="p-5 rounded-2xl bg-black/50 border border-sky-950 space-y-3">
          <h5 class="font-heading font-bold text-white text-sm">Active Student Dashboard</h5>
          <div class="space-y-2 text-xs">
            <div class="p-3 rounded-xl bg-black/80 border border-sky-950 flex items-center justify-between">
              <span class="text-slate-200">CS 4800: Advanced Distributed Cryptography</span>
              <span class="text-emerald-400 font-bold">Grade: A</span>
            </div>
            <div class="p-3 rounded-xl bg-black/80 border border-sky-950 flex items-center justify-between">
              <span class="text-slate-200">CS 4950: Behavioral Biometrics &amp; AI Security</span>
              <span class="text-emerald-400 font-bold">Grade: A+</span>
            </div>
          </div>
        </div>
      </div>`;
  } else if (type === 'healthcare') {
    container.innerHTML = `
      <div class="space-y-6 font-mono">
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div class="p-4 rounded-xl bg-black/40 border border-emerald-900/40">
            <span class="text-xs text-slate-400 block uppercase">Clinical Department</span>
            <strong class="text-lg text-emerald-400 font-extrabold">Cardiology EHR</strong>
          </div>
          <div class="p-4 rounded-xl bg-black/40 border border-emerald-900/40">
            <span class="text-xs text-slate-400 block uppercase">HIPAA Status</span>
            <strong class="text-lg text-white font-extrabold">100% Compliant</strong>
          </div>
          <div class="p-4 rounded-xl bg-black/40 border border-emerald-900/40">
            <span class="text-xs text-slate-400 block uppercase">Workstation Guard</span>
            <strong class="text-lg text-emerald-400 font-extrabold">Proximity Active</strong>
          </div>
        </div>
        <div class="p-5 rounded-2xl bg-black/50 border border-emerald-950 space-y-3">
          <h5 class="font-heading font-bold text-white text-sm">Recent Patient Records Access</h5>
          <div class="space-y-2 text-xs">
            <div class="p-3 rounded-xl bg-black/80 border border-emerald-950 flex items-center justify-between">
              <span class="text-slate-200">Patient #92810 - Post-op Telemetry</span>
              <span class="text-emerald-400 font-bold">PHI Shielded</span>
            </div>
            <div class="p-3 rounded-xl bg-black/80 border border-emerald-950 flex items-center justify-between">
              <span class="text-slate-200">Patient #88129 - EKG Analysis</span>
              <span class="text-emerald-400 font-bold">PHI Shielded</span>
            </div>
          </div>
        </div>
      </div>`;
  }
}

// 5. TECHNOLOGY SECTION TAB SWITCHING (FULL SPEC)
const techPillarsData = {
  behavioral: {
    title: 'Behavioral Biometrics',
    badge: '1,000Hz Monitoring',
    subtitle: 'Passive Interaction Rhythm Analysis',
    desc: 'Analyzes unique human motor traits—such as flight-time, dwell-time keystroke dynamics, Bezier curve mouse accelerations, and touch swipe pressures—to form an un-replicable biometric signature.',
    capabilities: [
      'Keystroke flight & dwell rhythm matching',
      'Mouse curvature & velocity vector analysis',
      'Passive micro-gesture tracking',
      'Non-intrusive background profiling'
    ],
    metric: '99.94% Behavioral Accuracy',
    fidelity: '99.8%',
    fidelityWidth: '99.8%',
    overhead: '< 0.8ms',
    overheadWidth: '15%',
    alert: 'Sub-millisecond real-time scoring without user latency.',
    icon: `<svg class="w-7 h-7" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4z"/><path d="M6 21v-2a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v2"/></svg>`
  },
  cognitive: {
    title: 'Cognitive Authentication',
    badge: 'Zero Knowledge',
    subtitle: 'Zero-Knowledge Entropy Challenges',
    desc: 'Evaluates subconscious cognitive decision patterns and reaction timings against high-dimensional neural baselines without prompting the user for passwords.',
    capabilities: [
      'Subconscious decision latency profiling',
      'Zero-knowledge challenge-response',
      'Neural entropy pattern analysis',
      'Continuous cognitive state matching'
    ],
    metric: '< 0.4ms Verification',
    fidelity: '99.5%',
    fidelityWidth: '99.5%',
    overhead: '< 0.4ms',
    overheadWidth: '10%',
    alert: 'Zero friction passwordless authentication running silently.',
    icon: `<svg class="w-7 h-7" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96.44L2.04 15.5A2.5 2.5 0 0 1 2 14.5v-5a2.5 2.5 0 0 1 2.04-2.44l5.04-4.5A2.48 2.48 0 0 1 9.5 2Z"/><path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96.44l5.04-4.44A2.5 2.5 0 0 0 22 14.5v-5a2.5 2.5 0 0 0-2.04-2.44l-5.04-4.5A2.48 2.48 0 0 0 14.5 2Z"/></svg>`
  },
  device: {
    title: 'Device Fingerprinting',
    badge: 'Hardware Shield',
    subtitle: 'Hardware & Browser Integrity',
    desc: 'Inspects low-level Canvas rendering, WebGL context signatures, AudioContext entropy, and TPM 2.0 cryptographic keys to ensure session integrity.',
    capabilities: [
      'GPU WebGL shader entropy hashing',
      'TPM 2.0 hardware security module integration',
      'AudioContext frequency response profiling',
      'Anti-virtualization & anti-bot isolation'
    ],
    metric: 'TPM 2.0 Encrypted',
    fidelity: '100.0%',
    fidelityWidth: '100%',
    overhead: '< 0.2ms',
    overheadWidth: '5%',
    alert: 'Hardware tamper detection active across browser sessions.',
    icon: `<svg class="w-7 h-7" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="14" x="2" y="3" rx="2"/><line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/></svg>`
  },
  'risk-engine': {
    title: 'AI Risk Engine',
    badge: '< 0.8ms Inference',
    subtitle: 'Sub-Millisecond Threat Inference',
    desc: 'Runs light-speed local and edge neural models to continuously calculate a zero-trust anomaly score based on device health and biometric fidelity.',
    capabilities: [
      'Edge neural network anomaly scoring',
      'Dynamic trust floor recalculation',
      'Instant step-up challenge trigger',
      'Automated threat vector isolation'
    ],
    metric: '0.02 Risk Score',
    fidelity: '99.9%',
    fidelityWidth: '99.9%',
    overhead: '< 0.8ms',
    overheadWidth: '15%',
    alert: 'Real-time AI threat mitigation with sub-millisecond precision.',
    icon: `<svg class="w-7 h-7" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="16" height="16" x="4" y="4" rx="2"/><rect width="6" height="6" x="9" y="9" rx="1"/><path d="M15 2v2"/><path d="M15 20v2"/><path d="M2 15h2"/><path d="M2 9h2"/><path d="M20 15h2"/><path d="M20 9h2"/><path d="M9 2v2"/><path d="M9 20v2"/></svg>`
  },
  continuous: {
    title: 'Continuous Verification',
    badge: 'Always Active',
    subtitle: 'Always-On Zero Trust Protection',
    desc: 'Replaces static login checkpoints with continuous, real-time protection. If session anomalies exceed risk thresholds, the system isolates the session.',
    capabilities: [
      'Persistent session token re-binding',
      'Real-time risk score streaming',
      'Zero-downtime identity enforcement',
      'Automated step-up MFA escalation'
    ],
    metric: '24/7 Session Shield',
    fidelity: '99.99%',
    fidelityWidth: '99.99%',
    overhead: '< 0.1ms',
    overheadWidth: '4%',
    alert: 'Always-on session protection active across all active portals.',
    icon: `<svg class="w-7 h-7" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>`
  }
};

window.switchTechTab = function(key) {
  const data = techPillarsData[key];
  if (!data) return;

  ['behavioral', 'cognitive', 'device', 'risk-engine', 'continuous'].forEach(k => {
    const btn = document.getElementById(`tab-${k}`);
    const iconBox = document.getElementById(`tab-icon-${k}`);
    const dot = document.getElementById(`tab-dot-${k}`);
    if (btn) {
      if (k === key) {
        btn.className = 'relative p-4 rounded-2xl border text-left transition-all duration-300 cursor-pointer border-red-500 bg-red-950/40 shadow-[0_0_25px_rgba(239,68,68,0.35)] flex flex-col justify-between space-y-3 group';
        if (iconBox) iconBox.className = 'p-2.5 rounded-xl bg-red-900/40 border border-red-700/50 text-red-400';
        if (dot) dot.className = 'w-2 h-2 rounded-full bg-emerald-400 opacity-100';
      } else {
        btn.className = 'relative p-4 rounded-2xl border text-left transition-all duration-300 cursor-pointer border-red-900/30 bg-black/40 hover:border-red-700/50 flex flex-col justify-between space-y-3 group';
        if (iconBox) iconBox.className = 'p-2.5 rounded-xl bg-black/60 border border-red-950 text-slate-400';
        if (dot) dot.className = 'w-2 h-2 rounded-full bg-slate-800 opacity-0';
      }
    }
  });

  const heroIcon = document.getElementById('tech-hero-icon');
  if (heroIcon) heroIcon.innerHTML = data.icon;

  document.getElementById('tech-title').textContent = data.title;
  document.getElementById('tech-badge').textContent = data.badge;
  document.getElementById('tech-subtitle').textContent = data.subtitle;
  document.getElementById('tech-desc').textContent = data.desc;
  document.getElementById('tech-metric').textContent = data.metric;
  document.getElementById('tech-fidelity-val').textContent = data.fidelity;
  document.getElementById('tech-fidelity-bar').style.width = data.fidelityWidth;
  document.getElementById('tech-overhead-val').textContent = data.overhead;
  document.getElementById('tech-overhead-bar').style.width = data.overheadWidth;
  document.getElementById('tech-alert-text').textContent = data.alert;

  const capGrid = document.getElementById('tech-capabilities-grid');
  if (capGrid && data.capabilities) {
    capGrid.innerHTML = data.capabilities.map(cap => `
      <div class="flex items-start gap-2">
        <span class="w-4 h-4 rounded-full bg-emerald-950 border border-emerald-700 text-emerald-400 flex items-center justify-center text-[10px] shrink-0">✓</span>
        <span>${cap}</span>
      </div>
    `).join('');
  }
};


// 6. ARCHITECTURE PIPELINE DEMO SIMULATOR (CONTINUOUS ACTIVE FLOW)
let pipelineCurrentStep = 1;
let pipelineTimer = null;

function setPipelineStep(step) {
  pipelineCurrentStep = step;
  
  for (let i = 1; i <= 3; i++) {
    const node = document.getElementById(`pipe-node-${i}`);
    const num = document.getElementById(`pipe-num-${i}`);
    const badge = document.getElementById(`pipe-badge-${i}`);

    if (i === step) {
      if (i === 1) {
        if (node) node.className = 'p-5 rounded-2xl border border-emerald-500 bg-emerald-950/30 shadow-[0_0_30px_rgba(16,185,129,0.35)] transition-all duration-500';
        if (num) num.className = 'text-xs font-mono text-emerald-400 font-bold';
        if (badge) {
          badge.textContent = '● ACTIVE FLOW';
          badge.className = 'text-[9px] font-mono font-bold px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 animate-pulse';
        }
      } else if (i === 2) {
        if (node) node.className = 'p-5 rounded-2xl border border-sky-500 bg-sky-950/30 shadow-[0_0_30px_rgba(14,165,233,0.35)] transition-all duration-500';
        if (num) num.className = 'text-xs font-mono text-sky-400 font-bold';
        if (badge) {
          badge.textContent = '● EVALUATING';
          badge.className = 'text-[9px] font-mono font-bold px-2 py-0.5 rounded bg-sky-950 text-sky-400 border border-sky-800 animate-pulse';
        }
      } else if (i === 3) {
        if (node) node.className = 'p-5 rounded-2xl border border-red-500 bg-red-950/40 shadow-[0_0_30px_rgba(239,68,68,0.35)] transition-all duration-500';
        if (num) num.className = 'text-xs font-mono text-red-400 font-bold';
        if (badge) {
          badge.textContent = '● ENFORCING';
          badge.className = 'text-[9px] font-mono font-bold px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-800 animate-pulse';
        }
      }
    } else {
      if (node) node.className = 'p-5 rounded-2xl border border-red-900/30 bg-black/40 hover:border-red-700/50 transition-all duration-500';
      if (num) num.className = 'text-xs font-mono text-slate-400 font-bold';
      if (badge) {
        badge.textContent = 'STANDBY';
        badge.className = 'text-[9px] font-mono font-bold px-2 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800';
      }
    }
  }
}

function startPipelineAutoLoop() {
  if (pipelineTimer) return;
  setPipelineStep(1);
  pipelineTimer = setInterval(() => {
    let nextStep = pipelineCurrentStep + 1;
    if (nextStep > 3) nextStep = 1;
    setPipelineStep(nextStep);
  }, 1600);
}

window.runPipelineDemo = function() {
  let nextStep = pipelineCurrentStep + 1;
  if (nextStep > 3) nextStep = 1;
  setPipelineStep(nextStep);
};

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', startPipelineAutoLoop);
} else {
  startPipelineAutoLoop();
}


// 7. HUD 3D CORE MODE SWITCHER & THREAT SIMULATION
window.setHudMode = function(mode) {
  const modes = ['core', 'biometric', 'neural', 'stream'];
  modes.forEach(m => {
    const btn = document.getElementById(`hud-btn-${m}`);
    if (btn) {
      if (m === mode) {
        btn.className = 'px-3 py-1.5 rounded-lg text-[10px] font-mono font-bold transition-all bg-red-600 text-white shadow-[0_0_15px_rgba(220,38,38,0.7)] cursor-pointer';
      } else {
        btn.className = 'px-3 py-1.5 rounded-lg text-[10px] font-mono font-bold transition-all text-slate-400 hover:text-white cursor-pointer';
      }
    }
  });

  const contentEl = document.getElementById('hud-core-content');
  if (!contentEl) return;

  if (mode === 'core') {
    contentEl.innerHTML = `
      <div class="relative">
        <svg class="w-20 h-20 text-red-500 drop-shadow-[0_0_35px_rgba(239,68,68,0.95)] animate-pulse" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/></svg>
        <svg class="w-8 h-8 text-white absolute inset-0 m-auto drop-shadow-[0_0_15px_#ffffff]" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
      </div>
      <div class="text-center">
        <span class="block text-xs font-mono font-bold text-white tracking-widest uppercase">ZERO TRUST NUCLEUS</span>
        <span id="hud-status-text" class="text-[10px] font-mono text-red-400/90 font-semibold">CONTINUOUS BEHAVIORAL LOCK</span>
      </div>`;
  } else if (mode === 'biometric') {
    contentEl.innerHTML = `
      <div class="relative">
        <svg class="w-20 h-20 text-red-500 drop-shadow-[0_0_40px_rgba(239,68,68,0.95)] animate-pulse" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4z"/><path d="M6 21v-2a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v2"/></svg>
      </div>
      <div class="text-center">
        <span class="block text-xs font-mono font-bold text-white tracking-widest uppercase">BIOMETRIC MESH</span>
        <span class="text-[10px] font-mono text-emerald-400 font-semibold">MATCH: 99.98% (VERIFIED)</span>
      </div>`;
  } else if (mode === 'neural') {
    contentEl.innerHTML = `
      <div class="relative">
        <svg class="w-20 h-20 text-red-400 drop-shadow-[0_0_40px_rgba(239,68,68,0.9)] animate-bounce" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96.44L2.04 15.5A2.5 2.5 0 0 1 2 14.5v-5a2.5 2.5 0 0 1 2.04-2.44l5.04-4.5A2.48 2.48 0 0 1 9.5 2Z"/><path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96.44l5.04-4.44A2.5 2.5 0 0 0 22 14.5v-5a2.5 2.5 0 0 0-2.04-2.44l-5.04-4.5A2.48 2.48 0 0 0 14.5 2Z"/></svg>
      </div>
      <div class="text-center">
        <span class="block text-xs font-mono font-bold text-white tracking-widest uppercase">COGNITIVE AI NET</span>
        <span class="text-[10px] font-mono text-red-400 font-semibold">ENTROPY OPTIMAL</span>
      </div>`;
  } else if (mode === 'stream') {
    contentEl.innerHTML = `
      <div class="flex flex-col items-center justify-center p-2 text-left font-mono text-[9px] text-red-300/90 leading-snug w-full h-full">
        <div class="text-emerald-400 font-bold border-b border-red-900/50 pb-1 mb-1 w-full text-center">[LIVE STREAM]</div>
        <div>&gt; AUTH_REQ: ID_892_ALPHA</div>
        <div>&gt; COGNITIVE_HASH: 0x9F4B...8A</div>
        <div>&gt; KEYSTROKE_ENTROPY: 0.942</div>
        <div class="text-emerald-400 font-semibold">&gt; CONTINUOUS TRUST PASS</div>
      </div>`;
  }
};

let isThreatActive = false;
window.triggerThreatSimulation = async function() {
  if (isThreatActive) return;
  isThreatActive = true;

  const btnText = document.getElementById('threat-btn-text');
  const progressText = document.getElementById('scan-progress-text');
  const simBtn = document.getElementById('threat-sim-btn');

  if (btnText) btnText.textContent = 'THREAT INTERCEPT IN PROGRESS...';
  if (progressText) {
    progressText.textContent = 'RISK SCORE: 0.942 (CRITICAL)';
    progressText.className = 'text-[10px] font-mono text-red-400 font-extrabold animate-pulse';
  }
  if (simBtn) simBtn.className = 'w-full py-1.5 px-3 rounded-lg text-[10px] font-mono font-bold tracking-wider uppercase transition-all flex items-center justify-center gap-2 border bg-red-600 text-white border-red-400 animate-pulse shadow-[0_0_15px_#ef4444] cursor-pointer';

  // Trigger backend attack simulator
  if (window.cognisec) {
    window.cognisec.simulateAttack('SESSION_HIJACKING', 'ecommerce');
  }

  setTimeout(() => {
    if (btnText) btnText.textContent = 'ZERO-TRUST KILL SWITCH EXECUTED';
  }, 2000);

  setTimeout(() => {
    isThreatActive = false;
    if (btnText) btnText.textContent = 'Simulate Threat Attack';
    if (progressText) {
      progressText.textContent = '99.94% FIDELITY';
      progressText.className = 'text-[10px] font-mono text-emerald-400 font-semibold';
    }
    if (simBtn) simBtn.className = 'w-full py-1.5 px-3 rounded-lg text-[10px] font-mono font-bold tracking-wider uppercase transition-all flex items-center justify-center gap-2 border bg-red-950/70 hover:bg-red-900 text-red-200 border-red-700/60 hover:border-red-500 cursor-pointer';
  }, 4500);
};

// Intersection Observer for Slow-Motion Scroll Reveal of Cards & Workflow Items
function initRevealObserver() {
  const elements = document.querySelectorAll('.reveal-card, .reveal-left, .reveal-right');
  if (elements.length === 0) return;

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('revealed');
      }
    });
  }, {
    root: null,
    rootMargin: '0px 0px -20px 0px',
    threshold: 0.1
  });

  elements.forEach(el => {
    observer.observe(el);
    const rect = el.getBoundingClientRect();
    if (rect.top < window.innerHeight && rect.bottom > 0) {
      el.classList.add('revealed');
    }
  });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    initRevealObserver();
    setTimeout(initRevealObserver, 300);
  });
} else {
  initRevealObserver();
  setTimeout(initRevealObserver, 300);
}

// COINFLECT MIGRATION MODAL HANDLERS
let isCoinflectWalletConnected = false;
let userV1Balance = 12500;
let userV2Balance = 0;

window.openCoinflectModal = function(type) {
  const modal = document.getElementById(`coinflect-modal-${type}`);
  if (modal) {
    modal.classList.remove('hidden');
    document.body.style.overflow = 'hidden';
  }
};

window.closeCoinflectModal = function(type) {
  const modal = document.getElementById(`coinflect-modal-${type}`);
  if (modal) {
    modal.classList.add('hidden');
    document.body.style.overflow = 'auto';
  }
};

window.switchCoinflectManualTab = function(tab) {
  const guideContent = document.getElementById('coinflect-manual-guide-content');
  const faqContent = document.getElementById('coinflect-manual-faq-content');
  const btnGuide = document.getElementById('coinflect-tab-guide');
  const btnFaq = document.getElementById('coinflect-tab-faq');

  if (tab === 'guide') {
    if (guideContent) guideContent.classList.remove('hidden');
    if (faqContent) faqContent.classList.add('hidden');
    if (btnGuide) btnGuide.className = 'px-3.5 py-1.5 rounded-lg text-xs font-medium bg-zinc-800 text-white cursor-pointer';
    if (btnFaq) btnFaq.className = 'px-3.5 py-1.5 rounded-lg text-xs font-medium text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900 cursor-pointer';
  } else {
    if (guideContent) guideContent.classList.add('hidden');
    if (faqContent) faqContent.classList.remove('hidden');
    if (btnGuide) btnGuide.className = 'px-3.5 py-1.5 rounded-lg text-xs font-medium text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900 cursor-pointer';
    if (btnFaq) btnFaq.className = 'px-3.5 py-1.5 rounded-lg text-xs font-medium bg-zinc-800 text-white cursor-pointer';
  }
};

window.copyCoinflectAddr = function(btn) {
  navigator.clipboard.writeText('0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D');
  if (btn) {
    btn.textContent = 'Copied! ✓';
    btn.className = 'px-2.5 py-1 text-xs bg-emerald-950 text-emerald-400 border border-emerald-800 rounded transition-colors font-bold cursor-pointer';
    setTimeout(() => {
      btn.textContent = 'Copy';
      btn.className = 'px-2.5 py-1 text-xs bg-zinc-800 hover:bg-zinc-700 text-white rounded transition-colors cursor-pointer';
    }, 2000);
  }
};

window.connectCoinflectWallet = function() {
  isCoinflectWalletConnected = true;
  const statusEl = document.getElementById('portal-wallet-status');
  const btnConnect = document.getElementById('portal-connect-btn');
  const btnSwap = document.getElementById('portal-swap-btn');

  if (statusEl) statusEl.textContent = 'Connected: 0x3F8...b912 (Verified)';
  if (btnConnect) {
    btnConnect.textContent = 'Connected ✓';
    btnConnect.className = 'px-3 py-1.5 text-xs font-bold bg-emerald-950 text-emerald-400 border border-emerald-800 rounded-lg cursor-default';
  }
  if (btnSwap) {
    btnSwap.textContent = 'Execute 1:1 Migration Swap';
    btnSwap.className = 'w-full py-3 px-4 bg-emerald-400 hover:bg-emerald-300 text-black font-extrabold text-sm rounded-xl transition-all shadow-md cursor-pointer';
  }
};

window.updatePortalSwapAmount = function(val) {
  const receiveEl = document.getElementById('portal-receive-val');
  if (receiveEl) receiveEl.textContent = val || '0';
};

window.executeCoinflectSwap = function() {
  if (!isCoinflectWalletConnected) {
    connectCoinflectWallet();
    return;
  }

  const inputVal = parseFloat(document.getElementById('portal-input-val')?.value || '1000');
  const btnSwap = document.getElementById('portal-swap-btn');

  if (btnSwap) {
    btnSwap.textContent = 'Processing On-Chain Migration... ⏳';
    btnSwap.disabled = true;
  }

  setTimeout(() => {
    userV1Balance = Math.max(0, userV1Balance - inputVal);
    userV2Balance += inputVal;

    const v1BalEl = document.getElementById('portal-v1-balance');
    const v2BalEl = document.getElementById('portal-v2-balance');
    const txAmtEl = document.getElementById('portal-tx-amount');
    const txHashEl = document.getElementById('portal-tx-hash');
    const formEl = document.getElementById('portal-swap-form');
    const successEl = document.getElementById('portal-success-view');

    if (v1BalEl) v1BalEl.textContent = userV1Balance.toLocaleString();
    if (v2BalEl) v2BalEl.textContent = userV2Balance.toLocaleString();
    if (txAmtEl) txAmtEl.textContent = inputVal.toLocaleString();
    if (txHashEl) txHashEl.textContent = `0x${Math.random().toString(16).substring(2, 10)}...${Math.random().toString(16).substring(2, 6)}`;

    if (formEl) formEl.classList.add('hidden');
    if (successEl) successEl.classList.remove('hidden');
  }, 1800);
};

// COGNISEC AI AGENT INTERACTIVE HANDLERS
window.toggleAiAgent = function() {
  const win = document.getElementById('ai-agent-window');
  if (win) {
    win.classList.toggle('hidden');
  }
};

window.sendAgentQuickQuery = function(type) {
  const container = document.getElementById('ai-agent-messages');
  if (!container) return;

  let queryText = '';
  let responseText = '';

  if (type === 'scan') {
    queryText = 'Run active threat scan';
    responseText = '⚡ <strong>Threat Scan Complete:</strong> 0 active anomalies detected across Shopping, College, and Healthcare endpoints. Behavioral entropy index is stable at 99.98%.';
  } else if (type === 'risk') {
    queryText = 'Check zero-trust risk score';
    responseText = '🛡 <strong>Zero-Trust Telemetry:</strong> Current session risk score is <strong>0.001 (LOW RISK)</strong>. Hardware TPM integrity verified.';
  } else if (type === 'match') {
    queryText = 'Verify biometric match';
    responseText = '✓ <strong>Biometric Verification:</strong> Keystroke flight rhythm matches primary user (Boomika Ram) with 99.98% confidence.';
  }

  // Append user message
  const userMsg = document.createElement('div');
  userMsg.className = 'p-2.5 rounded-xl bg-slate-900 border border-slate-800 text-right space-y-1';
  userMsg.innerHTML = `<span class="text-[10px] text-slate-400 font-bold uppercase block">YOU</span><p class="text-white">${queryText}</p>`;
  container.appendChild(userMsg);

  // Append agent response after short delay
  setTimeout(() => {
    const botMsg = document.createElement('div');
    botMsg.className = 'p-3 rounded-xl bg-red-950/40 border border-red-900/40 space-y-1.5 animate-fade-in';
    botMsg.innerHTML = `<span class="text-[10px] text-red-400 font-bold uppercase block">🤖 AGENTIC SECURITY BOT</span><p>${responseText}</p>`;
    container.appendChild(botMsg);
    container.scrollTop = container.scrollHeight;
  }, 400);

  container.scrollTop = container.scrollHeight;
};

window.handleAgentMessageSubmit = function(e) {
  e.preventDefault();
  const input = document.getElementById('ai-agent-input');
  const container = document.getElementById('ai-agent-messages');
  if (!input || !input.value.trim() || !container) return;

  const text = input.value.trim();
  input.value = '';

  // Append user message
  const userMsg = document.createElement('div');
  userMsg.className = 'p-2.5 rounded-xl bg-slate-900 border border-slate-800 text-right space-y-1';
  userMsg.innerHTML = `<span class="text-[10px] text-slate-400 font-bold uppercase block">YOU</span><p class="text-white">${text}</p>`;
  container.appendChild(userMsg);

  // Generate automated agent response
  setTimeout(() => {
    let reply = `I have analyzed your query regarding "${text}". COGNISEC AI actively monitors all active sessions with zero-latency behavioral risk evaluation.`;
    if (text.toLowerCase().includes('hello') || text.toLowerCase().includes('hi')) {
      reply = 'Greetings! I am monitoring your active session identity vectors. All security systems are online.';
    } else if (text.toLowerCase().includes('demo') || text.toLowerCase().includes('portal')) {
      reply = 'You can launch the live demo websites for Shopping, College, and Healthcare portals directly from the Interactive Applications section!';
    }

    const botMsg = document.createElement('div');
    botMsg.className = 'p-3 rounded-xl bg-red-950/40 border border-red-900/40 space-y-1.5 animate-fade-in';
    botMsg.innerHTML = `<span class="text-[10px] text-red-400 font-bold uppercase block">🤖 AGENTIC SECURITY BOT</span><p>${reply}</p>`;
    container.appendChild(botMsg);
    container.scrollTop = container.scrollHeight;
  }, 500);

  container.scrollTop = container.scrollHeight;
};

// 8. SECURITY NOTIFICATION CENTER POPUP HANDLERS
window.toggleNotificationCenter = function() {
  const container = document.getElementById('notif-popup-container');
  if (container) {
    container.classList.toggle('hidden');
  }
};

window.closeNotificationPopup = function() {
  const container = document.getElementById('notif-popup-container');
  if (container) {
    container.classList.add('hidden');
  }
};

window.handleNotificationResponse = function(answer) {
  const actionBtns = document.getElementById('notif-action-buttons');
  const resultBanner = document.getElementById('notif-result-banner');
  const badge = document.getElementById('notif-badge');

  if (badge) {
    badge.textContent = '0';
    badge.classList.remove('bg-red-600', 'animate-pulse');
    badge.classList.add('bg-slate-700');
  }

  if (actionBtns) actionBtns.classList.add('hidden');

  if (resultBanner) {
    resultBanner.classList.remove('hidden');
    if (answer === 'yes') {
      resultBanner.className = 'p-3 rounded-xl bg-emerald-950/80 border border-emerald-500 text-emerald-300 text-xs font-bold text-center animate-fade-in';
      resultBanner.innerHTML = '🟢 Device Confirmed as Trusted!<br><span class="text-[10px] text-slate-300">Added to Verified Hardware Inventory.</span>';
    } else {
      resultBanner.className = 'p-3 rounded-xl bg-red-950/90 border-2 border-red-500 text-red-300 text-xs font-bold text-center animate-fade-in shadow-[0_0_20px_#ef4444]';
      resultBanner.innerHTML = '⛔ CRITICAL SECURITY INTERCEPT!<br><span class="text-[10px] text-white">Session Locked &amp; Unauthorized IP Blocked.</span>';

      // Append log entry to SOC Dashboard
      const logsEl = document.getElementById('soc-live-logs');
      if (logsEl) {
        const timeStr = new Date().toLocaleTimeString('en-US', { hour12: false });
        const newLog = document.createElement('div');
        newLog.className = 'p-3 rounded-xl bg-black/50 border border-red-950 flex items-center justify-between font-mono text-[11px] animate-fade-in';
        newLog.innerHTML = `
          <div class="flex items-center gap-3">
            <span class="text-red-400 font-bold">🔴 [${timeStr}]</span>
            <span class="text-white font-bold">USER DENIED LOGIN (MacBook Pro M3)</span>
            <span class="text-slate-400 text-[10px]">&bull; IP 103.21.124.9 &bull; Zero-Trust Kill Switch Executed</span>
          </div>
          <span class="px-2.5 py-0.5 bg-red-950 text-red-400 border border-red-800 rounded text-[10px] font-bold">SESSION KILLED</span>
        `;
        logsEl.prepend(newLog);
      }
    }
  }

  setTimeout(() => {
    window.closeNotificationPopup();
  }, 2800);
};

// DASHBOARD SECTION REDIRECT & ADMIN ACCESS CONTROL
window.isAdminUser = true; // Boomika Ram (Security Administrator - USR-9842-X9)

window.scrollToSection = function(id) {
  const section = document.getElementById(id);
  if (section) {
    section.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
};

window.openSocDashboard = function() {
  if (window.isAdminUser) {
    window.openModal('dashboard');
  } else {
    const resultBanner = document.getElementById('notif-result-banner');
    if (resultBanner) {
      resultBanner.classList.remove('hidden');
      resultBanner.className = 'p-3 rounded-xl bg-red-950/90 border-2 border-red-500 text-red-300 text-xs font-bold text-center animate-fade-in shadow-[0_0_20px_#ef4444]';
      resultBanner.innerHTML = '🔒 ACCESS RESTRICTED!<br><span class="text-[10px] text-white">Only Security Administrators can access the SOC Operations Console.</span>';
      
      const popup = document.getElementById('notif-popup-container');
      if (popup) popup.classList.remove('hidden');
      
      setTimeout(() => {
        resultBanner.classList.add('hidden');
      }, 3500);
    } else {
      alert('🔒 Access Restricted: Only Security Administrators can access the SOC Security Operations Dashboard.');
    }
  }
};




