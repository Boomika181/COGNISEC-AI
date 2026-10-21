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

// Device Pixel Ratio Ultra-HD Supersampling & Crisp Filtering
let currentDpr = Math.min(window.devicePixelRatio || 1, 2.0);

function resizeCanvas() {
  currentDpr = Math.min(window.devicePixelRatio || 1, 2.0);
  const width = window.innerWidth;
  const height = window.innerHeight;

  if (canvas && ctx) {
    canvas.width = Math.round(width * currentDpr);
    canvas.height = Math.round(height * currentDpr);
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;
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

  if (!ctx.imageSmoothingEnabled || ctx.imageSmoothingQuality !== 'high') {
    ctx.imageSmoothingEnabled = true;
    ctx.imageSmoothingQuality = 'high';
  }

  const cw = canvas.width;
  const ch = canvas.height;

  const imgWidth = img.naturalWidth;
  const imgHeight = img.naturalHeight;

  const imgRatio = imgWidth / imgHeight;
  const canvasRatio = cw / ch;

  let renderWidth, renderHeight, offsetX, offsetY;

  if (canvasRatio > imgRatio) {
    renderWidth = cw;
    renderHeight = Math.round(cw / imgRatio);
    offsetX = 0;
    offsetY = Math.round((ch - renderHeight) / 2);
  } else {
    renderWidth = Math.round(ch * imgRatio);
    renderHeight = ch;
    offsetX = Math.round((cw - renderWidth) / 2);
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
        ctx.lineWidth = Math.max(1, 1.0 * currentDpr);
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
    const scaledRadius = p.radius * currentDpr;

    // Outer Glow
    ctx.beginPath();
    ctx.arc(px, py, scaledRadius * 2.8, 0, Math.PI * 2);
    ctx.fillStyle = `${p.color}${currentAlpha * 0.35})`;
    ctx.fill();

    // Core Particle
    ctx.beginPath();
    ctx.arc(px, py, scaledRadius, 0, Math.PI * 2);
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
  const dpr = Math.min(window.devicePixelRatio || 1, 2.0);
  if (endCanvas && endCtx) {
    const rect = endCanvas.parentElement ? endCanvas.parentElement.getBoundingClientRect() : { width: window.innerWidth, height: window.innerHeight };
    const w = Math.round(rect.width || window.innerWidth);
    const h = Math.round(rect.height || window.innerHeight);
    endCanvas.width = Math.round(w * dpr);
    endCanvas.height = Math.round(h * dpr);
    endCanvas.style.width = `${w}px`;
    endCanvas.style.height = `${h}px`;
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
    if (!endCtx.imageSmoothingEnabled || endCtx.imageSmoothingQuality !== 'high') {
      endCtx.imageSmoothingEnabled = true;
      endCtx.imageSmoothingQuality = 'high';
    }

    const cw = endCanvas.width;
    const ch = endCanvas.height;
    const imgRatio = img.naturalWidth / img.naturalHeight;
    const canvasRatio = cw / ch;

    let rw, rh, ox, oy;
    if (canvasRatio > imgRatio) {
      rw = cw;
      rh = Math.round(cw / imgRatio);
      ox = 0;
      oy = Math.round((ch - rh) / 2);
    } else {
      rw = Math.round(ch * imgRatio);
      rh = ch;
      ox = Math.round((cw - rw) / 2);
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
    if (notifBell) {
      notifBell.classList.remove('hidden');
    }
    if (typeof window.refreshNotifications === 'function') {
      window.refreshNotifications();
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

    if (typeof refreshAdaptiveMfaStatus === 'function') {
      refreshAdaptiveMfaStatus();
    }
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

    if (userDashName) userDashName.textContent = 'Enterprise User';
    if (userDashEmail) userDashEmail.textContent = 'Sign In Required';
    if (userDashRole) userDashRole.textContent = 'ROLE: GUEST';
    if (userDashStatus) userDashStatus.textContent = 'ACCOUNT: UNAUTHENTICATED';
    if (userDashSession) userDashSession.textContent = 'No Active Session';
    if (userDashDevice) userDashDevice.textContent = `${navigator.platform || 'macOS / Desktop'} • Chrome (Desktop)`;
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

window.showNotificationToast = function(title, message, icon = 'ℹ️') {
  if (window.cognisec && typeof window.cognisec.showToastNotification === 'function') {
    window.cognisec.showToastNotification(title, message, icon);
  }
};

// Modal Open / Close
window.openModal = function(id) {
  if (id.startsWith('portal-')) {
    const portalType = id.replace('portal-', '');
    openPortalModal(portalType);
    return;
  }

  // Zero-Trust Step-Up Re-Authentication Modal
  if (id === 'stepup') {
    if (window.cognisec && typeof window.cognisec.openStepUpModal === 'function') {
      window.cognisec.openStepUpModal();
      return;
    }
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

  // Authentication Protection Check for User Dashboard
  if (id === 'liveDemo') {
    if (!window.cognisec || !window.cognisec.isAuthenticated()) {
      openModal('login');
      setLoginScreen('select');
      return;
    }
  }

  // Display clear alert if session expired or terminated
  if (id === 'login' && window.cognisec && window.cognisec.sessionExpiredMessage) {
    const errUser = document.getElementById('login-error-user');
    const errSoc = document.getElementById('login-error-soc');
    if (errUser) {
      errUser.textContent = window.cognisec.sessionExpiredMessage;
      errUser.classList.remove('hidden');
    }
    if (errSoc) {
      errSoc.textContent = window.cognisec.sessionExpiredMessage;
      errSoc.classList.remove('hidden');
    }
    window.cognisec.sessionExpiredMessage = null;
  }

  const modal = document.getElementById(`modal-${id}`);
  if (modal) {
    modal.classList.remove('hidden');
  }

  if (id === 'dashboard') {
    startDashboardTimer();
    startSocPolling();
  }

  if (id === 'liveDemo') {
    if (typeof refreshAdaptiveMfaStatus === 'function') {
      refreshAdaptiveMfaStatus();
    }
    if (typeof refreshMaturityProgress === 'function') {
      refreshMaturityProgress();
    }
    if (typeof refreshUserDevices === 'function') {
      refreshUserDevices();
    }
    if (typeof refreshNotifications === 'function') {
      refreshNotifications();
    }
  }
};

window.closeModal = function(id) {
  if (id === 'stepup') {
    if (window.cognisec && typeof window.cognisec.closeStepUpModal === 'function') {
      window.cognisec.closeStepUpModal();
      return;
    }
  }

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
  const succUser = document.getElementById('login-success-user');
  const errSignup = document.getElementById('signup-error-user');

  if (errUser) errUser.classList.add('hidden');
  if (errSoc) errSoc.classList.add('hidden');
  if (succUser) succUser.classList.add('hidden');
  if (errSignup) errSignup.classList.add('hidden');

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
    if (container) container.className = 'relative w-full max-w-md bg-[#08050e] border border-red-900/60 rounded-2xl shadow-[0_0_80px_rgba(220,38,38,0.4)] overflow-hidden flex flex-col transition-all duration-300';
    switchUserAuthTab('signin');
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

// User Portal Tab Switching (Sign In vs Sign Up)
window.switchUserAuthTab = function(tab) {
  const signinTab = document.getElementById('tab-auth-signin');
  const signupTab = document.getElementById('tab-auth-signup');
  const signinPane = document.getElementById('user-auth-signin-pane');
  const signupPane = document.getElementById('user-auth-signup-pane');
  const titleEl = document.getElementById('login-modal-title');
  const subEl = document.getElementById('login-modal-subtitle');
  const errUser = document.getElementById('login-error-user');
  const errSignup = document.getElementById('signup-error-user');

  if (errUser) errUser.classList.add('hidden');
  if (errSignup) errSignup.classList.add('hidden');

  if (tab === 'signup') {
    if (signinTab) {
      signinTab.className = 'flex-1 py-2 px-3 rounded-lg text-xs font-mono font-semibold transition-all text-slate-400 hover:text-white cursor-pointer';
    }
    if (signupTab) {
      signupTab.className = 'flex-1 py-2 px-3 rounded-lg text-xs font-mono font-bold transition-all bg-red-600 text-white shadow-[0_0_15px_rgba(239,68,68,0.5)] cursor-pointer';
    }
    if (signinPane) signinPane.classList.add('hidden');
    if (signupPane) signupPane.classList.remove('hidden');
    if (titleEl) titleEl.textContent = 'CREATE USER ACCOUNT';
    if (subEl) subEl.textContent = 'Register a new enterprise identity protected by Zero Trust';

    const nameInput = document.getElementById('signup-user-name');
    if (nameInput) setTimeout(() => nameInput.focus(), 50);
  } else {
    // Default: 'signin'
    if (signinTab) {
      signinTab.className = 'flex-1 py-2 px-3 rounded-lg text-xs font-mono font-bold transition-all bg-red-600 text-white shadow-[0_0_15px_rgba(239,68,68,0.5)] cursor-pointer';
    }
    if (signupTab) {
      signupTab.className = 'flex-1 py-2 px-3 rounded-lg text-xs font-mono font-semibold transition-all text-slate-400 hover:text-white cursor-pointer';
    }
    if (signinPane) signinPane.classList.remove('hidden');
    if (signupPane) signupPane.classList.add('hidden');
    if (titleEl) titleEl.textContent = 'USER PORTAL SIGN IN';
    if (subEl) subEl.textContent = 'Continuous identity verified user authentication';

    const emailInput = document.getElementById('login-user-email');
    if (emailInput) setTimeout(() => emailInput.focus(), 50);
  }
};

// Inline Password Policy Validation
window.validateSignupPasswordPolicy = function(pwd) {
  pwd = pwd || '';
  const reqLen = document.getElementById('req-len');
  const reqUpper = document.getElementById('req-upper');
  const reqLower = document.getElementById('req-lower');
  const reqDigit = document.getElementById('req-digit');
  const reqSpecial = document.getElementById('req-special');

  const updateItem = (el, isValid, text) => {
    if (!el) return;
    if (isValid) {
      el.className = 'text-emerald-400 flex items-center gap-1 font-semibold';
      el.textContent = `✓ ${text}`;
    } else {
      el.className = 'text-slate-500 flex items-center gap-1';
      el.textContent = `✕ ${text}`;
    }
  };

  updateItem(reqLen, pwd.length >= 8, '8+ characters');
  updateItem(reqUpper, /[A-Z]/.test(pwd), '1 uppercase');
  updateItem(reqLower, /[a-z]/.test(pwd), '1 lowercase');
  updateItem(reqDigit, /\d/.test(pwd), '1 number');
  updateItem(reqSpecial, /[!@#$%^&*(),.?":{}|<>\-_=+[\]\\/;~`']/.test(pwd), '1 special (!@#$%^&*...)');

  validateSignupPasswordMatch();
};

// Inline Password Confirmation Match
window.validateSignupPasswordMatch = function() {
  const pwdInput = document.getElementById('signup-user-password');
  const confirmInput = document.getElementById('signup-user-confirm');
  const errConfirm = document.getElementById('err-inline-confirm');
  if (!confirmInput || !errConfirm) return true;

  const pwd = pwdInput ? pwdInput.value : '';
  const confirm = confirmInput.value;

  if (confirm.length > 0 && confirm !== pwd) {
    errConfirm.textContent = 'Passwords do not match.';
    errConfirm.classList.remove('hidden');
    return false;
  } else {
    errConfirm.textContent = '';
    errConfirm.classList.add('hidden');
    return true;
  }
};

window.submitUserSignIn = function(e) {
  submitLoginForm(e, 'user');
};

// ==============================================================================
// REGISTRATION WIZARD STATE MACHINE & MULTI-FACTOR ENROLLMENT
// ==============================================================================
const regWizardState = {
  currentStep: 1,
  gestureInitial: [],
  gestureConfirm: [],
  gestureStage: 'initial', // 'initial' | 'confirm'
  imageSequence: [],
  privateQuestion: '',
  privateResponse: '',
  regGestureGrid: null
};

window.goToSignupStep = function(step) {
  regWizardState.currentStep = step;

  // Update stepper pills
  for (let i = 1; i <= 4; i++) {
    const pill = document.getElementById(`reg-step-pill-${i}`);
    const pane = document.getElementById(`reg-step-pane-${i}`);
    if (pill) {
      if (i === step) {
        pill.className = 'py-1 px-1.5 rounded-lg bg-red-600 text-white font-bold transition-all shadow-[0_0_10px_rgba(239,68,68,0.5)]';
      } else if (i < step) {
        pill.className = 'py-1 px-1.5 rounded-lg bg-emerald-950 text-emerald-300 font-bold border border-emerald-800 transition-all';
      } else {
        pill.className = 'py-1 px-1.5 rounded-lg bg-slate-900 text-slate-500 font-bold border border-slate-800 transition-all';
      }
    }
    if (pane) {
      if (i === step) pane.classList.remove('hidden');
      else pane.classList.add('hidden');
    }
  }

  // Hook step initialization
  if (step === 2) {
    initRegGestureGrid();
  } else if (step === 3) {
    renderRegImageGrid();
  }
};

window.proceedSignupStep1 = function() {
  const nameInput = document.getElementById('signup-user-name');
  const emailInput = document.getElementById('signup-user-email');
  const passwordInput = document.getElementById('signup-user-password');
  const confirmInput = document.getElementById('signup-user-confirm');
  const errBox = document.getElementById('signup-error-user');

  if (errBox) errBox.classList.add('hidden');

  const name = nameInput ? nameInput.value.trim() : '';
  const email = emailInput ? emailInput.value.trim() : '';
  const password = passwordInput ? passwordInput.value : '';
  const confirm = confirmInput ? confirmInput.value : '';

  if (!name || !email || !password || !confirm) {
    if (errBox) {
      errBox.textContent = 'Please fill out all account information fields.';
      errBox.classList.remove('hidden');
    }
    return;
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    if (errBox) {
      errBox.textContent = 'Please enter a valid email address.';
      errBox.classList.remove('hidden');
    }
    return;
  }
  if (password !== confirm) {
    if (errBox) {
      errBox.textContent = 'Passwords do not match.';
      errBox.classList.remove('hidden');
    }
    return;
  }
  if (password.length < 8 || !/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/\d/.test(password) || !/[!@#$%^&*(),.?":{}|<>\-_=+[\]\\/;~`']/.test(password)) {
    if (errBox) {
      errBox.textContent = 'Password does not meet the complexity requirements.';
      errBox.classList.remove('hidden');
    }
    return;
  }

  goToSignupStep(2);
};

function initRegGestureGrid() {
  const container = document.getElementById('reg-gesture-grid');
  if (!container) return;

  if (!regWizardState.regGestureGrid) {
    regWizardState.regGestureGrid = new NeuralTraceAuth(container, {
      theme: 'theme-cyber',
      minNodes: 4,
      onPatternChange: (pattern) => {
        const display = document.getElementById('reg-gesture-display');
        if (display) {
          display.textContent = pattern.length > 0 ? `${pattern.length} nodes traversed` : '(Trace route along connected edges)';
        }
      },
      onPatternComplete: (pattern) => {
        const display = document.getElementById('reg-gesture-display');
        if (display) display.textContent = `Signal route complete (${pattern.length} nodes)`;
        const errEl = document.getElementById('reg-gesture-error');
        if (errEl) errEl.classList.add('hidden');
      },
      onPatternTooShort: (pattern) => {
        const display = document.getElementById('reg-gesture-display');
        if (display) display.textContent = `Insufficient route complexity: ${pattern.length} nodes (min 4 required)`;
        const errEl = document.getElementById('reg-gesture-error');
        if (errEl) {
          errEl.textContent = 'Route must connect at least 4 nodes along valid network edges.';
          errEl.classList.remove('hidden');
        }
      },
      onReset: () => {
        const display = document.getElementById('reg-gesture-display');
        if (display) display.textContent = '(Trace route along connected edges)';
      }
    });
  } else {
    regWizardState.regGestureGrid.reset();
  }
}

window.resetRegGesture = function() {
  regWizardState.gestureInitial = [];
  regWizardState.gestureConfirm = [];
  regWizardState.gestureStage = 'initial';

  if (regWizardState.regGestureGrid) {
    regWizardState.regGestureGrid.reset();
  }

  const tag = document.getElementById('reg-gesture-step-tag');
  if (tag) {
    tag.textContent = 'STAGE: TRACE PRIVATE ROUTE';
    tag.className = 'px-2 py-0.5 rounded text-[10px] bg-red-950 text-red-300 border border-red-800 font-bold';
  }
  const hint = document.getElementById('reg-gesture-hint');
  if (hint) hint.textContent = 'Trace your private secret route across connected network nodes (min 4 nodes).';

  const display = document.getElementById('reg-gesture-display');
  if (display) display.textContent = '(Trace route along connected edges)';

  const nextBtn = document.getElementById('reg-gesture-next-btn');
  if (nextBtn) nextBtn.textContent = 'Confirm Route →';

  const errEl = document.getElementById('reg-gesture-error');
  if (errEl) errEl.classList.add('hidden');
};

window.proceedSignupStep2 = function() {
  const errEl = document.getElementById('reg-gesture-error');
  if (errEl) errEl.classList.add('hidden');

  if (regWizardState.gestureStage === 'initial') {
    const pattern = regWizardState.regGestureGrid ? regWizardState.regGestureGrid.getPattern() : [];
    if (!pattern || pattern.length < 4) {
      if (errEl) {
        errEl.textContent = 'Please trace a valid initial neural route of at least 4 connected nodes.';
        errEl.classList.remove('hidden');
      }
      if (regWizardState.regGestureGrid) regWizardState.regGestureGrid.triggerShake();
      return;
    }

    regWizardState.gestureInitial = [...pattern];
    regWizardState.gestureStage = 'confirm';

    if (regWizardState.regGestureGrid) {
      regWizardState.regGestureGrid.reset();
    }

    const tag = document.getElementById('reg-gesture-step-tag');
    if (tag) {
      tag.textContent = 'STAGE: RETRACE TO CONFIRM';
      tag.className = 'px-2 py-0.5 rounded text-[10px] bg-amber-950 text-amber-300 border border-amber-800 font-bold';
    }
    const hint = document.getElementById('reg-gesture-hint');
    if (hint) hint.textContent = 'Retrace the exact same route across connected nodes to verify your secret.';

    const display = document.getElementById('reg-gesture-display');
    if (display) display.textContent = '(Retrace same route to confirm)';

    const nextBtn = document.getElementById('reg-gesture-next-btn');
    if (nextBtn) nextBtn.textContent = 'Verify Confirmation Route ✓';

  } else {
    // Stage is 'confirm'
    const confirmPattern = regWizardState.regGestureGrid ? regWizardState.regGestureGrid.getPattern() : [];
    if (!confirmPattern || confirmPattern.length < 4) {
      if (errEl) {
        errEl.textContent = 'Please retrace your confirmation route (min 4 nodes).';
        errEl.classList.remove('hidden');
      }
      if (regWizardState.regGestureGrid) regWizardState.regGestureGrid.triggerShake();
      return;
    }

    const match = JSON.stringify(regWizardState.gestureInitial) === JSON.stringify(confirmPattern);
    if (!match) {
      if (errEl) {
        errEl.textContent = 'Routes do not match! Please retrace confirmation route or reset.';
        errEl.classList.remove('hidden');
      }
      if (regWizardState.regGestureGrid) {
        regWizardState.regGestureGrid.triggerShake();
        regWizardState.regGestureGrid.reset();
      }
      return;
    }

    regWizardState.gestureConfirm = [...confirmPattern];
    goToSignupStep(3);
  }
};

const REG_IMAGE_CATALOGUE = [
  { id: 'img_shield', label: 'Shield', icon: '🛡️' },
  { id: 'img_key', label: 'Key', icon: '🔑' },
  { id: 'img_lock', label: 'Lock', icon: '🔒' },
  { id: 'img_radar', label: 'Radar', icon: '📡' },
  { id: 'img_vault', label: 'Vault', icon: '🏛️' },
  { id: 'img_biometric', label: 'Biometric', icon: '🧬' },
  { id: 'img_firewall', label: 'Firewall', icon: '🧱' },
  { id: 'img_token', label: 'Token', icon: '🪙' },
  { id: 'img_chip', label: 'Enclave', icon: '💾' }
];

window.renderRegImageGrid = function() {
  const grid = document.getElementById('reg-image-grid');
  if (!grid) return;
  grid.innerHTML = REG_IMAGE_CATALOGUE.map(item => `
    <div class="symbol-card ${regWizardState.imageSequence.includes(item.id) ? 'selected' : ''}" data-symbol="${item.id}" onclick="handleRegImageClick('${item.id}')">
      <span class="text-2xl">${item.icon}</span>
      <span class="text-[10px] text-slate-300 font-bold">${item.label}</span>
      ${regWizardState.imageSequence.includes(item.id) ? `<span class="symbol-order-badge">${regWizardState.imageSequence.indexOf(item.id) + 1}</span>` : ''}
    </div>
  `).join('');
  updateRegImageStrip();
};

window.handleRegImageClick = function(id) {
  if (regWizardState.imageSequence.includes(id)) return;
  regWizardState.imageSequence.push(id);
  renderRegImageGrid();
  const errEl = document.getElementById('reg-image-error');
  if (errEl) errEl.classList.add('hidden');
};

window.clearRegImageSequence = function() {
  regWizardState.imageSequence = [];
  renderRegImageGrid();
};

function updateRegImageStrip() {
  const strip = document.getElementById('reg-image-strip');
  if (!strip) return;
  if (regWizardState.imageSequence.length === 0) {
    strip.innerHTML = '<span class="text-slate-500 text-[11px]">(Click symbols below)</span>';
  } else {
    strip.innerHTML = regWizardState.imageSequence.map((id, i) => {
      const item = REG_IMAGE_CATALOGUE.find(c => c.id === id) || { label: id };
      return `<span class="px-2 py-0.5 rounded bg-red-950 text-red-300 border border-red-800 text-[10px] font-bold">${i+1}. ${item.label}</span>`;
    }).join('');
  }
}

window.proceedSignupStep3 = function() {
  const errEl = document.getElementById('reg-image-error');
  if (errEl) errEl.classList.add('hidden');

  if (regWizardState.imageSequence.length < 3) {
    if (errEl) {
      errEl.textContent = 'Please select at least 3 symbols in your cognitive sequence.';
      errEl.classList.remove('hidden');
    }
    return;
  }
  goToSignupStep(4);
};

window.handleSignupWizardSubmit = async function(e) {
  if (e && e.preventDefault) e.preventDefault();

  const nameInput = document.getElementById('signup-user-name');
  const emailInput = document.getElementById('signup-user-email');
  const passwordInput = document.getElementById('signup-user-password');
  const confirmInput = document.getElementById('signup-user-confirm');
  const questionSelect = document.getElementById('reg-private-question');
  const responseInput = document.getElementById('reg-private-response');
  const confirmResponseInput = document.getElementById('reg-confirm-response');
  const privErr = document.getElementById('reg-private-error');
  const globalErr = document.getElementById('signup-error-user');
  const btn = document.getElementById('btn-submit-user-signup');
  const loginSuccessBox = document.getElementById('login-success-user');

  if (privErr) privErr.classList.add('hidden');
  if (globalErr) globalErr.classList.add('hidden');

  const question = questionSelect ? questionSelect.value : '';
  const response = responseInput ? responseInput.value.trim() : '';
  const confirmResponse = confirmResponseInput ? confirmResponseInput.value.trim() : '';

  if (!response || response.length < 3) {
    if (privErr) {
      privErr.textContent = 'Private answer must be at least 3 characters long.';
      privErr.classList.remove('hidden');
    }
    return;
  }
  if (response.toLowerCase() !== confirmResponse.toLowerCase()) {
    if (privErr) {
      privErr.textContent = 'Private answers do not match.';
      privErr.classList.remove('hidden');
    }
    return;
  }

  // Double check gesture pattern
  if (!regWizardState.gestureInitial || regWizardState.gestureInitial.length < 4) {
    goToSignupStep(2);
    const errEl = document.getElementById('reg-gesture-error');
    if (errEl) {
      errEl.textContent = 'Gesture pattern is mandatory. Please draw your pattern.';
      errEl.classList.remove('hidden');
    }
    return;
  }

  // Double check image sequence
  if (!regWizardState.imageSequence || regWizardState.imageSequence.length < 3) {
    goToSignupStep(3);
    const errEl = document.getElementById('reg-image-error');
    if (errEl) {
      errEl.textContent = 'Image sequence is mandatory. Please select at least 3 symbols.';
      errEl.classList.remove('hidden');
    }
    return;
  }

  const name = nameInput ? nameInput.value.trim() : '';
  const email = emailInput ? emailInput.value.trim() : '';
  const password = passwordInput ? passwordInput.value : '';

  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Enrolling Factors & Creating Account...';
  }

  const factorData = {
    gesture_pattern: regWizardState.gestureInitial,
    confirm_gesture_pattern: regWizardState.gestureConfirm.length ? regWizardState.gestureConfirm : regWizardState.gestureInitial,
    image_sequence: regWizardState.imageSequence,
    confirm_image_sequence: regWizardState.imageSequence,
    private_question: question,
    private_response: response,
    confirm_private_response: confirmResponse
  };

  try {
    const res = await window.cognisec.register(name, email, password, 'USER', factorData);

    if (!res.success) {
      if (privErr) {
        privErr.textContent = res.error || 'Registration failed. Please check factor inputs.';
        privErr.classList.remove('hidden');
      }
      if (globalErr) {
        globalErr.textContent = res.error || 'Registration failed.';
        globalErr.classList.remove('hidden');
      }
      if (btn) {
        btn.disabled = false;
        btn.textContent = 'Activate Account & Enroll Factors ✓';
      }
      return;
    }

    // Success! Clear sensitive inputs
    if (passwordInput) passwordInput.value = '';
    if (confirmInput) confirmInput.value = '';
    if (responseInput) responseInput.value = '';
    if (confirmResponseInput) confirmResponseInput.value = '';
    regWizardState.gestureInitial = [];
    regWizardState.gestureConfirm = [];
    regWizardState.imageSequence = [];
    goToSignupStep(1);

    // Switch to sign in tab
    const loginEmailInput = document.getElementById('login-user-email');
    if (loginEmailInput) loginEmailInput.value = email;

    switchUserAuthTab('signin');

    if (loginSuccessBox) {
      loginSuccessBox.textContent = `✓ Account and factors registered successfully for ${email}! Please sign in.`;
      loginSuccessBox.classList.remove('hidden');
    }

    if (btn) {
      btn.disabled = false;
      btn.textContent = 'Activate Account & Enroll Factors ✓';
    }

  } catch (err) {
    if (privErr) {
      privErr.textContent = `Error: ${err.message}`;
      privErr.classList.remove('hidden');
    }
    if (btn) {
      btn.disabled = false;
      btn.textContent = 'Activate Account & Enroll Factors ✓';
    }
  }
};

window.submitUserSignUp = window.handleSignupWizardSubmit;

window.submitLoginForm = async function(e, type) {
  e.preventDefault();
  const btn = document.getElementById(type === 'user' ? 'btn-submit-user-login' : 'btn-submit-soc-login');
  const errBox = document.getElementById(type === 'user' ? 'login-error-user' : 'login-error-soc');
  const succBox = document.getElementById('login-success-user');
  const emailInput = document.getElementById(type === 'user' ? 'login-user-email' : 'login-soc-email');
  const passwordInput = document.getElementById(type === 'user' ? 'login-user-password' : 'login-soc-password');

  if (errBox) errBox.classList.add('hidden');
  if (succBox) succBox.classList.add('hidden');

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
    let locData = null;
    const shareLocBox = document.getElementById('login-share-location');
    if (shareLocBox && shareLocBox.checked) {
      if (btn) btn.innerHTML = `<span>Requesting location permission...</span>`;
      locData = await window.cognisec.requestDeviceLocation();
    }
    const nicknameInput = document.getElementById('login-device-nickname');
    const nickname = (nicknameInput && nicknameInput.value.trim()) ? nicknameInput.value.trim() : null;

    if (btn) btn.innerHTML = `<span>Authenticating with FastAPI Backend...</span>`;
    const result = await window.cognisec.login(email, password, 'platform', null, locData, nickname);
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

    if (btn) {
      btn.disabled = false;
      btn.innerHTML = type === 'user' ? 'Sign In User Portal' : 'Sign In SOC Console';
    }

    // Stage 1 complete! Transition to Stage 2: 60-Second Background Observation Period + Mandatory OTP
    if (result.data.session_status === 'PENDING_OBSERVATION' || result.data.session_status === 'PENDING_OTP') {
      closeModal('login');
      syncAuthStateUI();

      if (typeof window.refreshNotifications === 'function') {
        window.refreshNotifications();
      }
      if (typeof window.refreshUserDevices === 'function') {
        window.refreshUserDevices();
      }

      // Enter permitted interactive application interface without blocking countdown
      if (result.data.role === 'ADMIN') {
        openModal('dashboard');
      } else {
        openModal('liveDemo');
      }

      showNotificationToast(
        "Signed In // Baseline Observation",
        "Behavioral baseline observation running silently in background. Verification OTP required in 10s.",
        "info"
      );

      startObservationFlow(result.data);
      return;
    }

    // Synchronize UI if already active
    syncAuthStateUI();
    closeModal('login');

    if (typeof window.refreshNotifications === 'function') {
      window.refreshNotifications();
    }
    if (typeof window.refreshUserDevices === 'function') {
      window.refreshUserDevices();
    }

    // Role-based routing: Admin -> SOC Dashboard, Normal User -> User Dashboard
    if (result.data.role === 'ADMIN') {
      openModal('dashboard');
    } else {
      openModal('liveDemo');
    }

  } catch (err) {
    if (errBox) {
      errBox.textContent = err.message || 'Network error connecting to authentication server.';
      errBox.classList.remove('hidden');
    }
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = type === 'user' ? 'Sign In User Portal' : 'Sign In SOC Console';
    }
  }
};

// ==============================================================================
// PASSWORD RECOVERY / FORGOT PASSWORD HANDLER & VISIBILITY TOGGLE
// ==============================================================================
if (!window.togglePasswordVisibility) {
  window.togglePasswordVisibility = function(inputId, btn) {
    const input = typeof inputId === 'string' ? document.getElementById(inputId) : inputId;
    if (!input) return;
    const isPass = input.type === 'password';
    const start = input.selectionStart;
    const end = input.selectionEnd;
    input.type = isPass ? 'text' : 'password';
    try {
      if (start !== null && end !== null && document.activeElement === input) {
        input.setSelectionRange(start, end);
      }
    } catch (_) {}
    if (btn) {
      btn.setAttribute('aria-label', isPass ? 'Hide password' : 'Show password');
      btn.setAttribute('title', isPass ? 'Hide password' : 'Show password');
      btn.innerHTML = isPass ? (window.EYE_OFF_SVG || '✕') : (window.EYE_ON_SVG || '👁');
    }
  };
}

window.openForgotPasswordModal = function(prefillEmail) {
  if (window.cognisec && window.cognisec.openForgotPasswordModal) {
    window.cognisec.openForgotPasswordModal(prefillEmail);
  }
};

window.closeForgotPasswordModal = function() {
  if (window.cognisec && window.cognisec.closeForgotPasswordModal) {
    window.cognisec.closeForgotPasswordModal();
  }
};

window.submitPasswordResetRequest = function(e) {
  if (window.cognisec && window.cognisec.submitPasswordResetRequestFromModal) {
    return window.cognisec.submitPasswordResetRequestFromModal(e);
  }
};

window.submitPasswordResetVerify = function(e) {
  if (window.cognisec && window.cognisec.submitPasswordResetVerifyFromModal) {
    return window.cognisec.submitPasswordResetVerifyFromModal(e);
  }
};

window.resendPasswordReset = function() {
  if (window.cognisec && window.cognisec.resendPasswordResetFromModal) {
    return window.cognisec.resendPasswordResetFromModal();
  }
};

window.resendPasswordResetFromModal = function() {
  if (window.cognisec && window.cognisec.resendPasswordResetFromModal) {
    return window.cognisec.resendPasswordResetFromModal();
  }
};

// ==============================================================================
// 60-SECOND BACKGROUND OBSERVATION & LOGIN OTP CONTROLLER
// ==============================================================================

let obsTimer = null;
let otpExpiryInterval = null;
let currentObsSession = null;
let currentLoginChallenge = null;

window.closeObservationOtpModal = function() {
  if (window.cognisec && typeof window.cognisec.closeObservationOtpModal === 'function') {
    window.cognisec.closeObservationOtpModal();
  } else {
    const modal = document.getElementById('modal-login-observation');
    if (modal) modal.classList.add('hidden');
  }
};

window.startObservationFlow = function(loginData) {
  currentObsSession = loginData;
  if (!loginData || !loginData.session_id) return;
  if (window.cognisec) {
    window.cognisec.startObservationFlow(loginData);
  }
};

window.showLoginOtpChallengeView = async function(sessionId) {
  if (window.cognisec) {
    await window.cognisec.executeObservationOtpTransition(sessionId);
  }
};

function startOtpExpiryTimer(ttlSeconds) {
  if (otpExpiryInterval) clearInterval(otpExpiryInterval);
  let remaining = ttlSeconds;
  const timerEl = document.getElementById('login-otp-expiry-timer');

  function updateDisplay() {
    const m = Math.floor(remaining / 60);
    const s = remaining % 60;
    if (timerEl) {
      timerEl.textContent = `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
    }
  }

  updateDisplay();
  otpExpiryInterval = setInterval(() => {
    remaining--;
    if (remaining <= 0) {
      clearInterval(otpExpiryInterval);
      otpExpiryInterval = null;
      if (timerEl) timerEl.textContent = 'EXPIRED';
      const errBanner = document.getElementById('login-otp-error-banner');
      if (errBanner) {
        errBanner.textContent = 'Verification code has expired. Please click "Resend Code" to receive a fresh code.';
        errBanner.classList.remove('hidden');
      }
    } else {
      updateDisplay();
    }
  }, 1000);
}

window.submitLoginOtpVerification = async function(e) {
  if (e) e.preventDefault();
  const codeInput = document.getElementById('login-otp-code-input');
  const otpCode = codeInput ? codeInput.value.trim() : '';
  const errBanner = document.getElementById('login-otp-error-banner');
  const successBanner = document.getElementById('login-otp-success-banner');
  const verifyBtn = document.getElementById('btn-login-otp-verify');

  if (errBanner) errBanner.classList.add('hidden');
  if (successBanner) successBanner.classList.add('hidden');

  if (!otpCode || otpCode.length !== 6 || !/^\d{6}$/.test(otpCode)) {
    if (errBanner) {
      errBanner.textContent = 'Please enter a valid 6-digit numeric verification code.';
      errBanner.classList.remove('hidden');
    }
    return;
  }

  if (verifyBtn) {
    verifyBtn.disabled = true;
    verifyBtn.innerHTML = '<span>Verifying OTP...</span>';
  }

  try {
    const sessionId = currentObsSession ? currentObsSession.session_id : window.cognisec.sessionId;
    const chalId = currentLoginChallenge ? currentLoginChallenge.challenge_id : null;
    await window.cognisec.verifyLoginOtp(otpCode, sessionId, chalId);

    if (otpExpiryInterval) clearInterval(otpExpiryInterval);

    if (successBanner) {
      successBanner.textContent = '✓ Verification successful! Full session access granted. Redirecting...';
      successBanner.classList.remove('hidden');
    }

    setTimeout(() => {
      const modal = document.getElementById('modal-login-observation');
      if (modal) modal.classList.add('hidden');

      syncAuthStateUI();
      if (typeof window.refreshNotifications === 'function') window.refreshNotifications();
      if (typeof window.refreshUserDevices === 'function') window.refreshUserDevices();

      const role = currentObsSession ? currentObsSession.role : 'USER';
      if (role === 'ADMIN') {
        openModal('dashboard');
      } else {
        openModal('liveDemo');
      }
    }, 1200);

  } catch (err) {
    if (verifyBtn) {
      verifyBtn.disabled = true;
      verifyBtn.innerHTML = '<span>Session Terminated</span>';
    }
    if (codeInput) codeInput.disabled = true;

    if (errBanner) {
      errBanner.textContent = err.message || 'Verification failed. Pending session terminated. Please sign in again.';
      errBanner.classList.remove('hidden');
    }

    window.cognisec.clearAuth();
    syncAuthStateUI();

    setTimeout(() => {
      const modal = document.getElementById('modal-login-observation');
      if (modal) modal.classList.add('hidden');
      if (verifyBtn) {
        verifyBtn.disabled = false;
        verifyBtn.innerHTML = '<span>Verify &amp; Enter Dashboard →</span>';
      }
      openModal('login');
    }, 2800);
  }
};

window.handleLoginOtpResend = async function() {
  const resendBtn = document.getElementById('btn-login-otp-resend');
  const errBanner = document.getElementById('login-otp-error-banner');
  const successBanner = document.getElementById('login-otp-success-banner');
  const sessionId = currentObsSession ? currentObsSession.session_id : window.cognisec.sessionId;

  if (errBanner) {
    errBanner.textContent = '';
    errBanner.classList.add('hidden');
  }
  if (successBanner) {
    successBanner.textContent = '';
    successBanner.classList.add('hidden');
  }

  if (resendBtn) {
    resendBtn.disabled = true;
    resendBtn.textContent = 'Dispatching...';
  }

  try {
    const challenge = await window.cognisec.resendLoginOtp(sessionId);
    currentLoginChallenge = challenge;
    startOtpExpiryTimer(challenge.expires_in_seconds || 300);

    const destEmail = document.getElementById('login-otp-dest-email');
    if (destEmail) {
      destEmail.textContent = challenge.masked_email || (window.cognisec && window.cognisec.maskEmail(window.cognisec.user?.email)) || '***@***.***';
    }

    if (successBanner) {
      successBanner.textContent = 'Fresh verification code dispatched to your registered email.';
      successBanner.classList.remove('hidden');
    }

    let cd = 15;
    const cdInterval = setInterval(() => {
      cd--;
      if (cd <= 0) {
        clearInterval(cdInterval);
        if (resendBtn) {
          resendBtn.disabled = false;
          resendBtn.textContent = 'Resend Code';
        }
      } else {
        if (resendBtn) resendBtn.textContent = `Wait (${cd}s)`;
      }
    }, 1000);

  } catch (err) {
    if (errBanner) {
      errBanner.textContent = err.message || 'Failed to resend code. Please wait before retrying.';
      errBanner.classList.remove('hidden');
    }
    if (resendBtn) {
      resendBtn.disabled = false;
      resendBtn.textContent = 'Resend Code';
    }
  }
};

window.cancelObservationAndReturnToLogin = function() {
  if (obsInterval) clearInterval(obsInterval);
  if (otpExpiryInterval) clearInterval(otpExpiryInterval);
  const modal = document.getElementById('modal-login-observation');
  if (modal) modal.classList.add('hidden');
  window.cognisec.clearAuth();
  syncAuthStateUI();
  openModal('login');
};

// Global Listeners for Authentication & Zero-Trust Step-Up
window.addEventListener('cognisec:auth_change', () => {
  syncAuthStateUI();
});
window.addEventListener('cognisec:step_up_success', () => {
  const authBadge = document.getElementById('badge-auth-state');
  if (authBadge) {
    authBadge.textContent = '✓ Authenticated';
    authBadge.className = 'px-2 py-0.5 text-[10px] bg-emerald-950 text-emerald-400 border border-emerald-800 rounded font-bold';
  }
  if (typeof addConsoleLog === 'function') {
    addConsoleLog('Step-Up Challenge Verified: Identity re-authenticated & session access restored.');
  }
  syncAuthStateUI();
});
window.addEventListener('cognisec:session_locked', () => {
  const authBadge = document.getElementById('badge-auth-state');
  if (authBadge) {
    authBadge.textContent = '🚫 LOCKED';
    authBadge.className = 'px-2 py-0.5 text-[10px] bg-red-950 text-red-400 border border-red-800 rounded font-bold';
  }
  if (typeof addConsoleLog === 'function') {
    addConsoleLog('Security Alert: Session Restricted/Locked due to step-up verification failure.');
  }
  syncAuthStateUI();
});
document.addEventListener('DOMContentLoaded', () => {
  syncAuthStateUI();
});
setTimeout(() => {
  syncAuthStateUI();
}, 250);

// 3. GENUINE BEHAVIORAL CALIBRATION & TELEMETRY STREAM
let consoleStartTime = Date.now();

window.handleConsoleTyping = function(e) {
  const targetPrompt = "The zero trust security architecture verifies every continuous behavioral signal without storing private keystrokes.";
  const val = e.target.value;
  const chars = val.length;

  // 1. Progress calculation against neutral calibration sentence
  const progText = document.getElementById('calibration-progress-text');
  if (progText) {
    progText.textContent = `${chars} / ${targetPrompt.length} chars`;
    if (chars >= targetPrompt.length) {
      progText.className = 'text-emerald-400 font-bold';
    } else {
      progText.className = 'text-amber-400 font-bold';
    }
  }

  // 2. Extract genuine browser-measured physical timing dynamics
  // (Zero storage of input text, raw characters or typed content)
  if (window.cognisec) {
    const snap = window.cognisec.computeTelemetrySnapshot();
    const flightEl = document.getElementById('measured-flight-time');
    const dwellEl = document.getElementById('measured-dwell-time');
    const wpmEl = document.getElementById('wpm-count');

    if (flightEl) {
      flightEl.textContent = snap.avgFlight > 0 ? `${Math.round(snap.avgFlight)} ms` : '-- ms';
    }
    if (dwellEl) {
      dwellEl.textContent = snap.avgDwell > 0 ? `${Math.round(snap.avgDwell)} ms` : '-- ms';
    }
    if (wpmEl) {
      wpmEl.textContent = snap.wpm > 0 ? `${snap.wpm} WPM` : '-- WPM';
    }
  }

  // 3. Dispatch genuine telemetry burst to FastAPI on 15-character cadence
  if (chars % 15 === 0 && chars > 0) {
    if (window.cognisec && window.cognisec.sessionToken) {
      window.cognisec.sendBehaviorTelemetry().then(res => {
        if (res && res.success && res.data) {
          const d = res.data;
          const riskDisplay = (d.risk_score !== undefined && d.risk_score !== null) ? d.risk_score.toFixed(3) : 'Protected';
          addConsoleLog(`Behavioral Telemetry Transmitted (FastAPI POST /api/behavior/events | Decision: ${d.decision} | Risk: ${riskDisplay})`);
          if (typeof refreshMaturityProgress === 'function') {
            refreshMaturityProgress();
          }
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

window.refreshMaturityProgress = async function() {
  if (!window.cognisec || !window.cognisec.sessionToken) return;
  try {
    const res = await window.cognisec.getBehaviorProfile();
    if (res && res.success && res.data) {
      const p = res.data;
      const sampleCount = p.sample_count || 0;
      const modelSamples = p.model_sample_count !== undefined ? p.model_sample_count : sampleCount;

      // 1. Statistical Baseline (Welford 5 samples)
      const welfordCount = document.getElementById('maturity-welford-count');
      const welfordBar = document.getElementById('maturity-welford-bar');
      if (welfordCount) {
        welfordCount.textContent = `${Math.min(5, sampleCount)} / 5 samples`;
      }
      if (welfordBar) {
        const pct = Math.min(100, Math.round((sampleCount / 5) * 100));
        welfordBar.style.width = `${pct}%`;
        welfordBar.className = pct >= 100
          ? 'bg-emerald-500 h-1.5 rounded-full transition-all duration-300'
          : 'bg-amber-500 h-1.5 rounded-full transition-all duration-300';
      }

      // 2. Isolation Forest Model Readiness (25 samples)
      const ifCount = document.getElementById('maturity-if-count');
      const ifBar = document.getElementById('maturity-if-bar');
      if (ifCount) {
        ifCount.textContent = `${Math.min(25, modelSamples)} / 25 samples`;
      }
      if (ifBar) {
        const pct = Math.min(100, Math.round((modelSamples / 25) * 100));
        ifBar.style.width = `${pct}%`;
        ifBar.className = pct >= 100
          ? 'bg-emerald-500 h-1.5 rounded-full transition-all duration-300'
          : 'bg-emerald-600/60 h-1.5 rounded-full transition-all duration-300';
      }

      // 3. Calibration Status Badge
      const badge = document.getElementById('calibration-maturity-badge');
      if (badge) {
        if (sampleCount === 0) {
          badge.textContent = 'Calibration not started';
          badge.className = 'px-2.5 py-1 rounded-lg bg-slate-900 text-slate-400 border border-slate-700 text-[11px] font-mono font-bold self-start sm:self-auto';
        } else if (sampleCount < 5) {
          badge.textContent = `Collecting observations (${sampleCount}/5)`;
          badge.className = 'px-2.5 py-1 rounded-lg bg-amber-950 text-amber-300 border border-amber-800 text-[11px] font-mono font-bold self-start sm:self-auto';
        } else if (modelSamples < 25) {
          badge.textContent = 'Statistical baseline established (IF pending)';
          badge.className = 'px-2.5 py-1 rounded-lg bg-blue-950 text-blue-300 border border-blue-800 text-[11px] font-mono font-bold self-start sm:self-auto';
        } else {
          badge.textContent = '✓ Isolation Forest trained & ready';
          badge.className = 'px-2.5 py-1 rounded-lg bg-emerald-950 text-emerald-300 border border-emerald-600 text-[11px] font-mono font-bold self-start sm:self-auto';
        }
      }
    }
  } catch (err) {
    console.warn('[COGNISEC-AI] Failed to refresh maturity progress:', err);
  }
};

window.runConsoleVerification = async function() {
  const btn = document.getElementById('btn-console-verify');
  const authBadge = document.getElementById('badge-auth-state');
  if (btn) {
    btn.textContent = 'Transmitting Behavioral Telemetry...';
    btn.disabled = true;
  }

  addConsoleLog('Initiating Behavioral Telemetry Transmission (POST /api/behavior/events)...');

  try {
    const res = window.cognisec ? await window.cognisec.sendBehaviorTelemetry() : null;
    if (res && res.success && res.data) {
      const d = res.data;
      const riskDisplay = (d.risk_score !== undefined && d.risk_score !== null) ? d.risk_score.toFixed(3) : 'Protected';
      addConsoleLog(`FastAPI Ingestion Confirmed: Decision=${d.decision} | Session=${d.session_status} | Risk=${riskDisplay}`);
      if (authBadge) {
        authBadge.textContent = d.decision === 'ALLOW' ? '✓ Telemetry Accepted' : '⚠️ ' + d.decision;
        authBadge.className = d.decision === 'ALLOW'
          ? 'px-2 py-0.5 text-[10px] bg-emerald-950 text-emerald-400 border border-emerald-800 rounded font-bold'
          : 'px-2 py-0.5 text-[10px] bg-amber-950 text-amber-400 border border-amber-800 rounded font-bold';
      }
      if (btn) {
        btn.textContent = 'Telemetry Ingested & Verified ✓';
        setTimeout(() => {
          if (btn) {
            btn.textContent = 'Send Behavioral Calibration Sample →';
            btn.disabled = false;
          }
        }, 2000);
      }
      if (typeof refreshMaturityProgress === 'function') {
        await refreshMaturityProgress();
      }
    } else {
      const errMsg = (res && res.error) || 'Ingestion failed';
      addConsoleLog(`Telemetry Dispatch Error: ${errMsg}`);
      if (authBadge) {
        authBadge.textContent = 'Telemetry Failed';
        authBadge.className = 'px-2 py-0.5 text-[10px] bg-red-950 text-red-400 border border-red-800 rounded font-bold';
      }
      if (btn) {
        btn.textContent = 'Submission Failed - Retry';
        btn.disabled = false;
      }
    }
  } catch (err) {
    addConsoleLog(`Verification Network Error: ${err.message}`);
    if (btn) {
      btn.textContent = 'Network Error - Retry';
      btn.disabled = false;
    }
  }
};

// 4. APPLICATION PORTAL FLOW (SHOPPING / COLLEGE / HEALTHCARE)
let activePortalType = 'shopping';

function openPortalModal(type) {
  // Prevent bypass of required security enrollment for protected actions
  if (window.cognisec && window.cognisec.isAuthenticated() && !window.cognisec.isAdmin()) {
    if (typeof window.cognisec.getAdaptiveStatus === 'function') {
      window.cognisec.getAdaptiveStatus().then(status => {
        if (status && (!status.has_gesture_pattern || !status.has_cognitive_image_sequence || !status.has_private_response)) {
          alert('Zero-Trust Security Policy: Protected application actions require enrolled adaptive factors (Gesture Pattern, Image Sequence, and Private Response). Please complete enrollment in Security Settings.');
          const m = document.getElementById('modal-portal');
          if (m) m.classList.add('hidden');
          openModal('liveDemo');
          if (typeof scrollToAdaptiveSection === 'function') {
            scrollToAdaptiveSection();
          }
        }
      }).catch(() => {});
    }
  }

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

// 8. REAL SECURITY NOTIFICATION CENTER & DEVICE INVENTORY HANDLERS
window.toggleNotificationCenter = function() {
  const container = document.getElementById('notif-popup-container');
  if (container) {
    const isHidden = container.classList.contains('hidden');
    if (isHidden) {
      container.classList.remove('hidden');
      window.refreshNotifications();
    } else {
      container.classList.add('hidden');
    }
  }
};

window.closeNotificationPopup = function() {
  const container = document.getElementById('notif-popup-container');
  if (container) {
    container.classList.add('hidden');
  }
};

window.refreshNotifications = async function() {
  if (!window.cognisec || !window.cognisec.isAuthenticated()) {
    const badge = document.getElementById('notif-badge');
    if (badge) {
      badge.textContent = '0';
      badge.classList.add('hidden');
    }
    return;
  }

  const listEl = document.getElementById('notif-list-container');
  const badge = document.getElementById('notif-badge');
  const countBadge = document.getElementById('notif-count-badge');

  try {
    const data = await window.cognisec.getNotifications();
    const notifications = (data && data.notifications) ? data.notifications : [];
    const unreadCount = (data && typeof data.unread_count === 'number') ? data.unread_count : 0;

    // Update notification bell badge
    if (badge) {
      badge.textContent = String(unreadCount);
      if (unreadCount > 0) {
        badge.classList.remove('hidden');
        badge.classList.add('bg-red-600', 'animate-pulse');
      } else {
        badge.classList.add('hidden');
        badge.classList.remove('animate-pulse');
      }
    }

    if (countBadge) {
      countBadge.textContent = `${unreadCount} unread`;
    }

    if (!listEl) return;

    if (notifications.length === 0) {
      listEl.innerHTML = `
        <div class="p-4 rounded-xl bg-black/60 border border-red-950 text-center text-xs text-slate-400 font-mono">
          ✓ No security alerts recorded.<br><span class="text-[10px] text-slate-500">All registered devices are recognized.</span>
        </div>
      `;
      return;
    }

    listEl.innerHTML = notifications.map(n => {
      let statusBadge = '';
      if (n.status === 'PENDING_CONFIRMATION') {
        statusBadge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-300 border border-amber-800 animate-pulse">PENDING CONFIRMATION</span>';
      } else if (n.status === 'CONFIRMED_TRUSTED') {
        statusBadge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">TRUSTED</span>';
      } else if (n.status === 'CONFIRMED_DENIED') {
        statusBadge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-red-950 text-red-300 border border-red-800">DENIED &amp; REVOKED</span>';
      } else if (n.status === 'DEVICE_REVOKED') {
        statusBadge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-red-950 text-red-400 border border-red-800">REVOKED</span>';
      } else {
        statusBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-900 text-slate-400 border border-slate-700">${n.status}</span>`;
      }

      let emailStatusHtml = '';
      if (n.email_delivery_status === 'SENT') {
        emailStatusHtml = '<span class="text-[10px] text-emerald-400 font-mono">📧 Owner Alert: Email Sent</span>';
      } else if (n.email_delivery_status === 'FAILED') {
        emailStatusHtml = `<span class="text-[10px] text-red-400 font-mono" title="${n.email_error || ''}">📧 Email Failed (Recorded in SOC)</span>`;
      } else if (n.email_delivery_status === 'SKIPPED_UNCONFIGURED') {
        emailStatusHtml = '<span class="text-[10px] text-slate-500 font-mono">📧 SMTP Server Unconfigured</span>';
      } else {
        emailStatusHtml = '<span class="text-[10px] text-amber-400 font-mono">📧 Email In Queue</span>';
      }

      const timeStr = new Date(n.created_at).toLocaleString('en-US', { timeZone: 'UTC', hour12: false }) + ' UTC';

      const actionButtons = (n.status === 'PENDING_CONFIRMATION') ? `
        <div class="pt-2">
          <div class="text-[11px] text-amber-300 font-bold pb-1.5 text-center">Was this login authorized by you?</div>
          <div class="grid grid-cols-2 gap-2">
            <button
              onclick="handleNotificationResponse('${n.notification_id}', 'yes')"
              class="py-2 px-3 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-[11px] uppercase tracking-wider transition-all cursor-pointer flex items-center justify-center gap-1 shadow-[0_0_12px_rgba(52,211,153,0.3)]"
            >
              ✓ Yes, This Was Me
            </button>
            <button
              onclick="handleNotificationResponse('${n.notification_id}', 'no')"
              class="py-2 px-3 rounded-lg bg-red-600 hover:bg-red-500 text-white font-bold text-[11px] uppercase tracking-wider transition-all cursor-pointer flex items-center justify-center gap-1 shadow-[0_0_15px_rgba(239,68,68,0.5)]"
            >
              ⛔ No, Secure Account
            </button>
          </div>
        </div>
      ` : '';

      const markReadBtn = !n.is_read ? `
        <button onclick="handleMarkNotificationRead('${n.notification_id}')" class="text-[10px] text-slate-500 hover:text-slate-300 underline cursor-pointer">
          Mark as read
        </button>
      ` : '<span class="text-[10px] text-slate-600">Read</span>';

      return `
        <div class="p-3.5 rounded-xl bg-black/80 border ${n.is_read ? 'border-red-950/60' : 'border-red-800/80 shadow-[0_0_15px_rgba(220,38,38,0.2)]'} space-y-2">
          <div class="flex items-center justify-between gap-2">
            <span class="text-xs font-bold text-white">${n.title}</span>
            ${statusBadge}
          </div>
          <p class="text-xs text-slate-300 leading-relaxed font-sans">${n.message}</p>
          <div class="text-[10px] font-mono text-slate-400 space-y-0.5">
            <div><span class="text-slate-500">Location:</span> ${n.location_summary || 'Unknown Network'}</div>
            <div><span class="text-slate-500">Timestamp:</span> ${timeStr}</div>
          </div>
          <div class="flex items-center justify-between pt-1 border-t border-red-950/60">
            ${emailStatusHtml}
            ${markReadBtn}
          </div>
          ${actionButtons}
        </div>
      `;
    }).join('');

  } catch (err) {
    console.warn('[COGNISEC-AI] Failed to fetch notifications:', err.message);
  }
};

window.handleMarkNotificationRead = async function(notifId) {
  if (!window.cognisec) return;
  await window.cognisec.markNotificationRead(notifId);
  window.refreshNotifications();
};

window.markAllNotificationsAsRead = async function() {
  if (!window.cognisec) return;
  await window.cognisec.markAllNotificationsRead();
  window.refreshNotifications();
};

window.handleNotificationResponse = async function(notifId, answer) {
  if (window._isHandlingNotif) return;
  window._isHandlingNotif = true;
  const resultBanner = document.getElementById('notif-result-banner');

  if (resultBanner) {
    resultBanner.classList.remove('hidden');
    resultBanner.className = 'p-3 rounded-xl bg-black/80 border border-slate-700 text-slate-300 text-xs font-bold text-center';
    resultBanner.innerHTML = 'Communicating with zero-trust security authority...';
  }

  try {
    const res = await window.cognisec.respondToNotification(notifId, answer);
    if (res.status === 'success') {
      if (resultBanner) {
        if (answer === 'yes') {
          resultBanner.className = 'p-3 rounded-xl bg-emerald-950/80 border border-emerald-500 text-emerald-300 text-xs font-bold text-center animate-fade-in shadow-[0_0_15px_rgba(52,211,153,0.3)]';
          resultBanner.innerHTML = '🟢 Device Confirmed &amp; Trusted!<br><span class="text-[10px] text-slate-300">Updated in verified hardware inventory.</span>';
        } else {
          resultBanner.className = 'p-3 rounded-xl bg-red-950/90 border-2 border-red-500 text-red-300 text-xs font-bold text-center animate-fade-in shadow-[0_0_20px_#ef4444]';
          resultBanner.innerHTML = '⛔ UNAUTHORIZED ACCESS REJECTED!<br><span class="text-[10px] text-white">Device revoked &amp; all associated sessions terminated.</span>';
        }
      }
    } else {
      if (resultBanner) {
        resultBanner.className = 'p-3 rounded-xl bg-red-950/80 border border-red-800 text-red-300 text-xs font-bold text-center';
        resultBanner.textContent = res.message || 'Operation could not be completed.';
      }
    }

    setTimeout(() => {
      if (resultBanner) resultBanner.classList.add('hidden');
    }, 4000);

    window.refreshNotifications();
    window.refreshUserDevices();

  } catch (err) {
    if (resultBanner) {
      resultBanner.className = 'p-3 rounded-xl bg-red-950/80 border border-red-800 text-red-300 text-xs font-bold text-center';
      resultBanner.textContent = `Error: ${err.message}`;
    }
  } finally {
    window._isHandlingNotif = false;
  }
};

window.refreshUserDevices = async function() {
  const container = document.getElementById('user-devices-list');
  if (!container || !window.cognisec || !window.cognisec.isAuthenticated()) return;

  try {
    const devices = await window.cognisec.getDevices();
    if (!Array.isArray(devices) || devices.length === 0) {
      container.innerHTML = `
        <div class="p-4 rounded-xl bg-black/60 border border-red-950 text-center text-xs text-slate-400">
          No hardware devices registered yet.
        </div>
      `;
      return;
    }

    container.innerHTML = devices.map(d => {
      let trustBadge = '';
      if (d.trust_state === 'TRUSTED') {
        trustBadge = '<span class="px-2.5 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-800 flex items-center gap-1"><span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>TRUSTED</span>';
      } else if (d.trust_state === 'PENDING_CONFIRMATION') {
        trustBadge = '<span class="px-2.5 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-300 border border-amber-800 flex items-center gap-1 animate-pulse"><span class="w-1.5 h-1.5 rounded-full bg-amber-400"></span>PENDING CONFIRMATION</span>';
      } else if (d.trust_state === 'REVOKED') {
        trustBadge = '<span class="px-2.5 py-0.5 rounded text-[10px] font-bold bg-red-950 text-red-400 border border-red-800 flex items-center gap-1"><span class="w-1.5 h-1.5 rounded-full bg-red-500"></span>REVOKED</span>';
      } else {
        trustBadge = `<span class="px-2.5 py-0.5 rounded text-[10px] font-bold bg-slate-900 text-slate-400 border border-slate-700">${d.trust_state}</span>`;
      }

      let locationText = 'Location: ';
      if (d.latitude != null && d.longitude != null) {
        locationText += `GPS ${d.latitude.toFixed(4)}, ${d.longitude.toFixed(4)} (±${Math.round(d.location_accuracy || 0)}m, ${d.location_source})`;
      } else if (d.city || d.country) {
        locationText += `${d.city || ''}, ${d.region || ''}, ${d.country || ''} (${d.location_source || 'Approximate IP'})`;
      } else {
        locationText += `IP ${d.last_ip || '127.0.0.1'} (${d.location_source || 'Network'})`;
      }

      const firstSeen = new Date(d.first_seen).toLocaleString('en-US', { timeZone: 'UTC', hour12: false }) + ' UTC';
      const lastSeen = new Date(d.last_seen).toLocaleString('en-US', { timeZone: 'UTC', hour12: false }) + ' UTC';

      const revokeBtn = (d.trust_state !== 'REVOKED') ? `
        <button
          onclick="handleRevokeDevice('${d.device_id}')"
          class="px-3 py-1.5 rounded-lg bg-red-950/80 hover:bg-red-900 border border-red-800 text-red-300 hover:text-white text-[11px] font-bold transition-all cursor-pointer"
        >
          Revoke Access
        </button>
      ` : '<span class="text-[10px] text-red-400 font-bold uppercase">[TERMINATED]</span>';

      return `
        <div class="p-4 rounded-xl bg-black/70 border border-red-950 flex flex-col md:flex-row md:items-center justify-between gap-3 font-mono text-xs">
          <div class="space-y-1">
            <div class="flex items-center gap-2">
              <span class="font-bold text-white text-sm">${d.nickname || `${d.browser_name || 'Browser'} on ${d.os_name || 'OS'}`}</span>
              <button onclick="handleUpdateNickname('${d.device_id}')" class="text-[10px] text-slate-500 hover:text-slate-300 underline cursor-pointer" title="Rename device">✎ Edit Name</button>
              ${trustBadge}
            </div>
            <div class="text-[11px] text-slate-400 font-sans">
              ${d.browser_name || 'Browser'} ${d.browser_version || ''} &bull; ${d.os_name || 'OS'} ${d.os_version || ''} (${d.device_type || 'Desktop'})
            </div>
            <div class="text-[10px] text-slate-400">
              ${locationText}
            </div>
            <div class="text-[10px] text-slate-500 flex items-center gap-3">
              <span>First: ${firstSeen}</span>
              <span>&bull;</span>
              <span>Last: ${lastSeen}</span>
            </div>
          </div>
          <div class="shrink-0 pt-2 md:pt-0">
            ${revokeBtn}
          </div>
        </div>
      `;
    }).join('');

  } catch (err) {
    console.warn('[COGNISEC-AI] Failed to fetch devices:', err.message);
  }
};

window.handleRevokeDevice = async function(deviceId) {
  if (!confirm('Are you sure you want to revoke trust for this device? All active sessions associated with it will be immediately terminated.')) {
    return;
  }
  const res = await window.cognisec.revokeDevice(deviceId);
  if (res.status === 'success') {
    alert(res.message);
  } else {
    alert(res.message || 'Failed to revoke device.');
  }
  window.refreshUserDevices();
  window.refreshNotifications();
};

window.handleUpdateNickname = async function(deviceId) {
  const newName = prompt('Enter a recognizable nickname for this device (e.g., "My Work Laptop"):');
  if (newName && newName.trim()) {
    await window.cognisec.updateDeviceNickname(deviceId, newName.trim());
    window.refreshUserDevices();
  }
};

// DASHBOARD SECTION REDIRECT & ADMIN ACCESS CONTROL
window.isAdminUser = true; // Boomika Ram (Security Administrator - USR-9842-X9)

window.scrollToSection = function(id) {
  let section = document.getElementById(id);
  if (!section && (id === 'plain-black-applications-section' || id === 'applications')) {
    section = document.getElementById('interactive-applications') || document.getElementById('applications');
  }
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

// ================= ADAPTIVE AUTHENTICATION FACTOR ENROLLMENT =================
let activeEnrollTab = 'gesture';
let gestureEnrollState = {
  step: 1, // 1: Initial, 2: Confirmation
  initialPattern: [],
  confirmPattern: []
};
window.gestureEnrollState = gestureEnrollState;

let imageEnrollState = {
  step: 1, // 1: Initial, 2: Confirmation
  initialSeq: [],
  confirmSeq: [],
  catalogue: []
};

window.refreshAdaptiveMfaStatus = async function() {
  if (!window.cognisec || !window.cognisec.isAuthenticated()) return;
  try {
    const status = await window.cognisec.getAdaptiveStatus();
    if (!status) return;

    const gestureBadge = document.getElementById('mfa-badge-gesture');
    const imageBadge = document.getElementById('mfa-badge-image');
    const privateBadge = document.getElementById('mfa-badge-private');

    const hasGesture = !!status.has_gesture_pattern;
    const hasImage = !!status.has_cognitive_image_sequence;
    const hasPrivate = !!status.has_private_response;

    if (gestureBadge) {
      if (hasGesture) {
        gestureBadge.textContent = 'Enrolled ✓';
        gestureBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800';
      } else {
        gestureBadge.textContent = 'Not Enrolled';
        gestureBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950/80 text-amber-300 border border-amber-800/80';
      }
    }

    const resetBtn = document.getElementById('btn-reset-neuraltrace');
    if (resetBtn) {
      if (hasGesture) {
        resetBtn.classList.remove('hidden');
        resetBtn.disabled = false;
      } else {
        resetBtn.classList.add('hidden');
      }
    }

    if (imageBadge) {
      if (hasImage) {
        imageBadge.textContent = 'Enrolled ✓';
        imageBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800';
      } else {
        imageBadge.textContent = 'Not Enrolled';
        imageBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950/80 text-amber-300 border border-amber-800/80';
      }
    }

    if (privateBadge) {
      if (hasPrivate) {
        privateBadge.textContent = 'Enrolled ✓';
        privateBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800';
      } else {
        privateBadge.textContent = 'Not Enrolled';
        privateBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950/80 text-amber-300 border border-amber-800/80';
      }
    }

    // Update Onboarding Advisory Banner for Incomplete Enrollment
    const banner = document.getElementById('user-dash-enrollment-banner');
    const bannerTitle = document.getElementById('enrollment-banner-title');
    const bannerDesc = document.getElementById('enrollment-banner-desc');
    if (banner) {
      if (!hasGesture || !hasImage || !hasPrivate) {
        banner.classList.remove('hidden');
        const missing = [];
        if (!hasGesture) missing.push('Gesture Pattern');
        if (!hasImage) missing.push('Image Sequence');
        if (!hasPrivate) missing.push('Private Response');
        if (bannerTitle) bannerTitle.textContent = `Adaptive Security Factor Enrollment Incomplete (${3 - missing.length}/3 Enrolled)`;
        if (bannerDesc) bannerDesc.textContent = `Please configure your ${missing.join(', ')} below to enable full Zero-Trust protection and unlock portal actions.`;
      } else {
        banner.classList.remove('hidden');
        banner.className = 'p-3 rounded-xl bg-emerald-950/30 border border-emerald-800/60 text-xs font-mono flex items-center justify-between text-emerald-300';
        banner.innerHTML = '<div class="flex items-center gap-2"><span>🛡️</span><strong>All Adaptive Factors Enrolled &amp; Protected.</strong> Zero-Trust continuous baseline monitoring active.</div>';
      }
    }
  } catch (err) {
    console.warn('[COGNISEC-AI] Failed to refresh adaptive status:', err);
  }
};

window.scrollToAdaptiveSection = function() {
  const sec = document.getElementById('user-mfa-security-section');
  if (sec) {
    sec.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
};

window.switchEnrollTab = async function(tab) {
  activeEnrollTab = tab;
  ['gesture', 'image', 'private'].forEach(t => {
    const btn = document.getElementById(`enroll-tab-btn-${t}`);
    const pane = document.getElementById(`enroll-pane-${t}`);
    if (btn) {
      if (t === tab) {
        btn.className = 'px-3.5 py-1.5 rounded-lg text-xs font-bold bg-red-600 text-white cursor-pointer transition-all';
      } else {
        btn.className = 'px-3.5 py-1.5 rounded-lg text-xs font-bold bg-slate-900 text-slate-400 hover:text-white cursor-pointer transition-all';
      }
    }
    if (pane) {
      if (t === tab) pane.classList.remove('hidden');
      else pane.classList.add('hidden');
    }
  });

  if (tab === 'gesture') {
    initMfaGestureGrid();
  } else if (tab === 'image' && (!imageEnrollState.catalogue || imageEnrollState.catalogue.length === 0)) {
    await renderEnrollImageGrid();
  }
};

// --- GESTURE PATTERN ENROLLMENT HANDLERS ---
function initMfaGestureGrid() {
  const container = document.getElementById('enroll-gesture-grid');
  if (!container) return;

  if (!gestureEnrollState.gridInstance) {
    gestureEnrollState.gridInstance = new NeuralTraceAuth(container, {
      theme: 'theme-cyber',
      minNodes: 4,
      onPatternChange: (pattern) => {
        const preview = gestureEnrollState.step === 1
          ? document.getElementById('enroll-gesture-preview')
          : document.getElementById('enroll-gesture-confirm-preview');
        if (preview) {
          preview.textContent = pattern.length > 0 ? `${pattern.length} nodes traversed` : '(Trace route along connected edges)';
        }
      },
      onPatternComplete: (pattern) => {
        const preview = gestureEnrollState.step === 1
          ? document.getElementById('enroll-gesture-preview')
          : document.getElementById('enroll-gesture-confirm-preview');
        if (preview) preview.textContent = `Route recorded (${pattern.length} nodes)`;
      },
      onPatternTooShort: (pattern) => {
        const feedback = document.getElementById('enroll-gesture-feedback');
        if (feedback) {
          feedback.className = 'p-3 rounded-xl bg-amber-950/70 border border-amber-800 text-amber-300 text-xs font-mono block';
          feedback.textContent = 'Neural route must contain at least 4 connected nodes.';
        }
      },
      onReset: () => {
        const preview = gestureEnrollState.step === 1
          ? document.getElementById('enroll-gesture-preview')
          : document.getElementById('enroll-gesture-confirm-preview');
        if (preview) preview.textContent = '(Trace route along connected edges)';
      }
    });
  } else {
    gestureEnrollState.gridInstance.reset();
  }
}

window.handleGestureEnrollNode = function(nodeId) {
  if (gestureEnrollState.gridInstance) {
    gestureEnrollState.gridInstance.addNode(nodeId);
    return;
  }
  const currentList = gestureEnrollState.step === 1 ? gestureEnrollState.initialPattern : gestureEnrollState.confirmPattern;
  if (currentList.includes(nodeId)) return;
  currentList.push(nodeId);
};

window.resetGestureEnrollment = function() {
  gestureEnrollState.step = 1;
  gestureEnrollState.initialPattern = [];
  gestureEnrollState.confirmPattern = [];

  if (gestureEnrollState.gridInstance) {
    gestureEnrollState.gridInstance.reset();
  } else {
    initMfaGestureGrid();
  }

  const initialLabel = document.getElementById('enroll-gesture-initial-label');
  if (initialLabel) initialLabel.textContent = 'Route Status:';
  const preview = document.getElementById('enroll-gesture-preview');
  if (preview) preview.textContent = '(Trace route along connected edges)';
  const confirmBox = document.getElementById('enroll-gesture-confirm-box');
  if (confirmBox) confirmBox.classList.add('hidden');

  const tag = document.getElementById('enroll-gesture-step-tag');
  if (tag) {
    tag.textContent = 'STAGE: INITIAL ROUTE';
    tag.className = 'px-2 py-0.5 rounded text-[10px] bg-red-950 text-red-300 border border-red-800 font-bold self-start sm:self-auto';
  }

  const instr = document.getElementById('enroll-gesture-instruction');
  if (instr) instr.textContent = 'Step 1: Trace a private neural route across at least 4 connected network nodes.';

  const actionBtn = document.getElementById('enroll-gesture-action-btn');
  if (actionBtn) {
    actionBtn.disabled = false;
    actionBtn.textContent = 'Proceed to Route Confirmation →';
    actionBtn.className = 'flex-[2] py-2.5 px-4 rounded-xl bg-gradient-to-r from-red-600 to-red-700 hover:from-red-500 hover:to-red-600 text-white text-xs font-bold shadow-[0_0_20px_rgba(220,38,38,0.4)] transition-all cursor-pointer';
  }

  const feedback = document.getElementById('enroll-gesture-feedback');
  if (feedback) feedback.className = 'hidden';
};

window.advanceOrSubmitGestureEnrollment = async function() {
  const feedback = document.getElementById('enroll-gesture-feedback');
  if (feedback) feedback.className = 'hidden';

  if (!gestureEnrollState.gridInstance) {
    initMfaGestureGrid();
  }

  if (gestureEnrollState.step === 1) {
    const pattern = gestureEnrollState.gridInstance ? gestureEnrollState.gridInstance.getPattern() : [];
    if (!pattern || pattern.length < 4) {
      if (feedback) {
        feedback.className = 'p-3 rounded-xl bg-amber-950/70 border border-amber-800 text-amber-300 text-xs font-mono block';
        feedback.textContent = 'Neural route must contain at least 4 connected nodes.';
      }
      if (gestureEnrollState.gridInstance) gestureEnrollState.gridInstance.triggerShake();
      return;
    }

    gestureEnrollState.initialPattern = [...pattern];
    gestureEnrollState.step = 2;
    gestureEnrollState.confirmPattern = [];
    if (gestureEnrollState.gridInstance) gestureEnrollState.gridInstance.reset();

    const initialLabel = document.getElementById('enroll-gesture-initial-label');
    if (initialLabel) initialLabel.textContent = 'Target Route:';

    const preview = document.getElementById('enroll-gesture-preview');
    if (preview) preview.textContent = `Recorded (${gestureEnrollState.initialPattern.length} nodes)`;

    const confirmBox = document.getElementById('enroll-gesture-confirm-box');
    if (confirmBox) confirmBox.classList.remove('hidden');
    const confirmPreview = document.getElementById('enroll-gesture-confirm-preview');
    if (confirmPreview) confirmPreview.textContent = '(Retrace same route to confirm)';

    const tag = document.getElementById('enroll-gesture-step-tag');
    if (tag) {
      tag.textContent = 'STAGE: RETRACE TO CONFIRM';
      tag.className = 'px-2 py-0.5 rounded text-[10px] bg-amber-950 text-amber-300 border border-amber-800 font-bold self-start sm:self-auto';
    }

    const instr = document.getElementById('enroll-gesture-instruction');
    if (instr) instr.textContent = 'Step 2: Retrace the exact same route across network nodes to confirm enrollment.';

    const actionBtn = document.getElementById('enroll-gesture-action-btn');
    if (actionBtn) {
      actionBtn.textContent = 'Submit & Enroll NeuralTrace Route ✓';
      actionBtn.className = 'flex-[2] py-2.5 px-4 rounded-xl bg-gradient-to-r from-emerald-600 to-emerald-700 hover:from-emerald-500 hover:to-emerald-600 text-white text-xs font-bold shadow-[0_0_20px_rgba(16,185,129,0.4)] transition-all cursor-pointer';
    }
  } else {
    const confirmPattern = gestureEnrollState.gridInstance ? gestureEnrollState.gridInstance.getPattern() : [];
    if (!confirmPattern || confirmPattern.length < 4) {
      if (feedback) {
        feedback.className = 'p-3 rounded-xl bg-amber-950/70 border border-amber-800 text-amber-300 text-xs font-mono block';
        feedback.textContent = 'Confirmation route must have at least 4 nodes.';
      }
      if (gestureEnrollState.gridInstance) gestureEnrollState.gridInstance.triggerShake();
      return;
    }

    const match = JSON.stringify(gestureEnrollState.initialPattern) === JSON.stringify(confirmPattern);
    if (!match) {
      if (feedback) {
        feedback.className = 'p-3 rounded-xl bg-red-950/70 border border-red-800 text-red-300 text-xs font-mono block';
        feedback.textContent = 'Confirmation route does not match initial route. Try again or reset.';
      }
      gestureEnrollState.confirmPattern = [];
      if (gestureEnrollState.gridInstance) {
        gestureEnrollState.gridInstance.triggerShake();
        gestureEnrollState.gridInstance.reset();
      }
      const confirmPreview = document.getElementById('enroll-gesture-confirm-preview');
      if (confirmPreview) confirmPreview.textContent = '(Retrace same route to confirm)';
      return;
    }

    gestureEnrollState.confirmPattern = [...confirmPattern];

    const actionBtn = document.getElementById('enroll-gesture-action-btn');
    if (actionBtn) {
      actionBtn.disabled = true;
      actionBtn.textContent = 'Enrolling NeuralTrace Secret...';
    }

    try {
      const res = await window.cognisec.enrollGesturePattern(gestureEnrollState.initialPattern, gestureEnrollState.confirmPattern);
      if (res.success) {
        if (feedback) {
          feedback.className = 'p-3 rounded-xl bg-emerald-950/70 border border-emerald-600 text-emerald-300 text-xs font-mono block';
          feedback.textContent = '✓ NeuralTrace enrolled successfully and verifier persisted!';
        }
        if (gestureEnrollState.gridInstance) gestureEnrollState.gridInstance.triggerSuccess();
        await window.refreshAdaptiveMfaStatus();
        setTimeout(() => window.resetGestureEnrollment(), 1800);
      } else {
        if (feedback) {
          feedback.className = 'p-3 rounded-xl bg-red-950/70 border border-red-800 text-red-300 text-xs font-mono block';
          feedback.textContent = `Enrollment failed: ${res.error}`;
        }
      }
    } catch (e) {
      if (feedback) {
        feedback.className = 'p-3 rounded-xl bg-red-950/70 border border-red-800 text-red-300 text-xs font-mono block';
        feedback.textContent = `Error: ${e.message}`;
      }
    } finally {
      if (actionBtn) actionBtn.disabled = false;
    }
  }
};

// --- COGNITIVE IMAGE SEQUENCE ENROLLMENT HANDLERS ---
async function renderEnrollImageGrid() {
  const grid = document.getElementById('enroll-image-grid');
  if (!grid) return;

  let catalogue = await window.cognisec.getAdaptiveCatalogue();
  if (!catalogue || catalogue.length === 0) {
    catalogue = [
      { id: 'img_shield', label: 'Shield', icon: '🛡️', category: 'security' },
      { id: 'img_key', label: 'Key', icon: '🔑', category: 'access' },
      { id: 'img_lock', label: 'Lock', icon: '🔒', category: 'security' },
      { id: 'img_radar', label: 'Radar', icon: '📡', category: 'network' },
      { id: 'img_vault', label: 'Vault', icon: '🏛️', category: 'storage' },
      { id: 'img_biometric', label: 'Biometric', icon: '🧬', category: 'identity' },
      { id: 'img_firewall', label: 'Firewall', icon: '🧱', category: 'defense' },
      { id: 'img_token', label: 'Token', icon: '🪙', category: 'credential' },
      { id: 'img_chip', label: 'Enclave', icon: '💾', category: 'hardware' }
    ];
  }
  imageEnrollState.catalogue = catalogue;

  grid.innerHTML = catalogue.map(item => `
    <div class="symbol-card" data-symbol="${item.id}" onclick="handleImageEnrollSymbol('${item.id}')">
      <span class="text-2xl">${item.icon}</span>
      <span class="text-[10px] text-slate-300 font-bold">${item.label}</span>
    </div>
  `).join('');
}

window.handleImageEnrollSymbol = function(symbolId) {
  const maxLen = imageEnrollState.step === 1 ? 5 : (imageEnrollState.initialSeq.length || 5);
  const currentList = imageEnrollState.step === 1 ? imageEnrollState.initialSeq : imageEnrollState.confirmSeq;
  if (currentList.length >= maxLen) return;
  currentList.push(symbolId);
  updateEnrollImageVisuals();
};

function updateEnrollImageVisuals() {
  const initialStrip = document.getElementById('enroll-image-preview-strip');
  const confirmStrip = document.getElementById('enroll-image-confirm-strip');
  const confirmBox = document.getElementById('enroll-image-confirm-box');
  const initialLabel = document.getElementById('enroll-image-initial-label');
  const cards = document.querySelectorAll('#enroll-image-grid .symbol-card');

  // 1. Initial Strip always displays the initial selection
  if (initialStrip) {
    if (imageEnrollState.initialSeq.length === 0) {
      initialStrip.innerHTML = '<span class="text-slate-500 text-[11px]">(Click symbols below)</span>';
    } else {
      initialStrip.innerHTML = imageEnrollState.initialSeq.map((id, i) => {
        return `<span class="px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-700 text-[10px] font-bold">${i+1}. ${id.replace('img_', '')}</span>`;
      }).join('');
    }
  }

  // 2. Stage 2 Confirmation display: Keep Initial Sequence visible in Chosen/Target strip, render confirmation in confirm strip
  if (imageEnrollState.step === 2) {
    if (initialLabel) initialLabel.textContent = 'Target Order:';
    if (confirmBox) confirmBox.classList.remove('hidden');
    if (confirmStrip) {
      if (imageEnrollState.confirmSeq.length === 0) {
        confirmStrip.innerHTML = '<span class="text-amber-500/70 text-[11px]">(Click symbols in exact order)</span>';
      } else {
        confirmStrip.innerHTML = imageEnrollState.confirmSeq.map((id, i) => {
          return `<span class="px-2 py-0.5 rounded bg-amber-900/80 text-white border border-amber-500 text-[10px] font-bold">${i+1}. ${id.replace('img_', '')}</span>`;
        }).join('');
      }
    }
  } else {
    if (initialLabel) initialLabel.textContent = 'Chosen Order:';
    if (confirmBox) confirmBox.classList.add('hidden');
  }

  // 3. Grid badges: in step 1 show initialSeq indices, in step 2 show confirmSeq indices
  const activeList = imageEnrollState.step === 1 ? imageEnrollState.initialSeq : imageEnrollState.confirmSeq;
  cards.forEach(card => {
    const sym = card.getAttribute('data-symbol');
    const idx = activeList.indexOf(sym);
    const existingBadge = card.querySelector('.symbol-order-badge');
    if (idx !== -1) {
      card.classList.add('selected');
      if (!existingBadge) {
        const badge = document.createElement('span');
        badge.className = 'symbol-order-badge';
        badge.textContent = idx + 1;
        card.appendChild(badge);
      } else {
        existingBadge.textContent = idx + 1;
      }
    } else {
      card.classList.remove('selected');
      if (existingBadge) existingBadge.remove();
    }
  });
}

window.resetImageEnrollment = function() {
  imageEnrollState.step = 1;
  imageEnrollState.initialSeq = [];
  imageEnrollState.confirmSeq = [];
  updateEnrollImageVisuals();

  const tag = document.getElementById('enroll-image-step-tag');
  if (tag) {
    tag.textContent = 'STAGE: INITIAL SEQUENCE';
    tag.className = 'px-2 py-0.5 rounded text-[10px] bg-amber-950 text-amber-300 border border-amber-800 font-bold self-start sm:self-auto';
  }

  const instr = document.getElementById('enroll-image-instruction');
  if (instr) instr.textContent = 'Step 1: Select 3 to 5 cognitive symbols from the catalogue in your chosen sequence.';

  const actionBtn = document.getElementById('enroll-image-action-btn');
  if (actionBtn) {
    actionBtn.textContent = 'Proceed to Confirmation →';
    actionBtn.className = 'flex-[2] py-2.5 px-4 rounded-xl bg-gradient-to-r from-amber-600 to-red-600 hover:from-amber-500 hover:to-red-500 text-white text-xs font-bold shadow-[0_0_20px_rgba(245,158,11,0.4)] transition-all cursor-pointer';
  }

  const feedback = document.getElementById('enroll-image-feedback');
  if (feedback) feedback.className = 'hidden';
};

window.advanceOrSubmitImageEnrollment = async function() {
  const feedback = document.getElementById('enroll-image-feedback');
  if (feedback) feedback.className = 'hidden';

  if (imageEnrollState.step === 1) {
    if (imageEnrollState.initialSeq.length < 3 || imageEnrollState.initialSeq.length > 5) {
      if (feedback) {
        feedback.className = 'p-3 rounded-xl bg-amber-950/70 border border-amber-800 text-amber-300 text-xs font-mono block';
        feedback.textContent = 'Sequence must contain between 3 and 5 symbols.';
      }
      return;
    }

    imageEnrollState.step = 2;
    imageEnrollState.confirmSeq = [];
    updateEnrollImageVisuals();

    const tag = document.getElementById('enroll-image-step-tag');
    if (tag) {
      tag.textContent = 'STAGE: CONFIRMATION';
      tag.className = 'px-2 py-0.5 rounded text-[10px] bg-amber-950 text-amber-300 border border-amber-800 font-bold self-start sm:self-auto';
    }

    const instr = document.getElementById('enroll-image-instruction');
    if (instr) instr.textContent = 'Step 2: Repeat your chosen sequence in the exact order to confirm.';

    const actionBtn = document.getElementById('enroll-image-action-btn');
    if (actionBtn) {
      actionBtn.textContent = 'Submit & Enroll Image Sequence ✓';
      actionBtn.className = 'flex-[2] py-2.5 px-4 rounded-xl bg-gradient-to-r from-emerald-600 to-emerald-700 hover:from-emerald-500 hover:to-emerald-600 text-white text-xs font-bold shadow-[0_0_20px_rgba(16,185,129,0.4)] transition-all cursor-pointer';
    }
  } else {
    if (imageEnrollState.confirmSeq.length < imageEnrollState.initialSeq.length) {
      if (feedback) {
        feedback.className = 'p-3 rounded-xl bg-amber-950/70 border border-amber-800 text-amber-300 text-xs font-mono block';
        feedback.textContent = `Please enter all ${imageEnrollState.initialSeq.length} symbols to complete confirmation.`;
      }
      return;
    }

    const match = JSON.stringify(imageEnrollState.initialSeq) === JSON.stringify(imageEnrollState.confirmSeq);
    if (!match) {
      if (feedback) {
        feedback.className = 'p-3 rounded-xl bg-red-950/70 border border-red-800 text-red-300 text-xs font-mono block';
        feedback.textContent = 'Confirmation sequence does not match initial selection. Try again or reset.';
      }
      imageEnrollState.confirmSeq = [];
      updateEnrollImageVisuals();
      return;
    }

    const actionBtn = document.getElementById('enroll-image-action-btn');
    if (actionBtn) {
      actionBtn.disabled = true;
      actionBtn.textContent = 'Enrolling Sequence Factor...';
    }

    try {
      const res = await window.cognisec.enrollImageSequence(imageEnrollState.initialSeq, imageEnrollState.confirmSeq);
      if (res.success) {
        if (feedback) {
          feedback.className = 'p-3 rounded-xl bg-emerald-950/70 border border-emerald-600 text-emerald-300 text-xs font-mono block';
          feedback.textContent = '✓ Cognitive image sequence factor successfully enrolled!';
        }
        await window.refreshAdaptiveMfaStatus();
        setTimeout(() => window.resetImageEnrollment(), 1800);
      } else {
        if (feedback) {
          feedback.className = 'p-3 rounded-xl bg-red-950/70 border border-red-800 text-red-300 text-xs font-mono block';
          feedback.textContent = `Enrollment failed: ${res.error}`;
        }
      }
    } catch (e) {
      if (feedback) {
        feedback.className = 'p-3 rounded-xl bg-red-950/70 border border-red-800 text-red-300 text-xs font-mono block';
        feedback.textContent = `Error: ${e.message}`;
      }
    } finally {
      if (actionBtn) actionBtn.disabled = false;
    }
  }
};

// --- PRIVATE RESPONSE ENROLLMENT HANDLERS ---
window.handlePrivateQuestionSelectChange = function(sel) {
  const customInput = document.getElementById('enroll-private-custom-q');
  if (!customInput) return;
  if (sel.value === '__custom__') {
    customInput.classList.remove('hidden');
    customInput.focus();
  } else {
    customInput.classList.add('hidden');
  }
};

window.handlePrivateEnrollSubmit = async function(e) {
  if (e && e.preventDefault) e.preventDefault();

  const sel = document.getElementById('enroll-private-select');
  const customInput = document.getElementById('enroll-private-custom-q');
  const respInput = document.getElementById('enroll-private-resp');
  const confirmInput = document.getElementById('enroll-private-confirm');
  const feedback = document.getElementById('enroll-private-feedback');
  const submitBtn = document.getElementById('enroll-private-btn-submit');

  const question = (sel && sel.value === '__custom__') ? (customInput ? customInput.value.trim() : '') : (sel ? sel.value : '');
  const response = respInput ? respInput.value.trim() : '';
  const confirmResponse = confirmInput ? confirmInput.value.trim() : '';

  if (!question) {
    if (feedback) {
      feedback.className = 'p-3 rounded-xl bg-amber-950/70 border border-amber-800 text-amber-300 text-xs font-mono block';
      feedback.textContent = 'Please choose or type a valid security question.';
    }
    return;
  }

  if (!response || response.length < 3) {
    if (feedback) {
      feedback.className = 'p-3 rounded-xl bg-amber-950/70 border border-amber-800 text-amber-300 text-xs font-mono block';
      feedback.textContent = 'Private answer must be at least 3 characters long.';
    }
    return;
  }

  if (response.toLowerCase() !== confirmResponse.toLowerCase()) {
    if (feedback) {
      feedback.className = 'p-3 rounded-xl bg-red-950/70 border border-red-800 text-red-300 text-xs font-mono block';
      feedback.textContent = 'Confirmation answer does not match secret answer.';
    }
    return;
  }

  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.textContent = 'Enrolling Private Response...';
  }

  try {
    const res = await window.cognisec.enrollPrivateResponse(question, response, confirmResponse);
    if (res.success) {
      if (feedback) {
        feedback.className = 'p-3 rounded-xl bg-emerald-950/70 border border-emerald-600 text-emerald-300 text-xs font-mono block';
        feedback.textContent = '✓ Private response security factor successfully enrolled!';
      }
      if (respInput) respInput.value = '';
      if (confirmInput) confirmInput.value = '';
      await window.refreshAdaptiveMfaStatus();
    } else {
      if (feedback) {
        feedback.className = 'p-3 rounded-xl bg-red-950/70 border border-red-800 text-red-300 text-xs font-mono block';
        feedback.textContent = `Enrollment failed: ${res.error}`;
      }
    }
  } catch (err) {
    if (feedback) {
      feedback.className = 'p-3 rounded-xl bg-red-950/70 border border-red-800 text-red-300 text-xs font-mono block';
      feedback.textContent = `Error: ${err.message}`;
    }
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Save & Enroll Private Response →';
    }
  }
};


// ================= RESET NEURALTRACE MODAL CONTROLLER =================
let ntResetState = {
  challengeId: null,
  resetTicket: null,
  step: 1, // 1: Confirm/Request OTP, 2: Verify OTP, 3: Draw New Route
  drawStep: 1, // 1: Initial Route, 2: Confirmation Route
  initialPattern: [],
  confirmPattern: [],
  gridInstance: null
};

window.openResetNeuralTraceModal = function() {
  const modal = document.getElementById('modal-reset-neuraltrace');
  if (!modal) return;

  ntResetState.challengeId = null;
  ntResetState.resetTicket = null;
  ntResetState.step = 1;
  ntResetState.drawStep = 1;
  ntResetState.initialPattern = [];
  ntResetState.confirmPattern = [];

  const user = window.cognisec ? window.cognisec.getUser() : null;
  const maskedEmail = user && user.email ? (window.cognisec.maskEmail ? window.cognisec.maskEmail(user.email) : user.email) : 'registered email';
  const emailDisplay = document.getElementById('nt-reset-masked-email');
  if (emailDisplay) emailDisplay.textContent = maskedEmail;

  // Show Step 1, hide others
  document.getElementById('nt-reset-step1')?.classList.remove('hidden');
  document.getElementById('nt-reset-step2')?.classList.add('hidden');
  document.getElementById('nt-reset-step3')?.classList.add('hidden');

  const fb1 = document.getElementById('nt-reset-step1-feedback');
  if (fb1) fb1.className = 'hidden';
  const btn1 = document.getElementById('btn-nt-reset-send-otp');
  if (btn1) {
    btn1.disabled = false;
    btn1.innerHTML = '<span>Send Re-Authentication Code →</span>';
  }

  modal.classList.remove('hidden');
};

window.closeResetNeuralTraceModal = function() {
  const modal = document.getElementById('modal-reset-neuraltrace');
  if (modal) modal.classList.add('hidden');
  if (ntResetState.gridInstance) {
    ntResetState.gridInstance.reset();
  }
  ntResetState.challengeId = null;
  ntResetState.resetTicket = null;
};

window.handleSendResetOtp = async function() {
  const btn = document.getElementById('btn-nt-reset-send-otp');
  const fb1 = document.getElementById('nt-reset-step1-feedback');
  const fb2 = document.getElementById('nt-reset-step2-feedback');
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<span>Dispatching Re-Authentication Code...</span>';
  }
  if (fb1) fb1.className = 'hidden';
  if (fb2) fb2.className = 'hidden';

  try {
    const res = await window.cognisec.requestNeuralTraceReset();
    if (res.success) {
      ntResetState.challengeId = res.reset_challenge_id;
      ntResetState.step = 2;

      document.getElementById('nt-reset-step1')?.classList.add('hidden');
      document.getElementById('nt-reset-step2')?.classList.remove('hidden');

      const desc = document.getElementById('nt-reset-step2-desc');
      if (desc) desc.textContent = `A single-use verification code was dispatched to ${res.masked_email || 'your registered email'}.`;

      const otpInput = document.getElementById('nt-reset-otp-input');
      if (otpInput) {
        otpInput.value = '';
        otpInput.focus();
      }
    } else {
      if (fb1) {
        fb1.className = 'p-3 rounded-xl bg-red-950/70 border border-red-800 text-red-300 text-xs font-mono block';
        fb1.textContent = res.error || 'Failed to dispatch verification code. Please retry.';
      }
    }
  } catch (err) {
    if (fb1) {
      fb1.className = 'p-3 rounded-xl bg-red-950/70 border border-red-800 text-red-300 text-xs font-mono block';
      fb1.textContent = `Error: ${err.message}`;
    }
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<span>Send Re-Authentication Code →</span>';
    }
  }
};

window.handleVerifyResetOtp = async function() {
  const otpInput = document.getElementById('nt-reset-otp-input');
  const otp = otpInput ? otpInput.value.trim() : '';
  const fb = document.getElementById('nt-reset-step2-feedback');
  const btn = document.getElementById('btn-nt-reset-verify-otp');

  if (!otp || otp.length !== 6 || !/^\d{6}$/.test(otp)) {
    if (fb) {
      fb.className = 'p-3 rounded-xl bg-amber-950/70 border border-amber-800 text-amber-300 text-xs font-mono block';
      fb.textContent = 'Please enter a valid 6-digit numeric verification code.';
    }
    if (otpInput) otpInput.focus();
    return;
  }

  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<span>Verifying Identity...</span>';
  }
  if (fb) fb.className = 'hidden';

  try {
    const res = await window.cognisec.verifyNeuralTraceReset(ntResetState.challengeId, otp);
    if (res.success && res.reset_ticket) {
      ntResetState.resetTicket = res.reset_ticket;
      ntResetState.step = 3;

      document.getElementById('nt-reset-step2')?.classList.add('hidden');
      document.getElementById('nt-reset-step3')?.classList.remove('hidden');

      initModalResetNeuralTraceGrid();
    } else {
      if (fb) {
        fb.className = 'p-3 rounded-xl bg-red-950/70 border border-red-800 text-red-300 text-xs font-mono block';
        fb.textContent = res.error || 'Verification code failed. Please check your email or retry.';
      }
    }
  } catch (err) {
    if (fb) {
      fb.className = 'p-3 rounded-xl bg-red-950/70 border border-red-800 text-red-300 text-xs font-mono block';
      fb.textContent = `Error: ${err.message}`;
    }
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<span>Verify &amp; Draw New Route →</span>';
    }
  }
};

function initModalResetNeuralTraceGrid() {
  const container = document.getElementById('reset-neuraltrace-grid');
  if (!container) return;

  ntResetState.drawStep = 1;
  ntResetState.initialPattern = [];
  ntResetState.confirmPattern = [];

  const preview = document.getElementById('nt-reset-preview');
  if (preview) preview.textContent = '(Trace route along connected edges)';
  const confirmBox = document.getElementById('nt-reset-confirm-box');
  if (confirmBox) confirmBox.classList.add('hidden');

  const instr = document.getElementById('nt-reset-step3-instructions');
  if (instr) instr.textContent = 'Step 1: Trace your new private neural route across at least 4 connected network nodes.';
  const tag = document.getElementById('nt-reset-step3-tag');
  if (tag) {
    tag.textContent = 'STAGE: INITIAL ROUTE';
    tag.className = 'px-2 py-0.5 rounded text-[10px] bg-red-950 text-red-300 border border-red-800 font-bold self-start sm:self-auto';
  }
  const actionBtn = document.getElementById('btn-nt-reset-action');
  if (actionBtn) {
    actionBtn.disabled = false;
    actionBtn.textContent = 'Proceed to Route Confirmation →';
    actionBtn.className = 'flex-[2] py-2.5 px-4 rounded-xl bg-gradient-to-r from-red-600 to-red-700 hover:from-red-500 hover:to-red-600 text-white text-xs font-bold shadow-[0_0_20px_rgba(220,38,38,0.4)] transition-all cursor-pointer';
  }

  if (!ntResetState.gridInstance || ntResetState.gridInstance.container !== container) {
    ntResetState.gridInstance = new NeuralTraceAuth(container, {
      theme: 'theme-cyber',
      minNodes: 4,
      onPatternChange: (pattern) => {
        const p = ntResetState.drawStep === 1
          ? document.getElementById('nt-reset-preview')
          : document.getElementById('nt-reset-confirm-preview');
        if (p) p.textContent = pattern.length > 0 ? `${pattern.length} nodes traversed` : '(Trace route along connected edges)';
      },
      onPatternComplete: (pattern) => {
        const p = ntResetState.drawStep === 1
          ? document.getElementById('nt-reset-preview')
          : document.getElementById('nt-reset-confirm-preview');
        if (p) p.textContent = `Route recorded (${pattern.length} nodes)`;
      },
      onPatternTooShort: () => {
        const fb = document.getElementById('nt-reset-step3-feedback');
        if (fb) {
          fb.className = 'p-3 rounded-xl bg-amber-950/70 border border-amber-800 text-amber-300 text-xs font-mono block';
          fb.textContent = 'Neural route must contain at least 4 connected nodes.';
        }
      },
      onReset: () => {
        const p = ntResetState.drawStep === 1
          ? document.getElementById('nt-reset-preview')
          : document.getElementById('nt-reset-confirm-preview');
        if (p) p.textContent = '(Trace route along connected edges)';
      }
    });
  } else {
    ntResetState.gridInstance.reset();
  }
}

window.resetModalNeuralTraceDrawing = function() {
  ntResetState.drawStep = 1;
  ntResetState.initialPattern = [];
  ntResetState.confirmPattern = [];

  if (ntResetState.gridInstance) {
    ntResetState.gridInstance.reset();
  }

  const initialLabel = document.getElementById('nt-reset-initial-label');
  if (initialLabel) initialLabel.textContent = 'Target Route:';
  const preview = document.getElementById('nt-reset-preview');
  if (preview) preview.textContent = '(Trace route along connected edges)';
  const confirmBox = document.getElementById('nt-reset-confirm-box');
  if (confirmBox) confirmBox.classList.add('hidden');

  const tag = document.getElementById('nt-reset-step3-tag');
  if (tag) {
    tag.textContent = 'STAGE: INITIAL ROUTE';
    tag.className = 'px-2 py-0.5 rounded text-[10px] bg-red-950 text-red-300 border border-red-800 font-bold self-start sm:self-auto';
  }

  const instr = document.getElementById('nt-reset-step3-instructions');
  if (instr) instr.textContent = 'Step 1: Trace your new private neural route across at least 4 connected network nodes.';

  const actionBtn = document.getElementById('btn-nt-reset-action');
  if (actionBtn) {
    actionBtn.disabled = false;
    actionBtn.textContent = 'Proceed to Route Confirmation →';
    actionBtn.className = 'flex-[2] py-2.5 px-4 rounded-xl bg-gradient-to-r from-red-600 to-red-700 hover:from-red-500 hover:to-red-600 text-white text-xs font-bold shadow-[0_0_20px_rgba(220,38,38,0.4)] transition-all cursor-pointer';
  }

  const fb = document.getElementById('nt-reset-step3-feedback');
  if (fb) fb.className = 'hidden';
};

window.advanceOrSubmitResetRoute = async function() {
  const fb = document.getElementById('nt-reset-step3-feedback');
  if (fb) fb.className = 'hidden';

  if (!ntResetState.gridInstance) {
    initModalResetNeuralTraceGrid();
  }

  if (ntResetState.drawStep === 1) {
    const pattern = ntResetState.gridInstance ? ntResetState.gridInstance.getPattern() : [];
    if (!pattern || pattern.length < 4) {
      if (fb) {
        fb.className = 'p-3 rounded-xl bg-amber-950/70 border border-amber-800 text-amber-300 text-xs font-mono block';
        fb.textContent = 'Neural route must contain at least 4 connected nodes.';
      }
      if (ntResetState.gridInstance) ntResetState.gridInstance.triggerShake();
      return;
    }

    ntResetState.initialPattern = [...pattern];
    ntResetState.drawStep = 2;
    ntResetState.confirmPattern = [];
    if (ntResetState.gridInstance) ntResetState.gridInstance.reset();

    const preview = document.getElementById('nt-reset-preview');
    if (preview) preview.textContent = `Recorded (${ntResetState.initialPattern.length} nodes)`;

    const confirmBox = document.getElementById('nt-reset-confirm-box');
    if (confirmBox) confirmBox.classList.remove('hidden');
    const confirmPreview = document.getElementById('nt-reset-confirm-preview');
    if (confirmPreview) confirmPreview.textContent = '(Retrace same route to confirm)';

    const tag = document.getElementById('nt-reset-step3-tag');
    if (tag) {
      tag.textContent = 'STAGE: RETRACE TO CONFIRM';
      tag.className = 'px-2 py-0.5 rounded text-[10px] bg-amber-950 text-amber-300 border border-amber-800 font-bold self-start sm:self-auto';
    }

    const instr = document.getElementById('nt-reset-step3-instructions');
    if (instr) instr.textContent = 'Step 2: Retrace the exact same route across network nodes to confirm.';

    const actionBtn = document.getElementById('btn-nt-reset-action');
    if (actionBtn) {
      actionBtn.textContent = 'Save & Protect New NeuralTrace Route ✓';
      actionBtn.className = 'flex-[2] py-2.5 px-4 rounded-xl bg-gradient-to-r from-emerald-600 to-emerald-700 hover:from-emerald-500 hover:to-emerald-600 text-white text-xs font-bold shadow-[0_0_20px_rgba(16,185,129,0.4)] transition-all cursor-pointer';
    }
  } else {
    const confirmPattern = ntResetState.gridInstance ? ntResetState.gridInstance.getPattern() : [];
    if (!confirmPattern || confirmPattern.length < 4) {
      if (fb) {
        fb.className = 'p-3 rounded-xl bg-amber-950/70 border border-amber-800 text-amber-300 text-xs font-mono block';
        fb.textContent = 'Confirmation route must have at least 4 nodes.';
      }
      if (ntResetState.gridInstance) ntResetState.gridInstance.triggerShake();
      return;
    }

    const match = JSON.stringify(ntResetState.initialPattern) === JSON.stringify(confirmPattern);
    if (!match) {
      if (fb) {
        fb.className = 'p-3 rounded-xl bg-red-950/70 border border-red-800 text-red-300 text-xs font-mono block';
        fb.textContent = 'Confirmation route does not match initial route. Retrace or reset.';
      }
      ntResetState.confirmPattern = [];
      if (ntResetState.gridInstance) {
        ntResetState.gridInstance.triggerShake();
        ntResetState.gridInstance.reset();
      }
      const confirmPreview = document.getElementById('nt-reset-confirm-preview');
      if (confirmPreview) confirmPreview.textContent = '(Retrace same route to confirm)';
      return;
    }

    ntResetState.confirmPattern = [...confirmPattern];

    const actionBtn = document.getElementById('btn-nt-reset-action');
    if (actionBtn) {
      actionBtn.disabled = true;
      actionBtn.textContent = 'Saving New NeuralTrace Verifier...';
    }

    try {
      const res = await window.cognisec.confirmNeuralTraceReset(
        ntResetState.resetTicket,
        ntResetState.initialPattern,
        ntResetState.confirmPattern
      );
      if (res.success) {
        if (fb) {
          fb.className = 'p-3 rounded-xl bg-emerald-950/70 border border-emerald-600 text-emerald-300 text-xs font-mono block';
          fb.textContent = '✓ NeuralTrace route successfully reset and protected! Old challenges invalidated.';
        }
        if (ntResetState.gridInstance) ntResetState.gridInstance.triggerSuccess();
        await window.refreshAdaptiveMfaStatus();
        setTimeout(() => {
          closeResetNeuralTraceModal();
        }, 1500);
      } else {
        if (fb) {
          fb.className = 'p-3 rounded-xl bg-red-950/70 border border-red-800 text-red-300 text-xs font-mono block';
          fb.textContent = `Reset failed: ${res.error}`;
        }
        if (actionBtn) {
          actionBtn.disabled = false;
          actionBtn.textContent = 'Save & Protect New NeuralTrace Route ✓';
        }
      }
    } catch (err) {
      if (fb) {
        fb.className = 'p-3 rounded-xl bg-red-950/70 border border-red-800 text-red-300 text-xs font-mono block';
        fb.textContent = `Error: ${err.message}`;
      }
      if (actionBtn) {
        actionBtn.disabled = false;
        actionBtn.textContent = 'Save & Protect New NeuralTrace Route ✓';
      }
    }
  }
};





