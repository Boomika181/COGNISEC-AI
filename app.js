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
    if (profId) profId.textContent = user.id ? `ID: USR-00${user.id}` : 'ID: --';
    if (profSession) profSession.textContent = `Account: ${user.account_status || 'ACTIVE'} • Session: ACTIVE`;
    if (profDevice) profDevice.textContent = `${navigator.platform || 'Desktop'} • ${isAdmin ? 'Primary SOC Console' : 'Enterprise User Client'}`;
    if (profSessionId) profSessionId.textContent = window.cognisec && window.cognisec.sessionId ? `Active Session: ${window.cognisec.sessionId}` : 'Active';
    if (profLogoutBtn) profLogoutBtn.classList.remove('hidden');
    if (profActionBtn) {
      profActionBtn.innerHTML = `<span>${isAdmin ? 'Open SOC Command Center →' : 'Open User Dashboard →'}</span>`;
    }

    if (userDashName) userDashName.textContent = user.name;
    if (userDashEmail) userDashEmail.textContent = user.email;
    if (userDashRole) userDashRole.textContent = `ROLE: ${user.role}`;
    if (userDashStatus) userDashStatus.textContent = `ACCOUNT: ${user.account_status || 'ACTIVE'}`;
    if (userDashSession) userDashSession.textContent = `Session ID: ${window.cognisec && window.cognisec.sessionId ? window.cognisec.sessionId : 'Active (TLS 1.3)'}`;
    if (userDashDevice) {
      const devLabel = (typeof window.getSuggestedDeviceLabel === 'function' ? window.getSuggestedDeviceLabel() : null) || (navigator.userAgent.includes('Firefox') ? 'Firefox' : (navigator.userAgent.includes('Safari') && !navigator.userAgent.includes('Chrome')) ? 'Safari' : navigator.userAgent.includes('Edg') ? 'Edge' : 'Browser');
      userDashDevice.textContent = userDashDevice.title = `${navigator.platform || 'Desktop'} • ${devLabel}`;
    }

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
    if (notifBell) {
      notifBell.classList.remove('hidden');
    }
    if (typeof window.refreshNotifications === 'function') {
      window.refreshNotifications();
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
    if (userDashDevice) userDashDevice.textContent = '--';
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
  if (typeof window._resetNotificationGuestState === 'function') {
    window._resetNotificationGuestState();
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

  // Display clear alert if session expired or terminated, and suggest device label
  if (id === 'login') {
    if (window.cognisec && window.cognisec.sessionExpiredMessage) {
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
    const nicknameInput = document.getElementById('login-device-nickname');
    if (nicknameInput && typeof window.getSuggestedDeviceLabel === 'function') {
      const suggestedLabel = window.getSuggestedDeviceLabel();
      nicknameInput.value = suggestedLabel;
      nicknameInput.placeholder = `e.g. ${suggestedLabel}`;
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

  if (id === 'liveDemo') {
    if (typeof refreshAdaptiveMfaStatus === 'function') {
      refreshAdaptiveMfaStatus();
    }
    if (typeof refreshMaturityProgress === 'function') {
      refreshMaturityProgress();
    }
    if (typeof refreshBehavioralDashboard === 'function') {
      refreshBehavioralDashboard();
    }
    if (typeof startLiveTelemetryMonitoring === 'function') {
      startLiveTelemetryMonitoring();
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

  if (id === 'liveDemo') {
    if (typeof stopLiveTelemetryMonitoring === 'function') {
      stopLiveTelemetryMonitoring();
    }
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

function escapeHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

async function loadSocDashboardData() {
  if (!window.cognisec || !window.cognisec.isAdmin()) return;

  const opEmailEl = document.getElementById('soc-operator-email-val');
  if (opEmailEl && window.cognisec && window.cognisec.user) {
    opEmailEl.textContent = window.cognisec.user.email;
  }

  // 1. High-Level SOC KPI Metrics
  try {
    const metrics = await window.cognisec.fetchSocMetrics();
    if (metrics) {
      const sessionsEl = document.getElementById('soc-stat-sessions');
      const trustedEl = document.getElementById('soc-stat-trusted');
      const blockedEl = document.getElementById('soc-stat-blocked');
      const devicesEl = document.getElementById('soc-stat-devices');
      const alertsEl = document.getElementById('soc-stat-alerts');
      const anomalyEl = document.getElementById('soc-risk-anomaly');

      if (sessionsEl) sessionsEl.textContent = Number(metrics.live_sessions_count).toLocaleString();
      if (trustedEl) trustedEl.textContent = Number(metrics.active_users_count || metrics.trusted_users_count).toLocaleString();
      if (blockedEl) blockedEl.textContent = Number(metrics.blocked_sessions_count).toLocaleString();
      if (devicesEl) devicesEl.textContent = Number(metrics.active_devices_count).toLocaleString();
      if (alertsEl) alertsEl.textContent = Number(metrics.active_alerts_count).toLocaleString();
      if (anomalyEl) {
        anomalyEl.textContent = `ANOMALY RATE: ${metrics.anomaly_rate_label || (metrics.anomaly_rate_percent + '%')}`;
        anomalyEl.title = `Evaluated ${metrics.anomaly_rate_observations || 0} genuine security events in the past 24 hours. Rate: ${metrics.anomaly_rate_percent}%`;
      }

      const usersSub = document.getElementById('soc-stat-users-sub');
      if (usersSub && metrics.persisted_users_count !== undefined) {
        usersSub.textContent = `${metrics.active_users_count} Live · ${metrics.persisted_users_count} In DB`;
        usersSub.title = `Genuine Active: ${metrics.active_users_count} | Seeded Demo: ${metrics.seeded_demo_accounts_count || 0} | Known Test: ${metrics.known_test_accounts_count || 0} | Unknown Historical: ${metrics.unknown_provenance_accounts_count || 0} (Total: ${metrics.persisted_users_count})`;
      }
      const devSub = document.getElementById('soc-stat-devices-sub');
      if (devSub && metrics.persisted_devices_count !== undefined) {
        devSub.textContent = `${metrics.active_devices_count} Live · ${metrics.persisted_devices_count} In DB`;
        devSub.title = `1 physical device with live authenticated session. 101 historical persisted development records (physical hardware unconfirmed; no active connection).`;
      }
      const blockedSub = document.getElementById('soc-stat-blocked-sub');
      if (blockedSub) {
        blockedSub.textContent = `${metrics.restricted_sessions_count || 0} Restr · ${metrics.revoked_devices_count || 0} Dev`;
        blockedSub.title = `Active Security Enforcements: ${metrics.restricted_sessions_count || 0} restricted sessions + ${metrics.revoked_devices_count || 0} revoked devices. (Historical closed sessions: ${metrics.terminated_sessions_count || 0})`;
      }
      const alertsSub = document.getElementById('soc-stat-alerts-sub');
      if (alertsSub && metrics.open_alerts_count !== undefined) {
        alertsSub.textContent = `${metrics.open_alerts_count} Open · ${metrics.total_alerts_count || metrics.open_alerts_count} Total`;
        alertsSub.title = `Unresolved alerts awaiting triage: ${metrics.open_alerts_count} Open + ${metrics.reopened_alerts_count || 0} Reopened (${metrics.resolved_alerts_count || 0} resolved)`;
      }
    }
  } catch (err) {
    console.warn('[COGNISEC-AI] Failed to load SOC metrics:', err);
  }

  // 2. Risk Distribution & Verification Activity
  try {
    const riskDist = await window.cognisec.fetchSocRiskDistribution();
    const lowEl = document.getElementById('soc-risk-low');
    const medEl = document.getElementById('soc-risk-med');
    const highEl = document.getElementById('soc-risk-high');
    const stepEl = document.getElementById('soc-risk-stepup');

    if (riskDist) {
      if (lowEl) lowEl.textContent = Number(riskDist.low_risk_sessions || 0).toLocaleString();
      if (medEl) medEl.textContent = Number(riskDist.medium_risk_sessions || 0).toLocaleString();
      if (highEl) highEl.textContent = Number((riskDist.high_risk_sessions || 0) + (riskDist.critical_risk_sessions || 0)).toLocaleString();
      if (stepEl) stepEl.textContent = Number(riskDist.step_up_verified_count || 0).toLocaleString();
    } else {
      if (lowEl) lowEl.textContent = '0';
      if (medEl) medEl.textContent = '0';
      if (highEl) highEl.textContent = '0';
      if (stepEl) stepEl.textContent = '0';
    }
  } catch (err) {
    console.warn('[COGNISEC-AI] Failed to load risk distribution:', err);
    ['soc-risk-low', 'soc-risk-med', 'soc-risk-high', 'soc-risk-stepup'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.textContent = '0';
    });
  }

  // 3. Real Security Alerts (Overview and Logs tabs)
  try {
    const alertsScopeSelect = document.getElementById('soc-alerts-scope-select');
    const alertsScope = alertsScopeSelect ? alertsScopeSelect.value : 'genuine';
    const alerts = await window.cognisec.fetchSocAlerts(50, '', '', null, alertsScope);
    window._cachedSocAlerts = alerts || [];
    const overviewAlertsEl = document.getElementById('soc-overview-alerts');
    const logsAlertsContainer = document.getElementById('soc-all-alerts-container');
    const logsAlertsCount = document.getElementById('soc-logs-alerts-count');

    if (logsAlertsCount) logsAlertsCount.textContent = `${(alerts || []).length} Incidents Logged`;

    const openAlerts = (alerts || []).filter(a => a.status === 'OPEN');
    const overviewBadge = document.getElementById('soc-overview-alerts-badge');
    if (overviewBadge) overviewBadge.textContent = `${openAlerts.length} OPEN`;

    if (overviewAlertsEl) {
      if (openAlerts.length > 0) {
        overviewAlertsEl.innerHTML = '';
        openAlerts.forEach(al => {
          const timeStr = new Date(al.created_at).toLocaleTimeString('en-US', { hour12: false });
          const card = document.createElement('div');
          card.className = 'p-3.5 rounded-xl bg-red-950/30 border border-red-800/70 space-y-2 font-mono text-xs';
          card.innerHTML = `
            <div class="flex items-center justify-between">
              <div class="flex items-center gap-2">
                <span class="px-2 py-0.5 rounded text-[10px] font-bold ${al.severity === 'CRITICAL' ? 'bg-red-600 text-white' : 'bg-amber-950 text-amber-300'}">${al.severity}</span>
                ${al.is_simulated ? '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-950 text-purple-300 border border-purple-800">[SIMULATED SCENARIO]</span>' : ''}
                <strong class="text-white font-bold">${escapeHtml(al.alert_type.replace(/_/g, ' '))}</strong>
              </div>
              <span class="text-slate-500 text-[10px]">[${timeStr}]</span>
            </div>
            <p class="text-slate-300 text-[11px] leading-relaxed">${escapeHtml(al.message)}</p>
            <div class="flex flex-wrap items-center justify-between pt-1 gap-2">
              <span class="text-[10px] text-slate-400">Target: ${escapeHtml(al.user_name || 'User')} (${escapeHtml(al.user_email || '')})</span>
              <div class="flex items-center gap-1.5">
                <button onclick="window.openIncidentInvestigation(${al.id})" class="px-2 py-0.5 rounded bg-red-950 hover:bg-red-900 border border-red-700 text-red-300 text-[10px] font-bold cursor-pointer transition-all">🔍 Inspect</button>
                <button onclick="window.triageQuickAlert(${al.id}, 'ACKNOWLEDGED')" class="px-2 py-0.5 rounded bg-amber-950 hover:bg-amber-900 border border-amber-700 text-amber-300 text-[10px] font-bold cursor-pointer">Acknowledge</button>
                <button onclick="window.triageResolvePrompt(${al.id})" class="px-2 py-0.5 rounded bg-emerald-950 hover:bg-emerald-900 border border-emerald-700 text-emerald-300 text-[10px] font-bold cursor-pointer">Resolve</button>
              </div>
            </div>
          `;
          overviewAlertsEl.appendChild(card);
        });
      } else {
        overviewAlertsEl.innerHTML = `<div class="p-8 text-center text-slate-500 font-mono text-xs">✓ No open security alerts. All systems operational.</div>`;
      }
    }

    if (logsAlertsContainer) {
      window.renderSocAlertsList(alerts || []);
    }
  } catch (err) {
    console.warn('[COGNISEC-AI] Failed to load alerts:', err);
    const overviewAlertsEl = document.getElementById('soc-overview-alerts');
    if (overviewAlertsEl) {
      overviewAlertsEl.innerHTML = `<div class="p-8 text-center text-red-400 font-mono text-xs">Failed to load security alerts. <button onclick="window.loadSocDashboardData()" class="underline text-slate-300 hover:text-white cursor-pointer ml-1.5 font-bold">Retry</button></div>`;
    }
  }

  // 4. Real Security Events Feed
  try {
    const eventsScopeSelect = document.getElementById('soc-events-scope-select');
    const eventsScope = eventsScopeSelect ? eventsScopeSelect.value : 'genuine';
    const events = await window.cognisec.fetchSocEvents(50, eventsScope);
    const logsEl = document.getElementById('soc-live-logs');
    const allEventsContainer = document.getElementById('soc-all-events-container');
    const logsEventsCount = document.getElementById('soc-logs-events-count');

    if (logsEventsCount) logsEventsCount.textContent = `${(events || []).length} Events Streamed`;

    if (logsEl) {
      if (events && events.length > 0) {
        logsEl.innerHTML = '';
        events.slice(0, 15).forEach(ev => {
          const timeStr = new Date(ev.timestamp).toLocaleTimeString('en-US', { hour12: false });
          const isClean = ev.severity === 'LOW';
          const isCritical = ev.severity === 'CRITICAL' || ev.decision === 'TERMINATE_SESSION';
          const newLog = document.createElement('div');
          newLog.className = `p-3 rounded-xl bg-black/50 border ${isClean ? 'border-emerald-950' : (isCritical ? 'border-red-600 bg-red-950/20' : 'border-amber-950')} flex items-center justify-between font-mono text-[11px] animate-fade-in transition-all`;
          newLog.innerHTML = `
            <div class="flex items-center gap-3">
              <span class="${isClean ? 'text-emerald-400' : 'text-red-400'} font-bold">${isClean ? '🟢' : '🔴'} [${timeStr}]</span>
              ${ev.is_simulated ? '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-950 text-purple-300 border border-purple-800">[SIMULATED]</span>' : ''}
              <span class="text-white font-bold">${escapeHtml(ev.event_type.replace(/_/g, ' '))} (${(ev.application || 'PLATFORM').toUpperCase()})</span>
              <span class="text-slate-400 text-[10px]">&bull; User: ${escapeHtml(ev.user_name || 'Portal User')} &bull; Severity: <span class="${isClean ? 'text-emerald-400' : 'text-red-400'} font-bold">${ev.severity}</span></span>
            </div>
            <div class="flex items-center gap-2">
              <span class="px-2.5 py-0.5 ${isClean ? 'bg-emerald-950 text-emerald-400 border-emerald-800' : 'bg-red-950 text-red-400 border-red-800'} border rounded text-[10px] font-bold">${ev.decision}</span>
              ${ev.id ? `<button onclick="window.openIncidentInvestigation(${ev.id})" class="px-2 py-0.5 rounded bg-black border border-slate-700 text-slate-300 hover:text-white text-[10px] font-mono cursor-pointer transition-all">🔍 Inspect</button>` : ''}
            </div>
          `;
          logsEl.appendChild(newLog);
        });
      } else {
        logsEl.innerHTML = `<div class="p-8 text-center text-slate-500 font-mono text-xs">No security events recorded yet. Zero-Trust monitoring active.</div>`;
      }
    }

    if (allEventsContainer) {
      window.renderSocEventsTable(events || []);
    }
  } catch (err) {
    console.warn('[COGNISEC-AI] Failed to load security events:', err);
    const logsEl = document.getElementById('soc-live-logs');
    if (logsEl) {
      logsEl.innerHTML = `<div class="p-8 text-center text-red-400 font-mono text-xs">Failed to load security event feed. <button onclick="window.loadSocDashboardData()" class="underline text-slate-300 hover:text-white cursor-pointer ml-1.5 font-bold">Retry</button></div>`;
    }
  }

  // 5. Active Sessions & User Management
  try {
    const sessions = await window.cognisec.fetchSocSessions(50);
    window._cachedSocSessions = sessions || [];
    const sessionsContainer = document.getElementById('soc-sessions-table-container');
    const sessionsCountBadge = document.getElementById('soc-sessions-count-badge');

    const activeSessions = (sessions || []).filter(s => s.status === 'ACTIVE');
    if (sessionsCountBadge) sessionsCountBadge.textContent = `${activeSessions.length} ACTIVE SESSIONS`;

    if (sessionsContainer) {
      window.renderSocSessionsTable(sessions || []);
    }
  } catch (err) {
    console.warn('[COGNISEC-AI] Failed to load sessions:', err);
  }

  // 6. Enterprise Users Directory
  try {
    const users = await window.cognisec.fetchSocUsers(100);
    const usersContainer = document.getElementById('soc-users-table-container');
    const usersCountBadge = document.getElementById('soc-users-count-badge');
    const userSelect = document.getElementById('soc-behavior-user-select');

    if (usersCountBadge) usersCountBadge.textContent = `${(users || []).length} REGISTERED`;

    if (userSelect && users && users.length > 0) {
      const currentSelected = userSelect.value;
      userSelect.innerHTML = '';
      users.forEach((u, idx) => {
        const opt = document.createElement('option');
        opt.value = u.id;
        opt.textContent = `${u.name} (${u.email}) — ${u.baseline_status || 'COLD_START'}`;
        if (currentSelected ? u.id == currentSelected : idx === 0) opt.selected = true;
        userSelect.appendChild(opt);
      });
      if (userSelect.value) {
        window.inspectUserBehavior(userSelect.value);
      }
    }

    if (usersContainer) {
      if (users && users.length > 0) {
        let usersTableHtml = `
          <table class="w-full text-left font-mono text-xs border-collapse">
            <thead>
              <tr class="border-b border-red-950 text-slate-400 text-[10px] uppercase">
                <th class="py-2.5 px-3">User</th>
                <th class="py-2.5 px-3">Role</th>
                <th class="py-2.5 px-3">Status</th>
                <th class="py-2.5 px-3">Data Provenance</th>
                <th class="py-2.5 px-3">Devices</th>
                <th class="py-2.5 px-3">Active Sessions</th>
                <th class="py-2.5 px-3">Behavior Baseline</th>
                <th class="py-2.5 px-3">Member Since</th>
                <th class="py-2.5 px-3 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-red-950/40">
        `;
        users.forEach(u => {
          const isAct = u.account_status === 'ACTIVE';
          const joinStr = new Date(u.created_at).toLocaleDateString();

          let provBadge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-900 text-slate-400 border border-slate-700">📜 HISTORICAL</span>';
          if (u.is_active || u.provenance === 'GENUINE_ACTIVE') {
            provBadge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800">🟢 GENUINE LIVE</span>';
          } else if (u.provenance === 'SEEDED_DEMO') {
            provBadge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-sky-950 text-sky-400 border border-sky-800">👤 SEEDED DEMO</span>';
          } else if (u.provenance === 'KNOWN_TEST') {
            provBadge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-950 text-purple-300 border border-purple-800">🧪 KNOWN TEST</span>';
          }

          usersTableHtml += `
            <tr class="hover:bg-red-950/10 transition-colors">
              <td class="py-2.5 px-3">
                <strong class="text-white block">${escapeHtml(u.name)}</strong>
                <span class="text-slate-500 text-[10px]">${escapeHtml(u.email)}</span>
              </td>
              <td class="py-2.5 px-3">
                <span class="px-2 py-0.5 rounded text-[10px] font-bold ${u.role === 'ADMIN' ? 'bg-purple-950 text-purple-300 border border-purple-800' : 'bg-slate-900 text-slate-400'}">${u.role}</span>
              </td>
              <td class="py-2.5 px-3">
                <span class="px-2 py-0.5 rounded text-[10px] font-bold ${isAct ? 'bg-emerald-950 text-emerald-400' : 'bg-red-950 text-red-400'}">${u.account_status}</span>
              </td>
              <td class="py-2.5 px-3">
                ${provBadge}
              </td>
              <td class="py-2.5 px-3 text-sky-400 font-bold">${u.registered_devices_count || 0}</td>
              <td class="py-2.5 px-3 text-emerald-400 font-bold">${u.active_sessions_count || 0}</td>
              <td class="py-2.5 px-3">
                <span class="px-2 py-0.5 rounded text-[10px] font-bold ${u.sample_count > 15 ? 'bg-emerald-950 text-emerald-400' : 'bg-amber-950 text-amber-300'}">${u.baseline_status || 'COLD_START'} (${u.sample_count || 0})</span>
              </td>
              <td class="py-2.5 px-3 text-slate-400 text-[10px]">${joinStr}</td>
              <td class="py-2.5 px-3 text-right">
                <button onclick="window.switchDashboardTab('behavior'); window.inspectUserBehavior(${u.id});" class="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 font-mono text-[10px] font-bold cursor-pointer">View Telemetry →</button>
              </td>
            </tr>
          `;
        });
        usersTableHtml += `</tbody></table>`;
        usersContainer.innerHTML = usersTableHtml;
      } else {
        usersContainer.innerHTML = `<div class="p-6 text-center text-slate-500 font-mono text-xs">No users found.</div>`;
      }
    }
  } catch (err) {
    console.warn('[COGNISEC-AI] Failed to load users:', err);
  }

  // 7. Enterprise Hardware Device Inventory
  try {
    const devices = await window.cognisec.fetchSocDevices();
    window._cachedSocDevices = devices || [];
    const devicesContainer = document.getElementById('soc-devices-table-container');
    const devicesCountBadge = document.getElementById('soc-devices-count-badge');

    if (devicesCountBadge) devicesCountBadge.textContent = `${(devices || []).length} REGISTERED DEVICES`;

    if (devicesContainer) {
      window.renderSocDevicesTable(devices || []);
    }
  } catch (err) {
    console.warn('[COGNISEC-AI] Failed to load devices:', err);
  }

  // 8. Measurable System Health & Command Status
  try {
    await window.loadSocSystemHealth();
  } catch (err) {
    console.warn('[COGNISEC-AI] Failed to load health telemetry:', err);
  }
}

// Render Functions for SOC Views
window.renderSocAlertsList = function(alerts) {
  const container = document.getElementById('soc-all-alerts-container');
  if (!container) return;
  if (!alerts || alerts.length === 0) {
    container.innerHTML = `<div class="p-6 text-center text-slate-500 font-mono text-xs">No alerts found matching filter criteria.</div>`;
    return;
  }
  container.innerHTML = '';
  alerts.forEach(al => {
    const isResolved = al.status === 'RESOLVED';
    const isAck = al.status === 'ACKNOWLEDGED';
    const isInv = al.status === 'INVESTIGATING';
    const isReopened = al.status === 'REOPENED';
    const timeStr = new Date(al.created_at).toLocaleString();
    const card = document.createElement('div');
    card.className = `p-3.5 rounded-xl border ${isResolved ? 'bg-black/40 border-slate-800' : 'bg-red-950/20 border-red-800/60'} flex flex-col md:flex-row md:items-center justify-between gap-3 font-mono text-xs transition-all`;
    card.innerHTML = `
      <div class="space-y-1.5 flex-1 min-w-0">
        <div class="flex flex-wrap items-center gap-2">
          <span class="px-2 py-0.5 rounded text-[10px] font-bold ${al.severity === 'CRITICAL' ? 'bg-red-600 text-white' : 'bg-amber-950 text-amber-300'}">${al.severity}</span>
          ${al.is_simulated ? '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-950 text-purple-300 border border-purple-800">[SIMULATED SCENARIO]</span>' : ''}
          <span class="px-2 py-0.5 rounded text-[10px] font-bold ${isResolved ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : (isInv ? 'bg-purple-950 text-purple-300 border border-purple-800' : (isAck ? 'bg-sky-950 text-sky-300 border border-sky-800' : (isReopened ? 'bg-amber-950 text-amber-300 border border-amber-800' : 'bg-red-950 text-red-400 border border-red-800')))}">
            STATUS: ${al.status}
          </span>
          <strong class="text-white font-bold">${escapeHtml(al.alert_type.replace(/_/g, ' '))}</strong>
          <span class="text-slate-500 text-[10px]">[${timeStr}]</span>
        </div>
        <p class="text-slate-300 text-[11px] leading-relaxed">${escapeHtml(al.message)}</p>
        <div class="flex flex-wrap items-center gap-x-4 gap-y-1 text-[10px] text-slate-400">
          <span>Target: <strong class="text-slate-300">${escapeHtml(al.user_name || 'User')}</strong> (${escapeHtml(al.user_email || '')})</span>
          <span>App: <strong class="text-slate-300">${(al.application || 'PLATFORM').toUpperCase()}</strong></span>
          ${al.assigned_to ? `<span>Assignee: <strong class="text-sky-300">${escapeHtml(al.assigned_to)}</strong></span>` : ''}
          ${al.resolved_by ? `<span>Resolved By: <strong class="text-emerald-300">${escapeHtml(al.resolved_by)}</strong></span>` : ''}
        </div>
        ${al.notes ? `<div class="p-2 rounded bg-black/60 border border-red-950 text-[10px] text-slate-300 font-mono">📝 Notes: ${escapeHtml(al.notes)}</div>` : ''}
        ${al.resolution_reason ? `<div class="p-2 rounded bg-emerald-950/30 border border-emerald-900/60 text-[10px] text-emerald-300 font-mono">✓ Resolution Reason: ${escapeHtml(al.resolution_reason)}</div>` : ''}
      </div>
      <div class="flex flex-wrap items-center gap-1.5 shrink-0 self-start md:self-center">
        <button onclick="window.openIncidentInvestigation(${al.id})" class="px-2.5 py-1 rounded bg-red-950 hover:bg-red-900 border border-red-700 text-red-300 text-[10px] font-bold cursor-pointer transition-all">🔍 Inspect</button>
        ${!isResolved ? `
          <button onclick="window.triageQuickAlert(${al.id}, 'ACKNOWLEDGED')" class="px-2.5 py-1 rounded bg-sky-950 hover:bg-sky-900 border border-sky-700 text-sky-300 text-[10px] font-bold cursor-pointer">Acknowledge</button>
          <button onclick="window.triageQuickAlert(${al.id}, 'INVESTIGATING')" class="px-2.5 py-1 rounded bg-purple-950 hover:bg-purple-900 border border-purple-700 text-purple-300 text-[10px] font-bold cursor-pointer">Investigate</button>
          <button onclick="window.triageResolvePrompt(${al.id})" class="px-2.5 py-1 rounded bg-emerald-950 hover:bg-emerald-900 border border-emerald-700 text-emerald-300 text-[10px] font-bold cursor-pointer">Resolve</button>
        ` : `
          <button onclick="window.triageQuickAlert(${al.id}, 'REOPENED')" class="px-2.5 py-1 rounded bg-amber-950 hover:bg-amber-900 border border-amber-700 text-amber-300 text-[10px] font-bold cursor-pointer">Reopen</button>
        `}
      </div>
    `;
    container.appendChild(card);
  });
};

window.renderSocEventsTable = function(events) {
  const container = document.getElementById('soc-all-events-container');
  if (!container) return;
  if (!events || events.length === 0) {
    container.innerHTML = `<div class="p-6 text-center text-slate-500 font-mono text-xs">No security events found.</div>`;
    return;
  }
  let eventsTableHtml = `
    <table class="w-full text-left font-mono text-xs border-collapse">
      <thead>
        <tr class="border-b border-red-950 text-slate-400 text-[10px] uppercase">
          <th class="py-2.5 px-3">Timestamp</th>
          <th class="py-2.5 px-3">Event Type</th>
          <th class="py-2.5 px-3">Target User</th>
          <th class="py-2.5 px-3">App</th>
          <th class="py-2.5 px-3">Severity</th>
          <th class="py-2.5 px-3">Anomaly</th>
          <th class="py-2.5 px-3">Decision</th>
          <th class="py-2.5 px-3 text-right">Inspect</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-red-950/40">
  `;
  events.forEach(ev => {
    const timeStr = new Date(ev.timestamp).toLocaleString();
    const isCritical = ev.severity === 'CRITICAL' || ev.decision === 'TERMINATE_SESSION';
    const isLow = ev.severity === 'LOW';
    eventsTableHtml += `
      <tr class="hover:bg-red-950/10 transition-colors">
        <td class="py-2.5 px-3 text-slate-400 text-[11px] whitespace-nowrap">${timeStr}</td>
        <td class="py-2.5 px-3 text-white font-bold">
          ${ev.is_simulated ? '<span class="px-1.5 py-0.5 rounded text-[9px] font-bold bg-purple-950 text-purple-300 border border-purple-800 mr-1.5">[SIMULATED]</span>' : ''}
          ${escapeHtml(ev.event_type.replace(/_/g, ' '))}
        </td>
        <td class="py-2.5 px-3 text-slate-300">${escapeHtml(ev.user_name || 'Unknown')}</td>
        <td class="py-2.5 px-3 text-slate-400 uppercase text-[10px]">${escapeHtml(ev.application)}</td>
        <td class="py-2.5 px-3">
          <span class="px-2 py-0.5 rounded text-[10px] font-bold ${isCritical ? 'bg-red-600 text-white' : (isLow ? 'bg-emerald-950 text-emerald-400' : 'bg-amber-950 text-amber-300')}">${ev.severity}</span>
        </td>
        <td class="py-2.5 px-3 font-mono text-slate-300">${Number(ev.anomaly_score).toFixed(2)}</td>
        <td class="py-2.5 px-3">
          <span class="px-2 py-0.5 rounded text-[10px] font-bold ${isCritical ? 'bg-red-950 text-red-400 border border-red-800' : 'bg-slate-900 text-slate-300 border border-slate-800'}">${ev.decision}</span>
        </td>
        <td class="py-2.5 px-3 text-right">
          ${ev.id ? `<button onclick="window.openIncidentInvestigation(${ev.id})" class="px-2.5 py-0.5 rounded bg-black border border-slate-700 text-slate-300 hover:text-white text-[10px] font-mono font-bold cursor-pointer transition-all">🔍 Inspect</button>` : '—'}
        </td>
      </tr>
    `;
  });
  eventsTableHtml += `</tbody></table>`;
  container.innerHTML = eventsTableHtml;
};

window.renderSocSessionsTable = function(sessions) {
  const container = document.getElementById('soc-sessions-table-container');
  if (!container) return;
  if (!sessions || sessions.length === 0) {
    container.innerHTML = `<div class="p-6 text-center text-slate-500 font-mono text-xs">No sessions found matching filters.</div>`;
    return;
  }
  let sessTableHtml = `
    <table class="w-full text-left font-mono text-xs border-collapse">
      <thead>
        <tr class="border-b border-red-950 text-slate-400 text-[10px] uppercase">
          <th class="py-2.5 px-3">Session ID</th>
          <th class="py-2.5 px-3">User</th>
          <th class="py-2.5 px-3">Application</th>
          <th class="py-2.5 px-3">IP &amp; Device</th>
          <th class="py-2.5 px-3">Risk Level</th>
          <th class="py-2.5 px-3">Status</th>
          <th class="py-2.5 px-3">Login Time</th>
          <th class="py-2.5 px-3 text-right">Actions</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-red-950/40">
  `;
  sessions.forEach(s => {
    const isActive = s.status === 'ACTIVE';
    const isTerminated = s.status === 'TERMINATED' || s.status === 'REVOKED';
    const isRestricted = s.status === 'RESTRICTED';
    const isStepUp = s.status === 'STEP_UP_REQUIRED';
    const timeStr = new Date(s.login_time).toLocaleTimeString();
    sessTableHtml += `
      <tr class="hover:bg-red-950/10 transition-colors">
        <td class="py-2.5 px-3 text-slate-400 font-mono text-[11px] whitespace-nowrap" title="${s.id}">
          ${s.is_simulated ? '<span class="px-1.5 py-0.5 rounded text-[9px] font-bold bg-purple-950 text-purple-300 border border-purple-800 mr-1.5">[SIMULATED]</span>' : ''}
          ${s.id.substring(0, 16)}...
        </td>
        <td class="py-2.5 px-3">
          <strong class="text-white block">${escapeHtml(s.user_name || 'User')}</strong>
          <span class="text-slate-500 text-[10px]">${escapeHtml(s.user_email || '')}</span>
        </td>
        <td class="py-2.5 px-3 uppercase text-[10px] text-slate-300 font-bold">${escapeHtml(s.application)}</td>
        <td class="py-2.5 px-3 text-slate-300 text-[11px]">
          <div>${escapeHtml(s.ip_address || '127.0.0.1')}</div>
          <span class="text-slate-500 text-[10px]">${escapeHtml(s.device_nickname || 'Client Browser')}</span>
        </td>
        <td class="py-2.5 px-3">
          <span class="px-2 py-0.5 rounded text-[10px] font-bold ${s.current_risk_level === 'CRITICAL' || s.current_risk_level === 'HIGH' ? 'bg-red-950 text-red-400 border border-red-800' : 'bg-emerald-950 text-emerald-400 border border-emerald-800'}">${s.current_risk_level}</span>
        </td>
        <td class="py-2.5 px-3">
          <span class="px-2 py-0.5 rounded text-[10px] font-bold ${isActive ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : (isRestricted ? 'bg-amber-950 text-amber-300 border border-amber-800' : (isStepUp ? 'bg-purple-950 text-purple-300 border border-purple-800' : 'bg-slate-900 text-slate-500 border border-slate-800'))}">
            ${s.status}
          </span>
        </td>
        <td class="py-2.5 px-3 text-slate-400 text-[10px] whitespace-nowrap">${timeStr}</td>
        <td class="py-2.5 px-3 text-right">
          <div class="flex items-center justify-end gap-1.5">
            <button onclick="window.openIncidentInvestigation('${s.id}')" class="px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 font-mono text-[10px] font-bold cursor-pointer transition-all">🔍 Inspect</button>
            ${isActive ? `
              <button onclick="window.terminateSocSession('${s.id}')" class="px-2.5 py-1 rounded bg-red-950 hover:bg-red-800 border border-red-700 text-red-300 font-mono text-[10px] font-bold cursor-pointer transition-all">⛔ Terminate</button>
            ` : `
              <span class="text-slate-600 text-[10px] font-mono">${s.status}</span>
            `}
          </div>
        </td>
      </tr>
    `;
  });
  sessTableHtml += `</tbody></table>`;
  container.innerHTML = sessTableHtml;
};

window.renderSocDevicesTable = function(devices) {
  const container = document.getElementById('soc-devices-table-container');
  if (!container) return;
  if (!devices || devices.length === 0) {
    container.innerHTML = `<div class="p-6 text-center text-slate-500 font-mono text-xs">No devices found in this queue.</div>`;
    return;
  }
  let devTableHtml = `
    <table class="w-full text-left font-mono text-xs border-collapse">
      <thead>
        <tr class="border-b border-red-950 text-slate-400 text-[10px] uppercase">
          <th class="py-2.5 px-3">Device &amp; Fingerprint Hash</th>
          <th class="py-2.5 px-3">Account Owner</th>
          <th class="py-2.5 px-3">Browser &amp; OS</th>
          <th class="py-2.5 px-3">Network &amp; Location</th>
          <th class="py-2.5 px-3">Trust State</th>
          <th class="py-2.5 px-3">Hardware &amp; Provenance</th>
          <th class="py-2.5 px-3">Sessions</th>
          <th class="py-2.5 px-3">Last Seen</th>
          <th class="py-2.5 px-3 text-right">Administrative Actions</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-red-950/40">
  `;
  devices.forEach(d => {
    const isTrusted = d.trust_state === 'TRUSTED';
    const isRevoked = d.trust_state === 'REVOKED';
    const isPending = d.trust_state === 'PENDING_CONFIRMATION';
    const lastSeenStr = new Date(d.last_seen || d.first_seen).toLocaleDateString();
    const devIdent = d.device_id || `dev_${d.id}`;
    const isUnverified = (d.nickname === 'Identity not verified');

    const provBadge = d.is_active ?
      '<span class="px-1.5 py-0.5 rounded text-[9px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-700">🟢 LIVE ACTIVE</span>' :
      (d.provenance === 'KNOWN_TEST' ?
        '<span class="px-1.5 py-0.5 rounded text-[9px] font-bold bg-purple-950 text-purple-300 border border-purple-800">🧪 KNOWN TEST</span>' :
        '<span class="px-1.5 py-0.5 rounded text-[9px] font-bold bg-slate-900 text-slate-400 border border-slate-700">📜 HISTORICAL</span>');

    const hwEvidence = d.is_physical_device_confirmed ?
      `<div class="text-[10px] text-emerald-400 font-bold" title="${escapeHtml(d.hardware_evidence_summary || '')}">✓ Physical Hardware Confirmed</div>` :
      `<div class="text-[10px] text-slate-500" title="${escapeHtml(d.hardware_evidence_summary || 'Physical hardware unconfirmed; historical record')}">⚠️ Hardware Unconfirmed</div>`;

    devTableHtml += `
      <tr class="hover:bg-red-950/10 transition-colors">
        <td class="py-2.5 px-3">
          <strong class="${isUnverified ? 'text-amber-400' : 'text-white'} block">${escapeHtml(d.nickname || 'Unlabeled Device')}</strong>
          <span class="text-slate-500 text-[10px] font-mono" title="Client Browser SHA-256 Fingerprint Hash">${escapeHtml(devIdent)}</span>
        </td>
        <td class="py-2.5 px-3">
          <strong class="text-slate-300 block">${escapeHtml(d.user_name || 'Owner')}</strong>
          <span class="text-slate-500 text-[10px]">${escapeHtml(d.user_email || '')}</span>
        </td>
        <td class="py-2.5 px-3 text-slate-300 text-[11px]">
          <div>${escapeHtml(d.browser_name || d.browser || 'Browser')} ${d.browser_version || ''}</div>
          <span class="text-slate-500 text-[10px]">${escapeHtml(d.os_name || d.os || 'OS')} (${escapeHtml(d.device_type || 'Desktop')})</span>
        </td>
        <td class="py-2.5 px-3 text-slate-400 text-[11px]">
          <div>${escapeHtml(d.last_ip || '127.0.0.1')}</div>
          <span class="text-slate-500 text-[10px]">${escapeHtml(d.city ? `${d.city}, ${d.country || ''}` : 'Local network')}</span>
        </td>
        <td class="py-2.5 px-3">
          <span class="px-2 py-0.5 rounded text-[10px] font-bold ${isTrusted ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : (isRevoked ? 'bg-red-950 text-red-400 border border-red-800' : 'bg-amber-950 text-amber-300 border border-amber-800')}">${d.trust_state}</span>
        </td>
        <td class="py-2.5 px-3">
          ${provBadge}
          ${hwEvidence}
        </td>
        <td class="py-2.5 px-3 ${d.is_active ? 'text-emerald-400 font-bold' : 'text-slate-500'}">${d.active_session_count || 0} active</td>
        <td class="py-2.5 px-3 text-slate-400 text-[10px] whitespace-nowrap">${lastSeenStr}</td>
        <td class="py-2.5 px-3 text-right">
          <div class="flex items-center justify-end gap-1.5">
            ${!isTrusted ? `
              <button onclick="window.confirmSocDevice('${devIdent}')" class="px-2 py-0.5 rounded bg-emerald-950 hover:bg-emerald-900 border border-emerald-700 text-emerald-300 font-mono text-[10px] font-bold cursor-pointer transition-all">✓ Confirm Trust</button>
            ` : ''}
            ${!isRevoked ? `
              <button onclick="window.revokeSocDevice('${devIdent}')" class="px-2 py-0.5 rounded bg-red-950 hover:bg-red-900 border border-red-700 text-red-300 font-mono text-[10px] font-bold cursor-pointer transition-all">Revoke Access</button>
            ` : `
              <span class="text-red-500 text-[10px] font-mono">REVOKED</span>
            `}
          </div>
        </td>
      </tr>
    `;
  });
  devTableHtml += `</tbody></table>`;
  container.innerHTML = devTableHtml;
};

// Filter Handlers
window.filterSocSessions = async function() {
  if (!window.cognisec) return;
  const searchInput = document.getElementById('soc-sessions-search');
  const statusSelect = document.getElementById('soc-sessions-status');
  const riskSelect = document.getElementById('soc-sessions-risk');
  const scopeSelect = document.getElementById('soc-sessions-scope');

  const search = searchInput ? searchInput.value.trim() : '';
  const status = statusSelect && statusSelect.value !== 'ALL' ? statusSelect.value : null;
  const risk = riskSelect && riskSelect.value !== 'ALL' ? riskSelect.value : null;
  const scope = scopeSelect ? scopeSelect.value : 'all';

  try {
    const sessions = await window.cognisec.fetchSocSessions(50, status, risk, search, scope);
    window._cachedSocSessions = sessions || [];
    window.renderSocSessionsTable(sessions || []);
    const sessionsCountBadge = document.getElementById('soc-sessions-count-badge');
    if (sessionsCountBadge) {
      sessionsCountBadge.textContent = `${(sessions || []).length} FILTERED`;
    }
  } catch (e) {
    console.error('Failed to filter sessions:', e);
  }
};

window.filterSocDevices = function(queue) {
  const container = document.getElementById('soc-device-queue-pills');
  if (container) {
    const pills = container.querySelectorAll('button');
    pills.forEach(p => {
      p.className = 'px-2.5 py-1 rounded-lg text-[10px] font-bold bg-black border border-red-900/60 text-slate-300 hover:bg-red-950/40 cursor-pointer transition-all';
    });
    const filterKey = queue === 'PENDING_CONFIRMATION' ? 'pending' : (queue === 'KNOWN_TEST' ? 'test' : queue.toLowerCase());
    const activeBtn = document.getElementById(`dev-filter-${filterKey}`);
    if (activeBtn) {
      activeBtn.className = 'px-2.5 py-1 rounded-lg text-[10px] font-bold bg-red-600 text-white cursor-pointer transition-all';
    }
  }

  const allDevices = window._cachedSocDevices || [];
  let filtered = allDevices;
  if (queue === 'ACTIVE') {
    filtered = allDevices.filter(d => d.is_active);
  } else if (queue === 'PENDING_CONFIRMATION') {
    filtered = allDevices.filter(d => d.trust_state === 'PENDING_CONFIRMATION');
  } else if (queue === 'TRUSTED') {
    filtered = allDevices.filter(d => d.trust_state === 'TRUSTED');
  } else if (queue === 'REVOKED') {
    filtered = allDevices.filter(d => d.trust_state === 'REVOKED');
  } else if (queue === 'KNOWN_TEST') {
    filtered = allDevices.filter(d => d.provenance === 'KNOWN_TEST');
  } else if (queue === 'INSUFFICIENT') {
    filtered = allDevices.filter(d => (d.trust_state !== 'TRUSTED' && d.trust_state !== 'REVOKED') || d.nickname === 'Identity not verified');
  }

  window.renderSocDevicesTable(filtered);
};

window.filterSocAlerts = async function(status) {
  const container = document.getElementById('soc-alert-status-pills');
  if (container) {
    const pills = container.querySelectorAll('button');
    pills.forEach(p => {
      p.className = 'px-2.5 py-0.5 rounded font-bold bg-black border border-red-900/60 text-slate-400 hover:bg-red-950/40 cursor-pointer';
    });
    const keyMap = { 'ALL': 'all', 'OPEN': 'open', 'REOPENED': 'reopened', 'ACKNOWLEDGED': 'ack', 'INVESTIGATING': 'inv', 'RESOLVED': 'res' };
    const activeBtn = document.getElementById(`alert-pill-${keyMap[status] || 'all'}`);
    if (activeBtn) {
      activeBtn.className = 'px-2.5 py-0.5 rounded font-bold bg-red-600 text-white cursor-pointer';
    }
  }

  try {
    const scopeSelect = document.getElementById('soc-alerts-scope-select');
    const scope = scopeSelect ? scopeSelect.value : 'all';
    const alerts = await window.cognisec.fetchSocAlerts(50, status === 'ALL' ? null : status, null, null, scope);
    window._cachedSocAlerts = alerts || [];
    window.renderSocAlertsList(alerts || []);
    const countEl = document.getElementById('soc-logs-alerts-count');
    if (countEl) countEl.textContent = `${(alerts || []).length} Alerts (${status || 'ALL'})`;
  } catch (e) {
    console.error('Failed to filter alerts:', e);
  }
};

window.onSocScopeChange = async function(target, scope) {
  if (!window.cognisec) return;
  if (target === 'alerts') {
    try {
      const alerts = await window.cognisec.fetchSocAlerts(50, '', '', null, scope);
      window._cachedSocAlerts = alerts || [];
      const openAlerts = (alerts || []).filter(a => a.status === 'OPEN');
      const overviewAlertsEl = document.getElementById('soc-overview-alerts');
      const overviewBadge = document.getElementById('soc-overview-alerts-badge');
      if (overviewBadge) overviewBadge.textContent = `${openAlerts.length} OPEN`;
      if (overviewAlertsEl) {
        if (openAlerts.length > 0) {
          overviewAlertsEl.innerHTML = '';
          openAlerts.forEach(al => {
            const timeStr = new Date(al.created_at).toLocaleTimeString('en-US', { hour12: false });
            const card = document.createElement('div');
            card.className = 'p-3.5 rounded-xl bg-red-950/30 border border-red-800/70 space-y-2 font-mono text-xs';
            card.innerHTML = `
              <div class="flex items-center justify-between">
                <div class="flex items-center gap-2">
                  <span class="px-2 py-0.5 rounded text-[10px] font-bold ${al.severity === 'CRITICAL' ? 'bg-red-600 text-white' : 'bg-amber-950 text-amber-300'}">${al.severity}</span>
                  ${al.is_simulated ? '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-950 text-purple-300 border border-purple-800">[SIMULATED SCENARIO]</span>' : ''}
                  <strong class="text-white font-bold">${escapeHtml(al.alert_type.replace(/_/g, ' '))}</strong>
                </div>
                <span class="text-slate-500 text-[10px]">[${timeStr}]</span>
              </div>
              <p class="text-slate-300 text-[11px] leading-relaxed">${escapeHtml(al.message)}</p>
              <div class="flex flex-wrap items-center justify-between pt-1 gap-2">
                <span class="text-slate-400 text-[10px]">App: <span class="text-white uppercase">${al.application}</span> &bull; Status: <span class="text-amber-400 font-bold">${al.status}</span></span>
                <button onclick="window.triageAlert(${al.id}, 'ACKNOWLEDGED')" class="px-2.5 py-1 rounded bg-amber-950 border border-amber-700 text-amber-300 hover:text-white text-[10px] font-bold cursor-pointer transition-all">Acknowledge</button>
              </div>
            `;
            overviewAlertsEl.appendChild(card);
          });
        } else {
          overviewAlertsEl.innerHTML = `<div class="p-6 text-center text-slate-500 font-mono text-xs">No active threats for selected scope. Zero-Trust perimeter secure.</div>`;
        }
      }
    } catch (e) {
      console.error('Failed to change alerts scope:', e);
    }
  } else if (target === 'events') {
    try {
      const events = await window.cognisec.fetchSocEvents(50, scope);
      const logsEl = document.getElementById('soc-live-logs');
      if (logsEl) {
        if (events && events.length > 0) {
          logsEl.innerHTML = '';
          events.slice(0, 15).forEach(ev => {
            const timeStr = new Date(ev.timestamp).toLocaleTimeString('en-US', { hour12: false });
            const isClean = ev.severity === 'LOW';
            const isCritical = ev.severity === 'CRITICAL' || ev.decision === 'TERMINATE_SESSION';
            const newLog = document.createElement('div');
            newLog.className = `p-3 rounded-xl bg-black/50 border ${isClean ? 'border-emerald-950' : (isCritical ? 'border-red-600 bg-red-950/20' : 'border-amber-950')} flex items-center justify-between font-mono text-[11px] animate-fade-in transition-all`;
            newLog.innerHTML = `
              <div class="flex items-center gap-3">
                <span class="${isClean ? 'text-emerald-400' : 'text-red-400'} font-bold">${isClean ? '🟢' : '🔴'} [${timeStr}]</span>
                ${ev.is_simulated ? '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-950 text-purple-300 border border-purple-800">[SIMULATED]</span>' : ''}
                <span class="text-white font-bold">${escapeHtml(ev.event_type.replace(/_/g, ' '))} (${(ev.application || 'PLATFORM').toUpperCase()})</span>
                <span class="text-slate-400 text-[10px]">&bull; User: ${escapeHtml(ev.user_name || 'Portal User')} &bull; Severity: <span class="${isClean ? 'text-emerald-400' : 'text-red-400'} font-bold">${ev.severity}</span></span>
              </div>
              <div class="flex items-center gap-2">
                <span class="px-2.5 py-0.5 ${isClean ? 'bg-emerald-950 text-emerald-400 border-emerald-800' : 'bg-red-950 text-red-400 border-red-800'} border rounded text-[10px] font-bold">${ev.decision}</span>
                ${ev.id ? `<button onclick="window.openIncidentInvestigation(${ev.id})" class="px-2 py-0.5 rounded bg-black border border-slate-700 text-slate-300 hover:text-white text-[10px] font-mono cursor-pointer transition-all">🔍 Inspect</button>` : ''}
              </div>
            `;
            logsEl.appendChild(newLog);
          });
        } else {
          logsEl.innerHTML = `<div class="p-8 text-center text-slate-500 font-mono text-xs">No events matching selected scope. Zero-Trust monitoring active.</div>`;
        }
      }
    } catch (e) {
      console.error('Failed to change events scope:', e);
    }
  }
};

window.loadSocAuditLogs = async function(actionFilter) {
  const container = document.getElementById('soc-audit-table-container');
  if (!container || !window.cognisec) return;
  try {
    container.innerHTML = `<div class="p-6 text-center text-slate-500 font-mono text-xs">Loading audit trail records...</div>`;
    const logs = await window.cognisec.fetchSocAuditLogs(actionFilter === 'ALL' ? null : actionFilter, 50);
    if (!logs || logs.length === 0) {
      container.innerHTML = `<div class="p-6 text-center text-slate-500 font-mono text-xs">No administrative actions logged yet.</div>`;
      return;
    }
    let html = `
      <table class="w-full text-left font-mono text-xs border-collapse">
        <thead>
          <tr class="border-b border-red-950 text-slate-400 text-[10px] uppercase">
            <th class="py-2.5 px-3">Timestamp</th>
            <th class="py-2.5 px-3">Administrator</th>
            <th class="py-2.5 px-3">Action</th>
            <th class="py-2.5 px-3">Target Resource</th>
            <th class="py-2.5 px-3">Outcome</th>
            <th class="py-2.5 px-3">Notes / Reason</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-red-950/40">
    `;
    logs.forEach(l => {
      const timeStr = new Date(l.timestamp).toLocaleString();
      const isSuccess = l.outcome === 'SUCCESS';
      html += `
        <tr class="hover:bg-red-950/10 transition-colors">
          <td class="py-2.5 px-3 text-slate-400 text-[11px] whitespace-nowrap">${timeStr}</td>
          <td class="py-2.5 px-3 text-white font-bold">${escapeHtml(l.operator_email || 'admin')}</td>
          <td class="py-2.5 px-3">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-red-950 text-red-300 border border-red-800">${escapeHtml(l.action)}</span>
          </td>
          <td class="py-2.5 px-3 text-slate-300 font-mono text-[11px]">${escapeHtml(l.target_resource_id ? `${l.target_resource_type}: ${l.target_resource_id}` : l.target_resource_type)}</td>
          <td class="py-2.5 px-3">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold ${isSuccess ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-red-950 text-red-400 border border-red-800'}">${l.outcome}</span>
          </td>
          <td class="py-2.5 px-3 text-slate-400 text-[11px]">${escapeHtml(l.reason || '—')}</td>
        </tr>
      `;
    });
    html += `</tbody></table>`;
    container.innerHTML = html;
  } catch (e) {
    container.innerHTML = `<div class="p-6 text-center text-red-400 font-mono text-xs">Failed to load audit logs: ${e.message}</div>`;
  }
};

window.loadSocAnalytics = async function(timeWindow) {
  ['24h', '7d', '30d'].forEach(w => {
    const btn = document.getElementById(`analytics-btn-${w}`);
    if (btn) {
      if (w === timeWindow) btn.className = 'px-3 py-1 rounded-lg text-[11px] font-bold bg-red-600 text-white cursor-pointer';
      else btn.className = 'px-3 py-1 rounded-lg text-[11px] font-bold bg-black border border-red-900/60 text-slate-300 hover:bg-red-950/40 cursor-pointer';
    }
  });

  if (!window.cognisec) return;
  try {
    const data = await window.cognisec.fetchSocAnalytics(timeWindow);
    if (!data) return;

    const authTotalEl = document.getElementById('analytics-stat-auth-total');
    const authRateEl = document.getElementById('analytics-stat-auth-rate');
    const allowEl = document.getElementById('analytics-stat-allow');
    const stepUpEl = document.getElementById('analytics-stat-stepup');
    const stepUpRateEl = document.getElementById('analytics-stat-stepup-rate');
    const restEl = document.getElementById('analytics-stat-restricted');
    const termEl = document.getElementById('analytics-stat-terminated');
    const alertsEl = document.getElementById('analytics-stat-alerts');
    const alertsRateEl = document.getElementById('analytics-stat-alerts-rate');

    if (authTotalEl) authTotalEl.textContent = Number(data.total_auth_attempts || 0).toLocaleString();
    if (authRateEl) authRateEl.textContent = `${data.auth_success_rate_percent || 0}% Success`;
    if (allowEl) allowEl.textContent = Number(data.risk_decisions?.allow || 0).toLocaleString();
    if (stepUpEl) stepUpEl.textContent = Number(data.step_up_challenges?.required || 0).toLocaleString();
    if (stepUpRateEl) stepUpRateEl.textContent = `${data.step_up_challenges?.verified || 0} Verified`;
    if (restEl) restEl.textContent = Number(data.session_enforcement?.restricted || 0).toLocaleString();
    if (termEl) termEl.textContent = Number(data.session_enforcement?.terminated || 0).toLocaleString();
    if (alertsEl) alertsEl.textContent = Number(data.alerts_lifecycle?.resolved || 0).toLocaleString();
    if (alertsRateEl) {
      const openCount = data.alerts_lifecycle?.opened || 0;
      const resCount = data.alerts_lifecycle?.resolved || 0;
      const rate = (openCount + resCount) > 0 ? Math.round((resCount / (openCount + resCount)) * 100) : 100;
      alertsRateEl.textContent = `${rate}% Triage Rate`;
    }
  } catch (e) {
    console.error('Failed to load analytics:', e);
  }
};

window.loadSocSystemHealth = async function() {
  if (!window.cognisec) return;
  try {
    const h = await window.cognisec.fetchSocSystemHealth();
    if (!h) return;

    const dbText = document.getElementById('health-db-status-text');
    const dbLat = document.getElementById('health-db-latency');
    const teleStatus = document.getElementById('health-telemetry-status');
    const lastEvent = document.getElementById('health-last-event');
    const lastEventSub = document.getElementById('health-last-event-sub');
    const activeSess = document.getElementById('health-active-sessions');

    if (dbText) dbText.textContent = h.database_connected ? 'CONNECTED' : 'OFFLINE';
    if (dbLat) dbLat.textContent = `Ping Latency: ${h.database_latency_ms} ms (Real DB)`;
    if (teleStatus) teleStatus.textContent = h.telemetry_pipeline_status || 'ACTIVE';
    if (lastEvent) lastEvent.textContent = h.last_event_timestamp ? new Date(h.last_event_timestamp).toLocaleTimeString() : 'None';
    if (activeSess) activeSess.textContent = `${h.active_sessions_count} Active`;

    // Dynamic Command Footer status indicator
    const footerText = document.getElementById('soc-engine-status-text');
    const footerDot = document.getElementById('soc-engine-status-dot');
    if (footerText && footerDot) {
      if (h.database_connected) {
        footerDot.className = 'w-2 h-2 rounded-full bg-emerald-400 animate-pulse';
        footerText.className = 'text-emerald-400 font-bold';
        footerText.textContent = `SOC ENGINE ONLINE • DB CONNECTED (${h.database_latency_ms}ms) • PIPELINE ${h.telemetry_pipeline_status || 'ACTIVE'}`;
      } else {
        footerDot.className = 'w-2 h-2 rounded-full bg-red-500';
        footerText.className = 'text-red-400 font-bold';
        footerText.textContent = 'SOC ENGINE STATUS • DATABASE DISCONNECTED';
      }
    }
  } catch (e) {
    console.error('Failed to load system health:', e);
    const footerText = document.getElementById('soc-engine-status-text');
    const footerDot = document.getElementById('soc-engine-status-dot');
    if (footerText && footerDot) {
      footerDot.className = 'w-2 h-2 rounded-full bg-amber-500';
      footerText.className = 'text-amber-400 font-bold';
      footerText.textContent = 'SOC ENGINE STATUS • HEALTH CHECK PENDING';
    }
  }
};

// Incident Investigation View
window.openIncidentInvestigation = async function(incidentId) {
  if (!window.cognisec) return;
  openModal('incident-investigation');
  const body = document.getElementById('inc-modal-body');
  const idBadge = document.getElementById('inc-modal-id-badge');
  const statusBadge = document.getElementById('inc-modal-status-badge');
  const sevBadge = document.getElementById('inc-modal-severity-badge');

  if (body) body.innerHTML = `<div class="p-12 text-center text-slate-500 font-mono text-xs">Correlating persistent identity, device, session, and behavioral vectors for incident #${incidentId}...</div>`;
  if (idBadge) idBadge.textContent = `ID: ${incidentId}`;

  try {
    const dossier = await window.cognisec.fetchSocIncident(incidentId);
    if (!dossier) {
      if (body) body.innerHTML = `<div class="p-8 text-center text-red-400 font-mono text-xs">Incident or correlated session not found.</div>`;
      return;
    }

    if (statusBadge) {
      statusBadge.textContent = dossier.status;
      statusBadge.className = `px-2 py-0.5 rounded text-[10px] font-bold ${dossier.status === 'RESOLVED' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-amber-950 text-amber-300 border border-amber-800'}`;
    }
    if (sevBadge) {
      sevBadge.textContent = dossier.severity;
      sevBadge.className = `px-2 py-0.5 rounded text-[10px] font-bold ${dossier.severity === 'CRITICAL' ? 'bg-red-600 text-white' : 'bg-amber-950 text-amber-300 border border-amber-800'}`;
    }

    const u = dossier.user || {};
    const d = dossier.device || {};
    const s = dossier.session || {};
    const r = dossier.risk_assessment || {};
    const b = dossier.behavioral_signals || {};
    const sigs = b.observed_signals || {};
    const base = b.user_baseline || {};
    const devMap = b.deviation_status || {};
    const timeline = dossier.related_timeline || [];
    const actions = dossier.admin_actions || [];

    const featuresDef = [
      { key: "typing_speed_wpm", name: "Typing Speed", unit: "WPM" },
      { key: "avg_flight_time_ms", name: "Flight Time", unit: "ms" },
      { key: "avg_dwell_time_ms", name: "Dwell Time", unit: "ms" },
      { key: "mouse_velocity_avg", name: "Mouse Velocity", unit: "px/s" },
      { key: "mouse_acceleration_avg", name: "Mouse Acceleration", unit: "px/s²" },
      { key: "mouse_curvature_entropy", name: "Curvature Entropy", unit: "bits" },
      { key: "click_frequency", name: "Click Frequency", unit: "clicks/s" },
      { key: "scroll_speed_avg", name: "Scroll Speed", unit: "px/s" },
      { key: "idle_duration_sec", name: "Idle Duration", unit: "s" },
      { key: "navigation_entropy", name: "Navigation Entropy", unit: "bits" }
    ];

    body.innerHTML = `
      <!-- Row 1: Correlated Identities (User, Session, Device) -->
      <div class="grid grid-cols-1 md:grid-cols-3 gap-3 font-mono text-xs">
        <!-- User Identity -->
        <div class="p-3.5 rounded-xl bg-black/70 border border-red-950 space-y-1">
          <span class="text-slate-400 text-[10px] uppercase font-bold flex items-center gap-1.5">
            <span>👤</span> Correlated User
          </span>
          <strong class="text-white block text-sm">${escapeHtml(u.name || 'Unknown User')}</strong>
          <div class="text-[11px] text-slate-300">${escapeHtml(u.email || 'No email')}</div>
          <div class="text-[10px] text-slate-500 pt-1">Role: <span class="text-slate-300 font-bold">${u.role || 'USER'}</span> &bull; Account: <span class="text-emerald-400 font-bold">${u.account_status || 'ACTIVE'}</span></div>
        </div>

        <!-- Session Context -->
        <div class="p-3.5 rounded-xl bg-black/70 border border-red-950 space-y-1">
          <span class="text-slate-400 text-[10px] uppercase font-bold flex items-center gap-1.5">
            <span>⚡</span> Correlated Session
          </span>
          <strong class="text-white block text-sm font-mono">${s.id ? escapeHtml(s.id.substring(0, 18)) + '...' : 'Direct Event'}</strong>
          <div class="text-[11px] text-slate-300">Status: <span class="text-emerald-400 font-bold">${s.status || 'ACTIVE'}</span> &bull; Risk: <span class="text-amber-300 font-bold">${s.current_risk_level || 'LOW'}</span></div>
          <div class="text-[10px] text-slate-500 pt-1">App: ${(s.application || dossier.application || 'PLATFORM').toUpperCase()} &bull; IP: ${escapeHtml(s.ip_address || '127.0.0.1')}</div>
        </div>

        <!-- Device Identity & Fingerprint -->
        <div class="p-3.5 rounded-xl bg-black/70 border border-red-950 space-y-1">
          <span class="text-slate-400 text-[10px] uppercase font-bold flex items-center gap-1.5">
            <span>💻</span> Device &amp; Browser Identity
          </span>
          <strong class="text-white block text-sm">${escapeHtml(d.nickname || 'Web Client')}</strong>
          <div class="text-[10px] text-slate-400 font-mono truncate" title="SHA-256 Client Browser Fingerprint">${escapeHtml(d.device_fingerprint || 'Unbound')}</div>
          <div class="text-[10px] text-slate-500 pt-1">Trust: <span class="${d.trust_state === 'TRUSTED' ? 'text-emerald-400' : 'text-amber-300'} font-bold">${d.trust_state || 'UNTRUSTED'}</span> &bull; OS: ${escapeHtml(d.os || 'OS')}</div>
        </div>
      </div>

      <!-- Row 2: Zero Trust Decision & Enforcement Assessment -->
      <div class="p-4 rounded-xl bg-black/80 border border-red-900/60 space-y-3 font-mono text-xs">
        <div class="flex items-center justify-between pb-2 border-b border-red-950">
          <div class="flex items-center gap-2">
            <span class="text-amber-400 font-bold">🛡️</span>
            <strong class="text-white uppercase tracking-wider text-xs">Zero Trust Risk Assessment &amp; Policy Decision</strong>
          </div>
          <span class="px-2 py-0.5 rounded text-[10px] font-bold ${r.risk_decision === 'ALLOW' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-red-950 text-red-400 border border-red-800'}">
            DECISION: ${r.risk_decision || 'ALLOW'}
          </span>
        </div>
        <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
          <div class="p-2.5 rounded bg-black/50 border border-red-950">
            <span class="text-slate-500 text-[10px] block">Observed Risk Score</span>
            <strong class="text-base text-white">${Number(r.risk_score || 0).toFixed(2)}</strong>
          </div>
          <div class="p-2.5 rounded bg-black/50 border border-red-950">
            <span class="text-slate-500 text-[10px] block">Anomaly Score</span>
            <strong class="text-base text-amber-300">${Number(r.anomaly_score || 0).toFixed(2)}</strong>
          </div>
          <div class="p-2.5 rounded bg-black/50 border border-red-950">
            <span class="text-slate-500 text-[10px] block">Enforcement Result</span>
            <strong class="text-base text-emerald-400">${r.enforcement_outcome || 'ACCESS_GRANTED'}</strong>
          </div>
          <div class="p-2.5 rounded bg-black/50 border border-red-950">
            <span class="text-slate-500 text-[10px] block">Step-Up Outcome</span>
            <strong class="text-base text-purple-300">${dossier.step_up_challenges?.length > 0 ? dossier.step_up_challenges[0].outcome : 'NONE'}</strong>
          </div>
        </div>
        <div class="text-[11px] text-slate-300 pt-1">
          <span class="text-slate-500">Decision Rationale:</span> ${escapeHtml(r.decision_reason || dossier.message || 'Evaluated under Zero Trust continuous verification policy.')}
        </div>
      </div>

      <!-- Row 3: 10 Behavioral Signals vs User Baseline -->
      <div class="p-4 rounded-xl bg-black/80 border border-red-950 space-y-3 font-mono text-xs">
        <div class="flex items-center justify-between pb-2 border-b border-red-950">
          <div class="flex items-center gap-2">
            <span class="text-purple-400 font-bold">🧠</span>
            <strong class="text-white uppercase tracking-wider text-xs">10-Dimensional Behavioral Signals vs Learned Baseline</strong>
          </div>
          <span class="text-[10px] text-slate-400">Baseline Status: <strong class="text-slate-200">${b.baseline_status || 'COLD_START'}</strong> (${b.baseline_samples || 0} Samples)</span>
        </div>
        <div class="grid grid-cols-2 sm:grid-cols-5 gap-2.5">
          ${featuresDef.map(f => {
            const obsVal = sigs[f.key];
            const hasObs = obsVal !== undefined && obsVal !== null;
            const meanVal = base.means && base.means[f.key];
            const stdVal = base.stds && base.stds[f.key];
            const status = devMap[f.key] || (hasObs ? 'NORMAL' : 'AWAITING BASELINE DATA');
            const isDev = status === 'HIGH DEVIATION' || status === 'ELEVATED';
            return `
              <div class="p-2.5 rounded-lg bg-black/50 border ${isDev ? 'border-amber-700 bg-amber-950/20' : 'border-red-950/60'} space-y-1">
                <span class="text-slate-400 text-[10px] block truncate" title="${f.name}">${f.name}</span>
                <strong class="${hasObs ? (isDev ? 'text-amber-300' : 'text-emerald-400') : 'text-slate-500'} text-xs block">
                  ${hasObs ? `${Number(obsVal).toFixed(2)} ${f.unit}` : '—'}
                </strong>
                <span class="text-[9px] text-slate-500 block truncate">
                  ${meanVal !== undefined && meanVal !== null ? `Base: ${Number(meanVal).toFixed(1)} ±${Number(stdVal || 0).toFixed(1)}` : 'No baseline'}
                </span>
                <span class="inline-block px-1.5 py-0.2 rounded text-[9px] font-bold ${isDev ? 'bg-amber-900 text-amber-200' : 'bg-slate-900 text-slate-400'}">${status}</span>
              </div>
            `;
          }).join('')}
        </div>
        <div class="text-[10px] text-slate-500 italic">
          * Private keystroke contents, passwords, OTPs, and cognitive security answers are cryptographically masked and never logged.
        </div>
      </div>

      <!-- Row 4: Chronological Correlated Timeline -->
      <div class="p-4 rounded-xl bg-black/80 border border-red-950 space-y-3 font-mono text-xs">
        <div class="flex items-center justify-between pb-2 border-b border-red-950">
          <div class="flex items-center gap-2">
            <span class="text-red-400 font-bold">⏱️</span>
            <strong class="text-white uppercase tracking-wider text-xs">Chronological Correlated Event Timeline</strong>
          </div>
          <span class="text-[10px] text-slate-500">${timeline.length} Events Correlated by User &amp; Session</span>
        </div>
        <div class="space-y-2 max-h-48 overflow-y-auto pr-1">
          ${timeline.length > 0 ? timeline.map(ev => {
            const timeStr = new Date(ev.timestamp).toLocaleTimeString();
            return `
              <div class="p-2.5 rounded bg-black/50 border border-red-950/60 flex items-center justify-between text-[11px]">
                <div class="flex items-center gap-2">
                  <span class="text-slate-500 text-[10px]">[${timeStr}]</span>
                  <strong class="text-white">${escapeHtml(ev.event_type.replace(/_/g, ' '))}</strong>
                  <span class="text-slate-400 text-[10px]">(${escapeHtml(ev.application || 'platform')})</span>
                </div>
                <div class="flex items-center gap-2">
                  <span class="px-2 py-0.5 rounded text-[9px] font-bold ${ev.severity === 'CRITICAL' ? 'bg-red-600 text-white' : 'bg-slate-900 text-slate-300'}">${ev.severity}</span>
                  <span class="px-2 py-0.5 rounded text-[9px] font-bold bg-black border border-slate-800 text-slate-300">${ev.decision}</span>
                </div>
              </div>
            `;
          }).join('') : '<div class="text-slate-500 text-center py-4">No correlated timeline events recorded.</div>'}
        </div>
      </div>

      <!-- Row 5: Administrative Triage & Incident Notes Controls -->
      <div class="p-4 rounded-xl bg-gradient-to-r from-red-950/40 via-black to-red-950/40 border border-red-800/60 space-y-3 font-mono text-xs">
        <div class="flex items-center justify-between pb-2 border-b border-red-950">
          <div class="flex items-center gap-2">
            <span class="text-red-400 font-bold">📝</span>
            <strong class="text-white uppercase tracking-wider text-xs">Incident Response &amp; Administrator Triage</strong>
          </div>
          <span class="text-[10px] text-slate-400">Authenticated SOC Administrator Action</span>
        </div>

        <form id="inc-triage-form" onsubmit="window.submitIncidentTriage(event, ${incidentId})" class="space-y-3">
          <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label class="text-slate-400 text-[11px] block mb-1">Update Status:</label>
              <select id="inc-triage-status" class="w-full px-3 py-1.5 rounded-lg bg-black border border-red-900/60 text-white text-xs focus:outline-none focus:border-red-500">
                <option value="OPEN" ${dossier.status === 'OPEN' ? 'selected' : ''}>OPEN</option>
                <option value="ACKNOWLEDGED" ${dossier.status === 'ACKNOWLEDGED' ? 'selected' : ''}>ACKNOWLEDGED</option>
                <option value="INVESTIGATING" ${dossier.status === 'INVESTIGATING' ? 'selected' : ''}>INVESTIGATING</option>
                <option value="RESOLVED" ${dossier.status === 'RESOLVED' ? 'selected' : ''}>RESOLVED</option>
                <option value="REOPENED" ${dossier.status === 'REOPENED' ? 'selected' : ''}>REOPENED</option>
              </select>
            </div>
            <div>
              <label class="text-slate-400 text-[11px] block mb-1">Assign Analyst:</label>
              <input id="inc-triage-assigned" type="email" value="${escapeHtml(dossier.assigned_to || '')}" placeholder="analyst@cognisec.ai" class="w-full px-3 py-1.5 rounded-lg bg-black border border-red-900/60 text-white text-xs focus:outline-none focus:border-red-500">
            </div>
            <div>
              <label class="text-slate-400 text-[11px] block mb-1">Resolution Reason (if resolving):</label>
              <input id="inc-triage-reason" type="text" value="${escapeHtml(dossier.resolution_reason || '')}" placeholder="e.g. False positive confirmed via OTP" class="w-full px-3 py-1.5 rounded-lg bg-black border border-red-900/60 text-white text-xs focus:outline-none focus:border-red-500">
            </div>
          </div>
          <div>
            <label class="text-slate-400 text-[11px] block mb-1">Investigation Notes &amp; Findings:</label>
            <textarea id="inc-triage-notes" rows="2" placeholder="Record technical forensic notes or rationale..." class="w-full px-3 py-1.5 rounded-lg bg-black border border-red-900/60 text-white text-xs focus:outline-none focus:border-red-500">${escapeHtml(dossier.notes || '')}</textarea>
          </div>
          <div class="flex items-center justify-between pt-1">
            <span class="text-[10px] text-slate-500">All lifecycle transitions are recorded in the security audit trail.</span>
            <button type="submit" class="px-4 py-1.5 rounded-xl bg-red-600 hover:bg-red-500 text-white font-bold text-xs uppercase tracking-wider cursor-pointer shadow-[0_0_15px_rgba(239,68,68,0.5)] transition-all">
              Save Triage Update →
            </button>
          </div>
        </form>
      </div>
    `;

  } catch (e) {
    if (body) body.innerHTML = `<div class="p-8 text-center text-red-400 font-mono text-xs">Failed to load incident dossier: ${e.message}</div>`;
  }
};

window.submitIncidentTriage = async function(event, incidentId) {
  if (event) event.preventDefault();
  const statusEl = document.getElementById('inc-triage-status');
  const assignedEl = document.getElementById('inc-triage-assigned');
  const reasonEl = document.getElementById('inc-triage-reason');
  const notesEl = document.getElementById('inc-triage-notes');

  const status = statusEl ? statusEl.value : 'ACKNOWLEDGED';
  const assignedTo = assignedEl ? assignedEl.value.trim() : null;
  const reason = reasonEl ? reasonEl.value.trim() : null;
  const notes = notesEl ? notesEl.value.trim() : null;

  if (status === 'RESOLVED' && !reason) {
    alert("Please provide a resolution reason when marking an incident as RESOLVED.");
    return;
  }

  try {
    await window.cognisec.triageSocAlert(incidentId, status, notes, assignedTo, reason);
    showNotificationToast("Incident Triaged", `Incident #${incidentId} status transitioned to ${status}.`, "success");
    await window.openIncidentInvestigation(incidentId);
    await loadSocDashboardData();
  } catch (e) {
    alert(`Failed to save triage update: ${e.message}`);
  }
};

window.triageQuickAlert = async function(alertId, newStatus) {
  try {
    await window.cognisec.triageSocAlert(alertId, newStatus, `Quick triage transition to ${newStatus}`);
    showNotificationToast("Alert Updated", `Alert #${alertId} updated to ${newStatus}.`, "success");
    await loadSocDashboardData();
  } catch (e) {
    alert(`Failed to update alert: ${e.message}`);
  }
};

window.triageResolvePrompt = async function(alertId) {
  const reason = prompt("Enter resolution reason for this incident (e.g., False positive, user verified, risk mitigated):");
  if (!reason || !reason.trim()) return;
  try {
    await window.cognisec.triageSocAlert(alertId, 'RESOLVED', 'Resolved via SOC dashboard control', null, reason.trim());
    showNotificationToast("Alert Resolved", `Alert #${alertId} marked as RESOLVED.`, "success");
    await loadSocDashboardData();
  } catch (e) {
    alert(`Failed to resolve alert: ${e.message}`);
  }
};

window.terminateSocSession = async function(sessionId) {
  if (!confirm(`Are you sure you want to terminate session ${sessionId}? This will immediately invalidate the session token and record an administrative audit entry.`)) return;
  try {
    await window.cognisec.terminateSocSession(sessionId);
    showNotificationToast("Session Terminated", `Session ${sessionId.substring(0, 12)}... terminated by SOC Administrator.`, "info");
    await loadSocDashboardData();
  } catch (e) {
    alert(`Failed to terminate session: ${e.message}`);
  }
};

window.revokeSocDevice = async function(deviceId) {
  if (!confirm(`Revoke trust for device ${deviceId}? All active sessions on this device will be immediately revoked.`)) return;
  try {
    await window.cognisec.revokeSocDevice(deviceId);
    showNotificationToast("Device Revoked", `Device ${deviceId} revoked by SOC Administrator.`, "warning");
    await loadSocDashboardData();
  } catch (e) {
    alert(`Failed to revoke device: ${e.message}`);
  }
};

window.confirmSocDevice = async function(deviceId) {
  try {
    await window.cognisec.updateDeviceTrust(deviceId, true);
    showNotificationToast("Device Confirmed", `Device ${deviceId} confirmed as TRUSTED by SOC Administrator.`, "success");
    await loadSocDashboardData();
  } catch (e) {
    alert(`Failed to confirm device: ${e.message}`);
  }
};

window.inspectUserBehavior = async function(userId) {
  if (!userId) return;
  const container = document.getElementById('soc-behavior-display');
  if (!container) return;

  try {
    const prof = await window.cognisec.fetchUserProfile(userId);
    if (!prof) {
      container.innerHTML = `<div class="p-6 text-center text-slate-500 font-mono text-xs">No behavioral profile found for user ID ${userId}.</div>`;
      return;
    }

    const mlColor = prof.ml_status === 'ML_READY' ? 'text-emerald-400 border-emerald-800 bg-emerald-950' : 'text-amber-300 border-amber-800 bg-amber-950';
    const means = prof.baseline_features?.means || {};
    const stds = prof.baseline_features?.stds || {};

    const featuresList = [
      { key: "typing_speed_wpm", name: "Typing Speed", unit: "WPM" },
      { key: "avg_flight_time_ms", name: "Keystroke Flight Time", unit: "ms" },
      { key: "avg_dwell_time_ms", name: "Key Dwell Time", unit: "ms" },
      { key: "mouse_velocity_avg", name: "Mouse Velocity", unit: "px/s" },
      { key: "mouse_acceleration_avg", name: "Mouse Acceleration", unit: "px/s²" },
      { key: "mouse_curvature_entropy", name: "Curvature Entropy", unit: "bits" },
      { key: "click_frequency", name: "Click Frequency", unit: "clicks/s" },
      { key: "scroll_speed_avg", name: "Scroll Speed", unit: "px/s" },
      { key: "idle_duration_sec", name: "Idle Duration", unit: "s" },
      { key: "navigation_entropy", name: "Navigation Entropy", unit: "bits" }
    ];

    container.innerHTML = `
      <div class="grid grid-cols-1 sm:grid-cols-3 gap-4 font-mono text-xs">
        <div class="p-4 rounded-xl bg-black/80 border border-red-950 space-y-1">
          <span class="text-slate-400 text-[10px]">Statistical Baseline</span>
          <strong class="text-white block text-sm font-bold">${prof.baseline_status}</strong>
          <span class="text-slate-500 text-[10px]">Confidence: ${Math.round(prof.maturity_confidence * 100)}%</span>
        </div>
        <div class="p-4 rounded-xl bg-black/80 border border-red-950 space-y-1">
          <span class="text-slate-400 text-[10px]">Trusted Telemetry Samples</span>
          <strong class="text-white block text-sm font-bold">${prof.sample_count} Samples</strong>
          <span class="text-slate-500 text-[10px]">Model Buffer: ${prof.model_sample_count || prof.sample_count}</span>
        </div>
        <div class="p-4 rounded-xl bg-black/80 border border-red-950 space-y-1">
          <span class="text-slate-400 text-[10px]">Machine Learning Model</span>
          <strong class="block text-sm font-bold ${mlColor}">${prof.ml_status}</strong>
          <span class="text-slate-500 text-[10px]">${prof.ml_status === 'ML_READY' ? 'Isolation Forest Active (100 Trees)' : 'Heuristic Welford Calibration'}</span>
        </div>
      </div>

      <div class="space-y-3">
        <div class="flex items-center justify-between">
          <h5 class="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">Learned 10-Dimensional Vector Means &amp; Standard Deviations:</h5>
          <span class="text-[10px] font-mono text-slate-500">${prof.sample_count > 0 ? 'Calibration Active' : 'Zero Baseline // Clean Cold-Start'}</span>
        </div>
        <div class="grid grid-cols-2 sm:grid-cols-5 gap-3 font-mono text-[11px]">
          ${featuresList.map(f => {
            const hasData = prof.sample_count > 0 && means[f.key] !== undefined && means[f.key] !== null;
            const meanVal = hasData ? Number(means[f.key]).toFixed(2) : null;
            const stdVal = hasData && stds[f.key] !== undefined ? Number(stds[f.key]).toFixed(2) : null;
            return `
              <div class="p-3 rounded-xl bg-black/50 border border-red-950/60 space-y-1">
                <span class="text-slate-400 block text-[10px] truncate" title="${f.name}">${f.name}</span>
                <strong class="${hasData ? 'text-emerald-400' : 'text-slate-500'} block text-xs font-bold">
                  ${hasData ? `${meanVal} ${f.unit}` : 'AWAITING DATA'}
                </strong>
                <span class="text-slate-500 text-[10px] block truncate">
                  ${hasData && stdVal !== null ? `σ: ±${stdVal}` : 'No variance data'}
                </span>
              </div>
            `;
          }).join('')}
        </div>
      </div>
    `;

  } catch (e) {
    container.innerHTML = `<div class="p-6 text-center text-red-400 font-mono text-xs">Error inspecting behavior: ${e.message}</div>`;
  }
};

window.resolveSocAlert = async function(alertId, status) {
  if (window.cognisec) {
    await window.cognisec.resolveAlert(alertId, status, `Alert marked as ${status} by SOC Administrator`);
    showNotificationToast("Alert Updated", `Alert #${alertId} updated to ${status}.`, "success");
    await loadSocDashboardData();
  }
};

window.filterSocEvents = async function(severity) {
  const container = document.getElementById('soc-all-events-container');
  if (!container || !window.cognisec) return;
  try {
    const events = await window.cognisec.fetchSocEvents(50, severity === 'ALL' ? null : severity);
    const countEl = document.getElementById('soc-logs-events-count');
    if (countEl) countEl.textContent = `${(events || []).length} Events Filtered (${severity})`;
    window.renderSocEventsTable(events || []);
  } catch (e) {
    container.innerHTML = `<div class="p-6 text-center text-red-400 font-mono text-xs">Failed to filter events: ${e.message}</div>`;
  }
};

window.switchDashboardTab = function(tabKey) {
  const tabs = ['overview', 'users', 'devices', 'behavior', 'logs', 'audit', 'health'];
  tabs.forEach(k => {
    const btn = document.getElementById(`dash-tab-${k}`);
    const content = document.getElementById(`dash-content-${k}`);
    if (btn) {
      if (k === tabKey) {
        btn.className = 'px-4 py-2 rounded-xl font-bold transition-all flex items-center gap-2 bg-red-600 text-white shadow-[0_0_15px_rgba(220,38,38,0.5)] cursor-pointer shrink-0';
      } else {
        btn.className = 'px-4 py-2 rounded-xl font-bold transition-all flex items-center gap-2 text-slate-400 hover:text-white hover:bg-red-950/40 cursor-pointer shrink-0';
      }
    }
    if (content) {
      if (k === tabKey) content.classList.remove('hidden');
      else content.classList.add('hidden');
    }
  });

  if (tabKey === 'audit') {
    window.loadSocAuditLogs('ALL');
  } else if (tabKey === 'health') {
    window.loadSocAnalytics('24h');
    window.loadSocSystemHealth();
  }
};

window.triggerSocRescan = async function() {
  const btn = document.getElementById('soc-rescan-btn');
  const origText = btn ? btn.innerHTML : '';
  if (btn) {
    btn.innerHTML = `<span>⚡ Analyzing...</span>`;
    btn.disabled = true;
  }

  try {
    const res = await window.cognisec.triggerSocRescan();
    if (res) {
      const sessEl = document.getElementById('rescan-eval-sessions');
      const devEl = document.getElementById('rescan-eval-devices');
      const alertEl = document.getElementById('rescan-eval-alerts');
      const timeEl = document.getElementById('rescan-eval-time');
      const findContainer = document.getElementById('rescan-findings-container');

      if (sessEl) sessEl.textContent = res.evaluated_sessions || 0;
      if (devEl) devEl.textContent = res.pending_devices || 0;
      if (alertEl) alertEl.textContent = res.open_critical_alerts || 0;
      if (timeEl) timeEl.textContent = new Date(res.executed_at).toLocaleString();

      if (findContainer) {
        if (res.findings && res.findings.length > 0) {
          findContainer.innerHTML = res.findings.map(f => `
            <div class="p-2.5 rounded-lg bg-black/60 border border-red-950/80 text-xs font-mono space-y-1">
              <div class="flex items-center justify-between">
                <span class="text-amber-400 font-bold">${escapeHtml(f.finding_type || 'FINDING')}</span>
                <span class="text-[10px] text-slate-500">${escapeHtml(f.severity || 'INFO')}</span>
              </div>
              <p class="text-slate-300 text-[11px]">${escapeHtml(f.description)}</p>
            </div>
          `).join('');
        } else {
          findContainer.innerHTML = `<div class="p-3 rounded-xl bg-black/50 border border-slate-900 text-slate-400">All evaluated zero-trust sessions, device bindings, and behavioral profiles operating within parameters.</div>`;
        }
      }

      openModal('soc-rescan-result');
    }
    await loadSocDashboardData();
    showNotificationToast("AI Re-Scan Completed", "Evaluated active sessions, devices, and open threats.", "success");
  } catch (e) {
    alert(`AI Re-Scan failed: ${e.message}`);
  } finally {
    if (btn) {
      btn.innerHTML = origText;
      btn.disabled = false;
    }
  }
};


// Detect available device information using browser-supported APIs and derive an evidence-supported label
window.getSuggestedDeviceLabel = function() {
  const ua = navigator.userAgent || '';
  const navPlatform = (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || '';
  const isMobile = (navigator.userAgentData && navigator.userAgentData.mobile) ||
    /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(ua);

  // Evidence-supported browser detection
  let browser = 'Browser';
  if (/Edg\//i.test(ua)) browser = 'Edge';
  else if (/Chrome\//i.test(ua) && !/Chromium|Edg\//i.test(ua)) browser = 'Chrome';
  else if (/Firefox\//i.test(ua)) browser = 'Firefox';
  else if (/Safari\//i.test(ua) && !/Chrome\//i.test(ua)) browser = 'Safari';
  else if (/Opera|OPR\//i.test(ua)) browser = 'Opera';

  // Evidence-supported OS/Platform detection
  if (/iPad/i.test(ua) || (navPlatform === 'MacIntel' && navigator.maxTouchPoints > 1)) {
    return `iPad · ${browser}`;
  }
  if (/iPhone/i.test(ua)) {
    return `iPhone · ${browser}`;
  }
  if (/Android/i.test(ua)) {
    return `Android · ${browser}`;
  }
  if (/Win/i.test(ua) || (/Win/i.test(navPlatform) && !/Macintosh/i.test(ua))) {
    return `Windows · ${browser}`;
  }
  if (/Mac/i.test(navPlatform) || /Macintosh|Mac OS X/i.test(ua)) {
    return `macOS · ${browser}`;
  }
  if (/CrOS/i.test(ua)) {
    return `Chromebook · ${browser}`;
  }
  if (/Linux/i.test(navPlatform) || /Linux/i.test(ua)) {
    return `Linux · ${browser}`;
  }
  return isMobile ? `Mobile · ${browser}` : `Desktop · ${browser}`;
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

    const nicknameInput = document.getElementById('login-device-nickname');
    if (nicknameInput && typeof window.getSuggestedDeviceLabel === 'function') {
      const suggestedLabel = window.getSuggestedDeviceLabel();
      nicknameInput.value = suggestedLabel;
      nicknameInput.placeholder = `e.g. ${suggestedLabel}`;
    }
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
    const locationEnabled = !shareLocBox || shareLocBox.checked;

    if (locationEnabled && navigator.geolocation) {
      if (btn) btn.innerHTML = `<span>Verifying device security & location...</span>`;

      // Check current browser permission state if Permissions API is available
      let permState = null;
      if (navigator.permissions && navigator.permissions.query) {
        try {
          const permStatus = await navigator.permissions.query({ name: 'geolocation' });
          permState = permStatus ? permStatus.state : null;
        } catch (e) {
          permState = null;
        }
      }

      // If browser already permanently denied permission, don't stall; skip to fallback
      if (permState !== 'denied') {
        try {
          // If permission is already granted, this retrieves position immediately without prompting.
          // If undecided ('prompt'), this allows native browser permission dialog to appear.
          // Timeout is capped (3500ms) to ensure login never waits indefinitely.
          locData = await window.cognisec.requestDeviceLocation(3500);
          if (!locData || locData.latitude == null) {
            locData = null; // Ensure no fabricated coordinates
          }
        } catch (locErr) {
          locData = null; // Continue with existing fallback on error/timeout
        }
      }
    }

    const nicknameInput = document.getElementById('login-device-nickname');
    const rawNickname = nicknameInput ? nicknameInput.value.trim() : '';
    const nickname = rawNickname || (typeof window.getSuggestedDeviceLabel === 'function' ? window.getSuggestedDeviceLabel() : null);

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
  const nicknameInput = document.getElementById('login-device-nickname');
  if (nicknameInput && typeof window.getSuggestedDeviceLabel === 'function') {
    const suggestedLabel = window.getSuggestedDeviceLabel();
    nicknameInput.value = suggestedLabel;
    nicknameInput.placeholder = `e.g. ${suggestedLabel}`;
  }
});
setTimeout(() => {
  syncAuthStateUI();
}, 250);

// 3. GENUINE BEHAVIORAL CALIBRATION & TELEMETRY STREAM
let consoleStartTime = Date.now();
let liveTelemetryMonitoringInterval = null;
let isDemoTelemetryMode = false;

window.toggleDemoTelemetryMode = function() {
  isDemoTelemetryMode = !isDemoTelemetryMode;
  const pill = document.getElementById('bt-demo-mode-pill');
  const btn = document.getElementById('bt-toggle-demo-btn');
  if (pill) {
    if (isDemoTelemetryMode) {
      pill.classList.remove('hidden');
    } else {
      pill.classList.add('hidden');
    }
  }
  if (btn) {
    btn.innerHTML = isDemoTelemetryMode
      ? '<span>🧪 Exit Demo Mode</span>'
      : '<span>🧪 Demo Mode</span>';
    btn.className = isDemoTelemetryMode
      ? 'px-2.5 py-1.5 rounded-lg bg-amber-950/80 hover:bg-amber-900 border border-amber-600 text-amber-300 text-xs font-semibold transition-all cursor-pointer flex items-center gap-1 shadow-[0_0_12px_rgba(245,158,11,0.3)]'
      : 'px-2.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 hover:border-amber-600 text-slate-300 hover:text-amber-300 text-xs font-semibold transition-all cursor-pointer flex items-center gap-1';
  }

  if (typeof addConsoleLog === 'function') {
    addConsoleLog(isDemoTelemetryMode 
      ? 'DEMO MODE ACTIVATED: Demonstration session enabled. Demonstrates capture without altering genuine baseline.'
      : 'DEMO MODE DEACTIVATED: Live user telemetry monitoring resumed.');
  }

  window.updateLiveBehavioralIndicators();
};

window.startLiveTelemetryMonitoring = function() {
  if (liveTelemetryMonitoringInterval) clearInterval(liveTelemetryMonitoringInterval);
  window.updateLiveBehavioralIndicators();
  liveTelemetryMonitoringInterval = setInterval(() => {
    window.updateLiveBehavioralIndicators();
  }, 1000);
};

window.stopLiveTelemetryMonitoring = function() {
  if (liveTelemetryMonitoringInterval) {
    clearInterval(liveTelemetryMonitoringInterval);
    liveTelemetryMonitoringInterval = null;
  }
};

let cachedLatestStoredLog = null;
let cachedBaselineProfile = null;

window.updateBehavioralFactorCoverage = function() {
  const panel = document.getElementById('section-factor-coverage');
  if (!panel) return;

  const liveMetrics = (window.cognisec && typeof window.cognisec.getLiveTelemetryMetrics === 'function')
    ? window.cognisec.getLiveTelemetryMetrics()
    : null;

  const latestLog = cachedLatestStoredLog;
  const profile = cachedBaselineProfile;

  const means = (profile && profile.baseline_features && profile.baseline_features.means) || {};
  const stds = (profile && profile.baseline_features && profile.baseline_features.stds) || {};
  const sampleCount = (profile && profile.sample_count) || 0;

  const factors = [
    // Typing Dynamics
    { key: 'typing_speed_wpm', unit: 'WPM', decimals: 1, minLive: 1.0 },
    { key: 'avg_flight_time_ms', unit: 'ms', decimals: 1, minLive: 1.0 },
    { key: 'avg_dwell_time_ms', unit: 'ms', decimals: 1, minLive: 1.0 },

    // Mouse Dynamics
    { key: 'mouse_velocity_avg', unit: 'px/s', decimals: 1, minLive: 1.0 },
    { key: 'mouse_acceleration_avg', unit: 'px/s²', decimals: 1, minLive: 1.0 },
    { key: 'mouse_curvature_entropy', unit: '', decimals: 2, minLive: 0.01 },
    { key: 'click_frequency', unit: 'clicks/s', decimals: 2, minLive: 0.01 },

    // Activity Dynamics
    { key: 'scroll_speed_avg', unit: 'px/s', decimals: 1, minLive: 1.0 },
    { key: 'idle_duration_sec', unit: 's', decimals: 1, minLive: 0.1 },

    // Navigation Dynamics
    { key: 'navigation_entropy', unit: '', decimals: 2, minLive: 0.01 }
  ];

  let activeCount = 0;

  factors.forEach(feat => {
    const statusEl = document.getElementById(`coverage-status-${feat.key}`);
    const valEl = document.getElementById(`coverage-val-${feat.key}`);
    const baseEl = document.getElementById(`coverage-base-${feat.key}`);

    // Check Live Active Status
    let isLive = false;
    let liveVal = null;
    if (liveMetrics && liveMetrics[feat.key] !== undefined && liveMetrics[feat.key] !== null) {
      const v = Number(liveMetrics[feat.key]);
      if (feat.key === 'idle_duration_sec') {
        if (window.cognisec && window.cognisec.hasRealInteraction && window.cognisec.lastInteractionTime) {
          isLive = true;
          liveVal = v;
        }
      } else if (v >= feat.minLive) {
        isLive = true;
        liveVal = v;
      }
    }

    // Check Stored Status (Backend persistence confirmed)
    let isStored = false;
    let storedVal = null;
    if (latestLog && latestLog[feat.key] !== undefined && latestLog[feat.key] !== null) {
      const sv = Number(latestLog[feat.key]);
      if (feat.key === 'idle_duration_sec') {
        if (latestLog.timestamp) {
          isStored = true;
          storedVal = sv;
        }
      } else if (sv >= feat.minLive) {
        isStored = true;
        storedVal = sv;
      }
    }

    // Determine status & latest measured value
    let statusText = 'AWAITING DATA';
    let statusClass = 'text-[9px] px-1.5 py-0.2 rounded bg-slate-900 text-slate-500 border border-slate-800 font-bold shrink-0';
    let displayedVal = '--';
    let valClass = 'font-extrabold text-slate-500 font-mono';

    if (isLive) {
      statusText = '● LIVE';
      statusClass = 'text-[9px] px-1.5 py-0.2 rounded bg-emerald-950/90 text-emerald-400 border border-emerald-800 font-bold shrink-0 shadow-[0_0_8px_rgba(16,185,129,0.25)]';
      displayedVal = `${liveVal.toFixed(feat.decimals)}${feat.unit ? ' ' + feat.unit : ''}`;
      valClass = 'font-extrabold text-white font-mono';
      activeCount++;
    } else if (isStored) {
      statusText = 'STORED';
      statusClass = 'text-[9px] px-1.5 py-0.2 rounded bg-cyan-950/90 text-cyan-300 border border-cyan-800 font-bold shrink-0';
      displayedVal = `${storedVal.toFixed(feat.decimals)}${feat.unit ? ' ' + feat.unit : ''}`;
      valClass = 'font-extrabold text-slate-200 font-mono';
      activeCount++;
    }

    if (statusEl) {
      statusEl.textContent = statusText;
      statusEl.className = statusClass;
    }

    if (valEl) {
      valEl.textContent = displayedVal;
      valEl.className = valClass;
    }

    // Baseline Mean and Standard Deviation
    if (baseEl) {
      if (sampleCount > 0 && means[feat.key] !== undefined) {
        const m = Number(means[feat.key]).toFixed(feat.decimals);
        const s = stds[feat.key] !== undefined ? Number(stds[feat.key]).toFixed(feat.decimals) : '1.0';
        baseEl.textContent = `${m} ± ${s}${feat.unit ? ' ' + feat.unit : ''}`;
        baseEl.className = 'font-mono text-slate-300';
      } else {
        baseEl.textContent = '--';
        baseEl.className = 'font-mono text-slate-500';
      }
    }
  });

  // Overall Coverage Count Badge
  const countBadge = document.getElementById('factor-coverage-count-badge');
  if (countBadge) {
    countBadge.textContent = `${activeCount} / 10 Active`;
    if (activeCount === 10) {
      countBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-800';
    } else if (activeCount > 0) {
      countBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-300 border border-amber-800';
    } else {
      countBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-slate-900 text-slate-400 border border-slate-800';
    }
  }
};

window.updateLiveBehavioralIndicators = function() {
  if (!window.cognisec) return;
  const metrics = window.cognisec.getLiveTelemetryMetrics ? window.cognisec.getLiveTelemetryMetrics() : null;
  if (!metrics) return;

  function updateMetricDisplay(metricKey, liveVal, unit, isLiveActive) {
    const liveEl = document.getElementById(`metric-${metricKey}-live`);
    const pillEl = document.getElementById(`pill-${metricKey}`);

    if (liveEl) {
      if (isLiveActive) {
        liveEl.textContent = typeof liveVal === 'number' ? liveVal.toFixed(1) : liveVal;
        liveEl.className = 'text-base font-extrabold text-white';
      } else {
        liveEl.textContent = '--';
        liveEl.className = 'text-base font-extrabold text-slate-500';
      }
    }

    if (pillEl) {
      if (isLiveActive) {
        pillEl.textContent = '● LIVE';
        pillEl.className = 'text-[9px] px-1.5 py-0.2 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 font-semibold';
      } else {
        pillEl.textContent = 'AWAITING';
        pillEl.className = 'text-[9px] px-1.5 py-0.2 rounded bg-slate-900 text-slate-400 border border-slate-800';
      }
    }
  }

  updateMetricDisplay('typing-wpm', metrics.typing_speed_wpm, 'WPM', metrics.typing_speed_wpm > 0);
  updateMetricDisplay('flight-time', metrics.avg_flight_time_ms, 'ms', metrics.avg_flight_time_ms > 0);
  updateMetricDisplay('dwell-time', metrics.avg_dwell_time_ms, 'ms', metrics.avg_dwell_time_ms > 0);
  updateMetricDisplay('mouse-vel', metrics.mouse_velocity_avg, 'px/s', metrics.mouse_velocity_avg > 0);
  updateMetricDisplay('mouse-acc', metrics.mouse_acceleration_avg, 'px/s²', metrics.mouse_acceleration_avg > 0);
  updateMetricDisplay('mouse-curv', metrics.mouse_curvature_entropy, 'entropy', metrics.mouse_curvature_entropy > 0);
  updateMetricDisplay('click-freq', metrics.click_frequency, 'clicks/s', metrics.click_frequency > 0);
  updateMetricDisplay('scroll-speed', metrics.scroll_speed_avg, 'px/s', metrics.scroll_speed_avg > 0);

  // Idle duration is continuously monitored if real interaction occurred
  const idleEl = document.getElementById('metric-idle-dur-live');
  const idlePill = document.getElementById('pill-idle-dur');
  const hasInteracted = window.cognisec && window.cognisec.hasRealInteraction;
  if (idleEl) {
    idleEl.textContent = hasInteracted && metrics.idle_duration_sec !== undefined ? metrics.idle_duration_sec.toFixed(1) : '--';
    idleEl.className = hasInteracted ? 'text-base font-extrabold text-white' : 'text-base font-extrabold text-slate-500';
  }
  if (idlePill) {
    if (hasInteracted) {
      idlePill.textContent = '● LIVE';
      idlePill.className = 'text-[9px] px-1.5 py-0.2 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 font-semibold';
    } else {
      idlePill.textContent = 'AWAITING';
      idlePill.className = 'text-[9px] px-1.5 py-0.2 rounded bg-slate-900 text-slate-400 border border-slate-800';
    }
  }

  updateMetricDisplay('nav-entropy', metrics.navigation_entropy, 'entropy', metrics.navigation_entropy > 0);

  // Update real collector stream status pill
  const collectorPill = document.getElementById('bt-collector-status-pill');
  if (collectorPill) {
    const isStreamActive = window.cognisec && window.cognisec.isAuthenticated() && !!window.cognisec.telemetryInterval;
    if (isStreamActive) {
      collectorPill.innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>Live Monitoring Active';
      collectorPill.className = 'px-2.5 py-0.5 rounded-full bg-emerald-950/80 text-emerald-400 border border-emerald-800/70 text-[11px] font-medium flex items-center gap-1.5';
    } else {
      collectorPill.innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-slate-500"></span>Monitoring Inactive';
      collectorPill.className = 'px-2.5 py-0.5 rounded-full bg-slate-900 text-slate-400 border border-slate-700 text-[11px] font-medium flex items-center gap-1.5';
    }
  }

  if (typeof window.updateBehavioralFactorCoverage === 'function') {
    window.updateBehavioralFactorCoverage();
  }
};

window.addEventListener('cognisec:telemetry_dispatched', () => {
  const modal = document.getElementById('modal-liveDemo');
  if (modal && !modal.classList.contains('hidden')) {
    if (typeof refreshBehavioralDashboard === 'function') {
      refreshBehavioralDashboard();
    }
  }
});

function formatDecisionLabel(decision) {
  if (!decision || decision === 'AWAITING DATA') return 'Awaiting Data';
  if (decision === 'STEP_UP_VERIFICATION' || decision === 'STEP_UP_REQUIRED') return 'Additional verification required';
  if (decision === 'ALLOW') return 'Access Granted';
  if (decision === 'RESTRICT') return 'Access Restricted';
  if (decision === 'TERMINATE_SESSION' || decision === 'TERMINATE') return 'Session Terminated';
  if (decision === 'OBSERVATION_PENDING') return 'Observation Pending';
  if (decision === 'EVALUATED') return 'Recorded & Evaluated';
  return decision;
}

window.refreshBehavioralDashboard = async function() {
  if (!window.cognisec || !window.cognisec.isAuthenticated()) return;

  // 1. Safe Masked Session Identifier
  const rawSessionId = window.cognisec.sessionId || localStorage.getItem('cognisec_session_id') || 'sess_default';
  const maskedSessionId = (rawSessionId && rawSessionId.length > 12)
    ? `${rawSessionId.substring(0, 8)}••••${rawSessionId.substring(rawSessionId.length - 4)}`
    : (rawSessionId || 'sess_unknown');

  const sessEl = document.getElementById('bt-session-id');
  if (sessEl) {
    sessEl.textContent = maskedSessionId;
    sessEl.title = `Active Session: ${rawSessionId}`;
  }

  // 2. Fetch User Behavioral Profile
  try {
    const profileRes = await window.cognisec.getBehaviorProfile();
    if (profileRes && profileRes.success && profileRes.data) {
      const p = profileRes.data;
      cachedBaselineProfile = p;
      const sampleCount = p.sample_count || 0;
      const modelSamples = p.model_sample_count !== undefined ? p.model_sample_count : sampleCount;
      const totalObs = p.total_observations !== undefined ? p.total_observations : sampleCount;
      const lastObsTs = p.last_observation_timestamp
        ? new Date(p.last_observation_timestamp).toLocaleTimeString()
        : (p.last_updated ? new Date(p.last_updated).toLocaleTimeString() : 'Awaiting collection');
      const lastUpdateTs = p.last_updated ? new Date(p.last_updated).toLocaleTimeString() : 'Initial start';

      // Profile Status
      const statusEl = document.getElementById('bt-profile-status');
      if (statusEl) {
        if (sampleCount === 0 || p.enrollment_status === 'NOT_ENROLLED') {
          statusEl.textContent = 'Setup Required';
          statusEl.className = 'text-amber-400 font-semibold block truncate text-xs mt-1';
        } else if (sampleCount < 5 || p.enrollment_status === 'ENROLLMENT_IN_PROGRESS') {
          statusEl.textContent = `In Progress (${sampleCount} of 5)`;
          statusEl.className = 'text-amber-300 font-semibold block truncate text-xs mt-1';
        } else {
          statusEl.textContent = 'Profile Ready (Baseline)';
          statusEl.className = 'text-emerald-400 font-semibold block truncate text-xs mt-1';
        }
      }

      // Total Observations
      const totalObsEl = document.getElementById('bt-total-obs');
      if (totalObsEl) {
        totalObsEl.textContent = `${totalObs} event${totalObs === 1 ? '' : 's'}`;
      }

      // Last Observation Timestamp
      const lastObsEl = document.getElementById('bt-last-obs-time');
      if (lastObsEl) {
        lastObsEl.textContent = lastObsTs;
      }

      // Normal Behavior Profile Sample Count
      const baselineSamplesEl = document.getElementById('bt-baseline-samples');
      if (baselineSamplesEl) {
        baselineSamplesEl.textContent = sampleCount === 0
          ? '0 / 5 (Not Started)'
          : `${sampleCount} / 5 (${sampleCount >= 5 ? 'Established' : 'Learning'})`;
      }

      // Last Baseline Update
      const lastUpdateEl = document.getElementById('bt-baseline-updated');
      if (lastUpdateEl) {
        lastUpdateEl.textContent = lastUpdateTs;
      }

      // Authoritative HUD Elements
      const hasObs = Boolean(p.total_observations && p.total_observations > 0);
      const anomEl = document.getElementById('bt-hud-anomaly-score');
      if (anomEl) {
        anomEl.textContent = (hasObs && p.anomaly_score !== undefined && p.anomaly_score !== null) ? Number(p.anomaly_score).toFixed(3) : '--';
        anomEl.className = hasObs ? 'text-base font-extrabold text-amber-300 font-mono' : 'text-base font-extrabold text-slate-500 font-mono';
      }
      const driftEl = document.getElementById('bt-hud-drift-status');
      if (driftEl) {
        if (!hasObs) {
          driftEl.textContent = 'AWAITING DATA';
          driftEl.className = 'text-[10px] font-semibold text-slate-400';
        } else if (p.is_anomaly) {
          driftEl.textContent = '⚠️ DRIFT DETECTED';
          driftEl.className = 'text-[10px] font-bold text-red-400';
        } else {
          driftEl.textContent = 'NORMAL';
          driftEl.className = 'text-[10px] font-semibold text-emerald-400';
        }
      }
      const riskEl = document.getElementById('bt-hud-risk-score');
      if (riskEl) {
        riskEl.textContent = (hasObs && p.latest_risk_score !== undefined && p.latest_risk_score !== null) ? Number(p.latest_risk_score).toFixed(3) : '--';
        riskEl.className = hasObs ? 'text-base font-extrabold text-emerald-400 font-mono' : 'text-base font-extrabold text-slate-500 font-mono';
      }
      const catEl = document.getElementById('bt-hud-risk-category');
      if (catEl) {
        if (!hasObs || !p.latest_risk_level) {
          catEl.textContent = 'AWAITING DATA';
          catEl.className = 'px-1.5 py-0.2 rounded text-[10px] font-semibold bg-slate-900 text-slate-400 border border-slate-700';
        } else {
          const cat = p.latest_risk_level;
          catEl.textContent = cat;
          catEl.className = cat === 'LOW'
            ? 'px-1.5 py-0.2 rounded text-[10px] font-semibold bg-emerald-950 text-emerald-300 border border-emerald-800'
            : cat === 'MEDIUM'
            ? 'px-1.5 py-0.2 rounded text-[10px] font-semibold bg-amber-950 text-amber-300 border border-amber-800'
            : 'px-1.5 py-0.2 rounded text-[10px] font-semibold bg-red-950 text-red-300 border border-red-800';
        }
      }
      const decEl = document.getElementById('bt-hud-decision');
      if (decEl) {
        if (!hasObs || !p.latest_decision) {
          decEl.textContent = 'Awaiting Data';
          decEl.className = 'px-2 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-700 text-xs font-semibold inline-block';
        } else {
          const dec = p.latest_decision;
          decEl.textContent = formatDecisionLabel(dec);
          decEl.className = dec === 'ALLOW'
            ? 'px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-xs font-semibold inline-block'
            : 'px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800 text-xs font-semibold inline-block';
        }
      }
      const trainGuardEl = document.getElementById('bt-hud-training-eligibility');
      if (trainGuardEl) {
        if (!hasObs) {
          trainGuardEl.textContent = 'Awaiting Data';
          trainGuardEl.className = 'text-xs font-semibold text-slate-400';
        } else {
          const isEligible = (p.latest_decision === 'ALLOW' && (p.latest_risk_score || 0) < 0.30);
          trainGuardEl.textContent = isEligible ? 'Active (Protected)' : 'Paused (Review Required)';
          trainGuardEl.className = isEligible ? 'text-xs font-semibold text-emerald-400' : 'text-xs font-semibold text-amber-300';
        }
      }

      // Self-Explaining Risk Guidance Banner
      const riskSummaryEl = document.getElementById('bt-risk-status-summary');
      const riskDetailEl = document.getElementById('bt-risk-status-detail');
      const riskActionEl = document.getElementById('bt-risk-action-required');
      const riskIconEl = document.getElementById('bt-risk-status-icon');

      if (riskSummaryEl && riskDetailEl && riskActionEl) {
        if (!hasObs) {
          if (riskIconEl) riskIconEl.textContent = 'ℹ️';
          riskSummaryEl.textContent = 'Awaiting behavioral activity';
          riskSummaryEl.className = 'font-bold text-slate-300';
          riskDetailEl.textContent = 'No behavioral telemetry has been recorded yet. Set up your behavior profile below or continue using the portal normally.';
          riskActionEl.textContent = 'Set up your behavior profile below to establish normal baseline';
          riskActionEl.className = 'font-semibold text-amber-300';
        } else {
          const dec = p.latest_decision || 'ALLOW';
          const isAnomaly = Boolean(p.is_anomaly);

          if (dec === 'STEP_UP_VERIFICATION' || dec === 'STEP_UP_REQUIRED') {
            if (riskIconEl) riskIconEl.textContent = '⚠️';
            riskSummaryEl.textContent = 'Additional verification required';
            riskSummaryEl.className = 'font-bold text-amber-400';
            const reasonStr = p.step_up_reason || p.user_message || (isAnomaly ? 'Unusual typing patterns and interaction kinematics detected that deviate from your normal baseline.' : 'Current security risk level requires secondary verification.');
            riskDetailEl.textContent = reasonStr;
            riskActionEl.textContent = 'Action Required: Complete additional verification challenge to verify your identity';
            riskActionEl.className = 'font-semibold text-amber-300';
          } else if (dec === 'RESTRICT') {
            if (riskIconEl) riskIconEl.textContent = '🚫';
            riskSummaryEl.textContent = 'Access restricted';
            riskSummaryEl.className = 'font-bold text-red-400';
            riskDetailEl.textContent = p.user_message || 'Behavioral telemetry indicates significant deviation from normal patterns. Sensitive operations are locked.';
            riskActionEl.textContent = 'Action Required: Re-verify identity or contact your administrator';
            riskActionEl.className = 'font-semibold text-red-400';
          } else if (dec === 'TERMINATE_SESSION' || dec === 'TERMINATE') {
            if (riskIconEl) riskIconEl.textContent = '🛑';
            riskSummaryEl.textContent = 'Session terminated';
            riskSummaryEl.className = 'font-bold text-red-400';
            riskDetailEl.textContent = p.user_message || 'Critical behavioral deviation detected. Session terminated to safeguard account integrity.';
            riskActionEl.textContent = 'Action Required: Log in again with primary credentials';
            riskActionEl.className = 'font-semibold text-red-400';
          } else {
            if (riskIconEl) riskIconEl.textContent = '✓';
            riskSummaryEl.textContent = 'Normal activity — access secure';
            riskSummaryEl.className = 'font-bold text-emerald-400';
            riskDetailEl.textContent = isAnomaly
              ? 'Minor variance detected, but overall risk score remains within acceptable normal thresholds.'
              : 'Interaction patterns match your established behavior profile. Risk score is within normal parameters.';
            riskActionEl.textContent = 'None — your session is active and protected';
            riskActionEl.className = 'font-semibold text-emerald-400';
          }
        }
      }

      // Baseline Stored Features (Means & Stds)
      const means = (p.baseline_features && p.baseline_features.means) || {};
      const stds = (p.baseline_features && p.baseline_features.stds) || {};

      function renderBaseVal(elementId, featureKey, unit) {
        const el = document.getElementById(elementId);
        if (!el) return;
        if (sampleCount > 0 && means[featureKey] !== undefined) {
          const mVal = Number(means[featureKey]).toFixed(1);
          const sVal = stds[featureKey] !== undefined ? Number(stds[featureKey]).toFixed(1) : '1.0';
          el.textContent = `${mVal} ± ${sVal} ${unit}`;
          el.className = 'text-slate-300 font-semibold';
        } else {
          el.textContent = 'Awaiting baseline';
          el.className = 'text-slate-500 italic';
        }
      }

      renderBaseVal('metric-typing-wpm-base', 'typing_speed_wpm', 'WPM');
      renderBaseVal('metric-flight-time-base', 'avg_flight_time_ms', 'ms');
      renderBaseVal('metric-dwell-time-base', 'avg_dwell_time_ms', 'ms');
      renderBaseVal('metric-mouse-vel-base', 'mouse_velocity_avg', 'px/s');
      renderBaseVal('metric-mouse-acc-base', 'mouse_acceleration_avg', 'px/s²');
      renderBaseVal('metric-mouse-curv-base', 'mouse_curvature_entropy', '');
      renderBaseVal('metric-click-freq-base', 'click_frequency', 'c/s');
      renderBaseVal('metric-scroll-speed-base', 'scroll_speed_avg', 'px/s');
      renderBaseVal('metric-idle-dur-base', 'idle_duration_sec', 's');
      renderBaseVal('metric-nav-entropy-base', 'navigation_entropy', '');

      // Calibration Studio Samples Progress & Readiness
      const calibCount = document.getElementById('calibration-samples-count');
      const calibBar = document.getElementById('calibration-samples-bar');
      const calibReadiness = document.getElementById('calibration-profile-readiness');

      if (calibCount) {
        calibCount.textContent = `${Math.min(5, sampleCount)} of 5 required`;
      }
      if (calibBar) {
        const pct = Math.min(100, Math.round((sampleCount / 5) * 100));
        calibBar.style.width = `${pct}%`;
        calibBar.className = pct >= 100
          ? 'bg-emerald-500 h-2 rounded-full transition-all duration-300'
          : 'bg-amber-500 h-2 rounded-full transition-all duration-300';
      }
      if (calibReadiness) {
        if (sampleCount === 0) {
          calibReadiness.textContent = 'Profile Setup Required';
          calibReadiness.className = 'text-[11px] font-semibold text-amber-400';
        } else if (sampleCount < 5) {
          calibReadiness.textContent = `Profile Setup in Progress (${5 - sampleCount} more sample${5 - sampleCount === 1 ? '' : 's'} needed)`;
          calibReadiness.className = 'text-[11px] font-semibold text-amber-300';
        } else {
          calibReadiness.textContent = '✓ Behavior Profile Ready';
          calibReadiness.className = 'text-[11px] font-semibold text-emerald-400';
        }
      }

      // Progress Bars (Expandable section)
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

      const badge = document.getElementById('calibration-maturity-badge');
      if (badge) {
        if (sampleCount === 0) {
          badge.textContent = 'Profile Setup Required';
          badge.className = 'px-2.5 py-1 rounded-lg bg-amber-950/80 text-amber-300 border border-amber-800 text-xs font-semibold self-start sm:self-auto';
        } else if (sampleCount < 5) {
          badge.textContent = `Profile in Progress (${sampleCount} of 5 samples)`;
          badge.className = 'px-2.5 py-1 rounded-lg bg-amber-950/80 text-amber-300 border border-amber-800 text-xs font-semibold self-start sm:self-auto';
        } else if (modelSamples < 25) {
          badge.textContent = '✓ Behavior Profile Ready';
          badge.className = 'px-2.5 py-1 rounded-lg bg-emerald-950/80 text-emerald-300 border border-emerald-700 text-xs font-semibold self-start sm:self-auto';
        } else {
          badge.textContent = '✓ Behavior Profile Ready (Model Trained)';
          badge.className = 'px-2.5 py-1 rounded-lg bg-emerald-950/80 text-emerald-300 border border-emerald-600 text-xs font-semibold self-start sm:self-auto';
        }
      }
    }
  } catch (err) {
    console.warn('[COGNISEC-AI] Failed to fetch profile:', err);
  }

  // 3. Fetch Recent Behavior Logs for Timeline
  try {
    const logsRes = await window.cognisec.getBehaviorLogs(20);
    const tbody = document.getElementById('bt-timeline-tbody');
    const countBadge = document.getElementById('bt-timeline-count-badge');

    if (logsRes && logsRes.success && Array.isArray(logsRes.data)) {
      const logs = logsRes.data;
      cachedLatestStoredLog = logs.length > 0 ? logs[0] : null;
      if (countBadge) countBadge.textContent = `${logs.length} event${logs.length === 1 ? '' : 's'}`;

      if (tbody) {
        if (logs.length === 0) {
          tbody.innerHTML = `
            <tr>
              <td colspan="5" class="py-6 text-center text-slate-500 italic font-sans">
                No behavioral events recorded yet. Interact or complete calibration to establish profile.
              </td>
            </tr>
          `;
        } else {
          tbody.innerHTML = logs.map(log => {
            const timeStr = new Date(log.timestamp).toLocaleTimeString();
            let parsed = {};
            if (log.raw_feature_json) {
              try { parsed = JSON.parse(log.raw_feature_json); } catch (_) {}
            }

            const decision = parsed.decision || 'EVALUATED';
            const riskScore = parsed.risk_score !== undefined ? Number(parsed.risk_score).toFixed(3) : '--';
            const isTrusted = parsed.is_trusted === true;

            // Determine dominant signal in this observation
            let eventIcon = '⌨️';
            let eventLabel = 'Typing Patterns';
            if (log.typing_speed_wpm > 0) {
              eventIcon = '⌨️';
              eventLabel = 'Typing Patterns';
            } else if (log.mouse_velocity_avg > 0 || log.mouse_curvature_entropy > 0) {
              eventIcon = '🖱️';
              eventLabel = 'Mouse Movement';
            } else if (log.scroll_speed_avg > 0) {
              eventIcon = '📜';
              eventLabel = 'Activity Patterns';
            } else {
              eventIcon = '⏱️';
              eventLabel = 'Navigation Patterns';
            }

            const safeSummary = `WPM: ${log.typing_speed_wpm} | Flight: ${log.avg_flight_time_ms}ms | Mouse: ${log.mouse_velocity_avg}px/s | Idle: ${log.idle_duration_sec}s`;
            const formattedDec = formatDecisionLabel(decision);

            return `
              <tr class="hover:bg-red-950/20 transition-colors">
                <td class="py-2 px-3 text-slate-300 font-mono whitespace-nowrap">${timeStr}</td>
                <td class="py-2 px-3 whitespace-nowrap">
                  <span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-black/60 border border-slate-800 text-slate-200 text-[10px] font-medium">
                    <span>${eventIcon}</span>
                    <span>${eventLabel}</span>
                  </span>
                </td>
                <td class="py-2 px-3 text-slate-400 font-mono text-[10px] truncate max-w-xs" title="${safeSummary}">
                  ${safeSummary}
                </td>
                <td class="py-2 px-3 whitespace-nowrap">
                  <span class="text-xs font-semibold ${decision === 'ALLOW' ? 'text-emerald-400' : 'text-amber-400'}">${formattedDec}</span>
                  <span class="text-[10px] text-slate-500 font-mono ml-1">(${riskScore})</span>
                </td>
                <td class="py-2 px-3 text-right whitespace-nowrap">
                  <span class="text-[9px] px-1.5 py-0.5 rounded font-medium ${isTrusted ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-slate-900 text-slate-400 border border-slate-800'}">
                    ${isTrusted ? 'Profile Baseline' : 'Recorded'}
                  </span>
                </td>
              </tr>
            `;
          }).join('');
        }
      }
    }
  } catch (err) {
    console.warn('[COGNISEC-AI] Failed to fetch behavior logs:', err);
  }

  if (typeof window.updateBehavioralFactorCoverage === 'function') {
    window.updateBehavioralFactorCoverage();
  }
};

window.refreshMaturityProgress = window.refreshBehavioralDashboard;

window.handleConsoleTyping = function(e) {
  const targetPrompt = "The zero trust security architecture verifies every continuous behavioral signal without storing private keystrokes.";
  const val = e.target.value;
  const chars = val.length;

  // 1. Progress calculation against neutral calibration sentence
  const progText = document.getElementById('calibration-progress-text');
  if (progText) {
    progText.textContent = `${chars} / ${targetPrompt.length} characters`;
    if (chars >= targetPrompt.length) {
      progText.className = 'text-emerald-400 font-bold';
    } else {
      progText.className = 'text-amber-400 font-bold';
    }
  }

  // 2. Extract genuine browser-measured physical timing dynamics
  window.updateLiveBehavioralIndicators();

  // 3. Dispatch genuine telemetry burst to FastAPI on 15-character cadence
  if (chars % 15 === 0 && chars > 0) {
    if (window.cognisec && window.cognisec.sessionToken) {
      window.cognisec.sendBehaviorTelemetry().then(res => {
        if (res && res.success && res.data) {
          const d = res.data;
          const riskDisplay = (d.risk_score !== undefined && d.risk_score !== null) ? d.risk_score.toFixed(3) : 'Protected';
          addConsoleLog(`Telemetry Stream Sample Transmitted (Decision: ${formatDecisionLabel(d.decision)} | Risk: ${riskDisplay})`);
          if (typeof refreshBehavioralDashboard === 'function') {
            refreshBehavioralDashboard();
          }
        } else if (res && !res.success) {
          addConsoleLog(`Telemetry Notice: ${res.error}`);
        }
      }).catch(err => {
        addConsoleLog(`Telemetry Network Notice: ${err.message}`);
      });
    }
  }
};

function addConsoleLog(text) {
  const logContainer = document.getElementById('console-event-log');
  if (!logContainer) return;
  const timeStr = new Date().toLocaleTimeString();
  const div = document.createElement('div');
  div.className = 'p-2 rounded bg-black/60 border border-slate-900 text-emerald-300 font-mono text-[11px]';
  div.textContent = `> ${timeStr} - ${text}`;
  logContainer.prepend(div);
}

window.runConsoleVerification = async function() {
  const btn = document.getElementById('btn-console-verify');
  const authBadge = document.getElementById('badge-auth-state');
  const feedbackEl = document.getElementById('calibration-user-feedback');

  if (btn) {
    btn.textContent = 'Submitting Calibration Sample...';
    btn.disabled = true;
  }
  if (feedbackEl) {
    feedbackEl.textContent = 'Transmitting timing patterns to security engine...';
    feedbackEl.className = 'text-xs font-medium text-slate-400 block';
  }

  addConsoleLog('Transmitting behavioral calibration sample to backend (POST /api/behavior/events)...');

  try {
    const res = window.cognisec ? await window.cognisec.sendBehaviorTelemetry() : null;
    if (res && res.success && res.data) {
      const d = res.data;
      const riskDisplay = (d.risk_score !== undefined && d.risk_score !== null) ? d.risk_score.toFixed(3) : 'Protected';
      addConsoleLog(`Backend Ingestion Confirmed: Decision=${formatDecisionLabel(d.decision)} | Risk=${riskDisplay}`);
      if (authBadge) {
        authBadge.textContent = d.decision === 'ALLOW' ? '✓ Sample Ingested' : '⚠️ ' + formatDecisionLabel(d.decision);
        authBadge.className = d.decision === 'ALLOW'
          ? 'px-2 py-0.5 text-[10px] bg-emerald-950 text-emerald-400 border border-emerald-800 rounded font-bold'
          : 'px-2 py-0.5 text-[10px] bg-amber-950 text-amber-400 border border-amber-800 rounded font-bold';
      }
      if (btn) {
        btn.textContent = 'Sample Recorded Successfully ✓';
        setTimeout(() => {
          if (btn) {
            btn.textContent = 'Submit Calibration Sample';
            btn.disabled = false;
          }
        }, 2000);
      }
      if (feedbackEl) {
        feedbackEl.textContent = 'Sample recorded successfully and added to your behavior profile.';
        feedbackEl.className = 'text-xs font-semibold text-emerald-400 block';
      }
      if (typeof refreshBehavioralDashboard === 'function') {
        await refreshBehavioralDashboard();
      }
    } else {
      const errMsg = (res && res.error) || 'Sample submission failed';
      addConsoleLog(`Submission Error: ${errMsg}`);
      if (authBadge) {
        authBadge.textContent = 'Submission Failed';
        authBadge.className = 'px-2 py-0.5 text-[10px] bg-red-950 text-red-400 border border-red-800 rounded font-bold';
      }
      if (btn) {
        btn.textContent = 'Submission Failed - Retry';
        btn.disabled = false;
      }
      if (feedbackEl) {
        feedbackEl.textContent = `Unable to record sample: ${errMsg}. Please try again.`;
        feedbackEl.className = 'text-xs font-semibold text-red-400 block';
      }
    }
  } catch (err) {
    addConsoleLog(`Network Error: ${err.message}`);
    if (btn) {
      btn.textContent = 'Network Error - Retry';
      btn.disabled = false;
    }
    if (feedbackEl) {
      feedbackEl.textContent = `Network error: ${err.message}. Please try again.`;
      feedbackEl.className = 'text-xs font-semibold text-red-400 block';
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
let _guestDemoNotifRead = false;
let _lastAuthUserId = null;

window._resetNotificationGuestState = function() {
  _guestDemoNotifRead = false;
  _lastAuthUserId = null;
};

function _escapeHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

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
  const listEl = document.getElementById('notif-list-container');
  const badge = document.getElementById('notif-badge');
  const countBadge = document.getElementById('notif-count-badge');
  const bellBtn = document.getElementById('notif-bell-btn');

  // Keep bell icon visible always
  if (bellBtn) {
    bellBtn.classList.remove('hidden');
  }

  // CASE 1: UNLOGGED / GUEST MODE
  const isAuth = Boolean(window.cognisec && window.cognisec.isAuthenticated());
  if (!isAuth) {
    _lastAuthUserId = null;

    // Update bell badge for guest demo
    if (badge) {
      if (!_guestDemoNotifRead) {
        badge.textContent = '1';
        badge.classList.remove('hidden');
        badge.classList.add('bg-red-600', 'animate-pulse');
      } else {
        badge.textContent = '0';
        badge.classList.add('hidden');
        badge.classList.remove('animate-pulse');
      }
    }

    // Update header count badge for guest demo
    if (countBadge) {
      if (!_guestDemoNotifRead) {
        countBadge.textContent = '1 unread (Demo)';
        countBadge.className = 'px-1.5 py-0.5 bg-amber-950 border border-amber-800 text-amber-300 text-[10px] rounded font-bold';
      } else {
        countBadge.textContent = '0 unread (Demo)';
        countBadge.className = 'px-1.5 py-0.5 bg-slate-900 border border-slate-700 text-slate-400 text-[10px] rounded font-bold';
      }
    }

    if (!listEl) return;

    if (_guestDemoNotifRead) {
      listEl.innerHTML = `
        <div class="p-4 rounded-xl bg-black/60 border border-red-950 text-center text-xs text-slate-400 font-mono space-y-1">
          <div class="text-xs font-semibold text-slate-300">✓ All demo notifications marked as read.</div>
          <div class="text-[10px] text-slate-500">Sign in to view real-time security telemetry for your account.</div>
        </div>
      `;
    } else {
      listEl.innerHTML = `
        <div class="p-3.5 rounded-xl bg-black/80 border border-amber-900/60 shadow-[0_0_15px_rgba(245,158,11,0.15)] space-y-2">
          <div class="flex items-center justify-between gap-2">
            <div class="flex items-center gap-1.5">
              <span class="px-1.5 py-0.5 rounded text-[9px] font-bold bg-amber-950 text-amber-300 border border-amber-800 tracking-wider font-mono">DEMO PREVIEW</span>
              <span class="text-xs font-bold text-white">New Login Detected</span>
            </div>
            <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-300 border border-amber-800 animate-pulse font-mono">PENDING CONFIRMATION</span>
          </div>
          <p class="text-xs text-slate-300 leading-relaxed font-sans">
            An unrecognized device login attempt was registered for <strong>Boomika Ram</strong> from <span class="text-amber-300 font-mono font-bold">Bengaluru, IN (MacBook Pro M3 • IP 103.21.124.9)</span>.
          </p>
          <div class="text-[10px] font-mono text-slate-400 space-y-0.5">
            <div><span class="text-slate-500">Location:</span> Bengaluru, IN (Simulated Network)</div>
            <div><span class="text-slate-500">Timestamp:</span> Just Now (Demo Mode)</div>
          </div>
          <div class="flex items-center justify-between pt-1 border-t border-red-950/60">
            <span class="text-[10px] text-amber-400 font-mono">📧 Demo Alert: Simulated Dispatch</span>
            <button onclick="handleMarkNotificationRead()" class="text-[10px] text-slate-500 hover:text-slate-300 underline cursor-pointer">
              Mark as read
            </button>
          </div>
          <div id="notif-action-buttons" class="pt-2">
            <div class="text-[11px] text-amber-300 font-bold pb-1.5 text-center font-mono">Was this login authorized by you?</div>
            <div class="grid grid-cols-2 gap-2">
              <button
                onclick="handleNotificationResponse(null, 'yes')"
                class="py-2 px-3 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-[11px] uppercase tracking-wider transition-all cursor-pointer flex items-center justify-center gap-1 shadow-[0_0_12px_rgba(52,211,153,0.3)] font-mono"
              >
                ✓ Yes, This Was Me
              </button>
              <button
                onclick="handleNotificationResponse(null, 'no')"
                class="py-2 px-3 rounded-lg bg-red-600 hover:bg-red-500 text-white font-bold text-[11px] uppercase tracking-wider transition-all cursor-pointer flex items-center justify-center gap-1 shadow-[0_0_15px_rgba(239,68,68,0.5)] font-mono"
              >
                ⛔ No, Secure Account
              </button>
            </div>
          </div>
        </div>
      `;
    }
    return;
  }

  // CASE 2: AUTHENTICATED MODE
  // 1. Enforce account isolation: check if user switched
  const currentUserId = (window.cognisec.user && window.cognisec.user.id != null) ? window.cognisec.user.id : 'unknown';
  if (_lastAuthUserId !== null && _lastAuthUserId !== currentUserId) {
    if (listEl) listEl.innerHTML = '';
  }
  _lastAuthUserId = currentUserId;

  // 2. Render loading state while fetching real notifications
  if (listEl) {
    listEl.innerHTML = `
      <div id="notif-loading-indicator" class="p-6 rounded-xl bg-black/60 border border-red-950 text-center text-xs text-slate-400 font-mono flex flex-col items-center justify-center gap-2">
        <div class="w-5 h-5 border-2 border-red-500 border-t-transparent rounded-full animate-spin"></div>
        <span>Loading security notifications...</span>
      </div>
    `;
  }

  try {
    const data = await window.cognisec.getNotifications();

    // Guard against race conditions if user logged out or switched while fetch was inflight
    if (!window.cognisec || !window.cognisec.isAuthenticated() || (window.cognisec.user && window.cognisec.user.id !== currentUserId)) {
      return;
    }

    const notifications = (data && Array.isArray(data.notifications)) ? data.notifications : [];
    const unreadCount = (data && typeof data.unread_count === 'number') ? data.unread_count : 0;

    // Update bell badge with real backend unread count
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

    // Update header count badge
    if (countBadge) {
      countBadge.textContent = `${unreadCount} unread`;
      countBadge.className = unreadCount > 0
        ? 'px-1.5 py-0.5 bg-red-950 border border-red-800 text-red-300 text-[10px] rounded font-bold'
        : 'px-1.5 py-0.5 bg-slate-900 border border-slate-700 text-slate-400 text-[10px] rounded font-bold';
    }

    if (!listEl) return;

    // Empty state: account has zero notifications
    if (notifications.length === 0) {
      listEl.innerHTML = `
        <div class="p-6 rounded-xl bg-black/60 border border-red-950 text-center text-xs text-slate-400 font-mono space-y-1">
          <div class="text-sm font-semibold text-slate-300">No notifications yet</div>
          <div class="text-[10px] text-slate-500">There are no security alerts or unrecognized sign-ins for your account.</div>
        </div>
      `;
      return;
    }

    // Render genuine backend notifications ONLY
    listEl.innerHTML = notifications.map(n => {
      let statusBadge = '';
      if (n.status === 'PENDING_CONFIRMATION') {
        statusBadge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-300 border border-amber-800 animate-pulse font-mono">PENDING CONFIRMATION</span>';
      } else if (n.status === 'CONFIRMED_TRUSTED') {
        statusBadge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-800 font-mono">TRUSTED</span>';
      } else if (n.status === 'CONFIRMED_DENIED') {
        statusBadge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-red-950 text-red-300 border border-red-800 font-mono">DENIED &amp; REVOKED</span>';
      } else if (n.status === 'DEVICE_REVOKED') {
        statusBadge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-red-950 text-red-400 border border-red-800 font-mono">REVOKED</span>';
      } else {
        statusBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-900 text-slate-400 border border-slate-700 font-mono">${_escapeHtml(n.status)}</span>`;
      }

      let emailStatusHtml = '';
      if (n.email_delivery_status === 'SENT') {
        emailStatusHtml = '<span class="text-[10px] text-emerald-400 font-mono">📧 Owner Alert: Email Sent</span>';
      } else if (n.email_delivery_status === 'FAILED') {
        emailStatusHtml = `<span class="text-[10px] text-red-400 font-mono" title="${_escapeHtml(n.email_error || '')}">📧 Email Failed (Recorded in SOC)</span>`;
      } else if (n.email_delivery_status === 'SKIPPED_UNCONFIGURED') {
        emailStatusHtml = '<span class="text-[10px] text-slate-500 font-mono">📧 SMTP Server Unconfigured</span>';
      } else {
        emailStatusHtml = '<span class="text-[10px] text-amber-400 font-mono">📧 Email In Queue</span>';
      }

      const timeStr = n.created_at ? (new Date(n.created_at).toLocaleString('en-US', { timeZone: 'UTC', hour12: false }) + ' UTC') : 'Unknown Time';

      const actionButtons = (n.status === 'PENDING_CONFIRMATION') ? `
        <div class="pt-2">
          <div class="text-[11px] text-amber-300 font-bold pb-1.5 text-center font-mono">Was this login authorized by you?</div>
          <div class="grid grid-cols-2 gap-2">
            <button
              onclick="handleNotificationResponse('${_escapeHtml(n.notification_id)}', 'yes')"
              class="py-2 px-3 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-[11px] uppercase tracking-wider transition-all cursor-pointer flex items-center justify-center gap-1 shadow-[0_0_12px_rgba(52,211,153,0.3)] font-mono"
            >
              ✓ Yes, This Was Me
            </button>
            <button
              onclick="handleNotificationResponse('${_escapeHtml(n.notification_id)}', 'no')"
              class="py-2 px-3 rounded-lg bg-red-600 hover:bg-red-500 text-white font-bold text-[11px] uppercase tracking-wider transition-all cursor-pointer flex items-center justify-center gap-1 shadow-[0_0_15px_rgba(239,68,68,0.5)] font-mono"
            >
              ⛔ No, Secure Account
            </button>
          </div>
        </div>
      ` : '';

      const markReadBtn = !n.is_read ? `
        <button onclick="handleMarkNotificationRead('${_escapeHtml(n.notification_id)}')" class="text-[10px] text-slate-500 hover:text-slate-300 underline cursor-pointer">
          Mark as read
        </button>
      ` : '<span class="text-[10px] text-slate-600">Read</span>';

      return `
        <div class="p-3.5 rounded-xl bg-black/80 border ${n.is_read ? 'border-red-950/60' : 'border-red-800/80 shadow-[0_0_15px_rgba(220,38,38,0.2)]'} space-y-2">
          <div class="flex items-center justify-between gap-2">
            <span class="text-xs font-bold text-white">${_escapeHtml(n.title)}</span>
            ${statusBadge}
          </div>
          <p class="text-xs text-slate-300 leading-relaxed font-sans">${_escapeHtml(n.message)}</p>
          <div class="text-[10px] font-mono text-slate-400 space-y-0.5">
            <div><span class="text-slate-500">Location:</span> ${_escapeHtml(n.location_summary || 'Unknown Network')}</div>
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
    if (!window.cognisec || !window.cognisec.isAuthenticated() || (window.cognisec.user && window.cognisec.user.id !== currentUserId)) {
      return;
    }
    console.warn('[COGNISEC-AI] Failed to fetch notifications:', err.message);

    if (badge) {
      badge.textContent = '0';
      badge.classList.add('hidden');
      badge.classList.remove('animate-pulse');
    }
    if (countBadge) {
      countBadge.textContent = 'Error';
      countBadge.className = 'px-1.5 py-0.5 bg-red-950 border border-red-800 text-red-400 text-[10px] rounded font-bold';
    }
    if (!listEl) return;

    const is401 = (err && err.status === 401) || (err && err.message && err.message.includes('401'));
    if (is401) {
      listEl.innerHTML = `
        <div class="p-5 rounded-xl bg-red-950/40 border border-red-900 text-center text-xs text-red-300 font-mono space-y-2">
          <div class="font-bold">⚠️ Session Expired</div>
          <div class="text-[11px] text-slate-400">Your session has expired. Please sign in again to view your security notifications.</div>
        </div>
      `;
    } else {
      listEl.innerHTML = `
        <div class="p-5 rounded-xl bg-red-950/40 border border-red-900 text-center text-xs text-red-300 font-mono space-y-2">
          <div class="font-bold text-red-400">⚠️ Failed to Load Notifications</div>
          <div class="text-[11px] text-slate-400">${_escapeHtml(err.message || 'Unable to retrieve real-time alerts.')}</div>
          <button onclick="refreshNotifications()" class="mt-2 px-3 py-1 bg-red-900/60 hover:bg-red-800 text-white rounded text-[10px] cursor-pointer">Retry</button>
        </div>
      `;
    }
  }
};

window.handleMarkNotificationRead = async function(notifId) {
  if (!window.cognisec || !window.cognisec.isAuthenticated()) {
    // Guest demo mode: mark demo notification read locally
    _guestDemoNotifRead = true;
    window.refreshNotifications();
    return;
  }
  if (!notifId) return;
  await window.cognisec.markNotificationRead(notifId);
  window.refreshNotifications();
};

window.markAllNotificationsAsRead = async function() {
  if (!window.cognisec || !window.cognisec.isAuthenticated()) {
    // Guest demo mode: mark all demo notifications read locally
    _guestDemoNotifRead = true;
    window.refreshNotifications();
    return;
  }
  await window.cognisec.markAllNotificationsRead();
  window.refreshNotifications();
};

window.handleNotificationResponse = async function(notifId, answer) {
  // Support legacy single-argument call: handleNotificationResponse('yes')
  if (!answer && (notifId === 'yes' || notifId === 'no')) {
    answer = notifId;
    notifId = null;
  }

  const resultBanner = document.getElementById('notif-result-banner');

  // CASE A: GUEST DEMO MODE
  if (!window.cognisec || !window.cognisec.isAuthenticated() || !notifId) {
    _guestDemoNotifRead = true;
    if (resultBanner) {
      resultBanner.classList.remove('hidden');
      if (answer === 'yes') {
        resultBanner.className = 'p-3 rounded-xl bg-emerald-950/80 border border-emerald-500 text-emerald-300 text-xs font-bold text-center animate-fade-in shadow-[0_0_15px_rgba(52,211,153,0.3)] font-mono';
        resultBanner.innerHTML = '🟢 Device Confirmed as Trusted! (Demo Mode)<br><span class="text-[10px] text-slate-300">Added to Verified Hardware Inventory.</span>';
      } else {
        resultBanner.className = 'p-3 rounded-xl bg-red-950/90 border-2 border-red-500 text-red-300 text-xs font-bold text-center animate-fade-in shadow-[0_0_20px_#ef4444] font-mono';
        resultBanner.innerHTML = '⛔ CRITICAL SECURITY INTERCEPT! (Demo Mode)<br><span class="text-[10px] text-white">Session Locked &amp; Unauthorized IP Blocked.</span>';

        const logsEl = document.getElementById('soc-live-logs');
        if (logsEl) {
          const timeStr = new Date().toLocaleTimeString('en-US', { hour12: false });
          const newLog = document.createElement('div');
          newLog.className = 'p-3 rounded-xl bg-black/50 border border-red-950 flex items-center justify-between font-mono text-[11px] animate-fade-in';
          newLog.innerHTML = `
            <div class="flex items-center gap-3">
              <span class="text-red-400 font-bold">🔴 [${timeStr}]</span>
              <span class="text-white font-bold">DEMO: USER DENIED LOGIN (MacBook Pro M3)</span>
              <span class="text-slate-400 text-[10px]">&bull; IP 103.21.124.9 &bull; Zero-Trust Kill Switch Executed</span>
            </div>
            <span class="px-2.5 py-0.5 bg-red-950 text-red-400 border border-red-800 rounded text-[10px] font-bold">SESSION KILLED</span>
          `;
          logsEl.prepend(newLog);
        }
      }

      setTimeout(() => {
        if (resultBanner) resultBanner.classList.add('hidden');
      }, 4000);
    }

    window.refreshNotifications();
    return;
  }

  // CASE B: AUTHENTICATED REAL NOTIFICATION RESPONSE
  if (window._isHandlingNotif) return;
  window._isHandlingNotif = true;

  if (resultBanner) {
    resultBanner.classList.remove('hidden');
    resultBanner.className = 'p-3 rounded-xl bg-black/80 border border-slate-700 text-slate-300 text-xs font-bold text-center font-mono';
    resultBanner.innerHTML = 'Communicating with zero-trust security authority...';
  }

  try {
    const res = await window.cognisec.respondToNotification(notifId, answer);
    if (res.status === 'success') {
      if (resultBanner) {
        if (answer === 'yes') {
          resultBanner.className = 'p-3 rounded-xl bg-emerald-950/80 border border-emerald-500 text-emerald-300 text-xs font-bold text-center animate-fade-in shadow-[0_0_15px_rgba(52,211,153,0.3)] font-mono';
          resultBanner.innerHTML = '🟢 Device Confirmed &amp; Trusted!<br><span class="text-[10px] text-slate-300">Updated in verified hardware inventory.</span>';
        } else {
          resultBanner.className = 'p-3 rounded-xl bg-red-950/90 border-2 border-red-500 text-red-300 text-xs font-bold text-center animate-fade-in shadow-[0_0_20px_#ef4444] font-mono';
          resultBanner.innerHTML = '⛔ UNAUTHORIZED ACCESS REJECTED!<br><span class="text-[10px] text-white">Device revoked &amp; all associated sessions terminated.</span>';
        }
      }
    } else {
      if (resultBanner) {
        resultBanner.className = 'p-3 rounded-xl bg-red-950/80 border border-red-800 text-red-300 text-xs font-bold text-center font-mono';
        resultBanner.textContent = res.message || 'Operation could not be completed.';
      }
    }

    setTimeout(() => {
      if (resultBanner) resultBanner.classList.add('hidden');
    }, 4000);

    window.refreshNotifications();
    if (typeof window.refreshUserDevices === 'function') {
      window.refreshUserDevices();
    }

  } catch (err) {
    if (resultBanner) {
      resultBanner.className = 'p-3 rounded-xl bg-red-950/80 border border-red-800 text-red-300 text-xs font-bold text-center font-mono';
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
        <div class="p-4 rounded-xl bg-black/60 border border-red-950 text-center text-xs text-slate-400 font-sans">
          No recognized hardware devices registered for this account yet.
        </div>
      `;
      return;
    }

    const currentSessionId = window.cognisec.sessionId || localStorage.getItem('cognisec_session_id');

    container.innerHTML = devices.map(d => {
      // 1. Trust & Verification State Badges
      let trustBadge = '';
      if (d.trust_state === 'TRUSTED') {
        trustBadge = '<span class="px-2.5 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-800 flex items-center gap-1"><span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>TRUSTED</span>';
      } else if (d.trust_state === 'PENDING_CONFIRMATION') {
        trustBadge = '<span class="px-2.5 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-300 border border-amber-800 flex items-center gap-1"><span class="w-1.5 h-1.5 rounded-full bg-amber-400"></span>PENDING CONFIRMATION</span>';
      } else if (d.trust_state === 'REVOKED') {
        trustBadge = '<span class="px-2.5 py-0.5 rounded text-[10px] font-bold bg-red-950 text-red-400 border border-red-800 flex items-center gap-1"><span class="w-1.5 h-1.5 rounded-full bg-red-500"></span>REVOKED</span>';
      } else {
        trustBadge = `<span class="px-2.5 py-0.5 rounded text-[10px] font-bold bg-slate-900 text-slate-400 border border-slate-700">${d.trust_state}</span>`;
      }

      // 2. Active Session Association
      const isCurrentDevice = (currentSessionId && d.active_session_ids && Array.isArray(d.active_session_ids) && d.active_session_ids.includes(currentSessionId));
      let sessionBadge = '';
      if (isCurrentDevice) {
        sessionBadge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950/90 text-emerald-300 border border-emerald-600 flex items-center gap-1">★ Current Device (This Session)</span>';
      } else if (d.active_session_count && d.active_session_count > 0) {
        sessionBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-blue-950 text-blue-300 border border-blue-800 flex items-center gap-1">● ${d.active_session_count} Active Session${d.active_session_count > 1 ? 's' : ''}</span>`;
      } else {
        sessionBadge = '<span class="px-2 py-0.5 rounded text-[10px] text-slate-500 bg-black/40 border border-slate-800">No active session</span>';
      }

      // 3. Environment & Verification Status
      const hasKnownEnv = d.browser_name && d.os_name && d.browser_name !== 'Unknown' && d.os_name !== 'Unknown';
      const isIdentityUnverified = !hasKnownEnv || d.device_fingerprint === 'unknown' || (d.nickname && d.nickname === 'Identity not verified');
      
      let displayNickname = d.nickname;
      if (!displayNickname || displayNickname.startsWith('Device #') || displayNickname === 'Unverified Device') {
        displayNickname = hasKnownEnv ? `${d.os_name} · ${d.browser_name}` : 'Identity not verified';
      }

      const unverifiedBadge = isIdentityUnverified
        ? '<span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-900 text-slate-400 border border-slate-700">Identity Not Verified</span>'
        : '';

      const envDetails = hasKnownEnv
        ? `${d.browser_name} ${d.browser_version || ''} &bull; ${d.os_name} ${d.os_version || ''} (${d.device_type || 'Desktop'})`
        : `Unverified browser environment &bull; Probabilistic client fingerprint`;

      // 4. Location Context (Honest and Privacy-Preserving)
      let locationText = '';
      const ip = (d.last_ip || '127.0.0.1').trim();
      const isPrivateNetwork = (
        ip.startsWith('127.') || ip.startsWith('10.') || ip.startsWith('192.168.') ||
        ip.startsWith('172.') || ip === '::1' || ip === 'localhost' || d.city === 'Local Network'
      );

      if (d.latitude != null && d.longitude != null) {
        locationText = `GPS: ${d.latitude.toFixed(2)}, ${d.longitude.toFixed(2)} (User-permitted)`;
      } else if (isPrivateNetwork) {
        locationText = `Local network (${ip} · No external location lookup)`;
      } else if (d.city || d.country) {
        locationText = `Approximate location (${[d.city, d.region, d.country].filter(Boolean).join(', ')} · IP-derived)`;
      } else {
        locationText = `Network: IP ${ip} (Approximate)`;
      }

      // 5. Timestamps
      const firstSeen = new Date(d.first_seen).toLocaleString('en-US', { timeZone: 'UTC', hour12: false }) + ' UTC';
      const lastSeen = new Date(d.last_seen).toLocaleString('en-US', { timeZone: 'UTC', hour12: false }) + ' UTC';

      // 6. Action Controls
      const confirmBtn = (d.trust_state === 'PENDING_CONFIRMATION') ? `
        <button
          onclick="handleConfirmDevice('${d.device_id}')"
          class="px-2.5 py-1.5 rounded-lg bg-emerald-950/80 hover:bg-emerald-900 border border-emerald-700 text-emerald-300 hover:text-white text-[11px] font-bold transition-all cursor-pointer flex items-center gap-1"
          title="Confirm device as recognized and trusted"
        >
          ✓ Confirm Trust
        </button>
      ` : '';

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
          <div class="space-y-1.5">
            <div class="flex items-center gap-2 flex-wrap">
              <span class="font-bold text-white text-sm">${displayNickname}</span>
              <button onclick="handleUpdateNickname('${d.device_id}')" class="text-[10px] text-slate-500 hover:text-slate-300 underline cursor-pointer" title="Rename device">✎ Edit Name</button>
              ${trustBadge}
              ${sessionBadge}
              ${unverifiedBadge}
            </div>
            <div class="text-[11px] text-slate-400 font-sans">
              ${envDetails}
            </div>
            <div class="text-[10px] text-slate-400">
              Location: ${locationText}
            </div>
            <div class="text-[10px] text-slate-500 flex items-center gap-3">
              <span>First: ${firstSeen}</span>
              <span>&bull;</span>
              <span>Last: ${lastSeen}</span>
            </div>
          </div>
          <div class="shrink-0 pt-2 md:pt-0 flex items-center gap-2 flex-wrap">
            ${confirmBtn}
            ${revokeBtn}
          </div>
        </div>
      `;
    }).join('');

  } catch (err) {
    console.warn('[COGNISEC-AI] Failed to fetch devices:', err.message);
    container.innerHTML = `
      <div class="p-4 rounded-xl bg-red-950/40 border border-red-800 text-center text-xs text-red-300 font-sans">
        Unable to load device inventory: ${err.message}. Please refresh or verify authentication.
      </div>
    `;
  }
};

window.handleConfirmDevice = async function(deviceId) {
  if (!confirm('Confirm this device as recognized and trusted for your account?')) {
    return;
  }
  const res = await window.cognisec.confirmDevice(deviceId);
  if (res && res.status === 'success') {
    alert(res.message);
  } else {
    alert((res && res.message) || 'Failed to confirm device trust.');
  }
  window.refreshUserDevices();
  if (typeof window.refreshNotifications === 'function') {
    window.refreshNotifications();
  }
};

window.handleRevokeDevice = async function(deviceId) {
  if (!confirm('Are you sure you want to revoke trust for this device? All active sessions associated with it will be immediately terminated.')) {
    return;
  }
  const res = await window.cognisec.revokeDevice(deviceId);
  if (res && res.status === 'success') {
    alert(res.message);
  } else {
    alert((res && res.message) || 'Failed to revoke device.');
  }
  window.refreshUserDevices();
  if (typeof window.refreshNotifications === 'function') {
    window.refreshNotifications();
  }
};

window.handleUpdateNickname = async function(deviceId) {
  const newName = prompt('Enter a recognizable nickname for this device (e.g., "My Work Laptop"):');
  if (newName && newName.trim()) {
    const res = await window.cognisec.updateDeviceNickname(deviceId, newName.trim());
    if (res && res.status === 'error') {
      alert(res.message || 'Failed to update device nickname.');
    }
    window.refreshUserDevices();
  }
};

// DASHBOARD SECTION REDIRECT & ADMIN ACCESS CONTROL
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
  if (window.cognisec && window.cognisec.isAdmin()) {
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





