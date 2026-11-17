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
  const userDashSecStatus = document.getElementById('user-dash-sec-status');
  const liveDemoBadge = document.getElementById('liveDemo-session-badge');

  const curSessStatus = (window.cognisec && window.cognisec.sessionStatus) ? String(window.cognisec.sessionStatus).toUpperCase() : 'ACTIVE';
  const locksSummary = window.cognisec ? window.cognisec._portalLocksSummary : null;
  const activeLockCount = locksSummary && Array.isArray(locksSummary.locks) ? locksSummary.locks.length : 0;

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

    const acctLabel = (user.account_status && !['PENDING_OBSERVATION', 'PENDING_OTP', 'RESTRICTED', 'STEP_UP_REQUIRED'].includes(String(user.account_status).toUpperCase()))
      ? String(user.account_status).toUpperCase()
      : 'ACTIVE';
    const isPendingInit = (curSessStatus === 'PENDING_OBSERVATION' || curSessStatus === 'PENDING_OTP');
    const isPortalRestricted = (activeLockCount > 0 || curSessStatus === 'RESTRICTED');

    if (profName) profName.textContent = user.name;
    if (profRole) profRole.textContent = isAdmin ? 'Security Administrator (SOC)' : 'Verified Enterprise User';
    if (profId) profId.textContent = user.id ? `ID: USR-00${user.id}` : 'ID: --';
    if (profSession) {
      if (isPortalRestricted) {
        profSession.textContent = `Account: ${acctLabel} • Global Session: VALID (${activeLockCount || 1} Portal Suspended)`;
      } else if (isPendingInit) {
        profSession.textContent = `Account: ${acctLabel} • Global Identity Signed In (Portal Verification Pending)`;
      } else {
        profSession.textContent = `Account: ${acctLabel} • Global Session: ACTIVE`;
      }
    }
    if (profDevice) profDevice.textContent = `${navigator.platform || 'Desktop'} • ${isAdmin ? 'Primary SOC Console' : 'Enterprise User Client'}`;
    if (profSessionId) profSessionId.textContent = window.cognisec && window.cognisec.sessionId ? `Global Session: ${window.cognisec.sessionId}` : 'Active';
    if (profLogoutBtn) profLogoutBtn.classList.remove('hidden');
    if (profActionBtn) {
      profActionBtn.innerHTML = `<span>${isAdmin ? 'Open SOC Command Center →' : 'Open User Dashboard →'}</span>`;
    }

    if (userDashName) userDashName.textContent = user.name;
    if (userDashEmail) userDashEmail.textContent = user.email;
    if (userDashRole) userDashRole.textContent = `ROLE: ${user.role}`;
    if (userDashStatus) userDashStatus.textContent = `ACCOUNT: ${acctLabel}`;
    if (userDashSession) {
      const sidText = (window.cognisec && window.cognisec.sessionId) ? window.cognisec.sessionId : 'Active';
      if (isPortalRestricted) {
        userDashSession.textContent = `VALID (${sidText})`;
        userDashSession.className = 'text-emerald-400 font-medium block truncate text-xs mt-0.5';
      } else if (isPendingInit) {
        userDashSession.textContent = `Identity Authenticated (${sidText}) — Portal Auth Pending`;
        userDashSession.className = 'text-amber-300 font-medium block truncate text-xs mt-0.5';
      } else {
        userDashSession.textContent = `Active (${sidText})`;
        userDashSession.className = 'text-emerald-400 font-medium block truncate text-xs mt-0.5';
      }
    }
    if (liveDemoBadge) {
      if (isPortalRestricted) {
        liveDemoBadge.className = 'px-2.5 py-0.5 text-[10px] font-sans bg-amber-950/80 text-amber-300 border border-amber-700/70 rounded-full font-medium flex items-center gap-1.5';
        liveDemoBadge.innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-amber-400"></span> Global Session Valid • Portal Suspended';
      } else if (isPendingInit) {
        liveDemoBadge.className = 'px-2.5 py-0.5 text-[10px] font-sans bg-amber-950/80 text-amber-300 border border-amber-700/70 rounded-full font-medium flex items-center gap-1.5';
        liveDemoBadge.innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-amber-400"></span> Portal Verification Pending';
      } else {
        liveDemoBadge.className = 'px-2.5 py-0.5 text-[10px] font-sans bg-emerald-950/80 text-emerald-400 border border-emerald-800/70 rounded-full font-medium flex items-center gap-1.5';
        liveDemoBadge.innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span> Global Session Valid';
      }
    }
    if (userDashSecStatus) {
      if (isPortalRestricted) {
        userDashSecStatus.className = 'text-amber-300 font-medium text-xs mt-0.5 flex items-center gap-1.5';
        userDashSecStatus.innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-amber-400"></span> Portal Lock Enforced (Isolated)';
      } else if (isPendingInit) {
        userDashSecStatus.className = 'text-amber-300 font-medium text-xs mt-0.5 flex items-center gap-1.5';
        userDashSecStatus.innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-amber-400"></span> Portal Verification Pending';
      } else {
        userDashSecStatus.className = 'text-emerald-400 font-medium text-xs mt-0.5 flex items-center gap-1.5';
        userDashSecStatus.innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span> Global Identity Authenticated';
      }
    }
    if (userDashDevice) {
      const devLabel = (typeof window.getSuggestedDeviceLabel === 'function' ? window.getSuggestedDeviceLabel() : null) || (navigator.userAgent.includes('Firefox') ? 'Firefox' : (navigator.userAgent.includes('Safari') && !navigator.userAgent.includes('Chrome')) ? 'Safari' : navigator.userAgent.includes('Edg') ? 'Edge' : 'Browser');
      userDashDevice.textContent = userDashDevice.title = `${navigator.platform || 'Desktop'} • ${devLabel}`;
    }

    if (typeof refreshAdaptiveMfaStatus === 'function') {
      refreshAdaptiveMfaStatus();
    }
    if (typeof window.refreshDashboardPortalLocks === 'function') {
      window.refreshDashboardPortalLocks();
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
    if (typeof window.renderDashboardPortalLocks === 'function') {
      window.renderDashboardPortalLocks(null);
    }
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
  try { sessionStorage.removeItem('cognisec_portal_ejection'); } catch (_) {}
  if (window.cognisec) {
    window.cognisec._portalLocksSummary = null;
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
    if (typeof window.refreshDashboardPortalLocks === 'function') {
      window.refreshDashboardPortalLocks();
    }
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

const SOC_EVENT_LABELS = {
  LOGIN_SUCCESS: 'Successful sign-in',
  LOGIN_ATTEMPT_FAILED: 'Failed sign-in attempt',
  LOGIN_OTP_ISSUED: 'Login verification code issued',
  LOGIN_OTP_VERIFIED: 'Login verification code confirmed',
  LOGIN_OTP_FAILED: 'Login verification code failed',
  STEP_UP_CHALLENGE: 'Step-up verification challenge issued',
  STEP_UP_VERIFIED: 'Step-up verification completed',
  STEP_UP_FAILED: 'Step-up verification failed',
  PORTAL_SECURITY_LOCKED: 'Portal access suspended due to security policy',
  PORTAL_RECOVERY_OTP_REQUESTED: 'Portal recovery verification code requested',
  PORTAL_RECOVERY_OTP_VERIFIED: 'Portal recovery code verified by user',
  PORTAL_RECOVERY_OTP_FAILED: 'Portal recovery code verification failed',
  PORTAL_RECOVERY_APPROVED: 'Administrator approved portal recovery',
  PORTAL_RECOVERY_REJECTED: 'Administrator rejected portal recovery',
  ADMIN_SESSION_TERMINATED: 'Administrator terminated a session',
  ADMIN_DEVICE_REVOKED: 'Administrator revoked a device',
  ADMIN_DEVICE_TRUSTED: 'Administrator confirmed device trust',
  ADMIN_DEVICE_TRUST_MODIFIED: 'Administrator updated device trust',
  ADMIN_ALERT_RESOLVED: 'Administrator resolved a security incident',
  ADMIN_ALERT_TRIAGED: 'Administrator updated incident status',
  ADMIN_ALERT_REOPENED: 'Administrator reopened a security incident',
  ZERO_TRUST_KILL_SWITCH: 'Security system terminated a high-risk session',
  SESSION_TERMINATED: 'Session terminated',
  GRANT_REVOKED: 'Protected-resource access grant revoked',
  PASSWORD_CHANGE_COMPLETED: 'Account password updated',
  BEHAVIORAL_ANOMALY: 'Behavioral anomaly detected',
};

function formatSocEventLabel(code) {
  if (!code) return 'Security Event';
  const key = String(code).toUpperCase();
  return SOC_EVENT_LABELS[key] || key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function formatSocPortalName(app) {
  const key = (app || 'platform').toLowerCase();
  if (key === 'ecommerce' || key === 'shopping') return 'Shopping';
  if (key === 'college') return 'College';
  if (key === 'healthcare') return 'Healthcare';
  return 'Platform';
}

function formatSocTimestamp(iso) {
  if (!iso) return 'Unavailable';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return 'Unavailable';
  return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

async function loadSocDashboardData() {
  if (!window.cognisec || !window.cognisec.isAdmin()) return;

  const opEmailEl = document.getElementById('soc-operator-email-val');
  if (opEmailEl && window.cognisec && window.cognisec.user) {
    opEmailEl.textContent = window.cognisec.user.email;
  }

  const errBanner = document.getElementById('soc-global-error-banner');
  const errText = document.getElementById('soc-global-error-text');
  const refreshEl = document.getElementById('soc-last-refresh-time');

  const globalScopeEl = document.getElementById('soc-global-scope-select');
  const globalScope = globalScopeEl ? globalScopeEl.value : 'genuine';

  // 1. High-Level SOC KPI Metrics
  try {
    const metrics = await window.cognisec.fetchSocMetrics(globalScope);
    if (metrics) {
      if (errBanner) errBanner.classList.add('hidden');
      if (refreshEl) refreshEl.textContent = new Date().toLocaleTimeString();

      const sessionsEl = document.getElementById('soc-stat-sessions');
      const trustedEl = document.getElementById('soc-stat-trusted');
      const blockedEl = document.getElementById('soc-stat-blocked');
      const devicesEl = document.getElementById('soc-stat-devices');
      const alertsEl = document.getElementById('soc-stat-alerts');
      const recoveryEl = document.getElementById('soc-stat-recovery');
      const anomalyEl = document.getElementById('soc-risk-anomaly');

      const regUsersVal = metrics.registered_users_count ?? 0;
      if (trustedEl) trustedEl.textContent = Number(regUsersVal).toLocaleString();
      if (sessionsEl) sessionsEl.textContent = Number(metrics.live_sessions_count ?? 0).toLocaleString();
      if (blockedEl) blockedEl.textContent = Number(metrics.suspended_accounts_count ?? 0).toLocaleString();
      if (devicesEl) devicesEl.textContent = Number(metrics.total_devices_count ?? 0).toLocaleString();
      if (alertsEl) alertsEl.textContent = Number(metrics.open_alerts_count ?? metrics.active_alerts_count ?? 0).toLocaleString();
      if (recoveryEl) recoveryEl.textContent = Number(metrics.pending_recovery_count ?? 0).toLocaleString();

      if (anomalyEl) {
        anomalyEl.textContent = `Anomaly Rate: ${metrics.anomaly_rate_label || (metrics.anomaly_rate_percent + '%')}`;
        anomalyEl.title = `Evaluated ${metrics.anomaly_rate_observations || 0} security events in the past 24 hours (${globalScope === 'genuine' ? 'Production Only' : 'All Records'}).`;
      }

      const usersSub = document.getElementById('soc-stat-users-sub');
      if (usersSub) {
        const emailVerified = metrics.email_verified_users_count ?? 0;
        const loggedIn = metrics.logged_in_users_count ?? 0;
        usersSub.textContent = `${emailVerified} Verified · ${loggedIn} Active`;
      }
      const provDetails = document.getElementById('soc-users-provenance-details');
      if (provDetails) {
        const reg = metrics.registered_users_count ?? 0;
        const ver = metrics.email_verified_users_count ?? 0;
        const act = metrics.logged_in_users_count ?? 0;
        const sess = metrics.live_sessions_count ?? 0;
        const adm = metrics.admin_accounts_count ?? 0;
        const tst = metrics.test_and_demo_accounts_count ?? 0;
        const unv = metrics.unverified_provenance_accounts_count ?? 0;
        const raw = metrics.total_users_count ?? 0;
        provDetails.innerHTML = `
          <div class="flex justify-between"><span>Public Registered:</span><strong class="text-emerald-300">${reg}</strong></div>
          <div class="flex justify-between"><span>Email-Verified:</span><strong class="text-emerald-300">${ver}</strong></div>
          <div class="flex justify-between"><span>Active Users / Sess:</span><strong class="text-white">${act} / ${sess}</strong></div>
          <div class="flex justify-between"><span>Administrators:</span><strong class="text-sky-300">${adm}</strong></div>
          <div class="flex justify-between"><span>Test / Demo:</span><strong class="text-slate-300">${tst}</strong></div>
          ${unv > 0 ? `<div class="flex justify-between"><span>Unverified Origin:</span><strong class="text-amber-300">${unv}</strong></div>` : ''}
          <div class="flex justify-between border-t border-emerald-950/60 pt-0.5"><span>Total DB Rows:</span><strong class="text-slate-400">${raw}</strong></div>
        `;
      }
      const sessionsSub = document.getElementById('soc-stat-sessions-sub');
      if (sessionsSub) {
        sessionsSub.textContent = `${metrics.active_users_count ?? 0} Active Users`;
      }
      const devSub = document.getElementById('soc-stat-devices-sub');
      if (devSub) {
        devSub.textContent = `${metrics.trusted_devices_count || 0} Trusted · ${metrics.untrusted_devices_count ?? 0} Untrusted`;
      }
      const devSummary = document.getElementById('soc-devices-live-summary');
      if (devSummary) {
        devSummary.textContent = `${metrics.active_devices_count || 0} Active · ${metrics.trusted_devices_count || 0} Trusted · ${metrics.total_devices_count || 0} Total in DB`;
      }
      const blockedSub = document.getElementById('soc-stat-blocked-sub');
      if (blockedSub) {
        blockedSub.textContent = `${metrics.restricted_sessions_count || 0} Restr Sess · ${metrics.revoked_devices_count || 0} Rev Dev`;
      }
      const alertsSub = document.getElementById('soc-stat-alerts-sub');
      if (alertsSub && metrics.open_alerts_count !== undefined) {
        alertsSub.textContent = `${metrics.open_alerts_count} Open · ${metrics.total_alerts_count || 0} Total`;
      }
    } else {
      if (errBanner) errBanner.classList.remove('hidden');
      if (errText) errText.textContent = 'Unable to load live security metrics from backend database.';
    }
  } catch (err) {
    console.warn('[COGNISEC-AI] Failed to load SOC metrics:', err);
    if (errBanner) errBanner.classList.remove('hidden');
    if (errText) errText.textContent = `Database telemetry error: ${err.message || 'Connection failed'}`;
  }

  // 2. Risk Distribution & Verification Activity
  try {
    const riskDist = await window.cognisec.fetchSocRiskDistribution(globalScope);
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
      ['soc-risk-low', 'soc-risk-med', 'soc-risk-high', 'soc-risk-stepup'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.textContent = 'Unavailable';
      });
    }
  } catch (err) {
    console.warn('[COGNISEC-AI] Failed to load risk distribution:', err);
    ['soc-risk-low', 'soc-risk-med', 'soc-risk-high', 'soc-risk-stepup'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.textContent = 'Unavailable';
    });
  }

  // 2b. Portal Recovery Locks (SOC Portal Recovery Tab & Overview Callout)
  try {
    const portalLocks = await window.cognisec.fetchSocPortalLocks();
    window._cachedSocPortalLocks = Array.isArray(portalLocks) ? portalLocks : [];
    if (typeof window.updateSocRecoveryOverviewAndBadge === 'function') {
      window.updateSocRecoveryOverviewAndBadge();
    }
    if (typeof window.renderSocPortalRecoveryQueue === 'function') {
      window.renderSocPortalRecoveryQueue();
    }
  } catch (err) {
    console.warn('[COGNISEC-AI] Failed to load portal recovery locks:', err);
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

    if (logsAlertsCount) logsAlertsCount.textContent = `${(alerts || []).length} Incidents`;

    const openAlerts = (alerts || []).filter(a => a.status === 'OPEN' || a.status === 'REOPENED');
    const overviewBadge = document.getElementById('soc-overview-alerts-badge');
    if (overviewBadge) overviewBadge.textContent = `${openAlerts.length} Open`;

    if (overviewAlertsEl) {
      if (openAlerts.length > 0) {
        overviewAlertsEl.innerHTML = '';
        openAlerts.forEach(al => {
          const timeStr = formatSocTimestamp(al.created_at);
          const card = document.createElement('div');
          card.className = 'p-4 rounded-xl bg-red-950/25 border border-red-800/70 space-y-2.5 text-sm';
          card.innerHTML = `
            <div class="flex flex-wrap items-center justify-between gap-2">
              <div class="flex flex-wrap items-center gap-2">
                <span class="px-2.5 py-0.5 rounded-md text-xs font-bold ${al.severity === 'CRITICAL' ? 'bg-red-600 text-white' : 'bg-amber-950 text-amber-200 border border-amber-800'}">${al.severity}</span>
                ${al.is_simulated ? '<span class="px-2 py-0.5 rounded-md text-xs font-semibold bg-purple-950 text-purple-200 border border-purple-800">Simulated</span>' : ''}
                <strong class="text-white text-base font-bold">${escapeHtml(formatSocEventLabel(al.alert_type))}</strong>
              </div>
              <span class="text-slate-400 text-xs font-mono">${timeStr}</span>
            </div>
            <p class="text-slate-200 text-sm leading-relaxed">${escapeHtml(al.message)}</p>
            <div class="flex flex-wrap items-center justify-between pt-1 gap-2">
              <span class="text-sm text-slate-300">${escapeHtml(al.user_name || 'User')} (${escapeHtml(al.user_email || '')}) &bull; ${formatSocPortalName(al.application)}</span>
              <div class="flex items-center gap-2">
                <button onclick="window.openIncidentInvestigation(${al.id})" class="px-3 py-1.5 rounded-lg bg-red-950 hover:bg-red-900 border border-red-700 text-red-200 text-xs font-semibold cursor-pointer transition-all">Inspect</button>
                <button onclick="window.triageQuickAlert(${al.id}, 'ACKNOWLEDGED')" class="px-3 py-1.5 rounded-lg bg-amber-950 hover:bg-amber-900 border border-amber-700 text-amber-200 text-xs font-semibold cursor-pointer">Acknowledge</button>
                ${window._isPortalLockAlertType && window._isPortalLockAlertType(al.alert_type)
                  ? `<button onclick="switchDashboardTab('recovery')" class="px-3 py-1.5 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-semibold cursor-pointer">Review Recovery →</button>`
                  : `<button onclick="window.triageResolvePrompt(${al.id})" class="px-3 py-1.5 rounded-lg bg-emerald-950 hover:bg-emerald-900 border border-emerald-700 text-emerald-200 text-xs font-semibold cursor-pointer">Resolve</button>`}
              </div>
            </div>
          `;
          overviewAlertsEl.appendChild(card);
        });
      } else {
        overviewAlertsEl.innerHTML = `<div class="p-8 text-center text-slate-400 text-sm">No open security incidents.</div>`;
      }
    }

    if (logsAlertsContainer) {
      window.renderSocAlertsList(alerts || []);
    }
  } catch (err) {
    console.warn('[COGNISEC-AI] Failed to load alerts:', err);
    const overviewAlertsEl = document.getElementById('soc-overview-alerts');
    if (overviewAlertsEl) {
      overviewAlertsEl.innerHTML = `<div class="p-8 text-center text-red-400 text-sm">Failed to load security incidents. <button onclick="window.loadSocDashboardData()" class="underline text-slate-200 hover:text-white cursor-pointer ml-1.5 font-semibold">Retry</button></div>`;
    }
  }

  // 4. Recent Security Activity Feed
  try {
    const eventsScopeSelect = document.getElementById('soc-events-scope-select');
    const eventsScope = eventsScopeSelect ? eventsScopeSelect.value : 'genuine';
    const events = await window.cognisec.fetchSocEvents(50, eventsScope);
    const logsEl = document.getElementById('soc-live-logs');
    const allEventsContainer = document.getElementById('soc-all-events-container');
    const logsEventsCount = document.getElementById('soc-logs-events-count');

    if (logsEventsCount) logsEventsCount.textContent = `${(events || []).length} Events`;

    if (logsEl) {
      const priorityEvents = (events || []).filter(ev => ['CRITICAL', 'HIGH'].includes(String(ev.severity || '').toUpperCase()));
      if (priorityEvents.length > 0) {
        logsEl.innerHTML = '';
        priorityEvents.slice(0, 15).forEach(ev => {
          const timeStr = formatSocTimestamp(ev.timestamp);
          const isClean = ev.severity === 'LOW';
          const isCritical = ev.severity === 'CRITICAL' || ev.decision === 'TERMINATE_SESSION';
          const newLog = document.createElement('div');
          newLog.className = `p-3.5 rounded-xl bg-black/50 border ${isClean ? 'border-emerald-950' : (isCritical ? 'border-red-700 bg-red-950/20' : 'border-amber-950')} flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 text-sm animate-fade-in transition-all`;
          newLog.innerHTML = `
            <div class="space-y-1 min-w-0">
              <div class="flex flex-wrap items-center gap-2">
                <span class="px-2 py-0.5 rounded text-xs font-bold ${isClean ? 'bg-emerald-950 text-emerald-300' : (isCritical ? 'bg-red-600 text-white' : 'bg-amber-950 text-amber-200')}">${ev.severity}</span>
                ${ev.is_simulated ? '<span class="px-2 py-0.5 rounded text-xs font-semibold bg-purple-950 text-purple-200 border border-purple-800">Simulated</span>' : ''}
                <span class="text-white font-semibold">${escapeHtml(formatSocEventLabel(ev.event_type))}</span>
              </div>
              <div class="text-slate-300 text-xs">
                <span>${escapeHtml(ev.user_name || 'Unknown User')}</span> &bull;
                <span>${formatSocPortalName(ev.application)}</span> &bull;
                <span class="font-mono text-slate-400">${timeStr}</span>
              </div>
            </div>
            <div class="flex items-center gap-2 shrink-0">
              <span class="px-2.5 py-1 ${isClean ? 'bg-emerald-950 text-emerald-300 border-emerald-800' : 'bg-red-950 text-red-300 border-red-800'} border rounded-lg text-xs font-semibold">${escapeHtml(ev.decision || 'RECORDED')}</span>
              ${ev.id ? `<button onclick="window.openIncidentInvestigation(${ev.id})" class="px-3 py-1 rounded-lg bg-black border border-slate-700 text-slate-200 hover:text-white text-xs font-semibold cursor-pointer transition-all">Inspect</button>` : ''}
            </div>
          `;
          logsEl.appendChild(newLog);
        });
      } else {
        logsEl.innerHTML = `<div class="p-8 text-center text-slate-400 text-sm">No recent critical or high-priority security events.</div>`;
      }
    }

    if (allEventsContainer) {
      window.renderSocEventsTable(events || []);
    }
  } catch (err) {
    console.warn('[COGNISEC-AI] Failed to load security events:', err);
    const logsEl = document.getElementById('soc-live-logs');
    if (logsEl) {
      logsEl.innerHTML = `<div class="p-8 text-center text-red-400 text-sm">Failed to load security activity. <button onclick="window.loadSocDashboardData()" class="underline text-slate-200 hover:text-white cursor-pointer ml-1.5 font-semibold">Retry</button></div>`;
    }
  }

  // 5. Authentication Sessions (respect current UI filters)
  try {
    await window.filterSocSessions();
  } catch (err) {
    console.warn('[COGNISEC-AI] Failed to load sessions:', err);
  }

  // 6. Registered Users Directory (ALL accounts, paginated) + Behavior User Select
  try {
    await window.loadSocUsersDirectory();
    const users = await window.cognisec.fetchSocUsers(100, 'genuine');
    const userSelect = document.getElementById('soc-behavior-user-select');
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
  } catch (err) {
    console.warn('[COGNISEC-AI] Failed to load users:', err);
  }

  // 7. Enterprise Hardware Device Inventory
  try {
    const devices = await window.cognisec.fetchSocDevices('genuine');
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
    container.innerHTML = `<div class="p-8 text-center text-slate-400 text-sm">No security incidents found matching the selected filter.</div>`;
    return;
  }
  // Deduplicate incident cards by alert id and (security_event_id + alert_type)
  const seenIds = new Set();
  const seenEventKeys = new Set();
  const uniqueAlerts = [];
  alerts.forEach(al => {
    if (seenIds.has(al.id)) return;
    seenIds.add(al.id);
    if (al.security_event_id) {
      const evKey = `${al.security_event_id}:${al.alert_type || ''}`;
      if (seenEventKeys.has(evKey)) return;
      seenEventKeys.add(evKey);
    }
    uniqueAlerts.push(al);
  });

  container.innerHTML = '';
  uniqueAlerts.forEach(al => {
    const isResolved = al.status === 'RESOLVED';
    const isAck = al.status === 'ACKNOWLEDGED';
    const isInv = al.status === 'INVESTIGATING';
    const isReopened = al.status === 'REOPENED';
    const timeStr = formatSocTimestamp(al.created_at);
    const isPortalLock = window._isPortalLockAlertType && window._isPortalLockAlertType(al.alert_type);
    const recommendedAction = isPortalLock
      ? 'Review the portal recovery request in the Portal Recovery tab before granting re-entry.'
      : (!isResolved ? 'Inspect correlated session/device telemetry and document resolution notes before closing.' : '');
    const card = document.createElement('div');
    card.className = `p-4 rounded-xl border ${isResolved ? 'bg-black/40 border-slate-800' : 'bg-red-950/20 border-red-800/60'} flex flex-col md:flex-row md:items-center justify-between gap-4 text-sm transition-all`;
    card.innerHTML = `
      <div class="space-y-2 flex-1 min-w-0">
        <div class="flex flex-wrap items-center gap-2">
          <span class="px-2.5 py-0.5 rounded-md text-xs font-bold ${al.severity === 'CRITICAL' ? 'bg-red-600 text-white' : 'bg-amber-950 text-amber-200 border border-amber-800'}">${al.severity}</span>
          ${al.is_simulated ? '<span class="px-2.5 py-0.5 rounded-md text-xs font-semibold bg-purple-950 text-purple-200 border border-purple-800">Simulated</span>' : ''}
          <span class="px-2.5 py-0.5 rounded-md text-xs font-semibold ${isResolved ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : (isInv ? 'bg-purple-950 text-purple-200 border border-purple-800' : (isAck ? 'bg-sky-950 text-sky-200 border border-sky-800' : (isReopened ? 'bg-amber-950 text-amber-200 border border-amber-800' : 'bg-red-950 text-red-300 border border-red-800')))}">
            ${al.status}
          </span>
          <strong class="text-white text-base font-bold">${escapeHtml(formatSocEventLabel(al.alert_type))}</strong>
          <span class="text-slate-400 text-xs font-mono">${timeStr}</span>
        </div>
        <p class="text-slate-200 text-sm leading-relaxed">${escapeHtml(al.message)}</p>
        ${recommendedAction ? `<p class="text-xs text-slate-300"><strong class="text-slate-200">Recommended Action:</strong> ${escapeHtml(recommendedAction)}</p>` : ''}
        <div class="flex flex-wrap items-center gap-x-5 gap-y-1 text-xs text-slate-300">
          <span>User: <strong class="text-white">${escapeHtml(al.user_name || 'Unknown')}</strong> (${escapeHtml(al.user_email || '—')})</span>
          <span>Portal: <strong class="text-white">${formatSocPortalName(al.application)}</strong></span>
          ${al.assigned_to ? `<span>Assigned To: <strong class="text-sky-300">${escapeHtml(al.assigned_to)}</strong></span>` : ''}
          ${al.resolved_by ? `<span>Resolved By: <strong class="text-emerald-300">${escapeHtml(al.resolved_by)}</strong></span>` : ''}
        </div>
        ${al.notes ? `<div class="p-2.5 rounded-lg bg-black/60 border border-red-950 text-xs text-slate-200">Notes: ${escapeHtml(al.notes)}</div>` : ''}
        ${al.resolution_reason ? `<div class="p-2.5 rounded-lg bg-emerald-950/30 border border-emerald-900/60 text-xs text-emerald-200">Resolution Reason: ${escapeHtml(al.resolution_reason)}</div>` : ''}
      </div>
      <div class="flex flex-wrap items-center gap-2 shrink-0 self-start md:self-center">
        <button onclick="window.openIncidentInvestigation(${al.id})" class="px-3.5 py-2 rounded-lg bg-red-950 hover:bg-red-900 border border-red-700 text-red-200 text-xs font-semibold cursor-pointer transition-all">Inspect</button>
        ${!isResolved ? `
          <button onclick="window.triageQuickAlert(${al.id}, 'ACKNOWLEDGED')" class="px-3 py-2 rounded-lg bg-sky-950 hover:bg-sky-900 border border-sky-700 text-sky-200 text-xs font-semibold cursor-pointer">Acknowledge</button>
          <button onclick="window.triageQuickAlert(${al.id}, 'INVESTIGATING')" class="px-3 py-2 rounded-lg bg-purple-950 hover:bg-purple-900 border border-purple-700 text-purple-200 text-xs font-semibold cursor-pointer">Investigate</button>
          ${isPortalLock
            ? `<button onclick="switchDashboardTab('recovery')" class="px-3.5 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-semibold cursor-pointer">Review Recovery →</button>`
            : `<button onclick="window.triageResolvePrompt(${al.id})" class="px-3.5 py-2 rounded-lg bg-emerald-950 hover:bg-emerald-900 border border-emerald-700 text-emerald-200 text-xs font-semibold cursor-pointer">Resolve</button>`}
        ` : `
          <button onclick="window.triageQuickAlert(${al.id}, 'REOPENED')" class="px-3 py-2 rounded-lg bg-amber-950 hover:bg-amber-900 border border-amber-700 text-amber-200 text-xs font-semibold cursor-pointer">Reopen</button>
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
    container.innerHTML = `<div class="p-6 text-center text-slate-400 text-sm">No security events found.</div>`;
    return;
  }
  let eventsTableHtml = `
    <table class="w-full text-left text-sm border-collapse">
      <thead>
        <tr class="border-b border-red-950 text-slate-300 text-sm font-semibold">
          <th class="py-3 px-3.5">Timestamp</th>
          <th class="py-3 px-3.5">Event</th>
          <th class="py-3 px-3.5">User</th>
          <th class="py-3 px-3.5">Portal</th>
          <th class="py-3 px-3.5">Severity</th>
          <th class="py-3 px-3.5">Anomaly</th>
          <th class="py-3 px-3.5">Decision</th>
          <th class="py-3 px-3.5 text-right">Actions</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-red-950/40 text-[15px]">
  `;
  events.forEach(ev => {
    const timeStr = formatSocTimestamp(ev.timestamp);
    const isCritical = ev.severity === 'CRITICAL' || ev.decision === 'TERMINATE_SESSION';
    const isLow = ev.severity === 'LOW';
    eventsTableHtml += `
      <tr class="hover:bg-red-950/15 transition-colors">
        <td class="py-3 px-3.5 text-slate-300 text-xs font-mono whitespace-nowrap">${timeStr}</td>
        <td class="py-3 px-3.5 text-white font-semibold">
          ${ev.is_simulated ? '<span class="px-2 py-0.5 rounded text-xs font-semibold bg-purple-950 text-purple-200 border border-purple-800 mr-1.5">Simulated</span>' : ''}
          ${escapeHtml(formatSocEventLabel(ev.event_type))}
        </td>
        <td class="py-3 px-3.5 text-slate-200">${escapeHtml(ev.user_name || 'Unknown')}</td>
        <td class="py-3 px-3.5 text-slate-300">${formatSocPortalName(ev.application)}</td>
        <td class="py-3 px-3.5">
          <span class="px-2.5 py-0.5 rounded-md text-xs font-bold ${isCritical ? 'bg-red-600 text-white' : (isLow ? 'bg-emerald-950 text-emerald-300' : 'bg-amber-950 text-amber-200')}">${ev.severity}</span>
        </td>
        <td class="py-3 px-3.5 font-mono text-slate-200 text-sm">${Number(ev.anomaly_score).toFixed(2)}</td>
        <td class="py-3 px-3.5">
          <span class="px-2.5 py-0.5 rounded-md text-xs font-semibold ${isCritical ? 'bg-red-950 text-red-300 border border-red-800' : 'bg-slate-900 text-slate-200 border border-slate-700'}">${escapeHtml(ev.decision)}</span>
        </td>
        <td class="py-3 px-3.5 text-right">
          ${ev.id ? `<button onclick="window.openIncidentInvestigation(${ev.id})" class="px-3 py-1 rounded-lg bg-black border border-slate-700 text-slate-200 hover:text-white text-xs font-semibold cursor-pointer transition-all">Inspect</button>` : '—'}
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
    container.innerHTML = `<div class="p-8 text-center text-slate-400 text-sm">No sessions found matching the selected filters.</div>`;
    return;
  }
  let sessTableHtml = `
    <table class="w-full text-left text-sm border-collapse">
      <thead>
        <tr class="border-b border-red-950 text-slate-300 text-sm font-semibold">
          <th class="py-3 px-3.5">Session ID</th>
          <th class="py-3 px-3.5">User</th>
          <th class="py-3 px-3.5">Portal</th>
          <th class="py-3 px-3.5">Device / Browser</th>
          <th class="py-3 px-3.5">IP Address</th>
          <th class="py-3 px-3.5">Login Time</th>
          <th class="py-3 px-3.5">Last Activity</th>
          <th class="py-3 px-3.5">Risk Level</th>
          <th class="py-3 px-3.5">Status</th>
          <th class="py-3 px-3.5 text-right">Actions</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-red-950/40 text-[15px]">
  `;
  sessions.forEach(s => {
    const canTerminate = ['ACTIVE', 'RESTRICTED', 'STEP_UP_REQUIRED', 'PENDING_OBSERVATION', 'PENDING_OTP'].includes(s.status);
    const isActive = s.status === 'ACTIVE';
    const isRestricted = s.status === 'RESTRICTED';
    const isStepUp = s.status === 'STEP_UP_REQUIRED';
    const loginStr = formatSocTimestamp(s.login_time);
    const lastActStr = formatSocTimestamp(s.last_activity || s.logout_time || s.login_time);
    const deviceDisplay = [s.device_nickname, s.browser_os].filter(Boolean).join(' · ') || 'Browser Session';
    sessTableHtml += `
      <tr class="hover:bg-red-950/15 transition-colors">
        <td class="py-3 px-3.5 text-slate-300 font-mono text-xs whitespace-nowrap" title="${escapeHtml(s.id)}">
          ${s.is_simulated ? '<span class="px-2 py-0.5 rounded text-xs font-semibold bg-purple-950 text-purple-200 border border-purple-800 mr-1.5">Simulated</span>' : ''}
          ${escapeHtml(s.id.substring(0, 14))}…
        </td>
        <td class="py-3 px-3.5">
          <strong class="text-white block font-semibold">${escapeHtml(s.user_name || 'User')}</strong>
          <span class="text-slate-400 text-xs">${escapeHtml(s.user_email || '')}</span>
        </td>
        <td class="py-3 px-3.5 text-slate-200 font-medium">${formatSocPortalName(s.application)}</td>
        <td class="py-3 px-3.5 text-slate-200 text-sm">${escapeHtml(deviceDisplay)}</td>
        <td class="py-3 px-3.5 text-slate-300 font-mono text-xs">${escapeHtml(s.ip_address || 'Unavailable')}</td>
        <td class="py-3 px-3.5 text-slate-300 text-xs font-mono whitespace-nowrap">${loginStr}</td>
        <td class="py-3 px-3.5 text-slate-300 text-xs font-mono whitespace-nowrap">${lastActStr}</td>
        <td class="py-3 px-3.5">
          <span class="px-2.5 py-0.5 rounded-md text-xs font-bold ${s.current_risk_level === 'CRITICAL' || s.current_risk_level === 'HIGH' ? 'bg-red-950 text-red-300 border border-red-800' : (s.current_risk_level === 'MEDIUM' ? 'bg-amber-950 text-amber-200 border border-amber-800' : 'bg-emerald-950 text-emerald-300 border border-emerald-800')}">${s.current_risk_level}</span>
        </td>
        <td class="py-3 px-3.5">
          <span class="px-2.5 py-0.5 rounded-md text-xs font-semibold ${isActive ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : (isRestricted ? 'bg-amber-950 text-amber-200 border border-amber-800' : (isStepUp ? 'bg-purple-950 text-purple-200 border border-purple-800' : 'bg-slate-900 text-slate-300 border border-slate-700'))}">
            ${escapeHtml(s.status)}
          </span>
        </td>
        <td class="py-3 px-3.5 text-right whitespace-nowrap">
          <div class="flex items-center justify-end gap-2">
            <button onclick="window.openIncidentInvestigation('${escapeHtml(s.id)}')" class="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 text-xs font-semibold cursor-pointer transition-all">Inspect</button>
            ${canTerminate ? `
              <button onclick="window.terminateSocSession('${escapeHtml(s.id)}')" class="px-3 py-1.5 rounded-lg bg-red-950 hover:bg-red-800 border border-red-700 text-red-200 text-xs font-semibold cursor-pointer transition-all">Terminate</button>
            ` : ''}
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
  const portalSelect = document.getElementById('soc-sessions-portal');
  const riskSelect = document.getElementById('soc-sessions-risk');
  const scopeSelect = document.getElementById('soc-sessions-scope');

  const search = searchInput ? searchInput.value.trim() : '';
  const status = statusSelect && statusSelect.value !== 'ALL' ? statusSelect.value : null;
  const portal = portalSelect && portalSelect.value !== 'ALL' ? portalSelect.value : null;
  const risk = riskSelect && riskSelect.value !== 'ALL' ? riskSelect.value : null;
  const scope = scopeSelect ? scopeSelect.value : 'all';

  try {
    const sessions = await window.cognisec.fetchSocSessions(100, status, risk, search, scope, portal);
    window._cachedSocSessions = sessions || [];
    window.renderSocSessionsTable(sessions || []);
    const sessionsCountBadge = document.getElementById('soc-sessions-count-badge');
    if (sessionsCountBadge) {
      const activeCount = (sessions || []).filter(s => s.status === 'ACTIVE').length;
      sessionsCountBadge.textContent = `${(sessions || []).length} Shown (${activeCount} Active)`;
    }
  } catch (e) {
    console.error('Failed to filter sessions:', e);
    const container = document.getElementById('soc-sessions-table-container');
    if (container) {
      container.innerHTML = `<div class="p-6 text-center text-red-400 text-sm">Failed to load sessions. <button onclick="window.filterSocSessions()" class="underline text-slate-200 ml-1.5 font-semibold cursor-pointer">Retry</button></div>`;
    }
  }
};

window._socUsersState = { page: 1, page_size: 12, total_pages: 1 };

window.onSocUsersFilterChange = function(resetPage = false) {
  if (resetPage) window._socUsersState.page = 1;
  window.loadSocUsersDirectory();
};

window.changeSocUsersPage = function(delta) {
  const next = window._socUsersState.page + delta;
  if (next >= 1 && next <= window._socUsersState.total_pages) {
    window._socUsersState.page = next;
    window.loadSocUsersDirectory();
  }
};

window.loadSocUsersDirectory = async function() {
  const container = document.getElementById('soc-users-table-container');
  const badge = document.getElementById('soc-users-count-badge');
  const pageInfo = document.getElementById('soc-users-page-info');
  const prevBtn = document.getElementById('soc-users-prev-btn');
  const nextBtn = document.getElementById('soc-users-next-btn');
  if (!container || !window.cognisec) return;

  const search = document.getElementById('soc-users-search')?.value?.trim() || '';
  const role = document.getElementById('soc-users-role')?.value || 'ALL';
  const accountStatus = document.getElementById('soc-users-status')?.value || 'ALL';
  const scope = document.getElementById('soc-users-scope')?.value || 'genuine';
  const sortRaw = document.getElementById('soc-users-sort')?.value || 'created_at:desc';
  const [sort_by, sort_dir] = sortRaw.split(':');

  try {
    const res = await window.cognisec.fetchSocUsersDirectory({
      search,
      role,
      account_status: accountStatus,
      scope,
      sort_by,
      sort_dir,
      page: window._socUsersState.page,
      page_size: window._socUsersState.page_size,
    });
    const users = res.items || [];
    window._socUsersState.page = res.page || 1;
    window._socUsersState.total_pages = res.total_pages || 1;

    const scopeLabelMap = {
      genuine: 'Registered',
      admin: 'Administrators',
      test: 'Test / Demo',
      all: 'Total Accounts',
    };
    const countLabel = scopeLabelMap[scope] || 'Accounts';
    if (badge) badge.textContent = `${res.total || 0} ${countLabel}`;
    if (pageInfo) pageInfo.textContent = `Page ${res.page || 1} of ${res.total_pages || 1} (${res.total || 0} matching accounts)`;
    if (prevBtn) prevBtn.disabled = (res.page || 1) <= 1;
    if (nextBtn) nextBtn.disabled = (res.page || 1) >= (res.total_pages || 1);

    if (users.length === 0) {
      container.innerHTML = `<div class="p-8 text-center text-slate-400 text-sm">No accounts match the current scope and filters.</div>`;
      return;
    }

    let html = `
      <table class="w-full text-left text-sm border-collapse">
        <thead>
          <tr class="border-b border-red-950 text-slate-300 text-sm font-semibold">
            <th class="py-3 px-3.5">Name & Classification</th>
            <th class="py-3 px-3.5">Email & Verification</th>
            <th class="py-3 px-3.5">Account Status</th>
            <th class="py-3 px-3.5">Registration Date</th>
            <th class="py-3 px-3.5">Last Login</th>
            <th class="py-3 px-3.5">Sessions (Active / Total)</th>
            <th class="py-3 px-3.5">Last Known Risk</th>
            <th class="py-3 px-3.5">Portal Activity</th>
            <th class="py-3 px-3.5 text-right">Actions</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-red-950/40 text-[15px]">
    `;
    users.forEach(u => {
      const isAct = u.account_status === 'ACTIVE';
      const regStr = u.created_at ? formatSocTimestamp(u.created_at) : 'Not recorded';
      const lastLoginStr = u.last_login ? formatSocTimestamp(u.last_login) : 'Not recorded';
      const riskLabel = u.last_risk_level || 'Not recorded';
      const isHighRisk = riskLabel === 'HIGH' || riskLabel === 'CRITICAL';
      const portalStr = u.portal_activity ? escapeHtml(u.portal_activity) : '<span class="text-slate-500">Not recorded</span>';

      let classBadge = `<span class="ml-1.5 px-2 py-0.5 rounded text-xs font-semibold bg-emerald-950 text-emerald-300 border border-emerald-800">Registered User</span>`;
      if (u.provenance === 'ADMIN_ACCOUNT') {
        classBadge = `<span class="ml-1.5 px-2 py-0.5 rounded text-xs font-semibold bg-purple-950 text-purple-200 border border-purple-800">Administrator</span>`;
      } else if (u.provenance === 'SEEDED_DEMO') {
        classBadge = `<span class="ml-1.5 px-2 py-0.5 rounded text-xs font-semibold bg-amber-950 text-amber-200 border border-amber-800">Seeded Demo</span>`;
      } else if (u.provenance === 'KNOWN_TEST') {
        classBadge = `<span class="ml-1.5 px-2 py-0.5 rounded text-xs font-semibold bg-rose-950 text-rose-200 border border-rose-800">Test Account</span>`;
      } else if (u.provenance === 'SYSTEM_ACCOUNT') {
        classBadge = `<span class="ml-1.5 px-2 py-0.5 rounded text-xs font-semibold bg-slate-900 text-slate-300 border border-slate-700">System</span>`;
      } else if (u.provenance === 'UNKNOWN_PROVENANCE') {
        classBadge = `<span class="ml-1.5 px-2 py-0.5 rounded text-xs font-semibold bg-slate-900 text-slate-400 border border-slate-700">Unknown Provenance</span>`;
      }

      const verifiedBadge = u.email_verified
        ? `<span class="inline-block mt-1 px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-950/80 text-emerald-300 border border-emerald-800">Verified${u.email_verified_at ? ' · ' + formatSocTimestamp(u.email_verified_at) : ''}</span>`
        : `<span class="inline-block mt-1 px-2 py-0.5 rounded text-[11px] font-semibold bg-slate-900 text-slate-400 border border-slate-700">Unverified</span>`;

      html += `
        <tr class="hover:bg-red-950/15 transition-colors">
          <td class="py-3 px-3.5">
            <strong class="text-white font-semibold">${escapeHtml(u.name)}</strong>${classBadge}
            <div class="text-xs text-slate-400 mt-0.5">Role: ${escapeHtml(u.role)}</div>
          </td>
          <td class="py-3 px-3.5">
            <div class="text-slate-200 font-mono text-xs">${escapeHtml(u.email)}</div>
            ${verifiedBadge}
          </td>
          <td class="py-3 px-3.5">
            <span class="px-2.5 py-0.5 rounded-md text-xs font-semibold ${isAct ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-red-950 text-red-300 border border-red-800'}">${escapeHtml(u.account_status)}</span>
          </td>
          <td class="py-3 px-3.5 text-slate-300 text-xs font-mono whitespace-nowrap">${regStr}</td>
          <td class="py-3 px-3.5 text-slate-300 text-xs font-mono whitespace-nowrap">${lastLoginStr}</td>
          <td class="py-3 px-3.5 text-slate-100 font-semibold whitespace-nowrap">
            <span class="${u.active_sessions_count > 0 ? 'text-emerald-400' : 'text-slate-400'}">${u.active_sessions_count || 0} active</span>
            <span class="text-slate-500 mx-1">/</span>
            <span>${u.total_sessions_count || 0} total</span>
          </td>
          <td class="py-3 px-3.5">
            <span class="px-2.5 py-0.5 rounded-md text-xs font-semibold ${isHighRisk ? 'bg-red-950 text-red-300 border border-red-800' : (riskLabel === 'MEDIUM' ? 'bg-amber-950 text-amber-200 border border-amber-800' : 'bg-slate-900 text-slate-300 border border-slate-700')}">${escapeHtml(riskLabel)}</span>
          </td>
          <td class="py-3 px-3.5 text-xs text-slate-300">${portalStr}</td>
          <td class="py-3 px-3.5 text-right whitespace-nowrap">
            <button type="button" onclick="window.openSocUserDetail(${u.id})" class="px-3.5 py-1.5 rounded-lg bg-red-950/70 hover:bg-red-900 border border-red-700 text-red-100 text-xs font-semibold cursor-pointer transition-all">Inspect Account</button>
          </td>
        </tr>
      `;
    });
    html += `</tbody></table>`;
    container.innerHTML = html;
  } catch (err) {
    console.error('[COGNISEC-AI] Failed to load users directory:', err);
    container.innerHTML = `<div class="p-8 text-center text-red-400 text-sm">Failed to load registered users: ${escapeHtml(err.message)}. <button onclick="window.loadSocUsersDirectory()" class="underline text-slate-200 ml-1.5 font-semibold cursor-pointer">Retry</button></div>`;
  }
};

window.openSocUserDetail = async function(userId) {
  const modal = document.getElementById('modal-soc-user-detail');
  const titleEl = document.getElementById('soc-user-detail-title');
  const subEl = document.getElementById('soc-user-detail-subtitle');
  const bodyEl = document.getElementById('soc-user-detail-body');
  if (!modal || !bodyEl || !window.cognisec) return;

  modal.classList.remove('hidden');
  bodyEl.innerHTML = `<div class="p-8 text-center text-slate-300 text-sm">Loading account inspection dossier...</div>`;

  try {
    const data = await window.cognisec.fetchSocUserDetails(userId);
    const u = data.user || {};
    if (titleEl) titleEl.textContent = `${u.name || 'User'} — Account Inspection`;
    if (subEl) subEl.textContent = `${u.email || ''} • Role: ${u.role || 'USER'} • Status: ${u.account_status || 'UNKNOWN'}`;

    const devicesHtml = (data.devices || []).length > 0
      ? data.devices.map(d => `
          <div class="p-3 rounded-xl bg-black/60 border border-slate-800 flex flex-wrap items-center justify-between gap-2 text-sm">
            <div>
              <strong class="text-white">${escapeHtml(d.nickname || d.device_type || 'Device')}</strong>
              <span class="text-slate-400 text-xs block">${escapeHtml(d.browser || 'Unknown browser')} · ${escapeHtml(d.os || 'Unknown OS')}${d.location ? ` · ${escapeHtml(d.location)}` : ''}</span>
            </div>
            <span class="px-2.5 py-0.5 rounded text-xs font-semibold ${d.trust_state === 'TRUSTED' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-amber-950 text-amber-200 border border-amber-800'}">${escapeHtml(d.trust_state)}</span>
          </div>`).join('')
      : `<div class="text-sm text-slate-400">No devices registered for this account.</div>`;

    const sessionsHtml = (data.sessions || []).length > 0
      ? data.sessions.map(s => `
          <div class="p-3 rounded-xl bg-black/60 border border-slate-800 flex flex-wrap items-center justify-between gap-2 text-sm">
            <div>
              <strong class="text-white">${formatSocPortalName(s.application)}</strong>
              <span class="text-slate-400 font-mono text-xs ml-2">${escapeHtml(s.id.substring(0, 14))}…</span>
              <div class="text-xs text-slate-400">Login: ${formatSocTimestamp(s.login_time)} · IP: ${escapeHtml(s.ip_address || 'Unavailable')}</div>
            </div>
            <div class="flex items-center gap-2">
              <span class="px-2 py-0.5 rounded text-xs font-semibold bg-slate-900 text-slate-200 border border-slate-700">${escapeHtml(s.current_risk_level)}</span>
              <span class="px-2 py-0.5 rounded text-xs font-semibold ${s.status === 'ACTIVE' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-slate-900 text-slate-300 border border-slate-700'}">${escapeHtml(s.status)}</span>
            </div>
          </div>`).join('')
      : `<div class="text-sm text-slate-400">No authentication sessions recorded for this account.</div>`;

    const portalsHtml = (data.portal_locks || []).length > 0 || (data.portal_grants || []).length > 0
      ? [
          ...(data.portal_locks || []).map(l => `<div class="p-3 rounded-xl bg-red-950/25 border border-red-900/60 text-sm"><strong class="text-white">${formatSocPortalName(l.application)} Lock (${escapeHtml(l.security_reference_id)})</strong> — <span class="text-red-300">${escapeHtml(l.lock_status)}</span> (${escapeHtml(l.recovery_status)})<div class="text-xs text-slate-300 mt-0.5">${escapeHtml(l.lock_reason || '')}</div></div>`),
          ...(data.portal_grants || []).map(g => `<div class="p-3 rounded-xl bg-black/60 border border-slate-800 text-sm"><strong class="text-white">${formatSocPortalName(g.application)} Vault Grant</strong> — ${g.revoked ? '<span class="text-red-300">Revoked</span>' : '<span class="text-emerald-300">Active</span>'} · Granted: ${formatSocTimestamp(g.granted_at)}</div>`)
        ].join('')
      : `<div class="text-sm text-slate-400">No portal lockouts or vault grants recorded.</div>`;

    const eventsHtml = (data.recent_events || []).length > 0
      ? data.recent_events.map(ev => `
          <div class="p-3 rounded-xl bg-black/60 border border-slate-800 flex flex-wrap items-center justify-between gap-2 text-sm">
            <div>
              <strong class="text-white">${escapeHtml(formatSocEventLabel(ev.event_type))}</strong>
              <span class="text-xs text-slate-400 ml-2">${formatSocPortalName(ev.application)} · ${formatSocTimestamp(ev.timestamp)}</span>
              ${ev.details ? `<div class="text-xs text-slate-300 mt-0.5">${escapeHtml(ev.details)}</div>` : ''}
            </div>
            <span class="px-2 py-0.5 rounded text-xs font-semibold bg-slate-900 text-slate-200 border border-slate-700">${escapeHtml(ev.severity)} · Risk ${ev.risk_score}</span>
          </div>`).join('')
      : `<div class="text-sm text-slate-400">No authentication or security events recorded.</div>`;

    bodyEl.innerHTML = `
      <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div class="p-3.5 rounded-xl bg-black/70 border border-slate-800"><span class="text-xs text-slate-400 block">Registered</span><strong class="text-sm text-white">${formatSocTimestamp(u.created_at)}</strong></div>
        <div class="p-3.5 rounded-xl bg-black/70 border border-slate-800"><span class="text-xs text-slate-400 block">Last Login</span><strong class="text-sm text-white">${u.last_login ? formatSocTimestamp(u.last_login) : 'Never'}</strong></div>
        <div class="p-3.5 rounded-xl bg-black/70 border border-slate-800"><span class="text-xs text-slate-400 block">Sessions</span><strong class="text-sm text-white">${u.total_sessions_count || 0} Total (${u.active_sessions_count || 0} Active)</strong></div>
        <div class="p-3.5 rounded-xl bg-black/70 border border-slate-800"><span class="text-xs text-slate-400 block">Behavior Baseline</span><strong class="text-sm text-white">${escapeHtml(u.baseline_status || 'COLD_START')} (${u.sample_count || 0} samples)</strong></div>
      </div>
      <div class="space-y-2"><h4 class="font-bold text-base text-white">Portal Locks &amp; Access Grants</h4><div class="space-y-2">${portalsHtml}</div></div>
      <div class="space-y-2"><h4 class="font-bold text-base text-white">Registered Devices (${(data.devices || []).length})</h4><div class="space-y-2">${devicesHtml}</div></div>
      <div class="space-y-2"><h4 class="font-bold text-base text-white">Session History (${(data.sessions || []).length})</h4><div class="space-y-2 max-h-56 overflow-y-auto">${sessionsHtml}</div></div>
      <div class="space-y-2"><h4 class="font-bold text-base text-white">Recent Authentication &amp; Risk Events (${(data.recent_events || []).length})</h4><div class="space-y-2 max-h-64 overflow-y-auto">${eventsHtml}</div></div>
    `;
  } catch (err) {
    bodyEl.innerHTML = `<div class="p-8 text-center text-red-400 text-sm">Failed to load account details: ${escapeHtml(err.message)}</div>`;
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
      const openAlerts = (alerts || []).filter(a => a.status === 'OPEN' || a.status === 'REOPENED');
      const overviewAlertsEl = document.getElementById('soc-overview-alerts');
      const overviewBadge = document.getElementById('soc-overview-alerts-badge');
      if (overviewBadge) overviewBadge.textContent = `${openAlerts.length} Open`;
      if (overviewAlertsEl) {
        if (openAlerts.length > 0) {
          overviewAlertsEl.innerHTML = '';
          openAlerts.forEach(al => {
            const timeStr = formatSocTimestamp(al.created_at);
            const card = document.createElement('div');
            card.className = 'p-4 rounded-xl bg-red-950/25 border border-red-800/70 space-y-2.5 text-sm';
            card.innerHTML = `
              <div class="flex flex-wrap items-center justify-between gap-2">
                <div class="flex flex-wrap items-center gap-2">
                  <span class="px-2.5 py-0.5 rounded-md text-xs font-bold ${al.severity === 'CRITICAL' ? 'bg-red-600 text-white' : 'bg-amber-950 text-amber-200 border border-amber-800'}">${al.severity}</span>
                  ${al.is_simulated ? '<span class="px-2 py-0.5 rounded-md text-xs font-semibold bg-purple-950 text-purple-200 border border-purple-800">Simulated</span>' : ''}
                  <strong class="text-white text-base font-bold">${escapeHtml(formatSocEventLabel(al.alert_type))}</strong>
                </div>
                <span class="text-slate-400 text-xs font-mono">${timeStr}</span>
              </div>
              <p class="text-slate-200 text-sm leading-relaxed">${escapeHtml(al.message)}</p>
              <div class="flex flex-wrap items-center justify-between pt-1 gap-2">
                <span class="text-sm text-slate-300">${escapeHtml(al.user_name || 'User')} (${escapeHtml(al.user_email || '')}) &bull; ${formatSocPortalName(al.application)}</span>
                <div class="flex items-center gap-2">
                  <button onclick="window.openIncidentInvestigation(${al.id})" class="px-3 py-1.5 rounded-lg bg-red-950 hover:bg-red-900 border border-red-700 text-red-200 text-xs font-semibold cursor-pointer transition-all">Inspect</button>
                  <button onclick="window.triageQuickAlert(${al.id}, 'ACKNOWLEDGED')" class="px-3 py-1.5 rounded-lg bg-amber-950 hover:bg-amber-900 border border-amber-700 text-amber-200 text-xs font-semibold cursor-pointer">Acknowledge</button>
                  ${window._isPortalLockAlertType && window._isPortalLockAlertType(al.alert_type)
                    ? `<button onclick="switchDashboardTab('recovery')" class="px-3 py-1.5 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-semibold cursor-pointer">Review Recovery →</button>`
                    : `<button onclick="window.triageResolvePrompt(${al.id})" class="px-3 py-1.5 rounded-lg bg-emerald-950 hover:bg-emerald-900 border border-emerald-700 text-emerald-200 text-xs font-semibold cursor-pointer">Resolve</button>`}
                </div>
              </div>
            `;
            overviewAlertsEl.appendChild(card);
          });
        } else {
          overviewAlertsEl.innerHTML = `<div class="p-8 text-center text-slate-400 text-sm">No open security incidents for selected scope.</div>`;
        }
      }
      window.renderSocAlertsList(alerts || []);
    } catch (e) {
      console.error('Failed to change alerts scope:', e);
    }
  } else if (target === 'events') {
    try {
      const events = await window.cognisec.fetchSocEvents(50, scope);
      const logsEl = document.getElementById('soc-live-logs');
      if (logsEl) {
        const priorityEvents = (events || []).filter(ev => ['CRITICAL', 'HIGH'].includes(String(ev.severity || '').toUpperCase()));
        if (priorityEvents.length > 0) {
          logsEl.innerHTML = '';
          priorityEvents.slice(0, 15).forEach(ev => {
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

window._socAuditState = { page: 1, page_size: 15, total_pages: 1, view: 'timeline', selected_user_id: null, uh_tab: 'logins' };

window._getSecurityIntelFilters = function() {
  return {
    search: document.getElementById('soc-audit-search')?.value?.trim() || '',
    activity_scope: 'user',
    user_id: window._socAuditState.selected_user_id || '',
    category: document.getElementById('soc-audit-category-filter')?.value || 'ALL',
    application: document.getElementById('soc-audit-portal-filter')?.value || 'ALL',
    result: document.getElementById('soc-audit-result-filter')?.value || 'ALL',
    risk_level: document.getElementById('soc-audit-risk-filter')?.value || 'ALL',
    date_from: document.getElementById('soc-audit-date-from')?.value || '',
    date_to: document.getElementById('soc-audit-date-to')?.value || '',
  };
};

window.loadSecurityIntelAccountCards = async function() {
  const grid = document.getElementById('intel-accounts-cards-grid');
  const badge = document.getElementById('soc-audit-count-badge');
  if (!grid || !window.cognisec?.fetchSocUsersDirectory) return;

  const search = document.getElementById('intel-acct-search')?.value?.trim() || '';
  const account_status = document.getElementById('intel-acct-status')?.value || 'ALL';
  const date_from = document.getElementById('intel-acct-date-from')?.value || '';
  const date_to = document.getElementById('intel-acct-date-to')?.value || '';

  try {
    const res = await window.cognisec.fetchSocUsersDirectory({
      search,
      scope: 'genuine',
      account_status,
      date_from,
      date_to,
      sort_by: 'last_login',
      sort_dir: 'desc',
      page: 1,
      page_size: 100,
    });
    const users = res.items || [];
    if (badge) badge.textContent = `${res.total || 0} Registered Users`;

    if (users.length === 0) {
      grid.innerHTML = `<div class="p-8 text-center text-slate-400 text-sm col-span-full rounded-2xl bg-black/50 border border-red-950">No genuine registered accounts match the current filters.</div>`;
      return;
    }

    grid.innerHTML = users.map(u => {
      const isAct = u.account_status === 'ACTIVE';
      const regStr = u.created_at ? formatSocTimestamp(u.created_at) : 'Not recorded';
      const lastLoginStr = u.last_login ? formatSocTimestamp(u.last_login) : 'Not recorded';
      const verBadge = u.email_verified
        ? `<span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-950 text-emerald-300 border border-emerald-800">Verified</span>`
        : `<span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-900 text-slate-400 border border-slate-700">Unverified</span>`;
      const stBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-semibold ${isAct ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-red-950 text-red-300 border border-red-800'}">${escapeHtml(u.account_status)}</span>`;

      return `
        <div class="p-5 rounded-2xl bg-black/75 border border-red-900/60 hover:border-red-600/80 transition-all flex flex-col justify-between gap-4 shadow-lg">
          <div class="space-y-3">
            <div class="flex items-start justify-between gap-2">
              <div class="min-w-0">
                <h5 class="font-heading font-bold text-lg text-white truncate">${escapeHtml(u.name || 'Registered User')}</h5>
                <p class="text-xs font-mono text-sky-300 truncate">${escapeHtml(u.email)}</p>
              </div>
              <div class="flex flex-col items-end gap-1 shrink-0">
                ${stBadge}
                ${verBadge}
              </div>
            </div>

            <div class="grid grid-cols-2 gap-2.5 pt-2 border-t border-red-950/70 text-xs font-mono">
              <div>
                <span class="text-slate-400 text-[10px] uppercase block">Registered</span>
                <span class="text-slate-200">${regStr}</span>
              </div>
              <div>
                <span class="text-slate-400 text-[10px] uppercase block">Last Login</span>
                <span class="text-slate-200">${lastLoginStr}</span>
              </div>
              <div>
                <span class="text-slate-400 text-[10px] uppercase block">Total Logins</span>
                <strong class="text-white text-sm">${u.total_sessions_count ?? 0}</strong>
              </div>
              <div>
                <span class="text-slate-400 text-[10px] uppercase block">Registered Devices</span>
                <strong class="text-white text-sm">${u.registered_devices_count ?? 0}</strong>
              </div>
            </div>
          </div>

          <button type="button" onclick="window.openIntelUserFullHistory(${u.id})" class="w-full py-2.5 px-4 rounded-xl bg-red-600 hover:bg-red-500 text-white font-bold text-xs tracking-wider uppercase cursor-pointer transition-all shadow-[0_0_12px_rgba(220,38,38,0.35)]">
            VIEW FULL HISTORY
          </button>
        </div>
      `;
    }).join('');
  } catch (err) {
    grid.innerHTML = `<div class="p-8 text-center text-red-400 text-sm col-span-full">Failed to load registered accounts: ${escapeHtml(err.message)}</div>`;
  }
};

window.backToIntelAccounts = function() {
  window._socAuditState.selected_user_id = null;
  document.getElementById('intel-user-history-view')?.classList.add('hidden');
  document.getElementById('intel-accounts-directory-panel')?.classList.remove('hidden');
  document.getElementById('sec-intel-detail-panel')?.classList.add('hidden');
  window.loadSecurityIntelAccountCards();
};

window.switchIntelUserHistoryTab = function(tab) {
  window._socAuditState.uh_tab = tab;
  const tabs = ['logins', 'devices', 'portal', 'security'];
  tabs.forEach(t => {
    const btn = document.getElementById(`intel-uh-tab-${t}`);
    const panel = document.getElementById(`intel-uh-panel-${t}`);
    if (panel) panel.classList.toggle('hidden', t !== tab);
    if (btn) {
      btn.className = t === tab
        ? 'px-3.5 py-1.5 rounded-lg text-xs font-bold bg-red-600 text-white cursor-pointer'
        : 'px-3.5 py-1.5 rounded-lg text-xs font-bold bg-black border border-red-900/60 text-slate-300 hover:text-white cursor-pointer';
    }
  });
  if (tab === 'security' && window._socAuditState.selected_user_id) {
    window._socAuditState.page = 1;
    window.loadSocAuditTrail();
  }
};

window.openIntelUserFullHistory = async function(userId) {
  window._socAuditState.selected_user_id = userId;
  window._socAuditState.page = 1;
  document.getElementById('intel-accounts-directory-panel')?.classList.add('hidden');
  document.getElementById('intel-user-history-view')?.classList.remove('hidden');
  document.getElementById('sec-intel-detail-panel')?.classList.add('hidden');

  const ovEl = document.getElementById('intel-uh-overview');
  const loginsEl = document.getElementById('intel-uh-panel-logins');
  const devicesEl = document.getElementById('intel-uh-panel-devices');
  const portalEl = document.getElementById('intel-uh-panel-portal');
  if (ovEl) ovEl.innerHTML = `<div class="col-span-full text-center text-slate-400 py-3">Loading account overview...</div>`;
  if (loginsEl) loginsEl.innerHTML = `<div class="p-6 text-center text-slate-400 text-sm">Loading login history...</div>`;
  if (devicesEl) devicesEl.innerHTML = `<div class="p-6 text-center text-slate-400 text-sm">Loading device history...</div>`;
  if (portalEl) portalEl.innerHTML = `<div class="p-6 text-center text-slate-400 text-sm">Loading portal activity...</div>`;

  window.switchIntelUserHistoryTab('logins');

  try {
    const [d, bp] = await Promise.all([
      window.cognisec.fetchSocUserDetails(userId),
      window.cognisec.fetchAdminUserBehaviorProfile ? window.cognisec.fetchAdminUserBehaviorProfile(userId) : Promise.resolve(null),
    ]);
    const u = d.user || {};
    const logins = d.login_history || [];
    const devices = d.devices || [];
    const portalActs = d.portal_activity || [];

    const nameEl = document.getElementById('intel-uh-user-name');
    const emailEl = document.getElementById('intel-uh-user-email');
    const statusBadge = document.getElementById('intel-uh-status-badge');
    if (nameEl) nameEl.textContent = u.name || 'Registered User';
    if (emailEl) emailEl.textContent = u.email || 'Not recorded';
    if (statusBadge) {
      const isAct = u.account_status === 'ACTIVE';
      statusBadge.textContent = u.account_status || 'UNKNOWN';
      statusBadge.className = `px-3 py-1 rounded-lg text-xs font-semibold border ${isAct ? 'border-emerald-800 bg-emerald-950 text-emerald-300' : 'border-red-800 bg-red-950 text-red-300'}`;
    }

    if (ovEl) {
      const bpMeans = bp?.baseline_features?.means || {};
      const bpStds = bp?.baseline_features?.stds || {};
      const featureKeys = Object.keys(bpMeans);
      const tenDimHtml = featureKeys.length > 0 ? featureKeys.map(k => {
        const m = Number(bpMeans[k] ?? 0).toFixed(2);
        const sd = Number(bpStds[k] ?? 0).toFixed(2);
        return `<div class="p-2 rounded-lg bg-black/70 border border-slate-800"><span class="text-slate-400 text-[10px] block truncate">${escapeHtml(k)}</span><strong class="text-slate-100">${m} ± ${sd}</strong></div>`;
      }).join('') : `<div class="col-span-full text-slate-400">Welford baseline means not yet established.</div>`;

      ovEl.innerHTML = `
        <div><span class="text-slate-400 block">Full Name</span><strong class="text-white">${escapeHtml(u.name || 'Not recorded')}</strong></div>
        <div><span class="text-slate-400 block">Email</span><strong class="text-sky-300">${escapeHtml(u.email || 'Not recorded')}</strong></div>
        <div><span class="text-slate-400 block">Registered &amp; Verified</span><strong class="text-slate-200">${u.created_at ? formatSocTimestamp(u.created_at) : 'Not recorded'} · ${u.email_verified ? 'Verified' : 'Unverified'}</strong></div>
        <div><span class="text-slate-400 block">Total Logins</span><strong class="text-white">${u.total_sessions_count ?? 0}</strong></div>
        <div><span class="text-slate-400 block">Last Login</span><strong class="text-slate-200">${u.last_login ? formatSocTimestamp(u.last_login) : 'Not recorded'}</strong></div>
        <div><span class="text-slate-400 block">Total Devices</span><strong class="text-white">${devices.length}</strong></div>
        ${bp ? `
          <div class="col-span-full pt-3 mt-1 border-t border-red-950/70 space-y-2">
            <div class="flex flex-wrap items-center justify-between gap-2">
              <strong class="text-red-300 uppercase tracking-wider text-[11px]">SOC Behavioral Intelligence &amp; 10-D Welford Baseline</strong>
              <span class="text-slate-300">Risk: <strong>${escapeHtml(bp.latest_risk_level || 'LOW')}</strong> (${bp.latest_risk_score !== null && bp.latest_risk_score !== undefined ? Number(bp.latest_risk_score).toFixed(3) : '0.000'}) · Isolation Forest: <strong>${escapeHtml(bp.ml_status)}</strong> (Anomaly: ${Number(bp.anomaly_score || 0).toFixed(3)}) · Samples: <strong>${bp.sample_count}</strong> (${escapeHtml(bp.baseline_status)})</span>
            </div>
            <div class="grid grid-cols-2 sm:grid-cols-5 gap-2">${tenDimHtml}</div>
          </div>
        ` : ''}
      `;
    }

    if (loginsEl) {
      const rows = logins.length > 0 ? logins.map(l => {
        const dt = l.timestamp ? new Date(l.timestamp) : null;
        const datePart = dt && !isNaN(dt) ? dt.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) : 'Not recorded';
        const timePart = dt && !isNaN(dt) ? dt.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : 'Not recorded';
        const isOk = l.result === 'Successful';
        return `
          <tr class="hover:bg-red-950/15 text-xs">
            <td class="py-2.5 px-3 font-mono text-slate-200 whitespace-nowrap">${escapeHtml(datePart)}</td>
            <td class="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap">${escapeHtml(timePart)}</td>
            <td class="py-2.5 px-3 whitespace-nowrap"><span class="px-2 py-0.5 rounded font-semibold border ${isOk ? 'bg-emerald-950 text-emerald-300 border-emerald-800' : 'bg-red-950 text-red-300 border-red-800'}">${escapeHtml(l.result)}</span></td>
            <td class="py-2.5 px-3 text-slate-200">${escapeHtml(formatSocPortalName(l.application))}</td>
            <td class="py-2.5 px-3 text-slate-200">${escapeHtml(l.device_name || 'Not recorded')} <span class="text-slate-400">(${escapeHtml(l.device_type || 'Unknown')})</span></td>
            <td class="py-2.5 px-3 text-slate-300">${escapeHtml(l.browser || 'Not recorded')} · ${escapeHtml(l.os || 'Not recorded')}</td>
            <td class="py-2.5 px-3 font-mono text-slate-300">${escapeHtml(l.ip_address || 'Not recorded')}</td>
            <td class="py-2.5 px-3 text-slate-300">${escapeHtml(l.location || 'Location unavailable')}</td>
            <td class="py-2.5 px-3 font-mono text-slate-400">${escapeHtml(l.session_id ? l.session_id.slice(0, 14) + '…' : 'Not recorded')}</td>
          </tr>
        `;
      }).join('') : `<tr><td colspan="9" class="p-6 text-center text-slate-400 text-sm">No login records unavailable or none recorded yet.</td></tr>`;
      loginsEl.innerHTML = `
        <div class="overflow-x-auto rounded-xl border border-red-950 bg-black/50">
          <table class="w-full text-left border-collapse">
            <thead>
              <tr class="border-b border-red-950 text-slate-300 text-[11px] uppercase">
                <th class="py-2.5 px-3">Date</th>
                <th class="py-2.5 px-3">Time</th>
                <th class="py-2.5 px-3">Result</th>
                <th class="py-2.5 px-3">Portal</th>
                <th class="py-2.5 px-3">Device</th>
                <th class="py-2.5 px-3">Browser &amp; OS</th>
                <th class="py-2.5 px-3">IP Address</th>
                <th class="py-2.5 px-3">Location</th>
                <th class="py-2.5 px-3">Session ID</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-red-950/40">${rows}</tbody>
          </table>
        </div>
      `;
    }

    if (devicesEl) {
      devicesEl.innerHTML = devices.length > 0 ? `<div class="grid grid-cols-1 lg:grid-cols-2 gap-3">${devices.map(dev => `
        <div class="p-4 rounded-xl bg-black/70 border border-slate-800 space-y-2 text-xs">
          <div class="flex items-center justify-between gap-2">
            <strong class="text-white text-sm">${escapeHtml(dev.nickname || 'Registered Device')}</strong>
            <span class="px-2 py-0.5 rounded font-semibold border ${dev.is_trusted ? 'bg-emerald-950 text-emerald-300 border-emerald-800' : 'bg-amber-950 text-amber-200 border-amber-800'}">${escapeHtml(dev.trust_state || 'UNKNOWN')}</span>
          </div>
          <div class="grid grid-cols-2 gap-2 text-slate-300 font-mono">
            <div><span class="text-slate-500 block">Fingerprint</span>${escapeHtml(dev.masked_fingerprint || 'Not recorded')}</div>
            <div><span class="text-slate-500 block">Browser / OS</span>${escapeHtml(dev.browser || 'Unknown')} · ${escapeHtml(dev.os || 'Unknown')}</div>
            <div><span class="text-slate-500 block">First Seen</span>${dev.first_seen ? formatSocTimestamp(dev.first_seen) : 'Not recorded'}</div>
            <div><span class="text-slate-500 block">Last Seen · Sessions</span>${dev.last_seen ? formatSocTimestamp(dev.last_seen) : 'Not recorded'} · ${dev.session_count ?? 0}</div>
          </div>
          <div class="text-slate-400">Type: <span class="text-slate-200">${escapeHtml(dev.device_type || 'Unknown')}</span> · Location: <span class="text-slate-200">${escapeHtml(dev.location || 'Location unavailable')}</span></div>
        </div>
      `).join('')}</div>` : `<div class="p-6 text-center text-slate-400 text-sm rounded-xl bg-black/50 border border-red-950">No registered devices recorded for this user.</div>`;
    }

    if (portalEl) {
      portalEl.innerHTML = portalActs.length > 0 ? `<div class="space-y-2 max-h-[28rem] overflow-y-auto pr-1">${portalActs.map(pa => `
        <div class="p-3 rounded-xl bg-black/60 border border-red-950/60 flex flex-wrap items-center justify-between gap-2 text-xs">
          <div>
            <span class="font-mono text-slate-400 mr-2">${formatSocTimestamp(pa.timestamp)}</span>
            <span class="px-2 py-0.5 rounded bg-black border border-slate-800 text-slate-200 mr-2">${escapeHtml(formatSocPortalName(pa.application))}</span>
            <strong class="text-white">${escapeHtml(pa.action_label)}</strong>
            <span class="text-slate-400 ml-1.5">· ${escapeHtml(pa.description || '')}</span>
            ${pa.session_id ? `<span class="text-slate-500 font-mono ml-2">[${escapeHtml(pa.session_id.slice(0, 14))}…]</span>` : ''}
          </div>
          <span class="px-2 py-0.5 rounded border border-slate-700 bg-slate-900 text-slate-200 font-semibold">${escapeHtml(pa.outcome || pa.decision || 'Recorded')}</span>
        </div>
      `).join('')}</div>` : `<div class="p-6 text-center text-slate-400 text-sm rounded-xl bg-black/50 border border-red-950">No portal activity events recorded for this user yet.</div>`;
    }
  } catch (err) {
    if (ovEl) ovEl.innerHTML = `<div class="col-span-full text-center text-red-400 py-3">Failed to load user history: ${escapeHtml(err.message)}</div>`;
  }
};

window.onSocAuditFilterChange = function(resetPage = false) {
  if (resetPage) window._socAuditState.page = 1;
  window.loadSocAuditTrail();
};

window.changeSocAuditPage = function(delta) {
  const next = window._socAuditState.page + delta;
  if (next >= 1 && next <= window._socAuditState.total_pages) {
    window._socAuditState.page = next;
    window.loadSocAuditTrail();
  }
};

window.switchSecurityIntelView = function(view) {
  window._socAuditState.view = view;
  const views = ['timeline', 'adaptive', 'agentic', 'incidents'];
  views.forEach(v => {
    const el = document.getElementById(`intel-view-${v}`);
    const btn = document.getElementById(`intel-subtab-${v}`);
    if (el) el.classList.toggle('hidden', v !== view);
    if (btn) {
      if (v === view) {
        btn.className = 'px-3.5 py-1.5 rounded-lg text-xs font-bold bg-red-600 text-white cursor-pointer';
      } else {
        btn.className = 'px-3.5 py-1.5 rounded-lg text-xs font-bold bg-black border border-red-900/60 text-slate-300 hover:text-white cursor-pointer';
      }
    }
  });
  if (view === 'adaptive') window.loadAdaptiveAuthHistoryView();
  else if (view === 'agentic') window.loadAgenticIntelligenceView();
  else if (view === 'incidents') { /* rendered inside #intel-view-incidents */ }
  else if (window._socAuditState.selected_user_id) window.openIntelUserFullHistory(window._socAuditState.selected_user_id);
  else window.backToIntelAccounts();
};

window.loadSecurityIntelOverview = async function() {
  if (!window.cognisec?.fetchSecurityIntelligenceOverview) return;
  try {
    const f = window._getSecurityIntelFilters();
    const ov = await window.cognisec.fetchSecurityIntelligenceOverview(f);
    const setTxt = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    setTxt('intel-stat-reg-users', ov.total_registered_users ?? 0);
    setTxt('intel-stat-active-users', ov.active_users_count ?? 0);
    setTxt('intel-stat-succ-logins', ov.successful_logins_count ?? 0);
    setTxt('intel-stat-fail-logins', ov.failed_logins_count ?? 0);
    setTxt('intel-stat-anomalies', ov.behavioral_anomalies_count ?? 0);
    setTxt('intel-stat-transitions', ov.risk_transitions_count ?? 0);
    setTxt('intel-stat-stepup-verifs', ov.step_up_verifications_count ?? 0);
    setTxt('intel-stat-incidents', ov.security_incidents_count ?? 0);
    setTxt('intel-stat-locks', ov.portal_locks_and_terminations_count ?? 0);
    const limEl = document.getElementById('sec-intel-limitations');
    if (limEl && Array.isArray(ov.data_limitations) && ov.data_limitations.length > 0) {
      limEl.innerHTML = `<strong class="text-slate-300">Telemetry Scope Note:</strong> ${ov.data_limitations.map(escapeHtml).join(' ')}`;
      limEl.classList.remove('hidden');
    }
  } catch (e) {
    console.warn('Overview load failed:', e);
  }
};

window.openSecurityEventDetail = async function(eventId) {
  const panel = document.getElementById('sec-intel-detail-panel');
  const body = document.getElementById('sec-intel-detail-body');
  const sub = document.getElementById('intel-detail-subtitle');
  if (!panel || !body || !window.cognisec?.fetchSecurityEventDetail) return;

  panel.classList.remove('hidden');
  body.innerHTML = `<div class="p-6 text-center text-slate-400 text-sm">Loading investigation dossier for event #${eventId}...</div>`;
  panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

  try {
    const d = await window.cognisec.fetchSecurityEventDetail(eventId);
    const ev = d.event || {};
    const bi = d.behavioural_intelligence || {};
    const sess = d.session;
    const dev = d.device;
    const arb = d.arbiter_decision;

    if (sub) sub.textContent = `Event #${ev.id} · ${ev.action_label || ev.action_code} · ${formatSocTimestamp(ev.timestamp)}`;

    const riskTransitionHtml = ev.previous_risk_level
      ? `<span class="text-slate-300 font-mono">${escapeHtml(ev.previous_risk_level)}</span> → <span class="text-red-300 font-bold font-mono">${escapeHtml(ev.risk_level)}</span>`
      : `<span class="text-red-300 font-bold font-mono">${escapeHtml(ev.risk_level || 'Not recorded')}</span>`;

    const featuresRows = (bi.features || []).map(ft => {
      const obsTxt = ft.observed !== null && ft.observed !== undefined ? `${ft.observed} ${escapeHtml(ft.unit)}` : '—';
      const baseTxt = ft.baseline_mean !== null && ft.baseline_mean !== undefined
        ? `${ft.baseline_mean}${ft.baseline_std !== null && ft.baseline_std !== undefined ? ` ± ${ft.baseline_std}` : ''} ${escapeHtml(ft.unit)}`
        : 'Not learned';
      const devTxt = ft.deviation_z !== null && ft.deviation_z !== undefined ? `${ft.deviation_z > 0 ? '+' : ''}${ft.deviation_z}σ` : '—';
      const stColor = ft.status === 'High deviation' ? 'text-red-400 font-bold' : (ft.status === 'Moderate deviation' ? 'text-amber-300' : 'text-slate-400');
      return `
        <tr class="border-b border-slate-800/70">
          <td class="py-1.5 px-2 text-slate-200 font-medium">${escapeHtml(ft.label)}</td>
          <td class="py-1.5 px-2 font-mono text-white">${obsTxt}</td>
          <td class="py-1.5 px-2 font-mono text-slate-300">${baseTxt}</td>
          <td class="py-1.5 px-2 font-mono ${stColor}">${devTxt}</td>
          <td class="py-1.5 px-2 text-xs ${stColor}">${escapeHtml(ft.status)}</td>
        </tr>`;
    }).join('');

    const adaptiveRows = (d.adaptive_auth_history || []).map(ad => `
      <tr class="border-b border-slate-800/70">
        <td class="py-1.5 px-2 font-mono text-xs text-slate-400">${formatSocTimestamp(ad.timestamp)}</td>
        <td class="py-1.5 px-2 text-slate-200">${escapeHtml(ad.requested_factor)}</td>
        <td class="py-1.5 px-2 font-mono text-xs text-slate-300">${escapeHtml(ad.risk_level || '—')}</td>
        <td class="py-1.5 px-2 text-xs font-semibold ${ad.challenge_status === 'VERIFIED' ? 'text-emerald-400' : (ad.challenge_status === 'ISSUED' ? 'text-sky-300' : 'text-red-400')}">${escapeHtml(ad.actual_result)}</td>
      </tr>`).join('');

    const agentCards = (d.agent_executions || []).map(ag => {
      const isFb = (ag.analysis_status || '').includes('FALLBACK') || ag.analysis_status === 'FAILED';
      const badgeCls = ag.analysis_status === 'COMPLETED' ? 'bg-emerald-950 text-emerald-300 border-emerald-800' : (isFb ? 'bg-amber-950 text-amber-200 border-amber-800' : 'bg-slate-900 text-slate-400 border-slate-700');
      return `
        <div class="p-3 rounded-xl bg-black/70 border border-slate-800 space-y-1">
          <div class="flex items-center justify-between gap-2">
            <strong class="text-white text-xs">${escapeHtml(ag.agent_name)}</strong>
            <span class="px-2 py-0.5 rounded text-[10px] font-bold border ${badgeCls}">${escapeHtml(ag.analysis_status)}</span>
          </div>
          <div class="text-[11px] text-slate-300">${escapeHtml(ag.main_finding)}</div>
          <div class="text-[10px] text-slate-500 font-mono flex flex-wrap gap-3">
            <span>Provider: ${escapeHtml(ag.provider || '—')} (${escapeHtml(ag.provider_status || '—')})</span>
            ${ag.recommendation ? `<span>Rec (Advisory): ${escapeHtml(ag.recommendation)}</span>` : ''}
            ${ag.confidence !== null && ag.confidence !== undefined ? `<span>Confidence: ${ag.confidence}</span>` : ''}
            ${ag.execution_time_ms !== null && ag.execution_time_ms !== undefined ? `<span>Time: ${ag.execution_time_ms}ms</span>` : ''}
          </div>
        </div>`;
    }).join('');

    const incList = (d.related_incidents || []).map(inc => `
      <div class="flex items-center justify-between gap-2 p-2 rounded-lg bg-black/60 border border-red-950">
        <div class="text-xs"><strong class="text-white">#${inc.id} ${escapeHtml(inc.alert_type)}</strong> <span class="text-slate-400">(${escapeHtml(inc.severity)} · ${escapeHtml(inc.status)})</span></div>
        ${typeof window.openIncidentDossier === 'function' ? `<button type="button" onclick="window.openIncidentDossier(${inc.id})" class="px-2.5 py-1 rounded bg-red-600 hover:bg-red-500 text-white text-[11px] font-bold cursor-pointer">Open Dossier</button>` : ''}
      </div>`).join('');

    body.innerHTML = `
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div class="p-3.5 rounded-xl bg-black/60 border border-red-950/80 space-y-1.5 text-xs">
          <div class="text-red-400 font-bold uppercase tracking-wider text-[10px]">Event &amp; Risk Assessment</div>
          <div><span class="text-slate-400">Summary:</span> <span class="text-white">${escapeHtml(ev.summary || 'Not recorded')}</span></div>
          <div><span class="text-slate-400">Risk Transition:</span> ${riskTransitionHtml}</div>
          <div><span class="text-slate-400">Risk / Anomaly Score:</span> <span class="font-mono text-slate-200">${ev.risk_score ?? '—'} / ${ev.anomaly_score ?? '—'}</span></div>
          <div><span class="text-slate-400">Actual Enforcement:</span> <span class="font-semibold text-amber-300">${escapeHtml(ev.result || 'Recorded')}</span></div>
        </div>
        <div class="p-3.5 rounded-xl bg-black/60 border border-red-950/80 space-y-1.5 text-xs">
          <div class="text-red-400 font-bold uppercase tracking-wider text-[10px]">User &amp; Portal</div>
          <div><span class="text-slate-400">Name:</span> <span class="text-white">${escapeHtml(d.user?.name || 'System / Platform')}</span></div>
          <div><span class="text-slate-400">Email:</span> <span class="text-slate-200">${escapeHtml(d.user?.email || 'Not recorded')}</span></div>
          <div><span class="text-slate-400">Portal:</span> <span class="text-slate-200">${escapeHtml(formatSocPortalName(ev.application))}</span></div>
          <div><span class="text-slate-400">Provenance / Verified:</span> <span class="font-mono text-slate-300">${escapeHtml(d.user?.registration_source || 'Legacy/Unstamped')} · ${d.user?.email_verified ? 'Verified' : 'No'}</span></div>
        </div>
        <div class="p-3.5 rounded-xl bg-black/60 border border-red-950/80 space-y-1.5 text-xs">
          <div class="text-red-400 font-bold uppercase tracking-wider text-[10px]">Session &amp; Device</div>
          <div><span class="text-slate-400">Session:</span> <span class="font-mono text-slate-200">${escapeHtml(sess?.id || ev.session_id || 'Not recorded')}</span></div>
          <div><span class="text-slate-400">Session Status:</span> <span class="text-slate-200">${escapeHtml(sess?.status || 'Not recorded')}</span></div>
          <div><span class="text-slate-400">Device:</span> <span class="text-slate-200">${dev ? escapeHtml(`${dev.browser_name || ''} / ${dev.os_name || ''} (${dev.trust_status})`) : 'Not recorded'}</span></div>
        </div>
      </div>

      <!-- 3. Behavioural Intelligence Panel (10 Canonical Features) -->
      <div class="p-4 rounded-xl bg-black/60 border border-red-950/80 space-y-3">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h6 class="font-heading font-bold text-sm text-white">Behavioural Intelligence (10-Dimensional Welford &amp; Isolation Forest)</h6>
            <p class="text-xs text-slate-400">${bi.note ? escapeHtml(bi.note) : 'Observed session telemetry compared against learned Welford baseline.'}</p>
          </div>
          <div class="flex flex-wrap gap-2 text-xs font-mono">
            <span class="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-slate-200">Maturity: ${escapeHtml(bi.modality_maturity || 'COLD_START')} (${bi.sample_count || 0} samples)</span>
            <span class="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-amber-300">Anomaly: ${bi.anomaly_score ?? 'Not recorded'}</span>
          </div>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-xs border-collapse">
            <thead>
              <tr class="border-b border-red-950 text-slate-400 uppercase text-[10px]">
                <th class="py-1.5 px-2">Feature</th>
                <th class="py-1.5 px-2">Observed</th>
                <th class="py-1.5 px-2">Learned Baseline (Mean ± Std)</th>
                <th class="py-1.5 px-2">Deviation</th>
                <th class="py-1.5 px-2">Status</th>
              </tr>
            </thead>
            <tbody>${featuresRows}</tbody>
          </table>
        </div>
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div class="p-4 rounded-xl bg-black/60 border border-red-950/80 space-y-2">
          <h6 class="font-heading font-bold text-sm text-white">Adaptive Authentication History (Session/User)</h6>
          ${adaptiveRows ? `<table class="w-full text-left text-xs"><thead><tr class="border-b border-red-950 text-slate-400 text-[10px] uppercase"><th class="py-1 px-2">Time</th><th class="py-1 px-2">Factor</th><th class="py-1 px-2">Risk</th><th class="py-1 px-2">Outcome</th></tr></thead><tbody>${adaptiveRows}</tbody></table>` : '<div class="text-xs text-slate-500">No adaptive challenge events recorded for this session/user.</div>'}
        </div>
        <div class="p-4 rounded-xl bg-black/60 border border-red-950/80 space-y-2">
          <div class="flex items-center justify-between">
            <h6 class="font-heading font-bold text-sm text-white">Agentic AI vs Deterministic Arbiter</h6>
            ${arb ? `<span class="px-2 py-0.5 rounded bg-red-950 border border-red-700 text-red-200 text-[11px] font-bold">Arbiter: ${escapeHtml(arb.decision)} (${escapeHtml(arb.risk_level)})</span>` : ''}
          </div>
          <div class="space-y-2 max-h-64 overflow-y-auto pr-1">${agentCards}</div>
        </div>
      </div>

      ${incList ? `<div class="p-4 rounded-xl bg-black/60 border border-red-950/80 space-y-2"><h6 class="font-heading font-bold text-sm text-white">Related Security Incidents</h6>${incList}</div>` : ''}
      ${(d.related_session_events && d.related_session_events.length > 0) ? `
        <div class="p-4 rounded-xl bg-black/60 border border-red-950/80 space-y-2">
          <h6 class="font-heading font-bold text-sm text-white">Related Events in Same Session</h6>
          <div class="space-y-1.5 max-h-56 overflow-y-auto pr-1">
            ${d.related_session_events.map(re => `
              <div onclick="window.openSecurityEventDetail(${re.id})" class="p-2 rounded bg-black/70 border border-slate-800 hover:border-red-700 text-xs flex flex-wrap items-center justify-between gap-2 cursor-pointer">
                <div>
                  <span class="font-mono text-slate-400 mr-2">${formatSocTimestamp(re.timestamp)}</span>
                  <strong class="text-white">${escapeHtml(re.action_label)}</strong>
                  <span class="text-slate-400 ml-1">· ${escapeHtml(re.summary || '')}</span>
                </div>
                <span class="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-slate-200 font-mono text-[10px]">${escapeHtml(re.risk_level || 'LOW')} · ${escapeHtml(re.result)}</span>
              </div>
            `).join('')}
          </div>
        </div>
      ` : ''}
    `;
  } catch (e) {
    body.innerHTML = `<div class="p-4 text-red-400 text-sm">Failed to load event detail: ${escapeHtml(e.message)}</div>`;
  }
};

window.loadAdaptiveAuthHistoryView = async function() {
  const container = document.getElementById('intel-adaptive-container');
  if (!container || !window.cognisec?.fetchAdaptiveAuthHistory) return;
  window.loadSecurityIntelOverview();
  try {
    const f = window._getSecurityIntelFilters();
    const rows = await window.cognisec.fetchAdaptiveAuthHistory(f);
    if (!rows || rows.length === 0) {
      container.innerHTML = `<div class="p-8 text-center text-slate-400 text-sm">No adaptive authentication events match the current filters.</div>`;
      return;
    }
    let html = `<table class="w-full text-left text-sm border-collapse"><thead><tr class="border-b border-red-950 text-slate-300 text-xs uppercase"><th class="py-2.5 px-3">Timestamp</th><th class="py-2.5 px-3">User &amp; Portal</th><th class="py-2.5 px-3">Deterministic Risk</th><th class="py-2.5 px-3">Selected Factor</th><th class="py-2.5 px-3">Challenge Status</th><th class="py-2.5 px-3">Reason</th></tr></thead><tbody class="divide-y divide-red-950/40 text-xs">`;
    rows.forEach(r => {
      const stCls = r.challenge_status === 'VERIFIED' ? 'bg-emerald-950 text-emerald-300 border-emerald-800' : (r.challenge_status === 'ISSUED' ? 'bg-sky-950 text-sky-300 border-sky-800' : 'bg-red-950 text-red-300 border-red-800');
      html += `<tr class="hover:bg-red-950/15 cursor-pointer" onclick="window.openSecurityEventDetail(${r.id}); window.switchSecurityIntelView('timeline');">
        <td class="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap">${formatSocTimestamp(r.timestamp)}</td>
        <td class="py-2.5 px-3"><div class="text-white font-medium">${escapeHtml(r.user_email || 'Not recorded')}</div><div class="text-slate-400">${escapeHtml(formatSocPortalName(r.application))}</div></td>
        <td class="py-2.5 px-3 font-mono text-slate-200">${escapeHtml(r.risk_level || '—')}${r.risk_score !== null && r.risk_score !== undefined ? ` (${r.risk_score})` : ''}</td>
        <td class="py-2.5 px-3 text-white font-semibold">${escapeHtml(r.requested_factor)}</td>
        <td class="py-2.5 px-3 whitespace-nowrap"><span class="px-2 py-0.5 rounded border font-semibold ${stCls}">${escapeHtml(r.actual_result)}</span></td>
        <td class="py-2.5 px-3 text-slate-300 max-w-sm truncate">${escapeHtml(r.reason)}</td>
      </tr>`;
    });
    html += `</tbody></table>`;
    container.innerHTML = html;
  } catch (e) {
    container.innerHTML = `<div class="p-6 text-center text-red-400 text-sm">Failed to load adaptive auth history: ${escapeHtml(e.message)}</div>`;
  }
};

window.loadAgenticIntelligenceView = async function() {
  const container = document.getElementById('intel-agentic-container');
  if (!container || !window.cognisec?.fetchAgenticIntelligence) return;
  window.loadSecurityIntelOverview();
  try {
    const f = window._getSecurityIntelFilters();
    const res = await window.cognisec.fetchAgenticIntelligence(f);
    const execs = res.executions || [];
    if (execs.length === 0) {
      container.innerHTML = `<div class="p-8 text-center text-slate-400 text-sm">No persisted agentic orchestration events match the current filters.</div>`;
      return;
    }
    container.innerHTML = execs.map(ex => {
      const arb = ex.arbiter_decision || {};
      const agentsHtml = (ex.agents || []).map(ag => {
        const isFb = (ag.analysis_status || '').includes('FALLBACK') || ag.analysis_status === 'FAILED';
        const stCls = ag.analysis_status === 'COMPLETED' ? 'text-emerald-300' : (isFb ? 'text-amber-300' : 'text-slate-500');
        return `<div class="p-2.5 rounded-lg bg-black/70 border border-slate-800 text-xs space-y-1">
          <div class="flex items-center justify-between"><strong class="text-white">${escapeHtml(ag.agent_name)}</strong><span class="font-mono text-[10px] ${stCls}">${escapeHtml(ag.analysis_status)}</span></div>
          <div class="text-slate-400 text-[11px]">${escapeHtml(ag.main_finding)}</div>
        </div>`;
      }).join('');
      return `
        <div class="p-4 rounded-xl bg-black/70 border border-red-950 space-y-3">
          <div class="flex flex-wrap items-center justify-between gap-2 border-b border-red-950/60 pb-2 text-xs">
            <div><strong class="text-white">${escapeHtml(ex.event_type)}</strong> <span class="text-slate-400">· ${formatSocTimestamp(ex.timestamp)} · ${escapeHtml(ex.user_email || 'System')} · ${escapeHtml(formatSocPortalName(ex.application))}</span></div>
            <div class="flex items-center gap-2">
              <span class="px-2.5 py-0.5 rounded bg-red-950 border border-red-700 text-red-200 font-bold">Deterministic Arbiter: ${escapeHtml(arb.decision || '—')} (${escapeHtml(arb.risk_level || '—')})</span>
              <button type="button" onclick="window.openSecurityEventDetail(${ex.event_id}); window.switchSecurityIntelView('timeline');" class="px-2.5 py-0.5 rounded bg-slate-900 border border-slate-700 text-slate-200 cursor-pointer">Inspect</button>
            </div>
          </div>
          <div class="grid grid-cols-1 md:grid-cols-5 gap-2">${agentsHtml}</div>
        </div>`;
    }).join('');
  } catch (e) {
    container.innerHTML = `<div class="p-6 text-center text-red-400 text-sm">Failed to load agentic intelligence: ${escapeHtml(e.message)}</div>`;
  }
};

window.loadSocAuditTrail = async function() {
  const container = document.getElementById('soc-audit-table-container');
  const countBadge = document.getElementById('soc-audit-count-badge');
  const pageInfo = document.getElementById('soc-audit-page-info');
  const prevBtn = document.getElementById('soc-audit-prev-btn');
  const nextBtn = document.getElementById('soc-audit-next-btn');
  if (!container || !window.cognisec) return;
  if (!window._socAuditState.selected_user_id) {
    return;
  }

  window.loadSecurityIntelOverview();
  if (window._socAuditState.view === 'adaptive') { return window.loadAdaptiveAuthHistoryView(); }
  if (window._socAuditState.view === 'agentic') { return window.loadAgenticIntelligenceView(); }

  const { search, activity_scope, user_id, category, application, result, risk_level, date_from, date_to } = window._getSecurityIntelFilters();

  try {
    const res = await window.cognisec.fetchSocAuditTrail({
      search,
      activity_scope,
      user_id,
      category,
      application,
      result,
      risk_level,
      date_from,
      date_to,
      page: window._socAuditState.page,
      page_size: window._socAuditState.page_size,
    });
    const items = res.items || [];
    window._socAuditState.page = res.page || 1;
    window._socAuditState.total_pages = res.total_pages || 1;

    if (countBadge) countBadge.textContent = `${res.total || 0} Events`;
    if (pageInfo) pageInfo.textContent = `Page ${res.page || 1} of ${res.total_pages || 1} (${res.total || 0} total events)`;
    if (prevBtn) prevBtn.disabled = (res.page || 1) <= 1;
    if (nextBtn) nextBtn.disabled = (res.page || 1) >= (res.total_pages || 1);

    if (items.length === 0) {
      container.innerHTML = `<div class="p-8 text-center text-slate-400 text-sm">No user security events match the current filters.</div>`;
      return;
    }

    let html = `
      <table class="w-full text-left text-sm border-collapse">
        <thead>
          <tr class="border-b border-red-950 text-slate-300 text-xs uppercase tracking-wider font-semibold">
            <th class="py-3 px-3">Timestamp</th>
            <th class="py-3 px-3">User</th>
            <th class="py-3 px-3">Portal</th>
            <th class="py-3 px-3">Activity</th>
            <th class="py-3 px-3">Risk Level</th>
            <th class="py-3 px-3">System Decision</th>
            <th class="py-3 px-3">Outcome</th>
            <th class="py-3 px-3 text-right">Investigate</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-red-950/40 text-sm">
    `;
    items.forEach(item => {
      const timeStr = formatSocTimestamp(item.timestamp);
      const resClass = (item.result === 'Successful' || item.result === 'Advisory Completed')
        ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
        : (item.result === 'Denied' || item.result === 'Failed' || item.result === 'Escalated by Arbiter'
          ? 'bg-red-950 text-red-300 border-red-800'
          : (item.result === 'Enforced' || item.result === 'Fallback (Timeout)' ? 'bg-amber-950 text-amber-200 border-amber-800' : 'bg-slate-900 text-slate-200 border-slate-700'));
      const riskClass = item.risk_level === 'CRITICAL'
        ? 'bg-red-600 text-white'
        : (item.risk_level === 'HIGH' ? 'bg-red-950 text-red-300 border border-red-800' : (item.risk_level === 'MEDIUM' ? 'bg-amber-950 text-amber-200 border border-amber-800' : 'bg-slate-900 text-slate-300 border border-slate-700'));
      const repeatBadge = item.repeat_count > 1
        ? `<span class="ml-1.5 px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px] font-mono" title="Collapsed consecutive identical entries within 60s">×${item.repeat_count}</span>`
        : '';
      const riskColHtml = item.previous_risk_level
        ? `<span class="text-xs font-mono text-slate-400">${escapeHtml(item.previous_risk_level)} →</span> <span class="px-2 py-0.5 rounded text-xs font-bold ${riskClass}">${escapeHtml(item.risk_level || 'Not recorded')}</span>`
        : `<span class="px-2 py-0.5 rounded text-xs font-bold ${riskClass}">${escapeHtml(item.risk_level || 'Not recorded')}</span>`;
      const sysDecision = (item.technical_details && item.technical_details.decision) || (item.result === 'Denied' ? 'DENY' : (item.result === 'Enforced' ? 'ENFORCE' : (item.result === 'Successful' ? 'ALLOW' : item.result || 'Not recorded')));

      html += `
        <tr class="hover:bg-red-950/15 transition-colors cursor-pointer" onclick="window.openSecurityEventDetail(${item.id})">
          <td class="py-3 px-3 text-slate-300 text-xs font-mono whitespace-nowrap">${timeStr}</td>
          <td class="py-3 px-3 text-xs">
            <div class="text-white font-semibold">${escapeHtml(item.target_user_name || 'Not recorded')}</div>
            <div class="text-slate-400 font-mono">${escapeHtml(item.target_user_email || 'Not recorded')}</div>
          </td>
          <td class="py-3 px-3 whitespace-nowrap">
            <span class="px-2 py-0.5 rounded bg-black/70 border border-slate-800 text-slate-200 text-xs">${escapeHtml(formatSocPortalName(item.application))}</span>
          </td>
          <td class="py-3 px-3 max-w-md">
            <div class="text-white font-semibold">${escapeHtml(item.action_label)}${repeatBadge}</div>
            <div class="text-slate-400 text-xs truncate" title="${escapeHtml(item.summary || '')}">${escapeHtml(item.summary || 'Not recorded')}</div>
          </td>
          <td class="py-3 px-3 whitespace-nowrap">${riskColHtml}</td>
          <td class="py-3 px-3 whitespace-nowrap font-mono text-xs text-slate-200">${escapeHtml(sysDecision)}</td>
          <td class="py-3 px-3 whitespace-nowrap">
            <span class="px-2.5 py-0.5 rounded-md text-xs font-semibold border ${resClass}">${escapeHtml(item.result)}</span>
          </td>
          <td class="py-3 px-3 text-right whitespace-nowrap">
            <button type="button" onclick="event.stopPropagation(); window.openSecurityEventDetail(${item.id})" class="px-3 py-1 rounded-lg bg-red-950/80 hover:bg-red-600 border border-red-800 text-white text-xs font-semibold cursor-pointer">Inspect</button>
          </td>
        </tr>
      `;
    });
    html += `</tbody></table>`;
    container.innerHTML = html;
  } catch (e) {
    container.innerHTML = `<div class="p-8 text-center text-red-400 text-sm">Failed to load security timeline: ${escapeHtml(e.message)}. <button onclick="window.loadSocAuditTrail()" class="underline text-slate-200 ml-1.5 font-semibold cursor-pointer">Retry</button></div>`;
  }
};

window.loadSocAuditLogs = function(actionFilter) {
  const select = document.getElementById('soc-audit-action-filter');
  if (select && actionFilter) select.value = actionFilter;
  window.loadSocAuditTrail();
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
    const s = dossier.session || null;
    const r = dossier.risk_assessment || {};
    const b = dossier.behavioral_signals || {};
    const sigs = b.observed_signals || {};
    const base = b.user_baseline || {};
    const devMap = b.deviation_status || {};
    const timeline = dossier.related_timeline || [];
    const actions = dossier.admin_actions || [];
    const stepChallenges = dossier.step_up_challenges || dossier.step_up_history || [];
    const hasBaseline = Number(b.baseline_samples || 0) > 0;

    const validTransitionsMap = {
      OPEN: ['OPEN', 'ACKNOWLEDGED', 'INVESTIGATING', 'CONTAINED', 'RESOLVED'],
      REOPENED: ['REOPENED', 'ACKNOWLEDGED', 'INVESTIGATING', 'CONTAINED', 'RESOLVED'],
      ACKNOWLEDGED: ['ACKNOWLEDGED', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'REOPENED'],
      INVESTIGATING: ['INVESTIGATING', 'ACKNOWLEDGED', 'CONTAINED', 'RESOLVED', 'REOPENED'],
      CONTAINED: ['CONTAINED', 'INVESTIGATING', 'RESOLVED', 'REOPENED'],
      RESOLVED: ['RESOLVED', 'REOPENED']
    };
    const allowedStatuses = validTransitionsMap[(dossier.status || 'OPEN').toUpperCase()] || ['OPEN', 'ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED', 'REOPENED'];

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

    const histRiskScoreStr = (r.risk_score !== undefined && r.risk_score !== null) ? Number(r.risk_score).toFixed(2) : 'Not recorded';
    const histAnomScoreStr = (r.anomaly_score !== undefined && r.anomaly_score !== null) ? Number(r.anomaly_score).toFixed(2) : 'Not recorded';
    const histDecision = r.risk_decision || r.decision || 'Not recorded';
    const histEnforcement = r.enforcement_outcome || dossier.enforcement_outcome || 'Not recorded';
    const histRiskLevel = r.risk_level || dossier.severity || 'Not recorded';
    const stepOutcome = stepChallenges.length > 0 ? (stepChallenges[0].outcome || stepChallenges[0].decision || stepChallenges[0].event_type) : 'None recorded';

    body.innerHTML = `
      <!-- A. Incident Information -->
      <div class="p-4 rounded-xl bg-black/80 border border-red-900/60 space-y-2.5 font-mono text-xs">
        <div class="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-red-950">
          <strong class="text-white uppercase tracking-wider text-xs">A. Incident Information</strong>
          <span class="text-[10px] text-slate-400">Category: <strong class="text-slate-200">${escapeHtml(formatSocEventLabel(dossier.incident_category || dossier.event_type || 'INCIDENT'))}</strong></span>
        </div>
        <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 text-[11px]">
          <div><span class="text-slate-500 block">Incident ID</span><strong class="text-white">#${dossier.incident_id}</strong></div>
          <div><span class="text-slate-500 block">Lifecycle Status</span><strong class="text-amber-300">${escapeHtml(dossier.status || 'OPEN')}</strong></div>
          <div><span class="text-slate-500 block">Created</span><strong class="text-slate-200">${formatSocTimestamp(dossier.timestamp)}</strong></div>
          <div><span class="text-slate-500 block">Last Updated</span><strong class="text-slate-200">${formatSocTimestamp(dossier.updated_at || dossier.timestamp)}</strong></div>
          <div><span class="text-slate-500 block">Assigned Analyst</span><strong class="text-sky-300">${escapeHtml(dossier.assigned_to || 'Unassigned')}</strong></div>
          <div class="col-span-2 sm:col-span-3"><span class="text-slate-500 block">Resolution Reason</span><strong class="text-emerald-300">${escapeHtml(dossier.resolution_reason || 'Not resolved')}</strong></div>
        </div>
      </div>

      <!-- B. User, Session & Device Information -->
      <div class="grid grid-cols-1 md:grid-cols-3 gap-3 font-mono text-xs">
        <div class="p-3.5 rounded-xl bg-black/70 border border-red-950 space-y-1">
          <span class="text-slate-400 text-[10px] uppercase font-bold block">B1. Associated User</span>
          <strong class="text-white block text-sm">${escapeHtml(u.name || 'Unknown User')}</strong>
          <div class="text-[11px] text-slate-300">${escapeHtml(u.email || 'Not recorded')}</div>
          <div class="text-[10px] text-slate-500 pt-1">Role: <span class="text-slate-300 font-bold">${escapeHtml(u.role || 'USER')}</span> &bull; Account: <span class="text-emerald-400 font-bold">${escapeHtml(u.account_status || 'Unknown')}</span></div>
        </div>

        <div class="p-3.5 rounded-xl bg-black/70 border border-red-950 space-y-1">
          <span class="text-slate-400 text-[10px] uppercase font-bold block">B2. Session Information (Current State)</span>
          ${s ? `
            <strong class="text-white block text-sm font-mono">${escapeHtml(s.id.substring(0, 18))}...</strong>
            <div class="text-[11px] text-slate-300">Current Status: <span class="${s.status === 'ACTIVE' ? 'text-emerald-400' : 'text-red-400'} font-bold">${escapeHtml(s.status)}</span></div>
            <div class="text-[10px] text-slate-500 pt-1">Portal: ${escapeHtml((s.application || dossier.application || 'platform').toUpperCase())} &bull; IP: ${escapeHtml(s.ip_address || 'Not recorded')}</div>
          ` : `
            <strong class="text-slate-400 block text-sm">No correlated session</strong>
            <div class="text-[10px] text-slate-500 pt-1">Portal: ${escapeHtml((dossier.application || 'platform').toUpperCase())}</div>
          `}
        </div>

        <div class="p-3.5 rounded-xl bg-black/70 border border-red-950 space-y-1">
          <span class="text-slate-400 text-[10px] uppercase font-bold block">B3. Device &amp; Browser</span>
          ${d ? `
            <strong class="text-white block text-sm">${escapeHtml(d.nickname || 'Web Client')}</strong>
            <div class="text-[10px] text-slate-400 font-mono truncate">${escapeHtml(d.browser || 'Unknown')} &bull; ${escapeHtml(d.os || 'Unknown')}</div>
            <div class="text-[10px] text-slate-500 pt-1">Trust: <span class="${d.trust_state === 'TRUSTED' ? 'text-emerald-400' : 'text-amber-300'} font-bold">${escapeHtml(d.trust_state || 'UNTRUSTED')}</span></div>
          ` : `<strong class="text-slate-400 block text-sm">No device record</strong>`}
        </div>
      </div>

      <!-- C. Historical Risk Assessment & Enforcement (at incident time) -->
      <div class="p-4 rounded-xl bg-black/80 border border-red-900/60 space-y-3 font-mono text-xs">
        <div class="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-red-950">
          <strong class="text-white uppercase tracking-wider text-xs">C. Historical Risk Assessment &amp; Enforcement (At Incident Time)</strong>
          <span class="px-2 py-0.5 rounded text-[10px] font-bold ${histDecision === 'ALLOW' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : (histDecision === 'Not recorded' ? 'bg-slate-900 text-slate-300 border border-slate-700' : 'bg-red-950 text-red-400 border border-red-800')}">
            DECISION: ${escapeHtml(histDecision)}
          </span>
        </div>
        <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2.5 text-xs">
          <div class="p-2.5 rounded bg-black/50 border border-red-950">
            <span class="text-slate-500 text-[10px] block">Incident Risk Score</span>
            <strong class="text-sm text-white">${histRiskScoreStr}</strong>
          </div>
          <div class="p-2.5 rounded bg-black/50 border border-red-950">
            <span class="text-slate-500 text-[10px] block">Incident Risk Tier</span>
            <strong class="text-sm text-amber-300">${escapeHtml(histRiskLevel)}</strong>
          </div>
          <div class="p-2.5 rounded bg-black/50 border border-red-950">
            <span class="text-slate-500 text-[10px] block">Anomaly Score</span>
            <strong class="text-sm text-amber-300">${histAnomScoreStr}</strong>
          </div>
          <div class="p-2.5 rounded bg-black/50 border border-red-950">
            <span class="text-slate-500 text-[10px] block">Adaptive Auth Rec</span>
            <strong class="text-sm text-sky-300">${escapeHtml(r.adaptive_auth_recommendation || 'Not recorded')}</strong>
          </div>
          <div class="p-2.5 rounded bg-black/50 border border-red-950">
            <span class="text-slate-500 text-[10px] block">Enforcement Action</span>
            <strong class="text-sm ${histEnforcement === 'ALLOW' ? 'text-emerald-400' : (histEnforcement === 'Not recorded' ? 'text-slate-300' : 'text-red-400')}">${escapeHtml(histEnforcement)}</strong>
          </div>
          <div class="p-2.5 rounded bg-black/50 border border-red-950">
            <span class="text-slate-500 text-[10px] block">Step-Up Outcome</span>
            <strong class="text-sm text-purple-300">${escapeHtml(stepOutcome)}</strong>
          </div>
        </div>
        <div class="text-[11px] text-slate-300 pt-1">
          <span class="text-slate-500">Summary:</span> ${escapeHtml(r.decision_reason || dossier.message || 'Not recorded')}
        </div>
      </div>

      <!-- D. Behavioural Evidence (Canonical 10 Features) -->
      <div class="p-4 rounded-xl bg-black/80 border border-red-950 space-y-3 font-mono text-xs">
        <div class="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-red-950">
          <strong class="text-white uppercase tracking-wider text-xs">D. Behavioural Evidence (10 Canonical Features)</strong>
          <span class="text-[10px] text-slate-400">
            ${hasBaseline ? `Baseline: <strong class="text-slate-200">${escapeHtml(b.baseline_status)}</strong> (${b.baseline_samples} Samples)` : '<strong class="text-amber-300">No baseline data available (0 Samples)</strong>'}
          </span>
        </div>
        <div class="grid grid-cols-2 sm:grid-cols-5 gap-2.5">
          ${featuresDef.map(f => {
            const obsVal = sigs[f.key];
            const hasObs = obsVal !== undefined && obsVal !== null;
            const meanVal = hasBaseline && base.means ? base.means[f.key] : null;
            const stdVal = hasBaseline && base.stds ? base.stds[f.key] : null;
            const status = devMap[f.key] || (hasBaseline ? 'NORMAL' : 'No baseline data available');
            const isDev = status === 'HIGH DEVIATION' || status === 'ELEVATED';
            return `
              <div class="p-2.5 rounded-lg bg-black/50 border ${isDev ? 'border-amber-700 bg-amber-950/20' : 'border-red-950/60'} space-y-1">
                <span class="text-slate-400 text-[10px] block truncate" title="${f.name}">${f.name}</span>
                <strong class="${hasObs ? (isDev ? 'text-amber-300' : 'text-emerald-400') : 'text-slate-500'} text-xs block">
                  ${hasObs ? `${Number(obsVal).toFixed(2)} ${f.unit}` : 'Not observed'}
                </strong>
                <span class="text-[9px] text-slate-500 block truncate">
                  ${meanVal !== undefined && meanVal !== null ? `Base: ${Number(meanVal).toFixed(1)} ±${Number(stdVal || 0).toFixed(1)}` : 'No baseline data available'}
                </span>
                <span class="inline-block px-1.5 py-0.2 rounded text-[9px] font-bold ${isDev ? 'bg-amber-900 text-amber-200' : 'bg-slate-900 text-slate-400'}">${escapeHtml(status)}</span>
              </div>
            `;
          }).join('')}
        </div>
      </div>

      <!-- E. Event Timeline -->
      <div class="p-4 rounded-xl bg-black/80 border border-red-950 space-y-3 font-mono text-xs">
        <div class="flex items-center justify-between pb-2 border-b border-red-950">
          <strong class="text-white uppercase tracking-wider text-xs">E. Chronological Correlated Event Timeline</strong>
          <span class="text-[10px] text-slate-500">${timeline.length} Events</span>
        </div>
        <div class="space-y-2 max-h-52 overflow-y-auto pr-1">
          ${timeline.length > 0 ? timeline.map(ev => {
            const timeStr = formatSocTimestamp(ev.timestamp);
            return `
              <div class="p-2.5 rounded bg-black/50 border border-red-950/60 flex flex-wrap items-center justify-between gap-2 text-[11px]">
                <div class="flex flex-wrap items-center gap-2">
                  <span class="text-slate-500 text-[10px]">[${timeStr}]</span>
                  <strong class="text-white">${escapeHtml(formatSocEventLabel(ev.event_type))}</strong>
                  <span class="text-slate-400 text-[10px]">(${escapeHtml(formatSocPortalName(ev.application || 'platform'))})</span>
                </div>
                <div class="flex items-center gap-2">
                  <span class="px-2 py-0.5 rounded text-[9px] font-bold ${ev.risk_level === 'CRITICAL' || ev.severity === 'CRITICAL' ? 'bg-red-600 text-white' : 'bg-slate-900 text-slate-300'}">${escapeHtml(ev.risk_level || ev.severity || 'N/A')}</span>
                  <span class="px-2 py-0.5 rounded text-[9px] font-bold bg-black border border-slate-800 text-slate-300">${escapeHtml(ev.decision || 'RECORDED')}</span>
                </div>
              </div>
            `;
          }).join('') : '<div class="text-slate-500 text-center py-4">No correlated timeline events recorded.</div>'}
        </div>
      </div>

      <!-- F. Administrative Investigation & Audit Trail -->
      <div class="p-4 rounded-xl bg-gradient-to-r from-red-950/40 via-black to-red-950/40 border border-red-800/60 space-y-3 font-mono text-xs">
        <div class="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-red-950">
          <strong class="text-white uppercase tracking-wider text-xs">F. Administrative Investigation</strong>
          ${dossier.status === 'RESOLVED' ? `<button type="button" onclick="window.triageQuickAlert(${incidentId}, 'REOPENED').then(() => window.openIncidentInvestigation(${incidentId}))" class="px-3 py-1 rounded-lg bg-amber-950 hover:bg-amber-900 border border-amber-700 text-amber-200 text-xs font-bold cursor-pointer">Reopen Incident</button>` : ''}
        </div>

        <form id="inc-triage-form" onsubmit="window.submitIncidentTriage(event, ${incidentId})" class="space-y-3">
          <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label class="text-slate-400 text-[11px] block mb-1">Update Status:</label>
              <select id="inc-triage-status" class="w-full px-3 py-1.5 rounded-lg bg-black border border-red-900/60 text-white text-xs focus:outline-none focus:border-red-500">
                ${allowedStatuses.map(st => `<option value="${st}" ${dossier.status === st ? 'selected' : ''}>${st}</option>`).join('')}
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
            <textarea id="inc-triage-notes" rows="2" placeholder="Record technical forensic notes or rationale..." class="w-full px-3 py-1.5 rounded-lg bg-black border border-red-900/60 text-white text-xs focus:outline-none focus:border-red-500">${escapeHtml(dossier.notes || dossier.investigation_notes || '')}</textarea>
          </div>
          <div class="flex flex-wrap items-center justify-between gap-2 pt-1">
            <span class="text-[10px] text-slate-400">Resolving an incident records triage closure only; terminated sessions and portal locks remain enforced until separately recovered.</span>
            <button type="submit" class="px-4 py-1.5 rounded-xl bg-red-600 hover:bg-red-500 text-white font-bold text-xs uppercase tracking-wider cursor-pointer shadow-[0_0_15px_rgba(239,68,68,0.5)] transition-all">
              Save Triage Update →
            </button>
          </div>
        </form>

        ${actions.length > 0 ? `
          <div class="pt-3 border-t border-red-950/80 space-y-1.5">
            <span class="text-[10px] text-slate-400 uppercase font-bold block">Administrative Audit Trail</span>
            <div class="space-y-1 max-h-32 overflow-y-auto">
              ${actions.map(a => `<div class="text-[10px] text-slate-300 bg-black/50 px-2.5 py-1.5 rounded border border-slate-800">[${formatSocTimestamp(a.timestamp)}] <strong>${escapeHtml(a.action)}</strong> — ${escapeHtml(a.details || '')}</div>`).join('')}
            </div>
          </div>
        ` : ''}
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
    showNotificationToast("Resolution Reason Required", "Please provide a resolution reason when marking an incident as RESOLVED.", "warning");
    if (reasonEl) reasonEl.focus();
    return;
  }

  try {
    await window.cognisec.triageSocAlert(incidentId, status, notes, assignedTo, reason);
    showNotificationToast("Incident Triaged", `Incident #${incidentId} status transitioned to ${status}.`, "success");
    await window.openIncidentInvestigation(incidentId);
    await loadSocDashboardData();
  } catch (e) {
    showNotificationToast("Triage Update Failed", e.message || "Could not save triage update.", "error");
  }
};

window.triageQuickAlert = async function(alertId, newStatus) {
  try {
    await window.cognisec.triageSocAlert(alertId, newStatus, `Quick triage transition to ${newStatus}`);
    showNotificationToast("Alert Updated", `Alert #${alertId} updated to ${newStatus}.`, "success");
    await loadSocDashboardData();
  } catch (e) {
    showNotificationToast("Alert Update Failed", e.message || "Could not update alert.", "error");
  }
};

window._isPortalLockAlertType = function(alertType) {
  const t = String(alertType || '').toUpperCase();
  return [
    'PORTAL_SECURITY_LOCKOUT',
    'PORTAL_RECOVERY_REQUESTED',
    'PORTAL_REENTRY_ATTEMPT',
    'CROSS_PORTAL_LOCKOUT_ESCALATION',
    'PORTAL_LOCK_RECOVERY_REJECTED',
  ].includes(t);
};

window.closeSocActionModal = function() {
  const modal = document.getElementById('modal-soc-action');
  if (modal) modal.classList.add('hidden');
  window._activeSocActionHandler = null;
};

window.openSocActionModal = function({
  title = 'Confirm SOC Action',
  icon = '🛡️',
  refText = '',
  description = '',
  requireReason = false,
  reasonLabel = 'Administrative Reason / Audit Notes *',
  reasonPlaceholder = 'Enter clear verification / resolution notes...',
  confirmLabel = 'Confirm',
  confirmVariant = 'danger',
  onConfirm = null,
} = {}) {
  const modal = document.getElementById('modal-soc-action');
  if (!modal) return;
  const titleEl = document.getElementById('soc-action-title');
  const iconEl = document.getElementById('soc-action-icon');
  const refEl = document.getElementById('soc-action-ref');
  const descEl = document.getElementById('soc-action-desc');
  const reasonGroup = document.getElementById('soc-action-reason-group');
  const reasonLabelEl = document.getElementById('soc-action-reason-label');
  const reasonInput = document.getElementById('soc-action-reason');
  const errEl = document.getElementById('soc-action-error');
  const cancelBtn = document.getElementById('soc-action-cancel');
  const closeXBtn = document.getElementById('soc-action-close-x');
  const confirmBtn = document.getElementById('soc-action-confirm');

  if (titleEl) titleEl.textContent = title;
  if (iconEl) iconEl.textContent = icon;
  if (refEl) {
    if (refText) {
      refEl.textContent = refText;
      refEl.classList.remove('hidden');
    } else {
      refEl.classList.add('hidden');
    }
  }
  if (descEl) descEl.textContent = description || '';
  if (reasonGroup) {
    if (requireReason) reasonGroup.classList.remove('hidden');
    else reasonGroup.classList.add('hidden');
  }
  if (reasonLabelEl) reasonLabelEl.textContent = reasonLabel;
  if (reasonInput) {
    reasonInput.value = '';
    reasonInput.placeholder = reasonPlaceholder;
  }
  if (errEl) {
    errEl.textContent = '';
    errEl.classList.add('hidden');
  }
  if (confirmBtn) {
    confirmBtn.disabled = false;
    confirmBtn.textContent = confirmLabel;
    confirmBtn.className = confirmVariant === 'approve'
      ? 'px-5 py-2 rounded-xl bg-emerald-700 hover:bg-emerald-600 border border-emerald-400/60 text-white text-xs font-bold shadow-[0_0_15px_rgba(16,185,129,0.45)] cursor-pointer'
      : 'px-5 py-2 rounded-xl bg-red-600 hover:bg-red-500 text-white text-xs font-bold shadow-[0_0_15px_rgba(220,38,38,0.45)] cursor-pointer';
  }

  const closeFn = () => window.closeSocActionModal();
  if (cancelBtn) cancelBtn.onclick = closeFn;
  if (closeXBtn) closeXBtn.onclick = closeFn;

  if (confirmBtn) {
    confirmBtn.onclick = async () => {
      const reasonVal = reasonInput ? reasonInput.value.trim() : '';
      if (requireReason && !reasonVal) {
        if (errEl) {
          errEl.textContent = 'Please enter a clear administrative reason before continuing.';
          errEl.classList.remove('hidden');
        }
        if (reasonInput) reasonInput.focus();
        return;
      }
      if (errEl) errEl.classList.add('hidden');
      if (typeof onConfirm === 'function') {
        confirmBtn.disabled = true;
        const origLabel = confirmBtn.textContent;
        confirmBtn.textContent = 'Processing...';
        try {
          await onConfirm(reasonVal);
          window.closeSocActionModal();
        } catch (err) {
          if (errEl) {
            errEl.textContent = err.message || 'Operation failed. Please verify and retry.';
            errEl.classList.remove('hidden');
          }
          confirmBtn.disabled = false;
          confirmBtn.textContent = origLabel;
        }
      } else {
        window.closeSocActionModal();
      }
    };
  }

  modal.classList.remove('hidden');
  if (requireReason && reasonInput) setTimeout(() => reasonInput.focus(), 50);
};

window.triageResolvePrompt = function(alertId) {
  window.openSocActionModal({
    title: 'Resolve Security Incident',
    icon: '✅',
    refText: `Incident Alert #${alertId}`,
    description: 'Record a resolution reason for this security alert. Ordinary incident resolution updates alert triage only and does not clear portal security locks.',
    requireReason: true,
    reasonLabel: 'Resolution Reason *',
    reasonPlaceholder: 'e.g., False positive verified, user activity confirmed, risk mitigated...',
    confirmLabel: 'Confirm Resolve',
    confirmVariant: 'approve',
    onConfirm: async (reason) => {
      await window.cognisec.triageSocAlert(alertId, 'RESOLVED', 'Resolved via SOC dashboard control', null, reason);
      showNotificationToast("Alert Resolved", `Alert #${alertId} marked as RESOLVED.`, "success");
      await loadSocDashboardData();
    },
  });
};

window.terminateSocSession = function(sessionId) {
  window.openSocActionModal({
    title: 'Terminate Active Session',
    icon: '⛔',
    refText: `Session: ${String(sessionId).slice(0, 18)}...`,
    description: 'Are you sure you want to terminate this session? This immediately invalidates the session token and records an administrative audit entry.',
    requireReason: false,
    confirmLabel: 'Terminate Session',
    confirmVariant: 'danger',
    onConfirm: async () => {
      await window.cognisec.terminateSocSession(sessionId);
      showNotificationToast("Session Terminated", `Session ${String(sessionId).substring(0, 12)}... terminated by SOC Administrator.`, "info");
      await loadSocDashboardData();
    },
  });
};

window.revokeSocDevice = function(deviceId) {
  window.openSocActionModal({
    title: 'Revoke Device Trust',
    icon: '💻',
    refText: `Device: ${deviceId}`,
    description: 'Revoke trust for this device? All active sessions bound to this device will be immediately revoked.',
    requireReason: false,
    confirmLabel: 'Revoke Device',
    confirmVariant: 'danger',
    onConfirm: async () => {
      await window.cognisec.revokeSocDevice(deviceId);
      showNotificationToast("Device Revoked", `Device ${deviceId} revoked by SOC Administrator.`, "warning");
      await loadSocDashboardData();
    },
  });
};

window.confirmSocDevice = async function(deviceId) {
  try {
    await window.cognisec.updateDeviceTrust(deviceId, true);
    showNotificationToast("Device Confirmed", `Device ${deviceId} confirmed as TRUSTED by SOC Administrator.`, "success");
    await loadSocDashboardData();
  } catch (e) {
    showNotificationToast("Device Trust Failed", e.message || "Failed to confirm device.", "error");
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

window._socRecoveryStatusFilter = 'ACTIVE';
window._socRecoveryPortalFilter = 'ALL';

window.updateSocRecoveryOverviewAndBadge = function() {
  const allLocks = window._cachedSocPortalLocks || [];
  const activeLocks = allLocks.filter(lk => (lk.lock_status || '').toUpperCase() === 'ACTIVE');
  const badgeEl = document.getElementById('soc-recovery-pending-badge');
  const activeCountEl = document.getElementById('soc-recovery-active-count');
  const calloutEl = document.getElementById('soc-overview-recovery-callout');
  const summaryEl = document.getElementById('soc-overview-recovery-summary');

  if (activeCountEl) activeCountEl.textContent = String(activeLocks.length);
  if (badgeEl) {
    badgeEl.textContent = String(activeLocks.length);
    if (activeLocks.length > 0) badgeEl.classList.remove('hidden');
    else badgeEl.classList.add('hidden');
  }
  if (calloutEl) {
    if (activeLocks.length > 0) {
      calloutEl.classList.remove('hidden');
      if (summaryEl) {
        const otpVerifiedCount = activeLocks.filter(lk => lk.recovery_otp_verified).length;
        summaryEl.textContent = `${activeLocks.length} suspended portal lock(s) pending review (${otpVerifiedCount} recovery OTP verified). Review and approve or reject in Portal Recovery.`;
      }
    } else {
      calloutEl.classList.add('hidden');
    }
  }
};

window.filterSocPortalLocks = function(statusFilter = null, portalFilter = null) {
  if (statusFilter !== null) {
    window._socRecoveryStatusFilter = statusFilter;
    const pBtn = document.getElementById('recovery-filter-pending');
    const aBtn = document.getElementById('recovery-filter-all');
    if (pBtn && aBtn) {
      if (statusFilter === 'ACTIVE') {
        pBtn.className = 'px-3 py-1.5 rounded-lg font-bold bg-red-600 text-white cursor-pointer';
        aBtn.className = 'px-3 py-1.5 rounded-lg font-bold bg-black border border-red-900/60 text-slate-300 hover:bg-red-950/40 cursor-pointer';
      } else {
        aBtn.className = 'px-3 py-1.5 rounded-lg font-bold bg-red-600 text-white cursor-pointer';
        pBtn.className = 'px-3 py-1.5 rounded-lg font-bold bg-black border border-red-900/60 text-slate-300 hover:bg-red-950/40 cursor-pointer';
      }
    }
  }
  if (portalFilter !== null) {
    window._socRecoveryPortalFilter = portalFilter;
  }
  window.renderSocPortalRecoveryQueue();
};

window.renderSocPortalRecoveryQueue = function() {
  const container = document.getElementById('soc-recovery-list-container');
  if (!container) return;

  const allLocks = window._cachedSocPortalLocks || [];
  const statusFilter = window._socRecoveryStatusFilter || 'ACTIVE';
  const portalFilter = (window._socRecoveryPortalFilter || 'ALL').toLowerCase();

  let filtered = allLocks.slice();
  if (statusFilter === 'ACTIVE') {
    filtered = filtered.filter(lk => (lk.lock_status || '').toUpperCase() === 'ACTIVE');
  }
  if (portalFilter && portalFilter !== 'all') {
    filtered = filtered.filter(lk => (lk.portal || '').toLowerCase() === portalFilter);
  }

  if (filtered.length === 0) {
    container.innerHTML = `<div class="p-8 text-center text-slate-500 font-mono text-xs">${
      statusFilter === 'ACTIVE'
        ? '✓ No pending portal recovery requests require action right now.'
        : 'No portal security locks match the selected filter.'
    }</div>`;
    return;
  }

  const currentUser = window.cognisec ? window.cognisec.user : null;
  const isAdmin = currentUser && (currentUser.role || '').toUpperCase() === 'ADMIN';

  container.innerHTML = '';
  filtered.forEach(lk => {
    const isActive = (lk.lock_status || '').toUpperCase() === 'ACTIVE';
    const isRejected = (lk.recovery_status || '').toUpperCase() === 'REJECTED_BY_ADMIN';
    const isSelfLock = currentUser && lk.user_id && Number(currentUser.id) === Number(lk.user_id);
    const portalName = lk.portal_display_name || (lk.portal ? lk.portal.charAt(0).toUpperCase() + lk.portal.slice(1) : 'Portal');
    const reqTs = lk.request_timestamp ? new Date(lk.request_timestamp).toLocaleString() : '—';
    const otpStatusLabel = lk.recovery_otp_status_label || (lk.recovery_otp_verified ? 'OTP Verified — Awaiting Admin' : 'Pending Recovery OTP');
    const reviewStatus = lk.admin_review_status || (isActive ? (isRejected ? 'Rejected by Admin' : 'Pending Admin Review') : 'Approved by Admin');
    const factorAttemptStr = `${lk.failed_factor_label || lk.verification_purpose || 'Challenge'} (${lk.failed_attempt_count ?? 0}/${lk.max_attempts ?? 3} failed attempts)`;

    const otpBadgeCls = lk.recovery_otp_verified
      ? 'bg-emerald-950 text-emerald-300 border-emerald-700'
      : 'bg-amber-950 text-amber-300 border-amber-800';
    const reviewBadgeCls = !isActive
      ? 'bg-emerald-950 text-emerald-300 border-emerald-700'
      : (isRejected ? 'bg-red-950 text-red-300 border-red-700' : 'bg-sky-950 text-sky-300 border-sky-800');

    const card = document.createElement('div');
    card.className = `p-4 rounded-2xl border ${isActive ? 'bg-red-950/20 border-red-800/80' : 'bg-black/45 border-slate-800'} space-y-3 text-xs`;
    card.dataset.securityRef = lk.security_reference_id;
    card.innerHTML = `
      <div class="flex flex-col lg:flex-row lg:items-center justify-between gap-2 pb-2.5 border-b border-red-950/70">
        <div class="flex flex-wrap items-center gap-2">
          <span class="px-2.5 py-0.5 rounded-lg font-mono font-bold text-[10px] ${isActive ? 'bg-red-600 text-white' : 'bg-emerald-950 text-emerald-300 border border-emerald-800'}">
            ${isActive ? 'LOCKED' : 'RECOVERED'}
          </span>
          <span class="px-2.5 py-0.5 rounded-lg font-bold text-[11px] bg-black border border-red-900/70 text-white uppercase tracking-wide">${escapeHtml(portalName)}</span>
          <span class="px-2.5 py-0.5 rounded-lg font-mono text-[10px] border ${otpBadgeCls}">${escapeHtml(otpStatusLabel)}</span>
          <span class="px-2.5 py-0.5 rounded-lg font-mono text-[10px] border ${reviewBadgeCls}">${escapeHtml(reviewStatus)}</span>
        </div>
        <div class="font-mono text-[11px] text-red-300 font-bold">
          Ref: <span class="text-white select-all">${escapeHtml(lk.security_reference_id)}</span>
        </div>
      </div>

      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-[11px]">
        <div class="p-2.5 rounded-xl bg-black/50 border border-red-950/60">
          <span class="text-slate-500 block text-[10px] uppercase">Account Owner</span>
          <strong class="text-white block mt-0.5">${escapeHtml(lk.user_name || 'Unknown User')}</strong>
          <span class="text-slate-400 font-mono text-[10px] break-all">${escapeHtml(lk.user_email || '—')}</span>
        </div>
        <div class="p-2.5 rounded-xl bg-black/50 border border-red-950/60">
          <span class="text-slate-500 block text-[10px] uppercase">Failed Factor &amp; Attempts</span>
          <strong class="text-amber-300 block mt-0.5">${escapeHtml(factorAttemptStr)}</strong>
          <span class="text-slate-400 text-[10px]">Portal: ${escapeHtml(portalName)}</span>
        </div>
        <div class="p-2.5 rounded-xl bg-black/50 border border-red-950/60">
          <span class="text-slate-500 block text-[10px] uppercase">Request Timestamp</span>
          <strong class="text-slate-200 font-mono block mt-0.5">${escapeHtml(reqTs)}</strong>
          <span class="text-slate-400 text-[10px]">${lk.recovery_otp_verified ? 'Recovery OTP Confirmed' : 'Awaiting Recovery OTP'}</span>
        </div>
        <div class="p-2.5 rounded-xl bg-black/50 border border-red-950/60">
          <span class="text-slate-500 block text-[10px] uppercase">Lock Reason</span>
          <span class="text-slate-200 block mt-0.5 leading-snug">${escapeHtml(lk.lock_reason || 'Maximum failed verification attempts exceeded.')}</span>
        </div>
      </div>

      ${lk.recovery_notes ? `<div class="p-2 rounded-xl bg-black/60 border border-slate-800 text-[11px] font-mono text-slate-300">📋 Admin Note${lk.reviewed_by ? ` (${escapeHtml(lk.reviewed_by)})` : ''}: ${escapeHtml(lk.recovery_notes)}</div>` : ''}

      <div class="flex flex-wrap items-center justify-end gap-2 pt-1">
        <button type="button" onclick="window.openPortalRecoveryDetails('${escapeHtml(lk.security_reference_id)}')" class="px-3.5 py-1.5 rounded-xl bg-black hover:bg-red-950/40 border border-slate-700 hover:border-red-700 text-slate-200 text-xs font-bold cursor-pointer transition-all">
          🔍 View Details
        </button>
        ${isActive && isAdmin && !isSelfLock ? `
          <button type="button" onclick="window.promptRejectPortalRecovery('${escapeHtml(lk.security_reference_id)}')" class="px-3.5 py-1.5 rounded-xl bg-red-950/80 hover:bg-red-900 border border-red-600 text-red-200 text-xs font-bold cursor-pointer transition-all">
            ✕ Reject Recovery
          </button>
          <button type="button" onclick="window.promptApprovePortalRecovery('${escapeHtml(lk.security_reference_id)}')" class="px-4 py-1.5 rounded-xl bg-emerald-700 hover:bg-emerald-600 border border-emerald-400/60 text-white text-xs font-bold shadow-[0_0_12px_rgba(16,185,129,0.35)] cursor-pointer transition-all">
            ✓ Approve Recovery
          </button>
        ` : (isActive && isSelfLock ? `<span class="text-[10px] font-mono text-amber-400">Self-approval blocked by Zero-Trust policy</span>` : '')}
      </div>
    `;
    container.appendChild(card);
  });
};

window.closePortalRecoveryDetails = function() {
  const modal = document.getElementById('modal-portal-recovery-details');
  if (modal) modal.classList.add('hidden');
};

window.openPortalRecoveryDetails = async function(securityReferenceId) {
  const modal = document.getElementById('modal-portal-recovery-details');
  const subtitle = document.getElementById('prd-ref-subtitle');
  const body = document.getElementById('prd-body');
  const triageArea = document.getElementById('prd-alert-triage-actions');
  const approveBtn = document.getElementById('prd-approve-btn');
  const rejectBtn = document.getElementById('prd-reject-btn');
  if (!modal || !body) return;

  if (subtitle) subtitle.textContent = `Security Reference: ${securityReferenceId}`;
  body.innerHTML = `<div class="p-8 text-center text-slate-400 font-mono text-xs">Loading recovery dossier...</div>`;
  if (triageArea) triageArea.innerHTML = '';
  if (approveBtn) approveBtn.classList.add('hidden');
  if (rejectBtn) rejectBtn.classList.add('hidden');
  modal.classList.remove('hidden');

  try {
    const detail = await window.cognisec.fetchSocPortalLockDetail(securityReferenceId);
    const currentUser = window.cognisec ? window.cognisec.getCurrentUser() : null;
    const isAdmin = currentUser && (currentUser.role || '').toUpperCase() === 'ADMIN';
    const isActive = (detail.lock_status || '').toUpperCase() === 'ACTIVE';
    const isSelfLock = currentUser && detail.user_id && Number(currentUser.id) === Number(detail.user_id);
    const portalName = detail.portal_display_name || detail.portal || 'Portal';
    const lockedAt = detail.locked_at ? new Date(detail.locked_at).toLocaleString() : '—';
    const otpAt = detail.recovery_otp_verified_at ? new Date(detail.recovery_otp_verified_at).toLocaleString() : 'Not verified yet';

    const eventsHtml = (detail.events || []).length > 0
      ? detail.events.map(ev => {
          const ts = ev.timestamp ? new Date(ev.timestamp).toLocaleString() : '—';
          return `
            <div class="p-2.5 rounded-xl bg-black/60 border border-red-950/70 flex flex-col sm:flex-row sm:items-center justify-between gap-2 font-mono text-[11px]">
              <div>
                <span class="text-white font-bold">${escapeHtml((ev.event_type || '').replace(/_/g, ' '))}</span>
                <span class="text-slate-400 text-[10px] block">${escapeHtml(ts)}</span>
              </div>
              <div class="flex items-center gap-2 shrink-0">
                <span class="px-2 py-0.5 rounded text-[10px] bg-red-950 text-red-300 border border-red-800">${escapeHtml(ev.severity || 'INFO')}</span>
                <span class="px-2 py-0.5 rounded text-[10px] bg-black text-slate-300 border border-slate-700">${escapeHtml(ev.decision || 'LOG')}</span>
              </div>
            </div>
          `;
        }).join('')
      : `<div class="p-4 rounded-xl bg-black/50 border border-slate-800 text-slate-500 font-mono text-xs">No correlated portal security events recorded.</div>`;

    body.innerHTML = `
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div class="p-3 rounded-xl bg-black/60 border border-red-950 space-y-1">
          <span class="text-slate-500 text-[10px] uppercase block">Account Owner</span>
          <strong class="text-white block text-sm">${escapeHtml(detail.user_name || 'Unknown User')}</strong>
          <span class="text-slate-400 font-mono text-[11px]">${escapeHtml(detail.user_email || '—')}</span>
        </div>
        <div class="p-3 rounded-xl bg-black/60 border border-red-950 space-y-1">
          <span class="text-slate-500 text-[10px] uppercase block">Locked Portal &amp; Review State</span>
          <strong class="text-white block text-sm">${escapeHtml(portalName)} (${escapeHtml(detail.lock_status)})</strong>
          <span class="text-red-300 font-mono text-[11px]">${escapeHtml(detail.admin_review_status || 'Pending Admin Review')}</span>
        </div>
        <div class="p-3 rounded-xl bg-black/60 border border-red-950 space-y-1">
          <span class="text-slate-500 text-[10px] uppercase block">Failed Factor &amp; Attempts</span>
          <strong class="text-amber-300 block">${escapeHtml(detail.failed_factor_label || detail.verification_purpose || 'Challenge')}</strong>
          <span class="text-slate-400 font-mono text-[11px]">${detail.failed_attempt_count ?? 0} / ${detail.max_attempts ?? 3} attempts &bull; Locked at ${escapeHtml(lockedAt)}</span>
        </div>
        <div class="p-3 rounded-xl bg-black/60 border border-red-950 space-y-1">
          <span class="text-slate-500 text-[10px] uppercase block">Recovery OTP Verification</span>
          <strong class="${detail.recovery_otp_verified ? 'text-emerald-400' : 'text-amber-300'} block">${escapeHtml(detail.recovery_otp_status_label || (detail.recovery_otp_verified ? 'OTP Verified' : 'Pending Recovery OTP'))}</strong>
          <span class="text-slate-400 font-mono text-[11px]">Verified At: ${escapeHtml(otpAt)}</span>
        </div>
      </div>

      <div class="p-3.5 rounded-xl bg-red-950/25 border border-red-900/70 space-y-1">
        <span class="text-red-300 font-mono text-[10px] uppercase font-bold block">Lock Reason &amp; Device Context</span>
        <p class="text-slate-200 text-xs">${escapeHtml(detail.lock_reason || 'Security lockout enforced.')}</p>
        <p class="text-slate-400 font-mono text-[10px]">Device: ${escapeHtml(detail.device_summary || 'Unknown Device')} &bull; Audit ID: ${escapeHtml(detail.audit_correlation_id || '—')}</p>
        ${detail.recovery_notes ? `<p class="text-slate-300 font-mono text-[11px] pt-1 border-t border-red-950">Admin Notes: ${escapeHtml(detail.recovery_notes)}</p>` : ''}
      </div>

      <div class="space-y-2">
        <h5 class="font-mono font-bold text-[11px] text-slate-300 uppercase tracking-wider">Correlated Portal Security Event History</h5>
        <div class="space-y-1.5 max-h-56 overflow-y-auto pr-1">${eventsHtml}</div>
      </div>
    `;

    if (triageArea && detail.associated_alert_id && detail.associated_alert_status !== 'RESOLVED') {
      const aid = detail.associated_alert_id;
      triageArea.innerHTML = `
        <button type="button" onclick="window.triageQuickAlert(${aid}, 'ACKNOWLEDGED')" class="px-3 py-1.5 rounded-xl bg-sky-950 hover:bg-sky-900 border border-sky-700 text-sky-300 text-[11px] font-bold cursor-pointer">Acknowledge Alert</button>
        <button type="button" onclick="window.triageQuickAlert(${aid}, 'INVESTIGATING')" class="px-3 py-1.5 rounded-xl bg-purple-950 hover:bg-purple-900 border border-purple-700 text-purple-300 text-[11px] font-bold cursor-pointer">Mark Investigating</button>
      `;
    }

    if (isActive && isAdmin && !isSelfLock) {
      if (rejectBtn) {
        rejectBtn.classList.remove('hidden');
        rejectBtn.onclick = () => window.promptRejectPortalRecovery(securityReferenceId);
      }
      if (approveBtn) {
        approveBtn.classList.remove('hidden');
        approveBtn.onclick = () => window.promptApprovePortalRecovery(securityReferenceId);
      }
    }
  } catch (err) {
    body.innerHTML = `<div class="p-6 text-center text-red-400 font-mono text-xs">${escapeHtml(err.message || 'Failed to load recovery details.')}</div>`;
  }
};

window.promptApprovePortalRecovery = function(securityReferenceId) {
  const lock = (window._cachedSocPortalLocks || []).find(l => l.security_reference_id === securityReferenceId);
  const portalName = lock ? (lock.portal_display_name || lock.portal) : 'portal';
  const ownerDesc = lock ? `${lock.user_name || ''} (${lock.user_email || ''})` : securityReferenceId;

  window.openSocActionModal({
    title: 'Approve Portal Recovery',
    icon: '✅',
    refText: `Security Ref: ${securityReferenceId} • ${portalName}`,
    description: `Approve recovery clearance for ${ownerDesc}? This lifts only the ${portalName} security lock. Fresh 20-second behavioral observation and normal Email OTP remain mandatory on next login.`,
    requireReason: true,
    reasonLabel: 'Approval Reason & Verification Notes *',
    reasonPlaceholder: 'e.g., Identity confirmed with account owner, recovery OTP verified, portal cleared for fresh entry...',
    confirmLabel: 'Approve Recovery',
    confirmVariant: 'approve',
    onConfirm: async (reason) => {
      await window.cognisec.approveSocPortalRecovery(securityReferenceId, reason);
      window.closePortalRecoveryDetails();
      showNotificationToast("Portal Recovery Approved", `${portalName} security lock (${securityReferenceId}) cleared.`, "success");
      await loadSocDashboardData();
    },
  });
};

window.promptRejectPortalRecovery = function(securityReferenceId) {
  const lock = (window._cachedSocPortalLocks || []).find(l => l.security_reference_id === securityReferenceId);
  const portalName = lock ? (lock.portal_display_name || lock.portal) : 'portal';
  const ownerDesc = lock ? `${lock.user_name || ''} (${lock.user_email || ''})` : securityReferenceId;

  window.openSocActionModal({
    title: 'Reject Portal Recovery',
    icon: '🛑',
    refText: `Security Ref: ${securityReferenceId} • ${portalName}`,
    description: `Reject recovery request for ${ownerDesc}? The ${portalName} portal lock will remain ACTIVE and the account owner will be notified.`,
    requireReason: true,
    reasonLabel: 'Rejection Reason *',
    reasonPlaceholder: 'e.g., Unverified activity pattern, additional security confirmation required...',
    confirmLabel: 'Confirm Rejection',
    confirmVariant: 'danger',
    onConfirm: async (reason) => {
      await window.cognisec.rejectSocPortalRecovery(securityReferenceId, reason);
      window.closePortalRecoveryDetails();
      showNotificationToast("Portal Recovery Rejected", `${portalName} remains locked (${securityReferenceId}).`, "warning");
      await loadSocDashboardData();
    },
  });
};

window._socUsersSubtab = 'users';

window.switchUsersSubtab = function(subtab) {
  const valid = ['users', 'sessions', 'activity'];
  const target = valid.includes(subtab) ? subtab : 'users';
  window._socUsersSubtab = target;

  valid.forEach(k => {
    const btn = document.getElementById(`users-subtab-${k}`);
    if (btn) {
      btn.className = k === target
        ? 'px-4 py-2 rounded-xl text-sm font-semibold bg-red-600 text-white cursor-pointer transition-all'
        : 'px-4 py-2 rounded-xl text-sm font-semibold bg-black border border-red-900/60 text-slate-300 hover:text-white cursor-pointer transition-all';
    }
  });

  const usersPanel = document.getElementById('soc-users-directory-panel');
  const devDetails = document.getElementById('soc-devices-behavior-details');
  const sessPanel = document.getElementById('soc-sessions-panel');
  const actPanel = document.getElementById('dash-content-user-activity');

  if (usersPanel) usersPanel.classList.toggle('hidden', target !== 'users');
  if (devDetails) devDetails.classList.toggle('hidden', target !== 'users');
  if (sessPanel) sessPanel.classList.toggle('hidden', target !== 'sessions');
  if (actPanel) actPanel.classList.toggle('hidden', target !== 'activity');

  if (target === 'users' && typeof window.loadSocUsersDirectory === 'function') {
    window.loadSocUsersDirectory();
  } else if (target === 'sessions' && typeof window.filterSocSessions === 'function') {
    window.filterSocSessions();
  } else if (target === 'activity' && typeof window.loadUserActivityDirectory === 'function') {
    window.loadUserActivityDirectory();
  }
};

window.switchDashboardTab = function(tabKey) {
  const legacyMap = {
    alerts: 'audit',
    logs: 'audit',
    devices: 'users',
    behavior: 'users',
    'user-activity': 'users',
    health: 'audit',
  };
  const resolvedTab = legacyMap[tabKey] || tabKey;
  const tabs = ['overview', 'recovery', 'users', 'audit', 'agentic'];
  tabs.forEach(k => {
    const btn = document.getElementById(`dash-tab-${k}`);
    const content = document.getElementById(`dash-content-${k}`);
    if (btn) {
      if (k === resolvedTab) {
        btn.className = 'px-4 py-2.5 rounded-xl font-semibold transition-all flex items-center gap-2 bg-red-600 text-white shadow-[0_0_15px_rgba(220,38,38,0.5)] cursor-pointer shrink-0';
      } else {
        btn.className = 'px-4 py-2.5 rounded-xl font-semibold transition-all flex items-center gap-2 text-slate-300 hover:text-white hover:bg-red-950/40 cursor-pointer shrink-0';
      }
    }
    if (content) {
      if (k === resolvedTab) content.classList.remove('hidden');
      else content.classList.add('hidden');
    }
  });

  if (tabKey === 'behavior' || tabKey === 'devices') {
    window._socUsersSubtab = 'users';
    const det = document.getElementById('soc-devices-behavior-details');
    if (det) det.setAttribute('open', 'open');
  } else if (tabKey === 'user-activity') {
    window._socUsersSubtab = 'activity';
  }
  if (tabKey === 'alerts' || tabKey === 'logs') {
    window.switchSecurityIntelView('incidents');
  }
  if (resolvedTab === 'users') {
    window.switchUsersSubtab(window._socUsersSubtab || 'users');
  } else if (resolvedTab === 'audit') {
    window._socAuditState.selected_user_id = null;
    if (window._socAuditState.view === 'agentic') {
      window._socAuditState.view = 'timeline';
    }
    window.loadSecurityIntelOverview();
    if (window._socAuditState.view === 'timeline') {
      window.backToIntelAccounts();
    } else {
      window.switchSecurityIntelView(window._socAuditState.view);
    }
    window.loadSocAnalytics('24h');
    window.loadSocSystemHealth();
  } else if (resolvedTab === 'recovery') {
    window.renderSocPortalRecoveryQueue();
  } else if (resolvedTab === 'agentic') {
    window.loadAgenticMonitorData();
  }
};

window._uaState = { page: 1, page_size: 12, total_pages: 1 };

window.onUserActivityFilterChange = function(resetPage = false) {
  if (resetPage) window._uaState.page = 1;
  window.loadUserActivityDirectory();
};

window.changeUserActivityPage = function(delta) {
  const next = window._uaState.page + delta;
  if (next >= 1 && next <= window._uaState.total_pages) {
    window._uaState.page = next;
    window.loadUserActivityDirectory();
  }
};

window.closeUserActivityProfile = function() {
  document.getElementById('ua-profile-view')?.classList.add('hidden');
  document.getElementById('ua-directory-view')?.classList.remove('hidden');
};

window.loadUserActivityDirectory = async function() {
  const container = document.getElementById('ua-directory-table-container');
  const badge = document.getElementById('ua-users-count-badge');
  const pageInfo = document.getElementById('ua-page-info');
  const prevBtn = document.getElementById('ua-prev-btn');
  const nextBtn = document.getElementById('ua-next-btn');
  if (!container || !window.cognisec?.fetchSocUsersDirectory) return;

  const search = document.getElementById('ua-search')?.value?.trim() || '';
  const scope = document.getElementById('ua-scope')?.value || 'genuine';
  const account_status = document.getElementById('ua-status')?.value || 'ALL';
  const portal = document.getElementById('ua-portal')?.value || 'ALL';
  const date_from = document.getElementById('ua-date-from')?.value || '';
  const date_to = document.getElementById('ua-date-to')?.value || '';
  const sortRaw = document.getElementById('ua-sort')?.value || 'last_login:desc';
  const [sort_by, sort_dir] = sortRaw.split(':');

  try {
    const res = await window.cognisec.fetchSocUsersDirectory({
      search,
      scope,
      account_status,
      portal,
      date_from,
      date_to,
      sort_by,
      sort_dir,
      page: window._uaState.page,
      page_size: window._uaState.page_size,
    });
    const users = res.items || [];
    window._uaState.page = res.page || 1;
    window._uaState.total_pages = res.total_pages || 1;

    if (badge) badge.textContent = `${res.total || 0} ${scope === 'genuine' ? 'Registered' : 'Accounts'}`;
    if (pageInfo) pageInfo.textContent = `Page ${res.page || 1} of ${res.total_pages || 1} (${res.total || 0} matching accounts)`;
    if (prevBtn) prevBtn.disabled = (res.page || 1) <= 1;
    if (nextBtn) nextBtn.disabled = (res.page || 1) >= (res.total_pages || 1);

    if (users.length === 0) {
      container.innerHTML = `<div class="p-8 text-center text-slate-400 text-sm">No user accounts match the current filters.</div>`;
      return;
    }

    let html = `
      <table class="w-full text-left text-sm border-collapse">
        <thead>
          <tr class="border-b border-red-950 text-slate-300 text-xs uppercase tracking-wider font-semibold">
            <th class="py-3 px-3">User &amp; Role</th>
            <th class="py-3 px-3">Email &amp; Verification</th>
            <th class="py-3 px-3">Registered</th>
            <th class="py-3 px-3">Last Login</th>
            <th class="py-3 px-3">Logins</th>
            <th class="py-3 px-3">Last Known Device</th>
            <th class="py-3 px-3">Location</th>
            <th class="py-3 px-3">Status</th>
            <th class="py-3 px-3 text-right">Activity Profile</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-red-950/40 text-sm">
    `;
    users.forEach(u => {
      const isAct = u.account_status === 'ACTIVE';
      const regStr = u.created_at ? formatSocTimestamp(u.created_at) : 'Not recorded';
      const lastLoginStr = u.last_login ? formatSocTimestamp(u.last_login) : 'Not recorded';
      const devName = u.last_device_name || 'Not recorded';
      const devType = u.last_device_type || '';
      const locStr = u.last_location || 'Location unavailable';
      const verBadge = u.email_verified
        ? `<span class="inline-block mt-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-950 text-emerald-300 border border-emerald-800">Verified</span>`
        : `<span class="inline-block mt-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-900 text-slate-400 border border-slate-700">Unverified</span>`;
      const provBadge = u.provenance === 'ADMIN_ACCOUNT'
        ? `<span class="ml-1.5 px-2 py-0.5 rounded text-[10px] font-semibold bg-purple-950 text-purple-200 border border-purple-800">Admin</span>`
        : (u.is_test_account ? `<span class="ml-1.5 px-2 py-0.5 rounded text-[10px] font-semibold bg-rose-950 text-rose-200 border border-rose-800">Test/Demo</span>` : '');

      html += `
        <tr class="hover:bg-red-950/20 transition-colors cursor-pointer" onclick="window.openUserActivityProfile(${u.id})">
          <td class="py-3 px-3">
            <div class="text-white font-semibold">${escapeHtml(u.name)}${provBadge}</div>
            <div class="text-xs text-slate-400">${escapeHtml(u.role)}</div>
          </td>
          <td class="py-3 px-3">
            <div class="text-sky-300 hover:underline font-mono text-xs">${escapeHtml(u.email)}</div>
            ${verBadge}
          </td>
          <td class="py-3 px-3 text-slate-300 text-xs font-mono whitespace-nowrap">${regStr}</td>
          <td class="py-3 px-3 text-slate-300 text-xs font-mono whitespace-nowrap">${lastLoginStr}</td>
          <td class="py-3 px-3 text-white font-semibold whitespace-nowrap">${u.total_sessions_count || 0}</td>
          <td class="py-3 px-3 text-xs">
            <div class="text-slate-200 font-medium">${escapeHtml(devName)}</div>
            ${devType ? `<div class="text-slate-400">${escapeHtml(devType)}</div>` : ''}
          </td>
          <td class="py-3 px-3 text-xs text-slate-300">${escapeHtml(locStr)}</td>
          <td class="py-3 px-3">
            <span class="px-2 py-0.5 rounded text-xs font-semibold ${isAct ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-red-950 text-red-300 border border-red-800'}">${escapeHtml(u.account_status)}</span>
          </td>
          <td class="py-3 px-3 text-right whitespace-nowrap">
            <button type="button" onclick="event.stopPropagation(); window.openUserActivityProfile(${u.id})" class="px-3 py-1 rounded-lg bg-red-950/80 hover:bg-red-600 border border-red-800 text-white text-xs font-semibold cursor-pointer">View Profile</button>
          </td>
        </tr>
      `;
    });
    html += `</tbody></table>`;
    container.innerHTML = html;
  } catch (err) {
    container.innerHTML = `<div class="p-8 text-center text-red-400 text-sm">Failed to load user activity directory: ${escapeHtml(err.message)}</div>`;
  }
};

window.openUserActivityProfile = async function(userId) {
  const dirView = document.getElementById('ua-directory-view');
  const profView = document.getElementById('ua-profile-view');
  const titleEl = document.getElementById('ua-profile-title');
  const subEl = document.getElementById('ua-profile-subtitle');
  const bodyEl = document.getElementById('ua-profile-body');
  if (!dirView || !profView || !bodyEl || !window.cognisec?.fetchSocUserDetails) return;

  dirView.classList.add('hidden');
  profView.classList.remove('hidden');
  bodyEl.innerHTML = `<div class="p-8 text-center text-slate-300 text-sm">Loading complete user activity profile from PostgreSQL...</div>`;

  try {
    const d = await window.cognisec.fetchSocUserDetails(userId);
    const u = d.user || {};
    const logins = d.login_history || [];
    const devices = d.devices || [];
    const portalActs = d.portal_activity || [];
    const events = d.recent_events || [];

    if (titleEl) titleEl.textContent = `${u.name || 'User'} — User Activity Profile`;
    if (subEl) subEl.textContent = `${u.email || 'Not recorded'} · Role: ${u.role || 'USER'} · Status: ${u.account_status || 'UNKNOWN'}`;

    const loginRowsHtml = logins.length > 0 ? logins.map(l => {
      const dt = l.timestamp ? new Date(l.timestamp) : null;
      const datePart = dt && !isNaN(dt) ? dt.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) : 'Not recorded';
      const timePart = dt && !isNaN(dt) ? dt.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : 'Not recorded';
      const isOk = l.result === 'Successful';
      return `
        <tr class="hover:bg-red-950/15 text-xs">
          <td class="py-2.5 px-3 font-mono text-slate-200 whitespace-nowrap">${escapeHtml(datePart)}</td>
          <td class="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap">${escapeHtml(timePart)}</td>
          <td class="py-2.5 px-3 whitespace-nowrap"><span class="px-2 py-0.5 rounded font-semibold border ${isOk ? 'bg-emerald-950 text-emerald-300 border-emerald-800' : 'bg-red-950 text-red-300 border-red-800'}">${escapeHtml(l.result)}</span></td>
          <td class="py-2.5 px-3 text-slate-200">${escapeHtml(formatSocPortalName(l.application))}</td>
          <td class="py-2.5 px-3 text-slate-200">${escapeHtml(l.device_name || 'Not recorded')} <span class="text-slate-400">(${escapeHtml(l.device_type || 'Unknown')})</span></td>
          <td class="py-2.5 px-3 text-slate-300">${escapeHtml(l.browser || 'Not recorded')} · ${escapeHtml(l.os || 'Not recorded')}</td>
          <td class="py-2.5 px-3 font-mono text-slate-300">${escapeHtml(l.ip_address || 'Not recorded')}</td>
          <td class="py-2.5 px-3 text-slate-300">${escapeHtml(l.location || 'Location unavailable')}</td>
          <td class="py-2.5 px-3 font-mono text-slate-400">${escapeHtml(l.session_id ? l.session_id.slice(0, 14) + '…' : 'Not recorded')}</td>
        </tr>
      `;
    }).join('') : `<tr><td colspan="9" class="p-6 text-center text-slate-400 text-sm">No login records found for this user.</td></tr>`;

    const deviceCardsHtml = devices.length > 0 ? devices.map(dev => `
      <div class="p-4 rounded-xl bg-black/70 border border-slate-800 space-y-2 text-xs">
        <div class="flex items-center justify-between gap-2">
          <strong class="text-white text-sm">${escapeHtml(dev.nickname || 'Registered Device')}</strong>
          <span class="px-2 py-0.5 rounded font-semibold border ${dev.is_trusted ? 'bg-emerald-950 text-emerald-300 border-emerald-800' : 'bg-amber-950 text-amber-200 border-amber-800'}">${escapeHtml(dev.trust_state || 'UNKNOWN')}</span>
        </div>
        <div class="grid grid-cols-2 sm:grid-cols-4 gap-2 text-slate-300 font-mono">
          <div><span class="text-slate-500 block">Fingerprint</span>${escapeHtml(dev.masked_fingerprint || 'Not recorded')}</div>
          <div><span class="text-slate-500 block">Browser / OS</span>${escapeHtml(dev.browser || 'Unknown')} · ${escapeHtml(dev.os || 'Unknown')}</div>
          <div><span class="text-slate-500 block">First Seen</span>${dev.first_seen ? formatSocTimestamp(dev.first_seen) : 'Not recorded'}</div>
          <div><span class="text-slate-500 block">Last Seen · Sessions</span>${dev.last_seen ? formatSocTimestamp(dev.last_seen) : 'Not recorded'} · ${dev.session_count ?? 0}</div>
        </div>
        <div class="text-slate-400">Device Type: <span class="text-slate-200">${escapeHtml(dev.device_type || 'Unknown')}</span> · Location: <span class="text-slate-200">${escapeHtml(dev.location || 'Location unavailable')}</span></div>
      </div>
    `).join('') : `<div class="p-6 text-center text-slate-400 text-sm">No devices recorded for this user.</div>`;

    const portalRowsHtml = portalActs.length > 0 ? portalActs.map(pa => `
      <div class="p-3 rounded-xl bg-black/60 border border-red-950/60 flex flex-wrap items-center justify-between gap-2 text-xs">
        <div>
          <span class="font-mono text-slate-400 mr-2">${formatSocTimestamp(pa.timestamp)}</span>
          <span class="px-2 py-0.5 rounded bg-black border border-slate-800 text-slate-200 mr-2">${escapeHtml(formatSocPortalName(pa.application))}</span>
          <strong class="text-white">${escapeHtml(pa.action_label)}</strong>
          <span class="text-slate-400 ml-1.5">· ${escapeHtml(pa.description || '')}</span>
          ${pa.session_id ? `<span class="text-slate-500 font-mono ml-2">[${escapeHtml(pa.session_id.slice(0, 14))}…]</span>` : ''}
        </div>
        <span class="px-2 py-0.5 rounded border border-slate-700 bg-slate-900 text-slate-200 font-semibold">${escapeHtml(pa.outcome || pa.decision || 'Recorded')}</span>
      </div>
    `).join('') : `<div class="p-6 text-center text-slate-400 text-sm">No portal activity events recorded yet.</div>`;

    const secEvRowsHtml = events.length > 0 ? events.map(ev => `
      <div class="p-3 rounded-xl bg-black/60 border border-slate-800 flex flex-wrap items-center justify-between gap-2 text-xs">
        <div>
          <span class="font-mono text-slate-400 mr-2">${formatSocTimestamp(ev.timestamp)}</span>
          <strong class="text-white">${escapeHtml(ev.event_type)}</strong>
          <span class="text-slate-400 ml-1.5">(${escapeHtml(formatSocPortalName(ev.application))})</span>
          <span class="text-slate-300 ml-1.5">· ${escapeHtml(ev.details || '')}</span>
        </div>
        <span class="px-2 py-0.5 rounded font-mono ${ev.severity === 'CRITICAL' || ev.severity === 'HIGH' ? 'bg-red-950 text-red-300 border border-red-800' : 'bg-slate-900 text-slate-300 border border-slate-700'}">${escapeHtml(ev.severity || 'LOW')} · ${escapeHtml(ev.decision || 'ALLOW')}</span>
      </div>
    `).join('') : `<div class="p-6 text-center text-slate-400 text-sm">No security events recorded for this user.</div>`;

    bodyEl.innerHTML = `
      <div class="p-5 rounded-2xl bg-black/60 border border-red-900/50 space-y-3">
        <h5 class="font-heading font-bold text-base text-white border-b border-red-950 pb-2">1. Account Overview</h5>
        <div class="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs font-mono">
          <div><span class="text-slate-400 block">Full Name</span><strong class="text-white text-sm">${escapeHtml(u.name || 'Not recorded')}</strong></div>
          <div><span class="text-slate-400 block">Registered Email</span><strong class="text-sky-300 text-sm">${escapeHtml(u.email || 'Not recorded')}</strong></div>
          <div><span class="text-slate-400 block">Registration Date</span><strong class="text-slate-200">${u.created_at ? formatSocTimestamp(u.created_at) : 'Not recorded'}</strong></div>
          <div><span class="text-slate-400 block">Email Verification</span><strong class="${u.email_verified ? 'text-emerald-400' : 'text-amber-300'}">${u.email_verified ? 'Verified' : 'Unverified'}${u.email_verified_at ? ' · ' + formatSocTimestamp(u.email_verified_at) : ''}</strong></div>
          <div><span class="text-slate-400 block">Account Status</span><strong class="text-white">${escapeHtml(u.account_status || 'Not recorded')}</strong></div>
          <div><span class="text-slate-400 block">Role</span><strong class="text-white">${escapeHtml(u.role || 'USER')}</strong></div>
          <div><span class="text-slate-400 block">Total Logins / Sessions</span><strong class="text-white">${u.total_sessions_count ?? 0} (${u.active_sessions_count ?? 0} active)</strong></div>
          <div><span class="text-slate-400 block">Last Known Location</span><strong class="text-slate-200">${escapeHtml(u.last_location || 'Location unavailable')}</strong></div>
        </div>
      </div>

      <div class="p-5 rounded-2xl bg-black/60 border border-red-900/50 space-y-3">
        <h5 class="font-heading font-bold text-base text-white border-b border-red-950 pb-2">2. Login History (${logins.length} recorded)</h5>
        <div class="overflow-x-auto max-h-96">
          <table class="w-full text-left border-collapse">
            <thead>
              <tr class="border-b border-red-950 text-slate-300 text-[11px] uppercase">
                <th class="py-2 px-3">Date</th>
                <th class="py-2 px-3">Time</th>
                <th class="py-2 px-3">Result</th>
                <th class="py-2 px-3">Portal</th>
                <th class="py-2 px-3">Device</th>
                <th class="py-2 px-3">Browser &amp; OS</th>
                <th class="py-2 px-3">IP Address</th>
                <th class="py-2 px-3">Location</th>
                <th class="py-2 px-3">Session ID</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-red-950/40">${loginRowsHtml}</tbody>
          </table>
        </div>
      </div>

      <div class="p-5 rounded-2xl bg-black/60 border border-red-900/50 space-y-3">
        <h5 class="font-heading font-bold text-base text-white border-b border-red-950 pb-2">3. Registered Devices (${devices.length})</h5>
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-3">${deviceCardsHtml}</div>
      </div>

      <div class="p-5 rounded-2xl bg-black/60 border border-red-900/50 space-y-3">
        <h5 class="font-heading font-bold text-base text-white border-b border-red-950 pb-2">4. Portal Activity (${portalActs.length} events)</h5>
        <div class="space-y-2 max-h-80 overflow-y-auto pr-1">${portalRowsHtml}</div>
      </div>

      <div class="p-5 rounded-2xl bg-black/60 border border-red-900/50 space-y-3">
        <h5 class="font-heading font-bold text-base text-white border-b border-red-950 pb-2">5. Security Events (${events.length})</h5>
        <div class="space-y-2 max-h-80 overflow-y-auto pr-1">${secEvRowsHtml}</div>
      </div>
    `;
  } catch (err) {
    bodyEl.innerHTML = `<div class="p-8 text-center text-red-400 text-sm">Failed to load user activity profile: ${escapeHtml(err.message)}</div>`;
  }
};

window._agenticActivityCache = [];

window.verifyAgenticProviderNow = async function() {
  if (!window.cognisec?.verifyAgenticProvider) return;
  const btn = document.getElementById('agentic-verify-provider-btn');
  const orig = btn ? btn.textContent : '↻ Refresh Provider Status';
  if (btn) { btn.disabled = true; btn.textContent = '⏳ Checking Gemini...'; }
  try {
    await window.cognisec.verifyAgenticProvider();
  } catch (e) {
    console.warn('Provider verification error:', e);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = orig; }
    await window.loadAgenticMonitorData();
  }
};

window.renderAgenticWorkflow = function(act) {
  const container = document.getElementById('agentic-workflow-stages');
  const sub = document.getElementById('agentic-workflow-subtitle');
  const pill = document.getElementById('agentic-workflow-arbiter-pill');
  if (!container || !act) return;

  const executed = Array.isArray(act.agents_executed) ? act.agents_executed : [];
  const stageStatus = (key) => {
    if (executed.includes(`${key}:fallback`)) return 'FALLBACK';
    if (executed.includes(key)) return 'COMPLETED';
    return 'SKIPPED';
  };
  const badgeFor = (st) => {
    if (st === 'COMPLETED') return '<span class="px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-[10px] font-mono">COMPLETED</span>';
    if (st === 'FALLBACK') return '<span class="px-1.5 py-0.5 rounded bg-amber-950 text-amber-200 border border-amber-800 text-[10px] font-mono">FALLBACK</span>';
    return '<span class="px-1.5 py-0.5 rounded bg-slate-900 text-slate-500 border border-slate-700 text-[10px] font-mono">SKIPPED</span>';
  };

  if (sub) sub.textContent = `Showing execution #${act.event_id || 'demo'} (${act.environment_label || 'PRODUCTION'}) · Trigger: ${act.trigger_event} · Portal: ${formatSocPortalName(act.portal)}`;
  if (pill) {
    pill.textContent = `Deterministic Arbiter: ${act.arbiter_decision || act.outcome || '—'} (${act.risk_level || '—'})`;
    pill.classList.remove('hidden');
  }

  const out = act.sanitized_outputs || {};
  const stages = [
    { title: '1. Security Event →', st: 'COMPLETED', desc: `${act.trigger_event} on ${formatSocPortalName(act.portal)} (${act.risk_level || 'LOW'})` },
    { title: '2. Context Agent →', st: stageStatus('SecurityContextAgent'), desc: out.context_summary || 'Session & device trust context.' },
    { title: '3. Risk Agent →', st: stageStatus('RiskAnalysisAgent'), desc: out.risk_summary || 'Threat classification (monotonic floor).' },
    { title: '4. Adaptive Auth →', st: stageStatus('AdaptiveAuthAgent'), desc: out.adaptive_auth_factor ? `Recommended: ${out.adaptive_auth_factor}` : 'Policy-bounded step-up check.' },
    { title: '5. Response Agent →', st: stageStatus('SecurityResponseAgent'), desc: out.security_response || 'Bounded containment evaluation.' },
    { title: '6. SOC Agent →', st: stageStatus('SOCMonitoringAgent'), desc: out.soc_summary || 'Fleet posture & alert correlation.' },
    { title: '7. Deterministic Arbiter', st: 'ENFORCED', desc: `Authoritative decision: ${act.arbiter_decision || act.outcome || '—'}` },
  ];

  container.innerHTML = stages.map(s => `
    <div class="p-3 rounded-xl bg-slate-950/90 border ${s.st === 'COMPLETED' || s.st === 'ENFORCED' ? 'border-emerald-800/60' : (s.st === 'FALLBACK' ? 'border-amber-800/60' : 'border-slate-800')} space-y-1.5">
      <div class="flex items-center justify-between gap-1">
        <span class="font-bold text-white text-[11px]">${escapeHtml(s.title)}</span>
        ${s.st === 'ENFORCED' ? '<span class="px-1.5 py-0.5 rounded bg-red-950 text-red-200 border border-red-800 text-[10px] font-mono">ENFORCED</span>' : badgeFor(s.st)}
      </div>
      <p class="text-slate-400 text-[11px] leading-snug">${escapeHtml(String(s.desc).slice(0, 120))}</p>
    </div>
  `).join('');
};

window.inspectAgenticActivityItem = function(idx) {
  const act = window._agenticActivityCache[idx];
  const detailEl = document.getElementById('agentic-activity-detail');
  if (!act || !detailEl) return;
  window.renderAgenticWorkflow(act);
  const out = act.sanitized_outputs || {};
  detailEl.classList.remove('hidden');
  detailEl.innerHTML = `
    <div class="flex items-center justify-between border-b border-red-950 pb-2">
      <div><strong class="text-white">${escapeHtml(act.trigger_event)}</strong> <span class="px-1.5 py-0.5 rounded text-[10px] font-mono ${act.is_demo ? 'bg-sky-950 text-sky-300 border border-sky-800' : 'bg-red-950 text-red-200 border border-red-800'}">${escapeHtml(act.environment_label || 'PRODUCTION')}</span></div>
      <button type="button" onclick="document.getElementById('agentic-activity-detail').classList.add('hidden')" class="text-slate-400 hover:text-white cursor-pointer">Close</button>
    </div>
    <div class="grid grid-cols-2 gap-2 text-[11px]">
      <div><span class="text-slate-400">User Ref:</span> <span class="text-slate-200 font-mono">${escapeHtml(act.user_ref || '—')}</span></div>
      <div><span class="text-slate-400">Portal / Risk:</span> <span class="text-slate-200">${escapeHtml(formatSocPortalName(act.portal))} · ${escapeHtml(act.risk_level || '—')}</span></div>
      <div><span class="text-slate-400">Arbiter Decision:</span> <span class="text-red-300 font-semibold">${escapeHtml(act.arbiter_decision || '—')}</span></div>
      <div><span class="text-slate-400">Provider / Time:</span> <span class="text-slate-200 font-mono">${escapeHtml(act.provider_status || '—')}${act.duration_ms ? ` · ${act.duration_ms}ms` : ''}</span></div>
    </div>
    ${act.fallback_or_error ? `<div class="p-2 rounded bg-amber-950/40 border border-amber-800/60 text-amber-200"><strong>Fallback Reason:</strong> ${escapeHtml(typeof act.fallback_or_error === 'string' ? act.fallback_or_error : JSON.stringify(act.fallback_or_error))}</div>` : ''}
    <div class="space-y-1 text-[11px] text-slate-300">
      <div><strong class="text-slate-200">Summary:</strong> ${escapeHtml(act.sanitized_result || '—')}</div>
      ${out.adaptive_auth_factor ? `<div><strong class="text-slate-200">Adaptive Auth Recommendation:</strong> ${escapeHtml(out.adaptive_auth_factor)}</div>` : ''}
      ${out.security_response ? `<div><strong class="text-slate-200">Security Response Recommendation:</strong> ${escapeHtml(out.security_response)}</div>` : ''}
    </div>
  `;
};

window.loadAgenticMonitorData = async function() {
  if (!window.cognisec || !window.cognisec.isAdmin()) return;

  const provBadge = document.getElementById('agentic-provider-badge');
  const connBadge = document.getElementById('agentic-connectivity-badge');
  const metaProv = document.getElementById('agentic-meta-provider');
  const metaModel = document.getElementById('agentic-meta-model');
  const metaCreds = document.getElementById('agentic-meta-creds');
  const metaConn = document.getElementById('agentic-meta-connectivity');
  const metaTestGen = document.getElementById('agentic-meta-testgen');
  const metaLastCheck = document.getElementById('agentic-meta-lastcheck');
  const fbNoteEl = document.getElementById('agentic-provider-fallback-note');
  const agentsGrid = document.getElementById('agentic-agents-grid');
  const activityEl = document.getElementById('agentic-recent-activity');
  const socSummaryEl = document.getElementById('agentic-soc-summary');

  try {
    const [agentData, metrics, alertsList, locksList, containment] = await Promise.all([
      window.cognisec.fetchAgenticStatus(),
      window.cognisec.fetchSocMetrics('genuine'),
      window.cognisec.fetchSocAlerts(5, 'genuine'),
      window.cognisec.fetchSocPortalLocks ? window.cognisec.fetchSocPortalLocks() : Promise.resolve([]),
      window.cognisec.fetchSocContainmentActions(5),
    ]);

    const ph = agentData?.provider_health || {};
    const statusText = ph.connectivity_status || 'UNVERIFIED';
    if (provBadge) provBadge.textContent = `Provider: ${(ph.configured_provider || 'mock').toUpperCase()} (${ph.configured_model || '—'})`;
    if (connBadge) {
      connBadge.textContent = `Status: ${statusText}`;
      const isOk = statusText === 'VERIFIED' || statusText === 'MOCK_MODE';
      connBadge.className = isOk
        ? 'px-3 py-1 rounded-full text-xs font-mono font-semibold bg-emerald-950/80 text-emerald-300 border border-emerald-700/70'
        : 'px-3 py-1 rounded-full text-xs font-mono font-semibold bg-amber-950/80 text-amber-300 border border-amber-700/70';
    }
    if (metaProv) metaProv.textContent = (ph.configured_provider || 'mock').toUpperCase();
    if (metaModel) metaModel.textContent = ph.configured_model || '—';
    if (metaCreds) {
      metaCreds.textContent = ph.credentials_present ? 'Yes' : 'No';
      metaCreds.className = ph.credentials_present ? 'text-emerald-300 font-mono text-sm' : 'text-red-400 font-mono text-sm';
    }
    if (metaConn) {
      const apiConn = ph.api_connectivity || (ph.connectivity_verified ? 'Connected' : 'Not checked');
      metaConn.textContent = apiConn;
      metaConn.className = apiConn === 'Connected' ? 'text-emerald-300 font-mono text-sm' : (apiConn === 'Failed' ? 'text-red-400 font-mono text-sm' : 'text-amber-300 font-mono text-sm');
    }
    if (metaTestGen) {
      const tg = ph.test_generation || 'Not tested';
      metaTestGen.textContent = tg;
      metaTestGen.className = tg === 'Successful' ? 'text-emerald-300 font-mono text-sm' : (tg === 'Failed' ? 'text-red-400 font-mono text-sm' : 'text-slate-300 font-mono text-sm');
    }
    if (metaLastCheck) {
      metaLastCheck.textContent = ph.last_successful_check
        ? formatSocTimestamp(ph.last_successful_check)
        : (ph.last_failure_category ? `Error: ${ph.last_failure_category}` : 'Not checked yet');
    }
    if (fbNoteEl) {
      if (statusText === 'UNAVAILABLE' || statusText === 'MISCONFIGURED') {
        fbNoteEl.innerHTML = `<strong>Provider Notice (${escapeHtml(ph.last_failure_category || statusText)}):</strong> ${escapeHtml(ph.last_failure_reason || 'Gemini API is currently unavailable.')} Deterministic RiskService, DecisionService, and DeterministicSecurityArbiter remain fully operational.`;
        fbNoteEl.classList.remove('hidden');
      } else {
        fbNoteEl.classList.add('hidden');
      }
    }

    if (agentsGrid) {
      const agents = Array.isArray(agentData?.agents) ? agentData.agents : [];
      agentsGrid.innerHTML = agents.map(ag => {
        const av = ag.availability_status || 'READY';
        const avCls = (av === 'COMPLETED' || av === 'READY')
          ? 'text-emerald-300 bg-emerald-950/60 border-emerald-800/60'
          : (av === 'FALLBACK' ? 'text-amber-200 bg-amber-950/60 border-amber-800/60' : 'text-red-300 bg-red-950/60 border-red-800/60');
        return `
        <div class="p-4 rounded-xl bg-black/75 border border-slate-800 hover:border-red-800/80 transition-all flex flex-col justify-between space-y-3">
          <div class="space-y-1.5">
            <div class="flex items-center justify-between gap-2">
              <span class="text-[11px] font-mono font-semibold px-2 py-0.5 rounded bg-black text-slate-300 border border-slate-700">Stage ${Number(ag.stage)}</span>
              <span class="text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${avCls}">${escapeHtml(av)}</span>
            </div>
            <h5 class="font-heading font-bold text-sm text-white">${escapeHtml(ag.name)}</h5>
            <p class="text-xs text-slate-300 leading-relaxed">${escapeHtml(ag.responsibility)}</p>
          </div>
          <div class="pt-2 border-t border-slate-800/80 text-[11px] font-mono text-slate-400 space-y-1">
            <div>Last Run: <span class="text-slate-200">${ag.last_executed_at ? formatSocTimestamp(ag.last_executed_at) : 'Ready (no runs yet)'}</span></div>
            <div class="flex items-center gap-2 text-[10px]">
              <span class="text-emerald-400">OK: ${Number(ag.completed_count || 0)}</span>
              <span class="text-amber-300">Fallback: ${Number(ag.fallback_count || 0)}</span>
              <span class="text-red-400">Fail: ${Number(ag.failed_count || 0)}</span>
            </div>
            ${ag.latest_recommendation ? `<div class="text-[10px] text-slate-300 truncate" title="${escapeHtml(ag.latest_recommendation)}">Rec: ${escapeHtml(ag.latest_recommendation)}</div>` : ''}
          </div>
        </div>`;
      }).join('');
    }

    if (activityEl) {
      const acts = Array.isArray(agentData?.recent_activity) ? agentData.recent_activity : [];
      window._agenticActivityCache = acts;
      if (!acts.length) {
        activityEl.innerHTML = `<div class="p-5 rounded-xl bg-black/50 border border-slate-800 text-center text-slate-400 text-sm">No persisted agent executions recorded yet. Click <strong>Run Security Analysis</strong> above to run a live demonstration.</div>`;
      } else {
        window.renderAgenticWorkflow(acts[0]);
        activityEl.innerHTML = acts.map((act, idx) => {
          const envBadge = act.is_demo
            ? `<span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-sky-950 text-sky-300 border border-sky-800">DEMO</span>`
            : `<span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-red-950 text-red-200 border border-red-800">PROD</span>`;
          const provTag = act.provider_status === 'FALLBACK'
            ? `<span class="text-amber-300">FALLBACK</span>`
            : `<span class="text-emerald-300">${escapeHtml(act.provider_status || 'GEMINI')}</span>`;
          return `
          <div onclick="window.inspectAgenticActivityItem(${idx})" class="p-3.5 rounded-xl bg-black/70 border border-slate-800 hover:border-red-700/80 cursor-pointer space-y-1 transition-colors">
            <div class="flex items-center justify-between gap-2 text-xs">
              <div class="flex items-center gap-1.5 truncate">
                ${envBadge}
                <strong class="text-white font-semibold truncate">${escapeHtml(act.trigger_event)}</strong>
              </div>
              <span class="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-slate-200 font-mono text-[10px] shrink-0">${escapeHtml(act.arbiter_decision || act.outcome)}</span>
            </div>
            <div class="text-xs text-slate-300 truncate">${escapeHtml(act.sanitized_result)}</div>
            <div class="flex items-center justify-between text-[10px] text-slate-400 font-mono">
              <span>${escapeHtml(formatSocPortalName(act.portal))} · ${escapeHtml(act.risk_level || 'LOW')} · ${provTag}</span>
              <span>${escapeHtml(act.timestamp ? formatSocTimestamp(act.timestamp) : '—')}</span>
            </div>
          </div>`;
        }).join('');
      }
    }

    if (socSummaryEl) {
      const openIncidents = metrics?.open_incidents_count ?? metrics?.open_alerts_count ?? 0;
      const activeSessions = metrics?.live_sessions_count ?? 0;
      const activeLocks = Array.isArray(locksList) ? locksList.filter(l => l.status === 'ACTIVE').length : 0;
      const alertsArr = Array.isArray(alertsList) ? alertsList : [];
      const highCritCount = alertsArr.filter(a => a.severity === 'HIGH' || a.severity === 'CRITICAL').length;
      const containmentList = Array.isArray(containment?.actions) ? containment.actions : [];

      socSummaryEl.innerHTML = `
        <div class="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
          <div class="p-2.5 rounded-xl bg-black/70 border border-red-900/50">
            <span class="text-slate-400 text-[10px] uppercase block">Open Incidents</span>
            <strong class="text-lg font-bold text-amber-300">${Number(openIncidents)}</strong>
          </div>
          <div class="p-2.5 rounded-xl bg-black/70 border border-red-900/50">
            <span class="text-slate-400 text-[10px] uppercase block">High/Crit Recent</span>
            <strong class="text-lg font-bold text-red-400">${Number(highCritCount)}</strong>
          </div>
          <div class="p-2.5 rounded-xl bg-black/70 border border-slate-800">
            <span class="text-slate-400 text-[10px] uppercase block">Active Sessions</span>
            <strong class="text-lg font-bold text-emerald-300">${Number(activeSessions)}</strong>
          </div>
          <div class="p-2.5 rounded-xl bg-black/70 border border-slate-800">
            <span class="text-slate-400 text-[10px] uppercase block">Portal Locks</span>
            <strong class="text-lg font-bold text-red-300">${Number(activeLocks)}</strong>
          </div>
        </div>
        <div class="space-y-1.5">
          <div class="text-xs font-semibold uppercase text-slate-400">Recent Genuine Security Incidents</div>
          ${alertsArr.length ? alertsArr.slice(0, 4).map(inc => `
            <div onclick="window.openIncidentDossier ? window.openIncidentDossier(${inc.id}) : switchDashboardTab('alerts')" class="p-2.5 rounded-lg bg-black/70 border border-slate-800 hover:border-red-800 cursor-pointer flex items-center justify-between gap-2 text-xs">
              <div class="truncate">
                <span class="font-semibold text-white">${escapeHtml(inc.alert_type || 'Security Incident')}</span>
                <span class="text-slate-400 ml-1.5">(${escapeHtml(formatSocPortalName(inc.application || 'platform'))})</span>
              </div>
              <span class="px-2 py-0.5 rounded font-mono text-[11px] bg-red-950/70 text-red-200 border border-red-800/60 shrink-0">${escapeHtml(inc.status || 'OPEN')}</span>
            </div>
          `).join('') : '<div class="text-xs text-slate-400 p-2">No open genuine security incidents.</div>'}
        </div>
        <div class="space-y-1.5">
          <div class="text-xs font-semibold uppercase text-slate-400">Recent Containment Actions</div>
          ${containmentList.length ? containmentList.slice(0, 3).map(ca => `
            <div class="p-2.5 rounded-lg bg-black/70 border border-slate-800 flex items-center justify-between gap-2 text-xs">
              <span class="text-slate-200 truncate">${escapeHtml(ca.action_type || ca.action || 'Containment')} — ${escapeHtml(formatSocPortalName(ca.application || ca.portal || 'platform'))}</span>
              <span class="text-[11px] font-mono text-slate-400 shrink-0">${escapeHtml(ca.timestamp ? formatSocTimestamp(ca.timestamp) : '')}</span>
            </div>
          `).join('') : '<div class="text-xs text-slate-400 p-2">No recent containment actions recorded.</div>'}
        </div>
      `;
    }
  } catch (err) {
    if (agentsGrid) {
      agentsGrid.innerHTML = `<div class="col-span-full p-4 rounded-xl bg-red-950/40 border border-red-800 text-red-200 text-sm">Failed to load Agentic AI Monitor: ${escapeHtml(err?.message || 'Unauthorized or network error')}</div>`;
    }
  }
};

window.runAgenticDemoAnalysis = async function() {
  if (!window.cognisec || !window.cognisec.isAdmin()) return;

  const btn = document.getElementById('agentic-run-demo-btn');
  const scenarioEl = document.getElementById('agentic-demo-scenario');
  const resultsEl = document.getElementById('agentic-demo-results');
  const detEl = document.getElementById('agentic-demo-det');
  const recEl = document.getElementById('agentic-demo-rec');
  const arbEl = document.getElementById('agentic-demo-arbiter');
  const stagesEl = document.getElementById('agentic-demo-stage-details');

  const scenario = scenarioEl ? scenarioEl.value : 'medium';
  const origLabel = btn ? btn.textContent : '▶ Run Security Analysis';
  if (btn) {
    btn.disabled = true;
    btn.textContent = '⏳ Running Multi-Agent Analysis...';
  }

  try {
    const res = await window.cognisec.runAgenticDemoAnalysis(scenario);
    if (resultsEl) resultsEl.classList.remove('hidden');

    const det = res.deterministic_assessment || {};
    const recs = res.agent_recommendations || {};
    const arb = res.arbiter_decision || {};
    const exec = res.execution_result || {};

    if (detEl) {
      detEl.innerHTML = `
        <div>Score: <strong class="font-mono text-white">${Number(det.risk_score || 0).toFixed(2)}</strong></div>
        <div>Classification: <strong class="text-amber-300">${escapeHtml(det.risk_level || '—')}</strong></div>
        <div class="text-xs text-slate-400">Portal: ${escapeHtml(det.portal || 'shopping')}</div>
      `;
    }

    const riskRec = recs.risk_analysis || {};
    const authRec = recs.adaptive_auth || {};
    if (recEl) {
      recEl.innerHTML = `
        <div>Risk Agent: <strong class="text-sky-300">${escapeHtml(riskRec.recommended_risk_level || '—')}</strong> (${Number(riskRec.recommended_risk_score || 0).toFixed(2)})</div>
        <div>Factor: <strong class="font-mono text-purple-300">${escapeHtml(authRec.recommended_factor || '—')}</strong></div>
        <div class="text-xs text-slate-400">Threat: ${escapeHtml(riskRec.threat_category || '—')}</div>
      `;
    }

    if (arbEl) {
      arbEl.innerHTML = `
        <div>Final Decision: <strong class="text-emerald-300">${escapeHtml(arb.final_decision || '—')}</strong></div>
        <div>Final Level: <strong class="font-mono text-white">${escapeHtml(arb.final_risk_level || '—')} (${Number(arb.final_risk_score || 0).toFixed(2)})</strong></div>
        <div class="text-xs text-slate-400">Executed in ${Number(exec.duration_ms || 0)} ms &bull; Isolated Demo</div>
      `;
    }

    if (stagesEl) {
      const ctxRec = recs.security_context || {};
      const respRec = recs.security_response || {};
      const socRec = recs.soc_monitoring || {};
      const stMap = exec.agent_statuses || {};
      const badge = (k) => {
        const s = stMap[k]?.status || 'COMPLETED';
        const cls = s === 'COMPLETED' ? 'text-emerald-300' : (s === 'FALLBACK' ? 'text-amber-300' : 'text-slate-400');
        return `<span class="text-[10px] font-mono ${cls}">${escapeHtml(s)}</span>`;
      };
      stagesEl.innerHTML = `
        <div class="p-3 rounded-xl bg-black/70 border border-slate-800 space-y-1">
          <div class="flex items-center justify-between"><span class="font-bold text-sky-300">Security Context</span>${badge('SecurityContextAgent')}</div>
          <p class="text-slate-300">${escapeHtml(ctxRec.summary || 'Evaluated.')}</p>
        </div>
        <div class="p-3 rounded-xl bg-black/70 border border-slate-800 space-y-1">
          <div class="flex items-center justify-between"><span class="font-bold text-amber-300">Risk Analysis</span>${badge('RiskAnalysisAgent')}</div>
          <p class="text-slate-300">${escapeHtml((riskRec.explanation || 'Evaluated.').slice(0, 180))}</p>
        </div>
        <div class="p-3 rounded-xl bg-black/70 border border-slate-800 space-y-1">
          <div class="flex items-center justify-between"><span class="font-bold text-purple-300">Adaptive Auth</span>${badge('AdaptiveAuthAgent')}</div>
          <p class="text-slate-300">${escapeHtml((authRec.rationale || 'Policy evaluated.').slice(0, 180))}</p>
        </div>
        <div class="p-3 rounded-xl bg-black/70 border border-slate-800 space-y-1">
          <div class="flex items-center justify-between"><span class="font-bold text-red-300">Security Response</span>${badge('SecurityResponseAgent')}</div>
          <p class="text-slate-300">${escapeHtml((respRec.recommended_response || 'Bounded response.').slice(0, 180))}</p>
        </div>
        <div class="p-3 rounded-xl bg-black/70 border border-slate-800 space-y-1">
          <div class="flex items-center justify-between"><span class="font-bold text-emerald-300">SOC Monitoring</span>${badge('SOCMonitoringAgent')}</div>
          <p class="text-slate-300">${escapeHtml((socRec.executive_summary || 'Posture updated.').slice(0, 180))}</p>
        </div>
      `;
    }

    // Refresh recent activity & provider health after demo run
    await window.loadAgenticMonitorData();
  } catch (err) {
    if (resultsEl) resultsEl.classList.remove('hidden');
    if (detEl) detEl.innerHTML = `<span class="text-red-400">Demo execution failed: ${escapeHtml(err?.message || 'Error')}</span>`;
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = origLabel;
    }
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
    showNotificationToast("AI Re-Scan Failed", e.message || "AI Re-Scan encountered an error.", "error");
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

  const otpPane = document.getElementById('reg-step-pane-otp');
  const otpPill = document.getElementById('reg-step-pill-otp');
  if (step === 'otp') {
    const p1 = document.getElementById('reg-step-pane-1');
    const pill1 = document.getElementById('reg-step-pill-1');
    if (p1) p1.classList.add('hidden');
    if (otpPane) otpPane.classList.remove('hidden');
    if (pill1) pill1.className = 'py-1.5 px-2 rounded-lg bg-emerald-950 text-emerald-300 font-bold border border-emerald-800 transition-all';
    if (otpPill) otpPill.className = 'py-1.5 px-2 rounded-lg bg-red-600 text-white font-bold transition-all shadow-[0_0_10px_rgba(239,68,68,0.5)]';
    return;
  }
  if (otpPane) otpPane.classList.add('hidden');
  if (otpPill) otpPill.className = 'py-1.5 px-2 rounded-lg bg-slate-900 text-slate-500 font-bold border border-slate-800 transition-all';

  // Update stepper pills
  for (let i = 1; i <= 4; i++) {
    const pill = document.getElementById(`reg-step-pill-${i}`);
    const pane = document.getElementById(`reg-step-pane-${i}`);
    if (pill) {
      if (i === step) {
        pill.className = 'py-1.5 px-2 rounded-lg bg-red-600 text-white font-bold transition-all shadow-[0_0_10px_rgba(239,68,68,0.5)]';
      } else if (i < step) {
        pill.className = 'py-1.5 px-2 rounded-lg bg-emerald-950 text-emerald-300 font-bold border border-emerald-800 transition-all';
      } else {
        pill.className = 'py-1.5 px-2 rounded-lg bg-slate-900 text-slate-500 font-bold border border-slate-800 transition-all';
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

    // Enforce mandatory adaptive authentication enrollment before portal/dashboard access
    if (result.data.role !== 'ADMIN' && result.data.security_enrollment_completed === false) {
      closeModal('login');
      syncAuthStateUI();
      if (typeof window.openMandatoryEnrollmentModal === 'function') {
        await window.openMandatoryEnrollmentModal();
      }
      return;
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
      if (n.email_delivery_status === 'DELIVERY_CONFIRMED') {
        emailStatusHtml = '<span class="text-[10px] text-emerald-400 font-mono">📧 Owner Alert: Delivery Confirmed</span>';
      } else if (n.email_delivery_status === 'SMTP_ACCEPTED' || n.email_delivery_status === 'SENT') {
        emailStatusHtml = '<span class="text-[10px] text-emerald-400 font-mono">📧 Owner Alert: Submitted to Mail Server</span>';
      } else if (n.email_delivery_status === 'RETRY_PENDING') {
        emailStatusHtml = '<span class="text-[10px] text-amber-400 font-mono">📧 Delivery Retry Pending</span>';
      } else if (n.email_delivery_status === 'PENDING' || n.email_delivery_status === 'SENDING') {
        emailStatusHtml = '<span class="text-[10px] text-amber-400 font-mono">📧 Sending Verification Email...</span>';
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
      showNotificationToast("SOC Access Restricted", "Only Security Administrators can access the SOC Security Operations Dashboard.", "error");
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

// ============================================================================
// CENTRAL DASHBOARD PORTAL SUSPENSION & ISOLATION CONTROLLER (index.html)
// ============================================================================

let _portalLocksRefreshInFlight = false;

window.renderDashboardPortalLocks = function(summary = null) {
  const esc = (s) => (window.cognisec && typeof window.cognisec._escapeHtml === 'function')
    ? window.cognisec._escapeHtml(String(s ?? ''))
    : String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  let pendingNotice = null;
  try {
    const raw = sessionStorage.getItem('cognisec_portal_ejection');
    if (raw) pendingNotice = JSON.parse(raw);
  } catch (_) {}

  const portals = (summary && summary.portals) ? { ...summary.portals } : {};
  let locks = (summary && Array.isArray(summary.locks)) ? [...summary.locks] : [];

  if (summary && locks.length === 0 && pendingNotice) {
    try { sessionStorage.removeItem('cognisec_portal_ejection'); } catch (_) {}
    pendingNotice = null;
  } else if (!summary && pendingNotice && pendingNotice.portal) {
    const pKey = String(pendingNotice.portal).toLowerCase();
    locks = [pendingNotice.lock || pendingNotice];
    portals[pKey] = {
      portal: pKey,
      portal_display_name: pendingNotice.portal_display_name || pKey.toUpperCase(),
      locked: true,
      status: 'SUSPENDED',
      grant_active: false,
      lock: pendingNotice.lock || pendingNotice,
    };
  }

  const portalMeta = {
    college: {
      href: 'college.html',
      landingDefaultBadge: 'EDUCATION & ACADEMICS',
      landingLaunchHtml: '<span>Live Demo</span><svg class="w-4 h-4" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14"/><path d="m12 5 7 7-7 7"/></svg>',
      dashLaunchHtml: 'Launch Academic Portal →',
      dashEnabledClass: 'w-full py-2.5 px-3 rounded-lg bg-sky-600 hover:bg-sky-500 text-white font-mono font-bold text-xs text-center block transition-all shadow-[0_2px_12px_rgba(2,132,199,0.25)]',
      landingEnabledClass: 'w-full py-3.5 px-4 rounded-xl text-xs font-heading font-bold text-black uppercase bg-sky-400 hover:bg-sky-300 shadow-[0_0_20px_rgba(14,165,233,0.5)] transition-all flex items-center justify-center gap-2 cursor-pointer',
    },
    shopping: {
      href: 'shopping.html',
      landingDefaultBadge: 'E-COMMERCE & RETAIL',
      landingLaunchHtml: '<span>Live Demo</span><svg class="w-4 h-4" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14"/><path d="m12 5 7 7-7 7"/></svg>',
      dashLaunchHtml: 'Launch Shopping Portal →',
      dashEnabledClass: 'w-full py-2.5 px-3 rounded-lg bg-amber-600 hover:bg-amber-500 text-white font-mono font-bold text-xs text-center block transition-all shadow-[0_2px_12px_rgba(217,119,6,0.25)]',
      landingEnabledClass: 'w-full py-3.5 px-4 rounded-xl text-xs font-heading font-bold text-black uppercase bg-amber-500 hover:bg-amber-400 shadow-[0_0_20px_rgba(245,158,11,0.5)] transition-all flex items-center justify-center gap-2 cursor-pointer',
    },
    healthcare: {
      href: 'healthcare.html',
      landingDefaultBadge: 'CLINICAL & PATIENT EHR',
      landingLaunchHtml: '<span>Live Demo</span><svg class="w-4 h-4" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14"/><path d="m12 5 7 7-7 7"/></svg>',
      dashLaunchHtml: 'Launch Healthcare Portal →',
      dashEnabledClass: 'w-full py-2.5 px-3 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-mono font-bold text-xs text-center block transition-all shadow-[0_2px_12px_rgba(5,150,105,0.25)]',
      landingEnabledClass: 'w-full py-3.5 px-4 rounded-xl text-xs font-heading font-bold text-black uppercase bg-emerald-400 hover:bg-emerald-300 shadow-[0_0_20px_rgba(16,185,129,0.5)] transition-all flex items-center justify-center gap-2 cursor-pointer',
    },
  };

  Object.keys(portalMeta).forEach((pKey) => {
    const meta = portalMeta[pKey];
    const pState = portals[pKey] || { locked: false, status: 'AVAILABLE', grant_active: false };
    const isLocked = Boolean(pState.locked);
    const secRef = pState.lock && pState.lock.security_reference_id ? pState.lock.security_reference_id : 'LOCKED';

    ['dash', 'landing'].forEach((scope) => {
      const card = document.getElementById(`${scope}-card-${pKey}`);
      const badge = document.getElementById(`${scope}-status-${pKey}`);
      const btn = document.getElementById(`${scope}-launch-${pKey}`);

      if (card) {
        card.classList.toggle('border-red-600', isLocked);
      }

      if (badge) {
        if (isLocked) {
          badge.className = 'px-2.5 py-0.5 rounded-full text-[9px] font-mono font-bold bg-red-950 text-red-300 border border-red-600 uppercase tracking-wider';
          badge.textContent = `⛔ SUSPENDED (${secRef})`;
        } else if (scope === 'dash') {
          const authBadge = pState.grant_active ? 'AUTHORIZED' : 'AVAILABLE';
          badge.className = pState.grant_active
            ? 'px-2 py-0.5 rounded text-[9px] bg-emerald-950/90 text-emerald-300 border border-emerald-700 font-bold uppercase tracking-wider'
            : 'px-2 py-0.5 rounded text-[9px] bg-slate-900/90 text-slate-300 border border-slate-700 font-bold uppercase tracking-wider';
          badge.textContent = authBadge;
        } else {
          badge.className = pKey === 'shopping'
            ? 'px-3 py-1 rounded-full text-[10px] font-mono font-bold border border-amber-500/50 text-amber-400 bg-amber-950/40 uppercase tracking-wider'
            : pKey === 'college'
              ? 'px-3 py-1 rounded-full text-[10px] font-mono font-bold border border-sky-500/50 text-sky-400 bg-sky-950/40 uppercase tracking-wider'
              : 'px-3 py-1 rounded-full text-[10px] font-mono font-bold border border-emerald-500/50 text-emerald-400 bg-emerald-950/40 uppercase tracking-wider';
          badge.textContent = pState.grant_active ? `${meta.landingDefaultBadge} • ACTIVE` : meta.landingDefaultBadge;
        }
      }

      if (btn) {
        if (isLocked) {
          btn.setAttribute('aria-disabled', 'true');
          btn.setAttribute('data-locked-portal', pKey);
          btn.removeAttribute('href');
          btn.className = scope === 'dash'
            ? 'w-full py-2.5 px-3 rounded-lg bg-red-950/80 border border-red-700 text-red-300 font-mono font-bold text-xs text-center block cursor-not-allowed opacity-85'
            : 'w-full py-3.5 px-4 rounded-xl text-xs font-heading font-bold text-red-200 uppercase bg-red-950/90 border border-red-600 cursor-not-allowed flex items-center justify-center gap-2 opacity-90';
          btn.innerHTML = '<span>⛔ SUSPENDED — RECOVERY REQUIRED</span>';
          btn.onclick = (e) => {
            e.preventDefault();
            e.stopPropagation();
            if (typeof window.showNotificationToast === 'function') {
              window.showNotificationToast(
                'Portal Access Suspended',
                `${pState.portal_display_name || pKey.toUpperCase()} is suspended (${secRef}). Administrator recovery is required before re-entry.`,
                '⛔'
              );
            }
            return false;
          };
        } else {
          btn.removeAttribute('aria-disabled');
          btn.removeAttribute('data-locked-portal');
          btn.setAttribute('href', meta.href);
          btn.className = scope === 'dash' ? meta.dashEnabledClass : meta.landingEnabledClass;
          btn.innerHTML = scope === 'dash' ? meta.dashLaunchHtml : meta.landingLaunchHtml;
          btn.onclick = null;
        }
      }
    });
  });

  const buildBannerHtml = (scope) => (locks.length > 0 ? locks.map((lk) => {
    const pName = esc(lk.portal_display_name || String(lk.portal || '').toUpperCase());
    const pKey = esc(lk.portal || 'platform');
    const secRef = esc(lk.security_reference_id || 'SEC-LOCK-ACTIVE');
    const reason = esc(lk.lock_reason || 'Maximum unsuccessful verification attempts exceeded.');
    const recStat = lk.recovery_status === 'OTP_VERIFIED_AWAITING_ADMIN'
      ? 'OTP VERIFIED — AWAITING SECURITY ADMIN CLEARANCE'
      : (lk.recovery_status === 'REJECTED_BY_ADMIN'
        ? 'RECOVERY REJECTED BY SECURITY ADMIN — REMAINS SUSPENDED'
        : 'PENDING SECURITY ADMINISTRATOR RECOVERY');
    const recClass = lk.recovery_status === 'OTP_VERIFIED_AWAITING_ADMIN'
      ? 'text-emerald-300'
      : (lk.recovery_status === 'REJECTED_BY_ADMIN' ? 'text-red-300' : 'text-amber-300');
    const instr = esc(
      lk.recovery_instructions ||
      '1. Verify your registered-email Recovery OTP below if prompted. 2. Contact your Security Administrator / SOC referencing your Security Reference ID to authorize clearance. 3. After clearance, complete fresh 20-second observation and Email OTP.'
    );
    const fb = window.cognisec?._recoveryBannerFeedbackByPortal?.[lk.portal || pKey] || null;
    const fbText = fb ? esc(fb.text || '') : '';
    const fbClass = fb
      ? (fb.ok ? 'text-emerald-300 font-semibold' : 'text-red-300 font-semibold')
      : 'text-slate-300';
    return `
      <div class="space-y-2.5 border-b border-red-900/50 last:border-b-0 pb-3 last:pb-0" data-lock-portal="${pKey}" data-sec-ref="${secRef}">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <div class="flex items-center gap-2">
            <span class="px-2 py-0.5 rounded bg-red-600 text-white text-[10px] font-bold uppercase tracking-wider">⛔ PORTAL SUSPENDED</span>
            <strong class="text-white text-xs sm:text-sm">${pName}</strong>
          </div>
          <span class="text-[11px] font-bold text-red-300">Ref: ${secRef}</span>
        </div>
        <p class="text-red-100 font-sans text-xs leading-relaxed">
          Access to <strong>${pName}</strong> has been suspended (${reason}). Your authenticated global COGNISEC-AI identity and non-suspended portals remain active on this dashboard.
        </p>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-2 p-2.5 rounded-lg bg-black/60 border border-red-900/60 text-[11px]">
          <div><span class="text-slate-400">Recovery Status:</span> <strong class="${recClass}">${esc(recStat)}</strong></div>
          <div><span class="text-slate-400">Admin Gate:</span> <strong class="text-red-300">SOC Clearance Required (No Client Unlock)</strong></div>
        </div>
        <p class="text-[11px] text-slate-300 font-sans leading-relaxed"><strong class="text-slate-200">Recovery Instructions:</strong> ${instr}</p>
        <div class="flex flex-wrap items-center gap-2 pt-1">
          <button type="button" onclick="window.requestDashboardRecoveryOtp('${pKey}', '${scope}', this)" class="px-2.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 text-[11px] font-bold cursor-pointer">
            Send Recovery OTP Pre-Check
          </button>
          <input id="rec-otp-${scope}-${pKey}" data-rec-portal="${pKey}" type="text" inputmode="numeric" maxlength="6" placeholder="6-digit Recovery OTP" class="px-2.5 py-1.5 rounded-lg bg-black/80 border border-slate-700 text-white text-[11px] w-40 focus:outline-none focus:border-red-500">
          <button type="button" onclick="window.verifyDashboardRecoveryOtp('${pKey}', '${scope}', this)" class="px-2.5 py-1.5 rounded-lg bg-amber-900/80 hover:bg-amber-800 border border-amber-700 text-amber-100 text-[11px] font-bold cursor-pointer">
            Verify Recovery OTP
          </button>
          <span id="rec-msg-${scope}-${pKey}" class="text-[11px] ${fbClass}">${fbText}</span>
        </div>
      </div>
    `;
  }).join('') : '');

  [
    { id: 'dashboard-portal-suspension-banner', scope: 'dash' },
    { id: 'landing-portal-suspension-banner', scope: 'landing' },
  ].forEach(({ id, scope }) => {
    const el = document.getElementById(id);
    if (!el) return;
    const prevInp = locks.reduce((acc, lk) => {
      const pKey = lk.portal || 'platform';
      const existing = document.getElementById(`rec-otp-${scope}-${pKey}`);
      if (existing && existing.value) acc[pKey] = existing.value;
      return acc;
    }, {});
    const html = buildBannerHtml(scope);
    if (html) {
      el.innerHTML = html;
      el.classList.remove('hidden');
      Object.entries(prevInp).forEach(([pKey, val]) => {
        const restored = document.getElementById(`rec-otp-${scope}-${pKey}`);
        if (restored) restored.value = val;
      });
    } else {
      el.innerHTML = '';
      el.classList.add('hidden');
    }
  });
};

window.requestDashboardRecoveryOtp = async function(portal, scopeOrBtn = 'dash', maybeBtn = null) {
  if (!window.cognisec || !window.cognisec.token) return;
  let scope = 'dash';
  let btnEl = maybeBtn;
  if (typeof scopeOrBtn === 'string') {
    scope = scopeOrBtn || 'dash';
  } else if (scopeOrBtn && typeof scopeOrBtn === 'object') {
    btnEl = scopeOrBtn;
  }
  const msgEl = document.getElementById(`rec-msg-${scope}-${portal}`) || document.getElementById(`dash-rec-msg-${portal}`);
  const activeLk = (window.cognisec._portalLocksSummary?.active_locks || []).find((l) => l.portal === portal);
  const secRef = activeLk?.security_reference_id || null;
  if (btnEl) { btnEl.disabled = true; btnEl.textContent = 'Sending...'; }
  try {
    const res = await fetch(`${COGNISEC_API_BASE}/security/portal-lock/recovery-otp/request`, {
      method: 'POST',
      headers: window.cognisec.getHeaders(),
      body: JSON.stringify({ application: portal, security_reference_id: secRef })
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok && data.challenge_id) {
      window.cognisec._activeDashRecoveryChalMap = window.cognisec._activeDashRecoveryChalMap || {};
      window.cognisec._activeDashRecoveryChalMap[portal] = data.challenge_id;
      window.cognisec._activeDashRecoveryChalId = data.challenge_id;
    }
    const text = window.cognisec._extractErrorDetail(data, data.message || (res.ok ? 'Recovery OTP dispatched.' : 'Failed to send OTP.'));
    window.cognisec._recoveryBannerFeedbackByPortal = window.cognisec._recoveryBannerFeedbackByPortal || {};
    window.cognisec._recoveryBannerFeedbackByPortal[portal] = { ok: res.ok, text };
    if (msgEl) {
      msgEl.className = `text-[11px] font-semibold ${res.ok ? 'text-emerald-300' : 'text-red-300'}`;
      msgEl.textContent = text;
    }
  } catch (e) {
    const errText = e.message || 'Network error.';
    if (msgEl) {
      msgEl.className = 'text-[11px] font-semibold text-red-300';
      msgEl.textContent = errText;
    }
  } finally {
    if (btnEl) { btnEl.disabled = false; btnEl.textContent = 'Send Recovery OTP Pre-Check'; }
  }
};

window.verifyDashboardRecoveryOtp = async function(portal, scopeOrBtn = 'dash', maybeBtn = null) {
  if (!window.cognisec || !window.cognisec.token) return;
  let scope = 'dash';
  let btnEl = maybeBtn;
  if (typeof scopeOrBtn === 'string') {
    scope = scopeOrBtn || 'dash';
  } else if (scopeOrBtn && typeof scopeOrBtn === 'object') {
    btnEl = scopeOrBtn;
  }
  const inp = document.getElementById(`rec-otp-${scope}-${portal}`) || document.getElementById(`dash-rec-otp-${portal}`);
  const msgEl = document.getElementById(`rec-msg-${scope}-${portal}`) || document.getElementById(`dash-rec-msg-${portal}`);
  const code = inp ? inp.value.replace(/\s+/g, '').trim() : '';
  if (!code) {
    if (msgEl) {
      msgEl.className = 'text-[11px] font-semibold text-red-300';
      msgEl.textContent = 'Enter the 6-digit Recovery OTP first.';
    }
    if (inp) inp.focus();
    return;
  }
  const activeLk = (window.cognisec._portalLocksSummary?.active_locks || []).find((l) => l.portal === portal);
  const secRef = activeLk?.security_reference_id || null;
  const chalId = (window.cognisec._activeDashRecoveryChalMap && window.cognisec._activeDashRecoveryChalMap[portal])
    || window.cognisec._activeDashRecoveryChalId
    || null;
  if (btnEl) { btnEl.disabled = true; btnEl.textContent = 'Verifying...'; }
  try {
    const res = await fetch(`${COGNISEC_API_BASE}/security/portal-lock/recovery-otp/verify`, {
      method: 'POST',
      headers: window.cognisec.getHeaders(),
      body: JSON.stringify({
        application: portal,
        otp_code: code,
        challenge_id: chalId,
        security_reference_id: secRef
      })
    });
    const data = await res.json().catch(() => ({}));
    const text = window.cognisec._extractErrorDetail(data, data.message || (res.ok ? 'Recovery OTP verified. Portal remains suspended pending Admin clearance.' : 'Invalid recovery OTP.'));
    window.cognisec._recoveryBannerFeedbackByPortal = window.cognisec._recoveryBannerFeedbackByPortal || {};
    window.cognisec._recoveryBannerFeedbackByPortal[portal] = { ok: res.ok, text };
    if (msgEl) {
      msgEl.className = `text-[11px] font-semibold ${res.ok ? 'text-emerald-300' : 'text-red-300'}`;
      msgEl.textContent = text;
    }
    if (res.ok) {
      if (window.cognisec._activeDashRecoveryChalMap) {
        delete window.cognisec._activeDashRecoveryChalMap[portal];
      }
      if (inp) inp.value = '';
      await window.refreshDashboardPortalLocks();
    }
  } catch (e) {
    const errText = e.message || 'Network error.';
    if (msgEl) {
      msgEl.className = 'text-[11px] font-semibold text-red-300';
      msgEl.textContent = errText;
    }
  } finally {
    if (btnEl) { btnEl.disabled = false; btnEl.textContent = 'Verify Recovery OTP'; }
  }
};

window.refreshDashboardPortalLocks = async function() {
  if (!window.cognisec || !window.cognisec.isAuthenticated()) {
    window.renderDashboardPortalLocks(null);
    return null;
  }
  if (_portalLocksRefreshInFlight) return window.cognisec._portalLocksSummary || null;
  _portalLocksRefreshInFlight = true;
  try {
    window.renderDashboardPortalLocks(window.cognisec._portalLocksSummary || null);
    const summary = await window.cognisec.getPortalLocksSummary();
    window.renderDashboardPortalLocks(summary);
    return summary;
  } finally {
    _portalLocksRefreshInFlight = false;
  }
};

window.addEventListener('cognisec:portal_locks_updated', (ev) => {
  if (typeof window.renderDashboardPortalLocks === 'function') {
    window.renderDashboardPortalLocks(ev.detail || null);
  }
});

window.addEventListener('cognisec:auth_change', () => {
  if (typeof window.syncAuthStateUI === 'function') {
    window.syncAuthStateUI();
  }
});

document.addEventListener('DOMContentLoaded', async () => {
  try {
    const params = new URLSearchParams(window.location.search || '');
    const ejectedPortal = params.get('portal_ejected');
    if (typeof window.syncAuthStateUI === 'function') {
      window.syncAuthStateUI();
    }
    if (ejectedPortal) {
      if (window.cognisec && window.cognisec.isAuthenticated()) {
        await window.refreshDashboardPortalLocks();
        if (!window.cognisec.isAdmin() && typeof window.openModal === 'function') {
          window.openModal('liveDemo');
        }
        const secRef = params.get('sec_ref') || '';
        if (typeof window.showNotificationToast === 'function') {
          window.showNotificationToast(
            'Portal Access Suspended',
            `Access to ${ejectedPortal.toUpperCase()} portal was suspended${secRef ? ` (${secRef})` : ''}. Your global session remains active.`,
            '⛔'
          );
        }
      }
      if (window.history && typeof window.history.replaceState === 'function') {
        const cleanUrl = window.location.pathname + (window.location.hash || '');
        window.history.replaceState({}, document.title, cleanUrl);
      }
    } else if (window.cognisec && window.cognisec.isAuthenticated()) {
      await window.refreshDashboardPortalLocks();
    }
  } catch (e) {
    console.warn('[COGNISEC-AI] Dashboard portal lock sync notice:', e);
  }
});

// ============================================================================
// INTERACTIVE USER PROFILE INVESTIGATION DASHBOARD (SOC ADMIN ONLY)
// ============================================================================
window._userInvState = {
  userId: null,
  section: 'overview',
  page: 1,
  pageSize: 15,
  totalPages: 1,
  liveTimer: null,
  liveSessionFilter: 'ALL',
};

window._stopUserLivePolling = function() {
  if (window._userInvState.liveTimer) {
    clearInterval(window._userInvState.liveTimer);
    window._userInvState.liveTimer = null;
  }
};

window._startUserLivePolling = function() {
  window._stopUserLivePolling();
  window._userInvState.liveTimer = setInterval(() => {
    const modal = document.getElementById('modal-soc-user-investigation');
    if (!modal || modal.classList.contains('hidden') || window._userInvState.section !== 'live' || !window._userInvState.userId) {
      window._stopUserLivePolling();
      return;
    }
    window.renderUserLiveActivitySection(window._userInvState.userId, true);
  }, 4000);
};

window._formatInvLocation = function(loc, locSource) {
  if (!loc) return 'Not recorded';
  const src = String(locSource || '').toUpperCase();
  if (src === 'GPS') return `${loc} (Device-provided)`;
  if (src === 'IP_APPROXIMATE') return `${loc} (Approximate IP)`;
  return loc;
};

window.closeSocUserInvestigation = function() {
  window._stopUserLivePolling();
  document.getElementById('modal-soc-user-investigation')?.classList.add('hidden');
  window._userInvState.userId = null;
};

window.onUserInvFilterChange = function() {
  window._userInvState.page = 1;
  window.refreshSocUserInvestigationSection();
};

window.changeUserInvPage = function(delta) {
  const next = window._userInvState.page + delta;
  if (next >= 1 && next <= window._userInvState.totalPages) {
    window._userInvState.page = next;
    window.refreshSocUserInvestigationSection();
  }
};

window.openSocUserInvestigation = async function(userId) {
  if (!userId) return;
  window._userInvState.userId = userId;
  window._userInvState.section = 'overview';
  window._userInvState.page = 1;

  const sEl = document.getElementById('ui-inv-search');
  const pEl = document.getElementById('ui-inv-portal');
  const dfEl = document.getElementById('ui-inv-date-from');
  const dtEl = document.getElementById('ui-inv-date-to');
  if (sEl) sEl.value = '';
  if (pEl) pEl.value = 'ALL';
  if (dfEl) dfEl.value = '';
  if (dtEl) dtEl.value = '';

  const modal = document.getElementById('modal-soc-user-investigation');
  if (modal) modal.classList.remove('hidden');

  await window.switchUserInvestigationSection('overview');
};

window.switchUserInvestigationSection = async function(section) {
  window._stopUserLivePolling();
  window._userInvState.section = section;
  window._userInvState.page = 1;

  const sections = ['overview', 'logins', 'devices', 'portal', 'behavioral', 'security', 'sessions', 'live'];
  sections.forEach(s => {
    const btn = document.getElementById(`ui-nav-${s}`);
    if (btn) {
      btn.className = s === section
        ? 'px-3.5 py-2.5 rounded-xl text-left text-xs sm:text-sm font-semibold bg-red-600 text-white cursor-pointer shrink-0'
        : (s === 'live'
          ? 'px-3.5 py-2.5 rounded-xl text-left text-xs sm:text-sm font-semibold text-emerald-300 hover:bg-red-950/40 hover:text-white cursor-pointer shrink-0 border border-emerald-900/50'
          : 'px-3.5 py-2.5 rounded-xl text-left text-xs sm:text-sm font-semibold text-slate-300 hover:bg-red-950/40 hover:text-white cursor-pointer shrink-0');
    }
  });

  const filterBar = document.getElementById('ui-inv-filter-bar');
  if (filterBar) {
    filterBar.classList.toggle('hidden', section === 'overview' || section === 'devices' || section === 'live');
  }

  await window.refreshSocUserInvestigationSection();
  if (section === 'live') {
    window._startUserLivePolling();
  }
};

window._applyInvClientFilters = function(rows, getTs, getPortal, getHaystack) {
  const search = (document.getElementById('ui-inv-search')?.value || '').trim().toLowerCase();
  const portal = (document.getElementById('ui-inv-portal')?.value || 'ALL').toLowerCase();
  const dateFrom = document.getElementById('ui-inv-date-from')?.value || '';
  const dateTo = document.getElementById('ui-inv-date-to')?.value || '';

  return (rows || []).filter(r => {
    if (portal !== 'all' && (getPortal(r) || 'platform').toLowerCase() !== portal) return false;
    const tsRaw = getTs(r);
    if (dateFrom && tsRaw && tsRaw.slice(0, 10) < dateFrom) return false;
    if (dateTo && tsRaw && tsRaw.slice(0, 10) > dateTo) return false;
    if (search && !String(getHaystack(r) || '').toLowerCase().includes(search)) return false;
    return true;
  });
};

window._paginateInvRows = function(rows) {
  const ps = window._userInvState.pageSize || 15;
  const total = rows.length;
  const totalPages = Math.max(1, Math.ceil(total / ps));
  window._userInvState.totalPages = totalPages;
  const safePage = Math.min(window._userInvState.page, totalPages);
  window._userInvState.page = safePage;
  const start = (safePage - 1) * ps;

  const pagEl = document.getElementById('ui-inv-pagination');
  const infoEl = document.getElementById('ui-inv-page-info');
  const prevBtn = document.getElementById('ui-inv-prev-btn');
  const nextBtn = document.getElementById('ui-inv-next-btn');
  if (pagEl) pagEl.classList.toggle('hidden', total === 0);
  if (infoEl) infoEl.textContent = `Page ${safePage} of ${totalPages} (${total} records)`;
  if (prevBtn) prevBtn.disabled = safePage <= 1;
  if (nextBtn) nextBtn.disabled = safePage >= totalPages;

  return rows.slice(start, start + ps);
};

window.refreshSocUserInvestigationSection = async function() {
  const uid = window._userInvState.userId;
  const sec = window._userInvState.section || 'overview';
  const contentEl = document.getElementById('ui-inv-content');
  const pagEl = document.getElementById('ui-inv-pagination');
  if (!uid || !contentEl || !window.cognisec) return;

  if (pagEl) pagEl.classList.add('hidden');
  if (sec === 'live') {
    await window.renderUserLiveActivitySection(uid, false);
    return;
  }
  contentEl.innerHTML = `<div class="p-10 text-center text-slate-300 text-sm">Loading ${escapeHtml(sec)} from PostgreSQL...</div>`;

  try {
    const details = await window.cognisec.fetchSocUserDetails(uid);
    const u = details.user || {};

    // Update persistent header identity
    const nameEl = document.getElementById('ui-inv-name');
    const emailEl = document.getElementById('ui-inv-email');
    const regEl = document.getElementById('ui-inv-reg-date');
    const stBadge = document.getElementById('ui-inv-status-badge');
    const verBadge = document.getElementById('ui-inv-verified-badge');
    if (nameEl) nameEl.textContent = u.name || 'Not recorded';
    if (emailEl) emailEl.textContent = u.email || 'Not recorded';
    if (regEl) regEl.textContent = `Registered: ${u.created_at ? formatSocTimestamp(u.created_at) : 'Not recorded'}`;
    if (stBadge) {
      const isAct = u.account_status === 'ACTIVE';
      stBadge.textContent = u.account_status || 'UNKNOWN';
      stBadge.className = `px-2.5 py-0.5 rounded-md text-xs font-semibold border ${isAct ? 'border-emerald-800 bg-emerald-950 text-emerald-300' : 'border-red-800 bg-red-950 text-red-300'}`;
    }
    if (verBadge) {
      verBadge.textContent = u.email_verified ? 'Email Verified' : 'Email Unverified';
      verBadge.className = `px-2.5 py-0.5 rounded-md text-xs font-semibold border ${u.email_verified ? 'border-emerald-800 bg-emerald-950/70 text-emerald-300' : 'border-slate-700 bg-slate-900 text-slate-400'}`;
    }

    if (sec === 'overview') {
      contentEl.innerHTML = `
        <div class="p-6 rounded-2xl bg-black/60 border border-red-900/50 space-y-5">
          <h4 class="font-heading font-bold text-lg text-white border-b border-red-950 pb-3">1. Account Overview</h4>
          <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 text-xs font-mono">
            <div class="p-3.5 rounded-xl bg-black/70 border border-slate-800"><span class="text-slate-400 block">Full Name</span><strong class="text-white text-sm mt-1 block">${escapeHtml(u.name || 'Not recorded')}</strong></div>
            <div class="p-3.5 rounded-xl bg-black/70 border border-slate-800"><span class="text-slate-400 block">Registered Email</span><strong class="text-sky-300 text-sm mt-1 block">${escapeHtml(u.email || 'Not recorded')}</strong></div>
            <div class="p-3.5 rounded-xl bg-black/70 border border-slate-800"><span class="text-slate-400 block">Role &amp; Account Status</span><strong class="text-white text-sm mt-1 block">${escapeHtml(u.role || 'USER')} · ${escapeHtml(u.account_status || 'Not recorded')}</strong></div>
            <div class="p-3.5 rounded-xl bg-black/70 border border-slate-800"><span class="text-slate-400 block">Registration Date</span><strong class="text-slate-200 text-sm mt-1 block">${u.created_at ? formatSocTimestamp(u.created_at) : 'Not recorded'}</strong></div>
            <div class="p-3.5 rounded-xl bg-black/70 border border-slate-800"><span class="text-slate-400 block">Email Verification</span><strong class="${u.email_verified ? 'text-emerald-400' : 'text-amber-300'} text-sm mt-1 block">${u.email_verified ? 'Verified' : 'Unverified'}${u.email_verified_at ? ' · ' + formatSocTimestamp(u.email_verified_at) : ''}</strong></div>
            <div class="p-3.5 rounded-xl bg-black/70 border border-slate-800"><span class="text-slate-400 block">Total Logins &amp; Last Login</span><strong class="text-white text-sm mt-1 block">${u.total_sessions_count ?? 0} logins · ${u.last_login ? formatSocTimestamp(u.last_login) : 'Not recorded'}</strong></div>
            <div class="p-3.5 rounded-xl bg-black/70 border border-slate-800"><span class="text-slate-400 block">Current Active Sessions</span><strong class="${(u.active_sessions_count || 0) > 0 ? 'text-emerald-400' : 'text-slate-300'} text-sm mt-1 block">${u.active_sessions_count ?? 0} active</strong></div>
            <div class="p-3.5 rounded-xl bg-black/70 border border-slate-800"><span class="text-slate-400 block">Registered Devices</span><strong class="text-white text-sm mt-1 block">${(details.devices || []).length} devices</strong></div>
            <div class="p-3.5 rounded-xl bg-black/70 border border-slate-800"><span class="text-slate-400 block">Last Known Location</span><strong class="text-slate-200 text-sm mt-1 block">${escapeHtml(u.last_location || 'Not recorded')}</strong></div>
          </div>
        </div>
      `;
      return;
    }

    if (sec === 'logins') {
      const filtered = window._applyInvClientFilters(
        details.login_history || [],
        r => r.timestamp,
        r => r.application,
        r => `${r.result} ${r.application} ${r.device_name} ${r.browser} ${r.os} ${r.ip_address} ${r.location} ${r.session_id}`
      );
      const paged = window._paginateInvRows(filtered);
      if (paged.length === 0) {
        contentEl.innerHTML = `<div class="p-8 rounded-2xl bg-black/60 border border-red-950 text-center text-slate-400 text-sm">No login records found for this user under the current filters.</div>`;
        return;
      }
      const rowsHtml = paged.map(l => {
        const dt = l.timestamp ? new Date(l.timestamp) : null;
        const dStr = dt && !isNaN(dt) ? dt.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) : 'Not recorded';
        const tStr = dt && !isNaN(dt) ? dt.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : 'Not recorded';
        const isOk = l.result === 'Successful';
        return `
          <tr class="hover:bg-red-950/15 text-xs">
            <td class="py-2.5 px-3 font-mono text-slate-200 whitespace-nowrap">${escapeHtml(dStr)}</td>
            <td class="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap">${escapeHtml(tStr)}</td>
            <td class="py-2.5 px-3 whitespace-nowrap"><span class="px-2 py-0.5 rounded font-semibold border ${isOk ? 'bg-emerald-950 text-emerald-300 border-emerald-800' : 'bg-red-950 text-red-300 border-red-800'}">${escapeHtml(l.result)}</span></td>
            <td class="py-2.5 px-3 text-slate-200">${escapeHtml(formatSocPortalName(l.application))}</td>
            <td class="py-2.5 px-3 text-slate-200">${escapeHtml(l.device_name || 'Not recorded')}</td>
            <td class="py-2.5 px-3 text-slate-300">${escapeHtml(l.browser || 'Not recorded')} · ${escapeHtml(l.os || 'Not recorded')}</td>
            <td class="py-2.5 px-3 font-mono text-slate-300">${escapeHtml(l.ip_address || 'Not recorded')}</td>
            <td class="py-2.5 px-3 text-slate-300">${escapeHtml(window._formatInvLocation(l.location, l.location_source))}</td>
          </tr>
        `;
      }).join('');
      contentEl.innerHTML = `
        <div class="p-5 rounded-2xl bg-black/60 border border-red-900/50 space-y-3">
          <h4 class="font-heading font-bold text-base text-white">2. Login History (${filtered.length} matching)</h4>
          <div class="overflow-x-auto"><table class="w-full text-left border-collapse"><thead><tr class="border-b border-red-950 text-slate-300 text-[11px] uppercase"><th class="py-2 px-3">Date</th><th class="py-2 px-3">Time</th><th class="py-2 px-3">Outcome</th><th class="py-2 px-3">Portal</th><th class="py-2 px-3">Device</th><th class="py-2 px-3">Browser &amp; OS</th><th class="py-2 px-3">IP Address</th><th class="py-2 px-3">Location</th></tr></thead><tbody class="divide-y divide-red-950/40">${rowsHtml}</tbody></table></div>
        </div>
      `;
      return;
    }

    if (sec === 'devices') {
      const devs = details.devices || [];
      if (devs.length === 0) {
        contentEl.innerHTML = `<div class="p-8 rounded-2xl bg-black/60 border border-red-950 text-center text-slate-400 text-sm">No registered devices recorded for this user.</div>`;
        return;
      }
      contentEl.innerHTML = `
        <div class="p-5 rounded-2xl bg-black/60 border border-red-900/50 space-y-4">
          <h4 class="font-heading font-bold text-base text-white">3. Device History (${devs.length})</h4>
          <div class="grid grid-cols-1 lg:grid-cols-2 gap-3">
            ${devs.map(dev => `
              <div class="p-4 rounded-xl bg-black/75 border border-slate-800 space-y-2 text-xs">
                <div class="flex items-center justify-between gap-2">
                  <strong class="text-white text-sm">${escapeHtml(dev.nickname || 'Registered Device')}</strong>
                  <span class="px-2 py-0.5 rounded font-semibold border ${dev.is_trusted ? 'bg-emerald-950 text-emerald-300 border-emerald-800' : 'bg-amber-950 text-amber-200 border-amber-800'}">${escapeHtml(dev.trust_state || 'UNKNOWN')}</span>
                </div>
                <div class="grid grid-cols-2 gap-2 text-slate-300 font-mono">
                  <div><span class="text-slate-500 block">Fingerprint</span>${escapeHtml(dev.masked_fingerprint || 'Not recorded')}</div>
                  <div><span class="text-slate-500 block">Browser &amp; OS</span>${escapeHtml(dev.browser || 'Not recorded')} · ${escapeHtml(dev.os || 'Not recorded')}</div>
                  <div><span class="text-slate-500 block">First Seen</span>${dev.first_seen ? formatSocTimestamp(dev.first_seen) : 'Not recorded'}</div>
                  <div><span class="text-slate-500 block">Last Seen · Sessions</span>${dev.last_seen ? formatSocTimestamp(dev.last_seen) : 'Not recorded'} · ${dev.session_count ?? 0}</div>
                </div>
                <div class="text-slate-400">Type: <span class="text-slate-200">${escapeHtml(dev.device_type || 'Not recorded')}</span> · Location: <span class="text-slate-200">${escapeHtml(window._formatInvLocation(dev.location, dev.location_source))}</span></div>
              </div>
            `).join('')}
          </div>
        </div>
      `;
      return;
    }

    if (sec === 'portal') {
      const filtered = window._applyInvClientFilters(
        details.portal_activity || [],
        r => r.timestamp,
        r => r.application,
        r => `${r.action_label} ${r.description} ${r.application} ${r.session_id} ${r.outcome}`
      );
      const paged = window._paginateInvRows(filtered);
      if (paged.length === 0) {
        contentEl.innerHTML = `<div class="p-8 rounded-2xl bg-black/60 border border-red-950 text-center text-slate-400 text-sm">No portal activity recorded for this user under the current filters.</div>`;
        return;
      }
      contentEl.innerHTML = `
        <div class="p-5 rounded-2xl bg-black/60 border border-red-900/50 space-y-3">
          <h4 class="font-heading font-bold text-base text-white">4. Portal Activity (${filtered.length} matching)</h4>
          <div class="space-y-2">
            ${paged.map(pa => `
              <div class="p-3 rounded-xl bg-black/70 border border-red-950/70 flex flex-wrap items-center justify-between gap-2 text-xs">
                <div>
                  <span class="font-mono text-slate-400 mr-2">${formatSocTimestamp(pa.timestamp)}</span>
                  <span class="px-2 py-0.5 rounded bg-black border border-slate-800 text-slate-200 mr-2">${escapeHtml(formatSocPortalName(pa.application))}</span>
                  <strong class="text-white">${escapeHtml(pa.action_label)}</strong>
                  <span class="text-slate-400 ml-1.5">· ${escapeHtml(pa.description || 'Not recorded')}</span>
                  ${pa.session_id ? `<span class="text-slate-500 font-mono ml-2">[${escapeHtml(pa.session_id.slice(0, 14))}…]</span>` : ''}
                </div>
                <span class="px-2 py-0.5 rounded border border-slate-700 bg-slate-900 text-slate-200 font-semibold">${escapeHtml(pa.outcome || pa.decision || 'Recorded')}</span>
              </div>
            `).join('')}
          </div>
        </div>
      `;
      return;
    }

    if (sec === 'behavioral') {
      const bp = window.cognisec.fetchAdminUserBehaviorProfile
        ? await window.cognisec.fetchAdminUserBehaviorProfile(uid)
        : null;
      const bpMeans = bp?.baseline_features?.means || {};
      const bpStds = bp?.baseline_features?.stds || {};
      const fKeys = Object.keys(bpMeans);
      const behavEvents = (details.recent_events || []).filter(ev => {
        const et = String(ev.event_type || '').toUpperCase();
        return et.includes('BEHAVIOR') || et.includes('RISK') || et.includes('STEP_UP') || et.includes('OTP') || et.includes('BASELINE') || et.includes('COGNITIVE');
      });
      const filtered = window._applyInvClientFilters(
        behavEvents,
        r => r.timestamp,
        r => r.application,
        r => `${r.event_type} ${r.action_label} ${r.details} ${r.session_id} ${r.severity}`
      );
      const paged = window._paginateInvRows(filtered);
      const latestRisk = bp?.latest_risk_level || details?.user?.last_known_risk || details?.sessions?.[0]?.current_risk_level || (behavEvents[0]?.severity) || 'Not recorded';
      const bpM2 = bp?.baseline_features?.m2 || {};
      const anomDisplay = bp && (bp.ml_status === 'ML_READY' || Number(bp.anomaly_score || 0) > 0)
        ? Number(bp.anomaly_score || 0).toFixed(3)
        : 'Not recorded';
      contentEl.innerHTML = `
        <div class="p-5 rounded-2xl bg-black/60 border border-red-900/50 space-y-4">
          <h4 class="font-heading font-bold text-base text-white">5. Behavioral Security &amp; Adaptive Verification</h4>
          ${bp ? `
            <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
              <div class="p-3 rounded-xl bg-black/75 border border-slate-800"><span class="text-slate-400 block">Profile Readiness</span><strong class="text-white">${escapeHtml(bp.baseline_status)} (${bp.sample_count} samples)</strong></div>
              <div class="p-3 rounded-xl bg-black/75 border border-slate-800"><span class="text-slate-400 block">ML Model Status</span><strong class="text-sky-300">${escapeHtml(bp.ml_status)} (${Number(bp.model_sample_count || 0)} fitted)</strong></div>
              <div class="p-3 rounded-xl bg-black/75 border border-slate-800"><span class="text-slate-400 block">Anomaly Score</span><strong class="${bp.is_anomaly ? 'text-red-400' : 'text-emerald-400'}">${anomDisplay}</strong></div>
              <div class="p-3 rounded-xl bg-black/75 border border-slate-800"><span class="text-slate-400 block">Latest Risk</span><strong class="text-amber-300">${escapeHtml(latestRisk)}</strong></div>
            </div>
            <div class="grid grid-cols-2 sm:grid-cols-5 gap-2 text-xs font-mono">
              ${fKeys.length > 0 ? fKeys.map(k => {
                const meanVal = Number(bpMeans[k] ?? 0);
                const stdVal = Number(bpStds[k] ?? 0);
                const m2Val = Number(bpM2[k] ?? 0);
                const valText = (meanVal === 0 && m2Val === 0)
                  ? '<span class="text-slate-400 font-normal">Unavailable (awaiting signal)</span>'
                  : `${meanVal.toFixed(2)} ± ${stdVal.toFixed(2)}`;
                return `<div class="p-2 rounded-lg bg-black/70 border border-slate-800"><span class="text-slate-400 text-[10px] block truncate">${escapeHtml(k)}</span><strong class="text-slate-100">${valText}</strong></div>`;
              }).join('') : `<div class="col-span-full text-slate-400">Welford 10-D baseline not yet established.</div>`}
            </div>
          ` : `<div class="text-slate-400 text-xs">Behavioral profile unavailable.</div>`}
          <div class="space-y-2 pt-2 border-t border-red-950/60">
            <h5 class="text-xs font-bold uppercase text-slate-300">Risk, Anomaly &amp; Step-Up Events (${filtered.length})</h5>
            ${paged.length > 0 ? paged.map(ev => `
              <div class="p-3 rounded-xl bg-black/70 border border-slate-800 flex flex-wrap items-center justify-between gap-2 text-xs">
                <div>
                  <span class="font-mono text-slate-400 mr-2">${formatSocTimestamp(ev.timestamp)}</span>
                  <strong class="text-white">${escapeHtml(ev.action_label || ev.event_type)}</strong>
                  <span class="text-slate-400 ml-1.5">(${escapeHtml(formatSocPortalName(ev.application))}) · ${escapeHtml(ev.details || '')}</span>
                </div>
                <span class="px-2 py-0.5 rounded font-mono bg-slate-900 border border-slate-700 text-slate-200">${escapeHtml(ev.severity || 'LOW')} · ${escapeHtml(ev.outcome || ev.decision || 'Recorded')}</span>
              </div>
            `).join('') : `<div class="p-6 text-center text-slate-400 text-xs">No behavioral or step-up events match the current filters.</div>`}
          </div>
        </div>
      `;
      return;
    }

    if (sec === 'security') {
      const search = document.getElementById('ui-inv-search')?.value?.trim() || '';
      const portal = document.getElementById('ui-inv-portal')?.value || 'ALL';
      const dateFrom = document.getElementById('ui-inv-date-from')?.value || '';
      const dateTo = document.getElementById('ui-inv-date-to')?.value || '';
      const res = await window.cognisec.fetchSocAuditTrail({
        user_id: uid,
        activity_scope: 'user',
        search,
        application: portal,
        date_from: dateFrom,
        date_to: dateTo,
        page: window._userInvState.page,
        page_size: window._userInvState.pageSize,
      });
      const items = res.items || [];
      window._userInvState.totalPages = res.total_pages || 1;
      const pagEl2 = document.getElementById('ui-inv-pagination');
      const infoEl = document.getElementById('ui-inv-page-info');
      const prevBtn = document.getElementById('ui-inv-prev-btn');
      const nextBtn = document.getElementById('ui-inv-next-btn');
      if (pagEl2) pagEl2.classList.toggle('hidden', (res.total || 0) === 0);
      if (infoEl) infoEl.textContent = `Page ${res.page || 1} of ${res.total_pages || 1} (${res.total || 0} events)`;
      if (prevBtn) prevBtn.disabled = (res.page || 1) <= 1;
      if (nextBtn) nextBtn.disabled = (res.page || 1) >= (res.total_pages || 1);

      if (items.length === 0) {
        contentEl.innerHTML = `<div class="p-8 rounded-2xl bg-black/60 border border-red-950 text-center text-slate-400 text-sm">No security events recorded for this user under the current filters.</div>`;
        return;
      }
      contentEl.innerHTML = `
        <div class="p-5 rounded-2xl bg-black/60 border border-red-900/50 space-y-3">
          <h4 class="font-heading font-bold text-base text-white">6. Security Events (${res.total || 0} total)</h4>
          <div class="space-y-2">
            ${items.map(ev => `
              <div class="p-3 rounded-xl bg-black/70 border border-slate-800 flex flex-wrap items-center justify-between gap-2 text-xs">
                <div>
                  <span class="font-mono text-slate-400 mr-2">${formatSocTimestamp(ev.timestamp)}</span>
                  <span class="px-2 py-0.5 rounded bg-black border border-slate-800 text-slate-200 mr-2">${escapeHtml(formatSocPortalName(ev.application))}</span>
                  <strong class="text-white">${escapeHtml(ev.action_label)}</strong>
                  <span class="text-slate-400 ml-1.5">· ${escapeHtml(ev.summary || '')}</span>
                  ${ev.session_id ? `<span class="text-slate-500 font-mono ml-2">[${escapeHtml(ev.session_id.slice(0, 14))}…]</span>` : ''}
                </div>
                <span class="px-2 py-0.5 rounded font-mono ${ev.risk_level === 'CRITICAL' || ev.risk_level === 'HIGH' ? 'bg-red-950 text-red-300 border border-red-800' : 'bg-slate-900 text-slate-300 border border-slate-700'}">${escapeHtml(ev.risk_level || 'LOW')} · ${escapeHtml(ev.result)}</span>
              </div>
            `).join('')}
          </div>
        </div>
      `;
      return;
    }

    if (sec === 'sessions') {
      const filtered = window._applyInvClientFilters(
        details.sessions || [],
        r => r.login_time,
        r => r.application,
        r => `${r.id} ${r.application} ${r.status} ${r.device_name} ${r.termination_reason} ${r.ip_address}`
      );
      const paged = window._paginateInvRows(filtered);
      if (paged.length === 0) {
        contentEl.innerHTML = `<div class="p-8 rounded-2xl bg-black/60 border border-red-950 text-center text-slate-400 text-sm">No sessions recorded for this user under the current filters.</div>`;
        return;
      }
      const rowsHtml = paged.map(s => `
        <tr class="hover:bg-red-950/15 text-xs">
          <td class="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap">${escapeHtml(s.id ? s.id.slice(0, 16) + '…' : 'Not recorded')}</td>
          <td class="py-2.5 px-3 text-slate-200">${escapeHtml(formatSocPortalName(s.application))}</td>
          <td class="py-2.5 px-3 text-slate-200">${escapeHtml(s.device_name || 'Not recorded')}</td>
          <td class="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap">${s.login_time ? formatSocTimestamp(s.login_time) : 'Not recorded'}</td>
          <td class="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap">${s.logout_time ? formatSocTimestamp(s.logout_time) : 'Not recorded'}</td>
          <td class="py-2.5 px-3"><span class="px-2 py-0.5 rounded border border-slate-700 bg-slate-900 text-slate-200 font-semibold">${escapeHtml(s.status)}</span></td>
          <td class="py-2.5 px-3 text-slate-300">${escapeHtml(s.termination_reason || 'Not recorded')}</td>
        </tr>
      `).join('');
      contentEl.innerHTML = `
        <div class="p-5 rounded-2xl bg-black/60 border border-red-900/50 space-y-3">
          <h4 class="font-heading font-bold text-base text-white">7. Session History (${filtered.length} matching)</h4>
          <div class="overflow-x-auto"><table class="w-full text-left border-collapse"><thead><tr class="border-b border-red-950 text-slate-300 text-[11px] uppercase"><th class="py-2 px-3">Session ID</th><th class="py-2 px-3">Portal</th><th class="py-2 px-3">Device</th><th class="py-2 px-3">Login Time</th><th class="py-2 px-3">Logout Time</th><th class="py-2 px-3">Status</th><th class="py-2 px-3">Termination / Outcome</th></tr></thead><tbody class="divide-y divide-red-950/40">${rowsHtml}</tbody></table></div>
        </div>
      `;
    }
  } catch (err) {
    contentEl.innerHTML = `<div class="p-8 rounded-2xl bg-black/60 border border-red-900 text-center text-red-400 text-sm">Failed to load user investigation data: ${escapeHtml(err.message)}</div>`;
  }
};

window.openIntelUserFullHistory = function(userId) {
  return window.openSocUserInvestigation(userId);
};
window.openUserActivityProfile = function(userId) {
  return window.openSocUserInvestigation(userId);
};

// =========================================================================
// AGENTIC AI EXECUTION & INVESTIGATION CENTER (FULL-SCREEN DASHBOARD)
// =========================================================================
window._agenticInvState = {
  section: 'overview',
  page: 1,
  pageSize: 20,
  totalPages: 1,
  selectedAgentKey: 'SecurityContextAgent',
  selectedExecutionId: null,
  data: null,
};

function _agStatusBadge(status) {
  const s = String(status || 'UNKNOWN').toUpperCase();
  if (s === 'SUCCESS' || s === 'CONNECTED' || s === 'ENFORCED' || s === 'PERMITTED') {
    return `<span class="px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-950/70 text-emerald-300 border border-emerald-800/70">${escapeHtml(s)}</span>`;
  }
  if (s === 'FALLBACK' || s === 'UNVERIFIED' || s === 'CHALLENGED') {
    return `<span class="px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-950/70 text-amber-300 border border-amber-800/70">${escapeHtml(s)}</span>`;
  }
  if (s === 'TIMEOUT' || s === 'FAILED' || s === 'ERROR' || s === 'CONTAINED') {
    return `<span class="px-2 py-0.5 rounded text-[11px] font-semibold bg-red-950/70 text-red-300 border border-red-800/70">${escapeHtml(s)}</span>`;
  }
  return `<span class="px-2 py-0.5 rounded text-[11px] font-semibold bg-slate-900 text-slate-300 border border-slate-700">${escapeHtml(s)}</span>`;
}

window.openAgenticInvestigationDashboard = async function() {
  if (!window.cognisec || !window.cognisec.isAdmin()) return;
  const modal = document.getElementById('modal-agentic-investigation');
  if (!modal) return;
  modal.classList.remove('hidden');
  window._agenticInvState.section = 'overview';
  window._agenticInvState.page = 1;
  window._agenticInvState.selectedExecutionId = null;
  await window.switchAgenticInvSection('overview');
};

window.closeAgenticInvestigationDashboard = function() {
  const modal = document.getElementById('modal-agentic-investigation');
  if (modal) modal.classList.add('hidden');
};

window.switchAgenticInvSection = async function(section) {
  window._agenticInvState.section = section || 'overview';
  window._agenticInvState.selectedExecutionId = null;

  document.querySelectorAll('.ag-inv-nav').forEach(btn => {
    const isSel = btn.id === `ag-nav-${window._agenticInvState.section}`;
    btn.className = isSel
      ? 'ag-inv-nav w-full text-left px-3.5 py-2.5 rounded-xl text-sm font-semibold bg-red-600 text-white cursor-pointer'
      : 'ag-inv-nav w-full text-left px-3.5 py-2.5 rounded-xl text-sm font-medium text-slate-300 hover:bg-red-950/40 cursor-pointer';
  });

  await window.refreshAgenticInvestigation();
};

window.onAgenticInvFilterChange = function() {
  window._agenticInvState.page = 1;
  window._agenticInvState.selectedExecutionId = null;
  window.refreshAgenticInvestigation();
};

window.changeAgenticInvPage = function(delta) {
  const next = (window._agenticInvState.page || 1) + delta;
  if (next < 1 || next > (window._agenticInvState.totalPages || 1)) return;
  window._agenticInvState.page = next;
  window.refreshAgenticInvestigation();
};

window.selectAgenticDetailAgent = function(agentKey) {
  window._agenticInvState.selectedAgentKey = agentKey;
  window.renderAgenticInvSection();
};

window.closeAgenticExecutionDetail = function() {
  window._agenticInvState.selectedExecutionId = null;
  window.renderAgenticInvSection();
};

window.openAgenticExecutionDetail = async function(executionId) {
  const contentEl = document.getElementById('ag-inv-content');
  const pagEl = document.getElementById('ag-inv-pagination');
  if (!contentEl) return;
  if (pagEl) pagEl.classList.add('hidden');
  window._agenticInvState.selectedExecutionId = executionId;
  contentEl.innerHTML = `<div class="p-8 rounded-2xl bg-black/60 border border-red-900/50 text-center text-slate-300 text-sm">Loading execution investigation dossier...</div>`;
  try {
    const det = await window.cognisec.fetchAgenticExecutionDetail(executionId);
    const risk = det.risk_assessment || {};
    const rec = det.agent_recommendation || {};
    const arb = det.arbiter_decision || {};
    const errs = Array.isArray(det.errors_or_fallbacks) ? det.errors_or_fallbacks : [];
    const inpSummary = det.input_summary
      ? JSON.stringify(det.input_summary, null, 2)
      : 'Historical data not available (input summary was not persisted for this record).';
    const sanOut = det.sanitized_outputs && Object.keys(det.sanitized_outputs).length
      ? JSON.stringify(det.sanitized_outputs, null, 2)
      : 'Historical data not available.';

    contentEl.innerHTML = `
      <div class="p-5 sm:p-6 rounded-2xl bg-black/70 border border-red-900/60 space-y-5">
        <div class="flex flex-wrap items-center justify-between gap-3 border-b border-red-950/70 pb-4">
          <div class="space-y-1">
            <button type="button" onclick="window.closeAgenticExecutionDetail()" class="text-xs text-red-300 hover:text-white underline cursor-pointer mb-1">← Back to ${escapeHtml(window._agenticInvState.section)} view</button>
            <h3 class="font-heading font-bold text-lg text-white">Execution Investigation: <span class="font-mono text-sky-300">${escapeHtml(det.execution_id)}</span></h3>
            <p class="text-xs text-slate-400">Trigger: <strong class="text-slate-200">${escapeHtml(det.trigger_event)}</strong> &bull; Portal: <strong class="text-slate-200">${escapeHtml(formatSocPortalName(det.portal))}</strong> &bull; Timestamp: <span class="font-mono">${det.timestamp ? formatSocTimestamp(det.timestamp) : 'Historical data not available'}</span></p>
          </div>
          <div class="flex items-center gap-2">
            ${_agStatusBadge(det.status)}
            <span class="px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-700 text-xs font-mono text-slate-200">${det.processing_time_ms !== null && det.processing_time_ms !== undefined ? `${det.processing_time_ms} ms` : 'Duration not recorded'}</span>
          </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
          <div class="p-3.5 rounded-xl bg-black/70 border border-slate-800 space-y-1">
            <span class="text-slate-400 uppercase text-[10px] block">Risk Assessment</span>
            <div class="text-slate-200">Deterministic: <strong class="text-white">${escapeHtml(risk.deterministic_risk_level || '—')}</strong> (${risk.deterministic_risk_score !== null && risk.deterministic_risk_score !== undefined ? Number(risk.deterministic_risk_score).toFixed(3) : '—'})</div>
            <div class="text-slate-400">Arbiter Effective: <strong class="text-amber-300">${escapeHtml(risk.arbiter_risk_level || '—')}</strong> (${risk.arbiter_risk_score !== null && risk.arbiter_risk_score !== undefined ? Number(risk.arbiter_risk_score).toFixed(3) : '—'})</div>
          </div>
          <div class="p-3.5 rounded-xl bg-black/70 border border-slate-800 space-y-1">
            <span class="text-slate-400 uppercase text-[10px] block">Agent Recommendation</span>
            <div class="text-slate-200">Recommended Level: <strong class="text-sky-300">${escapeHtml(rec.recommended_risk_level || 'Historical data not available')}</strong></div>
            <div class="text-slate-400">Factor: <strong class="font-mono text-purple-300">${escapeHtml(rec.recommended_factor || 'None')}</strong> &bull; Threat: ${escapeHtml(rec.threat_category || 'Not recorded')}</div>
          </div>
          <div class="p-3.5 rounded-xl bg-black/70 border border-slate-800 space-y-1">
            <span class="text-slate-400 uppercase text-[10px] block">Deterministic Arbiter &amp; Final Action</span>
            <div class="text-slate-200">Final Action: <strong class="text-emerald-300">${escapeHtml(det.final_action || 'PERMITTED')}</strong></div>
            <div class="text-slate-400">Escalation Accepted: <strong>${arb.is_agent_accepted === true ? 'Yes' : (arb.is_agent_accepted === false ? 'Overridden / Clamped' : 'Not recorded')}</strong></div>
          </div>
        </div>

        <details open class="p-4 rounded-xl bg-black/60 border border-slate-800 space-y-2">
          <summary class="text-sm font-semibold text-white cursor-pointer">Sanitized Agent Output &amp; Arbiter Rationale</summary>
          <p class="text-xs text-slate-300 mt-2">${escapeHtml(det.result_summary || 'Historical data not available')}</p>
          ${arb.override_reason ? `<div class="text-xs text-amber-300">Arbiter Note: ${escapeHtml(arb.override_reason)}</div>` : ''}
          <pre class="mt-2 p-3 rounded-lg bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap">${escapeHtml(sanOut)}</pre>
        </details>

        <details class="p-4 rounded-xl bg-black/60 border border-slate-800 space-y-2">
          <summary class="text-sm font-semibold text-white cursor-pointer">Agent Input Summary (Sanitized)</summary>
          <pre class="mt-2 p-3 rounded-lg bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap">${escapeHtml(inpSummary)}</pre>
        </details>

        <details ${errs.length ? 'open' : ''} class="p-4 rounded-xl bg-black/60 border border-slate-800 space-y-2">
          <summary class="text-sm font-semibold text-white cursor-pointer">Errors &amp; Deterministic Fallbacks (${errs.length})</summary>
          ${errs.length
            ? errs.map(e => `<div class="mt-2 p-2.5 rounded-lg bg-red-950/40 border border-red-900/60 text-xs text-red-200"><strong>${escapeHtml(e.agent || 'Agent')}:</strong> ${escapeHtml(e.error || 'Fallback used')}</div>`).join('')
            : `<p class="mt-2 text-xs text-slate-400">No errors or fallbacks recorded for this execution.</p>`}
        </details>
      </div>
    `;
  } catch (err) {
    contentEl.innerHTML = `<div class="p-8 rounded-2xl bg-black/60 border border-red-900 text-center text-red-400 text-sm">Failed to load execution detail: ${escapeHtml(err.message)}</div>`;
  }
};

window.refreshAgenticInvestigation = async function() {
  const contentEl = document.getElementById('ag-inv-content');
  if (!contentEl || !window.cognisec) return;
  contentEl.innerHTML = `<div class="p-8 rounded-2xl bg-black/60 border border-red-900/50 text-center text-slate-300 text-sm">Loading persisted agentic execution records...</div>`;

  try {
    const data = await window.cognisec.fetchAgenticInvestigation({
      search: document.getElementById('ag-inv-search')?.value.trim() || '',
      agent: document.getElementById('ag-inv-agent')?.value || 'ALL',
      status: document.getElementById('ag-inv-status')?.value || 'ALL',
      date_from: document.getElementById('ag-inv-date-from')?.value || '',
      date_to: document.getElementById('ag-inv-date-to')?.value || '',
      page: window._agenticInvState.page || 1,
      page_size: window._agenticInvState.pageSize || 20,
    });
    window._agenticInvState.data = data;
    window._agenticInvState.totalPages = data?.pagination?.total_pages || 1;
    window.renderAgenticInvSection();
  } catch (err) {
    contentEl.innerHTML = `<div class="p-8 rounded-2xl bg-black/60 border border-red-900 text-center text-red-400 text-sm">Failed to load Agentic AI Investigation data: ${escapeHtml(err.message)}</div>`;
  }
};

window.renderAgenticInvSection = function() {
  const contentEl = document.getElementById('ag-inv-content');
  const pagEl = document.getElementById('ag-inv-pagination');
  const pageInfo = document.getElementById('ag-inv-page-info');
  const prevBtn = document.getElementById('ag-inv-prev-btn');
  const nextBtn = document.getElementById('ag-inv-next-btn');
  const data = window._agenticInvState.data;
  if (!contentEl || !data) return;

  const section = window._agenticInvState.section || 'overview';
  if (pagEl) pagEl.classList.add('hidden');

  if (section === 'overview') {
    const ov = data.overview || {};
    const llm = data.llm_activity || {};
    const agents = data.five_agents || [];
    const pipeStatus = ov.pipeline_status || 'UNAVAILABLE';
    const pipeCls = pipeStatus === 'OPERATIONAL'
      ? 'bg-emerald-950/70 text-emerald-300 border-emerald-800/70'
      : (pipeStatus === 'PARTIALLY_OPERATIONAL' ? 'bg-amber-950/70 text-amber-300 border-amber-800/70' : 'bg-red-950/70 text-red-300 border-red-800/70');

    const agentPills = agents.map(a => `
      <div class="p-3 rounded-xl bg-black/70 border border-slate-800 flex items-center justify-between gap-2 text-xs">
        <div class="min-w-0">
          <div class="font-semibold text-white truncate">${escapeHtml(a.name)}</div>
          <div class="text-[11px] text-slate-400">Runs: <strong class="text-slate-200">${Number(a.execution_count || 0)}</strong> &bull; OK: <strong class="text-emerald-300">${Number(a.successful_count || 0)}</strong></div>
        </div>
        ${_agStatusBadge(a.lifecycle_state || 'IMPLEMENTED')}
      </div>
    `).join('');

    contentEl.innerHTML = `
      <div class="p-5 rounded-2xl bg-black/60 border border-red-900/50 space-y-5">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <div class="flex items-center gap-2.5 flex-wrap">
            <h4 class="font-heading font-bold text-base text-white">1. Agentic AI Overview</h4>
            <span class="px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold border ${pipeCls}">Pipeline: ${escapeHtml(pipeStatus.replace(/_/g, ' '))}</span>
          </div>
          <span class="text-xs text-slate-400 font-mono">Last Successful Execution: ${ov.last_successful_execution_timestamp ? formatSocTimestamp(ov.last_successful_execution_timestamp) : 'No recorded executions'}</span>
        </div>

        <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
          <div class="p-3.5 rounded-xl bg-black/70 border border-slate-800"><span class="text-slate-400 uppercase text-[10px] block">Genuine Orchestrations</span><strong class="text-2xl font-bold text-white">${Number(ov.total_executions || 0)}</strong></div>
          <div class="p-3.5 rounded-xl bg-black/70 border border-emerald-900/60"><span class="text-slate-400 uppercase text-[10px] block">Successful Executions</span><strong class="text-2xl font-bold text-emerald-400">${Number(ov.successful_executions || 0)}</strong></div>
          <div class="p-3.5 rounded-xl bg-black/70 border border-red-900/60"><span class="text-slate-400 uppercase text-[10px] block">Failed / Timed-Out</span><strong class="text-2xl font-bold text-red-400">${Number(ov.failed_executions || 0)} / ${Number(ov.timed_out_executions || 0)}</strong></div>
          <div class="p-3.5 rounded-xl bg-black/70 border border-amber-900/60"><span class="text-slate-400 uppercase text-[10px] block">Deterministic Fallbacks</span><strong class="text-2xl font-bold text-amber-300">${Number(ov.deterministic_fallbacks || 0)}</strong></div>
          <div class="p-3.5 rounded-xl bg-black/70 border border-slate-800"><span class="text-slate-400 uppercase text-[10px] block">Gemini Provider Health</span><strong class="text-sm font-mono text-white">${escapeHtml(String(llm.provider || 'mock').toUpperCase())} (${escapeHtml((llm.connectivity_status === 'VERIFIED' || llm.connectivity_status === 'CONNECTED') ? 'Connected' : 'Unverified')})</strong></div>
          <div class="p-3.5 rounded-xl bg-black/70 border border-slate-800"><span class="text-slate-400 uppercase text-[10px] block">Average Duration</span><strong class="text-lg font-bold text-sky-300 font-mono">${ov.avg_execution_time_ms !== null && ov.avg_execution_time_ms !== undefined ? `${ov.avg_execution_time_ms} ms` : 'Not recorded'}</strong></div>
          <div class="p-3.5 rounded-xl bg-black/70 border border-slate-800 sm:col-span-2"><span class="text-slate-400 uppercase text-[10px] block">Last Execution Recorded</span><strong class="text-xs font-mono text-slate-200">${ov.last_execution_timestamp ? formatSocTimestamp(ov.last_execution_timestamp) : 'No recorded executions'}</strong></div>
        </div>

        <div class="space-y-2">
          <div class="text-xs font-semibold uppercase text-slate-400">Five-Agent Pipeline Status</div>
          <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2.5">${agentPills}</div>
        </div>
      </div>
    `;
    return;
  }

  if (section === 'executions') {
    const execs = data.executions || [];
    const pag = data.pagination || { page: 1, total_pages: 1, total: 0 };
    if (pagEl && pag.total > 0) {
      pagEl.classList.remove('hidden');
      if (pageInfo) pageInfo.textContent = `Page ${pag.page} of ${pag.total_pages} (${pag.total} executions)`;
      if (prevBtn) prevBtn.disabled = pag.page <= 1;
      if (nextBtn) nextBtn.disabled = pag.page >= pag.total_pages;
    }
    const rowsHtml = execs.length ? execs.map(r => {
      const invokedText = (r.agents_executed && r.agents_executed.length)
        ? r.agents_executed.join(', ')
        : 'No individual agents recorded (orchestration timed out)';
      return `
        <tr onclick="window.openAgenticExecutionDetail('${escapeHtml(r.execution_id)}')" class="hover:bg-red-950/30 cursor-pointer transition-colors text-xs">
          <td class="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap">${r.timestamp ? formatSocTimestamp(r.timestamp) : 'Not recorded'}</td>
          <td class="py-2.5 px-3 text-slate-200">${escapeHtml(r.trigger_event)}</td>
          <td class="py-2.5 px-3 text-white font-semibold">${escapeHtml(invokedText)}</td>
          <td class="py-2.5 px-3 font-mono text-slate-300">${escapeHtml(r.user_email || (r.user_id ? `User #${r.user_id}` : 'Not recorded'))}${r.session_id ? `<div class="text-[10px] text-slate-500">${escapeHtml(r.session_id)}</div>` : ''}</td>
          <td class="py-2.5 px-3 text-slate-200">${escapeHtml(formatSocPortalName(r.portal))}</td>
          <td class="py-2.5 px-3">${_agStatusBadge(r.status)}</td>
          <td class="py-2.5 px-3 font-mono text-sky-300">${r.processing_time_ms !== null && r.processing_time_ms !== undefined ? `${r.processing_time_ms} ms` : 'Not recorded'}</td>
          <td class="py-2.5 px-3 text-slate-300 max-w-xs truncate">${escapeHtml(r.result_summary || 'Not recorded')}</td>
        </tr>
      `;
    }).join('') : `<tr><td colspan="8" class="py-8 text-center text-slate-400 text-xs">No recorded executions match the current filters.</td></tr>`;

    contentEl.innerHTML = `
      <div class="p-5 rounded-2xl bg-black/60 border border-red-900/50 space-y-3">
        <div class="flex items-center justify-between">
          <h4 class="font-heading font-bold text-base text-white">2. Agent Execution History (${pag.total || 0})</h4>
          <span class="text-xs text-slate-400">Click any row to open full execution details</span>
        </div>
        <div class="overflow-x-auto"><table class="w-full text-left border-collapse"><thead><tr class="border-b border-red-950 text-slate-300 text-[11px] uppercase"><th class="py-2 px-3">Timestamp</th><th class="py-2 px-3">Triggering Event</th><th class="py-2 px-3">Agents Invoked</th><th class="py-2 px-3">User / Session</th><th class="py-2 px-3">Portal</th><th class="py-2 px-3">Status</th><th class="py-2 px-3">Duration</th><th class="py-2 px-3">Final Result</th></tr></thead><tbody class="divide-y divide-red-950/40">${rowsHtml}</tbody></table></div>
      </div>
    `;
    return;
  }

  if (section === 'agents') {
    const agents = data.five_agents || [];
    const selKey = window._agenticInvState.selectedAgentKey || (agents[0]?.agent_key || 'SecurityContextAgent');
    const sel = agents.find(a => a.agent_key === selKey) || agents[0];
    const tabsHtml = agents.map(a => `
      <button type="button" onclick="window.selectAgenticDetailAgent('${escapeHtml(a.agent_key)}')" class="p-3 rounded-xl border text-left cursor-pointer transition-all ${a.agent_key === sel?.agent_key ? 'bg-red-950/50 border-red-600 text-white' : 'bg-black/60 border-slate-800 text-slate-300 hover:border-red-900'}">
        <div class="font-semibold text-xs">${escapeHtml(a.name)}</div>
        <div class="text-[11px] text-slate-400 mt-1 flex items-center justify-between gap-1"><span>Runs: <strong class="text-white">${Number(a.execution_count || 0)}</strong></span> ${_agStatusBadge(a.lifecycle_state || 'IMPLEMENTED')}</div>
      </button>
    `).join('');

    const sumsHtml = sel && sel.output_summaries && sel.output_summaries.length
      ? sel.output_summaries.map(s => `
        <div onclick="window.openAgenticExecutionDetail('${escapeHtml(s.execution_id)}')" class="p-3 rounded-xl bg-black/70 border border-slate-800 hover:border-red-700 cursor-pointer flex items-center justify-between gap-3 text-xs">
          <div class="text-slate-200">${escapeHtml(s.summary)}</div>
          <span class="font-mono text-[11px] text-slate-400 shrink-0">${s.timestamp ? formatSocTimestamp(s.timestamp) : 'Not recorded'}</span>
        </div>
      `).join('')
      : `<div class="p-4 rounded-xl bg-slate-950/80 border border-slate-800 text-xs text-slate-400">No recorded executions for this agent yet.</div>`;

    const errsHtml = sel && sel.errors_and_fallbacks && sel.errors_and_fallbacks.length
      ? sel.errors_and_fallbacks.map(er => `
        <div onclick="window.openAgenticExecutionDetail('${escapeHtml(er.execution_id)}')" class="p-2.5 rounded-lg bg-red-950/30 border border-red-900/60 hover:border-red-600 cursor-pointer text-xs text-red-200 flex items-center justify-between gap-2">
          <span>${escapeHtml(er.error)}</span>
          <span class="font-mono text-[10px] text-slate-400 shrink-0">${er.timestamp ? formatSocTimestamp(er.timestamp) : ''}</span>
        </div>
      `).join('')
      : `<div class="text-xs text-slate-400">No recorded errors or fallbacks for this agent.</div>`;

    contentEl.innerHTML = `
      <div class="p-5 rounded-2xl bg-black/60 border border-red-900/50 space-y-4">
        <h4 class="font-heading font-bold text-base text-white">3. Five Agent Details</h4>
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2.5">${tabsHtml}</div>
        ${sel ? `
          <div class="p-4 rounded-xl bg-black/70 border border-slate-800 space-y-4">
            <div class="flex flex-wrap items-center justify-between gap-2">
              <div><h5 class="font-bold text-white text-sm">${escapeHtml(sel.name)}</h5><p class="text-xs text-slate-400">${escapeHtml(sel.description)}</p></div>
              <div class="flex items-center gap-2">${_agStatusBadge(sel.lifecycle_state || 'IMPLEMENTED')} ${_agStatusBadge(sel.last_status)}</div>
            </div>
            <div class="grid grid-cols-2 sm:grid-cols-5 gap-3 text-xs">
              <div class="p-2.5 rounded-lg bg-slate-950 border border-slate-800"><span class="text-slate-400 text-[10px] uppercase block">Total Runs</span><strong class="text-lg text-white">${Number(sel.execution_count || 0)}</strong></div>
              <div class="p-2.5 rounded-lg bg-slate-950 border border-slate-800"><span class="text-slate-400 text-[10px] uppercase block">Successful</span><strong class="text-lg text-emerald-400">${Number(sel.successful_count || 0)}</strong></div>
              <div class="p-2.5 rounded-lg bg-slate-950 border border-slate-800"><span class="text-slate-400 text-[10px] uppercase block">Fallbacks / Failed</span><strong class="text-lg text-amber-300">${Number(sel.fallback_count || 0)} / ${Number(sel.failed_count || 0)}</strong></div>
              <div class="p-2.5 rounded-lg bg-slate-950 border border-slate-800"><span class="text-slate-400 text-[10px] uppercase block">Avg Duration</span><strong class="text-sm font-mono text-sky-300">${sel.avg_processing_time_ms !== null && sel.avg_processing_time_ms !== undefined ? `${sel.avg_processing_time_ms} ms` : 'Not recorded'}</strong></div>
              <div class="p-2.5 rounded-lg bg-slate-950 border border-slate-800"><span class="text-slate-400 text-[10px] uppercase block">Last Execution</span><strong class="text-xs font-mono text-slate-200">${sel.last_execution ? formatSocTimestamp(sel.last_execution) : 'No recorded executions'}</strong></div>
            </div>
            <div class="space-y-2">
              <div class="text-xs font-semibold uppercase text-slate-400">Recorded Output Summaries (click to inspect)</div>
              ${sumsHtml}
            </div>
            <div class="space-y-2">
              <div class="text-xs font-semibold uppercase text-slate-400">Errors &amp; Fallbacks</div>
              ${errsHtml}
            </div>
          </div>
        ` : ''}
      </div>
    `;
    return;
  }

  if (section === 'decisions') {
    const arbItems = data.decision_arbiter_history || [];
    const respItems = data.security_response_history || [];
    const arbRows = arbItems.length ? arbItems.map(it => {
      const rec = it.agent_recommendation || {};
      const arb = it.arbiter_decision || {};
      const accLabel = it.escalation_accepted === true ? 'Accepted' : (it.escalation_accepted === false ? 'Overridden' : 'Not recorded');
      return `
        <tr onclick="window.openAgenticExecutionDetail('${escapeHtml(it.execution_id)}')" class="hover:bg-red-950/30 cursor-pointer text-xs">
          <td class="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap">${it.timestamp ? formatSocTimestamp(it.timestamp) : 'Not recorded'}</td>
          <td class="py-2.5 px-3 text-slate-200">${escapeHtml(formatSocPortalName(it.portal))} · ${escapeHtml(it.trigger_event)}</td>
          <td class="py-2.5 px-3 font-mono text-white">${escapeHtml(it.deterministic_risk_level || '—')} (${it.deterministic_risk_score !== null && it.deterministic_risk_score !== undefined ? Number(it.deterministic_risk_score).toFixed(2) : '—'})</td>
          <td class="py-2.5 px-3 text-sky-300">${escapeHtml(rec.recommended_risk_level || 'Not recorded')}${rec.recommended_factor ? ` · ${escapeHtml(rec.recommended_factor)}` : ''}</td>
          <td class="py-2.5 px-3 text-amber-300">${escapeHtml(arb.effective_risk_level || '—')} (${accLabel})</td>
          <td class="py-2.5 px-3 font-semibold text-emerald-300">${escapeHtml(it.final_enforcement_outcome || 'PERMITTED')}</td>
        </tr>
      `;
    }).join('') : `<tr><td colspan="6" class="py-6 text-center text-slate-400 text-xs">No recorded arbiter decisions yet.</td></tr>`;

    const respRows = respItems.length ? respItems.map(it => `
      <tr class="text-xs">
        <td class="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap">${it.timestamp ? formatSocTimestamp(it.timestamp) : 'Not recorded'}</td>
        <td class="py-2.5 px-3 font-semibold text-white">${escapeHtml(it.action_type)}</td>
        <td class="py-2.5 px-3"><span class="px-2 py-0.5 rounded text-[10px] font-semibold ${it.origin_type === 'Agent-Triggered' ? 'bg-purple-950/70 text-purple-200 border border-purple-800/70' : 'bg-slate-900 text-slate-300 border border-slate-700'}">${escapeHtml(it.origin_type || 'Deterministic Security Event')}</span></td>
        <td class="py-2.5 px-3 text-slate-200">${escapeHtml(formatSocPortalName(it.portal))}</td>
        <td class="py-2.5 px-3">${_agStatusBadge(it.status)}</td>
        <td class="py-2.5 px-3 text-slate-300 max-w-sm truncate">${escapeHtml(it.summary || 'Not recorded')}</td>
      </tr>
    `).join('') : `<tr><td colspan="6" class="py-6 text-center text-slate-400 text-xs">No recorded security enforcement actions yet.</td></tr>`;

    contentEl.innerHTML = `
      <div class="space-y-5">
        <div class="p-5 rounded-2xl bg-black/60 border border-red-900/50 space-y-3">
          <h4 class="font-heading font-bold text-base text-white">4A. Decision &amp; Arbiter History (${arbItems.length})</h4>
          <div class="overflow-x-auto"><table class="w-full text-left border-collapse"><thead><tr class="border-b border-red-950 text-slate-300 text-[11px] uppercase"><th class="py-2 px-3">Timestamp</th><th class="py-2 px-3">Portal / Trigger</th><th class="py-2 px-3">Deterministic Risk</th><th class="py-2 px-3">Agent Recommendation</th><th class="py-2 px-3">Arbiter Decision</th><th class="py-2 px-3">Final Enforcement</th></tr></thead><tbody class="divide-y divide-red-950/40">${arbRows}</tbody></table></div>
        </div>
        <div class="p-5 rounded-2xl bg-black/60 border border-red-900/50 space-y-3">
          <h4 class="font-heading font-bold text-base text-white">4B. Enforcement Actions (Locks, Terminations, Revocations &amp; Alerts) (${respItems.length})</h4>
          <div class="overflow-x-auto"><table class="w-full text-left border-collapse"><thead><tr class="border-b border-red-950 text-slate-300 text-[11px] uppercase"><th class="py-2 px-3">Timestamp</th><th class="py-2 px-3">Action</th><th class="py-2 px-3">Origin</th><th class="py-2 px-3">Portal</th><th class="py-2 px-3">Status</th><th class="py-2 px-3">Details</th></tr></thead><tbody class="divide-y divide-red-950/40">${respRows}</tbody></table></div>
        </div>
      </div>
    `;
    return;
  }

  if (section === 'llm') {
    const llm = data.llm_activity || {};
    const errs = data.errors_and_fallbacks || [];
    const errRows = errs.length ? errs.map(it => `
      <tr onclick="window.openAgenticExecutionDetail('${escapeHtml(it.execution_id)}')" class="hover:bg-red-950/30 cursor-pointer text-xs">
        <td class="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap">${it.timestamp ? formatSocTimestamp(it.timestamp) : 'Not recorded'}</td>
        <td class="py-2.5 px-3 font-mono text-sky-300">${escapeHtml(it.execution_id)}</td>
        <td class="py-2.5 px-3 text-white font-semibold">${escapeHtml(it.agent_name)}</td>
        <td class="py-2.5 px-3">${_agStatusBadge(it.category)}</td>
        <td class="py-2.5 px-3 text-red-200">${escapeHtml(it.error_message)}</td>
      </tr>
    `).join('') : `<tr><td colspan="5" class="py-6 text-center text-slate-400 text-xs">No recorded agent exceptions, provider failures, timeouts, or fallbacks.</td></tr>`;

    contentEl.innerHTML = `
      <div class="space-y-5">
        <div class="p-5 rounded-2xl bg-black/60 border border-red-900/50 space-y-4">
          <div class="flex flex-wrap items-center justify-between gap-2">
            <h4 class="font-heading font-bold text-base text-white">5A. Gemini Provider &amp; Runtime Activity</h4>
            ${_agStatusBadge((llm.connectivity_status === 'VERIFIED' || llm.connectivity_status === 'CONNECTED') ? 'CONNECTED' : 'UNVERIFIED')}
          </div>
          <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
            <div class="p-3.5 rounded-xl bg-black/70 border border-slate-800"><span class="text-slate-400 uppercase text-[10px] block">Provider &amp; Model</span><strong class="text-sm font-mono text-white">${escapeHtml(String(llm.provider || 'mock').toUpperCase())} / ${escapeHtml(llm.model || '—')}</strong></div>
            <div class="p-3.5 rounded-xl bg-black/70 border border-slate-800"><span class="text-slate-400 uppercase text-[10px] block">Credentials Configured</span><strong class="text-sm font-mono ${llm.credentials_configured ? 'text-emerald-300' : 'text-amber-300'}">${llm.credentials_configured ? 'Yes' : 'No'}</strong></div>
            <div class="p-3.5 rounded-xl bg-black/70 border border-slate-800"><span class="text-slate-400 uppercase text-[10px] block">API Requests / Success / Fail</span><strong class="text-sm font-mono text-white">${Number(llm.api_requests || 0)}</strong> <span class="text-slate-500">/</span> <strong class="text-emerald-300">${Number(llm.successful_requests || 0)}</strong> <span class="text-slate-500">/</span> <strong class="text-red-400">${Number(llm.failed_requests || 0)}</strong></div>
            <div class="p-3.5 rounded-xl bg-black/70 border border-slate-800"><span class="text-slate-400 uppercase text-[10px] block">Response Latency (Last / Avg)</span><strong class="text-sm font-mono text-sky-300">${llm.last_latency_ms !== null && llm.last_latency_ms !== undefined ? `${llm.last_latency_ms} ms` : 'Not recorded'} / ${llm.avg_latency_ms !== null && llm.avg_latency_ms !== undefined ? `${llm.avg_latency_ms} ms` : 'Not recorded'}</strong></div>
            <div class="p-3.5 rounded-xl bg-black/70 border border-slate-800"><span class="text-slate-400 uppercase text-[10px] block">Timeouts / Rate Limits</span><strong class="text-sm font-mono text-amber-300">${Number(llm.timeout_errors || 0)} / ${Number(llm.rate_limit_errors || 0)}</strong></div>
            <div class="p-3.5 rounded-xl bg-black/70 border border-slate-800"><span class="text-slate-400 uppercase text-[10px] block">Fallback Usage</span><strong class="text-xl font-bold text-amber-300">${Number(llm.fallback_usage_count || 0)}</strong></div>
            <div class="p-3.5 rounded-xl bg-black/70 border border-slate-800 sm:col-span-2"><span class="text-slate-400 uppercase text-[10px] block">Last Successful Connection</span><strong class="text-xs font-mono text-slate-200">${llm.last_successful_connection ? formatSocTimestamp(llm.last_successful_connection) : 'Unverified'}</strong></div>
          </div>
          ${llm.last_failure_reason ? `<div class="p-3 rounded-xl bg-red-950/40 border border-red-900/60 text-xs text-red-200">Last Failure (${escapeHtml(llm.last_failure_category || 'ERROR')}): ${escapeHtml(llm.last_failure_reason)}</div>` : ''}
        </div>

        <div class="p-5 rounded-2xl bg-black/60 border border-red-900/50 space-y-3">
          <h4 class="font-heading font-bold text-base text-white">5B. Errors &amp; Deterministic Fallbacks (${errs.length})</h4>
          <div class="overflow-x-auto"><table class="w-full text-left border-collapse"><thead><tr class="border-b border-red-950 text-slate-300 text-[11px] uppercase"><th class="py-2 px-3">Timestamp</th><th class="py-2 px-3">Execution ID</th><th class="py-2 px-3">Agent</th><th class="py-2 px-3">Category</th><th class="py-2 px-3">Error / Fallback Detail</th></tr></thead><tbody class="divide-y divide-red-950/40">${errRows}</tbody></table></div>
        </div>
      </div>
    `;
  }
};


// ============================================================================
// CENTRAL DASHBOARD PORTAL SUSPENSION & ISOLATION CONTROLLER (index.html)
// ============================================================================

_portalLocksRefreshInFlight = false;

window.renderDashboardPortalLocks = function(summary = null) {
  const esc = (s) => (window.cognisec && typeof window.cognisec._escapeHtml === 'function')
    ? window.cognisec._escapeHtml(String(s ?? ''))
    : String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  let pendingNotice = null;
  try {
    const raw = sessionStorage.getItem('cognisec_portal_ejection');
    if (raw) pendingNotice = JSON.parse(raw);
  } catch (_) {}

  const portals = (summary && summary.portals) ? { ...summary.portals } : {};
  let locks = (summary && Array.isArray(summary.locks)) ? [...summary.locks] : [];

  if (summary && locks.length === 0 && pendingNotice) {
    // Backend confirmed no active locks remain (e.g., recovered by admin)
    try { sessionStorage.removeItem('cognisec_portal_ejection'); } catch (_) {}
    pendingNotice = null;
  } else if (!summary && pendingNotice && pendingNotice.portal) {
    const pKey = String(pendingNotice.portal).toLowerCase();
    locks = [pendingNotice.lock || pendingNotice];
    portals[pKey] = {
      portal: pKey,
      portal_display_name: pendingNotice.portal_display_name || pKey.toUpperCase(),
      locked: true,
      status: 'SUSPENDED',
      grant_active: false,
      lock: pendingNotice.lock || pendingNotice,
    };
  }

  const portalMeta = {
    college: {
      href: 'college.html',
      landingDefaultBadge: 'EDUCATION & ACADEMICS',
      landingLaunchHtml: '<span>Live Demo</span><svg class="w-4 h-4" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14"/><path d="m12 5 7 7-7 7"/></svg>',
      dashLaunchHtml: 'Launch Academic Portal →',
      dashEnabledClass: 'w-full py-2.5 px-3 rounded-lg bg-sky-600 hover:bg-sky-500 text-white font-mono font-bold text-xs text-center block transition-all shadow-[0_2px_12px_rgba(2,132,199,0.25)]',
      landingEnabledClass: 'w-full py-3.5 px-4 rounded-xl text-xs font-heading font-bold text-black uppercase bg-sky-400 hover:bg-sky-300 shadow-[0_0_20px_rgba(14,165,233,0.5)] transition-all flex items-center justify-center gap-2 cursor-pointer',
    },
    shopping: {
      href: 'shopping.html',
      landingDefaultBadge: 'E-COMMERCE & RETAIL',
      landingLaunchHtml: '<span>Live Demo</span><svg class="w-4 h-4" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14"/><path d="m12 5 7 7-7 7"/></svg>',
      dashLaunchHtml: 'Launch Shopping Portal →',
      dashEnabledClass: 'w-full py-2.5 px-3 rounded-lg bg-amber-600 hover:bg-amber-500 text-white font-mono font-bold text-xs text-center block transition-all shadow-[0_2px_12px_rgba(217,119,6,0.25)]',
      landingEnabledClass: 'w-full py-3.5 px-4 rounded-xl text-xs font-heading font-bold text-black uppercase bg-amber-500 hover:bg-amber-400 shadow-[0_0_20px_rgba(245,158,11,0.5)] transition-all flex items-center justify-center gap-2 cursor-pointer',
    },
    healthcare: {
      href: 'healthcare.html',
      landingDefaultBadge: 'CLINICAL & PATIENT EHR',
      landingLaunchHtml: '<span>Live Demo</span><svg class="w-4 h-4" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14"/><path d="m12 5 7 7-7 7"/></svg>',
      dashLaunchHtml: 'Launch Healthcare Portal →',
      dashEnabledClass: 'w-full py-2.5 px-3 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-mono font-bold text-xs text-center block transition-all shadow-[0_2px_12px_rgba(5,150,105,0.25)]',
      landingEnabledClass: 'w-full py-3.5 px-4 rounded-xl text-xs font-heading font-bold text-black uppercase bg-emerald-400 hover:bg-emerald-300 shadow-[0_0_20px_rgba(16,185,129,0.5)] transition-all flex items-center justify-center gap-2 cursor-pointer',
    },
  };

  Object.keys(portalMeta).forEach((pKey) => {
    const meta = portalMeta[pKey];
    const pState = portals[pKey] || { locked: false, status: 'AVAILABLE', grant_active: false };
    const isLocked = Boolean(pState.locked);
    const secRef = pState.lock && pState.lock.security_reference_id ? pState.lock.security_reference_id : 'LOCKED';

    ['dash', 'landing'].forEach((scope) => {
      const card = document.getElementById(`${scope}-card-${pKey}`);
      const badge = document.getElementById(`${scope}-status-${pKey}`);
      const btn = document.getElementById(`${scope}-launch-${pKey}`);

      if (card) {
        card.classList.toggle('border-red-600', isLocked);
      }

      if (badge) {
        if (isLocked) {
          badge.className = 'px-2.5 py-0.5 rounded-full text-[9px] font-mono font-bold bg-red-950 text-red-300 border border-red-600 uppercase tracking-wider';
          badge.textContent = `⛔ SUSPENDED (${secRef})`;
        } else if (scope === 'dash') {
          const authBadge = pState.grant_active ? 'AUTHORIZED' : 'AVAILABLE';
          badge.className = pState.grant_active
            ? 'px-2 py-0.5 rounded text-[9px] bg-emerald-950/90 text-emerald-300 border border-emerald-700 font-bold uppercase tracking-wider'
            : 'px-2 py-0.5 rounded text-[9px] bg-slate-900/90 text-slate-300 border border-slate-700 font-bold uppercase tracking-wider';
          badge.textContent = authBadge;
        } else {
          badge.className = pKey === 'shopping'
            ? 'px-3 py-1 rounded-full text-[10px] font-mono font-bold border border-amber-500/50 text-amber-400 bg-amber-950/40 uppercase tracking-wider'
            : pKey === 'college'
              ? 'px-3 py-1 rounded-full text-[10px] font-mono font-bold border border-sky-500/50 text-sky-400 bg-sky-950/40 uppercase tracking-wider'
              : 'px-3 py-1 rounded-full text-[10px] font-mono font-bold border border-emerald-500/50 text-emerald-400 bg-emerald-950/40 uppercase tracking-wider';
          badge.textContent = pState.grant_active ? `${meta.landingDefaultBadge} • ACTIVE` : meta.landingDefaultBadge;
        }
      }

      if (btn) {
        if (isLocked) {
          btn.setAttribute('aria-disabled', 'true');
          btn.setAttribute('data-locked-portal', pKey);
          btn.removeAttribute('href');
          btn.className = scope === 'dash'
            ? 'w-full py-2.5 px-3 rounded-lg bg-red-950/80 border border-red-700 text-red-300 font-mono font-bold text-xs text-center block cursor-not-allowed opacity-85'
            : 'w-full py-3.5 px-4 rounded-xl text-xs font-heading font-bold text-red-200 uppercase bg-red-950/90 border border-red-600 cursor-not-allowed flex items-center justify-center gap-2 opacity-90';
          btn.innerHTML = '<span>⛔ SUSPENDED — RECOVERY REQUIRED</span>';
          btn.onclick = (e) => {
            e.preventDefault();
            e.stopPropagation();
            if (typeof window.showNotificationToast === 'function') {
              window.showNotificationToast(
                'Portal Access Suspended',
                `${pState.portal_display_name || pKey.toUpperCase()} is suspended (${secRef}). Administrator recovery is required before re-entry.`,
                '⛔'
              );
            }
            return false;
          };
        } else {
          btn.removeAttribute('aria-disabled');
          btn.removeAttribute('data-locked-portal');
          btn.setAttribute('href', meta.href);
          btn.className = scope === 'dash' ? meta.dashEnabledClass : meta.landingEnabledClass;
          btn.innerHTML = scope === 'dash' ? meta.dashLaunchHtml : meta.landingLaunchHtml;
          btn.onclick = null;
        }
      }
    });
  });

  const bannerHtml = locks.length > 0 ? locks.map((lk) => {
    const pName = esc(lk.portal_display_name || String(lk.portal || '').toUpperCase());
    const pKey = esc(lk.portal || 'platform');
    const secRef = esc(lk.security_reference_id || 'SEC-LOCK-ACTIVE');
    const reason = esc(lk.lock_reason || 'Maximum unsuccessful verification attempts exceeded.');
    const recStat = lk.recovery_status === 'OTP_VERIFIED_AWAITING_ADMIN'
      ? 'OTP VERIFIED — AWAITING SECURITY ADMIN CLEARANCE'
      : 'PENDING SECURITY ADMINISTRATOR RECOVERY';
    const instr = esc(
      lk.recovery_instructions ||
      '1. Verify your registered-email Recovery OTP below if prompted. 2. Contact your Security Administrator / SOC referencing your Security Reference ID to authorize clearance. 3. After clearance, complete fresh 20-second observation and Email OTP.'
    );
    return `
      <div class="space-y-2.5 border-b border-red-900/50 last:border-b-0 pb-3 last:pb-0">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <div class="flex items-center gap-2">
            <span class="px-2 py-0.5 rounded bg-red-600 text-white text-[10px] font-bold uppercase tracking-wider">⛔ PORTAL SUSPENDED</span>
            <strong class="text-white text-xs sm:text-sm">${pName}</strong>
          </div>
          <span class="text-[11px] font-bold text-red-300">Ref: ${secRef}</span>
        </div>
        <p class="text-red-100 font-sans text-xs leading-relaxed">
          Access to <strong>${pName}</strong> has been suspended (${reason}). Your authenticated global COGNISEC-AI identity and non-suspended portals remain active on this dashboard.
        </p>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-2 p-2.5 rounded-lg bg-black/60 border border-red-900/60 text-[11px]">
          <div><span class="text-slate-400">Recovery Status:</span> <strong class="text-amber-300">${esc(recStat)}</strong></div>
          <div><span class="text-slate-400">Admin Gate:</span> <strong class="text-red-300">SOC Clearance Required (No Client Unlock)</strong></div>
        </div>
        <p class="text-[11px] text-slate-300 font-sans leading-relaxed"><strong class="text-slate-200">Recovery Instructions:</strong> ${instr}</p>
        <div class="flex flex-wrap items-center gap-2 pt-1">
          <button type="button" onclick="window.requestDashboardRecoveryOtp('${pKey}', this)" class="px-2.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 text-[11px] font-bold cursor-pointer">
            Send Recovery OTP Pre-Check
          </button>
          <input id="dash-rec-otp-${pKey}" type="text" inputmode="numeric" maxlength="6" placeholder="6-digit Recovery OTP" class="px-2.5 py-1.5 rounded-lg bg-black/80 border border-slate-700 text-white text-[11px] w-40 focus:outline-none focus:border-red-500">
          <button type="button" onclick="window.verifyDashboardRecoveryOtp('${pKey}')" class="px-2.5 py-1.5 rounded-lg bg-amber-900/80 hover:bg-amber-800 border border-amber-700 text-amber-100 text-[11px] font-bold cursor-pointer">
            Verify Recovery OTP
          </button>
          <span id="dash-rec-msg-${pKey}" class="text-[11px] text-slate-300"></span>
        </div>
      </div>
    `;
  }).join('') : '';

  ['dashboard-portal-suspension-banner', 'landing-portal-suspension-banner'].forEach((id) => {
    const el = document.getElementById(id);
    if (!el) return;
    if (bannerHtml) {
      el.innerHTML = bannerHtml;
      el.classList.remove('hidden');
    } else {
      el.innerHTML = '';
      el.classList.add('hidden');
    }
  });
};

window.requestDashboardRecoveryOtp = async function(portal, btnEl) {
  if (!window.cognisec || !window.cognisec.token) return;
  const msgEl = document.getElementById(`dash-rec-msg-${portal}`);
  if (btnEl) { btnEl.disabled = true; btnEl.textContent = 'Sending...'; }
  try {
    const res = await fetch(`${COGNISEC_API_BASE}/security/portal-lock/recovery-otp/request`, {
      method: 'POST',
      headers: window.cognisec.getHeaders(),
      body: JSON.stringify({ application: portal })
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok && data.challenge_id) {
      window.cognisec._activeDashRecoveryChalId = data.challenge_id;
    }
    if (msgEl) msgEl.textContent = data.message || data.detail || (res.ok ? 'Recovery OTP dispatched.' : 'Failed to send OTP.');
  } catch (e) {
    if (msgEl) msgEl.textContent = e.message || 'Network error.';
  } finally {
    if (btnEl) { btnEl.disabled = false; btnEl.textContent = 'Send Recovery OTP Pre-Check'; }
  }
};

window.verifyDashboardRecoveryOtp = async function(portal) {
  if (!window.cognisec || !window.cognisec.token) return;
  const inp = document.getElementById(`dash-rec-otp-${portal}`);
  const msgEl = document.getElementById(`dash-rec-msg-${portal}`);
  const code = inp ? inp.value.trim() : '';
  if (!code) return;
  try {
    const res = await fetch(`${COGNISEC_API_BASE}/security/portal-lock/recovery-otp/verify`, {
      method: 'POST',
      headers: window.cognisec.getHeaders(),
      body: JSON.stringify({
        application: portal,
        otp_code: code,
        challenge_id: window.cognisec._activeDashRecoveryChalId || null
      })
    });
    const data = await res.json().catch(() => ({}));
    if (msgEl) msgEl.textContent = data.message || data.detail || 'Processed.';
    if (res.ok) {
      await window.refreshDashboardPortalLocks();
    }
  } catch (e) {
    if (msgEl) msgEl.textContent = e.message || 'Network error.';
  }
};

window.refreshDashboardPortalLocks = async function() {
  if (!window.cognisec || !window.cognisec.isAuthenticated()) {
    window.renderDashboardPortalLocks(null);
    return null;
  }
  if (_portalLocksRefreshInFlight) return window.cognisec._portalLocksSummary || null;
  _portalLocksRefreshInFlight = true;
  try {
    window.renderDashboardPortalLocks(window.cognisec._portalLocksSummary || null);
    const summary = await window.cognisec.getPortalLocksSummary();
    window.renderDashboardPortalLocks(summary);
    return summary;
  } finally {
    _portalLocksRefreshInFlight = false;
  }
};

// ============================================================================
// LIVE ACTIVITY & BEHAVIOUR (USER PROFILE NEAR-REAL-TIME MONITORING)
// ============================================================================
window._userLiveFilter = { sessionId: 'ALL', portal: 'ALL' };

window.onUserLiveFilterChange = function() {
  window._userLiveFilter.sessionId = document.getElementById('ui-live-session-select')?.value || 'ALL';
  window._userLiveFilter.portal = document.getElementById('ui-live-portal-select')?.value || 'ALL';
  if (window._userInvState.userId) {
    window.renderUserLiveActivitySection(window._userInvState.userId, false);
  }
};

window.renderUserLiveActivitySection = async function(uid, silentPoll = false) {
  const contentEl = document.getElementById('ui-inv-content');
  if (!contentEl || !window.cognisec?.fetchAdminUserLiveActivity) return;

  if (!silentPoll) {
    contentEl.innerHTML = `<div class="p-10 text-center text-slate-300 text-sm">Loading live activity &amp; behavioural telemetry from PostgreSQL...</div>`;
  }

  try {
    const sessFilter = window._userLiveFilter?.sessionId || 'ALL';
    const portalFilter = window._userLiveFilter?.portal || 'ALL';
    const data = await window.cognisec.fetchAdminUserLiveActivity(uid, {
      session_id: sessFilter,
      application: portalFilter,
      limit: 60,
    });

    if (data.excluded_role) {
      contentEl.innerHTML = `<div class="p-6 rounded-2xl bg-black/60 border border-amber-900/60 text-amber-200 text-sm">Administrator, SYSTEM, and SERVICE accounts are excluded from genuine user activity monitoring.</div>`;
      return;
    }

    const beh = data.behavioral_summary || {};
    const obs = beh.latest_observation || null;
    const bf = beh.baseline_features || {};
    const means = bf.means || {};
    const stds = bf.stds || {};
    const m2 = bf.m2 || {};
    const modMat = beh.modality_maturity || {};
    const ml = beh.ml_status_detail || {};
    const tc = beh.training_counts || {};
    const sessions = data.active_sessions || [];

    // Deduplicate timeline by uid_key while preserving newest-first chronological order
    const seen = new Set();
    const timeline = [];
    for (const item of (data.timeline || [])) {
      const k = item.uid_key || `${item.timestamp}_${item.event_type}`;
      if (!seen.has(k)) {
        seen.add(k);
        timeline.push(item);
      }
    }

    const dims = [
      ['typing_speed_wpm', 'Typing Speed (WPM)'],
      ['avg_flight_time_ms', 'Avg Flight Time (ms)'],
      ['avg_dwell_time_ms', 'Avg Dwell Time (ms)'],
      ['mouse_velocity_avg', 'Mouse Velocity (px/s)'],
      ['mouse_acceleration_avg', 'Mouse Accel (px/s²)'],
      ['mouse_curvature_entropy', 'Curvature Entropy'],
      ['click_frequency', 'Click Frequency (/s)'],
      ['scroll_speed_avg', 'Scroll Speed (px/s)'],
      ['idle_duration_sec', 'Idle Duration (s)'],
      ['navigation_entropy', 'Navigation Entropy'],
    ];

    const dimCardsHtml = dims.map(([k, label]) => {
      const liveVal = obs ? obs[k] : null;
      const meanVal = Number(means[k] ?? 0);
      const stdVal = Number(stds[k] ?? 0);
      const m2Val = Number(m2[k] ?? 0);
      const hasLive = liveVal !== null && liveVal !== undefined && Number.isFinite(Number(liveVal));
      const hasBase = !(meanVal === 0 && m2Val === 0);
      return `
        <div class="p-2.5 rounded-xl bg-black/70 border border-slate-800 space-y-1">
          <span class="text-[10px] text-slate-400 uppercase block truncate">${escapeHtml(label)}</span>
          <strong class="text-sm font-mono ${hasLive ? 'text-white' : 'text-slate-500'}">${hasLive ? Number(liveVal).toFixed(2) : 'No signal'}</strong>
          <div class="text-[10px] font-mono text-slate-400">${hasBase ? `Baseline: ${meanVal.toFixed(2)} ± ${stdVal.toFixed(2)}` : 'Baseline: Insufficient data'}</div>
        </div>
      `;
    }).join('');

    const sessOpts = [`<option value="ALL">All Sessions (${sessions.length})</option>`].concat(
      sessions.map(s => `<option value="${escapeHtml(s.id)}" ${sessFilter === s.id ? 'selected' : ''}>${escapeHtml(s.short_id)} · ${escapeHtml(formatSocPortalName(s.application))} (${escapeHtml(s.status)})</option>`)
    ).join('');

    const timelineHtml = timeline.length ? timeline.map(ev => {
      const sev = String(ev.severity || 'LOW').toUpperCase();
      const sevCls = sev === 'CRITICAL' ? 'bg-red-950 text-red-300 border-red-700' : (sev === 'HIGH' || sev === 'MEDIUM' ? 'bg-amber-950 text-amber-200 border-amber-800' : 'bg-slate-900 text-slate-200 border-slate-700');
      return `
        <div class="p-3 rounded-xl bg-black/70 border border-slate-800 flex flex-wrap items-center justify-between gap-2 text-xs">
          <div class="space-y-0.5 min-w-0">
            <div class="flex flex-wrap items-center gap-2">
              <span class="font-mono text-slate-400">${ev.timestamp ? formatSocTimestamp(ev.timestamp) : 'Not recorded'}</span>
              <span class="px-2 py-0.5 rounded bg-red-950/60 border border-red-900/60 text-red-200 text-[10px] font-semibold">${escapeHtml(ev.category)}</span>
              <span class="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-sky-300 text-[10px]">${escapeHtml(formatSocPortalName(ev.portal))}</span>
              ${ev.session_id ? `<span class="font-mono text-[10px] text-slate-400">${escapeHtml(ev.session_id)}</span>` : ''}
            </div>
            <div class="text-white font-semibold">${escapeHtml(ev.label)}</div>
            ${ev.details ? `<div class="text-slate-400 truncate max-w-3xl">${escapeHtml(ev.details)}</div>` : ''}
          </div>
          <span class="px-2.5 py-1 rounded-lg border font-mono text-[11px] shrink-0 ${sevCls}">${escapeHtml(sev)} · ${escapeHtml(ev.result || 'Recorded')}</span>
        </div>
      `;
    }).join('') : `<div class="p-8 rounded-xl bg-black/50 border border-slate-800 text-center text-slate-400 text-xs">No genuine user activity recorded for this user/filter yet.</div>`;

    contentEl.innerHTML = `
      <div class="p-5 rounded-2xl bg-black/60 border border-red-900/50 space-y-5">
        <div class="flex flex-wrap items-center justify-between gap-3 border-b border-red-950/70 pb-3">
          <div>
            <h4 class="font-heading font-bold text-base text-white flex items-center gap-2">
              <span class="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse"></span>
              <span>8. Live Activity &amp; Behaviour</span>
            </h4>
            <p class="text-xs text-slate-400 mt-0.5">Auto-polling PostgreSQL every 4s &bull; Latest Activity: <span id="ui-live-latest-ts" class="font-mono text-slate-200">${data.latest_activity_timestamp ? formatSocTimestamp(data.latest_activity_timestamp) : 'No activity yet'}</span></p>
          </div>
          <div class="flex flex-wrap items-center gap-2 text-xs">
            <select id="ui-live-session-select" onchange="window.onUserLiveFilterChange()" class="px-2.5 py-1.5 rounded-lg bg-black border border-slate-700 text-slate-200 focus:border-red-500 focus:outline-none">${sessOpts}</select>
            <select id="ui-live-portal-select" onchange="window.onUserLiveFilterChange()" class="px-2.5 py-1.5 rounded-lg bg-black border border-slate-700 text-slate-200 focus:border-red-500 focus:outline-none">
              <option value="ALL" ${portalFilter === 'ALL' ? 'selected' : ''}>All Portals</option>
              <option value="shopping" ${portalFilter === 'shopping' ? 'selected' : ''}>Shopping</option>
              <option value="college" ${portalFilter === 'college' ? 'selected' : ''}>College</option>
              <option value="healthcare" ${portalFilter === 'healthcare' ? 'selected' : ''}>Healthcare</option>
              <option value="platform" ${portalFilter === 'platform' ? 'selected' : ''}>Platform</option>
            </select>
            <button type="button" onclick="window.renderUserLiveActivitySection(${uid}, false)" class="px-3 py-1.5 rounded-lg bg-red-950/70 hover:bg-red-900 border border-red-800 text-red-100 font-semibold cursor-pointer">↻ Poll Now</button>
          </div>
        </div>

        <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
          <div class="p-3 rounded-xl bg-black/75 border border-slate-800"><span class="text-slate-400 block">Baseline Readiness</span><strong class="text-white">${escapeHtml(beh.baseline_readiness_label || 'No signal received')}</strong><div class="text-[10px] text-slate-400 mt-0.5">${Number(beh.trusted_samples || 0)} trusted / ${Number(beh.observation_count || 0)} logs</div></div>
          <div class="p-3 rounded-xl bg-black/75 border border-slate-800"><span class="text-slate-400 block">Isolation Forest Status</span><strong class="${ml.is_fitted ? 'text-emerald-300' : 'text-amber-300'}">${escapeHtml(ml.label || 'Model not fitted')}</strong><div class="text-[10px] text-slate-400 mt-0.5">${Number(ml.model_sample_count || 0)} fitted samples</div></div>
          <div class="p-3 rounded-xl bg-black/75 border border-slate-800"><span class="text-slate-400 block">Training Observations</span><strong class="text-sky-300">${Number(tc.eligible_or_processed || 0)} eligible</strong><div class="text-[10px] text-slate-400 mt-0.5">${Number(tc.rejected || 0)} rejected / ${Number(tc.total || 0)} total</div></div>
          <div class="p-3 rounded-xl bg-black/75 border border-slate-800"><span class="text-slate-400 block">Anomaly Score</span><strong class="${ml.is_anomaly ? 'text-red-400' : 'text-emerald-300'}">${ml.anomaly_score !== null && ml.anomaly_score !== undefined ? Number(ml.anomaly_score).toFixed(3) : 'Not recorded'}</strong><div class="text-[10px] text-slate-400 mt-0.5">Modalities: ${escapeHtml(Object.entries(modMat).map(([k, v]) => `${k}:${v}`).join(' · ') || 'Awaiting')}</div></div>
        </div>

        <div class="space-y-2">
          <div class="text-xs font-semibold uppercase text-slate-400">Live 10-Dimensional Behavioural Telemetry vs. Baseline</div>
          <div class="grid grid-cols-2 sm:grid-cols-5 gap-2">${dimCardsHtml}</div>
        </div>

        <div class="space-y-2 pt-2 border-t border-red-950/60">
          <div class="text-xs font-semibold uppercase text-slate-400">Chronological Live Activity Timeline (${timeline.length})</div>
          <div id="ui-live-timeline-list" class="space-y-2 max-h-[26rem] overflow-y-auto pr-1">${timelineHtml}</div>
        </div>
      </div>
    `;
  } catch (err) {
    contentEl.innerHTML = `<div class="p-6 rounded-2xl bg-black/60 border border-red-900 text-red-400 text-sm">Failed to load live user activity: ${escapeHtml(err.message)}</div>`;
  }
};


window.addEventListener('cognisec:portal_locks_updated', (ev) => {
  if (typeof window.renderDashboardPortalLocks === 'function') {
    window.renderDashboardPortalLocks(ev.detail || null);
  }
});

window.addEventListener('cognisec:auth_change', () => {
  if (typeof window.syncAuthStateUI === 'function') {
    window.syncAuthStateUI();
  }
});

document.addEventListener('DOMContentLoaded', async () => {
  try {
    const params = new URLSearchParams(window.location.search || '');
    const ejectedPortal = params.get('portal_ejected');
    if (typeof window.syncAuthStateUI === 'function') {
      window.syncAuthStateUI();
    }
    if (ejectedPortal) {
      if (window.cognisec && window.cognisec.isAuthenticated()) {
        await window.refreshDashboardPortalLocks();
        if (!window.cognisec.isAdmin() && typeof window.openModal === 'function') {
          window.openModal('liveDemo');
        }
        const secRef = params.get('sec_ref') || '';
        if (typeof window.showNotificationToast === 'function') {
          window.showNotificationToast(
            'Portal Access Suspended',
            `Access to ${ejectedPortal.toUpperCase()} portal was suspended${secRef ? ` (${secRef})` : ''}. Your global session remains active.`,
            '⛔'
          );
        }
      }
      if (window.history && typeof window.history.replaceState === 'function') {
        const cleanUrl = window.location.pathname + (window.location.hash || '');
        window.history.replaceState({}, document.title, cleanUrl);
      }
    } else if (window.cognisec && window.cognisec.isAuthenticated()) {
      await window.refreshDashboardPortalLocks();
    }
  } catch (e) {
    console.warn('[COGNISEC-AI] Dashboard portal lock sync notice:', e);
  }
});







// ============================================================================
// MANDATORY EMAIL OTP + 3-FACTOR ADAPTIVE AUTHENTICATION ENROLLMENT FLOW
// ============================================================================
const MANDATORY_NT_COORDS = [
  { id: 0, x: 70, y: 30 }, { id: 1, x: 160, y: 24 }, { id: 2, x: 250, y: 30 },
  { id: 3, x: 45, y: 95 }, { id: 4, x: 120, y: 90 }, { id: 5, x: 200, y: 90 }, { id: 6, x: 275, y: 95 },
  { id: 7, x: 45, y: 165 }, { id: 8, x: 120, y: 160 }, { id: 9, x: 200, y: 160 }, { id: 10, x: 275, y: 165 },
  { id: 11, x: 70, y: 230 }, { id: 12, x: 160, y: 236 }, { id: 13, x: 250, y: 230 }
];
const MANDATORY_NT_EDGES = [
  [0,1],[1,2],[0,3],[0,4],[1,3],[1,4],[1,5],[2,5],[2,6],
  [3,4],[4,5],[5,6],[3,7],[3,8],[4,7],[4,8],[4,9],[5,8],[5,9],[5,10],[6,9],[6,10],
  [7,8],[8,9],[9,10],[7,11],[7,12],[8,11],[8,12],[8,13],[9,11],[9,12],[9,13],[10,12],[10,13],
  [11,12],[12,13]
];
const MANDATORY_IMG_CATALOGUE = [
  { id: 'img_shield', label: 'Security Shield', icon: '🛡️' },
  { id: 'img_key', label: 'Cryptographic Key', icon: '🔑' },
  { id: 'img_lock', label: 'Security Padlock', icon: '🔒' },
  { id: 'img_radar', label: 'Threat Radar', icon: '📡' },
  { id: 'img_vault', label: 'Secure Vault', icon: '🏛️' },
  { id: 'img_biometric', label: 'Biometric Scanner', icon: '🧬' },
  { id: 'img_firewall', label: 'Perimeter Firewall', icon: '🧱' },
  { id: 'img_token', label: 'Hardware Token', icon: '🪙' },
  { id: 'img_chip', label: 'Secure Enclave', icon: '💾' }
];

const mandatoryEnrollState = {
  pendingEmail: '',
  currentStep: 1,
  ntStage: 'initial',
  ntInitial: [],
  ntConfirm: [],
  imgStage: 'initial',
  imgInitial: [],
  imgConfirm: [],
  saved: {
    gesture: false,
    image: false,
    privateResp: false
  }
};

function _mandAreAdjacent(a, b) {
  return MANDATORY_NT_EDGES.some(([u, v]) => (u === a && v === b) || (u === b && v === a));
}

function _mandSetFeedback(errMsg, okMsg) {
  const errEl = document.getElementById('mand-enroll-error');
  const okEl = document.getElementById('mand-enroll-success');
  if (errEl) {
    if (errMsg) { errEl.textContent = errMsg; errEl.classList.remove('hidden'); }
    else errEl.classList.add('hidden');
  }
  if (okEl) {
    if (okMsg) { okEl.textContent = okMsg; okEl.classList.remove('hidden'); }
    else okEl.classList.add('hidden');
  }
}

window.submitAccountCreationAndSendOtp = async function() {
  const nameInput = document.getElementById('signup-user-name');
  const emailInput = document.getElementById('signup-user-email');
  const passwordInput = document.getElementById('signup-user-password');
  const confirmInput = document.getElementById('signup-user-confirm');
  const errBox = document.getElementById('signup-error-user');
  const btn = document.getElementById('btn-create-account-otp');

  if (errBox) errBox.classList.add('hidden');
  const name = nameInput ? nameInput.value.trim() : '';
  const email = emailInput ? emailInput.value.trim() : '';
  const password = passwordInput ? passwordInput.value : '';
  const confirm = confirmInput ? confirmInput.value : '';

  if (!name || !email || !password || !confirm) {
    if (errBox) { errBox.textContent = 'Please fill out all account information fields.'; errBox.classList.remove('hidden'); }
    return;
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    if (errBox) { errBox.textContent = 'Please enter a valid email address.'; errBox.classList.remove('hidden'); }
    return;
  }
  if (password !== confirm) {
    if (errBox) { errBox.textContent = 'Passwords do not match.'; errBox.classList.remove('hidden'); }
    return;
  }
  if (password.length < 8 || !/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/\d/.test(password) || !/[!@#$%^&*(),.?":{}|<>\-_=+[\]\\/;~`']/.test(password)) {
    if (errBox) { errBox.textContent = 'Password does not meet the complexity requirements.'; errBox.classList.remove('hidden'); }
    return;
  }

  if (btn) { btn.disabled = true; btn.textContent = 'Creating Account & Dispatching OTP...'; }
  try {
    const res = await window.cognisec.register(name, email, password, 'USER', { require_email_verification: true });
    if (!res.success) {
      if (errBox) { errBox.textContent = res.error || 'Registration failed.'; errBox.classList.remove('hidden'); }
      return;
    }
    mandatoryEnrollState.pendingEmail = email.toLowerCase().trim();
    const disp = document.getElementById('reg-otp-email-display');
    if (disp) disp.textContent = res.data?.masked_email || email;
    const hint = document.getElementById('reg-otp-dev-hint');
    if (hint) {
      if (res.data?.dev_otp) {
        hint.textContent = `Verification OTP: ${res.data.dev_otp}`;
        hint.classList.remove('hidden');
      } else {
        hint.classList.add('hidden');
      }
    }
    if (passwordInput) passwordInput.value = '';
    if (confirmInput) confirmInput.value = '';
    const otpInput = document.getElementById('reg-email-otp-code');
    if (otpInput) otpInput.value = '';
    goToSignupStep('otp');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Create Account & Send Verification OTP →'; }
  }
};

window.resendEmailVerificationOtp = async function() {
  const email = mandatoryEnrollState.pendingEmail || document.getElementById('signup-user-email')?.value?.trim() || '';
  const errEl = document.getElementById('reg-otp-error');
  if (!email) return;
  const res = await window.cognisec.resendVerificationEmail(email);
  if (!res.success) {
    if (errEl) { errEl.textContent = res.error || 'Unable to resend code.'; errEl.classList.remove('hidden'); }
    return;
  }
  if (errEl) errEl.classList.add('hidden');
  const hint = document.getElementById('reg-otp-dev-hint');
  if (hint && res.data?.dev_otp) {
    hint.textContent = `Verification OTP: ${res.data.dev_otp}`;
    hint.classList.remove('hidden');
  }
};

window.submitEmailVerificationOtp = async function() {
  const email = mandatoryEnrollState.pendingEmail || document.getElementById('signup-user-email')?.value?.trim() || '';
  const otpCode = (document.getElementById('reg-email-otp-code')?.value || '').trim();
  const errEl = document.getElementById('reg-otp-error');
  const btn = document.getElementById('btn-verify-reg-otp');
  if (errEl) errEl.classList.add('hidden');
  if (!otpCode || otpCode.length < 4) {
    if (errEl) { errEl.textContent = 'Please enter the 6-digit verification code sent to your email.'; errEl.classList.remove('hidden'); }
    return;
  }
  if (btn) { btn.disabled = true; btn.textContent = 'Verifying Email...'; }
  try {
    const res = await window.cognisec.verifyEmail(email, otpCode);
    if (!res.success) {
      if (errEl) { errEl.textContent = res.error || 'Invalid verification code.'; errEl.classList.remove('hidden'); }
      return;
    }
    closeModal('login');
    if (typeof window.syncAuthStateUI === 'function') window.syncAuthStateUI();
    await window.openMandatoryEnrollmentModal();
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Verify Email & Start Security Enrollment →'; }
  }
};

window.openMandatoryEnrollmentModal = async function() {
  const modal = document.getElementById('modal-mandatory-enrollment');
  if (!modal) return;
  const user = window.cognisec ? window.cognisec.getUser() : null;
  const emailSpan = document.getElementById('mand-enroll-user-email');
  if (emailSpan) emailSpan.textContent = user?.email || 'Authenticated User';

  _mandSetFeedback(null, null);
  try {
    const st = await window.cognisec.getAdaptiveStatus();
    if (st) {
      mandatoryEnrollState.saved.gesture = Boolean(st.has_gesture_pattern);
      mandatoryEnrollState.saved.image = Boolean(st.has_cognitive_image_sequence);
      mandatoryEnrollState.saved.privateResp = Boolean(st.has_private_response);
    }
  } catch (_) {}

  modal.classList.remove('hidden');
  document.body.style.overflow = 'hidden';

  if (!mandatoryEnrollState.saved.gesture) {
    window.goToMandatoryEnrollmentStep(1);
  } else if (!mandatoryEnrollState.saved.image) {
    window.goToMandatoryEnrollmentStep(2);
  } else if (!mandatoryEnrollState.saved.privateResp) {
    window.goToMandatoryEnrollmentStep(3);
  } else {
    window.goToMandatoryEnrollmentStep(4);
  }
};

window.logoutFromMandatoryEnrollment = async function() {
  const modal = document.getElementById('modal-mandatory-enrollment');
  if (modal) modal.classList.add('hidden');
  document.body.style.overflow = '';
  if (window.cognisec) await window.cognisec.logout();
  if (typeof window.syncAuthStateUI === 'function') window.syncAuthStateUI();
};

function _renderMandatoryStepper() {
  const step = mandatoryEnrollState.currentStep;
  const saved = mandatoryEnrollState.saved;
  const states = [saved.gesture, saved.image, saved.privateResp, saved.gesture && saved.image && saved.privateResp];
  for (let i = 1; i <= 4; i++) {
    const pill = document.getElementById(`mand-pill-${i}`);
    const badge = document.getElementById(`mand-badge-${i}`);
    const pane = document.getElementById(`mand-step-${i}`);
    if (pane) pane.classList.toggle('hidden', i !== step);
    if (pill) {
      if (i === step) {
        pill.className = 'p-2 rounded-xl bg-red-600 text-white font-bold border border-red-400 shadow-[0_0_14px_rgba(220,38,38,0.45)]';
      } else if (states[i - 1]) {
        pill.className = 'p-2 rounded-xl bg-emerald-950 text-emerald-300 font-bold border border-emerald-700';
      } else {
        pill.className = 'p-2 rounded-xl bg-slate-900 text-slate-400 font-bold border border-slate-800';
      }
    }
    if (badge) {
      if (i < 4) badge.textContent = states[i - 1] ? '✓ Configured' : 'Pending';
      else badge.textContent = states[3] ? 'Ready' : 'Final';
    }
  }
  const s1 = document.getElementById('mand-summary-1');
  const s2 = document.getElementById('mand-summary-2');
  const s3 = document.getElementById('mand-summary-3');
  if (s1) s1.textContent = saved.gesture ? '✓ Configured & Saved' : 'Pending';
  if (s2) s2.textContent = saved.image ? '✓ Configured & Saved' : 'Pending';
  if (s3) s3.textContent = saved.privateResp ? '✓ Configured & Saved' : 'Pending';
}

function _renderMandatoryNeuralTrace() {
  const svg = document.getElementById('mand-nt-svg');
  if (!svg) return;
  const route = mandatoryEnrollState.ntStage === 'initial' ? mandatoryEnrollState.ntInitial : mandatoryEnrollState.ntConfirm;
  const tag = document.getElementById('mand-nt-stage-tag');
  const hint = document.getElementById('mand-nt-hint');
  const cnt = document.getElementById('mand-nt-nodes-count');
  const savedNote = document.getElementById('mand-nt-saved-note');
  const btn = document.getElementById('btn-mand-step1-next');

  if (tag) {
    tag.textContent = mandatoryEnrollState.ntStage === 'initial'
      ? 'STAGE 1: TRACE NEURAL ROUTE (MIN 4 CONNECTED NODES)'
      : 'STAGE 2: CONFIRM YOUR NEURAL ROUTE';
  }
  if (hint) {
    hint.textContent = mandatoryEnrollState.ntStage === 'initial'
      ? 'Click at least 4 connected nodes on the 14-node NeuralTrace graph to define your private route.'
      : 'Re-trace the exact same route to confirm before saving.';
  }
  if (cnt) cnt.textContent = `${route.length} / 4+ nodes`;
  if (savedNote) savedNote.classList.toggle('hidden', !mandatoryEnrollState.saved.gesture);
  if (btn) {
    btn.textContent = (mandatoryEnrollState.saved.gesture && mandatoryEnrollState.ntInitial.length === 0)
      ? 'Keep Saved NeuralTrace & Continue →'
      : (mandatoryEnrollState.ntStage === 'initial' ? 'Confirm Route →' : 'Save NeuralTrace & Continue →');
  }

  let html = '';
  for (const [u, v] of MANDATORY_NT_EDGES) {
    const a = MANDATORY_NT_COORDS[u];
    const b = MANDATORY_NT_COORDS[v];
    let activeEdge = false;
    for (let k = 1; k < route.length; k++) {
      if ((route[k - 1] === u && route[k] === v) || (route[k - 1] === v && route[k] === u)) {
        activeEdge = true;
        break;
      }
    }
    html += `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="${activeEdge ? '#ef4444' : '#334155'}" stroke-width="${activeEdge ? 3.5 : 1.5}" stroke-opacity="${activeEdge ? 0.95 : 0.6}"/>`;
  }
  for (const node of MANDATORY_NT_COORDS) {
    const idx = route.indexOf(node.id);
    const isSel = idx !== -1;
    const isLast = route.length > 0 && route[route.length - 1] === node.id;
    const fill = isLast ? '#ef4444' : (isSel ? '#b91c1c' : '#0f172a');
    const stroke = isSel ? '#fca5a5' : '#475569';
    html += `<g onclick="clickMandatoryNtNode(${node.id})" style="cursor:pointer;">
      <circle cx="${node.x}" cy="${node.y}" r="14" fill="${fill}" stroke="${stroke}" stroke-width="2"/>
      <text x="${node.x}" y="${node.y + 4}" text-anchor="middle" fill="#ffffff" font-size="10" font-family="monospace" font-weight="bold">${node.id}</text>
    </g>`;
  }
  svg.innerHTML = html;
}

window.clickMandatoryNtNode = function(nodeId) {
  _mandSetFeedback(null, null);
  const route = mandatoryEnrollState.ntStage === 'initial' ? mandatoryEnrollState.ntInitial : mandatoryEnrollState.ntConfirm;
  if (route.length > 0) {
    const last = route[route.length - 1];
    if (last === nodeId) return;
    if (!_mandAreAdjacent(last, nodeId)) {
      _mandSetFeedback(`Nodes ${last} and ${nodeId} are not directly connected. Choose an adjacent connected node.`, null);
      return;
    }
  }
  route.push(nodeId);
  _renderMandatoryNeuralTrace();
};

window.resetMandatoryNeuralTrace = function() {
  _mandSetFeedback(null, null);
  mandatoryEnrollState.ntStage = 'initial';
  mandatoryEnrollState.ntInitial = [];
  mandatoryEnrollState.ntConfirm = [];
  _renderMandatoryNeuralTrace();
};

window.saveMandatoryNeuralTrace = async function() {
  _mandSetFeedback(null, null);
  if (mandatoryEnrollState.saved.gesture && mandatoryEnrollState.ntInitial.length === 0) {
    window.goToMandatoryEnrollmentStep(2);
    return;
  }
  if (mandatoryEnrollState.ntStage === 'initial') {
    if (mandatoryEnrollState.ntInitial.length < 4) {
      _mandSetFeedback('Please connect at least 4 nodes for your NeuralTrace route.', null);
      return;
    }
    mandatoryEnrollState.ntStage = 'confirm';
    mandatoryEnrollState.ntConfirm = [];
    _renderMandatoryNeuralTrace();
    return;
  }
  if (mandatoryEnrollState.ntConfirm.length < 4) {
    _mandSetFeedback('Please re-trace your route (at least 4 connected nodes) to confirm.', null);
    return;
  }
  if (JSON.stringify(mandatoryEnrollState.ntInitial) !== JSON.stringify(mandatoryEnrollState.ntConfirm)) {
    _mandSetFeedback('Confirmation route does not match your initial route. Please re-trace.', null);
    mandatoryEnrollState.ntConfirm = [];
    _renderMandatoryNeuralTrace();
    return;
  }
  const btn = document.getElementById('btn-mand-step1-next');
  if (btn) { btn.disabled = true; btn.textContent = 'Saving NeuralTrace...'; }
  try {
    const res = await window.cognisec.enrollGesturePattern(mandatoryEnrollState.ntInitial, mandatoryEnrollState.ntConfirm);
    if (!res || !res.success) {
      _mandSetFeedback(res?.error || 'Failed to save NeuralTrace route.', null);
      return;
    }
    mandatoryEnrollState.saved.gesture = true;
    _mandSetFeedback(null, '✓ NeuralTrace Route saved successfully.');
    window.goToMandatoryEnrollmentStep(2);
  } finally {
    if (btn) btn.disabled = false;
  }
};

function _renderMandatoryImageGrid() {
  const grid = document.getElementById('mand-img-grid');
  if (!grid) return;
  const seq = mandatoryEnrollState.imgStage === 'initial' ? mandatoryEnrollState.imgInitial : mandatoryEnrollState.imgConfirm;
  const tag = document.getElementById('mand-img-stage-tag');
  const hint = document.getElementById('mand-img-hint');
  const preview = document.getElementById('mand-img-seq-preview');
  const btn = document.getElementById('btn-mand-step2-next');

  if (tag) {
    tag.textContent = mandatoryEnrollState.imgStage === 'initial'
      ? 'STAGE 1: SELECT 3–5 IMAGES IN ORDER'
      : 'STAGE 2: CONFIRM IMAGE SEQUENCE';
  }
  if (hint) {
    hint.textContent = mandatoryEnrollState.imgStage === 'initial'
      ? 'Select 3 to 5 unique symbols in a memorable order.'
      : 'Re-select the exact same symbols in the exact same order to confirm.';
  }
  if (preview) {
    preview.textContent = seq.length
      ? seq.map((id, idx) => {
          const item = MANDATORY_IMG_CATALOGUE.find(c => c.id === id);
          return `${idx + 1}. ${item ? item.icon + ' ' + item.label : id}`;
        }).join(' → ')
      : 'None selected';
  }
  if (btn) {
    btn.textContent = (mandatoryEnrollState.saved.image && mandatoryEnrollState.imgInitial.length === 0)
      ? 'Keep Saved Image Sequence & Continue →'
      : (mandatoryEnrollState.imgStage === 'initial' ? 'Confirm Sequence →' : 'Save Image Sequence & Continue →');
  }

  grid.innerHTML = MANDATORY_IMG_CATALOGUE.map(item => {
    const orderIdx = seq.indexOf(item.id);
    const selected = orderIdx !== -1;
    return `
      <button type="button" onclick="clickMandatoryImage('${item.id}')" class="p-3 rounded-xl border text-center transition-all cursor-pointer relative ${selected ? 'bg-red-950/60 border-red-500 text-white shadow-[0_0_12px_rgba(239,68,68,0.4)]' : 'bg-black/80 border-slate-800 hover:border-slate-600 text-slate-300'}">
        ${selected ? `<span class="absolute top-1.5 right-1.5 w-5 h-5 rounded-full bg-red-600 text-white text-[10px] font-bold flex items-center justify-center">${orderIdx + 1}</span>` : ''}
        <div class="text-2xl mb-1">${item.icon}</div>
        <div class="text-[10px] font-bold">${item.label}</div>
      </button>
    `;
  }).join('');
}

window.clickMandatoryImage = function(imgId) {
  _mandSetFeedback(null, null);
  const seq = mandatoryEnrollState.imgStage === 'initial' ? mandatoryEnrollState.imgInitial : mandatoryEnrollState.imgConfirm;
  const idx = seq.indexOf(imgId);
  if (idx !== -1) {
    seq.splice(idx, 1);
  } else {
    if (seq.length >= 5) {
      _mandSetFeedback('Maximum 5 images allowed in your cognitive sequence.', null);
      return;
    }
    seq.push(imgId);
  }
  _renderMandatoryImageGrid();
};

window.resetMandatoryImageSequence = function() {
  _mandSetFeedback(null, null);
  mandatoryEnrollState.imgStage = 'initial';
  mandatoryEnrollState.imgInitial = [];
  mandatoryEnrollState.imgConfirm = [];
  _renderMandatoryImageGrid();
};

window.saveMandatoryImageSequence = async function() {
  _mandSetFeedback(null, null);
  if (mandatoryEnrollState.saved.image && mandatoryEnrollState.imgInitial.length === 0) {
    window.goToMandatoryEnrollmentStep(3);
    return;
  }
  if (mandatoryEnrollState.imgStage === 'initial') {
    if (mandatoryEnrollState.imgInitial.length < 3 || mandatoryEnrollState.imgInitial.length > 5) {
      _mandSetFeedback('Please select between 3 and 5 images in order.', null);
      return;
    }
    mandatoryEnrollState.imgStage = 'confirm';
    mandatoryEnrollState.imgConfirm = [];
    _renderMandatoryImageGrid();
    return;
  }
  if (JSON.stringify(mandatoryEnrollState.imgInitial) !== JSON.stringify(mandatoryEnrollState.imgConfirm)) {
    _mandSetFeedback('Confirmation image sequence does not match. Please re-select in exact order.', null);
    mandatoryEnrollState.imgConfirm = [];
    _renderMandatoryImageGrid();
    return;
  }
  const btn = document.getElementById('btn-mand-step2-next');
  if (btn) { btn.disabled = true; btn.textContent = 'Saving Image Sequence...'; }
  try {
    const res = await window.cognisec.enrollImageSequence(mandatoryEnrollState.imgInitial, mandatoryEnrollState.imgConfirm);
    if (!res || !res.success) {
      _mandSetFeedback(res?.error || 'Failed to save cognitive image sequence.', null);
      return;
    }
    mandatoryEnrollState.saved.image = true;
    _mandSetFeedback(null, '✓ Cognitive Image Sequence saved successfully.');
    window.goToMandatoryEnrollmentStep(3);
  } finally {
    if (btn) btn.disabled = false;
  }
};

window.saveMandatoryPrivateResponse = async function() {
  _mandSetFeedback(null, null);
  const q = document.getElementById('mand-priv-question')?.value || '';
  const a = (document.getElementById('mand-priv-answer')?.value || '').trim();
  const c = (document.getElementById('mand-priv-confirm')?.value || '').trim();
  if (mandatoryEnrollState.saved.privateResp && !a && !c) {
    window.goToMandatoryEnrollmentStep(4);
    return;
  }
  if (!a || a.length < 3) {
    _mandSetFeedback('Private answer must be at least 3 characters long.', null);
    return;
  }
  if (a.toLowerCase() !== c.toLowerCase()) {
    _mandSetFeedback('Private response confirmation does not match.', null);
    return;
  }
  const btn = document.getElementById('btn-mand-step3-next');
  if (btn) { btn.disabled = true; btn.textContent = 'Saving Private Response...'; }
  try {
    const res = await window.cognisec.enrollPrivateResponse(q, a, c);
    if (!res || !res.success) {
      _mandSetFeedback(res?.error || 'Failed to save private response.', null);
      return;
    }
    mandatoryEnrollState.saved.privateResp = true;
    const ansInput = document.getElementById('mand-priv-answer');
    const confInput = document.getElementById('mand-priv-confirm');
    if (ansInput) ansInput.value = '';
    if (confInput) confInput.value = '';
    _mandSetFeedback(null, '✓ Private Security Response saved successfully.');
    window.goToMandatoryEnrollmentStep(4);
  } finally {
    if (btn) btn.disabled = false;
  }
};

window.goToMandatoryEnrollmentStep = function(step) {
  mandatoryEnrollState.currentStep = step;
  _renderMandatoryStepper();
  if (step === 1) _renderMandatoryNeuralTrace();
  if (step === 2) _renderMandatoryImageGrid();
};

window.finalizeMandatoryEnrollment = async function() {
  _mandSetFeedback(null, null);
  const btn = document.getElementById('btn-mand-finalize');
  if (btn) { btn.disabled = true; btn.textContent = 'Finalizing Security Enrollment...'; }
  try {
    const res = await window.cognisec.completeAdaptiveEnrollment();
    if (!res.success) {
      _mandSetFeedback(res.error || 'Please ensure all three factors are configured.', null);
      return;
    }
    const modal = document.getElementById('modal-mandatory-enrollment');
    if (modal) modal.classList.add('hidden');
    document.body.style.overflow = '';
    if (typeof window.syncAuthStateUI === 'function') window.syncAuthStateUI();
    openModal('liveDemo');
    if (typeof showNotificationToast === 'function') {
      showNotificationToast(
        'Security Enrollment Complete',
        'All 3 adaptive authentication factors are configured. Normal portal access is now unlocked.',
        'success'
      );
    }
  } finally {
    if (btn) btn.disabled = false; btn.textContent = 'Complete Security Enrollment & Enter Dashboard ✓';
  }
};

document.addEventListener('DOMContentLoaded', async () => {
  const client = window.cognisec;
  if (!client || !client.isAuthenticated() || client.isAdmin()) return;
  try {
    const meRes = await fetch(`${COGNISEC_API_BASE}/auth/me`, { headers: client.getHeaders() });
    if (meRes.ok) {
      const me = await meRes.json();
      if (me && me.security_enrollment_completed === false) {
        if (client.user) {
          client.user.security_enrollment_completed = false;
          localStorage.setItem('cognisec_user', JSON.stringify(client.user));
        }
        await window.openMandatoryEnrollmentModal();
      }
    }
  } catch (_) {}
});
