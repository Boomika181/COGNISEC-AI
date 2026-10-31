/**
 * COGNISEC-AI Client Telemetry & Integration Engine
 * Connects frontend portals to the FastAPI Zero-Trust Backend.
 * Endpoint: POST http://127.0.0.1:8000/api/behavior/events
 * Captures passive behavioral features (Privacy-safe: NO raw passwords/sensitive keystrokes).
 */

const COGNISEC_API_BASE = 'http://127.0.0.1:8000/api';

// Configurable observation window duration in seconds (Default 30s as required by policy)
const COGNISEC_OBSERVATION_SECONDS = 30;
if (typeof window !== 'undefined') {
  window.COGNISEC_OBSERVATION_SECONDS = COGNISEC_OBSERVATION_SECONDS;
}

// Accessible inline eye / eye-off SVG icons for password visibility toggles
const EYE_ON_SVG = '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-4 h-4 pointer-events-none" aria-hidden="true"><path d="M2.062 12.348a1 1 0 0 1 0-.696 10.75 10.75 0 0 1 19.876 0 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-19.876 0"/><circle cx="12" cy="12" r="3"/></svg>';
const EYE_OFF_SVG = '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-4 h-4 pointer-events-none text-red-400" aria-hidden="true"><path d="m15 18-.722-3.25"/><path d="M2 2l20 20"/><path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"/><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"/><path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"/></svg>';

window.EYE_ON_SVG = EYE_ON_SVG;
window.EYE_OFF_SVG = EYE_OFF_SVG;

/**
 * Universal accessible password visibility toggle function.
 * Toggles input type between password and text while preserving input value, selection, and form state.
 */
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
    btn.innerHTML = isPass ? EYE_OFF_SVG : EYE_ON_SVG;
  }
};

function ensureGestureStylesInjected() {
  if (typeof document === 'undefined') return;
  if (document.getElementById('cognisec-neuraltrace-styles')) return;
  const style = document.createElement('style');
  style.id = 'cognisec-neuraltrace-styles';
  style.textContent = `
    /* Modal Viewport and Scrolling Hotfix */
    #modal-stepup {
      box-sizing: border-box;
      padding: 1rem;
      overflow-y: auto;
      overscroll-behavior: contain;
    }
    #stepup-modal-container {
      box-sizing: border-box;
      max-height: calc(100vh - 32px);
      max-height: calc(100dvh - 32px);
      display: flex;
      flex-direction: column;
      margin: auto;
      overflow: hidden;
      width: 100%;
      max-width: 32rem;
    }
    #stepup-modal-container * {
      box-sizing: border-box;
    }
    #stepup-modal-header {
      flex-shrink: 0;
    }
    #stepup-modal-body {
      box-sizing: border-box;
      overflow-y: auto;
      overflow-x: hidden;
      flex: 1 1 auto;
      min-height: 0;
      overscroll-behavior: contain;
      -webkit-overflow-scrolling: touch;
      scrollbar-width: thin;
      scrollbar-color: rgba(245, 158, 11, 0.4) transparent;
    }
    #stepup-modal-body::-webkit-scrollbar {
      width: 6px;
    }
    #stepup-modal-body::-webkit-scrollbar-track {
      background: rgba(0, 0, 0, 0.2);
    }
    #stepup-modal-body::-webkit-scrollbar-thumb {
      background: rgba(245, 158, 11, 0.4);
      border-radius: 9999px;
    }
    #stepup-modal-footer {
      flex-shrink: 0;
      position: sticky;
      bottom: 0;
      z-index: 10;
      box-sizing: border-box;
      background: linear-gradient(180deg, rgba(8, 5, 14, 0.96) 0%, #08050e 100%);
      backdrop-filter: blur(8px);
      -webkit-backdrop-filter: blur(8px);
      border-top: 1px solid rgba(245, 158, 11, 0.25);
    }

    /* Responsive Graph Scaling */
    .neuraltrace-container {
      position: relative;
      width: 100%;
      max-width: 340px;
      aspect-ratio: 360 / 340;
      margin: 0 auto;
      border-radius: 1.25rem;
      background: radial-gradient(circle at 50% 50%, #0a1128 0%, #030712 100%);
      border: 1px solid rgba(56, 189, 248, 0.25);
      box-shadow: 0 16px 36px -10px rgba(0, 0, 0, 0.95), inset 0 0 30px rgba(14, 165, 233, 0.08);
      touch-action: none;
      user-select: none;
      overflow: hidden;
      transition: border-color 0.3s ease, box-shadow 0.3s ease;
    }

    @media (max-height: 820px) {
      .neuraltrace-container {
        max-width: 290px;
      }
      #stepup-modal-container {
        max-height: calc(100vh - 24px);
        max-height: calc(100dvh - 24px);
      }
    }

    @media (max-height: 700px) {
      .neuraltrace-container {
        max-width: 240px;
      }
      #stepup-modal-container {
        max-height: calc(100vh - 16px);
        max-height: calc(100dvh - 16px);
      }
    }

    @media (max-width: 480px) {
      #modal-stepup {
        padding: 0.5rem;
      }
      #stepup-modal-container {
        max-height: calc(100vh - 16px);
        max-height: calc(100dvh - 16px);
      }
      .neuraltrace-container {
        max-width: 280px;
      }
    }
    .neuraltrace-container.theme-cyber,
    .neuraltrace-container.theme-red {
      background: radial-gradient(circle at 50% 50%, #150a21 0%, #05050f 100%);
      border-color: rgba(168, 85, 247, 0.3);
      box-shadow: 0 16px 36px -10px rgba(0, 0, 0, 0.95), inset 0 0 30px rgba(168, 85, 247, 0.1);
    }
    .neuraltrace-container.theme-sky {
      background: radial-gradient(circle at 50% 50%, #071930 0%, #020714 100%);
      border-color: rgba(14, 165, 233, 0.35);
      box-shadow: 0 16px 36px -10px rgba(0, 0, 0, 0.95), inset 0 0 30px rgba(14, 165, 233, 0.1);
    }
    .neuraltrace-container.theme-amber {
      background: radial-gradient(circle at 50% 50%, #241407 0%, #090502 100%);
      border-color: rgba(245, 158, 11, 0.35);
      box-shadow: 0 16px 36px -10px rgba(0, 0, 0, 0.95), inset 0 0 30px rgba(245, 158, 11, 0.1);
    }
    .neuraltrace-container.theme-emerald {
      background: radial-gradient(circle at 50% 50%, #062316 0%, #020b06 100%);
      border-color: rgba(16, 185, 129, 0.35);
      box-shadow: 0 16px 36px -10px rgba(0, 0, 0, 0.95), inset 0 0 30px rgba(16, 185, 129, 0.1);
    }
    .neuraltrace-svg {
      position: absolute;
      inset: 0;
      width: 100%;
      height: 100%;
      pointer-events: none;
      z-index: 5;
    }
    .neuraltrace-bg-grid {
      position: absolute;
      inset: 0;
      background-image: 
        linear-gradient(rgba(56, 189, 248, 0.04) 1px, transparent 1px),
        linear-gradient(90deg, rgba(56, 189, 248, 0.04) 1px, transparent 1px);
      background-size: 20px 20px;
      pointer-events: none;
      z-index: 1;
    }
    .neuraltrace-edge {
      stroke: rgba(148, 163, 184, 0.16);
      stroke-width: 1.5px;
      stroke-linecap: round;
      transition: stroke 0.25s ease, stroke-width 0.25s ease;
    }
    .neuraltrace-edge-active {
      stroke: #06b6d4;
      stroke-width: 3.5px;
      stroke-linecap: round;
      stroke-linejoin: round;
      filter: drop-shadow(0 0 8px rgba(6, 182, 212, 0.9));
    }
    .neuraltrace-container.theme-cyber .neuraltrace-edge-active,
    .neuraltrace-container.theme-red .neuraltrace-edge-active {
      stroke: #a855f7;
      filter: drop-shadow(0 0 8px rgba(168, 85, 247, 0.9));
    }
    .neuraltrace-container.theme-sky .neuraltrace-edge-active {
      stroke: #38bdf8;
      filter: drop-shadow(0 0 8px rgba(56, 189, 248, 0.9));
    }
    .neuraltrace-container.theme-amber .neuraltrace-edge-active {
      stroke: #fbbf24;
      filter: drop-shadow(0 0 8px rgba(251, 191, 36, 0.9));
    }
    .neuraltrace-container.theme-emerald .neuraltrace-edge-active {
      stroke: #34d399;
      filter: drop-shadow(0 0 8px rgba(52, 211, 153, 0.9));
    }
    .neuraltrace-edge-reachable {
      stroke: rgba(56, 189, 248, 0.55);
      stroke-width: 2px;
      stroke-dasharray: 4 3;
      animation: neuralEdgePulse 1.2s infinite ease-in-out;
    }
    @keyframes neuralEdgePulse {
      0%, 100% { stroke-opacity: 0.35; }
      50% { stroke-opacity: 0.95; }
    }
    .neuraltrace-tracking-line {
      stroke: rgba(6, 182, 212, 0.85);
      stroke-width: 2.5px;
      stroke-dasharray: 5 4;
      stroke-linecap: round;
      filter: drop-shadow(0 0 6px rgba(6, 182, 212, 0.7));
    }
    .neuraltrace-nodes-layer {
      position: absolute;
      inset: 0;
      z-index: 10;
    }
    .neuraltrace-node {
      position: absolute;
      width: 44px;
      height: 44px;
      transform: translate(-50%, -50%);
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      outline: none;
      border-radius: 50%;
      background: transparent;
      border: none;
      padding: 0;
      touch-action: none;
      transition: transform 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    }
    .neuraltrace-node:focus-visible .neuraltrace-node-ring {
      box-shadow: 0 0 0 3px #38bdf8, 0 0 20px #38bdf8;
    }
    .neuraltrace-node-ring {
      position: absolute;
      inset: 3px;
      border-radius: 50%;
      border: 1.5px solid rgba(148, 163, 184, 0.3);
      background: rgba(15, 23, 42, 0.75);
      backdrop-filter: blur(4px);
      transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.6);
    }
    .neuraltrace-node-core {
      position: relative;
      z-index: 2;
      display: flex;
      align-items: center;
      justify-content: center;
      width: 22px;
      height: 22px;
      border-radius: 50%;
      background: rgba(30, 41, 59, 0.9);
      color: #94a3b8;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 11px;
      font-weight: 700;
      line-height: 1;
      transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
      pointer-events: none;
    }
    .neuraltrace-node:hover .neuraltrace-node-ring {
      border-color: rgba(56, 189, 248, 0.7);
      box-shadow: 0 0 14px rgba(56, 189, 248, 0.4);
      transform: scale(1.08);
    }
    .neuraltrace-node:hover .neuraltrace-node-core {
      color: #f8fafc;
    }
    .neuraltrace-node.reachable .neuraltrace-node-ring {
      border-color: rgba(56, 189, 248, 0.8);
      box-shadow: 0 0 16px rgba(56, 189, 248, 0.45);
      animation: neuralReachablePulse 1.5s infinite;
    }
    @keyframes neuralReachablePulse {
      0%, 100% { transform: scale(1); box-shadow: 0 0 12px rgba(56, 189, 248, 0.3); }
      50% { transform: scale(1.1); box-shadow: 0 0 20px rgba(56, 189, 248, 0.6); }
    }
    .neuraltrace-node.selected .neuraltrace-node-ring {
      border-color: #06b6d4;
      background: rgba(6, 182, 212, 0.25);
      box-shadow: 0 0 18px rgba(6, 182, 212, 0.7);
      transform: scale(1.15);
    }
    .neuraltrace-node.selected .neuraltrace-node-core {
      background: #06b6d4;
      color: #030712;
      box-shadow: 0 0 10px #06b6d4;
    }
    .neuraltrace-node.head .neuraltrace-node-ring {
      border-color: #38bdf8;
      background: rgba(56, 189, 248, 0.35);
      box-shadow: 0 0 25px rgba(56, 189, 248, 0.9);
      animation: neuralHeadPulse 1s infinite alternate;
    }
    @keyframes neuralHeadPulse {
      0% { transform: scale(1.15); }
      100% { transform: scale(1.25); box-shadow: 0 0 30px rgba(56, 189, 248, 1); }
    }
    .neuraltrace-container.theme-cyber .neuraltrace-node.selected .neuraltrace-node-ring,
    .neuraltrace-container.theme-red .neuraltrace-node.selected .neuraltrace-node-ring {
      border-color: #a855f7;
      background: rgba(168, 85, 247, 0.25);
      box-shadow: 0 0 18px rgba(168, 85, 247, 0.7);
    }
    .neuraltrace-container.theme-cyber .neuraltrace-node.selected .neuraltrace-node-core,
    .neuraltrace-container.theme-red .neuraltrace-node.selected .neuraltrace-node-core {
      background: #a855f7;
      color: #ffffff;
      box-shadow: 0 0 10px #a855f7;
    }
    .neuraltrace-container.theme-sky .neuraltrace-node.selected .neuraltrace-node-ring {
      border-color: #38bdf8;
      background: rgba(56, 189, 248, 0.25);
      box-shadow: 0 0 18px rgba(56, 189, 248, 0.7);
    }
    .neuraltrace-container.theme-sky .neuraltrace-node.selected .neuraltrace-node-core {
      background: #38bdf8;
      color: #082f49;
      box-shadow: 0 0 10px #38bdf8;
    }
    .neuraltrace-container.theme-amber .neuraltrace-node.selected .neuraltrace-node-ring {
      border-color: #fbbf24;
      background: rgba(251, 191, 36, 0.25);
      box-shadow: 0 0 18px rgba(251, 191, 36, 0.7);
    }
    .neuraltrace-container.theme-amber .neuraltrace-node.selected .neuraltrace-node-core {
      background: #fbbf24;
      color: #451a03;
      box-shadow: 0 0 10px #fbbf24;
    }
    .neuraltrace-container.theme-emerald .neuraltrace-node.selected .neuraltrace-node-ring {
      border-color: #34d399;
      background: rgba(52, 211, 153, 0.25);
      box-shadow: 0 0 18px rgba(52, 211, 153, 0.7);
    }
    .neuraltrace-container.theme-emerald .neuraltrace-node.selected .neuraltrace-node-core {
      background: #34d399;
      color: #064e3b;
      box-shadow: 0 0 10px #34d399;
    }
    @keyframes neuralShake {
      0%, 100% { transform: translateX(0); }
      20%, 60% { transform: translateX(-7px); }
      40%, 80% { transform: translateX(7px); }
    }
    .neuraltrace-container.animate-shake {
      animation: neuralShake 0.4s ease-in-out;
      border-color: #ef4444 !important;
      box-shadow: 0 0 30px rgba(239, 68, 68, 0.7) !important;
    }
    @keyframes neuralSuccessPulse {
      0% { transform: scale(1); filter: brightness(1); }
      50% { transform: scale(1.025); filter: brightness(1.25) drop-shadow(0 0 20px rgba(52, 211, 153, 0.9)); }
      100% { transform: scale(1); filter: brightness(1); }
    }
    .neuraltrace-container.animate-success {
      animation: neuralSuccessPulse 0.5s ease-out;
      border-color: #10b981 !important;
    }
    .neuraltrace-node.blocked .neuraltrace-node-ring {
      border-color: #ef4444 !important;
      background: rgba(239, 68, 68, 0.35) !important;
      box-shadow: 0 0 20px rgba(239, 68, 68, 0.9) !important;
      transform: scale(1.18) !important;
    }
    .neuraltrace-node.blocked .neuraltrace-node-core {
      background: #ef4444 !important;
      color: #ffffff !important;
      box-shadow: 0 0 12px #ef4444 !important;
    }
    @media (prefers-reduced-motion: reduce) {
      .neuraltrace-container,
      .neuraltrace-node,
      .neuraltrace-edge,
      .neuraltrace-edge-active,
      .neuraltrace-edge-reachable,
      .neuraltrace-tracking-line {
        transition: none !important;
        animation: none !important;
      }
    }
  `;
  document.head.appendChild(style);
}

/**
 * NEURALTRACE — Reconstruct the Signal
 * Interactive Graph-Tracing Cybersecurity Factor Authentication Component
 * Canonical 14-Node Constellation with Strict Graph-Edge Traversal
 */
class NeuralTraceAuth {
  constructor(container, options = {}) {
    this.container = typeof container === 'string' ? document.getElementById(container) : container;
    if (!this.container) {
      console.warn('[NeuralTraceAuth] Container not found:', container);
      return;
    }

    ensureGestureStylesInjected();

    this.options = Object.assign({
      minNodes: 4,
      maxNodes: 14,
      theme: 'theme-cyber',
      disabled: false,
      extraClass: '',
      onPatternChange: null,
      onPatternComplete: null,
      onPatternTooShort: null,
      onReset: null
    }, options);

    // Canonical 14-Node Constellation
    this.nodes = [
      { id: 0, x: 45, y: 65, glyph: 'α', name: 'Alpha', layer: 0 },
      { id: 1, x: 40, y: 170, glyph: 'β', name: 'Beta', layer: 0 },
      { id: 2, x: 45, y: 275, glyph: 'γ', name: 'Gamma', layer: 0 },

      { id: 3, x: 130, y: 70, glyph: 'δ', name: 'Delta', layer: 1 },
      { id: 4, x: 130, y: 170, glyph: 'ε', name: 'Epsilon', layer: 1 },
      { id: 5, x: 130, y: 270, glyph: 'ζ', name: 'Zeta', layer: 1 },

      { id: 6, x: 215, y: 45, glyph: 'η', name: 'Eta', layer: 2 },
      { id: 7, x: 220, y: 125, glyph: 'θ', name: 'Theta', layer: 2 },
      { id: 8, x: 220, y: 215, glyph: 'ι', name: 'Iota', layer: 2 },
      { id: 9, x: 215, y: 295, glyph: 'κ', name: 'Kappa', layer: 2 },

      { id: 10, x: 315, y: 55, glyph: 'λ', name: 'Lambda', layer: 3 },
      { id: 11, x: 315, y: 135, glyph: 'μ', name: 'Mu', layer: 3 },
      { id: 12, x: 315, y: 215, glyph: 'ν', name: 'Nu', layer: 3 },
      { id: 13, x: 315, y: 295, glyph: 'ξ', name: 'Xi', layer: 3 }
    ];

    // Canonical 28 Undirected Edges
    this.edges = [
      [0, 3], [0, 4], [1, 3], [1, 4], [1, 5], [2, 4], [2, 5],
      [3, 4], [4, 5], [3, 6], [3, 7], [4, 7], [4, 8], [5, 8], [5, 9],
      [6, 7], [7, 8], [8, 9], [6, 10], [7, 10], [7, 11], [8, 11], [8, 12], [9, 12], [9, 13],
      [10, 11], [11, 12], [12, 13]
    ];

    // Build Adjacency Map for O(1) edge validation
    this.adj = {};
    for (let i = 0; i < 14; i++) {
      this.adj[i] = new Set();
    }
    for (const [u, v] of this.edges) {
      this.adj[u].add(v);
      this.adj[v].add(u);
    }

    this.pattern = [];
    this.isDrawing = false;
    this.activePointerId = null;
    this.lastPointerPos = null;
    this.container._neuralTraceInstance = this;

    this.initDOM();
    this.attachEvents();
  }

  initDOM() {
    this.container.innerHTML = '';
    this.container.className = `neuraltrace-container ${this.options.theme} ${this.options.extraClass || ''}`.trim();
    this.container.setAttribute('role', 'region');
    this.container.setAttribute('aria-label', 'NeuralTrace Signal Reconstruction Graph');

    // Ambient Cyber Grid
    const bgGrid = document.createElement('div');
    bgGrid.className = 'neuraltrace-bg-grid';
    this.container.appendChild(bgGrid);

    // SVG Layer for graph edges & dynamic signal line
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('class', 'neuraltrace-svg');
    svg.setAttribute('viewBox', '0 0 360 340');

    // Static Network Edges
    let edgesHtml = '';
    for (const [u, v] of this.edges) {
      const p1 = this.nodes[u];
      const p2 = this.nodes[v];
      edgesHtml += `<line class="neuraltrace-edge" data-edge="${Math.min(u, v)}-${Math.max(u, v)}" x1="${p1.x}" y1="${p1.y}" x2="${p2.x}" y2="${p2.y}"></line>`;
    }

    // Dynamic Tracking Line
    edgesHtml += `<line class="neuraltrace-tracking-line" x1="0" y1="0" x2="0" y2="0" style="display:none"></line>`;

    svg.innerHTML = edgesHtml;
    this.container.appendChild(svg);
    this.svg = svg;
    this.trackingLine = svg.querySelector('.neuraltrace-tracking-line');

    // Nodes HTML Layer
    const nodesLayer = document.createElement('div');
    nodesLayer.className = 'neuraltrace-nodes-layer';

    this.nodeElements = [];
    for (let i = 0; i < 14; i++) {
      const node = this.nodes[i];
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'neuraltrace-node';
      btn.dataset.node = String(i);
      btn.setAttribute('aria-label', `Neural node ${node.name} (${node.glyph}), Stage ${node.layer + 1}`);
      btn.style.left = `${(node.x / 360) * 100}%`;
      btn.style.top = `${(node.y / 340) * 100}%`;
      btn.innerHTML = `<span class="neuraltrace-node-ring"></span><span class="neuraltrace-node-core">${node.glyph}</span>`;
      nodesLayer.appendChild(btn);
      this.nodeElements.push(btn);
    }
    this.container.appendChild(nodesLayer);
  }

  attachEvents() {
    this.container.addEventListener('pointerdown', (e) => this.handlePointerDown(e), { passive: false });
    this.container.addEventListener('pointermove', (e) => this.handlePointerMove(e), { passive: false });
    this.container.addEventListener('pointerup', (e) => this.handlePointerUp(e));
    this.container.addEventListener('pointercancel', (e) => this.handlePointerCancel(e));
    this.container.addEventListener('contextmenu', (e) => e.preventDefault());

    // Enhanced touch listeners to guarantee smooth mobile dragging and prevent accidental page scrolling
    this.container.addEventListener('touchmove', (e) => {
      if (this.isDrawing && e.touches && e.touches.length > 0) {
        if (e.cancelable) e.preventDefault();
        const touch = e.touches[0];
        this.checkHitNode(touch.clientX, touch.clientY);
        this.updateActiveTrackingLine(touch.clientX, touch.clientY);
        this.lastPointerPos = { x: touch.clientX, y: touch.clientY };
      }
    }, { passive: false });

    this.container.addEventListener('touchend', (e) => {
      if (this.isDrawing) {
        this.finishDrawing();
      }
    });

    this.container.addEventListener('touchcancel', (e) => {
      if (this.isDrawing) {
        this.finishDrawing();
      }
    });

    this.nodeElements.forEach((btn, idx) => {
      btn.addEventListener('keydown', (e) => {
        if (this.options.disabled) return;
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          this.addNode(idx);
          if (this.pattern.length >= this.options.minNodes && typeof this.options.onPatternComplete === 'function') {
            this.options.onPatternComplete(this.getPattern());
          }
        } else if (e.key === 'Escape' || e.key === 'Backspace') {
          e.preventDefault();
          this.reset();
        } else if (e.key.startsWith('Arrow')) {
          e.preventDefault();
          this.navigateKeyboardArrow(idx, e.key);
        }
      });
    });
  }

  navigateKeyboardArrow(currentIdx, arrowKey) {
    const neighbors = Array.from(this.adj[currentIdx] || []);
    if (neighbors.length === 0) return;
    const curPos = this.nodes[currentIdx];

    let bestNeighbor = neighbors[0];
    let bestScore = -Infinity;

    for (const nb of neighbors) {
      const pos = this.nodes[nb];
      const dx = pos.x - curPos.x;
      const dy = pos.y - curPos.y;
      let score = 0;
      if (arrowKey === 'ArrowRight') score = dx;
      else if (arrowKey === 'ArrowLeft') score = -dx;
      else if (arrowKey === 'ArrowDown') score = dy;
      else if (arrowKey === 'ArrowUp') score = -dy;

      if (score > bestScore) {
        bestScore = score;
        bestNeighbor = nb;
      }
    }

    if (this.nodeElements[bestNeighbor]) {
      this.nodeElements[bestNeighbor].focus();
    }
  }

  setTheme(theme) {
    this.options.theme = theme;
    this.container.className = `neuraltrace-container ${theme} ${this.options.extraClass || ''}`.trim();
  }

  handlePointerDown(e) {
    if (this.options.disabled) return;
    if (e.button !== undefined && e.button !== 0) return;
    e.preventDefault();

    this.activePointerId = e.pointerId;
    this.lastPointerPos = { x: e.clientX, y: e.clientY };
    try {
      this.container.setPointerCapture(e.pointerId);
    } catch (_) {}

    // Hit test starting node
    let hitNode = null;
    for (let i = 0; i < 14; i++) {
      const btn = this.nodeElements[i];
      const rect = btn.getBoundingClientRect();
      const cx = rect.left + rect.width / 2;
      const cy = rect.top + rect.height / 2;
      if (Math.hypot(e.clientX - cx, e.clientY - cy) <= 28) {
        hitNode = i;
        break;
      }
    }

    if (hitNode !== null) {
      if (this.pattern.length > 0) {
        const last = this.pattern[this.pattern.length - 1];
        if (this.adj[last].has(hitNode) && !this.pattern.includes(hitNode)) {
          // Connected neighbor tapped: continue existing route!
          this.isDrawing = true;
          this.addNode(hitNode);
          this.updateActiveTrackingLine(e.clientX, e.clientY);
          return;
        }
      }
      // Start a fresh route from this pressed node
      this.reset(false);
      this.isDrawing = true;
      this.addNode(hitNode);
      this.updateActiveTrackingLine(e.clientX, e.clientY);
    } else {
      if (this.pattern.length === 0) {
        this.isDrawing = true;
      }
    }
  }

  handlePointerMove(e) {
    if (!this.isDrawing || this.options.disabled) return;
    if (this.activePointerId !== null && e.pointerId !== this.activePointerId) return;
    e.preventDefault();

    this.checkHitNode(e.clientX, e.clientY);
    this.updateActiveTrackingLine(e.clientX, e.clientY);
    this.lastPointerPos = { x: e.clientX, y: e.clientY };
  }

  handlePointerUp(e) {
    if (!this.isDrawing) return;
    if (this.activePointerId !== null && e.pointerId !== this.activePointerId) return;
    this.finishDrawing();
  }

  handlePointerCancel(e) {
    if (!this.isDrawing) return;
    this.finishDrawing();
  }

  finishDrawing() {
    this.isDrawing = false;
    if (this.activePointerId !== null) {
      try {
        this.container.releasePointerCapture(this.activePointerId);
      } catch (_) {}
    }
    this.activePointerId = null;
    this.lastPointerPos = null;
    if (this.trackingLine) this.trackingLine.style.display = 'none';

    // Clear reachable pulsing hints when drawing ends
    this.nodeElements.forEach(btn => btn.classList.remove('reachable'));
    const reachableEdges = this.container.querySelectorAll('.neuraltrace-edge-reachable');
    reachableEdges.forEach(el => el.classList.remove('neuraltrace-edge-reachable'));

    if (this.pattern.length === 0) return;

    if (this.pattern.length < this.options.minNodes) {
      this.triggerShake();
      if (typeof this.options.onPatternTooShort === 'function') {
        this.options.onPatternTooShort(this.getPattern());
      }
    } else {
      this.triggerSuccess();
      if (typeof this.options.onPatternComplete === 'function') {
        this.options.onPatternComplete(this.getPattern());
      }
    }
  }

  checkHitNode(clientX, clientY) {
    if (this.pattern.length === 0) {
      for (let i = 0; i < 14; i++) {
        const btn = this.nodeElements[i];
        const rect = btn.getBoundingClientRect();
        const cx = rect.left + rect.width / 2;
        const cy = rect.top + rect.height / 2;
        const dist = Math.hypot(clientX - cx, clientY - cy);
        if (dist <= 28) {
          this.addNode(i);
          break;
        }
      }
      return;
    }

    // While drawing with an active route, search connected unvisited neighbors
    let added = true;
    while (added) {
      added = false;
      const last = this.pattern[this.pattern.length - 1];
      const neighbors = Array.from(this.adj[last] || []);
      const unvisited = neighbors.filter(nb => !this.pattern.includes(nb));

      let bestNeighbor = null;
      let minDistance = Infinity;

      for (const nb of unvisited) {
        const btn = this.nodeElements[nb];
        const rect = btn.getBoundingClientRect();
        const cx = rect.left + rect.width / 2;
        const cy = rect.top + rect.height / 2;

        let dist = Math.hypot(clientX - cx, clientY - cy);
        if (this.lastPointerPos) {
          const segDist = this.distToSegment(cx, cy, this.lastPointerPos.x, this.lastPointerPos.y, clientX, clientY);
          dist = Math.min(dist, segDist);
        }

        if (dist <= 28 && dist < minDistance) {
          minDistance = dist;
          bestNeighbor = nb;
        }
      }

      if (bestNeighbor !== null) {
        this.addNode(bestNeighbor);
        added = true; // Repeat to process intermediate nodes on fast swipe
      }
    }

    // Check if pointer is hovering over a non-connected/invalid node to show subtle feedback
    for (let i = 0; i < 14; i++) {
      if (this.pattern.includes(i)) continue;
      const last = this.pattern[this.pattern.length - 1];
      if (this.adj[last] && this.adj[last].has(i)) continue;

      const btn = this.nodeElements[i];
      const rect = btn.getBoundingClientRect();
      const cx = rect.left + rect.width / 2;
      const cy = rect.top + rect.height / 2;
      let dist = Math.hypot(clientX - cx, clientY - cy);
      if (this.lastPointerPos) {
        const segDist = this.distToSegment(cx, cy, this.lastPointerPos.x, this.lastPointerPos.y, clientX, clientY);
        dist = Math.min(dist, segDist);
      }

      if (dist <= 24) {
        this.triggerBlockedFeedback(i);
        break;
      }
    }
  }

  distToSegment(px, py, x1, y1, x2, y2) {
    const dx = x2 - x1;
    const dy = y2 - y1;
    const l2 = dx * dx + dy * dy;
    if (l2 === 0) return Math.hypot(px - x1, py - y1);
    let t = ((px - x1) * dx + (py - y1) * dy) / l2;
    t = Math.max(0, Math.min(1, t));
    return Math.hypot(px - (x1 + t * dx), py - (y1 + t * dy));
  }

  triggerBlockedFeedback(nodeIdx) {
    const el = this.nodeElements[nodeIdx];
    if (!el || el.classList.contains('blocked')) return;
    el.classList.add('blocked');
    setTimeout(() => {
      el.classList.remove('blocked');
    }, 280);
  }

  addNode(idx) {
    idx = Number(idx);
    if (isNaN(idx) || idx < 0 || idx >= 14) return;
    if (this.pattern.includes(idx)) return;

    // Strict graph-edge verification: only connected neighbors allowed!
    if (this.pattern.length > 0) {
      const last = this.pattern[this.pattern.length - 1];
      if (!this.adj[last].has(idx)) {
        this.triggerBlockedFeedback(idx);
        return;
      }
    }

    // Valid node addition
    const prevNode = this.pattern.length > 0 ? this.pattern[this.pattern.length - 1] : null;
    this.pattern.push(idx);

    // Update node styles
    this.nodeElements.forEach(btn => btn.classList.remove('head'));
    this.nodeElements[idx].classList.add('selected', 'head');

    // Highlight traversed edge
    if (prevNode !== null) {
      const edgeKey = `${Math.min(prevNode, idx)}-${Math.max(prevNode, idx)}`;
      const edgeEl = this.container.querySelector(`[data-edge="${edgeKey}"]`);
      if (edgeEl) {
        edgeEl.classList.add('neuraltrace-edge-active');
        edgeEl.classList.remove('neuraltrace-edge-reachable');
      }
    }

    // Update reachable hints for next hop
    this.updateReachableHints(idx);

    if (typeof navigator !== 'undefined' && navigator.vibrate) {
      try { navigator.vibrate(12); } catch (_) {}
    }

    if (typeof this.options.onPatternChange === 'function') {
      this.options.onPatternChange(this.getPattern());
    }
  }

  updateReachableHints(currentIdx) {
    // Clear old reachable states
    this.nodeElements.forEach(btn => btn.classList.remove('reachable'));
    const oldEdges = this.container.querySelectorAll('.neuraltrace-edge-reachable');
    oldEdges.forEach(el => el.classList.remove('neuraltrace-edge-reachable'));

    const neighbors = this.adj[currentIdx] || new Set();
    neighbors.forEach(nb => {
      if (!this.pattern.includes(nb)) {
        this.nodeElements[nb].classList.add('reachable');
        const edgeKey = `${Math.min(currentIdx, nb)}-${Math.max(currentIdx, nb)}`;
        const edgeEl = this.container.querySelector(`[data-edge="${edgeKey}"]`);
        if (edgeEl && !edgeEl.classList.contains('neuraltrace-edge-active')) {
          edgeEl.classList.add('neuraltrace-edge-reachable');
        }
      }
    });
  }

  updateActiveTrackingLine(clientX, clientY) {
    if (!this.trackingLine || this.pattern.length === 0) {
      if (this.trackingLine) this.trackingLine.style.display = 'none';
      return;
    }
    const rect = this.container.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return;

    const lastId = this.pattern[this.pattern.length - 1];
    const lastCoord = this.nodes[lastId];

    const svgX = ((clientX - rect.left) / rect.width) * 360;
    const svgY = ((clientY - rect.top) / rect.height) * 340;

    this.trackingLine.setAttribute('x1', String(lastCoord.x));
    this.trackingLine.setAttribute('y1', String(lastCoord.y));
    this.trackingLine.setAttribute('x2', String(Math.max(0, Math.min(360, svgX))));
    this.trackingLine.setAttribute('y2', String(Math.max(0, Math.min(340, svgY))));
    this.trackingLine.style.display = 'block';
  }

  triggerShake() {
    this.container.classList.remove('animate-shake');
    void this.container.offsetWidth;
    this.container.classList.add('animate-shake');
    setTimeout(() => {
      this.container.classList.remove('animate-shake');
    }, 450);
  }

  triggerSuccess() {
    this.container.classList.remove('animate-success');
    void this.container.offsetWidth;
    this.container.classList.add('animate-success');
    setTimeout(() => {
      this.container.classList.remove('animate-success');
    }, 550);
  }

  reset(triggerCallback = true) {
    this.pattern = [];
    this.isDrawing = false;
    this.lastPointerPos = null;
    if (this.nodeElements) {
      this.nodeElements.forEach(btn => btn.classList.remove('selected', 'head', 'reachable', 'blocked'));
    }
    const activeEdges = this.container.querySelectorAll('.neuraltrace-edge-active, .neuraltrace-edge-reachable');
    activeEdges.forEach(el => el.classList.remove('neuraltrace-edge-active', 'neuraltrace-edge-reachable'));

    if (this.trackingLine) this.trackingLine.style.display = 'none';

    if (triggerCallback && typeof this.options.onReset === 'function') {
      this.options.onReset();
    }
    if (triggerCallback && typeof this.options.onPatternChange === 'function') {
      this.options.onPatternChange([]);
    }
  }

  getPattern() {
    return [...this.pattern];
  }

  setDisabled(disabled) {
    this.options.disabled = !!disabled;
    if (disabled) {
      this.container.style.opacity = '0.5';
      this.container.style.pointerEvents = 'none';
    } else {
      this.container.style.opacity = '1';
      this.container.style.pointerEvents = 'auto';
    }
  }
}

// Preserve backward-compatible alias for existing callers
const GesturePatternGrid = NeuralTraceAuth;

if (typeof window !== 'undefined') {
  window.NeuralTraceAuth = NeuralTraceAuth;
  window.GesturePatternGrid = NeuralTraceAuth;
  window.ensureGestureStylesInjected = ensureGestureStylesInjected;
}


class CognisecClient {
  constructor() {
    this.token = localStorage.getItem('cognisec_token') || null;
    this.user = JSON.parse(localStorage.getItem('cognisec_user') || 'null');
    this.sessionId = localStorage.getItem('cognisec_session_id') || null;
    this.application = 'platform';
    this.observationDurationSeconds = COGNISEC_OBSERVATION_SECONDS;
    this._obsTimer = null;
    this._isRequestingOtp = false;
    this._challengeReqSeq = 0;
    this._activeChallengeId = null;

    // Telemetry capture buffers (non-sensitive metrics)
    this.keyPressTimings = [];
    this.dwellTimings = [];
    this.activeKeyDowns = new Map();
    this.mousePoints = [];
    this.scrollSpeeds = [];
    this.navigationHistory = [];
    this.lastInteractionTime = null;
    this.hasRealInteraction = false;
    this.lastTelemetryDispatchTime = null;
    this.clickCount = 0;
    this.scrollDeltaSum = 0;
    this.telemetryInterval = null;
    this.sequenceNumber = parseInt(localStorage.getItem('cognisec_seq_' + (this.sessionId || '')) || '0', 10);

    // Step-up lifecycle & state synchronization
    this.sessionStatus = localStorage.getItem('cognisec_session_status') || 'ACTIVE';
    this.currentChallenge = null;
    this.currentChallengeExpiresAt = null;
    this.lastStepUpVerifiedAt = 0;
    this.lastStepUpVerifiedSessionId = null;
    this.isStepUpModalOpen = false;
    this.isStepUpSubmitting = false;
    this.authorizedResources = new Set();
    this.currentTargetResource = null;
    this.stepUpSuccessCallback = null;
    this.wasLastStepUpSuccessful = false;
    this.factorEnrollState = {
      tab: 'image',
      step: 1,
      initialSeq: [],
      confirmSeq: [],
      catalogue: []
    };

    this.initPassiveCollectors();
    this.validateSessionOnStartup();
  }

  get isStepUpModalOpen() {
    const modal = document.getElementById('modal-stepup');
    if (!modal) return Boolean(this._isStepUpModalOpen);
    return !modal.classList.contains('hidden');
  }

  set isStepUpModalOpen(val) {
    this._isStepUpModalOpen = Boolean(val);
  }

  isResourceAuthorized(resource) {
    if (!resource || !this.sessionId || this.sessionStatus !== 'ACTIVE') return false;
    if (!this.authorizedResources || !this.sessionId || !resource) return false;
    const app = this.application || 'platform';
    return this.authorizedResources.has(`${app}:${resource}:${this.sessionId}`);
  }

  grantResourceClearance(resource) {
    if (!resource || !this.sessionId) return;
    if (resource === '*') return; // Reject wildcard clearance bypass
    if (!this.authorizedResources) this.authorizedResources = new Set();
    const app = this.application || 'platform';
    this.authorizedResources.add(`${app}:${resource}:${this.sessionId}`);
  }

  revokeResourceClearance(resource = null) {
    if (!this.authorizedResources) return;
    if (resource) {
      const app = this.application || 'platform';
      this.authorizedResources.delete(`${app}:${resource}:${this.sessionId}`);
      this.authorizedResources.delete(resource);
      this.authorizedResources.delete(`${this.sessionId}:${resource}`);
    } else {
      this.authorizedResources.clear();
    }
  }

  async checkResourceAccess(resource) {
    if (!this.token || !this.sessionId) {
      return { access_granted: false, decision: 'UNAUTHENTICATED', message: 'You are not signed in. Please sign in to continue.' };
    }
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/security/access-decision`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({
          session_id: this.sessionId,
          resource: resource,
          application: this.application || 'platform'
        })
      });
      if (res.ok) {
        const data = await res.json();
        if (data.session_status) {
          this.sessionStatus = data.session_status;
        }
        if (data.access_granted) {
          this.grantResourceClearance(resource);
        } else {
          this.revokeResourceClearance(resource);
        }
        console.info('[COGNISEC-AI][vault] access-decision', { resource, decision: data.decision, risk_level: data.risk_level, verification_required: data.verification_required, required_factor: data.required_factor });
        return data;
      }
      this.revokeResourceClearance(resource);
      let detail = '';
      try { const err = await res.json(); detail = typeof err.detail === 'string' ? err.detail : ''; } catch (_) {}
      console.warn('[COGNISEC-AI][vault] access-decision HTTP', res.status, detail);
      if (res.status === 401 || res.status === 403) {
        return { access_granted: false, decision: 'UNAUTHENTICATED', http_status: res.status, message: detail || 'Your session has expired or is no longer valid. Please sign in again.' };
      }
      return { access_granted: false, decision: 'ERROR', http_status: res.status, message: detail || `The security server returned an error (HTTP ${res.status}). Please retry.` };
    } catch (e) {
      console.warn('[COGNISEC-AI][vault] Server access-decision query failed:', e);
      this.revokeResourceClearance(resource);
      return { access_granted: false, decision: 'ERROR', message: 'Could not reach the security server. Check that the backend is running, then retry.' };
    }
  }


  // Persistent, in-page confidential-access notice (shared by college / shopping / healthcare).
  // Toasts vanish after ~3.5s; this stays visible until the next attempt so a denial is never silent.
  clearVaultAccessNotice() {
    const old = document.getElementById('vault-access-status');
    if (old) old.remove();
  }

  showVaultAccessNotice({ anchorId, title, message, tone = 'warn', actions = [] } = {}) {
    this.clearVaultAccessNotice();
    const anchor = anchorId ? document.getElementById(anchorId) : null;
    const box = document.createElement('div');
    box.id = 'vault-access-status';
    box.setAttribute('role', 'alert');
    const palette = tone === 'error'
      ? { bg: '#fef2f2', bd: '#fca5a5', fg: '#7f1d1d' }
      : tone === 'info'
        ? { bg: '#eff6ff', bd: '#93c5fd', fg: '#1e3a8a' }
        : { bg: '#fffbeb', bd: '#fcd34d', fg: '#78350f' };
    box.style.cssText = `margin:12px 0;padding:12px 14px;border-radius:12px;border:1px solid ${palette.bd};background:${palette.bg};color:${palette.fg};font:600 12px/1.5 ui-monospace,Menlo,monospace;text-align:left;`;
    const h = document.createElement('div');
    h.style.cssText = 'font-weight:800;margin-bottom:4px;text-transform:uppercase;letter-spacing:.04em;';
    h.textContent = title || 'Confidential access';
    const p = document.createElement('div');
    p.style.cssText = 'font-weight:500;';
    p.textContent = message || '';
    box.appendChild(h);
    box.appendChild(p);
    if (actions.length) {
      const row = document.createElement('div');
      row.style.cssText = 'display:flex;gap:8px;margin-top:10px;flex-wrap:wrap;';
      actions.forEach((a) => {
        const b = document.createElement('button');
        b.type = 'button';
        b.textContent = a.label;
        b.style.cssText = `padding:6px 12px;border-radius:8px;border:1px solid ${palette.bd};background:#fff;color:${palette.fg};font:700 11px ui-monospace,Menlo,monospace;cursor:pointer;`;
        b.addEventListener('click', () => { try { a.onClick && a.onClick(); } catch (e) { console.error(e); } });
        row.appendChild(b);
      });
      box.appendChild(row);
    }
    if (anchor && anchor.parentNode) anchor.parentNode.insertBefore(box, anchor);
    else document.body.insertBefore(box, document.body.firstChild);
    box.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    return box;
  }

  getDefaultResourceForApp(app) {
    const normalized = (app || '').toLowerCase().trim();
    if (normalized === 'college') return 'academic_vault';
    if (normalized === 'shopping') return 'financial_vault';
    if (normalized === 'healthcare') return 'ehr_vault';
    return null;
  }

  async relockVault(resource = null) {
    const targetResource = resource || this.getDefaultResourceForApp(this.application);
    if (!targetResource) return { success: false, message: 'No target resource specified' };

    // 1. Immediately revoke in-memory authorization clearance
    this.revokeResourceClearance(targetResource);

    // 2. Clear any cached responses in memory
    if (this._vaultCache) {
      delete this._vaultCache[targetResource];
    }

    // 3. Authoritative server-side revocation
    if (this.token && this.sessionId) {
      try {
        const payload = JSON.stringify({
          session_id: this.sessionId,
          resource: targetResource,
          application: this.application || 'platform'
        });

        const res = await fetch(`${COGNISEC_API_BASE}/security/vault/relock`, {
          method: 'POST',
          headers: this.getHeaders(),
          body: payload,
          keepalive: true
        });

        if (res.ok) {
          const data = await res.json();
          console.info('[COGNISEC-AI][vault] Server-enforced relock completed for', targetResource, data);
          window.dispatchEvent(new CustomEvent('cognisec:vault_relocked', { detail: { resource: targetResource } }));
          return data;
        }
      } catch (err) {
        console.warn('[COGNISEC-AI][vault] Failed to contact server for relock:', err);
      }
    }

    window.dispatchEvent(new CustomEvent('cognisec:vault_relocked', { detail: { resource: targetResource } }));
    return { success: true, vault_status: 'LOCKED', resource: targetResource };
  }

  async signOutAndRestart() {
    try { await this.logout(); } catch (_) { try { this.clearAuth(); } catch (__) {} }
    window.location.reload();
  }

  async fetchVaultData(resource) {
    if (!this.token || !this.sessionId) {
      throw new Error("Unauthenticated");
    }
    const res = await fetch(`${COGNISEC_API_BASE}/security/vault/${encodeURIComponent(resource)}?session_id=${encodeURIComponent(this.sessionId)}`, {
      method: 'GET',
      headers: this.getHeaders(),
      cache: 'no-store'
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      this.revokeResourceClearance(resource);
      throw new Error(err.detail || "Vault access denied by Zero Trust policy.");
    }
    return await res.json();
  }


  resetInteractionBuffers() {
    this.keyPressTimings = [];
    this.dwellTimings = [];
    this.activeKeyDowns.clear();
    this.mousePoints = [];
    this.scrollSpeeds = [];
    this.navigationHistory = [];
    this.lastInteractionTime = null;
    this.hasRealInteraction = false;
    this.lastTelemetryDispatchTime = null;
    this.clickCount = 0;
    this.scrollDeltaSum = 0;
    this.sequenceNumber = 0;
  }

  isSensitiveInput(target) {
    if (!target) return false;
    const type = (target.type || '').toLowerCase();
    if (type === 'password') return true;
    const id = (target.id || '').toLowerCase();
    if (id.includes('pass') || id.includes('otp') || id.includes('pin') || id.includes('secret') || id.includes('token') || id.includes('cvv') || id.includes('ssn') || id.includes('card')) return true;
    const name = (target.name || '').toLowerCase();
    if (name.includes('pass') || name.includes('otp') || name.includes('pin') || name.includes('secret') || name.includes('token') || name.includes('cvv') || name.includes('ssn') || name.includes('card')) return true;
    const autocomplete = (target.getAttribute && target.getAttribute('autocomplete') || '').toLowerCase();
    if (autocomplete === 'current-password' || autocomplete === 'new-password' || autocomplete === 'cc-number' || autocomplete === 'cc-csc' || autocomplete === 'one-time-code') return true;
    if (target.getAttribute && (target.getAttribute('data-sensitive') === 'true' || target.getAttribute('data-privacy') === 'exclude')) return true;
    if (target.dataset && (target.dataset.sensitive === 'true' || target.dataset.privacy === 'exclude')) return true;
    if (target.closest && target.closest('[data-privacy="exclude"], [data-sensitive="true"], .password-field, .otp-input-group')) return true;
    return false;
  }

  recordNavigationEvent(category) {
    if (!category || typeof category !== 'string') return;
    const clean = category.toLowerCase().replace(/[^a-z0-9_-]/g, '').substring(0, 30);
    if (!clean || clean === 'password') return;
    this.navigationHistory.push({ category: clean, t: Date.now() });
    this.hasRealInteraction = true;
    this.lastInteractionTime = Date.now();
    if (this.navigationHistory.length > 30) {
      this.navigationHistory.shift();
    }
  }

  setApplication(app) {
    let norm = (app || '').toLowerCase().trim();
    if (norm === 'ecommerce' || norm === 'nyraa' || norm === 'shopping_portal' || norm === 'retail') norm = 'shopping';
    if (norm === 'college_portal' || norm === 'academic' || norm === 'university') norm = 'college';
    if (norm === 'healthcare_portal' || norm === 'ehr' || norm === 'clinical' || norm === 'hospital') norm = 'healthcare';
    this.application = norm;
    this.recordNavigationEvent(`app_${norm}`);
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

  isFullyVerified() {
    const isSessionActive = (this.sessionStatus === 'ACTIVE' || localStorage.getItem('cognisec_session_status') === 'ACTIVE');
    return Boolean(this.token && this.user && isSessionActive);
  }

  maskEmail(email) {
    if (!email || typeof email !== 'string' || !email.includes('@')) {
      return '***@***.***';
    }
    const [local, domain] = email.trim().split('@');
    let maskedLocal = '*';
    if (local.length === 2) {
      maskedLocal = local[0] + '*';
    } else if (local.length > 2) {
      maskedLocal = local[0] + '***' + local[local.length - 1];
    }
    return `${maskedLocal}@${domain}`;
  }

  isPendingObservation() {
    return Boolean(this.token && this.user && (this.sessionStatus === 'PENDING_OBSERVATION' || this.sessionStatus === 'PENDING_OTP'));
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
        // Query observation status directly from server
        const obsStatus = await this.getObservationStatus(this.sessionId);

        if (!obsStatus) {
          // If observation endpoint fails, verify /me
          const meRes = await fetch(`${COGNISEC_API_BASE}/auth/me`, { headers: this.getHeaders() });
          if (!meRes.ok) {
            console.log('[COGNISEC-AI] [DIAGNOSTIC] Token expired or invalid on startup. Clearing authentication.');
            this.clearAuth();
            this.sessionExpiredMessage = 'Your previous session has expired. Please sign in to continue.';
            return;
          }
          const userProfile = await meRes.json();
          this.user = {
            id: userProfile.id,
            name: userProfile.name,
            email: userProfile.email,
            role: userProfile.role,
            account_status: userProfile.account_status || 'ACTIVE'
          };
          this.sessionStatus = this.user.account_status;
          localStorage.setItem('cognisec_user', JSON.stringify(this.user));
          this.startTelemetryLoop();
          window.dispatchEvent(new CustomEvent('cognisec:auth_change', {
            detail: { isAuthenticated: true, isFullyVerified: this.sessionStatus === 'ACTIVE', user: this.user }
          }));
          return;
        }

        if (obsStatus.status === 'TERMINATED') {
          console.log('[COGNISEC-AI] [DIAGNOSTIC] Session was terminated on server. Clearing authentication.');
          this.clearAuth();
          this.sessionExpiredMessage = 'Session was terminated. Please sign in to access protected resources.';
          return;
        }

        if (obsStatus.status === 'PENDING_OBSERVATION' || obsStatus.status === 'PENDING_OTP') {
          console.log(`[COGNISEC-AI] [DIAGNOSTIC] Resuming pending session ${this.sessionId} (${obsStatus.status}, ${obsStatus.observation_seconds_remaining}s remaining).`);
          this.sessionStatus = obsStatus.status;
          localStorage.setItem('cognisec_session_status', this.sessionStatus);
          if (this.user) {
            this.user.account_status = this.sessionStatus;
            localStorage.setItem('cognisec_user', JSON.stringify(this.user));
          }
          this.startTelemetryLoop();
          window.dispatchEvent(new CustomEvent('cognisec:auth_change', {
            detail: { isAuthenticated: true, isFullyVerified: false, user: this.user }
          }));

          // Seamlessly maintain background observation on the current page
          this.scheduleBackgroundOtpPrompt(obsStatus);
          return;
        }

        if (obsStatus.status === 'ACTIVE') {
          this.sessionStatus = 'ACTIVE';
          localStorage.setItem('cognisec_session_status', 'ACTIVE');
          if (this.user) {
            this.user.account_status = 'ACTIVE';
            localStorage.setItem('cognisec_user', JSON.stringify(this.user));
          }
          this.startTelemetryLoop();
          window.dispatchEvent(new CustomEvent('cognisec:auth_change', {
            detail: { isAuthenticated: true, isFullyVerified: true, user: this.user }
          }));
          return;
        }
      } catch (e) {
        console.warn('[COGNISEC-AI] Startup session validation warning:', e.message);
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
    this.sessionStatus = null;
    this.revokeResourceClearance();
    if (this._obsTimer) {
      clearTimeout(this._obsTimer);
      this._obsTimer = null;
    }
    localStorage.removeItem('cognisec_token');
    localStorage.removeItem('cognisec_session_id');
    localStorage.removeItem('cognisec_user');
    localStorage.removeItem('cognisec_obs_start');
    this.stopTelemetryLoop();
    this.resetInteractionBuffers();
    window.dispatchEvent(new CustomEvent('cognisec:auth_change', { detail: { isAuthenticated: false, user: null } }));
  }

  async login(email, password, application = 'platform', customFingerprint = null, locationData = null, nickname = null, options = {}) {
    try {
      const fingerprint = customFingerprint || await this.getDeviceFingerprint();
      const loginPayload = {
        email: email.trim(),
        password: password,
        application: application,
        device_fingerprint: fingerprint,
        browser: navigator.userAgent,
        os: navigator.platform,
        nickname: nickname || undefined,
        doctor_required: !!options.doctorRequired
      };

      if (locationData && locationData.latitude != null) {
        loginPayload.latitude = locationData.latitude;
        loginPayload.longitude = locationData.longitude;
        loginPayload.location_accuracy = locationData.accuracy;
        loginPayload.location_source = locationData.source || 'BROWSER_GEOLOCATION';
      }

      const res = await fetch(`${COGNISEC_API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(loginPayload)
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        let message = `Authentication failed with status ${res.status}`;
        if (err.detail) {
          if (Array.isArray(err.detail)) {
            message = err.detail.map(d => (d.msg || d.message || '').replace(/^Value error,\s*/i, '')).filter(Boolean).join('. ') || message;
          } else if (typeof err.detail === 'string') {
            message = err.detail;
          }
        }
        const customErr = new Error(message);
        customErr.raw = err;
        throw customErr;
      }

      const data = await res.json();
      this.token = data.access_token;
      this.sessionId = data.session_id;
      this.sequenceNumber = parseInt(localStorage.getItem('cognisec_seq_' + (this.sessionId || '')) || '0', 10);
      const isSessionActive = data.session_status === 'ACTIVE';
      this.sessionStatus = data.session_status || 'PENDING_OBSERVATION';
      this.user = {
        id: data.user_id,
        name: data.name,
        email: data.email,
        role: data.role,
        account_status: this.sessionStatus
      };

      localStorage.setItem('cognisec_token', this.token);
      localStorage.setItem('cognisec_session_id', this.sessionId);
      localStorage.setItem('cognisec_user', JSON.stringify(this.user));
      localStorage.setItem('cognisec_session_status', this.sessionStatus);

      this.resetInteractionBuffers();
      this.startTelemetryLoop();
      window.dispatchEvent(new CustomEvent('cognisec:auth_change', {
        detail: { isAuthenticated: true, isFullyVerified: isSessionActive, user: this.user }
      }));
      return { success: true, data };
    } catch (error) {
      console.warn('[COGNISEC-AI] Login error:', error.message);
      return { success: false, error: error.message, details: error.raw ? error.raw.detail : null };
    }
  }

  async loginDoctor(email, password, customFingerprint = null, locationData = null, nickname = null) {
    return await this.login(email, password, 'healthcare', customFingerprint, locationData, nickname, { doctorRequired: true });
  }

  // --- HEALTHCARE PORTAL & APPOINTMENT SERVICES ---
  async fetchHealthcareDepartments() {
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/healthcare/departments`);
      if (!res.ok) return [];
      return await res.json();
    } catch (e) {
      console.warn('[COGNISEC-AI] Failed to fetch departments:', e);
      return [];
    }
  }

  async fetchHealthcareDoctors(dept = null) {
    try {
      const url = dept && dept !== 'all'
        ? `${COGNISEC_API_BASE}/healthcare/doctors?dept=${encodeURIComponent(dept)}`
        : `${COGNISEC_API_BASE}/healthcare/doctors`;
      const res = await fetch(url);
      if (!res.ok) return [];
      return await res.json();
    } catch (e) {
      console.warn('[COGNISEC-AI] Failed to fetch doctors:', e);
      return [];
    }
  }

  async bookHealthcareAppointment(appointmentData) {
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/healthcare/appointments`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(appointmentData)
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(data.detail || `Appointment booking failed with status ${res.status}`);
      }
      return { success: true, data };
    } catch (e) {
      return { success: false, error: e.message };
    }
  }

  async fetchHealthcareAppointments(email = null) {
    try {
      if (!email) return [];
      const res = await fetch(`${COGNISEC_API_BASE}/healthcare/appointments?email=${encodeURIComponent(email)}`);
      if (!res.ok) return [];
      return await res.json();
    } catch (e) {
      console.warn('[COGNISEC-AI] Failed to fetch patient appointments:', e);
      return [];
    }
  }

  // --- OBSERVATION & LOGIN OTP FLOW ---
  async getObservationStatus(sessionId = null) {
    const sid = sessionId || this.sessionId;
    if (!sid) return null;
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/auth/observation-status/${sid}`, {
        method: 'GET',
        headers: this.getHeaders()
      });
      if (!res.ok) return null;
      return await res.json();
    } catch (e) {
      return null;
    }
  }

  async requestLoginOtp(sessionId = null) {
    const sid = sessionId || this.sessionId;
    if (!sid) throw new Error("No pending session available.");
    const reqSeq = ++this._challengeReqSeq;
    const res = await fetch(`${COGNISEC_API_BASE}/auth/login-otp/request`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({ session_id: sid })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(data.detail || "Failed to request login verification code.");
    }
    if (reqSeq === this._challengeReqSeq && data.challenge_id) {
      this._activeChallengeId = data.challenge_id;
    }
    return data;
  }

  async verifyLoginOtp(otpCode, sessionId = null, challengeId = null) {
    const sid = sessionId || this.sessionId;
    if (!sid) throw new Error("No pending session available.");
    const activeChalId = challengeId || this._activeChallengeId || undefined;
    const res = await fetch(`${COGNISEC_API_BASE}/auth/login-otp/verify`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({
        session_id: sid,
        otp_code: String(otpCode || '').trim(),
        challenge_id: activeChalId
      })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      // Immediate termination on failed OTP according to zero-trust security policy
      this.clearAuth();
      const err = new Error(data.detail || "Verification failed. Pending session terminated.");
      err.terminated = true;
      throw err;
    }

    // OTP succeeded! Activate local session and update authoritative timestamps
    this.sessionStatus = 'ACTIVE';
    this.lastStepUpVerifiedAt = Date.now();
    this.lastStepUpVerifiedSessionId = sid;
    localStorage.setItem('cognisec_session_status', 'ACTIVE');
    if (this._obsTimer) {
      clearTimeout(this._obsTimer);
      this._obsTimer = null;
    }
    if (this._otpExpiryTimer) {
      clearInterval(this._otpExpiryTimer);
      this._otpExpiryTimer = null;
    }
    if (this.user) {
      this.user.account_status = 'ACTIVE';
      localStorage.setItem('cognisec_user', JSON.stringify(this.user));
    }
    this.closeObservationOtpModal();
    window.dispatchEvent(new CustomEvent('cognisec:auth_change', {
      detail: { isAuthenticated: true, user: this.user, isFullyVerified: true }
    }));
    return data;
  }

  async resendLoginOtp(sessionId = null) {
    const sid = sessionId || this.sessionId;
    if (!sid) throw new Error("No pending session available.");
    const reqSeq = ++this._challengeReqSeq;
    const res = await fetch(`${COGNISEC_API_BASE}/auth/login-otp/resend`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({ session_id: sid })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(data.detail || "Failed to resend verification code.");
    }
    if (reqSeq === this._challengeReqSeq && data.challenge_id) {
      this._activeChallengeId = data.challenge_id;
    }
    return data;
  }

  _extractErrorMessage(data, fallback) {
    if (!data) return fallback;
    if (typeof data.detail === 'string') return data.detail;
    if (Array.isArray(data.detail)) {
      return data.detail.map(d => d.msg || d.message || JSON.stringify(d)).join('; ');
    }
    if (data.message && typeof data.message === 'string') return data.message;
    return fallback;
  }

  async requestPasswordReset(email) {
    const res = await fetch(`${COGNISEC_API_BASE}/auth/password-reset/request`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email.trim() })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(this._extractErrorMessage(data, "Failed to request password reset code."));
    }
    return data;
  }

  async resendPasswordReset(email) {
    const res = await fetch(`${COGNISEC_API_BASE}/auth/password-reset/resend`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email.trim() })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = new Error(this._extractErrorMessage(data, "Failed to resend recovery code."));
      err.status = res.status;
      err.retryAfter = res.headers.get('Retry-After');
      throw err;
    }
    return data;
  }

  async verifyPasswordReset(email, otpCode, newPassword, confirmPassword = null) {
    const payload = {
      email: email.trim(),
      otp_code: otpCode.trim(),
      new_password: newPassword
    };
    if (confirmPassword !== null && confirmPassword !== undefined) {
      payload.confirm_password = confirmPassword;
    }
    const res = await fetch(`${COGNISEC_API_BASE}/auth/password-reset/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(this._extractErrorMessage(data, "Failed to verify password reset."));
    }
    return data;
  }

  _startResetCooldownTimer(seconds = 30) {
    const btn = document.getElementById('btn-pwd-reset-resend');
    if (!btn) return;
    if (this._pwdResetCooldownIv) {
      clearInterval(this._pwdResetCooldownIv);
      this._pwdResetCooldownIv = null;
    }
    btn.disabled = true;
    let sec = seconds;
    btn.textContent = `Resend (${sec}s)`;
    this._pwdResetCooldownIv = setInterval(() => {
      sec -= 1;
      if (sec <= 0) {
        clearInterval(this._pwdResetCooldownIv);
        this._pwdResetCooldownIv = null;
        btn.disabled = false;
        btn.textContent = 'Resend Code';
      } else {
        btn.textContent = `Resend (${sec}s)`;
      }
    }, 1000);
  }

  ensureForgotPasswordModalInDom() {
    if (document.getElementById('modal-forgot-password')) return;

    const modalDiv = document.createElement('div');
    modalDiv.id = 'modal-forgot-password';
    modalDiv.className = 'fixed inset-0 z-50 hidden bg-black/90 backdrop-blur-2xl flex items-center justify-center p-4 font-mono animate-fade-in';
    modalDiv.innerHTML = `
      <div class="relative w-full max-w-md bg-[#08050e] border border-red-900/60 rounded-2xl shadow-[0_0_80px_rgba(220,38,38,0.4)] overflow-hidden flex flex-col">
        <div class="px-6 py-4 border-b border-red-950 flex items-center justify-between bg-gradient-to-r from-red-950/40 via-black to-red-950/20">
          <div class="flex items-center gap-3">
            <div class="p-2 rounded-xl bg-red-950/80 border border-red-800 text-red-400">
              <svg class="w-5 h-5" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            </div>
            <div>
              <h3 class="font-heading font-extrabold text-base text-white tracking-wide">RESET PASSWORD</h3>
              <p class="text-xs font-mono text-slate-400">Secure Recovery via Email OTP</p>
            </div>
          </div>
          <button onclick="window.closeForgotPasswordModal ? window.closeForgotPasswordModal() : (window.cognisec && window.cognisec.closeForgotPasswordModal())" class="p-2 rounded-xl bg-red-950/60 hover:bg-red-900/80 border border-red-800/50 text-slate-400 hover:text-white transition-colors cursor-pointer" title="Close">✕</button>
        </div>

        <!-- Step 1: Request OTP -->
        <form id="pwd-reset-step1-form" onsubmit="window.cognisec ? window.cognisec.submitPasswordResetRequestFromModal(event) : (window.submitPasswordResetRequest && window.submitPasswordResetRequest(event))" class="p-6 space-y-4">
          <div class="space-y-1">
            <h4 class="font-heading font-bold text-sm text-white">Request Verification Code</h4>
            <p class="text-xs font-mono text-slate-400">Enter your registered email to receive a 6-digit recovery code via Gmail SMTP.</p>
          </div>
          <div id="pwd-reset-err-1" class="hidden p-3 rounded-xl bg-red-950/80 border border-red-800 text-red-300 text-xs font-mono leading-relaxed"></div>
          <div class="space-y-1.5 font-mono text-xs">
            <label class="text-slate-300 uppercase tracking-wider block">Registered Email Address</label>
            <input id="pwd-reset-email" type="email" placeholder="e.g. name@domain.com" required class="w-full px-4 py-3 rounded-xl bg-black/80 border border-red-900/50 text-white focus:outline-none focus:border-red-500 font-mono">
          </div>
          <button id="btn-request-pwd-reset" type="submit" class="w-full py-3.5 px-5 rounded-xl bg-gradient-to-r from-red-600 to-red-500 hover:from-red-500 hover:to-red-400 text-white font-heading font-extrabold text-xs uppercase tracking-wider shadow-[0_0_20px_rgba(220,38,38,0.5)] transition-all cursor-pointer flex items-center justify-center gap-2">
            <span>Send Recovery Code →</span>
          </button>
          <div class="text-center pt-2">
            <button type="button" onclick="window.closeForgotPasswordModal ? window.closeForgotPasswordModal() : (window.cognisec && window.cognisec.closeForgotPasswordModal())" class="text-xs font-mono text-slate-400 hover:text-white underline cursor-pointer">Back to Sign In</button>
          </div>
        </form>

        <!-- Step 2: Verify OTP and Set New Password -->
        <form id="pwd-reset-step2-form" onsubmit="window.cognisec ? window.cognisec.submitPasswordResetVerifyFromModal(event) : (window.submitPasswordResetVerify && window.submitPasswordResetVerify(event))" class="hidden p-6 space-y-4">
          <div class="space-y-1">
            <h4 class="font-heading font-bold text-sm text-white">Enter Code &amp; New Password</h4>
            <p id="pwd-reset-step2-desc" class="text-xs font-mono text-slate-400">Verification code sent to your email.</p>
          </div>
          <div id="pwd-reset-err-2" class="hidden p-3 rounded-xl bg-red-950/80 border border-red-800 text-red-300 text-xs font-mono leading-relaxed"></div>
          <div id="pwd-reset-succ-2" class="hidden p-3 rounded-xl bg-emerald-950/80 border border-emerald-800 text-emerald-300 text-xs font-mono leading-relaxed"></div>
          <div class="space-y-3 font-mono text-xs">
            <div class="space-y-1.5">
              <label class="text-slate-300 uppercase tracking-wider block">6-Digit Code</label>
              <input id="pwd-reset-otp" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" placeholder="000000" autocomplete="one-time-code" required class="w-full px-4 py-3 rounded-xl bg-black/80 border border-red-900/50 text-white text-center font-mono text-lg tracking-widest focus:outline-none focus:border-red-500">
            </div>
            <div class="space-y-1.5">
              <label class="text-slate-300 uppercase tracking-wider block">New Password</label>
              <div class="relative flex items-center">
                <input id="pwd-reset-newpass" type="password" placeholder="At least 8 chars (upper, lower, num, sym)" required class="w-full pl-4 pr-11 py-3 rounded-xl bg-black/80 border border-red-900/50 text-white focus:outline-none focus:border-red-500">
                <button type="button" onclick="window.togglePasswordVisibility('pwd-reset-newpass', this)" aria-label="Show password" title="Show password" class="absolute right-3 p-1 rounded-lg text-slate-400 hover:text-white focus:outline-none focus:ring-1 focus:ring-red-500 cursor-pointer transition-colors">
                  ${EYE_ON_SVG}
                </button>
              </div>
              <p class="text-[10px] text-slate-500 font-mono">Must include uppercase, lowercase, digit, and special character.</p>
            </div>
            <div class="space-y-1.5">
              <label class="text-slate-300 uppercase tracking-wider block">Confirm New Password</label>
              <div class="relative flex items-center">
                <input id="pwd-reset-confirmpass" type="password" placeholder="Re-enter new password" required class="w-full pl-4 pr-11 py-3 rounded-xl bg-black/80 border border-red-900/50 text-white focus:outline-none focus:border-red-500">
                <button type="button" onclick="window.togglePasswordVisibility('pwd-reset-confirmpass', this)" aria-label="Show password" title="Show password" class="absolute right-3 p-1 rounded-lg text-slate-400 hover:text-white focus:outline-none focus:ring-1 focus:ring-red-500 cursor-pointer transition-colors">
                  ${EYE_ON_SVG}
                </button>
              </div>
            </div>
          </div>
          <div class="flex items-center gap-3 pt-1">
            <button id="btn-pwd-reset-resend" type="button" onclick="window.resendPasswordResetFromModal ? window.resendPasswordResetFromModal() : (window.cognisec && window.cognisec.resendPasswordResetFromModal())" class="flex-1 py-3 px-3 rounded-xl bg-black hover:bg-red-950/60 border border-red-900/50 hover:border-red-700 text-slate-300 hover:text-white font-mono font-semibold text-xs uppercase tracking-wider transition-colors cursor-pointer text-center">Resend Code</button>
            <button id="btn-verify-pwd-reset" type="submit" class="flex-[2] py-3.5 px-4 rounded-xl bg-gradient-to-r from-red-600 to-red-500 hover:from-red-500 hover:to-red-400 text-white font-heading font-extrabold text-xs uppercase tracking-wider shadow-[0_0_20px_rgba(220,38,38,0.5)] transition-all cursor-pointer flex items-center justify-center gap-2">
              <span>Update Password →</span>
            </button>
          </div>
          <div class="text-center pt-2">
            <button type="button" onclick="window.closeForgotPasswordModal ? window.closeForgotPasswordModal() : (window.cognisec && window.cognisec.closeForgotPasswordModal())" class="text-xs font-mono text-slate-400 hover:text-white underline cursor-pointer">Back to Sign In</button>
          </div>
        </form>
      </div>
    `;
    document.body.appendChild(modalDiv);
  }

  openForgotPasswordModal(prefillEmail = null) {
    this.ensureForgotPasswordModalInDom();
    const modal = document.getElementById('modal-forgot-password');
    if (!modal) return;

    let targetEmail = prefillEmail;
    if (!targetEmail) {
      const candidates = [
        document.getElementById('login-user-email'),
        document.getElementById('login-soc-email'),
        document.getElementById('student-signin-email'),
        document.getElementById('doctor-signin-email'),
        document.getElementById('signin-email-input')
      ];
      for (const input of candidates) {
        if (input && input.value && input.value.trim()) {
          targetEmail = input.value.trim();
          break;
        }
      }
    }

    const emailInput = document.getElementById('pwd-reset-email');
    if (emailInput && targetEmail) {
      emailInput.value = targetEmail;
    }

    const s1 = document.getElementById('pwd-reset-step1-form');
    const s2 = document.getElementById('pwd-reset-step2-form');
    if (s1) s1.classList.remove('hidden');
    if (s2) s2.classList.add('hidden');

    const err1 = document.getElementById('pwd-reset-err-1');
    const err2 = document.getElementById('pwd-reset-err-2');
    const succ2 = document.getElementById('pwd-reset-succ-2');
    if (err1) err1.classList.add('hidden');
    if (err2) err2.classList.add('hidden');
    if (succ2) succ2.classList.add('hidden');

    const otpInput = document.getElementById('pwd-reset-otp');
    const passInput = document.getElementById('pwd-reset-newpass');
    const confirmInput = document.getElementById('pwd-reset-confirmpass');
    if (otpInput) otpInput.value = '';
    if (passInput) passInput.value = '';
    if (confirmInput) confirmInput.value = '';

    modal.classList.remove('hidden');
  }

  closeForgotPasswordModal() {
    const modal = document.getElementById('modal-forgot-password');
    if (modal) modal.classList.add('hidden');
    if (this._pwdResetCooldownIv) {
      clearInterval(this._pwdResetCooldownIv);
      this._pwdResetCooldownIv = null;
    }
  }

  async submitPasswordResetRequestFromModal(e) {
    if (e && e.preventDefault) e.preventDefault();
    const emailInput = document.getElementById('pwd-reset-email');
    const btn = document.getElementById('btn-request-pwd-reset');
    const errBox = document.getElementById('pwd-reset-err-1');

    if (errBox) errBox.classList.add('hidden');

    if (!emailInput || !emailInput.value.trim()) {
      if (errBox) {
        errBox.textContent = 'Please enter your registered email address.';
        errBox.classList.remove('hidden');
      }
      return;
    }
    const email = emailInput.value.trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      if (errBox) {
        errBox.textContent = 'Please enter a valid email address (e.g. user@gmail.com).';
        errBox.classList.remove('hidden');
      }
      return;
    }

    if (btn) {
      btn.disabled = true;
      btn.innerHTML = `<span>Sending Verification Code...</span>`;
    }

    try {
      const data = await this.requestPasswordReset(email);
      const s1 = document.getElementById('pwd-reset-step1-form');
      const s2 = document.getElementById('pwd-reset-step2-form');
      const desc = document.getElementById('pwd-reset-step2-desc');
      if (s1) s1.classList.add('hidden');
      if (s2) s2.classList.remove('hidden');

      if (desc) {
        if (data.email_delivered === true) {
          desc.className = 'text-xs font-mono text-emerald-400 leading-relaxed';
          desc.textContent = `✓ Verification code sent to ${data.masked_email || email} via Gmail SMTP. Check your inbox and spam folder.`;
        } else {
          desc.className = 'text-xs font-mono text-amber-400 leading-relaxed';
          desc.textContent = data.message || `If ${email} is registered, a verification code was dispatched. Please check your inbox.`;
        }
      }
      this._lastResetEmail = email;
      this._startResetCooldownTimer(30);
      const otpInput = document.getElementById('pwd-reset-otp');
      if (otpInput) setTimeout(() => otpInput.focus(), 60);
    } catch (err) {
      if (errBox) {
        errBox.textContent = err.message || 'Failed to dispatch recovery code.';
        errBox.classList.remove('hidden');
      }
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = `<span>Send Recovery Code →</span>`;
      }
    }
  }

  async resendPasswordResetFromModal() {
    const email = this._lastResetEmail || document.getElementById('pwd-reset-email')?.value?.trim();
    const btn = document.getElementById('btn-pwd-reset-resend');
    const errBox = document.getElementById('pwd-reset-err-2');
    const succBox = document.getElementById('pwd-reset-succ-2');

    if (!email) {
      if (errBox) {
        errBox.textContent = 'Missing email context. Please enter your email in Step 1.';
        errBox.classList.remove('hidden');
      }
      return;
    }

    if (btn && btn.disabled) return;

    if (errBox) errBox.classList.add('hidden');
    if (succBox) succBox.classList.add('hidden');
    if (btn) {
      btn.disabled = true;
      btn.textContent = 'Sending...';
    }

    try {
      const data = await this.resendPasswordReset(email);
      if (succBox) {
        if (data.email_delivered === true) {
          succBox.className = 'p-3 rounded-xl bg-emerald-950/80 border border-emerald-800 text-emerald-300 text-xs font-mono leading-relaxed';
          succBox.textContent = `✓ Fresh verification code dispatched to ${data.masked_email || email} via Gmail SMTP.`;
        } else {
          succBox.className = 'p-3 rounded-xl bg-amber-950/80 border border-amber-800 text-amber-300 text-xs font-mono leading-relaxed';
          succBox.textContent = data.message || `If this account is registered, a new verification code was dispatched.`;
        }
        succBox.classList.remove('hidden');
      }
      this._startResetCooldownTimer(30);
    } catch (err) {
      if (errBox) {
        errBox.textContent = err.message || 'Failed to resend code.';
        errBox.classList.remove('hidden');
      }
      const match = err.message && err.message.match(/wait (\d+) second/i);
      const secs = parseInt(err.retryAfter, 10) || (match ? parseInt(match[1], 10) : (err.status === 429 ? 30 : null));
      if (secs) {
        this._startResetCooldownTimer(secs);
      } else {
        if (btn) {
          btn.disabled = false;
          btn.textContent = 'Resend Code';
        }
      }
    }
  }

  async submitPasswordResetVerifyFromModal(e) {
    if (e && e.preventDefault) e.preventDefault();
    const emailInput = document.getElementById('pwd-reset-email');
    const otpInput = document.getElementById('pwd-reset-otp');
    const passInput = document.getElementById('pwd-reset-newpass');
    const confirmInput = document.getElementById('pwd-reset-confirmpass');
    const btn = document.getElementById('btn-verify-pwd-reset');
    const errBox = document.getElementById('pwd-reset-err-2');
    const succBox = document.getElementById('pwd-reset-succ-2');

    const email = emailInput ? emailInput.value.trim() : (this._lastResetEmail || '');
    const otp = otpInput ? otpInput.value.trim() : '';
    const pass = passInput ? passInput.value : '';
    const confirm = confirmInput ? confirmInput.value : '';

    if (errBox) errBox.classList.add('hidden');
    if (succBox) succBox.classList.add('hidden');

    if (!otp) {
      if (errBox) {
        errBox.textContent = 'Please enter the 6-digit verification code dispatched to your email.';
        errBox.classList.remove('hidden');
      }
      return;
    }

    if (!/^[0-9]{6}$/.test(otp)) {
      if (errBox) {
        errBox.textContent = 'Verification code must be exactly 6 digits (0-9).';
        errBox.classList.remove('hidden');
      }
      return;
    }

    if (!pass) {
      if (errBox) {
        errBox.textContent = 'Please enter a new password.';
        errBox.classList.remove('hidden');
      }
      return;
    }

    if (pass.length < 8) {
      if (errBox) {
        errBox.textContent = 'Password must be at least 8 characters long.';
        errBox.classList.remove('hidden');
      }
      return;
    }

    if (!/[A-Z]/.test(pass)) {
      if (errBox) {
        errBox.textContent = 'Password must contain at least one uppercase letter (A-Z).';
        errBox.classList.remove('hidden');
      }
      return;
    }

    if (!/[a-z]/.test(pass)) {
      if (errBox) {
        errBox.textContent = 'Password must contain at least one lowercase letter (a-z).';
        errBox.classList.remove('hidden');
      }
      return;
    }

    if (!/\d/.test(pass)) {
      if (errBox) {
        errBox.textContent = 'Password must contain at least one digit (0-9).';
        errBox.classList.remove('hidden');
      }
      return;
    }

    if (!/[!@#$%^&*(),.?":{}|<>\-_=+[\]\\/;~`']/.test(pass)) {
      if (errBox) {
        errBox.textContent = 'Password must contain at least one special character (!@#$%^&*...).';
        errBox.classList.remove('hidden');
      }
      return;
    }

    if (!confirm) {
      if (errBox) {
        errBox.textContent = 'Please confirm your new password.';
        errBox.classList.remove('hidden');
      }
      return;
    }

    if (pass !== confirm) {
      if (errBox) {
        errBox.textContent = 'Passwords do not match. Please verify both fields.';
        errBox.classList.remove('hidden');
      }
      return;
    }

    if (btn) {
      btn.disabled = true;
      btn.innerHTML = `<span>Updating Password...</span>`;
    }

    try {
      const res = await this.verifyPasswordReset(email, otp, pass, confirm);
      if (succBox) {
        succBox.className = 'p-3 rounded-xl bg-emerald-950/80 border border-emerald-800 text-emerald-300 text-xs font-mono leading-relaxed';
        succBox.textContent = res.message || 'Password successfully updated! You may now sign in.';
        succBox.classList.remove('hidden');
      }

      // Invalidate any prior local tokens/session state
      this.clearAuth();

      // Sync updated credentials into all sign-in forms currently present on page
      const inputs = [
        document.getElementById('login-user-email'),
        document.getElementById('login-soc-email'),
        document.getElementById('student-signin-email'),
        document.getElementById('doctor-signin-email'),
        document.getElementById('signin-email-input')
      ];
      for (const inp of inputs) {
        if (inp) inp.value = email;
      }
      const passInputs = [
        document.getElementById('login-user-password'),
        document.getElementById('login-soc-password'),
        document.getElementById('student-signin-pass'),
        document.getElementById('doctor-signin-pass'),
        document.getElementById('signin-pass-input')
      ];
      for (const pinp of passInputs) {
        if (pinp) pinp.value = pass;
      }

      // Close modal and present appropriate sign-in screen
      setTimeout(() => {
        this.closeForgotPasswordModal();
        if (typeof window.openModal === 'function') {
          window.openModal('login');
        }
        if (typeof window.setLoginScreen === 'function') {
          if (email.toLowerCase().includes('soc') || email.toLowerCase().includes('admin')) {
            window.setLoginScreen('soc');
          } else {
            window.setLoginScreen('user');
            if (typeof window.switchUserAuthTab === 'function') {
              window.switchUserAuthTab('signin');
            }
          }
        }
      }, 1500);

    } catch (err) {
      if (errBox) {
        errBox.textContent = err.message || 'Failed to update password. Please check your code.';
        errBox.classList.remove('hidden');
      }
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = `<span>Update Password →</span>`;
      }
    }
  }


  startObservationFlow(loginData) {
    this.ensureObservationModalInDom();
    this.scheduleBackgroundOtpPrompt(loginData);
  }

  scheduleBackgroundOtpPrompt(loginData) {
    if (!loginData || !loginData.session_id) return;
    const sid = loginData.session_id;

    if (this._obsTimer) {
      clearTimeout(this._obsTimer);
      this._obsTimer = null;
    }

    const remaining = typeof loginData.observation_seconds_remaining === 'number'
      ? loginData.observation_seconds_remaining
      : this.observationDurationSeconds;

    const status = loginData.session_status || loginData.status;
    if (status === 'ACTIVE') {
      console.log(`[COGNISEC-AI] [DIAGNOSTIC] Session ${sid} is ACTIVE. Observation not needed.`);
      return;
    }

    if (status === 'PENDING_OTP' || remaining <= 0) {
      console.log(`[COGNISEC-AI] [DIAGNOSTIC] Observation complete for session ${sid}. Triggering OTP issuance...`);
      this.executeObservationOtpTransition(sid);
      return;
    }

    console.log(`[COGNISEC-AI] [DIAGNOSTIC] Silent background observation active for session ${sid} (${remaining}s duration). Normal browsing permitted.`);
    this._obsTimer = setTimeout(async () => {
      this._obsTimer = null;
      console.log(`[COGNISEC-AI] [DIAGNOSTIC] Background observation timer reached 0 for session ${sid}. Enforcing server transition...`);
      await this.executeObservationOtpTransition(sid);
    }, Math.max(500, remaining * 1000));
  }

  async executeObservationOtpTransition(sessionId = null) {
    const sid = sessionId || this.sessionId;
    if (!sid) return;

    if (this.sessionStatus === 'ACTIVE') {
      console.log(`[COGNISEC-AI] [DIAGNOSTIC] Session is already ACTIVE. Skipping OTP prompt.`);
      return;
    }

    if (this._isRequestingOtp) {
      console.log(`[COGNISEC-AI] [DIAGNOSTIC] OTP request already in progress for session ${sid}.`);
      return;
    }
    this._isRequestingOtp = true;

    try {
      console.log(`[COGNISEC-AI] [DIAGNOSTIC] Requesting server to authorize observation completion & dispatch OTP for session ${sid}...`);
      const challenge = await this.requestLoginOtp(sid);
      console.log(`[COGNISEC-AI] [DIAGNOSTIC] Backend confirmed OTP challenge issued (ID: ${challenge.challenge_id}). Delivered to ${challenge.masked_email}.`);

      // Open the modal ONLY after backend confirms challenge was created
      this.openObservationOtpModal(challenge);
    } catch (err) {
      console.warn(`[COGNISEC-AI] [DIAGNOSTIC] OTP challenge request failed:`, err.message);

      // If backend reports session is already active, synchronize auth state immediately without error
      if (err.message && err.message.toLowerCase().includes('already authenticated and active')) {
        this.sessionStatus = 'ACTIVE';
        localStorage.setItem('cognisec_session_status', 'ACTIVE');
        if (this.user) {
          this.user.account_status = 'ACTIVE';
          localStorage.setItem('cognisec_user', JSON.stringify(this.user));
        }
        this.closeObservationOtpModal();
        window.dispatchEvent(new CustomEvent('cognisec:auth_change', {
          detail: { isAuthenticated: true, user: this.user, isFullyVerified: true }
        }));
        return;
      }

      // Handle server timing guard if client clock ran slightly ahead
      if (err.message && err.message.toLowerCase().includes('observation period incomplete')) {
        const match = err.message.match(/(\d+)\s*second/i);
        const waitSec = match ? parseInt(match[1], 10) : 1;
        console.log(`[COGNISEC-AI] [DIAGNOSTIC] Server clock reports ${waitSec}s remaining. Retrying after delay...`);
        this._obsTimer = setTimeout(() => {
          this._obsTimer = null;
          this.executeObservationOtpTransition(sid);
        }, waitSec * 1000);
        return;
      }

      this.showOtpDeliveryError(err.message || 'Verification code delivery failed. Access remains restricted.');
    } finally {
      this._isRequestingOtp = false;
    }
  }

  openObservationOtpModal(challenge) {
    this.ensureObservationModalInDom();
    const modal = document.getElementById('modal-login-observation');
    if (!modal) return;
    if (!modal.classList.contains('hidden')) {
      // Modal is already open; do not re-open or wipe user-entered digits
      return;
    }

    const destEmail = document.getElementById('login-otp-dest-email');
    const errBanner = document.getElementById('login-otp-error-banner');
    const successBanner = document.getElementById('login-otp-success-banner');
    const codeInput = document.getElementById('login-otp-code-input');

    if (destEmail) {
      if (challenge && challenge.masked_email) {
        destEmail.textContent = challenge.masked_email;
      } else if (this.user && this.user.email) {
        destEmail.textContent = this.maskEmail(this.user.email);
      }
    }

    // Always clear previous error banners when opening on fresh challenge
    if (errBanner) {
      errBanner.textContent = '';
      errBanner.classList.add('hidden');
    }
    if (successBanner) {
      successBanner.textContent = '';
      successBanner.classList.add('hidden');
    }
    if (codeInput) {
      codeInput.value = '';
      codeInput.disabled = false;
    }

    modal.classList.remove('hidden');
    if (codeInput) codeInput.focus();

    this.startModalOtpExpiryCountdown(challenge ? challenge.expires_in_seconds || 300 : 300);
    console.log('[COGNISEC-AI] [DIAGNOSTIC] Login OTP popup displayed over current portal (no redirect).');
  }

  closeObservationOtpModal() {
    const modal = document.getElementById('modal-login-observation');
    if (modal) modal.classList.add('hidden');
  }

  async triggerLoginOtpModal(sessionId = null) {
    const sid = sessionId || this.sessionId;
    if (!sid) return;

    if (this.sessionStatus === 'ACTIVE') return;

    console.log(`[COGNISEC-AI] [DIAGNOSTIC] Protected action invoked. Checking observation status for session ${sid}...`);
    const obsStatus = await this.getObservationStatus(sid);
    if (obsStatus && obsStatus.observation_seconds_remaining > 0 && obsStatus.status === 'PENDING_OBSERVATION') {
      const rem = obsStatus.observation_seconds_remaining;
      this.showToastNotification(
        "Observation In Progress",
        `Zero-Trust behavioral observation active in background (${rem}s remaining). Complete OTP verification to unlock sensitive actions.`,
        "🔒"
      );
      return;
    }

    await this.executeObservationOtpTransition(sid);
  }

  showToastNotification(title, message, icon = "🔒") {
    const existing = document.getElementById('auth-toast') || document.getElementById('portal-toast');
    if (existing) {
      const titleEl = document.getElementById('toast-title') || existing.querySelector('h5, strong');
      const descEl = document.getElementById('toast-desc') || existing.querySelector('p');
      const iconEl = document.getElementById('toast-icon');
      if (titleEl) titleEl.textContent = title;
      if (descEl) descEl.textContent = message;
      if (iconEl) iconEl.textContent = icon;
      existing.classList.remove('hidden');
      setTimeout(() => existing.classList.add('hidden'), 4000);
    }
  }

  showOtpDeliveryError(errorMessage) {
    this.ensureObservationModalInDom();
    const modal = document.getElementById('modal-login-observation');
    if (modal) modal.classList.remove('hidden');
    const destEmail = document.getElementById('login-otp-dest-email');
    if (destEmail && this.user && this.user.email) {
      destEmail.textContent = this.maskEmail(this.user.email);
    }
    const errBanner = document.getElementById('login-otp-error-banner');
    if (errBanner) {
      errBanner.textContent = errorMessage;
      errBanner.classList.remove('hidden');
    }
  }

  startModalOtpExpiryCountdown(ttlSeconds) {
    if (this._otpExpiryTimer) clearInterval(this._otpExpiryTimer);
    let remaining = ttlSeconds;
    const timerEl = document.getElementById('login-otp-expiry-timer');
    const update = () => {
      const m = Math.floor(remaining / 60);
      const s = remaining % 60;
      if (timerEl) {
        timerEl.textContent = `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
      }
    };
    update();
    this._otpExpiryTimer = setInterval(() => {
      remaining--;
      if (remaining <= 0) {
        clearInterval(this._otpExpiryTimer);
        this._otpExpiryTimer = null;
        if (timerEl) timerEl.textContent = 'EXPIRED';
        const errBanner = document.getElementById('login-otp-error-banner');
        if (errBanner) {
          errBanner.textContent = 'Verification code has expired. Please click "Resend Code" to receive a fresh code.';
          errBanner.classList.remove('hidden');
        }
      } else {
        update();
      }
    }, 1000);
  }

  async submitLoginOtpFromForm(event) {
    if (event) event.preventDefault();
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
      await this.verifyLoginOtp(otpCode);
      if (successBanner) {
        successBanner.textContent = '✓ Verification successful! Full session access granted.';
        successBanner.classList.remove('hidden');
      }
      setTimeout(() => {
        this.closeObservationOtpModal();
        if (verifyBtn) {
          verifyBtn.disabled = false;
          verifyBtn.innerHTML = '<span>Verify &amp; Activate →</span>';
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
      setTimeout(() => {
        this.closeObservationOtpModal();
        if (verifyBtn) {
          verifyBtn.disabled = false;
          verifyBtn.innerHTML = '<span>Verify &amp; Activate →</span>';
        }
        if (codeInput) codeInput.disabled = false;
        window.location.reload();
      }, 2500);
    }
  }

  async resendLoginOtpFromModal() {
    const resendBtn = document.getElementById('btn-login-otp-resend');
    const errBanner = document.getElementById('login-otp-error-banner');
    const successBanner = document.getElementById('login-otp-success-banner');
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
      const challenge = await this.resendLoginOtp();
      this.startModalOtpExpiryCountdown(challenge.expires_in_seconds || 300);
      const destEmail = document.getElementById('login-otp-dest-email');
      if (destEmail) {
        destEmail.textContent = challenge.masked_email || this.maskEmail(this.user?.email);
      }
      if (successBanner) {
        successBanner.textContent = 'Fresh verification code dispatched to your registered email.';
        successBanner.classList.remove('hidden');
      }
    } catch (err) {
      if (errBanner) {
        errBanner.textContent = err.message || 'Failed to dispatch verification code. Please retry.';
        errBanner.classList.remove('hidden');
      }
    } finally {
      if (resendBtn) {
        resendBtn.disabled = false;
        resendBtn.textContent = 'Resend Code';
      }
    }
  }

  cancelObservationAndLogout() {
    this.closeObservationOtpModal();
    this.logout();
    window.location.reload();
  }

  async register(name, email, password, role = 'USER', factorData = {}) {
    try {
      const payload = Object.assign({
        name: name.trim(),
        email: email.trim(),
        password,
        role
      }, factorData || {});
      const res = await fetch(`${COGNISEC_API_BASE}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        let message = `Registration failed with status ${res.status}`;
        if (err.detail) {
          if (Array.isArray(err.detail)) {
            message = err.detail.map(d => (d.msg || d.message || '').replace(/^Value error,\s*/i, '')).filter(Boolean).join('. ') || message;
          } else if (typeof err.detail === 'string') {
            message = err.detail;
          }
        }
        const customErr = new Error(message);
        customErr.raw = err;
        throw customErr;
      }
      return { success: true, data: await res.json() };
    } catch (error) {
      console.error('[COGNISEC-AI] Registration error:', error.message);
      return { success: false, error: error.message, details: error.raw ? error.raw.detail : null };
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
      // Explicit Privacy Safeguard: Never monitor or capture keystroke events inside password/sensitive inputs
      if (this.isSensitiveInput(e.target)) {
        return;
      }

      // Ignore auto-repeated keydown events while a key is held down
      if (e.repeat) {
        return;
      }

      const now = performance.now();
      const codeKey = e.code || 'Key_Transient';

      // Record keydown timestamp for dwell time calculation
      if (!this.activeKeyDowns.has(codeKey)) {
        this.activeKeyDowns.set(codeKey, now);
      }

      // Record inter-keystroke flight time
      if (lastKeyTime > 0) {
        const flightTime = now - lastKeyTime;
        // Accept physiologically plausible flights between 10ms and 2000ms (exclude long idle pauses)
        if (flightTime >= 10 && flightTime <= 2000) {
          this.keyPressTimings.push({ flight: flightTime, t: now });
          if (this.keyPressTimings.length > 50) this.keyPressTimings.shift();
        }
      }
      lastKeyTime = now;
      this.hasRealInteraction = true;
      this.lastInteractionTime = Date.now();
    }, { passive: true });

    window.addEventListener('keyup', (e) => {
      // Explicit Privacy Safeguard
      if (this.isSensitiveInput(e.target)) {
        return;
      }

      const codeKey = e.code || 'Key_Transient';
      if (this.activeKeyDowns.has(codeKey)) {
        const downTime = this.activeKeyDowns.get(codeKey);
        this.activeKeyDowns.delete(codeKey);
        const now = performance.now();
        const dwell = now - downTime;
        // Accept physiologically plausible dwell durations between 10ms and 1500ms
        if (dwell >= 10 && dwell <= 1500) {
          this.dwellTimings.push({ dwell: dwell, t: now });
          if (this.dwellTimings.length > 50) this.dwellTimings.shift();
        }
      }
      this.hasRealInteraction = true;
      this.lastInteractionTime = Date.now();
    }, { passive: true });

    // Focus change / window blur / tab hidden safeguards:
    // Safely purge pending unreleased keys to prevent bogus dwell times
    window.addEventListener('blur', () => {
      this.activeKeyDowns.clear();
      lastKeyTime = 0;
    });
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        this.activeKeyDowns.clear();
        lastKeyTime = 0;
      }
    });

    // 2. Mouse trajectory vectors, velocities & accelerations
    let lastMouseTime = performance.now();
    window.addEventListener('mousemove', (e) => {
      const now = performance.now();
      const dt = now - lastMouseTime;
      // Filter out sub-4ms timer jitter or duplicate events
      if (dt >= 4) {
        this.mousePoints.push({ x: e.clientX, y: e.clientY, t: now, dt: dt });
        if (this.mousePoints.length > 60) this.mousePoints.shift();
        lastMouseTime = now;
      }
      this.hasRealInteraction = true;
      this.lastInteractionTime = Date.now();
    }, { passive: true });

    // 3. Clicks, Scrolls & Categorical Navigation Events
    window.addEventListener('click', (e) => {
      this.clickCount++;
      this.hasRealInteraction = true;
      this.lastInteractionTime = Date.now();

      // Extract coarse, privacy-preserving section/category tag (never inputs or credentials)
      try {
        const navEl = e.target && e.target.closest && e.target.closest('[data-section], [data-tab], [data-category], [data-route], nav a, .nav-link, button[id*="course-"], button[id*="filter-"], button[id*="tab-"]');
        if (navEl) {
          const category = (
            navEl.getAttribute('data-section') ||
            navEl.getAttribute('data-tab') ||
            navEl.getAttribute('data-category') ||
            navEl.getAttribute('data-route') ||
            navEl.id ||
            (navEl.getAttribute('href') && navEl.getAttribute('href').startsWith('#') ? navEl.getAttribute('href').replace('#', '') : null)
          );
          if (category) {
            this.recordNavigationEvent(category);
          }
        }
      } catch (_) {}
    }, { passive: true });

    let lastScrollY = window.scrollY || window.pageYOffset || 0;
    let lastScrollX = window.scrollX || window.pageXOffset || 0;
    let lastScrollTime = performance.now();

    window.addEventListener('scroll', () => {
      const now = performance.now();
      const currentScrollY = window.scrollY || window.pageYOffset || 0;
      const currentScrollX = window.scrollX || window.pageXOffset || 0;
      const dt = Math.max(1, now - lastScrollTime);
      const dy = Math.abs(currentScrollY - lastScrollY);
      const dx = Math.abs(currentScrollX - lastScrollX);
      const dist = Math.hypot(dx, dy);

      if (dist > 0 && dt >= 4) {
        const speed = (dist / dt) * 1000; // genuine pixels per second
        if (speed <= 20000.0) {
          this.scrollSpeeds.push({ speed, t: now });
          if (this.scrollSpeeds.length > 50) this.scrollSpeeds.shift();
        }
        lastScrollY = currentScrollY;
        lastScrollX = currentScrollX;
        lastScrollTime = now;
      }
      this.hasRealInteraction = true;
      this.lastInteractionTime = Date.now();
    }, { passive: true });

    // 4. Navigation route/section transitions (Hash & History events)
    window.addEventListener('hashchange', () => {
      const hash = (window.location.hash || '').replace('#', '');
      if (hash) this.recordNavigationEvent(hash);
      this.hasRealInteraction = true;
      this.lastInteractionTime = Date.now();
    });
    window.addEventListener('popstate', () => {
      const path = (window.location.pathname || '').split('/').pop().replace('.html', '') || 'root';
      this.recordNavigationEvent(path);
      this.hasRealInteraction = true;
      this.lastInteractionTime = Date.now();
    });
  }

  getLiveTelemetryMetrics() {
    const nowMs = performance.now();
    const recentKeyPresses = (this.keyPressTimings || []).filter(k => (nowMs - k.t) <= 30000);
    const recentDwells = (this.dwellTimings || []).filter(d => (nowMs - d.t) <= 30000);
    const recentPoints = (this.mousePoints || []).filter(p => (nowMs - p.t) <= 30000);

    let avgFlight = 0.0;
    let avgDwell = 0.0;
    let wpm = 0.0;

    if (recentDwells.length >= 2) {
      const dwells = recentDwells.map(d => d.dwell);
      avgDwell = dwells.reduce((a, b) => a + b, 0) / dwells.length;
    }

    if (recentKeyPresses.length >= 2) {
      const flights = recentKeyPresses.map(k => k.flight);
      avgFlight = flights.reduce((a, b) => a + b, 0) / flights.length;
      const effectiveDwell = avgDwell > 0 ? avgDwell : 60.0;
      const cycleMs = avgFlight + effectiveDwell;
      const calculatedWpm = Math.round(60000 / (5 * cycleMs));
      wpm = Math.min(250.0, Math.max(5.0, calculatedWpm));
    }

    let avgVel = 0.0;
    let avgAcc = 0.0;
    let curvatureEntropy = 0.0;

    if (recentPoints.length >= 3) {
      const segmentVelocities = [];
      for (let i = 1; i < recentPoints.length; i++) {
        const p1 = recentPoints[i - 1];
        const p2 = recentPoints[i];
        const dtMs = Math.max(1, p2.t - p1.t);
        const dist = Math.hypot(p2.x - p1.x, p2.y - p1.y);
        if (dist > 0 && dtMs >= 4) {
          const v = (dist / dtMs) * 1000;
          segmentVelocities.push(v);
        }
      }

      if (segmentVelocities.length >= 2) {
        avgVel = Math.min(10000.0, segmentVelocities.reduce((a, b) => a + b, 0) / segmentVelocities.length);
        let accSum = 0;
        let accCount = 0;
        for (let j = 1; j < segmentVelocities.length; j++) {
          const dv = Math.abs(segmentVelocities[j] - segmentVelocities[j - 1]);
          const dtSec = Math.max(0.005, (recentPoints[j].t - recentPoints[j - 1].t) / 1000);
          accSum += (dv / dtSec);
          accCount++;
        }
        if (accCount > 0) avgAcc = Math.min(50000.0, accSum / accCount);
      }

      const turningAngles = [];
      for (let i = 2; i < recentPoints.length; i++) {
        const p0 = recentPoints[i - 2];
        const p1 = recentPoints[i - 1];
        const p2 = recentPoints[i];
        const dx1 = p1.x - p0.x;
        const dy1 = p1.y - p0.y;
        const dx2 = p2.x - p1.x;
        const dy2 = p2.y - p1.y;
        const d1 = Math.hypot(dx1, dy1);
        const d2 = Math.hypot(dx2, dy2);
        if (d1 >= 2.0 && d2 >= 2.0) {
          let diff = Math.abs(Math.atan2(dy2, dx2) - Math.atan2(dy1, dx1));
          if (diff > Math.PI) diff = (2 * Math.PI) - diff;
          turningAngles.push(diff);
        }
      }
      if (turningAngles.length >= 3) {
        const numBins = 6;
        const binCounts = new Array(numBins).fill(0);
        const binWidth = Math.PI / numBins;
        for (const angle of turningAngles) {
          binCounts[Math.min(numBins - 1, Math.floor(angle / binWidth))]++;
        }
        let entropy = 0.0;
        for (let b = 0; b < numBins; b++) {
          if (binCounts[b] > 0) {
            const p = binCounts[b] / turningAngles.length;
            entropy -= p * Math.log(p);
          }
        }
        curvatureEntropy = Math.min(5.0, Math.max(0.0, entropy));
      }
    }

    let navEntropy = 0.0;
    const nowTime = Date.now();
    const navs = (this.navigationHistory || []).filter(item => (nowTime - item.t) <= 600000);
    if (navs.length >= 2) {
      const counts = {};
      for (const item of navs) counts[item.category] = (counts[item.category] || 0) + 1;
      let h = 0.0;
      for (const cat in counts) {
        const p = counts[cat] / navs.length;
        h -= p * Math.log(p);
      }
      navEntropy = Math.min(5.0, Math.max(0.0, h));
    }

    let avgScrollSpeed = 0.0;
    const scrolls = (this.scrollSpeeds || []).filter(s => (nowMs - s.t) <= 30000);
    if (scrolls.length > 0) {
      avgScrollSpeed = Math.min(20000.0, scrolls.reduce((a, b) => a + b.speed, 0) / scrolls.length);
    }

    const intervalSec = this.lastTelemetryDispatchTime ? Math.max(1, (Date.now() - this.lastTelemetryDispatchTime) / 1000) : 6.0;
    const clickFreq = Math.min(100.0, (this.clickCount || 0) / intervalSec);
    const idleSeconds = (this.hasRealInteraction && this.lastInteractionTime) ? Math.max(0, (Date.now() - this.lastInteractionTime) / 1000) : 0;

    return {
      typing_speed_wpm: Number(wpm.toFixed(1)),
      avg_flight_time_ms: Number(avgFlight.toFixed(1)),
      avg_dwell_time_ms: Number(avgDwell.toFixed(1)),
      mouse_velocity_avg: Number(avgVel.toFixed(1)),
      mouse_acceleration_avg: Number(avgAcc.toFixed(1)),
      mouse_curvature_entropy: Number(curvatureEntropy.toFixed(2)),
      click_frequency: Number(clickFreq.toFixed(2)),
      scroll_speed_avg: Number(avgScrollSpeed.toFixed(1)),
      idle_duration_sec: Number((Math.round(idleSeconds * 10) / 10).toFixed(1)),
      navigation_entropy: Number(navEntropy.toFixed(2)),
      sample_counts: {
        keystrokes: recentDwells.length,
        mouse_points: recentPoints.length,
        clicks: this.clickCount || 0,
        scrolls: scrolls.length,
        navigations: navs.length
      }
    };
  }

  computeTelemetrySnapshot() {
    const nowMs = performance.now();
    // Prune stale keystroke & pointer records older than 30 seconds
    this.keyPressTimings = this.keyPressTimings.filter(k => (nowMs - k.t) <= 30000);
    this.dwellTimings = this.dwellTimings.filter(d => (nowMs - d.t) <= 30000);
    this.mousePoints = this.mousePoints.filter(p => (nowMs - p.t) <= 30000);

    // 1. Keystroke timing statistics (Dwell Time, Flight Time, Typing Speed)
    let avgFlight = 0.0;
    let avgDwell = 0.0;
    let wpm = 0.0;

    if (this.dwellTimings.length >= 3) {
      const dwells = this.dwellTimings.map(d => d.dwell);
      avgDwell = dwells.reduce((a, b) => a + b, 0) / dwells.length;
    }

    if (this.keyPressTimings.length >= 3) {
      const flights = this.keyPressTimings.map(k => k.flight);
      avgFlight = flights.reduce((a, b) => a + b, 0) / flights.length;

      // Effective keystroke period = flight + dwell (use measured dwell if available, else 60ms)
      const effectiveDwell = avgDwell > 0 ? avgDwell : 60.0;
      const cycleMs = avgFlight + effectiveDwell;
      // Standard WPM: 1 word = 5 characters -> WPM = (60000 / cycleMs) / 5
      const calculatedWpm = Math.round(60000 / (5 * cycleMs));
      wpm = Math.min(250.0, Math.max(5.0, calculatedWpm));
    }

    // 2. Mouse trajectory, velocity, acceleration & curvature statistics
    let avgVel = 0.0;
    let avgAcc = 0.0;
    let curvatureEntropy = 0.0;

    if (this.mousePoints.length >= 4) {
      const segmentVelocities = [];
      const segmentTimes = [];

      for (let i = 1; i < this.mousePoints.length; i++) {
        const p1 = this.mousePoints[i - 1];
        const p2 = this.mousePoints[i];
        const dtMs = Math.max(1, p2.t - p1.t);
        const dist = Math.hypot(p2.x - p1.x, p2.y - p1.y);
        if (dist > 0 && dtMs >= 4) {
          const v = (dist / dtMs) * 1000; // px/s
          segmentVelocities.push(v);
          segmentTimes.push(dtMs / 1000); // seconds
        }
      }

      if (segmentVelocities.length >= 2) {
        // Average velocity
        const totalVel = segmentVelocities.reduce((a, b) => a + b, 0);
        avgVel = Math.min(10000.0, totalVel / segmentVelocities.length);

        // Genuine acceleration: dv / dt across consecutive velocity segments
        let accSum = 0;
        let accCount = 0;
        for (let j = 1; j < segmentVelocities.length; j++) {
          const dv = Math.abs(segmentVelocities[j] - segmentVelocities[j - 1]);
          const dtAcc = Math.max(0.005, (segmentTimes[j] + segmentTimes[j - 1]) / 2);
          const a = dv / dtAcc; // px/s²
          if (a <= 25000.0) {
            accSum += a;
            accCount++;
          }
        }
        if (accCount > 0) {
          avgAcc = Math.min(25000.0, accSum / accCount);
        }
      }

      // Dynamic Curvature Entropy Calculation:
      // Evaluates Shannon entropy of trajectory angular changes (turning angles)
      const turningAngles = [];
      for (let i = 2; i < this.mousePoints.length; i++) {
        const p0 = this.mousePoints[i - 2];
        const p1 = this.mousePoints[i - 1];
        const p2 = this.mousePoints[i];

        const dx1 = p1.x - p0.x;
        const dy1 = p1.y - p0.y;
        const dx2 = p2.x - p1.x;
        const dy2 = p2.y - p1.y;

        const d1 = Math.hypot(dx1, dy1);
        const d2 = Math.hypot(dx2, dy2);

        // Exclude stationary pauses or sub-pixel micro-jitter
        if (d1 >= 2.0 && d2 >= 2.0) {
          const theta1 = Math.atan2(dy1, dx1);
          const theta2 = Math.atan2(dy2, dx2);
          let diff = Math.abs(theta2 - theta1);
          if (diff > Math.PI) {
            diff = (2 * Math.PI) - diff;
          }
          turningAngles.push(diff);
        }
      }

      if (turningAngles.length >= 3) {
        // Partition [0, PI] into 6 equal angular bins (PI/6 radians each)
        const numBins = 6;
        const binCounts = new Array(numBins).fill(0);
        const binWidth = Math.PI / numBins;

        for (const angle of turningAngles) {
          const binIndex = Math.min(numBins - 1, Math.floor(angle / binWidth));
          binCounts[binIndex]++;
        }

        // Compute Shannon entropy: H = -sum(p * ln(p))
        const totalAngles = turningAngles.length;
        let entropy = 0.0;
        for (let b = 0; b < numBins; b++) {
          if (binCounts[b] > 0) {
            const p = binCounts[b] / totalAngles;
            entropy -= p * Math.log(p);
          }
        }
        // Entropy bounded by ln(6) ~= 1.792, strictly within [0.0, 5.0]
        curvatureEntropy = Math.min(5.0, Math.max(0.0, entropy));
      }
    }

    // 3. Navigation Entropy: Shannon entropy of categorical transitions
    let navEntropy = 0.0;
    const nowTime = Date.now();
    // Prune navigation records older than 10 minutes
    this.navigationHistory = this.navigationHistory.filter(item => (nowTime - item.t) <= 600000);

    if (this.navigationHistory.length >= 2) {
      const counts = {};
      for (const item of this.navigationHistory) {
        counts[item.category] = (counts[item.category] || 0) + 1;
      }
      const totalNav = this.navigationHistory.length;
      let h = 0.0;
      for (const cat in counts) {
        const p = counts[cat] / totalNav;
        h -= p * Math.log(p);
      }
      navEntropy = Math.min(5.0, Math.max(0.0, h));
    }

    // 4. Genuine scroll speed: Average px/s across scroll segments in window
    let avgScrollSpeed = 0.0;
    this.scrollSpeeds = (this.scrollSpeeds || []).filter(s => (nowMs - s.t) <= 30000);
    if (this.scrollSpeeds.length > 0) {
      const totalSpeed = this.scrollSpeeds.reduce((a, b) => a + b.speed, 0);
      avgScrollSpeed = Math.min(20000.0, totalSpeed / this.scrollSpeeds.length);
    }

    // 5. Genuine click frequency: clicks per second since last snapshot
    const nowEpoch = Date.now();
    const intervalSec = this.lastTelemetryDispatchTime ? Math.max(1, (nowEpoch - this.lastTelemetryDispatchTime) / 1000) : 6.0;
    this.lastTelemetryDispatchTime = nowEpoch;
    const clickFreq = Math.min(100.0, this.clickCount / intervalSec);
    this.clickCount = 0;

    // 6. Idle Duration in seconds
    const idleSeconds = (this.hasRealInteraction && this.lastInteractionTime) ? Math.max(0, (Date.now() - this.lastInteractionTime) / 1000) : 0.0;

    return {
      session_id: this.sessionId || '',
      application: this.application,
      typing_speed_wpm: Number(wpm.toFixed(1)),
      avg_flight_time_ms: Number(avgFlight.toFixed(1)),
      avg_dwell_time_ms: Number(avgDwell.toFixed(1)),
      mouse_velocity_avg: Number(avgVel.toFixed(1)),
      mouse_acceleration_avg: Number(avgAcc.toFixed(1)),
      mouse_curvature_entropy: Number(curvatureEntropy.toFixed(2)),
      click_frequency: Number(clickFreq.toFixed(2)),
      scroll_speed_avg: Number(avgScrollSpeed.toFixed(1)),
      idle_duration_sec: Number((Math.round(idleSeconds * 10) / 10).toFixed(1)),
      navigation_entropy: Number(navEntropy.toFixed(2)),
      context_signals: { is_new_device: false },
      timestamp: Date.now() / 1000,
      sequence_number: (() => {
        const seq = ++this.sequenceNumber;
        if (this.sessionId) {
          try { localStorage.setItem('cognisec_seq_' + this.sessionId, String(seq)); } catch (_) {}
        }
        return seq;
      })(),
      telemetry_nonce: 'nonce_' + Math.random().toString(36).substring(2, 10) + Date.now().toString(36)
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

      // Handle critical risk session revocation
      if (result && (result.decision === 'TERMINATE' || result.session_status === 'TERMINATED')) {
        console.warn('[COGNISEC-AI] Critical risk detected: Session revoked by server security policy.');
        this.clearAuth();
        window.dispatchEvent(new CustomEvent('cognisec:session_locked', { detail: result }));
        return { success: false, error: 'Session terminated due to critical risk.' };
      }

      // Handle step-up verification requirement
      if (result && (result.session_status === 'STEP_UP_REQUIRED' || result.decision === 'STEP_UP_VERIFICATION' || result.verification_required)) {
        // Stale telemetry guard: If current session is ACTIVE and result is from an old pending state, ignore it completely
        if (this.sessionStatus === 'ACTIVE' && result.session_status !== 'STEP_UP_REQUIRED') {
          console.log('[COGNISEC-AI] Stale pending telemetry response ignored; session is already ACTIVE.');
          return { success: true, data: result };
        }

        // Prevent stale in-flight telemetry from reopening challenge if recently verified on backend
        const recentlyVerified = this.lastStepUpVerifiedAt &&
          (Date.now() - this.lastStepUpVerifiedAt < 30000) &&
          (this.lastStepUpVerifiedSessionId === this.sessionId);

        if (recentlyVerified) {
          console.log('[COGNISEC-AI] Suppressing stale telemetry step-up trigger; session was recently verified.');
          return { success: true, data: result };
        }

        console.warn('[COGNISEC-AI] Step-up verification required by backend Zero Trust policy decision');
        this.sessionStatus = 'STEP_UP_REQUIRED';
        localStorage.setItem('cognisec_session_status', 'STEP_UP_REQUIRED');
        window.dispatchEvent(new CustomEvent('cognisec:step_up_required', { detail: result }));
        this.openStepUpModal({ reason: result.user_message });
      }

      window.dispatchEvent(new CustomEvent('cognisec:telemetry_dispatched', { detail: result }));
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

  async fetchSocRiskDistribution() {
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/admin/risk-distribution`, {
        headers: this.getHeaders()
      });
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn('[COGNISEC-AI] Failed to fetch risk distribution:', e);
    }
    return null;
  }

  async fetchSocEvents(limit = 20, scope = 'all') {
    try {
      const params = new URLSearchParams({ limit: String(limit) });
      if (scope && scope !== 'all') params.set('scope', scope);
      const res = await fetch(`${COGNISEC_API_BASE}/admin/events?${params.toString()}`, {
        headers: this.getHeaders()
      });
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn('[COGNISEC-AI] Failed to fetch events:', e);
    }
    return [];
  }

  async fetchSocAlerts(limit = 100, status = '', severity = '', userId = null, scope = 'all') {
    try {
      const params = new URLSearchParams({ limit: String(limit) });
      if (status && status !== 'ALL') params.set('status', status);
      if (severity && severity !== 'ALL') params.set('severity', severity);
      if (userId) params.set('user_id', String(userId));
      if (scope && scope !== 'all') params.set('scope', scope);
      const res = await fetch(`${COGNISEC_API_BASE}/admin/alerts?${params.toString()}`, {
        headers: this.getHeaders()
      });
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn('[COGNISEC-AI] Failed to fetch alerts:', e);
    }
    return [];
  }

  async fetchSocSessions(limit = 100, status = '', riskLevel = '', search = '', scope = 'all') {
    try {
      const params = new URLSearchParams({ limit: String(limit) });
      if (status && status !== 'ALL') params.set('status', status);
      if (riskLevel && riskLevel !== 'ALL') params.set('risk_level', riskLevel);
      if (search) params.set('search', search);
      if (scope && scope !== 'all') params.set('scope', scope);
      const res = await fetch(`${COGNISEC_API_BASE}/admin/sessions?${params.toString()}`, {
        headers: this.getHeaders()
      });
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn('[COGNISEC-AI] Failed to fetch sessions:', e);
    }
    return [];
  }

  async fetchSocUsers(limit = 100, scope = 'all') {
    try {
      const params = new URLSearchParams({ limit: String(limit) });
      if (scope && scope !== 'all') params.set('scope', scope);
      const res = await fetch(`${COGNISEC_API_BASE}/admin/users?${params.toString()}`, {
        headers: this.getHeaders()
      });
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn('[COGNISEC-AI] Failed to fetch users:', e);
    }
    return [];
  }

  async fetchSocDevices(scope = 'all') {
    try {
      const params = new URLSearchParams();
      if (scope && scope !== 'all') params.set('scope', scope);
      const queryStr = params.toString() ? `?${params.toString()}` : '';
      const res = await fetch(`${COGNISEC_API_BASE}/admin/devices${queryStr}`, {
        headers: this.getHeaders()
      });
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn('[COGNISEC-AI] Failed to fetch devices:', e);
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

  async fetchSocIncident(incidentId) {
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/admin/incidents/${incidentId}`, {
        headers: this.getHeaders()
      });
      if (res.ok) return await res.json();
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to fetch incident #${incidentId}`);
    } catch (e) {
      console.warn('[COGNISEC-AI] Failed to fetch incident:', e);
      throw e;
    }
  }

  async triageSocAlert(alertId, status = 'RESOLVED', notes = '', assignedTo = null, resolutionReason = '') {
    try {
      const payload = {
        status,
        notes: notes || null,
        assigned_to: assignedTo || null,
        resolution_reason: resolutionReason || null
      };
      const res = await fetch(`${COGNISEC_API_BASE}/admin/alerts/${alertId}/resolve`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify(payload)
      });
      if (res.ok) return await res.json();
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to triage alert #${alertId}`);
    } catch (e) {
      console.warn('[COGNISEC-AI] Failed to triage alert:', e);
      throw e;
    }
  }

  async fetchSocAuditLogs(action = '', limit = 100) {
    try {
      const params = new URLSearchParams({ limit: String(limit) });
      if (action && action !== 'ALL') params.set('action', action);
      const res = await fetch(`${COGNISEC_API_BASE}/admin/audit-logs?${params.toString()}`, {
        headers: this.getHeaders()
      });
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn('[COGNISEC-AI] Failed to fetch audit logs:', e);
    }
    return [];
  }

  async fetchSocAnalytics(timeWindow = '24h') {
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/admin/analytics?time_window=${encodeURIComponent(timeWindow)}`, {
        headers: this.getHeaders()
      });
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn('[COGNISEC-AI] Failed to fetch analytics:', e);
    }
    return null;
  }

  async fetchSocSystemHealth() {
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/admin/system-health`, {
        headers: this.getHeaders()
      });
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn('[COGNISEC-AI] Failed to fetch system health:', e);
    }
    return null;
  }

  async triggerSocRescan() {
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/admin/rescan`, {
        method: 'POST',
        headers: this.getHeaders()
      });
      if (res.ok) return await res.json();
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to execute system re-scan');
    } catch (e) {
      console.warn('[COGNISEC-AI] Failed to trigger rescan:', e);
      throw e;
    }
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

  // --- REAL STEP-UP MFA VERIFICATION ENGINE & MODAL CONTROLLER ---
  async getSessionSecurityStatus(sessionId = null) {
    const sid = sessionId || this.sessionId;
    if (!sid) return null;
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/security/status/${sid}`, {
        headers: this.getHeaders()
      });
      if (res.ok) {
        const data = await res.json();
        this.sessionStatus = data.session_status || this.sessionStatus;
        return data;
      }
    } catch (e) {
      console.warn('[COGNISEC-AI] Failed to fetch session security status:', e.message);
    }
    return null;
  }

  async requestStepUpChallenge(preferredFactor = null, sessionId = null) {
    const sid = sessionId || this.sessionId;
    if (!sid) return { success: false, error: 'No active session token available' };
    try {
      const body = {
        session_id: sid,
        application: this.application || 'platform',
        resource: this.currentTargetResource || null
      };
      if (preferredFactor) body.preferred_factor = preferredFactor;
      const res = await fetch(`${COGNISEC_API_BASE}/security/step-up/challenge`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify(body)
      });
      let data = {};
      try { data = await res.json(); } catch (_) {}
      if (!res.ok) {
        const detail = typeof data.detail === 'string' ? data.detail : (Array.isArray(data.detail) ? data.detail.map(d => d.msg).join('; ') : '');
        return { success: false, status: res.status, error: detail || `Failed to generate step-up challenge (HTTP ${res.status}).` };
      }
      this.currentChallenge = data;
      return { success: true, data };
    } catch (err) {
      return { success: false, error: 'Could not reach the security server to create the NeuralTrace challenge. Please retry.' };
    }
  }


  async verifyStepUpChallenge(challengeCode, sessionId = null) {
    const sid = sessionId || this.sessionId;
    if (!sid) return { success: false, error: 'No active session token available' };
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/security/step-up/verify`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({ session_id: sid, challenge_code: challengeCode })
      });
      const data = await res.json();
      if (!res.ok) {
        return { success: false, error: data.detail || 'Verification failed' };
      }
      this.sessionStatus = 'ACTIVE';
      return { success: true, data };
    } catch (err) {
      return { success: false, error: err.message };
    }
  }

  // --- ADAPTIVE MULTI-FACTOR METHODS ---
  async getAdaptiveCatalogue() {
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/security/adaptive/catalogue`);
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn('[COGNISEC-AI] Failed to fetch cognitive catalogue:', e.message);
    }
    return [];
  }

  async getAdaptiveStatus() {
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/security/adaptive/status`, {
        headers: this.getHeaders()
      });
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn('[COGNISEC-AI] Failed to fetch adaptive status:', e.message);
    }
    return null;
  }

  async getBehaviorProfile() {
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/behavior/profile`, {
        headers: this.getHeaders()
      });
      if (res.ok) {
        const data = await res.json();
        return { success: true, data };
      }
      const data = await res.json().catch(() => ({}));
      return { success: false, error: data.detail || 'Failed to fetch behavior profile' };
    } catch (e) {
      return { success: false, error: e.message };
    }
  }

  async getBehaviorLogs(limit = 20) {
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/behavior/logs?limit=${limit}`, {
        headers: this.getHeaders()
      });
      if (res.ok) {
        const data = await res.json();
        return { success: true, data };
      }
      const data = await res.json().catch(() => ({}));
      return { success: false, error: data.detail || 'Failed to fetch behavior logs' };
    } catch (e) {
      return { success: false, error: e.message };
    }
  }

  async enrollGesturePattern(pattern, confirmPattern) {
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/security/adaptive/enroll/gesture`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({ pattern, confirm_pattern: confirmPattern })
      });
      const data = await res.json();
      if (!res.ok) return { success: false, error: data.detail || 'Enrollment failed' };
      return { success: true, data };
    } catch (e) {
      return { success: false, error: e.message };
    }
  }

  async enrollImageSequence(imageSequence, confirmImageSequence) {
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/security/adaptive/enroll/image-sequence`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({ image_sequence: imageSequence, confirm_image_sequence: confirmImageSequence })
      });
      const data = await res.json();
      if (!res.ok) return { success: false, error: data.detail || 'Enrollment failed' };
      return { success: true, data };
    } catch (e) {
      return { success: false, error: e.message };
    }
  }

  async enrollPrivateResponse(question, response, confirmResponse) {
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/security/adaptive/enroll/private-response`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({ question, response, confirm_response: confirmResponse })
      });
      const data = await res.json();
      if (!res.ok) return { success: false, error: data.detail || 'Enrollment failed' };
      return { success: true, data };
    } catch (e) {
      return { success: false, error: e.message };
    }
  }

  async requestNeuralTraceReset() {
    if (!this.token) return { success: false, error: 'Authentication required' };
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/security/adaptive/neuraltrace/reset-request`, {
        method: 'POST',
        headers: this.getHeaders()
      });
      const data = await res.json();
      if (!res.ok) {
        return { success: false, error: data.detail || 'Failed to request reset verification code' };
      }
      return data;
    } catch (err) {
      return { success: false, error: err.message };
    }
  }

  async verifyNeuralTraceReset(resetChallengeId, otp) {
    if (!this.token) return { success: false, error: 'Authentication required' };
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/security/adaptive/neuraltrace/reset-verify`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({
          reset_challenge_id: resetChallengeId,
          otp: otp
        })
      });
      const data = await res.json();
      if (!res.ok) {
        return { success: false, error: data.detail || 'Verification failed. Please check the code.' };
      }
      return data;
    } catch (err) {
      return { success: false, error: err.message };
    }
  }

  async confirmNeuralTraceReset(resetTicket, pattern, confirmPattern) {
    if (!this.token) return { success: false, error: 'Authentication required' };
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/security/adaptive/neuraltrace/reset-confirm`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({
          reset_ticket: resetTicket,
          pattern: pattern,
          confirm_pattern: confirmPattern
        })
      });
      const data = await res.json();
      if (!res.ok) {
        return { success: false, error: data.detail || 'Failed to confirm new route' };
      }
      return data;
    } catch (err) {
      return { success: false, error: err.message };
    }
  }

  async verifyAdaptiveChallenge(payload, sessionId = null) {
    const sid = sessionId || this.sessionId;
    if (!sid) return { success: false, error: 'No active session token available' };
    try {
      const body = {
        session_id: sid,
        application: this.application || 'platform',
        resource: this.currentTargetResource || null,
        ...payload
      };
      const res = await fetch(`${COGNISEC_API_BASE}/security/step-up/verify`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify(body)
      });
      const data = await res.json();
      if (!res.ok) return { success: false, error: data.detail || 'Verification failed' };
      if (data.decision === 'ALLOW') {
        this.sessionStatus = data.session_status || 'ACTIVE';
      }
      return { success: true, data };
    } catch (err) {
      return { success: false, error: err.message };
    }
  }

  // --- ADAPTIVE FACTOR ENROLLMENT MODAL (ZERO TRUST STEP 3) ---

  ensureFactorEnrollmentModalInDom() {
    if (document.getElementById('modal-factor-enrollment')) return;

    if (!document.getElementById('cognisec-factor-enroll-styles')) {
      const styleEl = document.createElement('style');
      styleEl.id = 'cognisec-factor-enroll-styles';
      styleEl.textContent = `
        .fem-symbol-grid {
          display: grid;
          grid-template-columns: repeat(3, minmax(0, 1fr));
          gap: 0.65rem;
        }
        .fem-symbol-card {
          border-radius: 0.75rem;
          background-color: rgba(15, 10, 25, 0.85);
          border: 1px solid rgba(185, 28, 28, 0.35);
          padding: 0.75rem 0.5rem;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          text-align: center;
          gap: 0.35rem;
          cursor: pointer;
          transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
          position: relative;
          user-select: none;
        }
        .fem-symbol-card:hover {
          border-color: rgba(239, 68, 68, 0.75);
          background-color: rgba(220, 38, 38, 0.12);
          transform: translateY(-2px);
        }
        .fem-symbol-card.selected {
          border-color: #f59e0b;
          background-color: rgba(245, 158, 11, 0.18);
          box-shadow: 0 0 16px rgba(245, 158, 11, 0.35);
        }
        .fem-symbol-order-badge {
          position: absolute;
          top: 4px;
          right: 4px;
          width: 18px;
          height: 18px;
          border-radius: 9999px;
          background: #f59e0b;
          color: #000000;
          font-weight: 800;
          font-size: 10px;
          line-height: 18px;
          text-align: center;
          box-shadow: 0 0 8px rgba(245, 158, 11, 0.6);
        }
      `;
      document.head.appendChild(styleEl);
    }

    const modalDiv = document.createElement('div');
    modalDiv.id = 'modal-factor-enrollment';
    modalDiv.className = 'fixed inset-0 z-[110] hidden bg-black/85 backdrop-blur-xl flex items-center justify-center p-3 sm:p-4 font-mono animate-fade-in overflow-y-auto overscroll-contain';
    modalDiv.innerHTML = `
      <div id="factor-enroll-container" class="relative w-full max-w-xl max-h-[calc(100vh-2rem)] max-h-[calc(100dvh-2rem)] bg-[#08050e] border border-amber-600/70 rounded-2xl shadow-[0_0_80px_rgba(245,158,11,0.35)] overflow-hidden flex flex-col my-auto box-border">
        <!-- HEADER -->
        <div class="px-5 py-3.5 border-b border-amber-950/80 flex items-center justify-between bg-gradient-to-r from-amber-950/50 via-black to-red-950/30 flex-shrink-0">
          <div class="flex items-center gap-3">
            <div class="p-2 rounded-xl bg-amber-500/10 border border-amber-500/40 text-amber-400">
              <svg class="w-5 h-5" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            </div>
            <div>
              <h3 class="font-heading font-extrabold text-base text-white tracking-wide">ADAPTIVE FACTOR ENROLLMENT</h3>
              <p class="text-[11px] font-mono text-amber-300">Knowledge-Based Authenticators (Zero Trust)</p>
            </div>
          </div>
          <button id="fem-btn-close" onclick="window.cognisec && window.cognisec.closeFactorEnrollmentModal()" class="p-2 rounded-xl bg-red-950/60 hover:bg-red-900/80 border border-red-800/50 text-slate-400 hover:text-white transition-colors cursor-pointer" title="Close">✕</button>
        </div>

        <!-- LIVE FACTOR INVENTORY & STATUS BAR -->
        <div class="px-5 py-3 bg-black/60 border-b border-slate-800/80 flex-shrink-0 space-y-2">
          <div class="flex items-center justify-between text-xs">
            <span class="text-slate-400 font-bold uppercase tracking-wider text-[10px]">Your Enrolled Factor Inventory:</span>
            <button type="button" onclick="window.cognisec && window.cognisec.refreshFactorEnrollmentStatus()" class="text-[10px] text-amber-400 hover:text-amber-300 font-bold cursor-pointer">🔄 Refresh Status</button>
          </div>
          <div class="grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px]">
            <div class="p-2 rounded-lg bg-slate-950/80 border border-slate-800 flex items-center justify-between">
              <span class="text-slate-400">🖼️ Image Seq:</span>
              <span id="fem-status-badge-image" class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950/80 text-amber-300 border border-amber-800/80">Checking...</span>
            </div>
            <div class="p-2 rounded-lg bg-slate-950/80 border border-slate-800 flex items-center justify-between">
              <span class="text-slate-400">🛡️ Private Resp:</span>
              <span id="fem-status-badge-private" class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950/80 text-amber-300 border border-amber-800/80">Checking...</span>
            </div>
            <div class="p-2 rounded-lg bg-slate-950/80 border border-slate-800 flex items-center justify-between">
              <span class="text-slate-400">⚡ NeuralTrace:</span>
              <span id="fem-status-badge-gesture" class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950/80 text-amber-300 border border-amber-800/80">Checking...</span>
            </div>
          </div>
          <div id="fem-private-prompt-info" class="hidden text-[10px] text-slate-400 truncate">
            <span>Enrolled Prompt: </span><strong id="fem-private-prompt-text" class="text-slate-200"></strong>
          </div>
        </div>

        <!-- TAB NAVIGATION -->
        <div class="flex border-b border-slate-800 bg-[#0d0714] flex-shrink-0">
          <button id="fem-tab-btn-image" type="button" onclick="window.cognisec && window.cognisec.switchFactorEnrollmentTab('image')" class="flex-1 py-2.5 px-3 text-xs font-bold text-center border-b-2 border-amber-500 text-amber-300 cursor-pointer transition-colors">
            🖼️ Image Sequence (3–5 Symbols)
          </button>
          <button id="fem-tab-btn-private" type="button" onclick="window.cognisec && window.cognisec.switchFactorEnrollmentTab('private')" class="flex-1 py-2.5 px-3 text-xs font-bold text-center border-b-2 border-transparent text-slate-400 hover:text-slate-200 cursor-pointer transition-colors">
            🛡️ Private Security Response
          </button>
        </div>

        <!-- MODAL BODY -->
        <div class="p-4 sm:p-5 space-y-4 text-xs text-slate-300 overflow-y-auto flex-1 min-h-0 overscroll-contain">
          <!-- TAB 1: COGNITIVE IMAGE SEQUENCE PANE -->
          <div id="fem-pane-image" class="space-y-3.5">
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-1.5 text-xs">
              <span id="fem-image-instruction" class="text-slate-300">
                Step 1: Select 3 to 5 cognitive symbols from the catalogue in sequence.
              </span>
              <span id="fem-image-stage-tag" class="px-2 py-0.5 rounded text-[10px] bg-amber-950 text-amber-300 border border-amber-800 font-bold self-start sm:self-auto">
                STAGE: INITIAL SEQUENCE
              </span>
            </div>

            <!-- Sequence Strips -->
            <div class="space-y-1.5 font-mono">
              <div class="p-2.5 rounded-lg bg-black border border-slate-800 flex items-center justify-between text-xs min-h-[40px]">
                <span id="fem-image-initial-label" class="text-slate-400 text-[11px]">Chosen Order:</span>
                <div id="fem-image-preview-strip" class="flex items-center gap-1.5 flex-wrap">
                  <span class="text-slate-500 text-[11px]">(Click symbols below)</span>
                </div>
              </div>
              <div id="fem-image-confirm-box" class="hidden p-2.5 rounded-lg bg-amber-950/40 border border-amber-900/60 flex items-center justify-between text-xs min-h-[40px]">
                <span class="text-amber-300 font-bold text-[11px]">Confirm Order:</span>
                <div id="fem-image-confirm-strip" class="flex items-center gap-1.5 flex-wrap">
                  <span class="text-amber-500/70 text-[11px]">(Click symbols in exact order)</span>
                </div>
              </div>
            </div>

            <!-- Symbol Grid (9 items) -->
            <div class="fem-symbol-grid py-1" id="fem-image-grid">
              <!-- Rendered dynamically -->
            </div>

            <div id="fem-image-feedback" class="hidden p-3 rounded-xl text-center text-xs font-mono font-semibold transition-all"></div>

            <div class="flex items-center gap-3 pt-1">
              <button type="button" onclick="window.cognisec && window.cognisec.resetEnrollmentImageSequence()" class="flex-1 py-2.5 px-3 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 text-xs font-bold transition-all cursor-pointer">
                ✕ Clear Selection
              </button>
              <button id="fem-image-action-btn" type="button" onclick="window.cognisec && window.cognisec.advanceOrSubmitFactorEnrollmentImage()" class="flex-[2] py-2.5 px-4 rounded-xl bg-gradient-to-r from-amber-600 to-red-600 hover:from-amber-500 hover:to-red-500 text-white text-xs font-bold shadow-[0_0_20px_rgba(245,158,11,0.4)] transition-all cursor-pointer text-center">
                Proceed to Confirmation →
              </button>
            </div>
          </div>

          <!-- TAB 2: PRIVATE RESPONSE PANE -->
          <div id="fem-pane-private" class="hidden space-y-4">
            <div class="p-3 rounded-xl bg-amber-950/40 border border-amber-800/60 text-[11px] text-amber-200 space-y-1">
              <span class="font-bold flex items-center gap-1.5 text-amber-400">
                <span>⚠️</span> Zero Trust Security Advisory
              </span>
              <p class="leading-relaxed">
                Public facts (birthplace, pet name, high school) are weak answers vulnerable to OSINT. Choose an obscure private fact known strictly to you.
              </p>
              <p class="text-[10px] text-slate-400 pt-0.5">
                Your private answer is normalized and hashed with salted bcrypt. Raw plaintext answers are never saved in local storage or logged.
              </p>
            </div>

            <form id="fem-private-form" onsubmit="window.cognisec && window.cognisec.submitFactorEnrollmentPrivateResponse(event)" class="space-y-3.5 text-xs">
              <div class="space-y-1.5">
                <label for="fem-private-select" class="font-bold text-slate-300 uppercase text-[10px]">Security Question Prompt:</label>
                <select id="fem-private-select" onchange="window.cognisec && window.cognisec.handleEnrollmentPrivateQuestionChange(this)" class="w-full px-3 py-2.5 rounded-xl bg-black/80 border border-slate-700 text-slate-200 focus:outline-none focus:border-amber-500 font-mono">
                  <option value="What was the name of your first childhood robotics or science project?">What was the name of your first childhood robotics or science project?</option>
                  <option value="What code name was assigned to your first programming workstation?">What code name was assigned to your first programming workstation?</option>
                  <option value="What is your secret passphrase known only to your offline identity?">What is your secret passphrase known only to your offline identity?</option>
                  <option value="What was the title of your first cybersecurity research paper?">What was the title of your first cybersecurity research paper?</option>
                  <option value="What was the hardware model of your first offline computing device?">What was the hardware model of your first offline computing device?</option>
                  <option value="__custom__">-- Enter Custom Security Question --</option>
                </select>
                <input id="fem-private-custom-q" type="text" placeholder="Type your custom security question (min 5 chars)" class="hidden w-full mt-2 px-3 py-2.5 rounded-xl bg-black/80 border border-slate-700 text-slate-200 focus:outline-none focus:border-amber-500 font-mono" />
              </div>

              <div class="space-y-1.5">
                <label for="fem-private-resp" class="font-bold text-slate-300 uppercase text-[10px]">Private Response (Secret Answer):</label>
                <div class="relative flex items-center">
                  <input id="fem-private-resp" type="password" required placeholder="Enter private secret response (min 3 chars)" autocomplete="off" class="w-full pl-3 pr-11 py-2.5 rounded-xl bg-black/80 border border-slate-700 text-slate-100 placeholder-slate-600 focus:outline-none focus:border-amber-500 font-mono" />
                  <button type="button" onclick="window.togglePasswordVisibility('fem-private-resp', this)" aria-label="Show secret response" title="Show secret response" class="absolute right-3 p-1 rounded-lg text-slate-400 hover:text-white focus:outline-none focus:ring-1 focus:ring-amber-500 cursor-pointer transition-colors">
                    ${EYE_ON_SVG}
                  </button>
                </div>
              </div>

              <div class="space-y-1.5">
                <label for="fem-private-confirm" class="font-bold text-slate-300 uppercase text-[10px]">Confirm Private Response:</label>
                <div class="relative flex items-center">
                  <input id="fem-private-confirm" type="password" required placeholder="Re-enter secret response to confirm" autocomplete="off" class="w-full pl-3 pr-11 py-2.5 rounded-xl bg-black/80 border border-slate-700 text-slate-100 placeholder-slate-600 focus:outline-none focus:border-amber-500 font-mono" />
                  <button type="button" onclick="window.togglePasswordVisibility('fem-private-confirm', this)" aria-label="Show secret response" title="Show secret response" class="absolute right-3 p-1 rounded-lg text-slate-400 hover:text-white focus:outline-none focus:ring-1 focus:ring-amber-500 cursor-pointer transition-colors">
                    ${EYE_ON_SVG}
                  </button>
                </div>
              </div>

              <div id="fem-private-feedback" class="hidden p-3 rounded-xl text-center text-xs font-mono font-semibold transition-all"></div>

              <button id="fem-private-btn-submit" type="submit" class="w-full py-2.5 px-4 rounded-xl bg-gradient-to-r from-red-600 to-amber-600 hover:from-red-500 hover:to-amber-500 text-white font-bold text-xs uppercase tracking-wider shadow-[0_0_20px_rgba(245,158,11,0.4)] transition-all cursor-pointer">
                Save &amp; Enroll Private Response →
              </button>
            </form>
          </div>
        </div>
      </div>
    `;
    document.body.appendChild(modalDiv);
  }

  async openFactorEnrollmentModal(tab = 'image') {
    this.ensureFactorEnrollmentModalInDom();
    const modal = document.getElementById('modal-factor-enrollment');
    if (!modal) return;

    modal.classList.remove('hidden');
    this.switchFactorEnrollmentTab(tab);
    await this.refreshFactorEnrollmentStatus();

    this.resetEnrollmentImageSequence();
    await this.renderFactorEnrollmentImageGrid();
  }

  closeFactorEnrollmentModal() {
    const modal = document.getElementById('modal-factor-enrollment');
    if (modal) modal.classList.add('hidden');
    const feedbackImg = document.getElementById('fem-image-feedback');
    const feedbackPriv = document.getElementById('fem-private-feedback');
    if (feedbackImg) feedbackImg.className = 'hidden';
    if (feedbackPriv) feedbackPriv.className = 'hidden';
  }

  async refreshFactorEnrollmentStatus() {
    const bImg = document.getElementById('fem-status-badge-image');
    const bPriv = document.getElementById('fem-status-badge-private');
    const bGest = document.getElementById('fem-status-badge-gesture');
    const promptInfo = document.getElementById('fem-private-prompt-info');
    const promptText = document.getElementById('fem-private-prompt-text');

    if (bImg) bImg.textContent = 'Checking...';
    if (bPriv) bPriv.textContent = 'Checking...';
    if (bGest) bGest.textContent = 'Checking...';

    const status = await this.getAdaptiveStatus();
    if (!status) {
      if (bImg) bImg.textContent = 'Offline';
      if (bPriv) bPriv.textContent = 'Offline';
      if (bGest) bGest.textContent = 'Offline';
      return null;
    }

    if (bImg) {
      if (status.has_cognitive_image_sequence) {
        bImg.textContent = 'Enrolled ✓';
        bImg.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800';
      } else {
        bImg.textContent = 'Not Enrolled';
        bImg.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950/80 text-amber-300 border border-amber-800/80';
      }
    }

    if (bPriv) {
      if (status.has_private_response) {
        bPriv.textContent = 'Enrolled ✓';
        bPriv.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800';
      } else {
        bPriv.textContent = 'Not Enrolled';
        bPriv.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950/80 text-amber-300 border border-amber-800/80';
      }
    }

    if (bGest) {
      if (status.has_gesture_pattern) {
        bGest.textContent = 'Enrolled ✓';
        bGest.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800';
      } else {
        bGest.textContent = 'Not Enrolled';
        bGest.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950/80 text-amber-300 border border-amber-800/80';
      }
    }

    if (promptInfo && promptText) {
      if (status.private_question) {
        promptText.textContent = `"${status.private_question}"`;
        promptInfo.classList.remove('hidden');
      } else {
        promptInfo.classList.add('hidden');
      }
    }

    window.dispatchEvent(new CustomEvent('cognisec:adaptive_status_updated', { detail: status }));
    return status;
  }

  switchFactorEnrollmentTab(tab) {
    this.factorEnrollState.tab = tab;
    const btnImg = document.getElementById('fem-tab-btn-image');
    const btnPriv = document.getElementById('fem-tab-btn-private');
    const paneImg = document.getElementById('fem-pane-image');
    const panePriv = document.getElementById('fem-pane-private');

    if (tab === 'image') {
      if (btnImg) {
        btnImg.className = 'flex-1 py-2.5 px-3 text-xs font-bold text-center border-b-2 border-amber-500 text-amber-300 cursor-pointer transition-colors';
      }
      if (btnPriv) {
        btnPriv.className = 'flex-1 py-2.5 px-3 text-xs font-bold text-center border-b-2 border-transparent text-slate-400 hover:text-slate-200 cursor-pointer transition-colors';
      }
      if (paneImg) paneImg.classList.remove('hidden');
      if (panePriv) panePriv.classList.add('hidden');
    } else {
      if (btnPriv) {
        btnPriv.className = 'flex-1 py-2.5 px-3 text-xs font-bold text-center border-b-2 border-amber-500 text-amber-300 cursor-pointer transition-colors';
      }
      if (btnImg) {
        btnImg.className = 'flex-1 py-2.5 px-3 text-xs font-bold text-center border-b-2 border-transparent text-slate-400 hover:text-slate-200 cursor-pointer transition-colors';
      }
      if (paneImg) paneImg.classList.add('hidden');
      if (panePriv) panePriv.classList.remove('hidden');
    }
  }

  async renderFactorEnrollmentImageGrid() {
    const grid = document.getElementById('fem-image-grid');
    if (!grid) return;

    let catalogue = this.factorEnrollState.catalogue;
    if (!catalogue || catalogue.length === 0) {
      catalogue = await this.getAdaptiveCatalogue();
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
      this.factorEnrollState.catalogue = catalogue;
    }

    grid.innerHTML = catalogue.map(item => `
      <div class="fem-symbol-card" data-symbol="${item.id}" onclick="window.cognisec && window.cognisec.handleFactorEnrollmentImageClick('${item.id}')">
        <span class="text-2xl">${item.icon}</span>
        <span class="text-[10px] text-slate-300 font-bold">${item.label}</span>
      </div>
    `).join('');
    this.updateFactorEnrollmentImageVisuals();
  }

  handleFactorEnrollmentImageClick(symbolId) {
    if (this.factorEnrollState.step === 1) {
      // Prevent duplicates in initial selection
      if (this.factorEnrollState.initialSeq.includes(symbolId)) return;
      if (this.factorEnrollState.initialSeq.length >= 5) return;
      this.factorEnrollState.initialSeq.push(symbolId);
    } else {
      if (this.factorEnrollState.confirmSeq.length >= this.factorEnrollState.initialSeq.length) return;
      this.factorEnrollState.confirmSeq.push(symbolId);
    }
    this.updateFactorEnrollmentImageVisuals();
  }

  updateFactorEnrollmentImageVisuals() {
    const initialStrip = document.getElementById('fem-image-preview-strip');
    const confirmStrip = document.getElementById('fem-image-confirm-strip');
    const confirmBox = document.getElementById('fem-image-confirm-box');
    const initialLabel = document.getElementById('fem-image-initial-label');
    const cards = document.querySelectorAll('#fem-image-grid .fem-symbol-card');

    if (initialStrip) {
      if (this.factorEnrollState.initialSeq.length === 0) {
        initialStrip.innerHTML = '<span class="text-slate-500 text-[11px]">(Click symbols below)</span>';
      } else {
        initialStrip.innerHTML = this.factorEnrollState.initialSeq.map((id, i) => {
          return `<span class="px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-700 text-[10px] font-bold">${i+1}. ${id.replace('img_', '')}</span>`;
        }).join('');
      }
    }

    if (this.factorEnrollState.step === 2) {
      if (initialLabel) initialLabel.textContent = 'Target Order:';
      if (confirmBox) confirmBox.classList.remove('hidden');
      if (confirmStrip) {
        if (this.factorEnrollState.confirmSeq.length === 0) {
          confirmStrip.innerHTML = '<span class="text-amber-500/70 text-[11px]">(Click symbols in exact order)</span>';
        } else {
          confirmStrip.innerHTML = this.factorEnrollState.confirmSeq.map((id, i) => {
            return `<span class="px-2 py-0.5 rounded bg-amber-900/80 text-white border border-amber-500 text-[10px] font-bold">${i+1}. ${id.replace('img_', '')}</span>`;
          }).join('');
        }
      }
    } else {
      if (initialLabel) initialLabel.textContent = 'Chosen Order:';
      if (confirmBox) confirmBox.classList.add('hidden');
    }

    const activeList = this.factorEnrollState.step === 1 ? this.factorEnrollState.initialSeq : this.factorEnrollState.confirmSeq;
    cards.forEach(card => {
      const sym = card.getAttribute('data-symbol');
      const idx = activeList.indexOf(sym);
      const existingBadge = card.querySelector('.fem-symbol-order-badge');
      if (idx !== -1) {
        card.classList.add('selected');
        if (!existingBadge) {
          const badge = document.createElement('span');
          badge.className = 'fem-symbol-order-badge';
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

  resetEnrollmentImageSequence() {
    this.factorEnrollState.step = 1;
    this.factorEnrollState.initialSeq = [];
    this.factorEnrollState.confirmSeq = [];
    this.updateFactorEnrollmentImageVisuals();

    const tag = document.getElementById('fem-image-stage-tag');
    if (tag) {
      tag.textContent = 'STAGE: INITIAL SEQUENCE';
      tag.className = 'px-2 py-0.5 rounded text-[10px] bg-amber-950 text-amber-300 border border-amber-800 font-bold self-start sm:self-auto';
    }

    const instr = document.getElementById('fem-image-instruction');
    if (instr) instr.textContent = 'Step 1: Select 3 to 5 cognitive symbols from the catalogue in sequence.';

    const actionBtn = document.getElementById('fem-image-action-btn');
    if (actionBtn) {
      actionBtn.textContent = 'Proceed to Confirmation →';
      actionBtn.className = 'flex-[2] py-2.5 px-4 rounded-xl bg-gradient-to-r from-amber-600 to-red-600 hover:from-amber-500 hover:to-red-500 text-white text-xs font-bold shadow-[0_0_20px_rgba(245,158,11,0.4)] transition-all cursor-pointer text-center';
    }

    const feedback = document.getElementById('fem-image-feedback');
    if (feedback) feedback.className = 'hidden';
  }

  async advanceOrSubmitFactorEnrollmentImage() {
    const feedback = document.getElementById('fem-image-feedback');
    if (feedback) feedback.className = 'hidden';

    if (this.factorEnrollState.step === 1) {
      if (this.factorEnrollState.initialSeq.length < 3 || this.factorEnrollState.initialSeq.length > 5) {
        if (feedback) {
          feedback.className = 'p-3 rounded-xl bg-amber-950/70 border border-amber-800 text-amber-300 text-xs font-mono block';
          feedback.textContent = 'Sequence must contain between 3 and 5 distinct symbols.';
        }
        return;
      }

      this.factorEnrollState.step = 2;
      this.factorEnrollState.confirmSeq = [];
      this.updateFactorEnrollmentImageVisuals();

      const tag = document.getElementById('fem-image-stage-tag');
      if (tag) {
        tag.textContent = 'STAGE: CONFIRMATION';
        tag.className = 'px-2 py-0.5 rounded text-[10px] bg-amber-950 text-amber-300 border border-amber-800 font-bold self-start sm:self-auto';
      }

      const instr = document.getElementById('fem-image-instruction');
      if (instr) instr.textContent = 'Step 2: Repeat your chosen sequence in exact order to confirm.';

      const actionBtn = document.getElementById('fem-image-action-btn');
      if (actionBtn) {
        actionBtn.textContent = 'Submit & Enroll Image Sequence ✓';
        actionBtn.className = 'flex-[2] py-2.5 px-4 rounded-xl bg-gradient-to-r from-emerald-600 to-emerald-700 hover:from-emerald-500 hover:to-emerald-600 text-white text-xs font-bold shadow-[0_0_20px_rgba(16,185,129,0.4)] transition-all cursor-pointer text-center';
      }
    } else {
      if (this.factorEnrollState.confirmSeq.length < this.factorEnrollState.initialSeq.length) {
        if (feedback) {
          feedback.className = 'p-3 rounded-xl bg-amber-950/70 border border-amber-800 text-amber-300 text-xs font-mono block';
          feedback.textContent = `Please enter all ${this.factorEnrollState.initialSeq.length} symbols to complete confirmation.`;
        }
        return;
      }

      const match = JSON.stringify(this.factorEnrollState.initialSeq) === JSON.stringify(this.factorEnrollState.confirmSeq);
      if (!match) {
        if (feedback) {
          feedback.className = 'p-3 rounded-xl bg-red-950/70 border border-red-800 text-red-300 text-xs font-mono block';
          feedback.textContent = 'Confirmation sequence does not match initial selection. Try again or reset.';
        }
        this.factorEnrollState.confirmSeq = [];
        this.updateFactorEnrollmentImageVisuals();
        return;
      }

      const actionBtn = document.getElementById('fem-image-action-btn');
      if (actionBtn) {
        actionBtn.disabled = true;
        actionBtn.textContent = 'Enrolling Sequence Factor...';
      }

      try {
        const res = await this.enrollImageSequence(this.factorEnrollState.initialSeq, this.factorEnrollState.confirmSeq);
        if (res.success) {
          if (feedback) {
            feedback.className = 'p-3 rounded-xl bg-emerald-950/70 border border-emerald-600 text-emerald-300 text-xs font-mono block';
            feedback.textContent = '✓ Cognitive image sequence factor successfully enrolled and protected!';
          }
          await this.refreshFactorEnrollmentStatus();
          window.dispatchEvent(new CustomEvent('cognisec:factor_enrolled', { detail: { factor_type: 'COGNITIVE_IMAGE_SEQUENCE', success: true } }));
          if (typeof window.refreshAdaptiveMfaStatus === 'function') {
            await window.refreshAdaptiveMfaStatus();
          }
          setTimeout(() => this.resetEnrollmentImageSequence(), 2000);
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
  }

  handleEnrollmentPrivateQuestionChange(sel) {
    const customInput = document.getElementById('fem-private-custom-q');
    if (!customInput) return;
    if (sel.value === '__custom__') {
      customInput.classList.remove('hidden');
      customInput.focus();
    } else {
      customInput.classList.add('hidden');
    }
  }

  async submitFactorEnrollmentPrivateResponse(e) {
    if (e && e.preventDefault) e.preventDefault();

    const sel = document.getElementById('fem-private-select');
    const customInput = document.getElementById('fem-private-custom-q');
    const respInput = document.getElementById('fem-private-resp');
    const confirmInput = document.getElementById('fem-private-confirm');
    const feedback = document.getElementById('fem-private-feedback');
    const submitBtn = document.getElementById('fem-private-btn-submit');

    const question = (sel && sel.value === '__custom__')
      ? (customInput ? customInput.value.trim() : '')
      : (sel ? sel.value : '');
    const response = respInput ? respInput.value.trim() : '';
    const confirmResponse = confirmInput ? confirmInput.value.trim() : '';

    if (!question || question.length < 5) {
      if (feedback) {
        feedback.className = 'p-3 rounded-xl bg-amber-950/70 border border-amber-800 text-amber-300 text-xs font-mono block';
        feedback.textContent = 'Please choose or type a security question of at least 5 characters.';
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
      const res = await this.enrollPrivateResponse(question, response, confirmResponse);
      if (res.success) {
        if (feedback) {
          feedback.className = 'p-3 rounded-xl bg-emerald-950/70 border border-emerald-600 text-emerald-300 text-xs font-mono block';
          feedback.textContent = '✓ Private security response factor successfully enrolled and protected!';
        }
        if (respInput) respInput.value = '';
        if (confirmInput) confirmInput.value = '';
        await this.refreshFactorEnrollmentStatus();
        window.dispatchEvent(new CustomEvent('cognisec:factor_enrolled', { detail: { factor_type: 'PRIVATE_RESPONSE', success: true } }));
        if (typeof window.refreshAdaptiveMfaStatus === 'function') {
          await window.refreshAdaptiveMfaStatus();
        }
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
  }

  ensureObservationModalInDom() {
    if (document.getElementById('modal-login-observation')) return;

    const modalDiv = document.createElement('div');
    modalDiv.id = 'modal-login-observation';
    modalDiv.className = 'fixed inset-0 z-50 hidden bg-black/85 backdrop-blur-xl flex items-center justify-center p-4 font-mono animate-fade-in';
    modalDiv.innerHTML = `
      <div id="obs-modal-container" class="relative w-full max-w-lg bg-[#08050e] border border-red-900/60 rounded-2xl shadow-[0_0_80px_rgba(220,38,38,0.4)] overflow-hidden flex flex-col transition-all duration-300">
        <div class="px-6 py-4 border-b border-red-950 flex items-center justify-between bg-gradient-to-r from-red-950/40 via-black to-red-950/20">
          <div class="flex items-center gap-3">
            <div class="p-2 rounded-xl bg-red-950/80 border border-red-800 text-red-400">
              <svg class="w-5 h-5" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>
            </div>
            <div>
              <h3 id="obs-modal-title" class="font-heading font-extrabold text-base text-white tracking-wide">COGNISEC-AI AUTHENTICATION</h3>
              <p id="obs-modal-subtitle" class="text-xs font-mono text-slate-400">Mandatory Identity Verification</p>
            </div>
          </div>
          <div class="flex items-center gap-2">
            <span id="obs-stage-badge" class="px-2.5 py-1 rounded-full text-[10px] font-mono font-bold bg-amber-950 text-amber-300 border border-amber-700/60 uppercase tracking-wider">STAGE 2: OTP</span>
            <button id="obs-modal-close-btn" type="button" onclick="window.closeObservationOtpModal ? window.closeObservationOtpModal() : (window.cognisec && window.cognisec.closeObservationOtpModal())" class="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-red-950/50 transition-colors" title="Close">✕</button>
          </div>
        </div>

        <div id="obs-otp-view" class="p-6 sm:p-8 space-y-6">
          <div class="text-center space-y-2 max-w-md mx-auto">
            <div class="inline-flex p-3 rounded-2xl bg-red-950/50 border border-red-800 text-red-400 mb-1">
              <svg class="w-8 h-8" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>
            </div>
            <h4 class="font-heading font-bold text-xl text-white">Mandatory Identity Verification</h4>
            <p class="text-xs font-mono text-slate-300 leading-relaxed">Behavioral observation complete. Enter the 6-digit verification code dispatched via Gmail SMTP to your registered email.</p>
          </div>
          <div class="p-3 rounded-xl bg-black/70 border border-red-950 flex items-center justify-between text-xs font-mono">
            <div class="flex items-center gap-2">
              <span class="text-slate-400">Sent to:</span>
              <span id="login-otp-dest-email" class="text-white font-bold">registered email</span>
            </div>
            <div class="flex items-center gap-1.5">
              <span class="text-slate-400">Expires:</span>
              <span id="login-otp-expiry-timer" class="text-amber-400 font-bold">05:00</span>
            </div>
          </div>
          <div id="login-otp-error-banner" class="hidden p-3.5 rounded-xl bg-red-950/90 border border-red-700 text-red-200 text-xs font-mono leading-relaxed"></div>
          <div id="login-otp-success-banner" class="hidden p-3.5 rounded-xl bg-emerald-950/90 border border-emerald-700 text-emerald-200 text-xs font-mono leading-relaxed"></div>
          <form id="login-otp-form" onsubmit="window.submitLoginOtpVerification ? window.submitLoginOtpVerification(event) : (window.cognisec && window.cognisec.submitLoginOtpFromForm(event))" class="space-y-4">
            <div class="space-y-2">
              <label for="login-otp-code-input" class="text-xs font-bold text-slate-300 uppercase tracking-wider block text-center font-mono">Enter 6-Digit One-Time Password</label>
              <input id="login-otp-code-input" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" placeholder="000000" autocomplete="one-time-code" required class="w-full text-center text-3xl font-mono font-extrabold tracking-[0.4em] px-4 py-3.5 rounded-xl bg-black border border-red-900/60 text-white focus:outline-none focus:border-red-500 shadow-inner" />
            </div>
            <div class="flex items-center gap-3 pt-2">
              <button id="btn-login-otp-resend" type="button" onclick="window.handleLoginOtpResend ? window.handleLoginOtpResend() : (window.cognisec && window.cognisec.resendLoginOtpFromModal())" class="flex-1 py-3 px-4 rounded-xl bg-black hover:bg-red-950/60 border border-red-900/50 hover:border-red-700 text-slate-300 hover:text-white font-mono font-semibold text-xs uppercase tracking-wider transition-colors cursor-pointer">Resend Code</button>
              <button id="btn-login-otp-verify" type="submit" class="flex-[2] py-3.5 px-5 rounded-xl bg-gradient-to-r from-red-600 to-red-500 hover:from-red-500 hover:to-red-400 text-white font-heading font-extrabold text-xs uppercase tracking-wider shadow-[0_0_20px_rgba(220,38,38,0.5)] transition-all cursor-pointer flex items-center justify-center gap-2"><span>Verify &amp; Activate →</span></button>
            </div>
            <div class="text-center pt-2">
              <button type="button" onclick="window.cancelObservationAndReturnToLogin ? window.cancelObservationAndReturnToLogin() : (window.cognisec && window.cognisec.cancelObservationAndLogout())" class="text-[11px] font-mono text-slate-500 hover:text-slate-300 underline cursor-pointer">Cancel and sign in with another account</button>
            </div>
          </form>
        </div>
      </div>
    `;
    document.body.appendChild(modalDiv);
  }

  ensureStepUpModalInDom() {
    ensureGestureStylesInjected();
    if (document.getElementById('modal-stepup')) return;

    const modalDiv = document.createElement('div');
    modalDiv.id = 'modal-stepup';
    modalDiv.className = 'fixed inset-0 z-[100] hidden bg-black/85 backdrop-blur-xl flex items-center justify-center p-3 sm:p-4 font-mono animate-fade-in overflow-y-auto overscroll-contain';
    modalDiv.innerHTML = `
      <div id="stepup-modal-container" class="relative w-full max-w-lg max-h-[calc(100vh-2rem)] max-h-[calc(100dvh-2rem)] bg-[#08050e] border border-amber-600/70 rounded-2xl shadow-[0_0_80px_rgba(245,158,11,0.35)] overflow-hidden flex flex-col transition-all duration-300 my-auto box-border">
        <div id="stepup-modal-header" class="px-5 py-3 sm:px-6 sm:py-3.5 border-b border-amber-950/80 flex items-center justify-between bg-gradient-to-r from-amber-950/50 via-black to-red-950/30 flex-shrink-0">
          <div class="flex items-center gap-3">
            <div id="stepup-modal-icon" class="p-2 rounded-xl bg-amber-500/10 border border-amber-500/40 text-amber-400">
              <svg class="w-5 h-5" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/><circle cx="12" cy="16" r="1"/></svg>
            </div>
            <div>
              <h3 id="stepup-modal-title" class="font-heading font-extrabold text-base text-white tracking-wide">ZERO TRUST STEP-UP VERIFICATION</h3>
              <p id="stepup-modal-subtitle" class="text-[11px] font-mono text-amber-300">Continuous Identity Re-Authentication</p>
            </div>
          </div>
          <button id="stepup-btn-close" onclick="window.cognisec && window.cognisec.closeStepUpModal()" class="p-2 rounded-xl bg-red-950/60 hover:bg-red-900/80 border border-red-800/50 text-slate-400 hover:text-white transition-colors cursor-pointer" title="Dismiss">✕</button>
        </div>

        <form id="stepup-form" onsubmit="window.cognisec && window.cognisec.submitStepUpForm(event)" class="flex flex-col flex-1 min-h-0 overflow-hidden m-0 p-0">
          <div id="stepup-modal-body" class="p-4 sm:p-5 space-y-3 sm:space-y-3.5 text-xs text-slate-300 overflow-y-auto flex-1 min-h-0 overscroll-contain">
            <div class="p-3 rounded-xl bg-amber-950/40 border border-amber-800/50 space-y-1">
              <div class="flex items-center justify-between text-amber-400 font-bold text-xs uppercase tracking-wider">
                <span class="flex items-center gap-1.5">
                  <span class="w-2 h-2 rounded-full bg-amber-400 animate-ping"></span>
                  Verification Challenge
                </span>
                <span id="stepup-factor-badge" class="px-2 py-0.5 rounded text-[10px] bg-amber-900 text-amber-200 border border-amber-600 font-bold">FACTOR: OTP</span>
              </div>
              <p id="stepup-reason-text" class="text-[11px] text-slate-300 leading-relaxed font-sans">
                Dynamic risk evaluation requires step-up verification to restore session access. Complete the challenge below.
              </p>
              <div class="flex items-center justify-between pt-1 border-t border-amber-900/40 text-[10px] text-slate-400 font-mono">
                <span id="stepup-session-badge">Session Guard</span>
                <span id="stepup-timer-text" class="text-amber-400 font-bold">Expires: 05:00</span>
              </div>
            </div>

            <!-- FACTOR 1: OTP CALLOUT & INPUT PANE -->
            <div id="stepup-pane-otp" class="space-y-3">
              <div id="stepup-email-delivery-banner" class="p-3 rounded-xl bg-sky-950/40 border border-sky-800/60 text-[11px] font-mono text-sky-200 flex items-center justify-between">
                <span class="flex items-center gap-2">
                  <span class="text-base">📧</span>
                  <span>Code dispatched to: <strong id="stepup-recipient-email" class="text-white">registered email</strong></span>
                </span>
                <span class="text-[10px] text-sky-400 font-bold bg-sky-900/50 px-2 py-0.5 rounded border border-sky-700/50">OUT-OF-BAND</span>
              </div>

              <div id="stepup-demo-callout" class="hidden p-3 rounded-xl bg-slate-900/90 border border-amber-600/50 space-y-1 font-mono text-[11px]">
                <div class="flex items-center justify-between">
                  <span class="text-amber-400 uppercase text-[10px] font-bold">⚡ [DEV ONLY] Exhibition Delivery Fallback</span>
                </div>
                <p class="text-slate-400 text-[10px] leading-relaxed">
                  Exhibition mode is enabled for development/grading demonstration. The backend generated OTP is:
                </p>
                <div class="flex items-center justify-between pt-1">
                  <span class="text-slate-400 text-[10px]">Challenge OTP:</span>
                  <span id="stepup-demo-otp" class="px-2.5 py-1 rounded bg-black border border-amber-500/60 text-amber-400 font-mono font-extrabold tracking-widest text-xs">------</span>
                </div>
              </div>

              <div class="space-y-1.5">
                <label for="stepup-otp-input" class="text-xs font-bold text-slate-200 uppercase tracking-wider font-mono">
                  Enter 6-Digit Challenge Code:
                </label>
                <div class="relative">
                  <input
                    id="stepup-otp-input"
                    type="text"
                    maxlength="6"
                    inputmode="numeric"
                    pattern="[0-9]*"
                    autocomplete="one-time-code"
                    placeholder="••••••"
                    class="w-full px-4 py-3 rounded-xl bg-black/80 border border-slate-700 text-center font-mono text-xl tracking-[0.5em] text-white placeholder-slate-600 focus:outline-none focus:border-amber-500 transition-colors"
                  />
                </div>
              </div>
            </div>

            <!-- FACTOR 2: NEURALTRACE GRAPH CHALLENGE PANE -->
            <div id="stepup-pane-gesture" class="hidden space-y-2.5">
              <div class="flex items-center justify-between text-xs">
                <span id="stepup-gesture-title" class="text-cyan-400 font-bold uppercase tracking-wider font-mono">NEURALTRACE — RECONSTRUCT SIGNAL:</span>
                <button id="stepup-gesture-reset-btn" type="button" onclick="window.cognisec && window.cognisec.clearChallengeGesture()" class="text-[10px] text-cyan-400 hover:text-cyan-300 font-bold cursor-pointer font-mono">Clear / Reset</button>
              </div>
              <div class="p-2 rounded-lg bg-black border border-slate-800 flex items-center justify-between text-xs font-mono">
                <span class="text-slate-400 text-[11px]">Route Progress:</span>
                <span id="stepup-gesture-display" class="text-cyan-400 font-bold">Press a starting node and trace a valid connected route</span>
              </div>
              <div id="stepup-gesture-grid" class="neuraltrace-container my-1.5"></div>
              <p id="stepup-gesture-hint" class="text-[10px] text-slate-400 text-center font-mono">Press a starting node and trace a valid connected route (min 4 nodes).</p>
            </div>

            <!-- FACTOR 3: COGNITIVE IMAGE SEQUENCE CHALLENGE PANE -->
            <div id="stepup-pane-image" class="hidden space-y-3">
              <div class="flex items-center justify-between text-xs">
                <span class="text-slate-200 font-bold uppercase tracking-wider">Select Enrolled Image Sequence:</span>
                <button type="button" onclick="window.cognisec && window.cognisec.clearChallengeImageSequence()" class="text-[10px] text-amber-400 hover:text-amber-300 font-bold cursor-pointer">Clear Sequence</button>
              </div>
              <div class="p-2 rounded-lg bg-black border border-slate-800 flex items-center justify-between text-xs font-mono min-h-[38px]">
                <span class="text-slate-400 text-[11px]">Sequence:</span>
                <div id="stepup-image-strip" class="flex items-center gap-1.5 flex-wrap">
                  <span class="text-slate-500 text-[11px]">(Click symbols below)</span>
                </div>
              </div>
              <div class="symbol-grid py-1" id="stepup-image-grid">
                <!-- Rendered dynamically from challenge catalogue -->
              </div>
            </div>

            <!-- FACTOR 4: PRIVATE RESPONSE CHALLENGE PANE -->
            <div id="stepup-pane-private" class="hidden space-y-3">
              <div class="p-3.5 rounded-xl bg-amber-950/50 border border-amber-800 space-y-1">
                <span class="text-[10px] text-amber-400 font-bold uppercase block tracking-wider">Enrolled Security Question:</span>
                <p id="stepup-private-prompt" class="text-xs text-white font-semibold">
                  Loading security question...
                </p>
              </div>
              <div class="space-y-1.5">
                <label for="stepup-private-input" class="text-xs font-bold text-slate-200 uppercase tracking-wider font-mono">
                  Your Private Response:
                </label>
                <div class="relative flex items-center">
                  <input
                    id="stepup-private-input"
                    type="password"
                    autocomplete="off"
                    placeholder="Enter your private secret response"
                    class="w-full pl-4 pr-11 py-3 rounded-xl bg-black/80 border border-slate-700 text-slate-100 placeholder-slate-600 focus:outline-none focus:border-amber-500 font-mono transition-colors"
                  />
                  <button type="button" onclick="window.togglePasswordVisibility('stepup-private-input', this)" aria-label="Show secret response" title="Show secret response" class="absolute right-3 p-1 rounded-lg text-slate-400 hover:text-white focus:outline-none focus:ring-1 focus:ring-amber-500 cursor-pointer transition-colors">
                    ${EYE_ON_SVG}
                  </button>
                </div>
              </div>
            </div>
          </div>

          <!-- FIXED STICKY FOOTER -->
          <div id="stepup-modal-footer" class="p-3 sm:px-5 sm:py-3.5 border-t border-amber-950/80 bg-gradient-to-r from-black via-[#0d0714] to-black flex-shrink-0 space-y-2">
            <div class="flex items-center justify-between text-[10px] sm:text-[11px] font-mono text-slate-400">
              <span>Security Threshold: Zero Trust</span>
              <span id="stepup-attempts-info">3 attempts remaining</span>
            </div>

            <div id="stepup-feedback-banner" class="hidden p-2 rounded-xl text-center text-xs font-mono font-semibold transition-all"></div>

            <div class="flex items-center gap-3">
              <button
                id="stepup-btn-request-new"
                type="button"
                onclick="window.cognisec && window.cognisec.handleStepUpSecondaryAction()"
                class="flex-1 py-2.5 px-3 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 font-mono font-bold text-xs uppercase tracking-wider transition-all cursor-pointer text-center"
              >
                Clear / Reset
              </button>
              <button
                id="stepup-btn-submit"
                type="submit"
                onclick="window.cognisec && window.cognisec.submitStepUpForm(event)"
                class="flex-[2] py-2.5 px-4 rounded-xl bg-gradient-to-r from-amber-600 to-red-600 hover:from-amber-500 hover:to-red-500 text-white font-mono font-bold text-xs uppercase tracking-wider shadow-[0_0_20px_rgba(245,158,11,0.4)] transition-all cursor-pointer flex items-center justify-center gap-2 text-center"
              >
                <span>Verify Route →</span>
              </button>
            </div>
          </div>
        </form>
      </div>
    `;
    document.body.appendChild(modalDiv);
  }

  handleStepUpSecondaryAction() {
    const challenge = this.currentChallenge || {};
    const cType = challenge.challenge_type || this.currentStepUpFactor || 'OTP';
    if (cType === 'GESTURE_PATTERN') {
      if (!this.currentChallenge) {
        this.triggerNewStepUpChallenge(this.currentStepUpFactor || 'GESTURE_PATTERN');
      } else {
        this.clearChallengeGesture();
      }
    } else {
      this.triggerNewStepUpChallenge(this.currentStepUpFactor);
    }
  }

  async openStepUpModal(options = {}) {
    this.ensureStepUpModalInDom();
    const modal = document.getElementById('modal-stepup');
    if (!modal) return;

    if (!modal.classList.contains('hidden')) return; // Already open
    modal.classList.remove('hidden');
    this.isStepUpModalOpen = true;
    this.wasLastStepUpSuccessful = false;
    this.isStepUpSubmitting = false;

    this.currentTargetResource = options.targetResource || null;
    this.stepUpSuccessCallback = options.onSuccess || null;
    this.stepUpCancelCallback = options.onCancel || null;
    this.currentStepUpFactor = options.preferredFactor || null;

    const modalTitle = document.getElementById('stepup-modal-title');
    const modalSubtitle = document.getElementById('stepup-modal-subtitle');
    const feedback = document.getElementById('stepup-feedback-banner');
    const submitBtn = document.getElementById('stepup-btn-submit');
    const reqBtn = document.getElementById('stepup-btn-request-new');
    const attemptsInfo = document.getElementById('stepup-attempts-info');
    const reasonText = document.getElementById('stepup-reason-text');
    const sessionBadge = document.getElementById('stepup-session-badge');

    const isGesture = options.preferredFactor === 'GESTURE_PATTERN';

    if (modalTitle) {
      modalTitle.textContent = options.title || (isGesture ? 'NEURALTRACE — CONFIDENTIAL ACCESS VERIFICATION' : 'ZERO TRUST STEP-UP VERIFICATION');
    }
    if (modalSubtitle) {
      modalSubtitle.textContent = options.subtitle || (isGesture ? 'Additional identity verification is required to access confidential records.' : 'Continuous Identity Re-Authentication');
    }
    if (reasonText) {
      reasonText.textContent = options.reason || (isGesture ? 'Zero Trust verification: Reconstruct your enrolled neural route to authorize confidential access.' : 'Dynamic risk evaluation requires step-up verification to restore session access. Complete the challenge below.');
    }

    const sRef = this.sessionId ? this.sessionId.substring(0, 10) : 'Active';
    const cRef = this.currentChallenge && this.currentChallenge.challenge_id ? this.currentChallenge.challenge_id.substring(0, 10) : 'Pending';
    if (sessionBadge) {
      sessionBadge.textContent = `Session: ${sRef} | Ref: ${cRef}`;
    }

    if (feedback) feedback.className = 'hidden';
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerHTML = isGesture ? `<span>Verify Route →</span>` : `<span>Verify &amp; Restore Access →</span>`;
    }
    if (reqBtn) {
      reqBtn.disabled = false;
      reqBtn.textContent = isGesture ? 'Clear / Reset' : '🔄 Fresh Code';
    }
    if (attemptsInfo) attemptsInfo.textContent = '3 attempts remaining';

    // Reset challenge states
    this.challengeGestureNodes = [];
    this.challengeImageSequence = [];

    // Immediately reveal and initialize the requested challenge factor pane
    const paneOtp = document.getElementById('stepup-pane-otp');
    const paneGesture = document.getElementById('stepup-pane-gesture');
    const paneImage = document.getElementById('stepup-pane-image');
    const panePrivate = document.getElementById('stepup-pane-private');
    if (paneOtp) paneOtp.classList.add('hidden');
    if (paneImage) paneImage.classList.add('hidden');
    if (panePrivate) panePrivate.classList.add('hidden');

    if (isGesture) {
      if (paneGesture) paneGesture.classList.remove('hidden');
      const factorBadge = document.getElementById('stepup-factor-badge');
      if (factorBadge) factorBadge.textContent = 'FACTOR: GESTURE PATTERN';
      this.initStepUpGestureGrid();
    }

    // If an unexpired challenge already exists for this session, reuse it unless forceNew or different factor
    const hasValidChallenge = this.currentChallenge &&
      this.currentChallenge.session_id === this.sessionId &&
      this.currentChallengeExpiresAt &&
      (Date.now() < this.currentChallengeExpiresAt) &&
      (!options.preferredFactor || this.currentChallenge.challenge_type === options.preferredFactor);

    if (hasValidChallenge && !options.forceNew) {
      this.currentChallengePromise = null;
      this.renderChallengeUi(this.currentChallenge);
    } else {
      this.currentChallengePromise = this.triggerNewStepUpChallenge(options.preferredFactor || null);
      await this.currentChallengePromise;
    }
  }

  closeStepUpModal() {
    this.isStepUpModalOpen = false;
    this.currentChallengePromise = null;
    this.currentStepUpFactor = null;
    const modal = document.getElementById('modal-stepup');
    if (modal) {
      modal.classList.add('hidden');
    }
    if (this.stepUpTimerInterval) {
      clearInterval(this.stepUpTimerInterval);
      this.stepUpTimerInterval = null;
    }
    this.isStepUpSubmitting = false;
    this.currentChallengeStage = 1;
    this.currentChallenge = null;
    this.challengeGestureNodes = [];
    this.challengeImageSequence = [];
    if (this.stepupGestureGrid) {
      this.stepupGestureGrid.reset();
    }
    if (typeof this.stepUpCancelCallback === 'function' && !this.wasLastStepUpSuccessful) {
      try {
        this.stepUpCancelCallback();
      } catch (e) {
        console.error('Error in stepUpCancelCallback:', e);
      }
    }
    this.stepUpSuccessCallback = null;
    this.stepUpCancelCallback = null;
    this.currentTargetResource = null;
  }

  async triggerNewStepUpChallenge(preferredFactor = null) {
    const feedback = document.getElementById('stepup-feedback-banner');
    const demoOtpSpan = document.getElementById('stepup-demo-otp');
    const otpInput = document.getElementById('stepup-otp-input');
    const privInput = document.getElementById('stepup-private-input');
    const submitBtn = document.getElementById('stepup-btn-submit');

    if (feedback) feedback.className = 'hidden';
    if (otpInput) {
      otpInput.value = '';
      otpInput.disabled = false;
    }
    if (privInput) {
      privInput.value = '';
      privInput.disabled = false;
    }
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerHTML = preferredFactor === 'GESTURE_PATTERN' ? `<span>Verify Route →</span>` : `<span>Verify &amp; Restore Access →</span>`;
    }
    const reqBtn = document.getElementById('stepup-btn-request-new');
    if (reqBtn && preferredFactor === 'GESTURE_PATTERN') {
      reqBtn.textContent = 'Clear / Reset';
    }
    if (demoOtpSpan) demoOtpSpan.textContent = 'Generating...';

    // Request fresh challenge from backend API
    const res = await this.requestStepUpChallenge(preferredFactor);
    if (!this.isStepUpModalOpen) return;
    if (!res.success) {
      if (feedback) {
        feedback.className = 'p-3 rounded-xl bg-red-950/60 border border-red-800 text-red-300 font-mono text-xs block';
        feedback.textContent = `Challenge Issuance Error: ${res.error || 'Failed to generate challenge. Please click Retry.'}`;
      }
      if (demoOtpSpan) demoOtpSpan.textContent = 'Unavailable';
      const reqBtn = document.getElementById('stepup-btn-request-new');
      if (reqBtn) {
        reqBtn.disabled = false;
        reqBtn.textContent = '🔄 Retry';
      }
      return;
    }

    const challenge = res.data;
    this.currentChallenge = challenge;
    const ttlSecs = challenge.expires_in_seconds || 300;
    this.currentChallengeExpiresAt = Date.now() + (ttlSecs * 1000);

    this.renderChallengeUi(challenge);
  }

  renderChallengeUi(challenge) {
    if (!challenge) return;
    if (!this.isStepUpModalOpen) return;
    const cType = challenge.challenge_type || 'OTP';
    const factorBadge = document.getElementById('stepup-factor-badge');
    if (factorBadge) {
      factorBadge.textContent = `FACTOR: ${cType.replace(/_/g, ' ')}`;
    }

    const sessionBadge = document.getElementById('stepup-session-badge');
    if (sessionBadge) {
      const sRef = this.sessionId ? this.sessionId.substring(0, 10) : 'Active';
      const cRef = challenge.challenge_id ? challenge.challenge_id.substring(0, 10) : 'chal_...';
      sessionBadge.textContent = `Session: ${sRef} | Ref: ${cRef}`;
    }

    const emailSpan = document.getElementById('stepup-recipient-email');
    if (emailSpan && challenge.masked_email) {
      emailSpan.textContent = challenge.masked_email;
    }

    const demoCallout = document.getElementById('stepup-demo-callout');
    const demoOtpSpan = document.getElementById('stepup-demo-otp');
    if (demoCallout) {
      if (challenge.is_demo_otp && challenge.otp) {
        demoCallout.classList.remove('hidden');
        if (demoOtpSpan) demoOtpSpan.textContent = challenge.otp;
      } else {
        demoCallout.classList.add('hidden');
      }
    }

    const submitBtn = document.getElementById('stepup-btn-submit');
    const reqBtn = document.getElementById('stepup-btn-request-new');
    if (cType === 'GESTURE_PATTERN') {
      if (submitBtn) submitBtn.innerHTML = `<span>Verify Route →</span>`;
      if (reqBtn) reqBtn.textContent = 'Clear / Reset';
    } else {
      if (submitBtn) submitBtn.innerHTML = `<span>Verify &amp; Restore Access →</span>`;
      if (reqBtn) reqBtn.textContent = '🔄 Fresh Code';
    }

    const paneOtp = document.getElementById('stepup-pane-otp');
    const paneGesture = document.getElementById('stepup-pane-gesture');
    const paneImage = document.getElementById('stepup-pane-image');
    const panePrivate = document.getElementById('stepup-pane-private');
    const otpInput = document.getElementById('stepup-otp-input');
    const privInput = document.getElementById('stepup-private-input');
    const promptEl = document.getElementById('stepup-private-prompt');

    // Hide all panes first
    if (paneOtp) paneOtp.classList.add('hidden');
    if (paneGesture) paneGesture.classList.add('hidden');
    if (paneImage) paneImage.classList.add('hidden');
    if (panePrivate) panePrivate.classList.add('hidden');

    if (cType === 'OTP') {
      if (paneOtp) paneOtp.classList.remove('hidden');
      if (otpInput) {
        otpInput.focus();
        otpInput.oninput = (e) => {
          e.target.value = e.target.value.replace(/[^0-9]/g, '');
        };
      }
    } else if (cType === 'GESTURE_PATTERN') {
      if (paneGesture) paneGesture.classList.remove('hidden');
      this.initStepUpGestureGrid();
    } else if (cType === 'COGNITIVE_IMAGE_SEQUENCE') {
      if (paneImage) paneImage.classList.remove('hidden');
      this.clearChallengeImageSequence();
      this.renderChallengeImageGrid(challenge.catalogue);
    } else if (cType === 'PRIVATE_RESPONSE') {
      if (panePrivate) panePrivate.classList.remove('hidden');
      if (promptEl) {
        promptEl.textContent = challenge.prompt || 'Answer your registered private security question:';
      }
      if (privInput) privInput.focus();
    } else if (cType === 'HIGH_RISK_DUAL') {
      this.currentChallengeStage = 1;
      if (factorBadge) {
        factorBadge.textContent = 'HIGH RISK: STAGE 1 (IMAGE SEQUENCE)';
      }
      if (submitBtn) {
        submitBtn.innerHTML = '<span>Verify Stage 1 →</span>';
      }
      if (paneImage) paneImage.classList.remove('hidden');
      if (panePrivate) panePrivate.classList.add('hidden');
      this.clearChallengeImageSequence();
      this.renderChallengeImageGrid(challenge.catalogue);
      if (privInput) privInput.value = '';
    }

    const remainingSecs = this.currentChallengeExpiresAt
      ? Math.max(1, Math.floor((this.currentChallengeExpiresAt - Date.now()) / 1000))
      : (challenge.expires_in_seconds || 300);

    this.startStepUpCountdown(remainingSecs);
  }

  // Challenge factor UI helpers
  initStepUpGestureGrid() {
    this.challengeGestureNodes = [];
    const gridContainer = document.getElementById('stepup-gesture-grid');
    if (!gridContainer) return;

    let portalTheme = 'theme-cyber';
    let portalWording = 'NEURALTRACE — RECONSTRUCT SIGNAL:';
    let portalHint = 'Press a starting node and trace a valid connected route (min 4 nodes).';
    const path = (window.location.pathname || '').toLowerCase();
    if (path.includes('college')) {
      portalTheme = 'theme-sky';
      portalWording = 'Academic Signal Reconstruction:';
      portalHint = 'Press a starting node and trace a valid connected route to access academic records.';
    } else if (path.includes('shopping')) {
      portalTheme = 'theme-amber';
      portalWording = 'Financial Vault Clearance:';
      portalHint = 'Press a starting node and trace a valid connected route to access financial details.';
    } else if (path.includes('healthcare')) {
      portalTheme = 'theme-emerald';
      portalWording = 'Clinical Signal Verification:';
      portalHint = 'Press a starting node and trace a valid connected route to unlock clinical records.';
    }

    const titleEl = document.getElementById('stepup-gesture-title');
    if (titleEl) titleEl.textContent = portalWording;
    const hintEl = document.getElementById('stepup-gesture-hint');
    if (hintEl) hintEl.textContent = portalHint;

    if (!this.stepupGestureGrid || this.stepupGestureGrid.container !== gridContainer) {
      this.stepupGestureGrid = new NeuralTraceAuth(gridContainer, {
        theme: portalTheme,
        minNodes: 4,
        onPatternChange: (pattern) => {
          this.challengeGestureNodes = pattern;
          const display = document.getElementById('stepup-gesture-display');
          if (display) {
            display.textContent = pattern.length > 0
              ? `${pattern.length} node${pattern.length === 1 ? '' : 's'} traversed`
              : 'Press a starting node and trace a valid connected route';
          }
        },
        onPatternComplete: (pattern) => {
          this.challengeGestureNodes = pattern;
          const display = document.getElementById('stepup-gesture-display');
          if (display) {
            display.textContent = `${pattern.length} nodes traversed (Route Complete)`;
          }
        },
        onPatternTooShort: (pattern) => {
          this.challengeGestureNodes = pattern;
          const display = document.getElementById('stepup-gesture-display');
          if (display) {
            display.textContent = `${pattern.length} nodes traversed (min 4 required)`;
          }
        },
        onReset: () => {
          this.challengeGestureNodes = [];
          const display = document.getElementById('stepup-gesture-display');
          if (display) display.textContent = 'Press a starting node and trace a valid connected route';
        }
      });
    } else {
      this.stepupGestureGrid.setTheme(portalTheme);
      this.stepupGestureGrid.reset();
    }
  }

  handleChallengeGestureNode(nodeId) {
    if (this.stepupGestureGrid) {
      this.stepupGestureGrid.addNode(nodeId);
      return;
    }
    if (!this.challengeGestureNodes) this.challengeGestureNodes = [];
    if (this.challengeGestureNodes.includes(nodeId)) return;
    this.challengeGestureNodes.push(nodeId);

    const display = document.getElementById('stepup-gesture-display');
    if (display) {
      display.textContent = `${this.challengeGestureNodes.length} nodes traversed`;
    }
  }

  clearChallengeGesture() {
    this.challengeGestureNodes = [];
    if (this.stepupGestureGrid) {
      this.stepupGestureGrid.reset();
    }
    const display = document.getElementById('stepup-gesture-display');
    if (display) display.textContent = 'Press a starting node and trace a valid connected route';
    const feedback = document.getElementById('stepup-feedback-banner');
    if (feedback) feedback.className = 'hidden';
  }

  async renderChallengeImageGrid(catalogue) {
    const grid = document.getElementById('stepup-image-grid');
    if (!grid) return;

    let items = catalogue;
    if (!items || items.length === 0) {
      items = await this.getAdaptiveCatalogue();
    }
    if (!items || items.length === 0) {
      items = [
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

    grid.innerHTML = items.map(item => `
      <div class="symbol-card" data-symbol="${item.id}" onclick="window.cognisec && window.cognisec.handleChallengeImageClick('${item.id}')">
        <span class="text-2xl">${item.icon}</span>
        <span class="text-[10px] text-slate-300 font-bold">${item.label}</span>
      </div>
    `).join('');
  }

  handleChallengeImageClick(symbolId) {
    if (!this.challengeImageSequence) this.challengeImageSequence = [];
    if (this.challengeImageSequence.length >= 5) return;
    this.challengeImageSequence.push(symbolId);
    this.updateChallengeImageStrip();
  }

  clearChallengeImageSequence() {
    this.challengeImageSequence = [];
    this.updateChallengeImageStrip();
  }

  updateChallengeImageStrip() {
    const strip = document.getElementById('stepup-image-strip');
    const cards = document.querySelectorAll('#stepup-image-grid .symbol-card');

    cards.forEach(card => {
      const sym = card.getAttribute('data-symbol');
      const idx = this.challengeImageSequence.indexOf(sym);
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

    if (strip) {
      if (this.challengeImageSequence.length === 0) {
        strip.innerHTML = '<span class="text-slate-500 text-[11px]">(Click symbols below)</span>';
      } else {
        strip.innerHTML = this.challengeImageSequence.map((id, i) => {
          return `<span class="px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-700 text-[10px] font-bold">${i+1}. ${id.replace('img_', '')}</span>`;
        }).join('');
      }
    }
  }

  startStepUpCountdown(totalSeconds) {
    if (this.stepUpTimerInterval) {
      clearInterval(this.stepUpTimerInterval);
    }
    let remaining = totalSeconds;
    const timerText = document.getElementById('stepup-timer-text');

    const updateTimerDisplay = () => {
      const m = Math.floor(remaining / 60);
      const s = remaining % 60;
      if (timerText) {
        timerText.textContent = `Expires: ${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
      }
      if (remaining <= 0) {
        clearInterval(this.stepUpTimerInterval);
        this.stepUpTimerInterval = null;
        if (timerText) timerText.textContent = 'EXPIRED (00:00)';

        const feedback = document.getElementById('stepup-feedback-banner');
        const otpInput = document.getElementById('stepup-otp-input');
        const privInput = document.getElementById('stepup-private-input');
        const submitBtn = document.getElementById('stepup-btn-submit');
        if (otpInput) otpInput.disabled = true;
        if (privInput) privInput.disabled = true;
        if (submitBtn) submitBtn.disabled = true;
        if (feedback) {
          feedback.className = 'p-3 rounded-xl bg-amber-950/60 border border-amber-800 text-amber-300 font-mono text-xs block';
          feedback.textContent = 'Step-up challenge has expired. Click "Clear / Reset" or request a fresh challenge.';
        }
      }
      remaining--;
    };

    updateTimerDisplay();
    this.stepUpTimerInterval = setInterval(updateTimerDisplay, 1000);
  }

  async submitStepUpForm(e) {
    if (e && e.preventDefault) e.preventDefault();
    if (this.isStepUpSubmitting) return;

    if (this.currentChallengePromise) {
      try {
        await this.currentChallengePromise;
      } catch (err) {
        console.error('Error awaiting challenge promise:', err);
      }
    }

    let cType = (this.currentChallenge && this.currentChallenge.challenge_type) || this.currentStepUpFactor;
    if (!cType) {
      const paneGesture = document.getElementById('stepup-pane-gesture');
      const paneImage = document.getElementById('stepup-pane-image');
      const panePrivate = document.getElementById('stepup-pane-private');
      if (paneGesture && !paneGesture.classList.contains('hidden')) {
        cType = 'GESTURE_PATTERN';
      } else if (paneImage && !paneImage.classList.contains('hidden')) {
        cType = 'COGNITIVE_IMAGE_SEQUENCE';
      } else if (panePrivate && !panePrivate.classList.contains('hidden')) {
        cType = 'PRIVATE_RESPONSE';
      } else {
        cType = 'OTP';
      }
    }

    const submitBtn = document.getElementById('stepup-btn-submit');
    const reqBtn = document.getElementById('stepup-btn-request-new');
    const feedback = document.getElementById('stepup-feedback-banner');
    const attemptsInfo = document.getElementById('stepup-attempts-info');

    let payload = { challenge_type: cType };
    if (this.currentChallenge && this.currentChallenge.challenge_id) {
      payload.challenge_id = this.currentChallenge.challenge_id;
    }

    if (cType === 'OTP') {
      const input = document.getElementById('stepup-otp-input');
      const code = input ? input.value.trim() : '';
      if (!code || code.length !== 6 || !/^\d{6}$/.test(code)) {
        if (feedback) {
          feedback.className = 'p-3 rounded-xl bg-amber-950/60 border border-amber-800 text-amber-300 font-mono text-xs block';
          feedback.textContent = 'Please enter a valid 6-digit numeric verification code.';
        }
        if (input) input.focus();
        return;
      }
      payload.challenge_code = code;
    } else if (cType === 'GESTURE_PATTERN') {
      if (!this.challengeGestureNodes || this.challengeGestureNodes.length < 4) {
        if (feedback) {
          feedback.className = 'p-3 rounded-xl bg-amber-950/60 border border-amber-800 text-amber-300 font-mono text-xs block';
          feedback.textContent = 'Invalid route: Please press a starting node and trace at least 4 connected nodes.';
        }
        return;
      }
      payload.gesture_pattern = this.challengeGestureNodes;
    } else if (cType === 'COGNITIVE_IMAGE_SEQUENCE') {
      if (!this.challengeImageSequence || this.challengeImageSequence.length < 3) {
        if (feedback) {
          feedback.className = 'p-3 rounded-xl bg-amber-950/60 border border-amber-800 text-amber-300 font-mono text-xs block';
          feedback.textContent = 'Please select an image sequence of at least 3 symbols.';
        }
        return;
      }
      payload.image_sequence = this.challengeImageSequence;
    } else if (cType === 'PRIVATE_RESPONSE') {
      const input = document.getElementById('stepup-private-input');
      const ans = input ? input.value.trim() : '';
      if (!ans) {
        if (feedback) {
          feedback.className = 'p-3 rounded-xl bg-amber-950/60 border border-amber-800 text-amber-300 font-mono text-xs block';
          feedback.textContent = 'Please enter your private security answer.';
        }
        if (input) input.focus();
        return;
      }
      payload.private_response = ans;
    } else if (cType === 'HIGH_RISK_DUAL') {
      const stageToSubmit = this.currentChallengeStage || 1;
      payload.stage = stageToSubmit;

      if (stageToSubmit === 1) {
        if (!this.challengeImageSequence || this.challengeImageSequence.length < 3) {
          if (feedback) {
            feedback.className = 'p-3 rounded-xl bg-amber-950/60 border border-amber-800 text-amber-300 font-mono text-xs block';
            feedback.textContent = 'Please select your cognitive image sequence (minimum 3 symbols).';
          }
          return;
        }
        payload.image_sequence = this.challengeImageSequence;
      } else if (stageToSubmit === 2) {
        const input = document.getElementById('stepup-private-input');
        const ans = input ? input.value.trim() : '';
        if (!ans) {
          if (feedback) {
            feedback.className = 'p-3 rounded-xl bg-amber-950/60 border border-amber-800 text-amber-300 font-mono text-xs block';
            feedback.textContent = 'Please enter your private security answer.';
          }
          if (input) input.focus();
          return;
        }
        payload.private_response = ans;
      }
    }

    this.isStepUpSubmitting = true;
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.innerHTML = cType === 'GESTURE_PATTERN' ? `<span>Verifying Route...</span>` : `<span>Verifying Challenge...</span>`;
    }
    if (reqBtn) {
      reqBtn.disabled = true;
    }
    if (feedback) feedback.className = 'hidden';

    try {
      const res = await this.verifyAdaptiveChallenge(payload);

      if (res.success) {
        if (res.data && res.data.stage_1_passed && res.data.decision === 'STEP_UP_VERIFICATION') {
          // Stage 1 verified! Progress to Stage 2 within the same challenge
          this.currentChallengeStage = 2;
          this.isStepUpSubmitting = false;

          const paneImage = document.getElementById('stepup-pane-image');
          const panePrivate = document.getElementById('stepup-pane-private');
          const promptEl = document.getElementById('stepup-private-prompt');
          const privInput = document.getElementById('stepup-private-input');
          const factorBadge = document.getElementById('stepup-factor-badge');

          if (paneImage) paneImage.classList.add('hidden');
          if (panePrivate) panePrivate.classList.remove('hidden');

          if (factorBadge) {
            factorBadge.textContent = 'HIGH RISK: STAGE 2 (PRIVATE RESPONSE)';
          }
          if (promptEl) {
            promptEl.textContent = res.data.prompt || (this.currentChallenge && this.currentChallenge.prompt) || 'Answer your registered private security question:';
          }
          if (privInput) {
            privInput.value = '';
            privInput.disabled = false;
            privInput.focus();
          }
          if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.innerHTML = '<span>Verify Stage 2 &amp; Restore Access →</span>';
          }
          if (reqBtn) reqBtn.disabled = false;

          if (feedback) {
            feedback.className = 'p-3 rounded-xl bg-sky-950/60 border border-sky-600 text-sky-300 font-mono text-xs block';
            feedback.textContent = '✓ Stage 1 verified! Please answer your private security question to complete authentication.';
          }
          return;
        }

        // Enforce authoritative server-side access decision check before unlocking
        const authDecision = await this.checkResourceAccess(this.currentTargetResource || 'confidential_records');
        if (authDecision.access_granted) {
          this.wasLastStepUpSuccessful = true;
          this.lastStepUpVerifiedAt = Date.now();
          this.lastStepUpVerifiedSessionId = this.sessionId;
          this.sessionStatus = 'ACTIVE';
          this.currentChallenge = null;
          this.currentChallengeExpiresAt = null;

          const authorizedResource = this.currentTargetResource;
          if (authorizedResource && this.sessionId) {
            this.grantResourceClearance(authorizedResource);
          }

          if (this.stepUpTimerInterval) clearInterval(this.stepUpTimerInterval);

          if (feedback) {
            feedback.className = 'p-3 rounded-xl bg-emerald-950/60 border border-emerald-600 text-emerald-300 font-mono text-xs block';
            feedback.textContent = cType === 'GESTURE_PATTERN'
              ? '✓ Route verified! Confidential access granted.'
              : '✓ Identity step-up verified! Full access restored.';
          }

          if (this.stepupGestureGrid) {
            this.stepupGestureGrid.triggerSuccess();
          }

          // Immediate callback & event dispatch for instantaneous UI unlock
          if (typeof this.stepUpSuccessCallback === 'function') {
            try {
              this.stepUpSuccessCallback({
                resource: authorizedResource,
                session_id: this.sessionId,
                application: this.application
              });
            } catch (e) {
              console.error('Error in stepUpSuccessCallback:', e);
            }
          }

          window.dispatchEvent(new CustomEvent('cognisec:step_up_success', {
            detail: {
              session_id: this.sessionId,
              decision: 'ALLOW',
              application: this.application,
              target_resource: authorizedResource
            }
          }));

          setTimeout(() => {
            this.closeStepUpModal();
            this.isStepUpSubmitting = false;
          }, 800);
          return;
        } else {
          // Server refused access due to policy (e.g. HIGH risk or restricted state)
          this.isStepUpSubmitting = false;
          if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.innerHTML = cType === 'GESTURE_PATTERN' ? `<span>Verify Route →</span>` : `<span>Verify &amp; Restore Access →</span>`;
          }
          if (reqBtn) reqBtn.disabled = false;
          if (feedback) {
            feedback.className = 'p-3 rounded-xl bg-red-950/70 border border-red-800 text-red-300 font-mono text-xs block';
            feedback.textContent = authDecision.reason || authDecision.message || 'Access denied by server Zero Trust policy. Confidential records stay locked.';
          }
          return;
        }
      } else {
        this.isStepUpSubmitting = false;
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.innerHTML = cType === 'GESTURE_PATTERN' ? `<span>Verify Route →</span>` : `<span>Verify &amp; Restore Access →</span>`;
        }
        if (reqBtn) {
          reqBtn.disabled = false;
        }

        if (this.stepupGestureGrid) {
          this.stepupGestureGrid.triggerShake();
          this.stepupGestureGrid.reset();
        }

        const errMsg = res.error || 'Verification failed. Invalid route.';
        const isLockout = errMsg.toLowerCase().includes('maximum') || errMsg.toLowerCase().includes('restricted') || errMsg.toLowerCase().includes('locked');

        if (feedback) {
          feedback.className = isLockout
            ? 'p-3 rounded-xl bg-red-950/80 border-2 border-red-600 text-red-200 font-mono text-xs block animate-pulse'
            : 'p-3 rounded-xl bg-red-950/60 border border-red-800 text-red-300 font-mono text-xs block';
          feedback.textContent = errMsg;
        }

        if (isLockout) {
          this.revokeResourceClearance();
          const otpInput = document.getElementById('stepup-otp-input');
          const privInput = document.getElementById('stepup-private-input');
          if (otpInput) otpInput.disabled = true;
          if (privInput) privInput.disabled = true;
          if (submitBtn) submitBtn.disabled = true;
          if (reqBtn) reqBtn.disabled = true;
          if (attemptsInfo) attemptsInfo.textContent = '0 attempts remaining (LOCKED)';
          if (this.stepUpTimerInterval) clearInterval(this.stepUpTimerInterval);

          window.dispatchEvent(new CustomEvent('cognisec:session_locked', {
            detail: { session_id: this.sessionId, reason: errMsg }
          }));
        } else {
          const match = errMsg.match(/(\d+)\s+attempt/i);
          if (match && attemptsInfo) {
            attemptsInfo.textContent = `${match[1]} attempt${match[1] === '1' ? '' : 's'} remaining`;
          }
        }
      }
    } catch (err) {
      this.isStepUpSubmitting = false;
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = cType === 'GESTURE_PATTERN' ? `<span>Verify Route →</span>` : `<span>Verify &amp; Restore Access →</span>`;
      }
      if (reqBtn) reqBtn.disabled = false;
      if (feedback) {
        feedback.className = 'p-3 rounded-xl bg-red-950/60 border border-red-800 text-red-300 font-mono text-xs block';
        feedback.textContent = `Server / Network Error: ${err.message}`;
      }
    }
  }

  // --- DEVICE INTELLIGENCE & LOCATION SERVICES ---

  async getDeviceFingerprint() {
    let stored = localStorage.getItem('cognisec_device_fp');
    if (stored) return stored;
    try {
      const components = [
        navigator.userAgent || '',
        navigator.language || '',
        screen.width + 'x' + screen.height,
        screen.colorDepth || '',
        Intl.DateTimeFormat().resolvedOptions().timeZone || '',
        navigator.hardwareConcurrency || ''
      ].join('###');
      if (window.crypto && window.crypto.subtle) {
        const msgBuffer = new TextEncoder().encode(components);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        stored = 'fp_' + hashArray.map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 32);
      } else {
        stored = 'fp_' + Math.random().toString(36).substring(2, 18);
      }
    } catch (e) {
      stored = 'fp_fallback_' + Math.random().toString(36).substring(2, 10);
    }
    localStorage.setItem('cognisec_device_fp', stored);
    return stored;
  }

  async requestDeviceLocation(timeoutMs = 3500) {
    if (!navigator.geolocation) {
      return { source: 'UNAVAILABLE', error: 'Browser does not support geolocation' };
    }
    return new Promise((resolve) => {
      let resolved = false;
      const timer = setTimeout(() => {
        if (!resolved) {
          resolved = true;
          resolve({ source: 'TIMED_OUT', error: 'Location request timed out' });
        }
      }, timeoutMs);

      navigator.geolocation.getCurrentPosition(
        (pos) => {
          if (resolved) return;
          resolved = true;
          clearTimeout(timer);
          resolve({
            latitude: pos.coords.latitude,
            longitude: pos.coords.longitude,
            accuracy: pos.coords.accuracy,
            source: 'BROWSER_GEOLOCATION'
          });
        },
        (err) => {
          if (resolved) return;
          resolved = true;
          clearTimeout(timer);
          const src = err.code === 1 ? 'PERMISSION_DENIED' : 'UNAVAILABLE';
          resolve({ source: src, error: err.message });
        },
        { enableHighAccuracy: false, timeout: timeoutMs, maximumAge: 300000 }
      );
    });
  }

  async getDevices() {
    const res = await fetch(`${COGNISEC_API_BASE}/devices`, {
      headers: this.getHeaders()
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to load devices (HTTP ${res.status})`);
    }
    return await res.json();
  }

  async confirmDevice(deviceId) {
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/devices/${deviceId}/confirm`, {
        method: 'POST',
        headers: this.getHeaders()
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `Failed to confirm device (${res.status})`);
      }
      return await res.json();
    } catch (e) {
      return { status: 'error', message: e.message };
    }
  }

  async revokeDevice(deviceId) {
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/devices/${deviceId}/revoke`, {
        method: 'POST',
        headers: this.getHeaders()
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `Failed to revoke device (${res.status})`);
      }
      return await res.json();
    } catch (e) {
      return { status: 'error', message: e.message };
    }
  }

  async updateDeviceNickname(deviceId, nickname) {
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/devices/${deviceId}/nickname`, {
        method: 'PUT',
        headers: this.getHeaders(),
        body: JSON.stringify({ nickname: nickname })
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `Failed to update nickname (${res.status})`);
      }
      return await res.json();
    } catch (e) {
      return { status: 'error', message: e.message };
    }
  }

  async getNotifications(unreadOnly = false) {
    if (!this.isAuthenticated()) {
      return { notifications: [], unread_count: 0, total_count: 0 };
    }
    const url = `${COGNISEC_API_BASE}/notifications` + (unreadOnly ? '?unread_only=true' : '');
    const res = await fetch(url, { headers: this.getHeaders() });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      const message = err.detail || `HTTP ${res.status}`;
      const error = new Error(message);
      error.status = res.status;
      throw error;
    }
    return await res.json();
  }

  async markNotificationRead(notificationId) {
    if (!this.isAuthenticated() || !notificationId) {
      return { status: 'noop' };
    }
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/notifications/${notificationId}/read`, {
        method: 'POST',
        headers: this.getHeaders()
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }
      return await res.json();
    } catch (e) {
      return { status: 'error', message: e.message };
    }
  }

  async markAllNotificationsRead() {
    if (!this.isAuthenticated()) {
      return { status: 'noop' };
    }
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/notifications/mark-all-read`, {
        method: 'POST',
        headers: this.getHeaders()
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }
      return await res.json();
    } catch (e) {
      return { status: 'error', message: e.message };
    }
  }

  async respondToNotification(notificationId, decision) {
    if (!this.isAuthenticated() || !notificationId) {
      return { status: 'noop' };
    }
    try {
      const res = await fetch(`${COGNISEC_API_BASE}/notifications/${notificationId}/respond`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({ decision })
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `Action failed (${res.status})`);
      }
      return await res.json();
    } catch (e) {
      return { status: 'error', message: e.message };
    }
  }
}

// Global Singleton
window.cognisec = new CognisecClient();

// Expose global password recovery helpers for direct HTML onclick compatibility
window.openForgotPasswordModal = function(prefillEmail) {
  if (window.cognisec) window.cognisec.openForgotPasswordModal(prefillEmail);
};
window.closeForgotPasswordModal = function() {
  if (window.cognisec) window.cognisec.closeForgotPasswordModal();
};
window.submitPasswordResetRequest = function(e) {
  if (window.cognisec) window.cognisec.submitPasswordResetRequestFromModal(e);
};
window.submitPasswordResetVerify = function(e) {
  if (window.cognisec) window.cognisec.submitPasswordResetVerifyFromModal(e);
};
window.resendPasswordReset = function() {
  if (window.cognisec) window.cognisec.resendPasswordResetFromModal();
};
window.resendPasswordResetFromModal = function() {
  if (window.cognisec) window.cognisec.resendPasswordResetFromModal();
};

// Expose global factor enrollment helpers for direct portal HTML compatibility
window.openFactorEnrollmentModal = function(tab) {
  if (window.cognisec) window.cognisec.openFactorEnrollmentModal(tab);
};
window.closeFactorEnrollmentModal = function() {
  if (window.cognisec) window.cognisec.closeFactorEnrollmentModal();
};
window.refreshFactorEnrollmentStatus = function() {
  if (window.cognisec) return window.cognisec.refreshFactorEnrollmentStatus();
};

