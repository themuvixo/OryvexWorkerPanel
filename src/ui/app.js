/* OryvexWorkerPanel: panel client application (vanilla ES5/ES6, no external dependencies). */
(function () {
  'use strict';

  /* global __ORYVEX_UPDATE_REPO__ */
  var OFFICIAL_GITHUB_REPO = typeof __ORYVEX_UPDATE_REPO__ === 'string' && __ORYVEX_UPDATE_REPO__ ? __ORYVEX_UPDATE_REPO__ : 'themuvixo/OryvexWorkerPanel';
  var OFFICIAL_GITHUB_URL = 'https://github.com/' + OFFICIAL_GITHUB_REPO;
  /* global __ORYVEX_VERSION__ */
  var BUILD_VERSION = typeof __ORYVEX_VERSION__ === 'string' && __ORYVEX_VERSION__ ? __ORYVEX_VERSION__ : '';
  var UPDATE_CACHE_KEY = 'oryvex.update';
  var UPDATE_AUTO_MS = 6 * 3600 * 1000;

  // Null-safe element lookup: a missing optional element must never break rendering.
  var MISSING_WARNED = {};
  var $ = function (id) {
    var el = document.getElementById(id);
    if (el) return el;
    if (!MISSING_WARNED[id]) {
      MISSING_WARNED[id] = true;
      try { console.warn('[oryvex] missing element #' + id); } catch (e) {}
    }
    return null;
  };
  var setText = function (id, value) {
    var el = document.getElementById(id);
    if (el) el.textContent = value;
    return el;
  };
  var html = document.documentElement;

  /* ---------------------------------------------- overlay enter/exit motion
     Modals and the toast keep using `el.hidden = true/false` everywhere in this file.
     The setter below plays the exit animation first, then really hides the element. */
  var MOTION_OUT_MS = 210;
  function motionReduced() {
    if (html.getAttribute('data-motion') === 'reduced') return true;
    try { return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches; } catch (e) { return false; }
  }
  function installExitMotion(el) {
    if (!el || el.__oxMotion) return;
    el.__oxMotion = true;
    var logicalHidden = el.hasAttribute('hidden');
    var timer = null;
    Object.defineProperty(el, 'hidden', {
      configurable: true,
      get: function () { return logicalHidden; },
      set: function (v) {
        v = Boolean(v);
        clearTimeout(timer);
        if (!v) {
          logicalHidden = false;
          el.classList.remove('is-leaving');
          el.removeAttribute('hidden');
          return;
        }
        if (logicalHidden && el.hasAttribute('hidden')) return;
        logicalHidden = true;
        if (motionReduced() || el.hasAttribute('hidden')) {
          el.classList.remove('is-leaving');
          el.setAttribute('hidden', '');
          return;
        }
        el.classList.add('is-leaving');
        timer = setTimeout(function () {
          el.classList.remove('is-leaving');
          if (logicalHidden) el.setAttribute('hidden', '');
        }, MOTION_OUT_MS);
      }
    });
  }
  document.querySelectorAll('.modal-backdrop, #toast').forEach(installExitMotion);

  // Smooth colour crossfade whenever theme or accent changes.
  var xfadeTimer = null;
  try {
    new MutationObserver(function () {
      if (motionReduced()) return;
      html.classList.add('theme-xfade');
      clearTimeout(xfadeTimer);
      xfadeTimer = setTimeout(function () { html.classList.remove('theme-xfade'); }, 450);
    }).observe(html, { attributes: true, attributeFilter: ['data-theme', 'data-accent'] });
  } catch (e) {}

  var LS = {
    get: function (k) { try { return localStorage.getItem('oryvex.' + k); } catch (e) { return null; } },
    set: function (k, v) { try { localStorage.setItem('oryvex.' + k, v); } catch (e) {} }
  };

  var lang = 'en'; // English-only interface
  var theme = LS.get('theme') === 'light' ? 'light' : 'dark';
  var ipBlurred = LS.get('ipblur') === '1';

  var COUNTRY_NAMES = {
    IR: ['Iran', 'Iran'],
    NL: ['Netherlands', 'Netherlands'],
    DE: ['Germany', 'Germany'],
    US: ['United States', 'United States'],
    GB: ['United Kingdom', 'United Kingdom'],
    FR: ['France', 'France'],
    TR: ['Turkey', 'Turkey'],
    AE: ['UAE', 'UAE'],
    FI: ['Finland', 'Finland'],
    SE: ['Sweden', 'Sweden'],
    CA: ['Canada', 'Canada'],
    SG: ['Singapore', 'Singapore'],
    JP: ['Japan', 'Japan'],
    RU: ['Russia', 'Russia'],
    CN: ['China', 'China']
  };

  var ISP_LOCAL_MAP = [
    [/mobile communication|mci|hamrah/i, 'MCI (Hamrah Aval)', 'MCI (Hamrah Aval)'],
    [/irancell|mtn/i, 'MTN Irancell', 'MTN Irancell'],
    [/iran telecommunication|tci|mkh/i, 'TCI (Telecom Iran)', 'TCI (Telecom Iran)'],
    [/rightel/i, 'Rightel', 'Rightel'],
    [/shatel/i, 'Shatel', 'Shatel'],
    [/asiatech/i, 'Asiatech', 'Asiatech'],
    [/mobinnet/i, 'Mobinnet', 'Mobinnet'],
    [/hiweb/i, 'HiWEB', 'HiWEB'],
    [/pars online|parsonline/i, 'ParsOnline', 'ParsOnline'],
    [/zitel/i, 'Zitel', 'Zitel'],
    [/pishgaman/i, 'Pishgaman', 'Pishgaman'],
    [/afranet/i, 'Afranet', 'Afranet'],
    [/respina/i, 'Respina', 'Respina'],
    [/hetzner/i, 'Hetzner Online', 'Hetzner Online'],
    [/cloudflare/i, 'Cloudflare Net', 'Cloudflare Net']
  ];

  var STATE = {
    mode: 'loading',
    isDemo: false,
    host: location.host || 'oryvex.workers.dev',
    edge: '—',
    cf: {
      clientIp: '—',
      country: 'XX',
      countryNameFa: 'Detecting…',
      countryNameEn: 'Detecting…',
      city: '',
      asn: 0,
      ispRaw: '',
      ispFa: 'Detecting ISP…',
      ispEn: 'Detecting ISP…',
      colo: '—'
    },
    settings: null,
    cfIntegration: null,
    cfUsage: null,
    ghInfo: null,
    users: [],
    logs: [],
    selectedUserId: '',
    currentNodes: [],
    currentQrText: '',
    currentQrCaption: 'SUBSCRIPTION'
  };

  /* ------------------------------------------------- Helpers & Typography */

  function computeUserTrafficPercent(u, allUsers) {
    var used = Math.max(0, Number(u && u.usedBytes) || 0);
    if (used <= 0) return 0;
    var limit = Math.max(0, Number(u && u.limitBytes) || 0);
    if (limit > 0) {
      return Math.min(100, Math.max(1, Math.round((used / limit) * 100)));
    }
    var refMax = 50 * 1073741824; // 50 GB reference scale for unlimited accounts with >0 traffic
    if (Array.isArray(allUsers)) {
      allUsers.forEach(function (x) {
        if ((x.usedBytes || 0) > refMax) refMax = x.usedBytes;
      });
    }
    return Math.min(100, Math.max(1, Math.round((used / refMax) * 100)));
  }

  function formatCompactCount(n) {
    var v = Math.max(0, Number(n) || 0);
    if (v >= 1000000) return (v / 1000000).toFixed(1).replace(/\.0$/, '') + 'M';
    if (v >= 1000) return (v / 1000).toFixed(1).replace(/\.0$/, '') + 'K';
    return String(Math.round(v));
  }

  function tr(fa, en) {
    return lang === 'fa' ? fa : en;
  }

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function svgIcon(name, cls) {
    return '<svg class="ic' + (cls ? ' ' + cls : '') + '" aria-hidden="true"><use href="#i-' + name + '"/></svg>';
  }

  function formatBytes(b) {
    var n = Number(b) || 0;
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MB';
    return (n / 1073741824).toFixed(2) + ' GB';
  }

  function uuid4() {
    if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
    var b = new Uint8Array(16);
    crypto.getRandomValues(b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    var h = Array.from(b, function (x) { return ('0' + x.toString(16)).slice(-2); }).join('');
    return h.slice(0, 8) + '-' + h.slice(8, 12) + '-' + h.slice(12, 16) + '-' + h.slice(16, 20) + '-' + h.slice(20);
  }

  function randPass(len) {
    var chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
    var b = new Uint8Array(len || 14);
    crypto.getRandomValues(b);
    var s = '';
    for (var i = 0; i < b.length; i++) s += chars[b[i] % chars.length];
    return s;
  }

  function randHex(bytesLen) {
    var arr = new Uint8Array(bytesLen);
    if (window.crypto && crypto.getRandomValues) crypto.getRandomValues(arr);
    else for (var i = 0; i < bytesLen; i++) arr[i] = Math.floor(Math.random() * 256);
    var out = '';
    for (var j = 0; j < arr.length; j++) out += arr[j].toString(16).padStart(2, '0');
    return out;
  }

  /* ------------------ Tactile Stationary-Shadow Button Press Physics */

  document.addEventListener('pointerdown', function (ev) {
    var btn = ev.target && ev.target.closest ? ev.target.closest('.btn, .mini, .tab-btn, .blur-btn') : null;
    if (!btn || btn.disabled) return;
    btn.classList.add('is-pressed');
    var clear = function () {
      setTimeout(function () { btn.classList.remove('is-pressed'); }, 95);
      window.removeEventListener('pointerup', clear);
      window.removeEventListener('pointercancel', clear);
    };
    window.addEventListener('pointerup', clear);
    window.addEventListener('pointercancel', clear);
  }, { passive: true });

  var toastTimer = null;
  function showToast(fa, en) {
    try {
      var el = $('toast');
      if (!el) return;
      var wasVisible = !el.hidden;
      el.textContent = tr(fa, en);
      el.hidden = false;
      if (wasVisible && !motionReduced()) {
        el.style.animation = 'none';
        void el.offsetWidth;
        el.style.animation = '';
      }
      clearTimeout(toastTimer);
      toastTimer = setTimeout(function () { el.hidden = true; }, 2800);
    } catch (e) {}
  }

  window.addEventListener('error', function (ev) {
    try {
      var msg = (ev && ev.error && ev.error.message) || (ev && ev.message) || '';
      if (msg && msg.indexOf('ResizeObserver') === -1) {
        showToast('Handled UI error: ' + msg, 'Handled UI error: ' + msg);
      }
    } catch (e) {}
  });

  window.addEventListener('unhandledrejection', function (ev) {
    if (ev && typeof ev.preventDefault === 'function') ev.preventDefault();
    try {
      var reason = ev && ev.reason;
      var msg = reason && reason.message ? reason.message : String(reason || 'Network error');
      showToast(msg, msg);
    } catch (e) {}
  });

  function copyText(str, labelFa, labelEn) {
    if (!str) return;
    var done = function () {
      showToast((labelEn || 'Copied') + ' — OK', (labelEn || 'Copied') + ' — OK');
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(str).then(done, fallback);
    } else fallback();
    function fallback() {
      var ta = document.createElement('textarea');
      ta.value = str;
      ta.style.position = 'fixed';
      ta.style.top = '-999px';
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); done(); } catch (e) {}
      document.body.removeChild(ta);
    }
  }

  function drawQrInto(boxId, text) {
    var box = $(boxId);
    if (!box || !text || typeof qrcode !== 'function') return;
    try {
      var curTh = html.getAttribute('data-theme');
      var bg = curTh === 'dark' ? '#efeadd' : '#ffffff';
      var fg = '#15130f';
      var qr = qrcode(0, 'M');
      qr.addData(text);
      qr.make();
      box.innerHTML = qr.createSvgTag({ cellSize: 2, margin: 4, scalable: true });
      var svg = box.querySelector('svg');
      if (svg) {
        svg.setAttribute('width', '152');
        svg.setAttribute('height', '152');
        svg.setAttribute('shape-rendering', 'crispEdges');
        svg.querySelectorAll('rect').forEach(function (r) { r.setAttribute('fill', bg); });
        svg.querySelectorAll('path').forEach(function (p) { p.setAttribute('fill', fg); });
      }
    } catch (e) {
      box.innerHTML = '';
    }
  }

  /* ----------------------- Visitor Connection Identity & IP Blur Strip */

  function classifyLocalIsp(raw) {
    var s = String(raw || '').trim();
    if (!s) return null;
    for (var i = 0; i < ISP_LOCAL_MAP.length; i++) {
      if (ISP_LOCAL_MAP[i][0].test(s)) {
        return { fa: ISP_LOCAL_MAP[i][1], en: ISP_LOCAL_MAP[i][2] };
      }
    }
    return { fa: s, en: s };
  }

  function mergeVisitorCf(cfObj) {
    if (!cfObj || typeof cfObj !== 'object') return;
    var c = STATE.cf;
    var incomingIp = String(cfObj.clientIp || '');
    var incomingIsLoop = !incomingIp || incomingIp === '0.0.0.0' || incomingIp === '127.0.0.1' || incomingIp === '::1';
    var currentHasPublicIp = c.clientIp && c.clientIp !== '—' && c.clientIp !== '127.0.0.1' && c.clientIp !== '::1';

    if (incomingIp && (!incomingIsLoop || !currentHasPublicIp)) {
      c.clientIp = incomingIp;
    }
    if (cfObj.country && cfObj.country !== 'XX') {
      c.country = String(cfObj.country).toUpperCase();
      var pair = COUNTRY_NAMES[c.country];
      c.countryNameFa = cfObj.countryNameFa || (pair ? pair[0] : c.country);
      c.countryNameEn = cfObj.countryNameEn || (pair ? pair[1] : c.country);
    } else if (cfObj.countryNameFa && c.country === 'XX') {
      c.countryNameFa = cfObj.countryNameFa;
      c.countryNameEn = cfObj.countryNameEn || 'Local';
    }
    if (cfObj.city) c.city = cfObj.city;
    if (cfObj.asn) c.asn = Number(cfObj.asn) || 0;

    var genericIsp = !cfObj.ispEn || /^(unknown|local)/i.test(cfObj.ispEn);
    var currentHasRealIsp = c.ispEn && !/^(detecting|local)/i.test(c.ispEn);

    if (cfObj.ispRaw) {
      c.ispRaw = cfObj.ispRaw;
      var mapped = classifyLocalIsp(cfObj.ispRaw);
      if (mapped) { c.ispFa = mapped.fa; c.ispEn = mapped.en; }
    } else if (!genericIsp || !currentHasRealIsp) {
      if (cfObj.ispFa) c.ispFa = cfObj.ispFa;
      if (cfObj.ispEn) c.ispEn = cfObj.ispEn;
    }

    if (cfObj.colo && cfObj.colo !== '—' && (cfObj.colo !== 'CF-GLOBAL' || c.colo === '—')) {
      c.colo = cfObj.colo;
      STATE.edge = cfObj.colo;
    }
    renderVisitorStrip();
  }

  function renderVisitorStrip() {
    var c = STATE.cf;
    var ipEl = $('visitor-ip');
    var blurBtn = $('btn-ip-blur');
    var blurLbl = $('ip-blur-lbl');
    var blurIcon = $('ip-blur-icon');

    if (ipEl) {
      ipEl.textContent = c.clientIp || '—';
      ipEl.classList.toggle('is-blurred', ipBlurred);
    }
    if (blurBtn) blurBtn.classList.toggle('active', ipBlurred);
    if (blurLbl) blurLbl.textContent = ipBlurred ? 'SHOW' : 'BLUR';
    if (blurIcon) blurIcon.innerHTML = '<use href="#i-' + (ipBlurred ? 'eye' : 'eye-off') + '"/>';

    if ($('visitor-country')) {
      var locStr = tr(c.countryNameEn || 'Local', c.countryNameEn || 'Local');
      if (c.city) locStr += ' · ' + c.city;
      setText('visitor-country', locStr);
    }
    if ($('visitor-iso')) {
      setText('visitor-iso', (c.country && c.country !== 'XX') ? c.country : 'LOCAL');
    }
    if ($('visitor-isp')) {
      setText('visitor-isp', tr(c.ispEn || 'Local Network', c.ispEn || 'Local Network'));
    }
    if ($('visitor-asn')) {
      setText('visitor-asn', c.asn ? ('AS' + c.asn) : '');
    }
    if ($('visitor-colo')) {
      setText('visitor-colo', 'COLO · ' + (c.colo || STATE.edge || '—'));
    }
    if ($('top-edge')) {
      setText('top-edge', 'COLO · ' + (STATE.edge || '—'));
    }
  }

  if ($('btn-ip-blur')) {
    $('btn-ip-blur').addEventListener('click', function () {
      ipBlurred = !ipBlurred;
      LS.set('ipblur', ipBlurred ? '1' : '0');
      renderVisitorStrip();
    });
  }

  async function detectVisitorNetwork() {
    if (isSandboxPreview) {
      mergeVisitorCf({
        clientIp: '5.160.214.88',
        country: 'IR',
        countryNameFa: 'Iran',
        countryNameEn: 'Iran',
        city: 'Tehran',
        asn: 44244,
        ispFa: 'MTN Irancell',
        ispEn: 'MTN Irancell',
        colo: 'FRA'
      });
      pushTelemetrySample(46, 18.4);
      return;
    }

    // 1) Query Worker's own /api/client-info and measure true Worker RTT
    try {
      var t0 = performance.now();
      var r = await fetch('/api/client-info?_=' + Date.now(), { cache: 'no-store', credentials: 'same-origin' });
      var rtt = Math.max(1, Math.round(performance.now() - t0));
      if (r.ok) {
        var j = await r.json();
        if (j && j.cf) mergeVisitorCf(j.cf);
        pushTelemetrySample(rtt, null);
      }
    } catch (e) {}

    // 2) If running on local dev / loopback where Worker sees 127.0.0.1 or XX, try Cloudflare speed meta from browser
    var curIp = STATE.cf.clientIp;
    if (!curIp || curIp === '—' || curIp === '127.0.0.1' || curIp === '::1' || STATE.cf.country === 'XX') {
      try {
        var ctrl = new AbortController();
        var tid = setTimeout(function () { try { ctrl.abort(); } catch (e) {} }, 3200);
        var res = await fetch('https://speed.cloudflare.com/meta', { signal: ctrl.signal, cache: 'no-store' });
        clearTimeout(tid);
        if (res.ok) {
          var meta = await res.json();
          if (meta && meta.clientIp) {
            mergeVisitorCf({
              clientIp: meta.clientIp,
              country: meta.country || 'XX',
              city: meta.city || '',
              asn: meta.asn || 0,
              ispRaw: meta.asOrganization || '',
              colo: meta.colo || STATE.edge
            });
          }
        }
      } catch (e) {
        if (STATE.cf.clientIp === '127.0.0.1' || STATE.cf.clientIp === '::1') {
          STATE.cf.countryNameFa = 'Local environment';
          STATE.cf.countryNameEn = 'Local Sandbox';
          STATE.cf.ispFa = 'Local network (loopback)';
          STATE.cf.ispEn = 'Local Loopback';
          renderVisitorStrip();
        }
      }
    }
  }

  /* ------------ Dynamic Theme-Native Monochrome Animated Telemetry Chart */

  var chartMode = 'live'; // 'live' | 'usage'
  var rttHistory = [];
  var speedHistory = [];
  var MAX_POINTS = 36;
  var chartAnimPhase = 0;
  var usageAnimProgress = 1;
  var lastMeasuredMbps = 0;
  var speedBurstRunning = false;

  function pushTelemetrySample(rttMs, mbpsVal) {
    if (typeof rttMs === 'number' && isFinite(rttMs)) {
      rttHistory.push(Math.max(1, Math.min(999, rttMs)));
      if (rttHistory.length > MAX_POINTS) rttHistory.shift();
    }
    if (typeof mbpsVal === 'number' && isFinite(mbpsVal)) {
      lastMeasuredMbps = mbpsVal;
      speedHistory.push(Math.max(0.2, Math.min(500, mbpsVal)));
    } else {
      // Derive subtle organic baseline throughput estimate from edge response cadence when idle
      var base = lastMeasuredMbps > 0
        ? Math.max(0.8, lastMeasuredMbps * (0.94 + Math.random() * 0.1))
        : Math.max(1.2, Math.min(45, 220 / Math.max(8, (rttMs || 40)) + (Math.random() * 1.4 - 0.7)));
      speedHistory.push(Number(base.toFixed(2)));
    }
    if (speedHistory.length > MAX_POINTS) speedHistory.shift();
    updateTelemetryKpis();
  }

  function updateTelemetryKpis() {
    var latestRtt = rttHistory.length ? rttHistory[rttHistory.length - 1] : null;
    var jitter = 0;
    if (rttHistory.length >= 2) {
      var sumDiff = 0;
      for (var i = 1; i < rttHistory.length; i++) sumDiff += Math.abs(rttHistory[i] - rttHistory[i - 1]);
      jitter = Math.round(sumDiff / (rttHistory.length - 1));
    }
    var latestSpd = speedHistory.length ? speedHistory[speedHistory.length - 1] : 0;
    var totalB = (STATE.users || []).reduce(function (acc, u) { return acc + (u.usedBytes || 0); }, 0);

    if ($('kpi-rtt')) $('kpi-rtt').textContent = latestRtt != null ? (latestRtt + ' ms') : '— ms';
    if ($('kpi-jitter')) $('kpi-jitter').textContent = rttHistory.length >= 2 ? (jitter + ' ms') : '0 ms';
    if ($('kpi-speed')) $('kpi-speed').textContent = latestSpd > 0 ? (latestSpd.toFixed(1) + ' Mbps') : '— Mbps';
    if ($('kpi-total-bw')) $('kpi-total-bw').textContent = formatBytes(totalB);
    if ($('chart-sample-lbl')) $('chart-sample-lbl').textContent = 'SAMPLES · ' + rttHistory.length;
  }

  async function runBurstSpeedProbe() {
    if (speedBurstRunning) return;
    speedBurstRunning = true;
    var ic = $('speed-burst-ic');
    if (ic) ic.classList.add('ic-spin');
    try {
      if (isSandboxPreview) {
        for (var k = 0; k < 4; k++) {
          await new Promise(function (r) { setTimeout(r, 180); });
          pushTelemetrySample(38 + Math.round(Math.random() * 14), 24 + Math.random() * 18);
        }
      } else {
        var sizes = [65536, 131072, 262144, 262144];
        for (var i = 0; i < sizes.length; i++) {
          var t0 = performance.now();
          var res = await fetch('/api/speed-probe?bytes=' + sizes[i] + '&_=' + Date.now() + '_' + i, {
            cache: 'no-store',
            credentials: 'same-origin'
          });
          var buf = await res.arrayBuffer();
          var dtSec = Math.max(0.002, (performance.now() - t0) / 1000);
          var mbps = (buf.byteLength * 8) / (dtSec * 1000000);
          var pingEst = Math.max(1, Math.round(dtSec * 350));
          pushTelemetrySample(rttHistory.length ? rttHistory[rttHistory.length - 1] : pingEst, Number(mbps.toFixed(2)));
        }
      }
      showToast('Edge burst speed test complete', 'Edge burst speed test complete');
    } catch (e) {
      showToast('Speed probe failed', 'Speed probe failed');
    }
    speedBurstRunning = false;
    if (ic) ic.classList.remove('ic-spin');
  }

  if ($('btn-speed-burst')) {
    $('btn-speed-burst').addEventListener('click', function () {
      setChartMode('live');
      runBurstSpeedProbe();
    });
  }

  function setChartMode(mode) {
    chartMode = mode === 'usage' ? 'usage' : 'live';
    if ($('chart-mode-live')) $('chart-mode-live').classList.toggle('active', chartMode === 'live');
    if ($('chart-mode-usage')) $('chart-mode-usage').classList.toggle('active', chartMode === 'usage');
    if ($('chart-legend-live')) $('chart-legend-live').hidden = chartMode !== 'live';
    if ($('chart-legend-usage')) $('chart-legend-usage').hidden = chartMode !== 'usage';
    if (chartMode === 'usage') {
      usageAnimProgress = 0;
    }
  }

  if ($('chart-mode-live')) $('chart-mode-live').onclick = function () { setChartMode('live'); };
  if ($('chart-mode-usage')) $('chart-mode-usage').onclick = function () { setChartMode('usage'); };

  function drawMonochromeChartFrame() {
    var canvas = $('telemetry-canvas');
    if (!canvas || STATE.mode !== 'admin' || $('pane-sub').hidden) {
      requestAnimationFrame(drawMonochromeChartFrame);
      return;
    }
    var rect = canvas.parentElement.getBoundingClientRect();
    var w = Math.max(260, Math.floor(rect.width));
    var h = Math.max(140, Math.floor(rect.height));
    var dpr = Math.min(2, window.devicePixelRatio || 1);
    if (canvas.width !== Math.floor(w * dpr) || canvas.height !== Math.floor(h * dpr)) {
      canvas.width = Math.floor(w * dpr);
      canvas.height = Math.floor(h * dpr);
    }

    var ctx = canvas.getContext('2d');
    ctx.save();
    ctx.scale(dpr, dpr);

    // Strictly read current theme CSS variables — zero off-theme colors!
    var cs = getComputedStyle(html);
    var ink = (cs.getPropertyValue('--chart-ink') || cs.getPropertyValue('--ink') || '#0a6cff').trim();
    var inkFaint = (cs.getPropertyValue('--ink-faint') || '#746d5f').trim();
    var paper = (cs.getPropertyValue('--paper') || '#eae4d6').trim();
    var paper2 = (cs.getPropertyValue('--paper-2') || '#e0d9c8').trim();

    ctx.fillStyle = paper2;
    ctx.fillRect(0, 0, w, h);

    // Subtle editorial horizontal & vertical ledger rules
    ctx.strokeStyle = inkFaint;
    ctx.globalAlpha = 0.24;
    ctx.lineWidth = 1;
    var padL = 46, padR = 16, padT = 16, padB = 24;
    var plotW = Math.max(60, w - padL - padR);
    var plotH = Math.max(60, h - padT - padB);

    for (var g = 0; g <= 3; g++) {
      var gy = Math.round(padT + (plotH * g) / 3) + 0.5;
      ctx.beginPath();
      ctx.moveTo(padL, gy);
      ctx.lineTo(w - padR, gy);
      ctx.stroke();
    }
    ctx.globalAlpha = 1;

    chartAnimPhase += 0.045;

    if (chartMode === 'live') {
      // Seed initial baseline if empty so chart looks alive immediately
      if (rttHistory.length < 4) {
        for (var s0 = rttHistory.length; s0 < 12; s0++) {
          rttHistory.push(32 + Math.round(Math.sin(s0 * 0.7) * 6));
          speedHistory.push(Number((8.5 + Math.cos(s0 * 0.6) * 2.1).toFixed(2)));
        }
        updateTelemetryKpis();
      }

      var maxSpd = Math.max(10, Math.ceil(Math.max.apply(null, speedHistory) * 1.25));
      var maxRtt = Math.max(100, Math.ceil(Math.max.apply(null, rttHistory) * 1.3));

      // Y-axis editorial monospace labels
      ctx.fillStyle = inkFaint;
      ctx.font = '600 10px "JetBrains Mono", ui-monospace, monospace';
      ctx.textAlign = 'right';
      ctx.fillText(maxSpd + 'M', padL - 6, padT + 4);
      ctx.fillText(Math.round(maxSpd / 2) + 'M', padL - 6, padT + plotH / 2 + 3);
      ctx.fillText('0', padL - 6, padT + plotH + 3);

      var n = speedHistory.length;
      var stepX = plotW / Math.max(1, MAX_POINTS - 1);
      var startX = padL + (MAX_POINTS - n) * stepX;

      // Build smooth throughput points with gentle live micro-oscillation on the tip
      var spdPts = [];
      for (var i = 0; i < n; i++) {
        var val = speedHistory[i];
        if (i === n - 1) val += Math.sin(chartAnimPhase) * (maxSpd * 0.015);
        var px = startX + i * stepX;
        var py = padT + plotH - Math.max(2, Math.min(plotH, (val / maxSpd) * plotH));
        spdPts.push([px, py]);
      }

      // Area fill with subtle newsprint ink wash + diagonal halftone hatch
      if (spdPts.length >= 2) {
        ctx.save();
        ctx.beginPath();
        ctx.moveTo(spdPts[0][0], padT + plotH);
        for (var p = 0; p < spdPts.length; p++) ctx.lineTo(spdPts[p][0], spdPts[p][1]);
        ctx.lineTo(spdPts[spdPts.length - 1][0], padT + plotH);
        ctx.closePath();
        ctx.clip();

        ctx.fillStyle = ink;
        ctx.globalAlpha = 0.08;
        ctx.fillRect(padL, padT, plotW, plotH);

        ctx.strokeStyle = ink;
        ctx.globalAlpha = 0.14;
        ctx.lineWidth = 1;
        var hatchShift = (chartAnimPhase * 4) % 8;
        for (var hx = -h; hx < w + h; hx += 8) {
          ctx.beginPath();
          ctx.moveTo(hx + hatchShift, padT);
          ctx.lineTo(hx - h + hatchShift, padT + h);
          ctx.stroke();
        }
        ctx.restore();

        // Solid crisp primary trace (Throughput)
        ctx.strokeStyle = ink;
        ctx.lineWidth = 2;
        ctx.lineJoin = 'round';
        ctx.beginPath();
        ctx.moveTo(spdPts[0][0], spdPts[0][1]);
        for (var p2 = 1; p2 < spdPts.length; p2++) {
          var xc = (spdPts[p2 - 1][0] + spdPts[p2][0]) / 2;
          var yc = (spdPts[p2 - 1][1] + spdPts[p2][1]) / 2;
          ctx.quadraticCurveTo(spdPts[p2 - 1][0], spdPts[p2 - 1][1], xc, yc);
        }
        ctx.lineTo(spdPts[spdPts.length - 1][0], spdPts[spdPts.length - 1][1]);
        ctx.stroke();

        // Pulsing live telegraph nib at latest point
        var tip = spdPts[spdPts.length - 1];
        var pulseR = 3.5 + (Math.sin(chartAnimPhase * 1.8) + 1) * 2.2;
        ctx.strokeStyle = ink;
        ctx.globalAlpha = 0.35;
        ctx.lineWidth = 1.2;
        ctx.beginPath();
        ctx.arc(tip[0], tip[1], pulseR, 0, Math.PI * 2);
        ctx.stroke();
        ctx.globalAlpha = 1;
        ctx.fillStyle = ink;
        ctx.fillRect(tip[0] - 3, tip[1] - 3, 6, 6);
      }

      // Secondary dashed trace (Edge RTT ms)
      if (rttHistory.length >= 2) {
        ctx.save();
        ctx.strokeStyle = inkFaint;
        ctx.lineWidth = 1.5;
        ctx.setLineDash([4, 4]);
        ctx.beginPath();
        for (var rIdx = 0; rIdx < rttHistory.length; rIdx++) {
          var rx = padL + (MAX_POINTS - rttHistory.length + rIdx) * stepX;
          var ry = padT + plotH - Math.max(4, Math.min(plotH - 4, (rttHistory[rIdx] / maxRtt) * plotH));
          if (rIdx === 0) ctx.moveTo(rx, ry);
          else ctx.lineTo(rx, ry);
        }
        ctx.stroke();
        ctx.restore();
      }

      // Bottom time axis label
      ctx.fillStyle = inkFaint;
      ctx.font = '500 9.5px "JetBrains Mono", ui-monospace, monospace';
      ctx.textAlign = 'left';
      ctx.fillText('T - ' + Math.round(MAX_POINTS * 3.5) + 's', padL, h - 6);
      ctx.textAlign = 'right';
      ctx.fillText('NOW · LIVE', w - padR, h - 6);
    } else {
      // Mode B: Subscriber Usage Monochrome Hatched Bar Chart
      usageAnimProgress = Math.min(1, usageAnimProgress + 0.06);
      var ease = 1 - Math.pow(1 - usageAnimProgress, 3);
      var users = (STATE.users || []).slice(0, 6);
      if (!users.length) {
        ctx.fillStyle = inkFaint;
        ctx.font = '600 12px "JetBrains Mono", monospace';
        ctx.textAlign = 'center';
        ctx.fillText('NO SUBSCRIBERS', w / 2, h / 2);
      } else {
        var maxBytes = 1073741824; // min 1 GB scale
        users.forEach(function (u) {
          var ref = Math.max(u.usedBytes || 0, u.limitBytes || 0);
          if (ref > maxBytes) maxBytes = ref;
        });

        ctx.fillStyle = inkFaint;
        ctx.font = '600 9.5px "JetBrains Mono", ui-monospace, monospace';
        ctx.textAlign = 'right';
        ctx.fillText(formatBytes(maxBytes), padL + 8, padT + 4);
        ctx.fillText('0 B', padL + 8, padT + plotH + 3);

        var uPadL = padL + 14;
        var uPlotW = w - uPadL - padR;
        var slotW = uPlotW / users.length;
        var barW = Math.min(64, Math.max(20, slotW * 0.56));

        users.forEach(function (u, idx) {
          var bx = uPadL + idx * slotW + (slotW - barW) / 2;
          var capBytes = u.limitBytes > 0 ? u.limitBytes : maxBytes;
          var capH = Math.max(10, (capBytes / maxBytes) * plotH) * ease;
          var rawUsed = Math.max(0, Number(u.usedBytes) || 0);
          var usedRatio = rawUsed > 0 ? Math.min(1, rawUsed / Math.max(1, maxBytes)) : 0;
          var usedH = rawUsed > 0 ? Math.max(3, usedRatio * plotH) * ease : 0;

          // Quota capacity frame (dashed box)
          ctx.save();
          ctx.strokeStyle = inkFaint;
          ctx.lineWidth = 1;
          ctx.setLineDash([3, 3]);
          ctx.strokeRect(bx, padT + plotH - capH, barW, capH);
          ctx.restore();

          // Used bytes solid + diagonal paper hatch bar (only when usedBytes > 0)
          var by = padT + plotH - usedH;
          if (usedH > 0) {
            ctx.fillStyle = ink;
            ctx.fillRect(bx, by, barW, usedH);

            ctx.save();
            ctx.beginPath();
            ctx.rect(bx + 1.5, by + 1.5, Math.max(0, barW - 3), Math.max(0, usedH - 3));
            ctx.clip();
            ctx.strokeStyle = paper;
            ctx.globalAlpha = 0.25;
            ctx.lineWidth = 1;
            for (var d = -plotH; d < barW + plotH; d += 6) {
              ctx.beginPath();
              ctx.moveTo(bx + d, by);
              ctx.lineTo(bx + d - usedH, by + usedH);
              ctx.stroke();
            }
            ctx.restore();
          }

          // Value above bar
          ctx.fillStyle = ink;
          ctx.font = '700 9.5px "JetBrains Mono", ui-monospace, monospace';
          ctx.textAlign = 'center';
          ctx.fillText(formatBytes(u.usedBytes || 0), bx + barW / 2, Math.max(11, by - 5));

          // Subscriber short name below axis
          var nm = String(u.name || '').slice(0, 12);
          ctx.fillStyle = inkFaint;
          ctx.font = '600 10px "JetBrains Mono", monospace';
          ctx.fillText(nm, bx + barW / 2, h - 6);
        });
      }
    }

    ctx.restore();
    requestAnimationFrame(drawMonochromeChartFrame);
  }

  // Periodic background RTT pulse every 4s while Admin Tab 1 is open
  setInterval(function () {
    if (STATE.mode !== 'admin' || $('pane-sub').hidden || document.hidden || speedBurstRunning) return;
    if (isSandboxPreview) {
      pushTelemetrySample(40 + Math.round(Math.random() * 14), 16 + Math.random() * 6);
      return;
    }
    var t0 = performance.now();
    fetch('/api/client-info?_=' + Date.now(), { cache: 'no-store', credentials: 'same-origin' })
      .then(function (r) {
        if (r.ok) pushTelemetrySample(Math.max(1, Math.round(performance.now() - t0)), null);
      })
      .catch(function () {});
  }, 4000);

  /* -------------- Smart Browser-Based ISP & Connectivity Advisor --------- */

  var ADV_TARGETS = [
    { id: 'google', name: 'Google (204)', catFa: 'Core Web', catEn: 'Core Web', kind: 'core', url: 'https://www.gstatic.com/generate_204' },
    { id: 'cf_edge', name: 'Cloudflare Edge', catFa: 'CF Anycast', catEn: 'CF Anycast', kind: 'cf', url: 'https://cp.cloudflare.com/generate_204' },
    { id: 'cf_doh', name: 'Cloudflare DoH', catFa: 'Secure DoH', catEn: 'Secure DoH', kind: 'doh', url: 'https://cloudflare-dns.com/dns-query?name=example.com&type=A', corsJson: true },
    { id: 'chatgpt', name: 'ChatGPT (OpenAI)', catFa: 'AI Platform', catEn: 'AI Platform', kind: 'ai', url: 'https://chatgpt.com/favicon.ico' },
    { id: 'claude', name: 'Claude AI', catFa: 'AI Platform', catEn: 'AI Platform', kind: 'ai', url: 'https://claude.ai/favicon.ico' },
    { id: 'gemini', name: 'Google Gemini', catFa: 'AI Platform', catEn: 'AI Platform', kind: 'ai', url: 'https://gemini.google.com/favicon.ico' },
    { id: 'github', name: 'GitHub', catFa: 'Dev & Code', catEn: 'Dev & Code', kind: 'dev', url: 'https://github.githubassets.com/favicons/favicon.svg' },
    { id: 'youtube', name: 'YouTube', catFa: 'Filtered Media', catEn: 'Filtered Media', kind: 'social', url: 'https://www.youtube.com/favicon.ico' },
    { id: 'telegram', name: 'Telegram Web', catFa: 'Messenger', catEn: 'Messenger', kind: 'social', url: 'https://web.telegram.org/favicon.ico' },
    { id: 'x_social', name: 'X / Twitter', catFa: 'Social Net', catEn: 'Social Net', kind: 'social', url: 'https://abs.twimg.com/favicons/twitter.3.ico' },
    { id: 'cf_8443', name: 'CF TLS :8443', catFa: 'Alt TLS Port', catEn: 'Alt TLS Port', kind: 'port', port: 8443, url: 'https://www.speedtest.net:8443/cdn-cgi/trace' },
    { id: 'cf_2053', name: 'CF TLS :2053', catFa: 'Alt TLS Port', catEn: 'Alt TLS Port', kind: 'port', port: 2053, url: 'https://cp.cloudflare.com:2053/cdn-cgi/trace' }
  ];

  var lastAdvisorPatch = null;
  var advisorRunning = false;

  async function probeAdvisorTarget(t) {
    if (isSandboxPreview) {
      var noSignal = t.kind === 'social';
      return { target: t, ok: !noSignal, ms: noSignal ? 3200 : (45 + Math.floor(Math.random() * 90)) };
    }
    var timeoutMs = 3200;
    var ctrl = new AbortController();
    var tid = setTimeout(function () { ctrl.abort(); }, timeoutMs);
    var t0 = performance.now();
    try {
      var sep = t.url.indexOf('?') >= 0 ? '&' : '?';
      var fetchOpts = t.corsJson
        ? { mode: 'cors', headers: { accept: 'application/dns-json' }, cache: 'no-store', signal: ctrl.signal }
        : { mode: 'no-cors', cache: 'no-store', credentials: 'omit', signal: ctrl.signal };
      var resp = await fetch(t.url + sep + '_nl=' + Date.now(), fetchOpts);
      var ms = Math.max(1, Math.round(performance.now() - t0));
      // no-cors success is an opaque TLS/transport response, NOT proof of service access.
      return { target: t, ok: t.corsJson ? resp.ok : true, ms: ms };
    } catch (e) {
      // DNS, TLS, CORS, network denial and timeouts are indistinguishable here.
      return { target: t, ok: false, ms: Math.max(1, Math.round(performance.now() - t0)) };
    } finally { clearTimeout(tid); }
  }

  async function probeAdvisorTransfer(method, bytes) {
    if (isSandboxPreview) {
      return method === 'GET'
        ? { ok: true, bytes: bytes, ms: 230, mbps: 4.56 }
        : { ok: true, bytes: bytes, ms: 1100, mbps: 0.95 };
    }
    var ctrl = new AbortController();
    var tid = setTimeout(function () { ctrl.abort(); }, 6500);
    var t0 = performance.now();
    try {
      var options = { method: method, signal: ctrl.signal, cache: 'no-store', credentials: 'same-origin' };
      if (method === 'POST') {
        options.body = new Uint8Array(bytes);
        options.headers = { 'content-type': 'application/octet-stream' };
      }
      var response = await fetch('/api/speed-probe?bytes=' + bytes + '&_=' + Date.now(), options);
      if (!response.ok) throw new Error('HTTP ' + response.status);
      var actual = method === 'GET'
        ? (await response.arrayBuffer()).byteLength
        : Number((await response.json()).receivedBytes);
      if (actual !== bytes) throw new Error('Probe size mismatch');
      var ms = Math.max(1, Math.round(performance.now() - t0));
      return { ok: true, bytes: actual, ms: ms, mbps: Math.round((bytes * 8 / (ms * 1000)) * 100) / 100 };
    } catch (e) {
      return { ok: false, bytes: 0, ms: Math.round(performance.now() - t0) };
    } finally { clearTimeout(tid); }
  }

  function renderAdvisorSkeleton() {
    var grid = $('adv-grid');
    if (!grid || grid.children.length > 0) return;
    ADV_TARGETS.forEach(function (t) {
      var cell = document.createElement('div');
      cell.className = 'adv-item';
      cell.id = 'adv-cell-' + t.id;
      cell.innerHTML =
        '<div class="adv-item-top">' +
          '<span class="adv-item-name">' + esc(t.name) + '</span>' +
          '<span class="badge mono" id="adv-bdg-' + t.id + '">READY</span>' +
        '</div>' +
        '<div class="adv-item-cat">' +
          '<span><span class="fa">' + esc(t.catFa) + '</span><span class="en">' + esc(t.catEn) + '</span></span>' +
          '<span class="mono" id="adv-ms-' + t.id + '">—</span>' +
        '</div>' +
        '<div class="adv-bar"><i id="adv-bar-' + t.id + '" style="width:0%"></i></div>';
      grid.appendChild(cell);
    });
  }

  async function runSmartAdvisor() {
    if (advisorRunning) return;
    advisorRunning = true;
    lastAdvisorPatch = null;
    renderAdvisorSkeleton();
    var ic = $('adv-run-ic');
    if (ic) ic.classList.add('ic-spin');
    if ($('btn-adv-apply')) $('btn-adv-apply').hidden = true;
    if ($('adv-path-metrics')) $('adv-path-metrics').hidden = true;
    ADV_TARGETS.forEach(function (t) {
      var b = $('adv-bdg-' + t.id);
      if (b) { b.className = 'badge mono'; b.textContent = 'TESTING'; }
    });

    try {
      // Concurrent host observations; bounded sequential download/upload to THIS Worker.
      var diagnostic = await Promise.all([
        Promise.all(ADV_TARGETS.map(probeAdvisorTarget)),
        (async function () {
          var down = await probeAdvisorTransfer('GET', 131072);
          var up = await probeAdvisorTransfer('POST', 131072);
          return { down: down, up: up };
        })()
      ]);
      var results = diagnostic[0], transfer = diagnostic[1], byId = {};
      results.forEach(function (r) {
        byId[r.target.id] = r;
        var b = $('adv-bdg-' + r.target.id);
        var m = $('adv-ms-' + r.target.id);
        var bar = $('adv-bar-' + r.target.id);
        if (b) {
          b.className = r.ok ? 'badge ok' : 'badge';
          b.textContent = r.ok
            ? (r.target.corsJson ? tr('HTTP REPLY', 'HTTP REPLY') : tr('TLS REPLY', 'TLS REPLY'))
            : tr('NO SIGNAL', 'NO SIGNAL');
        }
        if (m) m.textContent = r.ok ? (r.ms + ' ms') : '—';
        if (bar) bar.style.width = r.ok ? Math.max(15, Math.min(100, Math.round(100 - r.ms / 18))) + '%' : '6%';
      });

      var pathBox = $('adv-path-metrics');
      if (pathBox) pathBox.hidden = false;
      function metricText(m) {
        return m.ok ? ('~' + m.mbps.toFixed(2) + ' Mbps · ' + m.ms + 'ms') : tr('NO RESPONSE', 'NO RESPONSE');
      }
      setText('adv-down', metricText(transfer.down));
      setText('adv-up', metricText(transfer.up));

      var coreReply = Boolean((byId.google && byId.google.ok) || (byId.cf_edge && byId.cf_edge.ok));
      var cfReply = Boolean(byId.cf_edge && byId.cf_edge.ok);
      var socialNoSignal = ['youtube', 'telegram', 'x_social'].filter(function (k) { return !byId[k] || !byId[k].ok; }).length;
      var aiNoSignal = ['chatgpt', 'claude', 'gemini'].filter(function (k) { return !byId[k] || !byId[k].ok; }).length;
      var portResponses = [8443, 2053].filter(function (port) {
        return byId['cf_' + port] && byId['cf_' + port].ok;
      });
      var ispLabelEn = STATE.cf.ispEn || 'current network';
      var verdictEn = coreReply
        ? 'At least one core transport replied; ' + socialNoSignal + ' social and ' + aiNoSignal + ' AI probes had no visible transport response. No-CORS cannot identify HTTP availability or the cause.'
        : 'Core routes produced no usable observation; this does not prove censorship, geo restriction, or tunnel failure.';
      $('adv-verdict').innerHTML =
        'Observation on <strong>' + esc(ispLabelEn) + '</strong>: ' + esc(verdictEn);

      var recsEn = [], patch = {};
      recsEn.push('A 128 KiB transfer to this Worker is a short sample, not a verified ISP upload/download cap. Repeat measurements and test with the actual client.');
      if (transfer.down.ok && !transfer.up.ok) {
        recsEn.push('Worker download replied but this upload POST did not finish; cause unknown. Setting WS Early Data to 0 is a conservative URI-compatible experiment reflected in Normal.');
        if (Number((STATE.settings || {}).earlyData) > 0) patch.earlyData = 0;
      } else if (transfer.down.ok && transfer.up.ok &&
                 transfer.down.ms >= 60 && transfer.up.ms >= 120 &&
                 transfer.up.mbps < Math.min(1.5, transfer.down.mbps * 0.3)) {
        recsEn.push('Upload was markedly slower in this short sample; reducing Early Data to 0 is a conservative Normal-URI experiment, not a speed guarantee.');
        if (Number((STATE.settings || {}).earlyData) > 0) patch.earlyData = 0;
      } else if (!transfer.down.ok) {
        recsEn.push('Even the Worker download did not complete; no ISP cap or final connection speed can be inferred.');
      } else {
        recsEn.push('Both short Worker transfers completed; no Early Data change is justified by this sample.');
      }

      if ((STATE.settings || {}).alpn === 'h3') {
        patch.alpn = 'http/1.1';
        recsEn.push('For WebSocket nodes, http/1.1 is more interoperable than h3; this ALPN change is carried by Normal URIs.');
      }
      if (coreReply && (socialNoSignal || aiNoSignal)) {
        recsEn.push('A missing browser response does not prove filtering or sanctions. If the actual client fails, try mild Fragment in a separate JSON profile; a standard URI cannot carry it.');
      }
      if (cfReply && aiNoSignal >= 2 && (STATE.settings || {}).sanctionBypass === false) {
        patch.sanctionBypass = true;
        recsEn.push('Optionally prefer tunnel routing for unresponsive AI domains. This affects structured profile routing, not Normal URI transport, and does not prove geo restrictions.');
      }
      recsEn.push(portResponses.length
        ? ('TLS replied on test hosts for port(s) ' + portResponses.join(', ') + ' only; 2083/2087/2096 were NOT tested. No port is auto-added or removed from subscriptions.')
        : 'No alternate port was confirmed in this sample; 2083/2087/2096 were NOT tested. Existing port choices are left intact.');
      recsEn.push('Observations apply to the admin network only. URI-compatible changes appear in the existing Normal link after Apply/Save. Test scanned IP candidates in a real client before publishing.');

      var ul = $('adv-recs');
      if (ul) {
        ul.hidden = false;
        ul.innerHTML = '';
        for (var k = 0; k < recsEn.length; k++) {
          var li = document.createElement('li');
          li.textContent = recsEn[k];
          ul.appendChild(li);
        }
      }
      lastAdvisorPatch = Object.keys(patch).length ? patch : null;
      if ($('btn-adv-apply')) $('btn-adv-apply').hidden = STATE.mode !== 'admin' || !lastAdvisorPatch;
    } catch (err) {
      setText('adv-verdict', tr('Diagnostic incomplete; no settings were applied.', 'Diagnostic incomplete; no settings were applied.'));
      lastAdvisorPatch = null;
    } finally {
      advisorRunning = false;
      if (ic) ic.classList.remove('ic-spin');
    }
  }

  if ($('btn-adv-run')) {
    $('btn-adv-run').addEventListener('click', runSmartAdvisor);
  }

  if ($('btn-adv-apply')) {
    $('btn-adv-apply').addEventListener('click', async function () {
      if (!lastAdvisorPatch || STATE.mode !== 'admin') return;
      try {
        var merged = Object.assign({}, collectSettingsFromForms(), lastAdvisorPatch);
        var res = await api('/api/settings', 'PUT', merged);
        ingestBootstrap(res);
        var uriChanged = Object.prototype.hasOwnProperty.call(lastAdvisorPatch, 'earlyData') ||
          Object.prototype.hasOwnProperty.call(lastAdvisorPatch, 'alpn');
        showToast(
          uriChanged ? 'URI-compatible settings saved; refresh the same Normal subscription URL' : 'Structured routing saved; Normal URI unchanged',
          uriChanged ? 'URI-compatible settings saved; refresh the same Normal subscription URL' : 'Structured routing saved; Normal URI unchanged'
        );
      } catch (err) {
        showToast(err.message, err.message);
      }
    });
  }

  if ($('btn-jump-advisor')) {
    $('btn-jump-advisor').addEventListener('click', function () {
      var card = $('advisor-master-card');
      var guestSlot = $('guest-advisor-slot');
      if (STATE.mode === 'admin') {
        if (card && $('pane-advisor') && card.parentElement !== $('pane-advisor')) {
          $('pane-advisor').appendChild(card);
        }
        if (guestSlot) guestSlot.hidden = true;
        if ($('btn-adv-close-guest')) $('btn-adv-close-guest').hidden = true;
        switchTab('advisor');
        runSmartAdvisor();
      } else if (card && guestSlot) {
        guestSlot.appendChild(card);
        guestSlot.hidden = false;
        if ($('btn-adv-close-guest')) $('btn-adv-close-guest').hidden = false;
        guestSlot.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        runSmartAdvisor();
      }
    });
  }

  if ($('btn-adv-close-guest')) {
    $('btn-adv-close-guest').addEventListener('click', function () {
      var guestSlot = $('guest-advisor-slot');
      if (guestSlot) guestSlot.hidden = true;
    });
  }

  /* -------------------------------------------- Appearance & Free Modal */

  function applyAppearance() {
    html.setAttribute('data-lang', lang);
    html.setAttribute('lang', lang === 'fa' ? 'fa' : 'en');
    html.setAttribute('dir', lang === 'fa' ? 'rtl' : 'ltr');
    html.setAttribute('data-theme', theme);
    document.querySelectorAll('.t-pick').forEach(function (b) {
      b.classList.toggle('on', b.getAttribute('data-th') === theme);
    });
    renderVisitorStrip();
    if (STATE.currentQrText) drawQrInto('main-qr', STATE.currentQrText);
    renderStatelessTicket();
    if (STATE.mode === 'admin') {
      renderAdminHeader();
      renderActiveUserPass();
      renderUsersLedger();
      syncCfQuotaUI();
    }
  }

  if (document.getElementById('lang')) document.getElementById('lang').addEventListener('click', function () {
    lang = lang === 'fa' ? 'en' : 'fa';
    LS.set('lang', lang);
    applyAppearance();
  });

  document.querySelectorAll('.t-pick').forEach(function (btn) {
    btn.addEventListener('click', function () {
      theme = btn.getAttribute('data-th') === 'dark' ? 'dark' : 'light';
      LS.set('theme', theme);
      applyAppearance();
    });
  });

  var freeModal = $('free-notice-modal');
  var freeInfoBtn = $('btn-free-info');
  var freeCloseBtn = $('btn-free-close');
  function closeFreeModal() {
    if (freeModal) freeModal.hidden = true;
    try { sessionStorage.setItem('nl.free.seen', '1'); } catch (e) {}
  }
  if (freeInfoBtn && freeModal) {
    freeInfoBtn.addEventListener('click', function () { freeModal.hidden = false; });
  }
  if (freeCloseBtn) {
    freeCloseBtn.addEventListener('click', closeFreeModal);
  }
  if (freeModal) {
    freeModal.addEventListener('click', function (ev) {
      if (ev.target === freeModal) closeFreeModal();
    });
    try {
      if (!sessionStorage.getItem('nl.free.seen') && location.search.indexOf('nopopup=1') === -1) {
        freeModal.hidden = false;
      }
    } catch (e) {}
  }

  /* ----------------------------- Offline Sandbox Preview Shim (file:/null) */

  var isSandboxPreview = (location.protocol !== 'http:' && location.protocol !== 'https:') || window.origin === 'null';
  var demoStore = null;

  function ensureDemoStore() {
    if (demoStore) return demoStore;
    var u1 = {
      id: 'u_demo1', name: 'Primary admin', note: 'Personal · home fiber', enabled: true,
      uuid: '9d4c1f2e-77b3-4a51-9c2e-1f0b6d3a8e44', trojanPassword: 'NightDesk1950',
      subToken: 'k8m2x9p4q7w3n5r2', trafficLimitGB: 50, usedUpBytes: 412000000, usedDownBytes: 3890000000,
      usedBytes: 4302000000, limitBytes: 53687091200, connections: 42, expiryDays: 30,
      effectiveExpiresAt: Date.now() + 26 * 86400000, remainingDays: 26, startOnFirstUse: false, status: 'active'
    };
    var u2 = {
      id: 'u_demo2', name: 'Guest · iPhone', note: 'Starts on first connect', enabled: true,
      uuid: '3b8a91c0-51f4-4d88-87a1-6c2d9e0f1122', trojanPassword: 'PressPass52',
      subToken: 'm9p4v7x2n8q3w6z1', trafficLimitGB: 20, usedUpBytes: 0, usedDownBytes: 1288490188,
      usedBytes: 1288490188, limitBytes: 21474836480, connections: 7, expiryDays: 15,
      effectiveExpiresAt: 0, remainingDays: 15, startOnFirstUse: true, status: 'active'
    };
    demoStore = {
      version: BUILD_VERSION || '1.2.0',
      mode: 'admin', kvBound: true, kvName: 'PREVIEW_KV', initialized: true, authenticated: true,
      edge: 'FRA', host: 'oryvex.example.workers.dev',
      cfIntegration: {
        hasToken: true,
        maskedToken: '••••••••9f2a',
        accountId: 'demo_acc_01',
        accountName: 'Cloudflare Edge Account',
        scriptName: 'oryvex-worker-panel',
        dailyLimit: 100000,
        canEditWorkers: true,
        tokensDashboardUrl: 'https://dash.cloudflare.com/profile/api-tokens'
      },
      settings: {
        enableVless: true, enableTrojan: true, killSwitch: false,
        wsPath: '/', earlyData: 2048,
        tlsPorts: [443, 8443, 2053, 2083, 2087, 2096],
        httpPorts: [80, 8080, 8880, 2052, 2082, 2086, 2095],
        enableHttpPorts: false,
        enableXhttp: true, xhttpPath: '/xh', nodePrefix: '',
        fingerprint: 'chrome', alpn: 'http/1.1',
        cleanIPs: ['www.speedtest.net#Speedtest', '172.67.73.163#US|CF-MCI'],
        customDomains: [],
        proxyIPs: ['ProxyIP.NL.CMLiussss.net', 'ProxyIP.DE.CMLiussss.net', 'ProxyIP.US.CMLiussss.net', 'nima.nscl.ir'],
        enableNAT64: true,
        nat64Prefixes: ['2a02:898:146:64::', '2602:fc59:b0:64::', '2602:fc59:11:64::'],
        chainProxy: '',
        enableTgProxy: true,
        tgProxySecret: '9f8e7d6c5b4a39281726354455667788',
        tgProxyDomain: '',
        enableFragment: true, fragmentPackets: '1-1', fragmentLength: '10-20', fragmentInterval: '10-20', enableNoise: false,
        upstreamDoH: 'https://1.1.1.1/dns-query', remoteDnsMode: 'private-doh', directDns: '8.8.8.8',
        bypassIran: true, bypassLAN: true, bypassChina: false, bypassRussia: false,
        blockQuic: true, blockAds: true, blockAdult: false, sanctionBypass: true,
        customDirectDomains: [], customProxyDomains: ['chatgpt.com', 'claude.ai', 'gemini.google.com', 'docker.io', 'github.com'],
        customBlockDomains: [], showSubInfoNodes: true, rootMode: 'panel', fallbackDomain: ''
      },
      users: [u1, u2],
      logs: [
        { ts: Date.now() - 120000, event: 'setup', detail: 'Interactive panel preview is ready (v' + (BUILD_VERSION || '1.2.0') + ')' },
        { ts: Date.now() - 30000, event: 'settings', detail: 'VLESS + Trojan + Telegram Web Proxy enabled' }
      ]
    };
    return demoStore;
  }

  function buildClientDemoNodes(user, s, host) {
    var list = [];
    var tlsPorts = (s.tlsPorts && s.tlsPorts.length) ? s.tlsPorts : [443];
    var targets = [{ addr: host, label: host }].concat(
      (s.cleanIPs || []).map(function (c) {
        var p = c.split('#');
        var addr = p[0].trim();
        var label = (p[1] || addr).trim();
        var geo = label.match(/^([A-Z]{2})\|(.*)$/i);
        if (geo && (/^\d{1,3}(\.\d{1,3}){3}$/.test(addr) || addr.indexOf(':') >= 0)) {
          var cc = geo[1].toUpperCase();
          var flag = String.fromCodePoint.apply(String, cc.split('').map(function (ch) { return 0x1f1e6 + ch.charCodeAt(0) - 65; }));
          label = flag + ' ' + cc + ' · ' + addr + (geo[2].trim() ? ' · ' + geo[2].trim() : '');
        }
        return { addr: addr, label: label };
      })
    );
    var path = (s.wsPath || '/') + (s.earlyData ? '?ed=' + s.earlyData : '');
    targets.forEach(function (t) {
      tlsPorts.forEach(function (port) {
        var ps = (tlsPorts.length > 1 || port !== 443) ? (':' + port) : '';
        if (s.enableVless) {
          var n1 = 'VLESS · ' + t.label + ps;
          list.push({
            name: n1, protocol: 'vless', port: port,
            uri: 'vless://' + user.uuid + '@' + t.addr + ':' + port + '?encryption=none&security=tls&sni=' + host + '&fp=' + s.fingerprint + '&type=ws&host=' + host + '&path=' + encodeURIComponent(path) + '#' + encodeURIComponent(n1)
          });
        }
        if (s.enableVless && s.enableXhttp) {
          var nx = 'VLESS · XHTTP · ' + t.label + ps;
          list.push({
            name: nx, protocol: 'vless', transport: 'xhttp', port: port,
            uri: 'vless://' + user.uuid + '@' + t.addr + ':' + port + '?encryption=none&security=tls&sni=' + host + '&fp=' + s.fingerprint + '&alpn=h2&type=xhttp&host=' + host + '&path=' + encodeURIComponent(s.xhttpPath || '/xh') + '&mode=stream-one#' + encodeURIComponent(nx)
          });
        }
        if (s.enableTrojan) {
          var n2 = 'Trojan · ' + t.label + ps;
          list.push({
            name: n2, protocol: 'trojan', port: port,
            uri: 'trojan://' + encodeURIComponent(user.trojanPassword) + '@' + t.addr + ':' + port + '?security=tls&sni=' + host + '&fp=' + s.fingerprint + '&type=ws&host=' + host + '&path=' + encodeURIComponent(path) + '#' + encodeURIComponent(n2)
          });
        }
      });
    });
    return list;
  }

  async function api(path, method, body) {
    method = method || 'GET';
    if (isSandboxPreview) {
      var ds = ensureDemoStore();
      if (path === '/api/bootstrap') {
        ds.initialNodes = buildClientDemoNodes(ds.users[0], ds.settings, ds.host);
        return JSON.parse(JSON.stringify(ds));
      }
      if (path === '/api/killswitch') {
        ds.settings.killSwitch = !ds.settings.killSwitch;
        return JSON.parse(JSON.stringify(ds));
      }
      if (path === '/api/cf/ip-ranges') {
        return {
          ok: true, source: 'https://api.cloudflare.com/client/v4/ips', fetchedAt: Date.now(),
          ipv4: ['104.16.0.0/13', '172.64.0.0/13', '162.158.0.0/15', '198.41.128.0/17'],
          ipv6: ['2606:4700::/32', '2a06:98c0::/29'], cached: true
        };
      }
      if (path.indexOf('/api/cf/usage') === 0) {
        if (!ds.cfIntegration.hasToken) return { ok: false, needsToken: true, cfIntegration: ds.cfIntegration };
        return {
          ok: true,
          cfIntegration: ds.cfIntegration,
          usage: {
            usedToday: 14280,
            scriptRequests: 12940,
            dailyLimit: ds.cfIntegration.dailyLimit || 100000,
            pct: Math.round((14280 / (ds.cfIntegration.dailyLimit || 100000)) * 1000) / 10,
            resetInSec: 31200
          }
        };
      }
      if (path === '/api/cf/config') {
        if (body && body.action === 'clear') {
          ds.cfIntegration.hasToken = false;
          ds.cfIntegration.maskedToken = '';
          return { ok: true, cleared: true, cfIntegration: ds.cfIntegration };
        }
        ds.cfIntegration.hasToken = true;
        ds.cfIntegration.maskedToken = '••••••••' + String(body.token || '9f2a').slice(-4);
        ds.cfIntegration.scriptName = body.scriptName || 'oryvex-worker-panel';
        ds.cfIntegration.dailyLimit = Number(body.dailyLimit) || 100000;
        return {
          ok: true,
          verified: true,
          saved: body.action !== 'verify',
          accountName: 'Cloudflare Edge Account',
          scriptName: ds.cfIntegration.scriptName,
          canReadAnalytics: true,
          canEditWorkers: true,
          cfIntegration: ds.cfIntegration,
          usage: { usedToday: 14280, dailyLimit: ds.cfIntegration.dailyLimit, pct: 14.3, resetInSec: 31200 }
        };
      }
      if (path.indexOf('/api/update/check') === 0) {
        var demoV = ds.version;
        return {
          ok: true,
          configured: true,
          repo: OFFICIAL_GITHUB_REPO,
          repoUrl: OFFICIAL_GITHUB_URL,
          currentVersion: demoV,
          latestVersion: demoV,
          tag: 'v' + demoV,
          updateAvailable: false,
          releaseUrl: OFFICIAL_GITHUB_URL + '/releases/tag/v' + demoV,
          releaseNotes: 'OryvexWorkerPanel v' + demoV + ' (preview build).',
          publishedAt: new Date().toISOString(),
          checkedAt: Date.now(),
          cfConfigured: ds.cfIntegration.hasToken,
          canEditWorkers: true,
          scriptName: ds.cfIntegration.scriptName || 'oryvex-worker-panel'
        };
      }
      if (path === '/api/update/apply') {
        return {
          ok: true,
          updated: true,
          previousVersion: ds.version,
          targetVersion: ds.version,
          scriptName: (body && body.scriptName) || 'oryvex-worker-panel',
          reloadAfterMs: 1200
        };
      }
      if (path === '/api/settings') {
        Object.assign(ds.settings, body || {});
        ds.initialNodes = buildClientDemoNodes(ds.users[0], ds.settings, ds.host);
        return JSON.parse(JSON.stringify(ds));
      }
      if (path === '/api/users' && method === 'POST') {
        var nu = {
          id: 'u_' + Math.random().toString(36).slice(2, 9),
          name: body.name || 'New subscriber', note: body.note || '', enabled: true,
          uuid: body.uuid || uuid4(), trojanPassword: body.trojanPassword || randPass(14),
          subToken: randPass(16).toLowerCase(), trafficLimitGB: Number(body.trafficLimitGB) || 0,
          usedBytes: 0, limitBytes: (Number(body.trafficLimitGB) || 0) * 1073741824,
          connections: 0, expiryDays: Number(body.expiryDays) || 0, remainingDays: Number(body.expiryDays) || null,
          startOnFirstUse: Boolean(body.startOnFirstUse), status: 'active'
        };
        ds.users.push(nu);
        return Object.assign({ ok: true, createdId: nu.id }, JSON.parse(JSON.stringify(ds)));
      }
      var mNode = path.match(/^\/api\/users\/([^/]+)\/nodes$/);
      if (mNode) {
        var u = ds.users.find(function (x) { return x.id === mNode[1]; }) || ds.users[0];
        return { ok: true, user: u, nodes: buildClientDemoNodes(u, ds.settings, ds.host) };
      }
      var mUser = path.match(/^\/api\/users\/([^/]+)$/);
      if (mUser) {
        var idx = ds.users.findIndex(function (x) { return x.id === mUser[1]; });
        if (idx >= 0 && method === 'DELETE') {
          if (ds.users.length > 1) ds.users.splice(idx, 1);
        } else if (idx >= 0 && method === 'PUT') {
          if (body.resetTraffic) ds.users[idx].usedBytes = 0;
          if (body.rotateKeys) { ds.users[idx].uuid = uuid4(); ds.users[idx].trojanPassword = randPass(14); }
          if (body.enabled !== undefined) { ds.users[idx].enabled = body.enabled; ds.users[idx].status = body.enabled ? 'active' : 'paused'; }
          if (body.name) ds.users[idx].name = body.name;
          if (body.note !== undefined) ds.users[idx].note = body.note;
          if (body.trafficLimitGB !== undefined) {
            ds.users[idx].trafficLimitGB = Number(body.trafficLimitGB) || 0;
            ds.users[idx].limitBytes = ds.users[idx].trafficLimitGB * 1073741824;
          }
        }
        return Object.assign({ ok: true }, JSON.parse(JSON.stringify(ds)));
      }
      if (path === '/api/test-proxyip') {
        return { ok: true, target: body.target || 'example.com:443', latencyMs: 42 };
      }
      if (path === '/api/backup') {
        return { ok: true, version: 2, exportedAt: new Date().toISOString(), settings: ds.settings, users: ds.users };
      }
      return { ok: true };
    }

    var ctrl = typeof AbortController === 'function' ? new AbortController() : null;
    var tid = ctrl ? setTimeout(function () { try { ctrl.abort(); } catch (e) {} }, 15000) : null;
    var opts = {
      method: method,
      credentials: 'same-origin',
      headers: { accept: 'application/json', 'x-oryvex': '1' }
    };
    if (ctrl) opts.signal = ctrl.signal;
    if (body !== undefined) {
      opts.headers['content-type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    var res;
    try {
      res = await fetch(path, opts);
    } catch (netErr) {
      if (tid) clearTimeout(tid);
      if (netErr && netErr.name === 'AbortError') {
        throw new Error(tr('Request timed out.', 'Request timed out.'));
      }
      throw new Error(tr('Network error — could not reach Worker.', 'Network error — could not reach Worker.'));
    }
    if (tid) clearTimeout(tid);

    var data = {};
    try { data = await res.json(); } catch (e) { data = {}; }

    if (res.status === 401 && path !== '/api/login' && path !== '/api/bootstrap') {
      ingestBootstrap({ mode: 'login', host: STATE.host, edge: STATE.edge });
      throw new Error(data.error || tr('Session expired — please sign in again.', 'Session expired — please sign in again.'));
    }

    if (!res.ok || data.ok === false) {
      throw new Error(data.error || ('HTTP ' + res.status));
    }
    return data;
  }

  /* ------------------------------------------------- View & State Hydrator */

  function ingestBootstrap(data) {
    if (!data || typeof data !== 'object') return;
    var stateToMode = {
      needs_setup: 'setup',
      locked: 'login',
      stateless: 'stateless',
      needs_kv: 'stateless',
      ready: 'admin'
    };
    var resolvedMode = data.mode || stateToMode[data.state] || 'stateless';
    STATE.mode = resolvedMode;
    STATE.isDemo = isSandboxPreview;
    STATE.host = data.host || (data.cf && data.cf.host) || location.host || 'oryvex.workers.dev';
    if (data.edge && data.edge !== 'CF-GLOBAL') STATE.edge = data.edge;
    else if (STATE.edge === '—' && data.edge) STATE.edge = data.edge;

    if (data.cf) mergeVisitorCf(data.cf);
    else renderVisitorStrip();


    $('v-setup').hidden = resolvedMode !== 'setup';
    $('v-login').hidden = resolvedMode !== 'login';
    $('v-stateless').hidden = resolvedMode !== 'stateless';
    $('v-admin').hidden = resolvedMode !== 'admin';

    if (resolvedMode === 'stateless') {
      setText('diag-mode', 'STATELESS');
      setText('diag-kv', data.kvBound ? 'UNINITIALIZED' : 'NOT BOUND');
      setText('diag-uuid', (data.hasEnvUuid || data.statelessUser) ? 'SET (READY)' : 'NOT SET');
      setText('diag-edge', STATE.edge);
      renderStatelessTicket();
      return;
    }

    if (resolvedMode === 'admin') {
      // Ensure Smart Advisor card lives inside Tab 5 when entering Admin
      var advCard = $('advisor-master-card');
      if (advCard && $('pane-advisor') && advCard.parentElement !== $('pane-advisor')) {
        $('pane-advisor').appendChild(advCard);
      }
      if ($('guest-advisor-slot')) $('guest-advisor-slot').hidden = true;
      if ($('btn-adv-close-guest')) $('btn-adv-close-guest').hidden = true;
      renderAdvisorSkeleton();

      STATE.settings = data.settings;
      if (data.cfIntegration) STATE.cfIntegration = data.cfIntegration;
      STATE.users = data.users || [];
      STATE.logs = data.logs || [];
      $('demo-badge').hidden = !STATE.isDemo;

      if (!STATE.selectedUserId || !STATE.users.some(function (u) { return u.id === STATE.selectedUserId; })) {
        STATE.selectedUserId = STATE.users[0] ? STATE.users[0].id : '';
      }

      renderAdminHeader();
      populateSettingsForms();
      renderUsersLedger();
      renderActivityLogs();
      updateTelemetryKpis();
      syncCfQuotaUI();
      syncGhUpdaterUI(data.version);
      autoCheckUpdates();
      if (STATE.cfIntegration && STATE.cfIntegration.hasToken && !STATE.cfUsage && !cfUsageFetching) {
        refreshCfDailyUsage(false);
      }

      if (data.initialNodes && STATE.users[0] && STATE.selectedUserId === STATE.users[0].id) {
        STATE.currentNodes = data.initialNodes;
        renderActiveUserPass();
      } else {
        STATE.currentNodes = [];
        renderActiveUserPass();
        loadUserNodes(STATE.selectedUserId);
      }
    }
  }

  /* -------------------------------------- Setup, Login & Stateless Views */

  $('setup-gen-uuid').addEventListener('click', function () {
    $('setup-uuid').value = uuid4();
  });

  $('f-setup').addEventListener('submit', async function (ev) {
    ev.preventDefault();
    $('setup-err').hidden = true;
    try {
      var res = await api('/api/setup', 'POST', {
        password: $('setup-pass').value,
        firstUserName: $('setup-name').value.trim(),
        preferredUuid: $('setup-uuid').value.trim()
      });
      showToast('Panel initialized', 'Panel initialized');
      ingestBootstrap(res);
    } catch (err) {
      setText('setup-err', err.message);
      $('setup-err').hidden = false;
    }
  });

  $('f-login').addEventListener('submit', async function (ev) {
    ev.preventDefault();
    $('login-err').hidden = true;
    try {
      var res = await api('/api/login', 'POST', {
        password: $('login-pass').value
      });
      $('login-pass').value = '';
      showToast('Signed in to Desk', 'Signed in to Desk');
      ingestBootstrap(res);
    } catch (err) {
      setText('login-err', err.message);
      $('login-err').hidden = false;
    }
  });

  $('sub-jump-btn').addEventListener('click', function () {
    var tok = ($('sub-jump-inp').value || '').trim();
    if (!tok) return;
    window.open('/sub/' + encodeURIComponent(tok), '_blank', 'noopener');
  });

  $('sl-uuid').value = LS.get('uuid') || '';
  $('sl-mint').addEventListener('click', function () {
    $('sl-uuid').value = uuid4();
    LS.set('uuid', $('sl-uuid').value);
    renderStatelessTicket();
  });
  $('sl-uuid').addEventListener('input', function () {
    LS.set('uuid', $('sl-uuid').value.trim());
    renderStatelessTicket();
  });

  var slUri = '';
  function renderStatelessTicket() {
    var inp = $('sl-uuid');
    if (!inp) return;
    var id = (inp.value || '').trim();
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
      $('sl-box').hidden = true;
      return;
    }
    $('sl-box').hidden = false;
    var h = STATE.host;
    slUri = 'vless://' + id + '@' + h + ':443?encryption=none&security=tls&sni=' + h + '&fp=chrome&type=ws&host=' + h + '&path=%2F%3Fed%3D2048#Oryvex';
    $('sl-sub').href = '/sub/' + id;
    drawQrInto('sl-qr', slUri);
  }
  $('sl-copy').addEventListener('click', function () {
    copyText(slUri, 'VLESS URI', 'VLESS URI');
  });

  /* -------------------------------------------- Admin Header & Navigation */

  function renderAdminHeader() {
    var s = STATE.settings || {};
    setText('st-edge', STATE.edge);
    setText('st-kv', STATE.isDemo ? 'DEMO' : 'OK');
    var activeCount = STATE.users.filter(function (u) { return u.status === 'active'; }).length;
    setText('st-users', activeCount + '/' + STATE.users.length);
    var totalB = STATE.users.reduce(function (acc, u) { return acc + (u.usedBytes || 0); }, 0);
    setText('st-traffic', formatBytes(totalB));

    var killBtn = $('btn-kill');
    var killed = Boolean(s.killSwitch);
    killBtn.classList.toggle('active', killed);
    if ($('kill-fa')) $('kill-fa').textContent = killed ? 'Tunnel paused (resume)' : 'Kill switch: off';
    setText('kill-en', killed ? 'Tunnel paused · resume' : 'Kill switch: off');
  }

  $('btn-kill').addEventListener('click', async function () {
    try {
      var res = await api('/api/killswitch', 'POST', {});
      ingestBootstrap(res);
      showToast(
        res.settings.killSwitch ? 'Tunnel paused' : 'Tunnel resumed',
        res.settings.killSwitch ? 'Tunnel paused' : 'Tunnel resumed'
      );
    } catch (err) {
      showToast(err.message, err.message);
    }
  });

  $('btn-logout').addEventListener('click', async function () {
    try {
      await api('/api/logout', 'POST', {});
      location.reload();
    } catch (e) {
      location.reload();
    }
  });

  function switchTab(tabName) {
    document.querySelectorAll('.tab-btn').forEach(function (b) {
      b.classList.toggle('active', b.getAttribute('data-tab') === tabName);
    });
    ['sub', 'users', 'net', 'route', 'advisor', 'sec'].forEach(function (t) {
      var p = $('pane-' + t);
      if (p) p.hidden = t !== tabName;
    });
    if (tabName === 'advisor') renderAdvisorSkeleton();
  }

  document.querySelectorAll('.tab-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      switchTab(btn.getAttribute('data-tab'));
    });
  });

  $('go-add-user').addEventListener('click', function () {
    resetUserForm();
    switchTab('users');
    $('uf-name').focus();
  });

  /* ------------------------------------ Tab 1: Active User & Subscriptions */

  async function loadUserNodes(userId) {
    if (!userId) return;
    try {
      var res = await api('/api/users/' + encodeURIComponent(userId) + '/nodes', 'GET');
      STATE.currentNodes = res.nodes || [];
      renderActiveUserPass();
    } catch (e) {}
  }

  $('sel-user').addEventListener('change', function () {
    STATE.selectedUserId = $('sel-user').value;
    loadUserNodes(STATE.selectedUserId);
  });

  function getSelectedUser() {
    return STATE.users.find(function (u) { return u.id === STATE.selectedUserId; }) || STATE.users[0] || null;
  }

  function subBaseUrl(user) {
    var proto = location.protocol === 'http:' ? 'http://' : 'https://';
    return proto + STATE.host + '/sub/' + encodeURIComponent(user.subToken);
  }

  function dohFullUrl(user) {
    var proto = location.protocol === 'http:' ? 'http://' : 'https://';
    return proto + STATE.host + '/dns-query/' + encodeURIComponent(user.subToken);
  }

  function statusBadgeHtml(st) {
    var mapFa = { active: 'Active', paused: 'Paused', expired: 'Expired', quota: 'Quota reached' };
    var mapEn = { active: 'ACTIVE', paused: 'PAUSED', expired: 'EXPIRED', quota: 'QUOTA FULL' };
    var cls = st === 'active' ? 'badge ok' : 'badge bad';
    return '<span class="' + cls + '">' + esc(tr(mapFa[st] || st, mapEn[st] || st)) + '</span>';
  }

  function expiryText(u) {
    if (u.effectiveExpiresAt > 0) {
      return tr(u.remainingDays + ' days left', u.remainingDays + ' days left');
    }
    if (u.startOnFirstUse && u.expiryDays > 0) {
      return tr(u.expiryDays + 'd (on first connect)', u.expiryDays + 'd (on first connect)');
    }
    return tr('Unlimited', 'Unlimited');
  }

  function computeTgLinks(useLiveInputs) {
    var s = STATE.settings || {};
    var enabled = useLiveInputs && $('s-tgproxy') ? $('s-tgproxy').checked : (s.enableTgProxy !== false);
    var sec = (useLiveInputs && $('s-tgsecret') ? $('s-tgsecret').value : s.tgProxySecret) || '';
    sec = String(sec).trim().toLowerCase();
    if (/^(?:dd|ee|ef)[0-9a-f]{32}$/.test(sec)) sec = sec.slice(-32);
    var dom = (useLiveInputs && $('s-tgdomain') ? $('s-tgdomain').value : s.tgProxyDomain) || '';
    dom = String(dom).trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
    var host = (dom || STATE.host || '').split(':')[0];
    if (!host || !/^[0-9a-f]{32}$/.test(sec)) {
      return { enabled: enabled, tgUrl: '', tmeUrl: '', host: host, secret: sec };
    }
    var qs = 'server=' + encodeURIComponent(host) + '&secret=' + sec;
    return {
      enabled: enabled,
      tgUrl: 'tg://webproxy?' + qs,
      tmeUrl: 'https://t.me/webproxy?' + qs,
      host: host,
      secret: sec
    };
  }

  function syncTgLinksUI() {
    var savedTg = computeTgLinks(false);
    var dashBox = $('dash-tg-box');
    if (dashBox) {
      dashBox.hidden = !savedTg.enabled || !savedTg.tgUrl;
      if (savedTg.tgUrl && $('dash-tg-open')) $('dash-tg-open').href = savedTg.tgUrl;
    }
    var liveTg = computeTgLinks(true);
    if ($('set-tg-open')) $('set-tg-open').href = liveTg.tgUrl || '#';
  }

  function renderActiveUserPass() {
    var sel = $('sel-user');
    sel.innerHTML = '';
    STATE.users.forEach(function (u) {
      var opt = document.createElement('option');
      opt.value = u.id;
      opt.textContent = u.name + (u.note ? ' (' + u.note + ')' : '');
      if (u.id === STATE.selectedUserId) opt.selected = true;
      sel.appendChild(opt);
    });

    var u = getSelectedUser();
    if (!u) return;

    $('u-status-cell').innerHTML = statusBadgeHtml(u.status);
    var limStr = u.limitBytes > 0 ? formatBytes(u.limitBytes) : '∞';
    setText('u-bw-cell', formatBytes(u.usedBytes || 0) + ' / ' + limStr);
    setText('u-exp-cell', expiryText(u));
    setText('u-uuid-cell', u.uuid);
    setText('u-tr-cell', u.trojanPassword);

    var pct = computeUserTrafficPercent(u, STATE.users);
    $('u-meter').style.width = pct + '%';
    if ($('u-meter').parentElement) {
      $('u-meter').parentElement.classList.toggle('warn', u.limitBytes > 0 && pct >= 90);
    }

    var base = subBaseUrl(u);
    $('open-pass').href = '/sub/' + encodeURIComponent(u.subToken);
    syncTgLinksUI();

    STATE.currentQrText = base;
    STATE.currentQrCaption = 'NORMAL SUB · ' + u.name;
    setText('qr-caption', STATE.currentQrCaption);
    drawQrInto('main-qr', STATE.currentQrText);

    var nodes = STATE.currentNodes || [];
    setText('node-count-en', String(nodes.length));

    var nbox = $('admin-nodes');
    nbox.innerHTML = '';
    nodes.forEach(function (n) {
      var row = document.createElement('div');
      row.className = 'node-row';
      row.innerHTML =
        '<div class="node-title"><span class="badge inv' + (n.transport === 'xhttp' ? ' xh' : '') + '">' + esc(n.transport === 'xhttp' ? 'XHTTP' : n.protocol.toUpperCase()) + '</span> <span>' + esc(n.name) + '</span></div>' +
        '<div class="node-acts">' +
          '<button class="btn ghost sm-btn" type="button">' + svgIcon('qr', 'ic-sm') + '<span>QR</span></button>' +
          '<button class="btn primary sm-btn" type="button">' + svgIcon('copy', 'ic-sm') + '<span>' + esc(tr('COPY', 'COPY')) + '</span></button>' +
        '</div>';
      var btns = row.querySelectorAll('button');
      btns[0].onclick = function () {
        STATE.currentQrText = n.uri;
        setText('qr-caption', n.name);
        drawQrInto('main-qr', n.uri);
      };
      btns[1].onclick = function () {
        copyText(n.uri, n.name, n.name);
      };
      nbox.appendChild(row);
    });
  }

  $('cp-b64').onclick = function () { var u = getSelectedUser(); if (u) copyText(subBaseUrl(u), 'Normal Sub URL', 'Normal Sub URL'); };
  $('cp-xray').onclick = function () { var u = getSelectedUser(); if (u) copyText(subBaseUrl(u) + '?format=xray', 'Xray Fragment URL', 'Xray Fragment URL'); };
  $('cp-sb').onclick = function () { var u = getSelectedUser(); if (u) copyText(subBaseUrl(u) + '?format=singbox', 'Sing-box URL', 'Sing-box URL'); };
  $('cp-clash').onclick = function () { var u = getSelectedUser(); if (u) copyText(subBaseUrl(u) + '?format=clash', 'Clash URL', 'Clash URL'); };
  $('cp-doh').onclick = function () { var u = getSelectedUser(); if (u) copyText(dohFullUrl(u), 'Private DoH URL', 'Private DoH URL'); };

  $('qr-btn-b64').onclick = function () {
    var u = getSelectedUser(); if (!u) return;
    STATE.currentQrText = subBaseUrl(u);
    setText('qr-caption', 'NORMAL SUBSCRIPTION');
    drawQrInto('main-qr', STATE.currentQrText);
  };
  $('qr-btn-xray').onclick = function () {
    var u = getSelectedUser(); if (!u) return;
    STATE.currentQrText = subBaseUrl(u) + '?format=xray';
    setText('qr-caption', 'FRAGMENT SUB (XRAY JSON)');
    drawQrInto('main-qr', STATE.currentQrText);
  };
  $('qr-btn-sb').onclick = function () {
    var u = getSelectedUser(); if (!u) return;
    STATE.currentQrText = subBaseUrl(u) + '?format=singbox';
    setText('qr-caption', 'SING-BOX / HIDDIFY SUB');
    drawQrInto('main-qr', STATE.currentQrText);
  };
  if ($('qr-btn-tg')) {
    $('qr-btn-tg').onclick = function () {
      var tg = computeTgLinks(false);
      if (!tg.tmeUrl) { showToast('Telegram Proxy is disabled', 'Telegram Proxy is disabled'); return; }
      STATE.currentQrText = tg.tmeUrl;
      setText('qr-caption', 'TELEGRAM WEB PROXY');
      drawQrInto('main-qr', STATE.currentQrText);
    };
  }
  if ($('dash-tg-copy')) {
    $('dash-tg-copy').onclick = function () {
      var tg = computeTgLinks(false);
      if (tg.tmeUrl) copyText(tg.tmeUrl, 'Telegram Proxy URL', 'Telegram Proxy URL');
    };
  }

  /* ------------------------------------ Tab 2: Subscribers CRUD & Ledger */

  $('uf-gen-uuid').onclick = function () { $('uf-uuid').value = uuid4(); };
  $('uf-gen-tr').onclick = function () { $('uf-tr').value = randPass(14); };

  function resetUserForm() {
    $('uf-id').value = '';
    $('uf-name').value = '';
    $('uf-note').value = '';
    $('uf-gb').value = '0';
    $('uf-days').value = '0';
    $('uf-uuid').value = '';
    $('uf-tr').value = '';
    $('uf-first').checked = false;
    $('uf-reset').hidden = true;
    if ($('uf-title-fa')) $('uf-title-fa').textContent = 'Add a subscriber';
    setText('uf-title-en', 'Add a subscriber');
    if ($('uf-submit-fa')) $('uf-submit-fa').textContent = 'Create subscriber';
    setText('uf-submit-en', 'Create subscriber');
  }

  $('uf-reset').onclick = resetUserForm;

  $('f-user').addEventListener('submit', async function (ev) {
    ev.preventDefault();
    var editId = $('uf-id').value;
    var payload = {
      name: $('uf-name').value.trim(),
      note: $('uf-note').value.trim(),
      trafficLimitGB: Number($('uf-gb').value) || 0,
      expiryDays: Number($('uf-days').value) || 0,
      startOnFirstUse: $('uf-first').checked
    };
    if ($('uf-uuid').value.trim()) payload.uuid = $('uf-uuid').value.trim();
    if ($('uf-tr').value.trim()) payload.trojanPassword = $('uf-tr').value.trim();

    try {
      var res;
      if (editId) {
        res = await api('/api/users/' + encodeURIComponent(editId), 'PUT', payload);
        showToast('Subscriber updated', 'Subscriber updated');
      } else {
        res = await api('/api/users', 'POST', payload);
        if (res.createdId) STATE.selectedUserId = res.createdId;
        showToast('Subscriber created', 'Subscriber created');
      }
      resetUserForm();
      ingestBootstrap(res);
    } catch (err) {
      showToast(err.message, err.message);
    }
  });

  function renderUsersLedger() {
    var box = $('users-list');
    box.innerHTML = '';

    STATE.users.forEach(function (u) {
      var card = document.createElement('div');
      card.className = 'user-card';
      var lim = u.limitBytes > 0 ? formatBytes(u.limitBytes) : '∞';
      var pct = computeUserTrafficPercent(u, STATE.users);

      card.innerHTML =
        '<div class="user-head">' +
          '<div class="user-name">' + svgIcon('users', 'ic-sm') + '<span>' + esc(u.name) + '</span>' + (u.note ? ' <span class="mono sm" style="opacity:.65">(' + esc(u.note) + ')</span>' : '') + '</div>' +
          '<div>' + statusBadgeHtml(u.status) + '</div>' +
        '</div>' +
        '<div class="user-meta">' +
          '<div><span>' + esc(tr('TRAFFIC', 'TRAFFIC')) + '</span><b>' + esc(formatBytes(u.usedBytes || 0) + ' / ' + lim) + '</b></div>' +
          '<div><span>' + esc(tr('EXPIRY', 'EXPIRY')) + '</span><b>' + esc(expiryText(u)) + '</b></div>' +
          '<div><span>' + esc(tr('CONNECTIONS', 'CONNECTIONS')) + '</span><b>' + (u.connections || 0) + '</b></div>' +
          '<div><span>SUB TOKEN</span><b>' + esc(u.subToken) + '</b></div>' +
        '</div>' +
        '<div class="meter' + (pct >= 90 ? ' warn' : '') + '"><i style="width:' + pct + '%"></i></div>' +
        '<div class="actions" style="margin-top:4px">' +
          '<button class="btn primary sm-btn u-act-sub" type="button">' + svgIcon('qr', 'ic-sm') + '<span>' + esc(tr('LINKS & QR', 'LINKS & QR')) + '</span></button>' +
          '<button class="btn ghost sm-btn u-act-edit" type="button">' + esc(tr('EDIT', 'EDIT')) + '</button>' +
          '<button class="btn ghost sm-btn u-act-toggle" type="button">' + esc(u.enabled ? tr('PAUSE', 'PAUSE') : tr('RESUME', 'RESUME')) + '</button>' +
          '<button class="btn ghost sm-btn u-act-reset" type="button">' + esc(tr('RESET GB', 'RESET GB')) + '</button>' +
          '<button class="btn ghost sm-btn u-act-rot" type="button">' + esc(tr('ROTATE KEYS', 'ROTATE KEYS')) + '</button>' +
          (STATE.users.length > 1
            ? '<button class="btn danger sm-btn u-act-del" type="button">' + esc(tr('DELETE', 'DELETE')) + '</button>'
            : '') +
        '</div>';

      card.querySelector('.u-act-sub').onclick = function () {
        STATE.selectedUserId = u.id;
        switchTab('sub');
        loadUserNodes(u.id);
      };
      card.querySelector('.u-act-edit').onclick = function () {
        $('uf-id').value = u.id;
        $('uf-name').value = u.name;
        $('uf-note').value = u.note || '';
        $('uf-gb').value = String(u.trafficLimitGB || 0);
        $('uf-days').value = String(u.expiryDays || 0);
        $('uf-uuid').value = u.uuid;
        $('uf-tr').value = u.trojanPassword;
        $('uf-first').checked = Boolean(u.startOnFirstUse);
        $('uf-reset').hidden = false;
        if ($('uf-title-fa')) $('uf-title-fa').textContent = 'Edit subscriber: ' + u.name;
        setText('uf-title-en', 'Edit subscriber: ' + u.name);
        if ($('uf-submit-fa')) $('uf-submit-fa').textContent = 'Save changes';
        setText('uf-submit-en', 'Save changes');
        $('f-user').scrollIntoView({ behavior: 'smooth', block: 'center' });
      };
      card.querySelector('.u-act-toggle').onclick = async function () {
        try {
          var r = await api('/api/users/' + encodeURIComponent(u.id), 'PUT', { enabled: !u.enabled });
          ingestBootstrap(r);
          showToast('Status updated', 'Status updated');
        } catch (err) {
          showToast(err.message, err.message);
        }
      };
      card.querySelector('.u-act-reset').onclick = async function () {
        try {
          var r = await api('/api/users/' + encodeURIComponent(u.id), 'PUT', { resetTraffic: true });
          ingestBootstrap(r);
          showToast('Bandwidth reset', 'Bandwidth reset');
        } catch (err) {
          showToast(err.message, err.message);
        }
      };
      card.querySelector('.u-act-rot').onclick = async function () {
        try {
          var r = await api('/api/users/' + encodeURIComponent(u.id), 'PUT', { rotateKeys: true });
          ingestBootstrap(r);
          showToast('Keys rotated', 'Keys rotated');
        } catch (err) {
          showToast(err.message, err.message);
        }
      };
      var delBtn = card.querySelector('.u-act-del');
      if (delBtn) {
        delBtn.onclick = async function () {
          try {
            var r = await api('/api/users/' + encodeURIComponent(u.id), 'DELETE');
            ingestBootstrap(r);
            showToast('Subscriber deleted', 'Subscriber deleted');
          } catch (err) {
            showToast(err.message, err.message);
          }
        };
      }

      box.appendChild(card);
    });
  }

  /* ------------------------------------ Tabs 3, 4, 6: Settings & Scanners */

  function linesToText(arr) {
    return Array.isArray(arr) ? arr.join('\n') : '';
  }

  function textToLines(str) {
    return String(str || '').split(/\r?\n/).map(function (s) { return s.trim(); }).filter(Boolean);
  }

  function populateSettingsForms() {
    var s = STATE.settings || {};

    $('s-vless').checked = Boolean(s.enableVless);
    $('s-trojan').checked = Boolean(s.enableTrojan);
    $('s-http-on').checked = Boolean(s.enableHttpPorts);

    var tlsSet = new Set((s.tlsPorts || [443]).map(Number));
    $('tls-ports-box').querySelectorAll('input[type="checkbox"]').forEach(function (cb) {
      cb.checked = tlsSet.has(Number(cb.value));
    });

    var httpSet = new Set((s.httpPorts || [80, 8080, 8880, 2052, 2082, 2086, 2095]).map(Number));
    if ($('http-ports-box')) {
      $('http-ports-box').querySelectorAll('input[type="checkbox"]').forEach(function (cb) {
        cb.checked = httpSet.has(Number(cb.value));
      });
    }

    $('s-fp').value = s.fingerprint || 'chrome';
    $('s-alpn').value = s.alpn || 'http/1.1';
    $('s-ed').value = String(s.earlyData != null ? s.earlyData : 2048);
    $('s-wspath').value = s.wsPath || '/';
    if ($('s-xhttp')) $('s-xhttp').checked = Boolean(s.enableXhttp);
    if ($('s-xhttp-path')) $('s-xhttp-path').value = s.xhttpPath || '/xh';
    if ($('s-node-prefix')) $('s-node-prefix').value = s.nodePrefix || '';
    syncXhttpUI();

    $('s-frag-on').checked = Boolean(s.enableFragment);
    $('s-frag-pkt').value = s.fragmentPackets || '1-1';
    $('s-frag-len').value = s.fragmentLength || '10-20';
    $('s-frag-int').value = s.fragmentInterval || '10-20';
    $('s-noise').checked = Boolean(s.enableNoise);

    $('s-cleanips').value = linesToText(s.cleanIPs);
    $('s-custom-domains').value = linesToText(s.customDomains);
    $('s-proxyips').value = linesToText(s.proxyIPs);
    $('s-nat64-on').checked = Boolean(s.enableNAT64);
    $('s-nat64').value = linesToText(s.nat64Prefixes);
    $('s-chain').value = s.chainProxy || '';

    if ($('s-tgproxy')) $('s-tgproxy').checked = s.enableTgProxy !== false;
    if ($('s-tgsecret')) $('s-tgsecret').value = s.tgProxySecret || '';
    if ($('s-tgdomain')) $('s-tgdomain').value = s.tgProxyDomain || '';
    syncTgLinksUI();

    $('s-updoh').value = s.upstreamDoH || 'https://1.1.1.1/dns-query';
    $('s-remotedns').value = s.remoteDnsMode || 'private-doh';
    $('s-directdns').value = s.directDns || '8.8.8.8';

    $('r-ir').checked = Boolean(s.bypassIran);
    $('r-lan').checked = Boolean(s.bypassLAN);
    $('r-quic').checked = Boolean(s.blockQuic);
    $('r-ads').checked = Boolean(s.blockAds);
    $('r-adult').checked = Boolean(s.blockAdult);
    $('r-sanction').checked = Boolean(s.sanctionBypass);
    $('r-cn').checked = Boolean(s.bypassChina);
    $('r-ru').checked = Boolean(s.bypassRussia);

    $('r-proxy-list').value = linesToText(s.customProxyDomains);
    $('r-direct-list').value = linesToText(s.customDirectDomains);
    $('r-block-list').value = linesToText(s.customBlockDomains);

    $('s-rootmode').value = s.rootMode || 'panel';
    $('s-fallback').value = s.fallbackDomain || '';
    $('s-infonodes').checked = s.showSubInfoNodes !== false;
  }

  // XHTTP card: dim the path field while the transport is off and show the endpoint clients dial.
  function syncXhttpUI() {
    var on = $('s-xhttp') ? $('s-xhttp').checked : false;
    var pathEl = $('s-xhttp-path');
    if (pathEl) pathEl.disabled = !on;
    var ep = $('xhttp-endpoint');
    if (ep) {
      var p = (pathEl && pathEl.value.trim()) || '/xh';
      if (p.charAt(0) !== '/') p = '/' + p;
      ep.textContent = (location.host || 'your-worker.workers.dev') + p.replace(/\/+$/, '');
    }
    var st = $('xhttp-state');
    if (st) {
      st.textContent = on ? 'On' : 'Off';
      st.className = 'badge ' + (on ? 'ok' : '');
    }
  }

  function collectSettingsFromForms() {
    var ports = [];
    $('tls-ports-box').querySelectorAll('input[type="checkbox"]').forEach(function (cb) {
      if (cb.checked) ports.push(Number(cb.value));
    });
    if (!ports.length) ports = [443];

    var hPorts = [];
    if ($('http-ports-box')) {
      $('http-ports-box').querySelectorAll('input[type="checkbox"]').forEach(function (cb) {
        if (cb.checked) hPorts.push(Number(cb.value));
      });
    }
    if (!hPorts.length) hPorts = [80];

    return {
      enableVless: $('s-vless').checked,
      enableTrojan: $('s-trojan').checked,
      enableHttpPorts: $('s-http-on').checked,
      tlsPorts: ports,
      httpPorts: hPorts,
      fingerprint: $('s-fp').value,
      alpn: $('s-alpn').value,
      earlyData: Number($('s-ed').value),
      wsPath: $('s-wspath').value.trim() || '/',
      enableXhttp: $('s-xhttp') ? $('s-xhttp').checked : false,
      xhttpPath: $('s-xhttp-path') ? ($('s-xhttp-path').value.trim() || '/xh') : '/xh',
      nodePrefix: $('s-node-prefix') ? $('s-node-prefix').value.trim() : '',

      enableFragment: $('s-frag-on').checked,
      fragmentPackets: $('s-frag-pkt').value.trim() || '1-1',
      fragmentLength: $('s-frag-len').value.trim() || '10-20',
      fragmentInterval: $('s-frag-int').value.trim() || '10-20',
      enableNoise: $('s-noise').checked,

      cleanIPs: textToLines($('s-cleanips').value),
      customDomains: textToLines($('s-custom-domains').value),
      proxyIPs: textToLines($('s-proxyips').value),
      enableNAT64: $('s-nat64-on').checked,
      nat64Prefixes: textToLines($('s-nat64').value),
      chainProxy: $('s-chain').value.trim(),

      enableTgProxy: $('s-tgproxy') ? $('s-tgproxy').checked : true,
      tgProxySecret: $('s-tgsecret') ? $('s-tgsecret').value.trim() : '',
      tgProxyDomain: $('s-tgdomain') ? $('s-tgdomain').value.trim() : '',

      upstreamDoH: $('s-updoh').value,
      remoteDnsMode: $('s-remotedns').value,
      directDns: $('s-directdns').value.trim() || '8.8.8.8',

      bypassIran: $('r-ir').checked,
      bypassLAN: $('r-lan').checked,
      blockQuic: $('r-quic').checked,
      blockAds: $('r-ads').checked,
      blockAdult: $('r-adult').checked,
      sanctionBypass: $('r-sanction').checked,
      bypassChina: $('r-cn').checked,
      bypassRussia: $('r-ru').checked,

      customProxyDomains: textToLines($('r-proxy-list').value),
      customDirectDomains: textToLines($('r-direct-list').value),
      customBlockDomains: textToLines($('r-block-list').value),

      rootMode: $('s-rootmode').value,
      fallbackDomain: $('s-fallback').value.trim(),
      showSubInfoNodes: $('s-infonodes').checked
    };
  }

  async function saveAllSettings() {
    try {
      var patch = collectSettingsFromForms();
      var res = await api('/api/settings', 'PUT', patch);
      ingestBootstrap(res);
      showToast('Settings saved to KV', 'Settings saved to KV');
    } catch (err) {
      showToast(err.message, err.message);
    }
  }

  $('save-net').onclick = saveAllSettings;
  $('save-route').onclick = saveAllSettings;
  $('save-sec').onclick = saveAllSettings;

  if ($('btn-gen-tgsecret')) {
    $('btn-gen-tgsecret').onclick = function () {
      $('s-tgsecret').value = randHex(16);
      syncTgLinksUI();
      showToast('New secret generated — click Save', 'New secret generated — click Save');
    };
  }
  if ($('s-tgsecret')) $('s-tgsecret').addEventListener('input', syncTgLinksUI);
  if ($('s-tgdomain')) $('s-tgdomain').addEventListener('input', syncTgLinksUI);
  if ($('s-tgproxy')) $('s-tgproxy').addEventListener('change', syncTgLinksUI);
  if ($('s-xhttp')) $('s-xhttp').addEventListener('change', syncXhttpUI);
  if ($('s-xhttp-path')) $('s-xhttp-path').addEventListener('input', syncXhttpUI);
  if ($('btn-xhttp-copy')) $('btn-xhttp-copy').addEventListener('click', function () {
    var ep = $('xhttp-endpoint');
    var txt = 'https://' + (ep ? ep.textContent.trim() : '');
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(txt).then(function () { showToast('XHTTP endpoint copied', 'XHTTP endpoint copied'); }, function () {});
    }
  });
  if ($('set-tg-copy')) {
    $('set-tg-copy').onclick = function () {
      var tg = computeTgLinks(true);
      if (tg.tmeUrl) copyText(tg.tmeUrl, 'Telegram Proxy URL', 'Telegram Proxy URL');
      else showToast('Invalid 32-hex secret', 'Invalid 32-hex secret');
    };
  }

  document.querySelectorAll('.frag-preset').forEach(function (btn) {
    btn.onclick = function () {
      $('s-frag-on').checked = true;
      $('s-frag-pkt').value = btn.getAttribute('data-p');
      $('s-frag-len').value = btn.getAttribute('data-l');
      $('s-frag-int').value = btn.getAttribute('data-i');
      showToast('Preset loaded — click Save', 'Preset loaded — click Save');
    };
  });

  $('btn-add-presets').onclick = function () {
    var presets = [
      'www.speedtest.net#Speedtest',
      'cp.cloudflare.com#CF-Captive',
      'radar.cloudflare.com#CF-Radar',
      '172.67.73.163#CF-Anycast-1',
      '104.18.2.14#CF-Anycast-2',
      '162.159.135.42#CF-Anycast-3'
    ];
    var existing = textToLines($('s-cleanips').value);
    presets.forEach(function (p) {
      if (existing.indexOf(p) < 0) existing.push(p);
    });
    $('s-cleanips').value = existing.join('\n');
    showToast('Clean IP presets added', 'Clean IP presets added');
  };

  /* -------------------- Browser Clean IP / Domain Scanner ---------------- */

  var lastUserScanHealthy = [];

  function parseUserCleanLine(rawLine) {
    var line = String(rawLine || '').trim();
    if (!line) return null;
    var hashIdx = line.indexOf('#');
    var addrPart = (hashIdx >= 0 ? line.slice(0, hashIdx) : line).trim();
    var remark = (hashIdx >= 0 ? line.slice(hashIdx + 1) : '').trim();
    if (!addrPart) return null;

    var host = addrPart;
    var port = 443;
    if (addrPart.charAt(0) === '[') {
      var closeBr = addrPart.indexOf(']');
      if (closeBr > 0) {
        host = addrPart.slice(0, closeBr + 1);
        var rest = addrPart.slice(closeBr + 1);
        if (rest.charAt(0) === ':') port = Number(rest.slice(1)) || 443;
      }
    } else {
      var colons = addrPart.split(':');
      if (colons.length === 2 && /^\d+$/.test(colons[1])) {
        host = colons[0];
        port = Number(colons[1]) || 443;
      } else if (colons.length > 2) {
        host = '[' + addrPart + ']';
      }
    }
    var bare = host.replace(/^\[|\]$/g, '');
    var isIpv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(bare);
    var isIpv6 = bare.indexOf(':') >= 0;
    var geoMatch = remark.match(/^([A-Z]{2})\|(.*)$/i);
    return {
      rawLine: line,
      addrPart: addrPart,
      host: host,
      bareHost: bare,
      port: port,
      remark: remark || bare,
      countryCode: geoMatch ? geoMatch[1].toUpperCase() : '',
      isRawIp: isIpv4 || isIpv6
    };
  }

  async function probeSingleCleanEntry(entry) {
    if (isSandboxPreview) {
      return { entry: entry, ms: 48 + Math.floor(Math.random() * 95), ok: true };
    }
    var timeoutMs = 3500;
    var targetBase = 'https://' + entry.host + (entry.port !== 443 ? (':' + entry.port) : '') + '/cdn-cgi/trace';

    async function singleAttempt() {
      var ctrl = typeof AbortController === 'function' ? new AbortController() : null;
      var aborted = false;
      var tid = ctrl ? setTimeout(function () {
        aborted = true;
        try { ctrl.abort(); } catch (e) {}
      }, timeoutMs) : null;
      var t0 = performance.now();
      try {
        await fetch(targetBase + '?_nl=' + Date.now() + Math.random().toString(36).slice(2, 6), {
          mode: 'no-cors',
          cache: 'no-store',
          credentials: 'omit',
          signal: ctrl ? ctrl.signal : undefined
        });
        if (tid) clearTimeout(tid);
        return { resolved: true, aborted: false, ms: Math.round(performance.now() - t0) };
      } catch (err) {
        if (tid) clearTimeout(tid);
        var elapsed = Math.round(performance.now() - t0);
        var wasAbort = aborted || (err && err.name === 'AbortError');
        return { resolved: false, aborted: wasAbort, ms: elapsed };
      }
    }

    var first = await singleAttempt();
    // no-cors cannot reveal HTTP status, and raw IP TLS has no useful Worker SNI.
    // A certificate error or a slow rejection is NOT proof that the IP works.
    if (first.resolved) {
      return { entry: entry, ms: Math.max(1, first.ms), ok: true };
    }
    return { entry: entry, ms: 9999, ok: false, inconclusive: true };
  }

  async function probeBatch(entries, concurrency) {
    var out = new Array(entries.length);
    var cursor = 0;
    async function worker() {
      while (cursor < entries.length) {
        var idx = cursor++;
        out[idx] = await probeSingleCleanEntry(entries[idx]);
      }
    }
    var workers = [];
    for (var i = 0; i < Math.min(concurrency || 6, entries.length); i++) {
      workers.push(worker());
    }
    await Promise.all(workers);
    return out;
  }

  var geoCountryCache = Object.create(null);
  function attachCountryToEntry(entry, cc) {
    if (!/^[A-Z]{2}$/.test(cc || '') || !entry.isRawIp) return;
    var note = entry.remark.replace(/^[A-Z]{2}\|/i, '').trim();
    if (note === entry.bareHost) note = 'Scan';
    entry.countryCode = cc;
    entry.rawLine = entry.addrPart + '#' + cc + '|' + (note || 'Scan');
  }

  async function enrichScanCountries(results) {
    var targets = results.filter(function (r) { return r.entry.isRawIp && !r.entry.countryCode; }).slice(0, 48);
    var pos = 0;
    async function work() {
      while (pos < targets.length) {
        var entry = targets[pos++].entry;
        var ip = entry.bareHost;
        if (/^(?:127\.|10\.|192\.168\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|169\.254\.|0\.|22[4-9]\.|23\d\.|24\d\.|25\d\.)/.test(ip) ||
            /^172\.(?:1[6-9]|2\d|3[01])\./.test(ip) || /^(?:fe80:|fc|fd|::1$)/i.test(ip)) continue;
        var cc = Object.prototype.hasOwnProperty.call(geoCountryCache, ip) ? geoCountryCache[ip] : '';
        if (!cc && !Object.prototype.hasOwnProperty.call(geoCountryCache, ip)) {
          if (isSandboxPreview) cc = 'US';
          else {
            var ctrl = new AbortController();
            var tid = setTimeout(function () { ctrl.abort(); }, 3000);
            try {
              var geo = await fetch('https://ipwho.is/' + encodeURIComponent(ip) + '?fields=success,country_code', {
                signal: ctrl.signal, credentials: 'omit', referrerPolicy: 'no-referrer', cache: 'no-store'
              });
              var data = geo.ok ? await geo.json() : null;
              cc = data && data.success === true && /^[A-Z]{2}$/.test(data.country_code || '') ? data.country_code : '';
            } catch (e) { cc = ''; }
            finally { clearTimeout(tid); }
          }
          geoCountryCache[ip] = cc;
        }
        if (cc) attachCountryToEntry(entry, cc);
      }
    }
    await Promise.all([work(), work(), work()]);
  }

  if ($('btn-scan-user-list')) {
    $('btn-scan-user-list').onclick = async function () {
      var rawLines = textToLines($('s-cleanips').value);
      var parsedList = rawLines.map(parseUserCleanLine).filter(Boolean);
      if (!parsedList.length) {
        showToast('Enter IPs or domains first', 'Enter IPs or domains first');
        return;
      }
      var box = $('scan-results');
      var sumEl = $('scan-summary');
      var pruneBtn = $('btn-prune-clean');
      box.hidden = false;
      box.innerHTML = '';
      if (pruneBtn) pruneBtn.hidden = true;
      sumEl.hidden = false;
      sumEl.textContent = tr('Probing browser reachability and looking up approximate IP country…', 'Probing browser reachability and looking up approximate IP country…');
      var results = await probeBatch(parsedList, 6);
      await enrichScanCountries(results);
      var taggedLines = parsedList.map(function (p) { return p.rawLine; });
      if (taggedLines.join('\n') !== rawLines.join('\n')) $('s-cleanips').value = taggedLines.join('\n');
      results.sort(function (a, b) { return a.ms - b.ms; });
      lastUserScanHealthy = results.filter(function (r) { return r.ok && !r.entry.isRawIp; });
      var candidateCount = results.filter(function (r) { return r.entry.isRawIp; }).length;
      sumEl.textContent = tr(
        'Domain browser responses: ' + lastUserScanHealthy.length + ' · raw IPs: ' + candidateCount + ' unverified candidates. GeoIP is approximate; save settings to update Normal subscription node labels. No IP is removed after a TLS error.',
        'Domain browser responses: ' + lastUserScanHealthy.length + ' · raw IPs: ' + candidateCount + ' unverified candidates. GeoIP is approximate; save settings to update Normal subscription node labels. No IP is removed after a TLS error.'
      );
      if (pruneBtn && lastUserScanHealthy.length) pruneBtn.hidden = false;
      results.forEach(function (r) {
        var item = document.createElement('div');
        item.className = 'scan-item';
        var labelStr = r.entry.bareHost + (r.entry.port !== 443 ? (':' + r.entry.port) : '');
        var verdict = r.entry.isRawIp
          ? (r.ok ? 'TLS ONLY · ' + r.ms + 'ms' : 'UNVERIFIED')
          : (r.ok ? 'FETCH OK · ' + r.ms + 'ms' : 'INCONCLUSIVE');
        item.innerHTML = '<span class="scan-entry" dir="ltr">' + esc(labelStr) +
          (r.entry.isRawIp ? ' <small>' + esc(r.entry.countryCode || 'CC ?') + '</small>' : '') + '</span>' +
          '<span class="badge' + (r.ok && !r.entry.isRawIp ? ' ok' : '') + '">' + esc(verdict) + '</span>';
        box.appendChild(item);
      });
    };
  }

  if ($('btn-prune-clean')) {
    $('btn-prune-clean').onclick = function () {
      if (!lastUserScanHealthy.length) return;
      var current = textToLines($('s-cleanips').value);
      var priority = new Set(lastUserScanHealthy.map(function (r) { return r.entry.addrPart; }));
      var first = [], rest = [];
      current.forEach(function (line) {
        var address = line.split('#')[0].trim();
        (priority.has(address) ? first : rest).push(line);
      });
      $('s-cleanips').value = first.concat(rest).join('\n');
      $('btn-prune-clean').hidden = true;
      showToast('Prioritized responses; kept all IPs. Save to update Normal', 'Prioritized responses; kept all IPs. Save to update Normal');
    };
  }

  // Cloudflare's own published IPv4/IPv6 lists are loaded through the same-origin Worker.
  // The browser cannot establish the subscription's Host/SNI by fetching a raw IP.
  var officialRanges = null;
  function sampleCidrAddresses(cidr, count, family) {
    var pair = cidr.split('/');
    var bits = Number(pair[1]);
    var output = [];
    if (family === 4) {
      var octets = pair[0].split('.').map(Number);
      if (octets.length !== 4 || bits < 0 || bits > 32) return output;
      var ipNumber = (((octets[0] * 256 + octets[1]) * 256 + octets[2]) * 256 + octets[3]) >>> 0;
      var total = Math.pow(2, 32 - bits);
      var net = (ipNumber & (bits ? (0xffffffff << (32 - bits)) : 0)) >>> 0;
      var seen = new Set();
      for (var i = 0; i < count; i++) {
        var offset = Math.floor(((i + Math.random()) / count) * total);
        if (total > 2) offset = Math.max(1, Math.min(total - 2, offset));
        var v = (net + offset) >>> 0;
        if (seen.has(v)) continue;
        seen.add(v);
        output.push([v >>> 24, (v >>> 16) & 255, (v >>> 8) & 255, v & 255].join('.'));
      }
      return output;
    }
    if (bits < 0 || bits > 128 || pair[0].split('::').length > 2) return output;
    var sides = pair[0].split('::');
    var lhs = sides[0] ? sides[0].split(':') : [];
    var rhs = sides.length === 2 && sides[1] ? sides[1].split(':') : [];
    var zeros = 8 - lhs.length - rhs.length;
    if (zeros < 0 || (sides.length === 1 && zeros !== 0)) return output;
    var words = lhs.concat(Array(zeros).fill('0'), rhs);
    var base = words.reduce(function (acc, h) { return (acc << 16n) + BigInt('0x' + h); }, 0n);
    var hostBits = BigInt(128 - bits);
    var size = 1n << hostBits;
    var network = (base >> hostBits) << hostBits;
    var seenV6 = new Set();
    for (var j = 0; j < count && BigInt(j) < size; j++) {
      var span = size / BigInt(count);
      var rand = new Uint32Array(4);
      crypto.getRandomValues(rand);
      var entropy = rand.reduce(function (acc, word) { return (acc << 32n) + BigInt(word); }, 0n);
      var offsetV6 = span > 0n ? BigInt(j) * span + (entropy % span) : BigInt(j);
      var v6 = network + offsetV6;
      var v6str = Array.from({ length: 8 }, function (_, k) {
        return Number((v6 >> BigInt((7 - k) * 16)) & 65535n).toString(16);
      }).join(':');
      if (!seenV6.has(v6str)) { seenV6.add(v6str); output.push('[' + v6str + ']'); }
    }
    return output;
  }

  $('btn-scan-clean').onclick = async function () {
    var loadBtn = $('btn-scan-clean');
    loadBtn.disabled = true;
    try {
      var data = await api('/api/cf/ip-ranges');
      if (!data || !Array.isArray(data.ipv4) || !Array.isArray(data.ipv6) || !data.ipv4.length) throw new Error('Official range feed is unavailable');
      officialRanges = data;
      var rows = $('cf-range-list');
      rows.innerHTML = '';
      var ipv4Total = 0;
      data.ipv4.concat(data.ipv6).forEach(function (cidr, i) {
        var ipv4 = i < data.ipv4.length;
        var mask = Number(cidr.split('/')[1]);
        var countText = ipv4 ? Math.pow(2, 32 - mask).toLocaleString('en-US') : ('2^' + (128 - mask));
        if (ipv4) ipv4Total += Math.pow(2, 32 - mask);
        var row = document.createElement('label');
        row.className = 'range-row';
        row.innerHTML = '<span class="range-key"><span class="badge">IPv' + (ipv4 ? '4' : '6') + '</span> ' +
          '<span class="mono" dir="ltr">' + esc(cidr) + '</span></span>' +
          '<span class="range-count mono" dir="ltr">' + esc(countText) + ' IP</span>' +
          '<input type="number" class="range-samples" min="0" max="12" step="1" value="' + (i < 3 ? '4' : '0') + '" data-cidr="' + esc(cidr) + '" data-family="' + (ipv4 ? '4' : '6') + '" aria-label="Samples for ' + esc(cidr) + '">';
        rows.appendChild(row);
      });
      setText('cf-ranges-total', data.ipv4.length + ' IPv4 + ' + data.ipv6.length + ' IPv6 · ' + ipv4Total.toLocaleString('en-US') + ' IPv4 IPs');
      $('cf-ranges-panel').hidden = false;
      $('scan-summary').hidden = false;
      $('scan-summary').textContent = tr(
        (data.stale ? 'An older cached ' : 'The ') + 'official Cloudflare list is loaded. Choose a count per CIDR; raw IPs remain unverified client-test candidates.',
        (data.stale ? 'An older cached ' : 'The ') + 'official Cloudflare list is loaded. Choose a count per CIDR; raw IPs remain unverified client-test candidates.'
      );
    } catch (err) {
      $('cf-ranges-panel').hidden = true;
      showToast('Official range feed unavailable; no guessed fallback', 'Official range feed unavailable; no guessed fallback');
    } finally { loadBtn.disabled = false; }
  };

  $('btn-scan-ranges').onclick = async function () {
    if (!officialRanges) return;
    var fields = Array.from($('cf-range-list').querySelectorAll('input.range-samples'));
    var selections = [], requested = 0;
    for (var i = 0; i < fields.length; i++) {
      var n = Number(fields[i].value);
      if (!Number.isInteger(n) || n < 0 || n > 12) {
        showToast('Samples per CIDR must be an integer between 0 and 12', 'Samples per CIDR must be an integer between 0 and 12'); return;
      }
      if (n) { requested += n; selections.push({ cidr: fields[i].dataset.cidr, family: Number(fields[i].dataset.family), count: n }); }
    }
    if (!requested || requested > 48) {
      showToast('Total samples must be between 1 and 48', 'Total samples must be between 1 and 48'); return;
    }
    var btn = $('btn-scan-ranges'), box = $('scan-results'), summary = $('scan-summary');
    btn.disabled = true;
    if ($('btn-prune-clean')) $('btn-prune-clean').hidden = true;
    box.hidden = false; box.innerHTML = ''; summary.hidden = false;
    summary.textContent = tr('Probing ' + requested + ' candidates and looking up approximate countries…', 'Probing ' + requested + ' candidates and looking up approximate countries…');
    try {
      var raw = [];
      selections.forEach(function (sel) {
        sampleCidrAddresses(sel.cidr, sel.count, sel.family).forEach(function (ip) {
          var item = parseUserCleanLine(ip + '#CF-Scan');
          if (item) raw.push(item);
        });
      });
      var results = await probeBatch(raw, 6);
      await enrichScanCountries(results);
      results.sort(function (a, b) { return a.ms - b.ms; });
      var tlsCount = results.filter(function (r) { return r.ok; }).length;
      var ccCount = results.filter(function (r) { return r.entry.countryCode; }).length;
      summary.textContent = tr(
        results.length + ' official-range samples · ' + tlsCount + ' browser TLS responses · ' + ccCount + ' approximate country codes. This does NOT verify the Worker connection; add and test in your actual client, then save for the Normal subscription.',
        results.length + ' official-range samples · ' + tlsCount + ' browser TLS responses · ' + ccCount + ' approximate country codes. This does NOT verify the Worker connection; add and test in your actual client, then save for the Normal subscription.'
      );
      results.forEach(function (r) {
        var item = document.createElement('div');
        item.className = 'scan-item range-result';
        item.innerHTML = '<span class="scan-entry mono" dir="ltr">' + esc(r.entry.bareHost) +
          ' <small>' + esc(r.entry.countryCode || 'CC ?') + '</small></span>' +
          '<span class="badge">' + (r.ok ? 'TLS ONLY ' + r.ms + 'ms' : 'UNVERIFIED') + '</span>' +
          (r.entry.countryCode ? '' : '<input class="range-manual-cc mono" type="text" maxlength="2" placeholder="CC" aria-label="ISO country code for ' + esc(r.entry.bareHost) + '">') +
          '<button class="btn ghost sm-btn" type="button">' + svgIcon('plus', 'ic-sm') + '<span>ADD</span></button>';
        var addBtn = item.querySelector('button');
        addBtn.onclick = function () {
          var manual = item.querySelector('.range-manual-cc');
          var cc = r.entry.countryCode || (manual ? manual.value.trim().toUpperCase() : '');
          if (!/^[A-Z]{2}$/.test(cc)) {
            showToast('Enter a two-letter country code before adding', 'Enter a two-letter country code before adding');
            if (manual) manual.focus();
            return;
          }
          attachCountryToEntry(r.entry, cc);
          var cur = textToLines($('s-cleanips').value).filter(function (line) { return line.split('#')[0].trim() !== r.entry.addrPart; });
          cur.push(r.entry.rawLine);
          $('s-cleanips').value = cur.join('\n');
          addBtn.disabled = true;
          addBtn.innerHTML = svgIcon('check', 'ic-sm') + '<span>ADDED</span>';
          showToast('Candidate added; client-test it, then save settings', 'Candidate added; client-test it, then save settings');
        };
        box.appendChild(item);
      });
    } catch (err) {
      summary.textContent = tr('Probe incomplete; no IP was verified.', 'Probe incomplete; no IP was verified.');
    } finally { btn.disabled = false; }
  };

  $('btn-test-proxyip').onclick = async function () {
    var first = textToLines($('s-proxyips').value)[0] || '';
    if (!first) { showToast('Enter a ProxyIP first', 'Enter a ProxyIP first'); return; }
    setText('proxyip-res', 'TESTING…');
    try {
      var r = await api('/api/test-proxyip', 'POST', { target: first });
      setText('proxyip-res', r.ok ? ('OK · ' + r.latencyMs + ' ms') : ('ERR · ' + r.error));
    } catch (e) {
      setText('proxyip-res', 'ERR · ' + e.message);
    }
  };

  $('btn-test-chain').onclick = async function () {
    var target = $('s-chain').value.trim();
    if (!target) { showToast('Enter chain proxy URL', 'Enter chain proxy URL'); return; }
    try {
      var r = await api('/api/test-proxyip', 'POST', { target: target });
      if (r.ok) showToast('Chain OK (' + r.latencyMs + 'ms)', 'Chain OK (' + r.latencyMs + 'ms)');
      else showToast('Failed: ' + r.error, 'Failed: ' + r.error);
    } catch (e) {
      showToast(e.message, e.message);
    }
  };

  $('f-pass').addEventListener('submit', async function (ev) {
    ev.preventDefault();
    try {
      await api('/api/password', 'POST', {
        currentPassword: $('pw-cur').value,
        newPassword: $('pw-new').value
      });
      $('pw-cur').value = '';
      $('pw-new').value = '';
      showToast('Password updated', 'Password updated');
    } catch (err) {
      showToast(err.message, err.message);
    }
  });

  $('btn-export').onclick = async function () {
    try {
      var data = await api('/api/backup', 'GET');
      var blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      var objUrl = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = objUrl;
      a.download = 'oryvex-backup-' + new Date().toISOString().slice(0, 10) + '.json';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(function () { try { URL.revokeObjectURL(objUrl); } catch (e) {} }, 2500);
      showToast('Backup downloaded', 'Backup downloaded');
    } catch (err) {
      showToast(err.message, err.message);
    }
  };

  $('inp-import').addEventListener('change', function (ev) {
    var file = ev.target.files && ev.target.files[0];
    if (!file) return;
    var reader = new FileReader();
    reader.onerror = function () {
      showToast('Failed to read backup file', 'Failed to read backup file');
      ev.target.value = '';
    };
    reader.onload = async function () {
      try {
        var parsed = JSON.parse(String(reader.result || '{}'));
        var res = await api('/api/restore', 'POST', parsed);
        ingestBootstrap(res);
        showToast('Backup restored', 'Backup restored');
      } catch (err) {
        showToast('Restore error: ' + err.message, 'Restore error: ' + err.message);
      }
      ev.target.value = '';
    };
    reader.readAsText(file);
  });

  function renderActivityLogs() {
    var box = $('logs-list');
    box.innerHTML = '';
    if (!STATE.logs.length) {
      box.innerHTML = '<div class="node-row"><span class="mono sm">NO LOGS YET</span></div>';
      return;
    }
    STATE.logs.forEach(function (l) {
      var row = document.createElement('div');
      row.className = 'node-row';
      var dt = new Date(l.ts).toISOString().replace('T', ' ').slice(0, 19);
      row.innerHTML = '<span class="mono sm">' + esc(dt) + ' · [' + esc(l.event) + ']</span><span>' + esc(l.detail) + '</span>';
      box.appendChild(row);
    });
  }

  /* ------ Cloudflare Daily Request Quota Bar & Hardcoded GitHub Updater --- */

  var cfUsageFetching = false;
  var ghChecking = false;

  function inferHostWorkerName() {
    var h = String(STATE.host || location.hostname || '').split(':')[0].toLowerCase();
    if (h.slice(-12) === '.workers.dev') {
      var p = h.split('.');
      if (p.length >= 4) return p[0];
    }
    return '';
  }

  function formatResetRemain(sec) {
    var s = Math.max(0, Number(sec) || 0);
    var hh = Math.floor(s / 3600);
    var mm = Math.floor((s % 3600) / 60);
    return tr('Reset in ' + hh + 'h ' + mm + 'm', 'Reset in ' + hh + 'h ' + mm + 'm');
  }

  function syncCfQuotaUI() {
    var cfg = STATE.cfIntegration || {};
    var u = STATE.cfUsage;
    var miniBar = $('cf-mini-bar');
    var miniTxt = $('cf-mini-txt');
    var modalBar = $('cf-modal-bar');
    var modalNums = $('cf-modal-nums');
    var modalAcc = $('cf-modal-acc');
    var modalReset = $('cf-modal-reset');

    if (!cfg.hasToken) {
      if (miniBar) miniBar.style.width = '0%';
      if (miniTxt) miniTxt.textContent = tr('SET TOKEN', 'SET TOKEN');
      if (modalBar) modalBar.style.width = '0%';
      if (modalNums) modalNums.textContent = '0 / 100,000 (0%)';
      if (modalAcc) modalAcc.textContent = tr('Cloudflare API token not set', 'Cloudflare API token not set');
      if (modalReset) modalReset.textContent = 'UTC 00:00';
      if ($('btn-cf-clear')) $('btn-cf-clear').hidden = true;
      if ($('gh-token-hint')) $('gh-token-hint').textContent = tr('Set CF Token', 'Set CF Token');
      return;
    }

    if ($('btn-cf-clear')) $('btn-cf-clear').hidden = false;
    if ($('gh-token-hint')) {
      $('gh-token-hint').textContent = cfg.canEditWorkers
        ? tr('CF Token Ready', 'CF Token Ready')
        : tr('CF Token Set', 'CF Token Set');
    }

    if (!u) {
      if (miniBar) miniBar.style.width = '0%';
      if (miniTxt) miniTxt.textContent = '...';
      if (modalAcc) modalAcc.textContent = (cfg.accountName || cfg.accountId || 'Cloudflare');
      return;
    }

    var lim = Math.max(1000, Number(u.dailyLimit || cfg.dailyLimit) || 100000);
    var used = Math.max(0, Number(u.usedToday) || 0);
    var pct = used <= 0 ? 0 : Math.min(100, Math.max(1, Math.round((used / lim) * 100)));
    var pctExact = Math.min(100, Math.round((used / lim) * 1000) / 10);

    if (miniBar) {
      miniBar.style.width = pct + '%';
      if (miniBar.parentElement) miniBar.parentElement.classList.toggle('warn', pct >= 85);
    }
    if (miniTxt) {
      miniTxt.textContent = formatCompactCount(used) + '/' + formatCompactCount(lim);
    }
    if (modalBar) {
      modalBar.style.width = pct + '%';
      if (modalBar.parentElement) modalBar.parentElement.classList.toggle('warn', pct >= 85);
    }
    if (modalNums) {
      modalNums.textContent = used.toLocaleString('en-US') + ' / ' + lim.toLocaleString('en-US') + ' (' + pctExact + '%)';
    }
    if (modalAcc) {
      var accLabel = cfg.accountName || cfg.accountId || 'Cloudflare';
      if (cfg.scriptName) accLabel += ' · ' + cfg.scriptName;
      modalAcc.textContent = accLabel;
    }
    if (modalReset) {
      modalReset.textContent = formatResetRemain(u.resetInSec);
    }
  }

  async function refreshCfDailyUsage(forceFresh) {
    if (cfUsageFetching) return;
    cfUsageFetching = true;
    try {
      var res = await api('/api/cf/usage' + (forceFresh ? '?fresh=1' : ''), 'GET');
      if (res && res.cfIntegration) STATE.cfIntegration = res.cfIntegration;
      if (res && res.ok && res.usage) {
        STATE.cfUsage = res.usage;
      }
      syncCfQuotaUI();
      if (forceFresh && res && res.ok) {
        showToast('Cloudflare daily quota refreshed', 'Cloudflare daily quota refreshed');
      }
    } catch (err) {
      if (forceFresh) showToast(err.message, err.message);
    } finally {
      cfUsageFetching = false;
    }
  }

  function showCfMessage(text, isOk) {
    var box = $('cf-verify-msg');
    if (!box) return;
    if (!text) {
      box.hidden = true;
      box.textContent = '';
      return;
    }
    box.className = isOk ? 'ok-msg' : 'err';
    box.textContent = text;
    box.hidden = false;
  }

  function openCfModal() {
    var modal = $('cf-modal');
    if (!modal) return;
    var cfg = STATE.cfIntegration || {};
    showCfMessage('', false);
    if ($('cf-perm-popover')) $('cf-perm-popover').hidden = true;
    if ($('cf-inp-token')) {
      $('cf-inp-token').value = '';
      $('cf-inp-token').placeholder = cfg.hasToken
        ? (cfg.maskedToken + ' (' + tr('saved — type to replace', 'saved — type to replace') + ')')
        : 'Paste Cloudflare API Token...';
    }
    if ($('cf-inp-script')) {
      $('cf-inp-script').value = cfg.scriptName || inferHostWorkerName();
    }
    if ($('cf-inp-limit')) {
      $('cf-inp-limit').value = String(cfg.dailyLimit || 100000);
    }
    syncCfQuotaUI();
    modal.hidden = false;
  }

  if ($('btn-cf-quota')) $('btn-cf-quota').onclick = openCfModal;
  if ($('btn-cf-close')) $('btn-cf-close').onclick = function () { $('cf-modal').hidden = true; };
  if ($('cf-modal')) {
    $('cf-modal').addEventListener('click', function (ev) {
      if (ev.target === $('cf-modal')) $('cf-modal').hidden = true;
    });
  }
  if ($('btn-cf-guide-pop')) {
    $('btn-cf-guide-pop').onclick = function () {
      var p = $('cf-perm-popover');
      if (p) p.hidden = !p.hidden;
    };
  }
  if ($('btn-cf-guide-close')) {
    $('btn-cf-guide-close').onclick = function () {
      if ($('cf-perm-popover')) $('cf-perm-popover').hidden = true;
    };
  }
  if ($('btn-cf-refresh')) {
    $('btn-cf-refresh').onclick = function () {
      refreshCfDailyUsage(true);
    };
  }

  async function submitCfTokenAction(actionMode) {
    var rawTok = ($('cf-inp-token') ? $('cf-inp-token').value : '').trim();
    var cfg = STATE.cfIntegration || {};
    var tokToSend = rawTok || (cfg.hasToken ? '__SAVED__' : '');
    if (!tokToSend) {
      showCfMessage(tr('Please enter your Cloudflare API Token first.', 'Please enter your Cloudflare API Token first.'), false);
      return;
    }
    var scriptName = ($('cf-inp-script') ? $('cf-inp-script').value : '').trim();
    var dailyLimit = Number($('cf-inp-limit') ? $('cf-inp-limit').value : 100000) || 100000;

    showCfMessage(tr('Verifying token & permissions with Cloudflare…', 'Verifying token & permissions with Cloudflare…'), true);
    try {
      var res = await api('/api/cf/config', 'POST', {
        action: actionMode,
        token: tokToSend,
        scriptName: scriptName,
        dailyLimit: dailyLimit
      });
      if (res.cfIntegration) STATE.cfIntegration = res.cfIntegration;
      if (res.usage) STATE.cfUsage = res.usage;
      if (res.scriptName && $('cf-inp-script')) $('cf-inp-script').value = res.scriptName;
      if ($('cf-inp-token')) $('cf-inp-token').value = '';
      syncCfQuotaUI();

      var updPermTxt = res.canEditWorkers
        ? tr('Workers Edit: YES', 'Workers Edit: YES')
        : tr('Analytics Read-Only', 'Analytics Read-Only');
      showCfMessage(
        tr(
          (actionMode === 'save' ? 'Token saved · Account: ' : 'Verified · Account: ') +
            (res.accountName || res.accountId || 'OK') +
            ' · ' + updPermTxt,
          (actionMode === 'save' ? 'Token saved · Account: ' : 'Verified · Account: ') +
            (res.accountName || res.accountId || 'OK') +
            ' · ' + updPermTxt
        ),
        true
      );
      if (actionMode === 'save') {
        showToast('Cloudflare token saved', 'Cloudflare token saved');
      }
    } catch (err) {
      showCfMessage(err.message, false);
    }
  }

  if ($('btn-cf-verify')) {
    $('btn-cf-verify').onclick = function () { submitCfTokenAction('verify'); };
  }
  if ($('btn-cf-save')) {
    $('btn-cf-save').onclick = function () { submitCfTokenAction('save'); };
  }
  if ($('btn-cf-clear')) {
    $('btn-cf-clear').onclick = async function () {
      try {
        var res = await api('/api/cf/config', 'POST', { action: 'clear' });
        STATE.cfIntegration = res.cfIntegration || { hasToken: false };
        STATE.cfUsage = null;
        if ($('cf-inp-token')) $('cf-inp-token').value = '';
        syncCfQuotaUI();
        showCfMessage(tr('Token removed from panel.', 'Token removed from panel.'), true);
        showToast('Cloudflare token removed', 'Cloudflare token removed');
      } catch (err) {
        showCfMessage(err.message, false);
      }
    };
  }

  // Refresh Cloudflare quota every 3 minutes when Admin panel is open and token is configured
  setInterval(function () {
    if (STATE.mode !== 'admin' || document.hidden) return;
    if (STATE.cfIntegration && STATE.cfIntegration.hasToken) {
      refreshCfDailyUsage(false);
    }
  }, 180000);

  /* -------- GitHub updater (repository injected at build time) -------- */

  function installedVersion() {
    return (STATE.ghInfo && STATE.ghInfo.currentVersion) || STATE.version || BUILD_VERSION || '';
  }

  function syncGhUpdaterUI(ver) {
    if (ver) STATE.version = ver;
    var curV = ver || installedVersion();
    if (curV) {
      setText('gh-mini-ver', 'V' + curV);
      setText('gh-cur-ver', 'V' + curV);
    }
    var hasUpdate = !!(STATE.ghInfo && STATE.ghInfo.updateAvailable);
    if ($('gh-upd-dot')) $('gh-upd-dot').hidden = !hasUpdate;
    if ($('btn-gh-updater')) {
      $('btn-gh-updater').title = hasUpdate
        ? 'V' + STATE.ghInfo.latestVersion + ' is available · github.com/' + OFFICIAL_GITHUB_REPO
        : 'github.com/' + OFFICIAL_GITHUB_REPO;
    }
  }

  function showGhMessage(text, isOk) {
    var box = $('gh-msg');
    if (!box) return;
    if (!text) {
      box.hidden = true;
      box.textContent = '';
      return;
    }
    box.className = isOk ? 'ok-msg' : 'err';
    box.textContent = text;
    box.hidden = false;
  }

  function fmtWhen(ts) {
    if (!ts) return '';
    var d = new Date(ts);
    if (isNaN(d.getTime())) return '';
    var diff = Math.round((Date.now() - d.getTime()) / 60000);
    if (diff < 1) return 'just now';
    if (diff < 60) return diff + ' min ago';
    if (diff < 1440) return Math.round(diff / 60) + ' h ago';
    return d.toISOString().slice(0, 10);
  }

  function setGhState(state, label) {
    var hero = $('gh-hero');
    if (hero) hero.setAttribute('data-state', state);
    var bdg = $('gh-status-badge');
    if (bdg) {
      bdg.className = 'badge' + (state === 'available' ? ' inv' : state === 'current' ? ' ok' : state === 'error' ? ' bad' : '');
      bdg.textContent = label;
    }
  }

  function renderGhInfo(res) {
    if (!res) return;
    STATE.ghInfo = res;
    syncGhUpdaterUI(res.currentVersion);
    setText('gh-rem-ver', res.latestVersion ? 'V' + res.latestVersion : '—');
    if ($('gh-dl-link')) $('gh-dl-link').href = res.releaseUrl || res.releasesUrl || OFFICIAL_GITHUB_URL + '/releases';
    setText('gh-published', res.publishedAt ? 'released ' + fmtWhen(res.publishedAt) : '');
    setText('gh-checked', res.checkedAt ? 'checked ' + fmtWhen(res.checkedAt) : '');
    var notes = $('gh-notes-box');
    if (notes) {
      var txt = String(res.releaseNotes || '').trim();
      notes.textContent = txt;
      notes.hidden = !txt;
    }
    if ($('gh-inp-script') && !($('gh-inp-script').value || '').trim() && res.scriptName) {
      $('gh-inp-script').value = res.scriptName;
    }
    var apply = $('btn-gh-apply');
    if (res.configured === false) {
      setGhState('error', 'NOT CONFIGURED');
      showGhMessage(res.message || 'This build has no update repository.', false);
    } else if (res.notPublishedYet) {
      setGhState('idle', 'NO RELEASE YET');
      showGhMessage(res.message || '', true);
    } else if (res.updateAvailable) {
      setGhState('available', 'UPDATE AVAILABLE');
    } else if (res.aheadOfRelease) {
      setGhState('current', 'AHEAD OF RELEASE');
    } else {
      setGhState('current', 'UP TO DATE');
    }
    if (apply) apply.disabled = !res.updateAvailable;
  }

  function cacheGhInfo(res) {
    try { localStorage.setItem(UPDATE_CACHE_KEY, JSON.stringify({ at: Date.now(), info: res })); } catch (e) {}
  }
  function readCachedGhInfo() {
    try {
      var raw = JSON.parse(localStorage.getItem(UPDATE_CACHE_KEY) || 'null');
      if (!raw || !raw.info) return null;
      // A cache written by another installed version is stale by definition.
      if (raw.info.currentVersion !== installedVersion()) return null;
      return raw;
    } catch (e) { return null; }
  }

  async function checkGitHubUpdates(silentToast, force) {
    if (ghChecking) return;
    ghChecking = true;
    setGhState('checking', 'CHECKING…');
    if ($('gh-check-ic')) $('gh-check-ic').classList.add('ic-spin');
    try {
      var res = await api('/api/update/check' + (force ? '?force=1' : ''), 'GET');
      if (!force || !silentToast) showGhMessage('', false);
      renderGhInfo(res);
      cacheGhInfo(res);
      if (!silentToast) {
        if (res.updateAvailable) showToast('V' + res.latestVersion + ' is available', 'V' + res.latestVersion + ' is available');
        else if (res.configured !== false && !res.notPublishedYet) showToast('You are on the latest release', 'You are on the latest release');
      }
    } catch (err) {
      setGhState('error', 'CHECK FAILED');
      showGhMessage(err.message, false);
    } finally {
      ghChecking = false;
      if ($('gh-check-ic')) $('gh-check-ic').classList.remove('ic-spin');
    }
  }

  // Quiet background check for admins: lights the NEW dot without opening anything.
  function autoCheckUpdates() {
    if (STATE.mode !== 'admin' || STATE.isDemo) return;
    var cached = readCachedGhInfo();
    if (cached) renderGhInfo(cached.info);
    if (!cached || Date.now() - cached.at > UPDATE_AUTO_MS) {
      setTimeout(function () { checkGitHubUpdates(true, false); }, 2500);
    }
  }

  function openGhModal() {
    var modal = $('gh-modal');
    if (!modal) return;
    showGhMessage('', false);
    var cfg = STATE.cfIntegration || {};
    if ($('gh-inp-script') && !($('gh-inp-script').value || '').trim()) {
      $('gh-inp-script').value = cfg.scriptName || inferHostWorkerName();
    }
    if ($('gh-token-hint')) $('gh-token-hint').textContent = cfg.hasToken ? 'CF token saved' : 'Configure CF token';
    syncCfQuotaUI();
    modal.hidden = false;
    if (STATE.ghInfo) renderGhInfo(STATE.ghInfo);
    var stale = !STATE.ghInfo || !STATE.ghInfo.checkedAt || Date.now() - STATE.ghInfo.checkedAt > 5 * 60000;
    if (stale) checkGitHubUpdates(true, false);
  }

  if ($('btn-gh-updater')) $('btn-gh-updater').onclick = openGhModal;
  if ($('btn-gh-close')) $('btn-gh-close').onclick = function () { $('gh-modal').hidden = true; };
  if ($('gh-modal')) {
    $('gh-modal').addEventListener('click', function (ev) {
      if (ev.target === $('gh-modal')) $('gh-modal').hidden = true;
    });
  }
  if ($('btn-gh-open-cf')) {
    $('btn-gh-open-cf').onclick = function () {
      $('gh-modal').hidden = true;
      openCfModal();
    };
  }
  if ($('btn-gh-check')) {
    $('btn-gh-check').onclick = function () {
      showGhMessage('', false);
      checkGitHubUpdates(false, true);
    };
  }
  if ($('btn-gh-apply')) {
    $('btn-gh-apply').onclick = async function () {
      var cfg = STATE.cfIntegration || {};
      if (!cfg.hasToken) {
        showGhMessage('Save a Cloudflare API token with Workers Scripts: Edit first (Configure CF token).', false);
        return;
      }
      var info = STATE.ghInfo || {};
      if (!info.updateAvailable) {
        showGhMessage('Nothing to install: you are already on the latest release.', true);
        return;
      }
      var targetScript = ($('gh-inp-script') ? $('gh-inp-script').value : '').trim();
      var btn = $('btn-gh-apply');
      btn.disabled = true;
      setGhState('checking', 'INSTALLING…');
      showGhMessage('Downloading ' + (info.tag || 'the release') + ' from github.com/' + OFFICIAL_GITHUB_REPO + ' and deploying it to "' + (targetScript || 'this Worker') + '"…', true);
      try {
        var res = await api('/api/update/apply', 'POST', { scriptName: targetScript });
        try { localStorage.removeItem(UPDATE_CACHE_KEY); } catch (e) {}
        setGhState('current', 'INSTALLED');
        showGhMessage('Worker "' + res.scriptName + '" is now on V' + res.targetVersion + '. Reloading…', true);
        showToast('Update installed', 'Update installed');
        setTimeout(function () { location.reload(); }, res.reloadAfterMs || 2200);
      } catch (err) {
        setGhState('error', 'INSTALL FAILED');
        showGhMessage(err.message, false);
        btn.disabled = false;
      }
    };
  }

  document.addEventListener('keydown', function (ev) {
    if (ev.key === 'Escape') {
      if ($('cf-modal') && !$('cf-modal').hidden) $('cf-modal').hidden = true;
      if ($('gh-modal') && !$('gh-modal').hidden) $('gh-modal').hidden = true;
    }
  });

  /* --------------------------------------------------------------- Boot */

  setText('year', String(new Date().getFullYear()));
  if (window.ORYVEX && window.ORYVEX.cf) {
    mergeVisitorCf(window.ORYVEX.cf);
  }
  applyAppearance();
  detectVisitorNetwork();
  requestAnimationFrame(drawMonochromeChartFrame);

  api('/api/bootstrap', 'GET')
    .then(ingestBootstrap)
    .catch(function () {
      setText('diag-mode', 'OFFLINE');
      $('v-stateless').hidden = false;
      renderStatelessTicket();
    });
})();
