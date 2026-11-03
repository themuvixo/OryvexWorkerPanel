/* OryvexWorkerPanel: Display options (theme, accent, density, text size, motion, small behaviours).
   Stored in localStorage only; nothing is sent to the Worker. Loaded right after app.js. */
(function () {
  'use strict';

  var KEY = 'oryvex.display';
  var html = document.documentElement;
  var DEFAULTS = {
    theme: 'dark',          // dark | light | system
    accent: 'signal',       // signal | blue | violet | emerald | amber | rose
    density: 'comfortable', // comfortable | compact
    text: 'default',        // default | large
    motion: 'full',         // full | reduced
    font: 'apple',          // apple (SF Pro system stack) | google (Google Sans, online) | inter (bundled, offline)
    corners: 'round',       // round | soft | square
    ticker: true,
    blurOnLoad: false,
    confirmLogout: false
  };

  function load() {
    var out = {};
    for (var k in DEFAULTS) out[k] = DEFAULTS[k];
    try {
      var raw = JSON.parse(localStorage.getItem(KEY) || '{}');
      for (var key in raw) if (Object.prototype.hasOwnProperty.call(DEFAULTS, key)) out[key] = raw[key];
      // first run: inherit the theme the panel already remembered
      if (!raw.theme) {
        var legacy = localStorage.getItem('oryvex.theme');
        if (legacy === 'light' || legacy === 'dark') out.theme = legacy;
      }
    } catch (e) { console.warn?.('[prefs] load error:', e); }
    return out;
  }
  function save() {
    try { localStorage.setItem(KEY, JSON.stringify(prefs)); } catch (e) { console.warn?.('[prefs] save error:', e); }
  }

  var prefs = load();
  var mq = window.matchMedia ? window.matchMedia('(prefers-color-scheme: light)') : null;
  var applyingTheme = false;

  function resolvedTheme() {
    if (prefs.theme === 'system') return mq && mq.matches ? 'light' : 'dark';
    return prefs.theme === 'light' ? 'light' : 'dark';
  }

  // Theme is owned by the panel script; drive it through its own buttons so both stay in sync.
  function applyTheme() {
    var want = resolvedTheme();
    if (html.getAttribute('data-theme') === want) return;
    var btn = document.querySelector('.t-pick[data-th="' + want + '"]');
    applyingTheme = true;
    if (btn) btn.click();
    else html.setAttribute('data-theme', want);
    applyingTheme = false;
  }

  // Google Sans is fetched from Google Fonts only when the admin picks it; the other
  // choices never leave the page (SF Pro is the device's own font, Inter is bundled).
  var GOOGLE_FONT_URLS = [
    'https://fonts.googleapis.com/css2?family=Google+Sans:wght@400;500;600;700&display=swap',
    'https://fonts.googleapis.com/css2?family=Google+Sans+Flex:wght@400;500;600;700&display=swap',
    'https://fonts.googleapis.com/css2?family=Google+Sans+Code:wght@400;500;600&display=swap'
  ];
  function ensureGoogleFonts() {
    if (document.getElementById('ox-gf-0')) return;
    GOOGLE_FONT_URLS.forEach(function (href, i) {
      var l = document.createElement('link');
      l.id = 'ox-gf-' + i;
      l.rel = 'stylesheet';
      l.href = href;
      l.crossOrigin = 'anonymous';
      document.head.appendChild(l);
    });
  }

  function apply() {
    if (['apple', 'google', 'inter'].indexOf(prefs.font) < 0) prefs.font = 'apple';
    if (['round', 'soft', 'square'].indexOf(prefs.corners) < 0) prefs.corners = 'round';
    html.setAttribute('data-font', prefs.font);
    html.setAttribute('data-corners', prefs.corners);
    if (prefs.font === 'google') ensureGoogleFonts();
    html.setAttribute('data-accent', prefs.accent);
    html.setAttribute('data-density', prefs.density);
    html.setAttribute('data-text', prefs.text);
    html.setAttribute('data-motion', prefs.motion);
    html.setAttribute('data-ticker', prefs.ticker ? 'on' : 'off');
    applyTheme();
    syncControls();
    // canvas charts read CSS variables on their next frame; nudge a resize so they repaint now
    try { window.dispatchEvent(new Event('resize')); } catch (e) { console.warn?.('[prefs] resize dispatch error:', e); }
  }

  function syncControls() {
    document.querySelectorAll('#display-modal [data-pref]').forEach(function (group) {
      var name = group.getAttribute('data-pref');
      group.querySelectorAll('[data-val]').forEach(function (b) {
        var on = b.getAttribute('data-val') === String(prefs[name]);
        b.classList.toggle('active', on);
        b.setAttribute('aria-pressed', on ? 'true' : 'false');
      });
    });
    document.querySelectorAll('#display-modal [data-pref-check]').forEach(function (c) {
      c.checked = Boolean(prefs[c.getAttribute('data-pref-check')]);
    });
  }

  // ---- wire controls
  document.querySelectorAll('#display-modal [data-pref]').forEach(function (group) {
    var name = group.getAttribute('data-pref');
    group.addEventListener('click', function (ev) {
      var b = ev.target.closest('[data-val]');
      if (!b) return;
      prefs[name] = b.getAttribute('data-val');
      save();
      apply();
    });
  });
  document.querySelectorAll('#display-modal [data-pref-check]').forEach(function (c) {
    c.addEventListener('change', function () {
      prefs[c.getAttribute('data-pref-check')] = c.checked;
      save();
      apply();
    });
  });

  // manual sun/moon clicks in the top bar become an explicit theme choice
  document.querySelectorAll('.t-pick').forEach(function (b) {
    b.addEventListener('click', function () {
      if (applyingTheme) return;
      prefs.theme = b.getAttribute('data-th') === 'light' ? 'light' : 'dark';
      save();
      syncControls();
    });
  });
  if (mq && mq.addEventListener) mq.addEventListener('change', function () { if (prefs.theme === 'system') applyTheme(); });

  // ---- modal open / close
  var modal = document.getElementById('display-modal');
  var opener = document.getElementById('btn-display');
  var lastFocus = null;
  function open() {
    if (!modal) return;
    lastFocus = document.activeElement;
    syncControls();
    modal.hidden = false;
    var first = modal.querySelector('.seg-btn.active') || modal.querySelector('button');
    if (first) first.focus();
  }
  function close() {
    if (!modal) return;
    modal.hidden = true;
    if (lastFocus && lastFocus.focus) lastFocus.focus();
  }
  if (opener) opener.addEventListener('click', open);
  var done = document.getElementById('dp-close');
  if (done) done.addEventListener('click', close);
  var reset = document.getElementById('dp-reset');
  if (reset) reset.addEventListener('click', function () {
    for (var k in DEFAULTS) prefs[k] = DEFAULTS[k];
    save();
    apply();
  });
  if (modal) {
    modal.addEventListener('click', function (ev) { if (ev.target === modal) close(); });
    document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape' && !modal.hidden) close(); });
  }

  // ---- behaviours
  // Blur IP on load: the panel renders the visitor strip asynchronously, so wait for a real value.
  if (prefs.blurOnLoad) {
    var tries = 0;
    var t = setInterval(function () {
      tries++;
      var ip = document.getElementById('visitor-ip');
      var btn = document.getElementById('btn-ip-blur');
      if (ip && btn && ip.textContent.trim() && ip.textContent.trim() !== '—') {
        if (!ip.classList.contains('is-blurred')) btn.click();
        clearInterval(t);
      } else if (tries > 40) {
        clearInterval(t);
      }
    }, 150);
  }

  // Confirm before signing out (capture phase runs before the panel's own handler)
  var logout = document.getElementById('btn-logout');
  if (logout) logout.addEventListener('click', function (ev) {
    if (prefs.confirmLogout && !window.confirm('Sign out of OryvexWorkerPanel?')) {
      ev.preventDefault();
      ev.stopImmediatePropagation();
    }
  }, true);

  apply();
})();
