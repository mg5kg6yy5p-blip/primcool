// PrimeCool shared frontend helpers — used by all six SPAs (admin.html,
// staff_home.html, tech.html, portal.html, staff_portal.html, portal_dashboard.html).
// Loaded via <script src="/static/pc_shared.js?v=..."></script> at the top of each SPA.
// Exports a global `PC` namespace; do not pollute window with bare identifiers.
//
// Served from the /static mount (main.py: app.mount("/static", StaticFiles(directory="static"))).
// This file at static/pc_shared.js is the single canonical copy — there is no
// icons/pc_shared.js duplicate. Bump the ?v= cache-buster in all six SPAs when editing.

(function () {
  if (typeof window === 'undefined') return;
  const PC = window.PC = window.PC || {};

  // ── In-app user settings (per-user, server-backed) ────────
  // Defaults mirror the server (_SETTINGS_DEFAULTS in main.py). Every key
  // here drives a real, wired-up effect — no decorative toggles. The server
  // is the source of truth; localStorage is only a cache so density/time
  // format apply instantly on the next load without a flash.
  PC._settings = {
    time_format: '24h', date_format: 'dmy', density: 'comfortable',
    theme: 'light', font_scale: 'normal', reduce_motion: false,
    start_of_week: 'monday',
  };
  PC.getSetting = function (k) { return PC._settings ? PC._settings[k] : undefined; };
  PC.applySettings = function (s) {
    if (!s || typeof s !== 'object') return PC._settings;
    PC._settings = Object.assign({}, PC._settings, s);
    try {
      // Theme goes on <html> (documentElement), which exists even while
      // pc_shared.js runs in <head> — so dark mode applies with zero flash
      // before <body> is parsed. CSS targets html[data-pc-theme="dark"].
      const root = document.documentElement;
      if (root) root.setAttribute('data-pc-theme', PC._settings.theme === 'dark' ? 'dark' : 'light');
      const b = document.body;
      if (b) {
        if (PC._settings.density)    b.setAttribute('data-pc-density', PC._settings.density);
        if (PC._settings.font_scale) b.setAttribute('data-pc-fontscale', PC._settings.font_scale);
        b.setAttribute('data-pc-motion', PC._settings.reduce_motion ? 'reduce' : 'full');
      }
    } catch (_) {}
    try { localStorage.setItem('pc_settings', JSON.stringify(PC._settings)); } catch (_) {}
    // Let pages react (re-render clocks/lists that depend on time/date format).
    try { window.dispatchEvent(new CustomEvent('pc:settings', { detail: PC._settings })); } catch (_) {}
    return PC._settings;
  };
  // Apply any cached settings immediately to avoid a flash on load.
  // Re-apply on DOMContentLoaded too: pc_shared.js usually loads in <head>
  // before <body> exists, so the first applySettings can't set body
  // attributes (theme/density/font/motion). This guarantees every page that
  // includes this module honors the cached prefs — including admin.html,
  // which doesn't run its own loadSettings.
  function _applyCached() {
    try {
      const _cached = JSON.parse(localStorage.getItem('pc_settings') || 'null');
      if (_cached) PC.applySettings(_cached);
    } catch (_) {}
  }
  _applyCached();
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', _applyCached, { once: true });
  }
  // Fetch + apply the authoritative settings for the current session.
  // url = the GET endpoint (/api/staff/me/settings | /api/portal/me/settings).
  PC.loadSettings = async function (url) {
    try {
      const r = await fetch(url, { credentials: 'same-origin' });
      if (!r.ok) return PC._settings;
      const j = await r.json();
      if (j && j.settings) PC.applySettings(j.settings);
    } catch (_) {}
    return PC._settings;
  };
  // Persist a partial update (PUT), then apply the canonical server result.
  PC.saveSettings = async function (url, patch) {
    const r = await fetch(url, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(patch || {}),
    });
    if (!r.ok) throw new Error('Could not save settings');
    const j = await r.json();
    if (j && j.settings) PC.applySettings(j.settings);
    return PC._settings;
  };
  // Format an (hours, minutes) pair honoring the time_format preference.
  // Exposed so clocks/tick functions can share one source of truth.
  PC.fmtClock = function (h, m) {
    const mm = String(m).padStart(2, '0');
    if ((PC._settings && PC._settings.time_format) === '12h') {
      const ap = h < 12 ? 'AM' : 'PM';
      const hr = h % 12 || 12;
      return `${hr}:${mm} ${ap}`;
    }
    return `${String(h).padStart(2, '0')}:${mm}`;
  };

  // ── Date / Time formatters (system-wide standard) ─────────
  // House style for every surface that renders a date or time:
  //   Date     → 27/May/2026
  //   Time     → 14:30 (24-hour)
  //   DateTime → 27/May/2026 14:30
  //
  // All accept either an ISO string (the storage format) or a Date.
  // Falsy / unparsable input renders as the empty string so callers
  // can drop the result straight into innerHTML without guards.
  const _MONTH_SHORT = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  function _toDate(v) {
    if (!v) return null;
    if (v instanceof Date) return isNaN(v) ? null : v;
    // Normalize bare YYYY-MM-DD to local midnight so timezones don't slip
    // a date back a day on the client.
    const s = String(v);
    if (/^\d{4}-\d{2}-\d{2}$/.test(s)) {
      const d = new Date(s + 'T00:00:00');
      return isNaN(d) ? null : d;
    }
    const d = new Date(s);
    return isNaN(d) ? null : d;
  }
  PC.fmtDate = function (v) {
    const d = _toDate(v); if (!d) return '';
    const dd = String(d.getDate()).padStart(2, '0');
    const mo = _MONTH_SHORT[d.getMonth()];
    const yr = d.getFullYear();
    const fmt = (PC._settings && PC._settings.date_format) || 'dmy';
    if (fmt === 'iso') return `${yr}-${String(d.getMonth() + 1).padStart(2, '0')}-${dd}`;
    if (fmt === 'mdy') return `${mo}/${dd}/${yr}`;
    return `${dd}/${mo}/${yr}`;  // dmy (house default)
  };
  PC.fmtTime = function (v) {
    const d = _toDate(v); if (!d) return '';
    return PC.fmtClock(d.getHours(), d.getMinutes());
  };
  PC.fmtDateTime = function (v) {
    const d = _toDate(v); if (!d) return '';
    return PC.fmtDate(d) + ' ' + PC.fmtTime(d);
  };
  // Convenience: compact format that omits the year when the date is in
  // the current year (used in dense rows like audit logs).
  PC.fmtDateTimeCompact = function (v) {
    const d = _toDate(v); if (!d) return '';
    const now = new Date();
    const yr = d.getFullYear() === now.getFullYear()
      ? '' : '/' + d.getFullYear();
    const dd = String(d.getDate()).padStart(2, '0');
    return `${dd}/${_MONTH_SHORT[d.getMonth()]}${yr} ${PC.fmtTime(d)}`;
  };

  // ── Accessibility prefs (font scale + reduce motion) ──────
  // Real, global effects so the toggles aren't decorative. Font scale uses
  // `zoom` because the SPAs size everything in px (rem scaling wouldn't
  // cascade); reduce_motion neutralizes animations/transitions everywhere.
  if (!document.getElementById('pc-a11y-style')) {
    const a = document.createElement('style');
    a.id = 'pc-a11y-style';
    a.textContent =
      'body[data-pc-fontscale="large"]{zoom:1.12;}' +
      'body[data-pc-motion="reduce"] *,body[data-pc-motion="reduce"] *::before,body[data-pc-motion="reduce"] *::after{' +
      'animation-duration:0.001ms !important;animation-iteration-count:1 !important;' +
      'transition-duration:0.001ms !important;scroll-behavior:auto !important;}';
    document.head && document.head.appendChild(a);
  }

  // ── Toast ─────────────────────────────────────────────────
  // PC.toast(message, kind?) — kind: 'info' (default) | 'success' | 'warning' | 'error'
  // Brand-aligned pill: PrimeCool navy by default, lime for success,
  // amber for warning, brand red for error. Slides up + fades in.
  // Auto-injects a stylesheet once.
  if (!document.getElementById('pc-toast-style')) {
    const s = document.createElement('style');
    s.id = 'pc-toast-style';
    s.textContent =
      '#pc-toast-host{position:fixed;left:50%;bottom:24px;transform:translateX(-50%);z-index:99999;display:flex;flex-direction:column;align-items:center;gap:8px;pointer-events:none;}' +
      '@media (min-width:900px){#pc-toast-host{left:auto;right:24px;bottom:24px;transform:none;align-items:flex-end;}}' +
      '.pc-toast{display:inline-flex;align-items:center;gap:10px;padding:11px 18px;border-radius:999px;font:600 13px/1.3 "IBM Plex Sans","Barlow",system-ui,sans-serif;box-shadow:0 8px 24px rgba(15,42,74,0.4);max-width:min(420px,calc(100vw - 48px));pointer-events:auto;opacity:0;transform:translateY(8px);transition:opacity 220ms cubic-bezier(0.16,1,0.3,1),transform 220ms cubic-bezier(0.16,1,0.3,1);}' +
      '.pc-toast.show{opacity:1;transform:translateY(0);}' +
      '.pc-toast .ico{display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;border-radius:50%;font-size:11px;font-weight:800;flex-shrink:0;}';
    document.head && document.head.appendChild(s);
  }
  // ── Density (compact / comfortable) — shared across surfaces ──────────
  // BUG FIX: previously crashed at boot when pc_shared.js loaded
  // inside <head> before <body> existed. document.body was null,
  // .dataset blew up, and the unhandled exception in this top-level
  // IIFE silently halted later admin.html bootstrap (the user saw
  // blank panels on 5S / Delegations / Performance KPI because
  // dependent JS never ran after the throw).
  PC.applyDensity = function (mode) {
    const b = document.body;
    if (!b) return;                              // not parsed yet — see deferred apply below
    b.dataset.pcDensity = mode === 'compact' ? 'compact' : 'comfortable';
  };
  PC.toggleDensity = function () {
    if (!document.body) return 'comfortable';
    const cur = (document.body.dataset.pcDensity || 'comfortable');
    const next = cur === 'compact' ? 'comfortable' : 'compact';
    try { localStorage.setItem('pc_density', next); } catch (_) {}
    PC.applyDensity(next);
    if (PC.toast) PC.toast('Density: ' + next, 'success');
    return next;
  };
  function _pcBootDensity() {
    let mode = 'comfortable';
    try { mode = localStorage.getItem('pc_density') || 'comfortable'; } catch (_) {}
    PC.applyDensity(mode);
  }
  if (document.body) {
    _pcBootDensity();
  } else if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', _pcBootDensity);
  } else {
    // Interactive / complete but no body yet? Belt-and-braces.
    setTimeout(_pcBootDensity, 0);
  }

  // ── Skeleton loader auto-swap ─────────────────────────────────────────
  // Any element with class="empty" whose text is literally "Loading…"
  // gets replaced with three shimmer bars. Idempotent + debounced via
  // MutationObserver, so newly-rendered tables get the polish too.
  // Requires the .pc-skeleton-line CSS to be present in the host page
  // (already shipped on admin / tech / portal / staff).
  PC.swapLoadingSkeletons = function (root) {
    root = root || document;
    const els = root.querySelectorAll('td.empty, .empty');
    for (let i = 0; i < els.length; i++) {
      const el = els[i];
      if (el.dataset.pcSkeleton === '1') continue;
      const t = (el.textContent || '').trim().toLowerCase();
      if (t !== 'loading…' && t !== 'loading...') continue;
      el.dataset.pcSkeleton = '1';
      el.innerHTML =
        '<div class="pc-skeleton-line" style="width:90%;"></div>' +
        '<div class="pc-skeleton-line" style="width:70%;"></div>' +
        '<div class="pc-skeleton-line" style="width:85%;"></div>';
    }
  };
  let _pcSkelDebounce = null;
  function _pcSkelScan() {
    if (_pcSkelDebounce) return;
    _pcSkelDebounce = setTimeout(function () {
      _pcSkelDebounce = null;
      try { PC.swapLoadingSkeletons(document); } catch (_) {}
    }, 80);
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', _pcSkelScan);
  } else {
    setTimeout(_pcSkelScan, 0);
  }
  setTimeout(function () {
    const root = document.getElementById('app') || document.body;
    if (root && window.MutationObserver) {
      new MutationObserver(_pcSkelScan).observe(root, { childList: true, subtree: true });
    }
  }, 500);

  PC.toast = function (message, kind) {
    kind = kind || 'info';
    let host = document.getElementById('pc-toast-host');
    if (!host) { host = document.createElement('div'); host.id = 'pc-toast-host'; document.body.appendChild(host); }
    const styles = {
      info:    { bg: '#0F2A4A', fg: '#fff',     ico: 'ℹ', icoBg: 'rgba(125,211,232,0.25)', icoFg: '#7DD3E8' },
      success: { bg: '#0F2A4A', fg: '#fff',     ico: '✓', icoBg: '#22A08A',                icoFg: '#0F2A4A' },
      warning: { bg: '#FFF1D6', fg: '#9A6700',  ico: '⚠', icoBg: '#FFD27A',                icoFg: '#5B3B00' },
      error:   { bg: '#FFE2E2', fg: '#B42318',  ico: '×', icoBg: '#B42318',                icoFg: '#fff'    },
    };
    const c = styles[kind] || styles.info;
    const el = document.createElement('div');
    el.className = 'pc-toast';
    el.setAttribute('role', 'status');
    el.setAttribute('aria-live', 'polite');
    el.style.background = c.bg;
    el.style.color = c.fg;
    el.innerHTML = '<span class="ico" style="background:' + c.icoBg + ';color:' + c.icoFg + ';">' + c.ico + '</span><span></span>';
    el.lastChild.textContent = String(message == null ? '' : message);
    host.appendChild(el);
    requestAnimationFrame(function () { el.classList.add('show'); });
    setTimeout(function () { el.classList.remove('show'); }, 3200);
    setTimeout(function () { if (el.parentNode) el.parentNode.removeChild(el); }, 3700);
  };

  // ── apiFetch ──────────────────────────────────────────────
  // Standard fetch wrapper: sends cookies, parses JSON, surfaces 401/403/409 with toast,
  // returns the parsed body OR throws PCApiError with .status and .body.
  class PCApiError extends Error {
    constructor(status, body, message) {
      super(message || (body && body.detail) || ('HTTP ' + status));
      this.status = status;
      this.body = body;
    }
  }
  PC.ApiError = PCApiError;

  PC.apiFetch = async function (url, opts) {
    opts = opts || {};
    opts.credentials = 'include';
    opts.headers = Object.assign({}, opts.headers || {});
    if (opts.body && typeof opts.body === 'object' && !(opts.body instanceof FormData) && !(opts.body instanceof Blob)) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(opts.body);
    }
    let res;
    try {
      res = await fetch(url, opts);
    } catch (e) {
      PC.toast('Network error — check your connection.', 'error');
      throw e;
    }
    let parsed = null;
    const ctype = res.headers.get('content-type') || '';
    if (ctype.includes('application/json')) {
      try { parsed = await res.json(); } catch (_) {}
    } else {
      try { parsed = await res.text(); } catch (_) {}
    }
    if (!res.ok) {
      if (res.status === 401) PC.toast('Session expired. Please log in again.', 'warning');
      else if (res.status === 403) PC.toast('You do not have permission to do that.', 'warning');
      else if (res.status === 409) PC.toast('This record was updated by another admin. Refresh to see latest changes.', 'warning');
      else if (res.status >= 500) PC.toast('Server error. Please try again.', 'error');
      throw new PCApiError(res.status, parsed);
    }
    return parsed;
  };

  // ── Currency ──────────────────────────────────────────────
  PC.fmtJMD = function (amount) {
    if (amount === null || amount === undefined || amount === '') return '—';
    const n = Number(amount);
    if (!isFinite(n)) return '—';
    return 'J$' + Math.round(n).toLocaleString('en-JM');
  };
  PC.fmtCurrency = function (amount, code) {
    if (amount === null || amount === undefined || amount === '') return '—';
    const n = Number(amount);
    if (!isFinite(n)) return '—';
    const prefix = code === 'USD' ? 'US$' : code === 'GBP' ? '£' : 'J$';
    const dp = code === 'JMD' ? 0 : 2;
    return prefix + n.toLocaleString('en-US', { minimumFractionDigits: dp, maximumFractionDigits: dp });
  };

  // ── Payslip print (single canonical renderer) ─────────────
  // The AstraZeneca/Workday-style, Jamaica-statutory payslip layout. This is
  // the ONE template every print path uses (admin apPrint, tech /home, the new
  // /profile Pay tab). Pass an enriched payslip object (as returned by
  // /api/{admin,tech}/me/payslips/{id} → _enrich_payslip_for_print) or an
  // array of them. The server supplies .ytd, .employer_contribs, .company,
  // .bank, .tax_year, .employee_ids; this renderer degrades gracefully when
  // any are missing.
  function _psMoney(n, cur) {
    const v = Number(n || 0);
    const sym = cur === 'JMD' ? 'J$' : (cur === 'USD' ? '$' : (cur || 'JMD') + ' ');
    return sym + v.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  }
  function _psEsc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c];
    });
  }

  // Inner sheet markup for ONE payslip (no <html>/<style>/print-bar wrapper).
  PC.payslipSheetHTML = function (p) {
    if (!p) return '';
    const cur = p.currency || 'JMD';
    const ytd = p.ytd || {};
    const er = p.employer_contribs || null;
    const company = p.company || { name: 'PrimeCool Services Limited', address: 'Kingston, Jamaica', trn: 'TODO', nis_er: 'TODO' };
    const empIds = p.employee_ids || { trn: 'On file', nis: 'On file' };
    const bank = p.bank || { bank_name: 'On file', account_name: p.subject_name || '', account_masked: '****' };
    const taxYr = p.tax_year || {};
    const n = function (v) { return _psMoney(v, cur); };
    const eh = _psEsc;
    const today = new Date().toISOString().slice(0, 10);
    const taxesCur = (Number(p.paye_tax) || 0) + (Number(p.nis) || 0) + (Number(p.nht) || 0) + (Number(p.education_tax) || 0);
    const taxesYtd = (Number(ytd.paye_tax) || 0) + (Number(ytd.nis) || 0) + (Number(ytd.nht) || 0) + (Number(ytd.education_tax) || 0);
    const preCur = 0, preYtd = 0;
    const postCur = Number(p.other_deductions) || 0;
    const postYtd = Number(ytd.other_deductions) || 0;
    return `
      <div class="sheet">
        <div class="hdr">
          <div>
            <div class="co-name">Prime<em>Cool</em> Services Ltd.</div>
            <div class="co-meta">
              ${eh(company.address)}<br>
              TRN: ${eh(company.trn)} &nbsp;·&nbsp; NIS Employer #: ${eh(company.nis_er)}
            </div>
          </div>
          <div style="text-align:right;">
            <div class="ps-label">PAYSLIP</div>
            <div class="meta-row" style="margin-top:10px;">
              <div class="l">Pay Period:</div><div class="v">${eh(p.period_start || '')} – ${eh(p.period_end || '')}</div>
              <div class="l">Pay Date:</div>  <div class="v">${eh(p.generated_at ? String(p.generated_at).slice(0, 10) : today)}</div>
              <div class="l">Tax Year:</div>  <div class="v">${eh(taxYr.label || '')}</div>
              <div class="l">Payslip No:</div><div class="v">PCL/PS/${eh(String(p.id).padStart(6, '0'))}</div>
            </div>
          </div>
        </div>

        <table class="tbl" style="margin-top:0;">
          <thead><tr>
            <th></th>
            <th style="text-align:right;">GROSS PAY</th>
            <th style="text-align:right;">PRE-TAX DEDUCTIONS</th>
            <th style="text-align:right;">STATUTORY TAXES</th>
            <th style="text-align:right;">POST-TAX DEDUCTIONS</th>
            <th style="text-align:right;background:#0B2545;color:#fff;">NET PAY</th>
          </tr></thead>
          <tbody>
            <tr>
              <td style="font-weight:700;">Current</td>
              <td class="num">${n(p.gross_pay)}</td>
              <td class="num">${n(preCur)}</td>
              <td class="num">${n(taxesCur)}</td>
              <td class="num">${n(postCur)}</td>
              <td class="num" style="background:#22A08A;color:#fff;font-weight:700;">${n(p.net_pay)}</td>
            </tr>
            <tr>
              <td style="font-weight:700;">YTD</td>
              <td class="num">${n(ytd.gross_pay)}</td>
              <td class="num">${n(preYtd)}</td>
              <td class="num">${n(taxesYtd)}</td>
              <td class="num">${n(postYtd)}</td>
              <td class="num" style="background:#0B2545;color:#fff;font-weight:700;">${n(ytd.net_pay)}</td>
            </tr>
          </tbody>
        </table>

        <div class="row">
          <div class="col box">
            <div class="box-h">EMPLOYEE DETAILS</div>
            <div class="box-body">
              <div class="l">Employee ID:</div><div class="v">${eh(p.subject_prid || '')}</div>
              <div class="l">Name:</div>       <div class="v">${eh(p.subject_name || '')}</div>
              <div class="l">Currency:</div>   <div class="v">${eh(cur)}</div>
            </div>
          </div>
          <div class="col box">
            <div class="box-h">JAMAICA TAX INFORMATION</div>
            <div class="box-body">
              <div class="l">TRN:</div>           <div class="v">${eh(empIds.trn || 'On file')}</div>
              <div class="l">NIS #:</div>         <div class="v">${eh(empIds.nis || 'On file')}</div>
              <div class="l">Tax Code:</div>     <div class="v">Threshold applied</div>
              <div class="l">Tax Year:</div>     <div class="v">${eh(taxYr.label || '')}</div>
              <div class="l">Add'l Withholding:</div><div class="v">—</div>
            </div>
          </div>
        </div>

        <table class="tbl">
          <thead><tr>
            <th colspan="5" style="background:#dde6f0;color:#0B2545;font-size:11px;">EARNINGS</th>
          </tr><tr>
            <th>DESCRIPTION</th><th>RATE</th><th>HOURS / UNITS</th>
            <th style="text-align:right;">CURRENT (J$)</th>
            <th style="text-align:right;">YTD (J$)</th>
          </tr></thead>
          <tbody>
            <tr><td>Regular Pay</td><td class="num">${n(p.hourly_rate)}</td><td class="num">${Number(p.hours_regular || 0).toFixed(2)}</td><td class="num">${n((Number(p.hours_regular) || 0) * (Number(p.hourly_rate) || 0))}</td><td class="num">${n(ytd.regular_pay || ((Number(ytd.hours_regular) || 0) * (Number(p.hourly_rate) || 0)))}</td></tr>
            <tr><td>Overtime</td><td class="num">${n(p.overtime_rate)}</td><td class="num">${Number(p.hours_overtime || 0).toFixed(2)}</td><td class="num">${n((Number(p.hours_overtime) || 0) * (Number(p.overtime_rate) || 0))}</td><td class="num">${n(ytd.overtime_pay || ((Number(ytd.hours_overtime) || 0) * (Number(p.overtime_rate) || 0)))}</td></tr>
            <tr><td>Fixed Salary</td><td></td><td></td><td class="num">${n(p.fixed_salary)}</td><td class="num">${n(ytd.fixed_salary)}</td></tr>
            <tr><td>Bonus</td><td></td><td></td><td class="num">${n(p.bonus)}</td><td class="num">${n(ytd.bonus)}</td></tr>
            <tr class="tot"><td colspan="3">TOTAL EARNINGS</td><td class="num">${n(p.gross_pay)}</td><td class="num">${n(ytd.gross_pay)}</td></tr>
          </tbody>
        </table>

        <div class="row">
          <table class="tbl col" style="margin-right:7px;">
            <thead><tr>
              <th colspan="3" style="background:#dde6f0;color:#0B2545;font-size:11px;">STATUTORY TAXES (EMPLOYEE)</th>
            </tr><tr>
              <th>DESCRIPTION</th><th style="text-align:right;">CURRENT (J$)</th><th style="text-align:right;">YTD (J$)</th>
            </tr></thead>
            <tbody>
              <tr><td>PAYE Income Tax</td><td class="num">${n(p.paye_tax)}</td><td class="num">${n(ytd.paye_tax)}</td></tr>
              <tr><td>NIS (Employee 3%)</td><td class="num">${n(p.nis)}</td><td class="num">${n(ytd.nis)}</td></tr>
              <tr><td>NHT (Employee 2%)</td><td class="num">${n(p.nht)}</td><td class="num">${n(ytd.nht)}</td></tr>
              <tr><td>Education Tax (2.25%)</td><td class="num">${n(p.education_tax)}</td><td class="num">${n(ytd.education_tax)}</td></tr>
              <tr class="tot"><td>TOTAL TAXES</td><td class="num">${n(taxesCur)}</td><td class="num">${n(taxesYtd)}</td></tr>
            </tbody>
          </table>
          <table class="tbl col" style="margin-left:7px;">
            <thead><tr>
              <th colspan="3" style="background:#dde6f0;color:#0B2545;font-size:11px;">OTHER DEDUCTIONS (POST-TAX)</th>
            </tr><tr>
              <th>DESCRIPTION</th><th style="text-align:right;">CURRENT (J$)</th><th style="text-align:right;">YTD (J$)</th>
            </tr></thead>
            <tbody>
              <tr><td>Other Deductions</td><td class="num">${n(p.other_deductions)}</td><td class="num">${n(ytd.other_deductions)}</td></tr>
              <tr class="tot"><td>TOTAL POST-TAX</td><td class="num">${n(postCur)}</td><td class="num">${n(postYtd)}</td></tr>
            </tbody>
          </table>
        </div>

        ${er ? `
        <table class="tbl">
          <thead><tr>
            <th colspan="3" style="background:#dde6f0;color:#0B2545;font-size:11px;">EMPLOYER CONTRIBUTIONS (NOT DEDUCTED FROM YOU)</th>
          </tr><tr>
            <th>DESCRIPTION</th><th style="text-align:right;">CURRENT (J$)</th><th style="text-align:right;">RATE</th>
          </tr></thead>
          <tbody>
            <tr><td>NIS — Employer</td><td class="num">${n(er.nis_er)}</td><td class="num">3.0%</td></tr>
            <tr><td>NHT — Employer</td><td class="num">${n(er.nht_er)}</td><td class="num">3.0%</td></tr>
            <tr><td>Education Tax — Employer</td><td class="num">${n(er.edtax_er)}</td><td class="num">3.5%</td></tr>
            <tr><td>HEART Trust / NTA</td><td class="num">${n(er.heart)}</td><td class="num">3.0%${er.heart === 0 ? ' (under threshold)' : ''}</td></tr>
            <tr class="tot"><td>TOTAL EMPLOYER COST</td><td class="num">${n((er.nis_er || 0) + (er.nht_er || 0) + (er.edtax_er || 0) + (er.heart || 0))}</td><td></td></tr>
          </tbody>
        </table>` : ''}

        <div class="row" style="margin-top:14px;">
          <div class="col" style="display:flex;flex-direction:column;gap:10px;">
            <div class="net-pay-box">
              <div class="l">NET PAY (Current Period)</div>
              <div class="v">${n(p.net_pay)}</div>
            </div>
          </div>
        </div>

        <table class="tbl">
          <thead><tr>
            <th colspan="5" style="background:#dde6f0;color:#0B2545;font-size:11px;">PAYMENT INFORMATION</th>
          </tr><tr>
            <th>BANK</th><th>ACCOUNT NAME</th><th>ACCOUNT NUMBER</th>
            <th style="text-align:right;">AMOUNT</th><th>CURRENCY</th>
          </tr></thead>
          <tbody>
            <tr>
              <td>${eh(bank.bank_name || 'On file')}</td>
              <td>${eh(bank.account_name || p.subject_name || '')}</td>
              <td>${eh(bank.account_masked || '****')}</td>
              <td class="num">${n(p.net_pay)}</td>
              <td>${eh(cur)}</td>
            </tr>
          </tbody>
        </table>

        ${p.notes ? `<div class="box"><div class="box-h">NOTES</div><div style="padding:8px 10px;font-size:11px;line-height:1.5;">${eh(p.notes).replace(/\n/g, '<br>')}</div></div>` : ''}

        <div class="footer-note">
          <strong>PAY ADVICE</strong> — This payslip is computer-generated and does not require a signature.
          Generated on ${eh(today)}.<br>
          <strong>Jamaica statutory compliance:</strong> calculations apply current PAYE, NIS (employee 3% / employer 3%, capped at insurable ceiling),
          NHT (employee 2% / employer 3%), Education Tax (employee 2.25% / employer 3.5%), and HEART Trust (employer 3% above monthly threshold) rates.
          Rates change with the JM National Budget — confirm with PrimeCool payroll if disputed.
        </div>
      </div>`;
  };

  // Full standalone HTML document (styles + print-bar + one or more sheets).
  // `slips` may be a single payslip object or an array of them.
  PC.payslipPrintHTML = function (slips, opts) {
    opts = opts || {};
    const saveMode = !!opts.saveMode;
    const list = Array.isArray(slips) ? slips.filter(Boolean) : (slips ? [slips] : []);
    const first = list[0] || {};
    const title = list.length === 1
      ? `PrimeCool Payslip — ${_psEsc(first.subject_name || '')} — ${_psEsc(first.period_label || '')}`
      : `PrimeCool Payslips (${list.length})`;
    const sheets = list.map(function (p) { return PC.payslipSheetHTML(p); }).join('\n');
    return `<!doctype html><html><head><meta charset="utf-8">
      <title>${title}</title>
      <style>
        @page{size:A4;margin:14mm;}
        *{box-sizing:border-box;}
        body{font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;color:#1a2533;margin:0;font-size:11px;line-height:1.35;background:#fff;}
        .sheet{max-width:780px;margin:0 auto;padding:18px 22px;page-break-after:always;}
        .sheet:last-child{page-break-after:auto;}
        .row{display:flex;gap:14px;}
        .col{flex:1;}
        .hdr{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:3px solid #0B2545;padding-bottom:12px;margin-bottom:14px;}
        .co-name{font-size:22px;font-weight:800;color:#0B2545;letter-spacing:.3px;}
        .co-name em{color:#22A08A;font-style:normal;}
        .co-meta{font-size:10.5px;color:#555;margin-top:4px;line-height:1.5;}
        .ps-label{background:#22A08A;color:#fff;padding:6px 14px;border-radius:4px;font-weight:800;letter-spacing:1.2px;font-size:12px;}
        .meta-row{display:grid;grid-template-columns:110px 1fr;row-gap:3px;column-gap:6px;font-size:10.5px;margin-top:8px;}
        .meta-row .l{color:#555;} .meta-row .v{font-weight:600;color:#0B2545;}
        .box{border:1px solid #cdd5e0;border-radius:4px;margin-top:12px;overflow:hidden;}
        .box-h{background:#eaf0f7;color:#0B2545;font-weight:700;font-size:11px;padding:5px 10px;letter-spacing:.5px;}
        .box-body{padding:8px 10px;display:grid;grid-template-columns:140px 1fr;row-gap:3px;column-gap:8px;font-size:10.5px;}
        .box-body .l{color:#555;} .box-body .v{font-weight:600;color:#0B2545;}
        table.tbl{width:100%;border-collapse:collapse;font-size:10.5px;margin-top:12px;}
        table.tbl th{background:#eaf0f7;color:#0B2545;text-align:left;padding:6px 8px;font-weight:700;border:1px solid #cdd5e0;font-size:10px;letter-spacing:.3px;}
        table.tbl td{padding:4px 8px;border:1px solid #e0e6ee;}
        table.tbl td.num{text-align:right;font-variant-numeric:tabular-nums;}
        .tot{background:#f5f7fa;font-weight:700;color:#0B2545;}
        .net-pay-box{background:linear-gradient(135deg,#1B4F82,#0B2545);color:#fff;border-radius:12px;padding:16px 18px;text-align:center;box-shadow:0 2px 4px rgba(11,37,69,0.08),0 12px 28px -10px rgba(11,37,69,0.20);}
        .net-pay-box .l{font-size:11px;font-weight:700;letter-spacing:1.4px;opacity:.92;color:#22A08A;}
        .net-pay-box .v{font-size:26px;font-weight:700;margin-top:6px;letter-spacing:.2px;font-family:'IBM Plex Mono',ui-monospace,monospace;font-variant-numeric:tabular-nums;}
        .footer-note{margin-top:14px;background:#f5f7fa;border:1px solid #cdd5e0;border-radius:4px;padding:7px 10px;font-size:10px;color:#4a5566;}
        @media print{
          .no-print{display:none !important;}
          body,.net-pay-box,.tot,table.tbl th{-webkit-print-color-adjust:exact !important;print-color-adjust:exact !important;}
          .net-pay-box,.row,table.tbl{page-break-inside:avoid;}
        }
        .print-bar{position:fixed;top:8px;right:8px;display:flex;gap:6px;z-index:10;}
        .print-bar button{background:#0B2545;color:#fff;border:none;padding:7px 14px;border-radius:4px;cursor:pointer;font-weight:600;font-size:12px;}
        .print-bar button.alt{background:#6b7280;}
      </style></head><body>
      <div class="print-bar no-print">
        <button onclick="window.print()" title="${saveMode ? 'Pick &quot;Save as PDF&quot; as the destination in the print dialog' : 'Pick your printer in the print dialog'}">${saveMode ? '💾 Save as PDF' : '🖨 Print'}</button>
        <button class="alt" onclick="window.close()">Close</button>
      </div>
      ${saveMode ? `<div class="no-print" style="background:#E0F2F1;color:#1A7A6A;padding:8px 14px;border:1px solid #E0F2F1;border-radius:4px;font-size:12px;margin:8px auto;max-width:780px;">💡 In the print dialog that just opened, pick <strong>Save as PDF</strong> from the destination dropdown to save this payslip to disk.</div>` : ''}
      ${sheets}
      ${saveMode ? `<script>window.addEventListener('load',function(){setTimeout(function(){try{window.focus();window.print();}catch(e){}},200);});<\/script>` : ''}
      </body></html>`;
  };

  // Open a print window and write the canonical payslip document into it.
  // Returns the window handle (or null if pop-up blocked). When opts.saveMode
  // is set the document AUTO-PRINTS ITSELF on load (via a script embedded in the
  // written HTML) rather than the opener calling w.print(). This matters: the
  // popup is same-origin and shares a renderer process with the opener, and
  // window.print() blocks its caller's event loop until the dialog closes —
  // calling it from here would freeze the opener tab ("Pages Unresponsive").
  // Letting the popup print itself keeps the opener fully responsive.
  PC.openPayslipPrint = function (slips, opts) {
    opts = opts || {};
    const saveMode = !!opts.saveMode;
    const w = window.open('', '_blank', 'width=900,height=1100');
    if (!w) {
      try { PC.toast('Pop-up blocked — allow pop-ups for this site and tap Print again.', 'warning'); } catch (_) {}
      return null;
    }
    w.document.write(PC.payslipPrintHTML(slips, { saveMode: saveMode }));
    w.document.close();
    return w;
  };

  // ── Payslip quick-view (lightweight on-screen modal) ─────────
  // A fast in-page glance at one payslip: period, gross, taxes, other
  // deductions and net pay — no popup window. The rich, print-ready layout
  // stays reachable via the "View full payslip" button (→ PC.openPayslipPrint,
  // read-only) and the "Print / PDF" button (→ saveMode). Use this for the
  // on-screen "View" action; reserve PC.openPayslipPrint for the full document.
  // Pass an enriched or basic payslip object. Self-contained (builds its own
  // overlay with inline styles) so every SPA renders it identically.
  PC.openPayslipQuickView = function (slip, opts) {
    opts = opts || {};
    if (!slip) return null;
    const cur = slip.currency || 'JMD';
    const n = function (v) { return _psMoney(v, cur); };
    const eh = _psEsc;
    const taxes = (Number(slip.paye_tax) || 0) + (Number(slip.nis) || 0)
                + (Number(slip.nht) || 0) + (Number(slip.education_tax) || 0);
    const other = Number(slip.other_deductions) || 0;
    const payDate = slip.generated_at ? String(slip.generated_at).slice(0, 10) : '';
    const period = slip.period_label || ((slip.period_start || '') + ' – ' + (slip.period_end || ''));
    const slipNo = slip.id ? 'PCL/PS/' + String(slip.id).padStart(6, '0') : '';

    // Tear down any prior instance so re-opening never stacks overlays.
    const prev = document.getElementById('pc-ps-quickview');
    if (prev) prev.remove();

    const ov = document.createElement('div');
    ov.id = 'pc-ps-quickview';
    ov.setAttribute('role', 'dialog');
    ov.setAttribute('aria-modal', 'true');
    ov.style.cssText = 'position:fixed;inset:0;z-index:99999;background:rgba(11,37,69,0.55);'
      + 'display:flex;align-items:center;justify-content:center;padding:18px;';
    const line = function (label, val, strong) {
      return '<div style="display:flex;justify-content:space-between;gap:14px;padding:8px 0;'
        + 'border-bottom:1px solid #eef1f5;font-size:13.5px;">'
        + '<span style="color:#5b6675;">' + eh(label) + '</span>'
        + '<span style="font-weight:' + (strong ? '700' : '600') + ';color:#0B2545;'
        + 'font-variant-numeric:tabular-nums;">' + val + '</span></div>';
    };
    ov.innerHTML =
      '<div style="background:#fff;border-radius:14px;max-width:420px;width:100%;'
      + 'box-shadow:0 20px 60px -12px rgba(11,37,69,0.45);overflow:hidden;'
      + "font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;\">"
      +   '<div style="background:linear-gradient(135deg,#1B4F82,#0B2545);color:#fff;padding:16px 20px;">'
      +     '<div style="font-size:12px;letter-spacing:1.4px;font-weight:700;color:#22A08A;">PAYSLIP</div>'
      +     '<div style="font-size:17px;font-weight:700;margin-top:2px;">' + eh(period) + '</div>'
      +     '<div style="font-size:12px;opacity:.85;margin-top:2px;">'
      +        eh(slip.subject_name || '') + (slipNo ? '&nbsp;·&nbsp;' + eh(slipNo) : '') + '</div>'
      +   '</div>'
      +   '<div style="padding:14px 20px 4px;">'
      +     (payDate ? line('Pay date', eh(payDate)) : '')
      +     line('Gross pay', n(slip.gross_pay))
      +     line('Statutory taxes', n(taxes))
      +     line('Other deductions', n(other))
      +   '</div>'
      +   '<div style="margin:8px 20px 0;background:linear-gradient(135deg,#1B4F82,#0B2545);color:#fff;'
      +     'border-radius:10px;padding:12px 16px;display:flex;justify-content:space-between;align-items:center;">'
      +     '<span style="font-size:11px;letter-spacing:1.2px;font-weight:700;color:#22A08A;">NET PAY</span>'
      +     '<span style="font-size:20px;font-weight:700;font-variant-numeric:tabular-nums;">' + n(slip.net_pay) + '</span>'
      +   '</div>'
      +   '<div style="padding:16px 20px;display:flex;gap:8px;flex-wrap:wrap;">'
      +     '<button type="button" data-pcact="full" style="flex:1;min-width:130px;background:#0B2545;color:#fff;'
      +       'border:none;padding:10px 14px;border-radius:8px;cursor:pointer;font-weight:600;font-size:13px;">View full payslip</button>'
      +     '<button type="button" data-pcact="print" style="flex:1;min-width:110px;background:#22A08A;color:#fff;'
      +       'border:none;padding:10px 14px;border-radius:8px;cursor:pointer;font-weight:600;font-size:13px;">Print / PDF</button>'
      +     '<button type="button" data-pcact="close" style="background:#eef1f5;color:#0B2545;'
      +       'border:none;padding:10px 14px;border-radius:8px;cursor:pointer;font-weight:600;font-size:13px;">Close</button>'
      +   '</div>'
      + '</div>';

    function close() { try { ov.remove(); } catch (_) {} document.removeEventListener('keydown', onKey); }
    function onKey(e) { if (e.key === 'Escape') close(); }
    ov.addEventListener('click', function (e) {
      const t = e.target;
      const act = t && t.getAttribute ? t.getAttribute('data-pcact') : null;
      if (t === ov || act === 'close') { close(); return; }
      if (act === 'full')  { close(); PC.openPayslipPrint(slip, { saveMode: false }); return; }
      if (act === 'print') { close(); PC.openPayslipPrint(slip, { saveMode: true }); return; }
    });
    document.addEventListener('keydown', onKey);
    document.body.appendChild(ov);
    return ov;
  };

  // (Date helpers PC.fmtDate / PC.fmtDateTime are defined once, above, and
  //  honor the user's date_format preference. A second ISO-only definition
  //  used to live here and silently shadowed them — removed.)

  // ── Modal helpers ─────────────────────────────────────────
  PC.modalOpen = function (id) {
    const el = document.getElementById(id);
    if (!el) return;
    el.classList.add('open');
    el.removeAttribute('hidden');
    document.body.style.overflow = 'hidden';
    const focusable = el.querySelector('[autofocus], input, select, textarea, button');
    if (focusable) focusable.focus();
  };
  PC.modalClose = function (id) {
    const el = document.getElementById(id);
    if (!el) return;
    el.classList.remove('open');
    document.body.style.overflow = '';
  };

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      const open = document.querySelector('.modal.open, [class*="modal"].open');
      if (open && open.id) PC.modalClose(open.id);
    }
  });

  // TEMPORARY shim — old SPA code calls bare `toast(...)`. Remove in next refactor pass
  // once all call sites have migrated to PC.toast(...).
  if (typeof window.toast === 'undefined') window.toast = PC.toast;

  // ── Access bundle ─────────────────────────────────────────
  // Loads the user's effective permissions (role + delegations). Cached
  // in-memory for 30 seconds. SPAs call PC.access() and await the promise.
  // On any 401/403, returns null (signals not-yet-authenticated).
  //
  // PC.access(force?) - force=true bypasses cache. Use after a delegation
  // grant/revoke event to refresh immediately.
  //
  // PC.accessSync() - returns the last-cached bundle synchronously or null.
  //   Used by render-time gate functions; never blocks.

  let _accessBundle = null;
  let _accessExpiresAt = 0;
  let _accessInflight = null;
  let _accessUrl = null;  // auto-detected based on path

  function _detectAccessUrl() {
    const path = (typeof location !== 'undefined' && location.pathname) || '';
    if (path.startsWith('/portal')) return '/api/portal/me/access-bundle';
    if (path.startsWith('/tech')) return '/api/tech/me/access-bundle';
    return '/api/admin/me/access-bundle';
  }

  PC.access = async function (force) {
    if (!_accessUrl) _accessUrl = _detectAccessUrl();
    const now = Date.now();
    if (!force && _accessBundle && now < _accessExpiresAt) {
      return _accessBundle;
    }
    if (_accessInflight) return _accessInflight;
    _accessInflight = (async () => {
      try {
        const data = await PC.apiFetch(_accessUrl);
        _accessBundle = data;
        _accessExpiresAt = now + 30 * 1000;  // 30s
        return data;
      } catch (e) {
        if (e && e.status && (e.status === 401 || e.status === 403)) {
          _accessBundle = null;
          _accessExpiresAt = 0;
          return null;
        }
        throw e;
      } finally {
        _accessInflight = null;
      }
    })();
    return _accessInflight;
  };

  PC.accessSync = function () {
    if (Date.now() < _accessExpiresAt) return _accessBundle;
    return null;
  };

  PC.accessInvalidate = function () {
    _accessBundle = null;
    _accessExpiresAt = 0;
  };

  // ── Permission evaluator ──────────────────────────────────
  function _hasPerm(bundle, perm) {
    return bundle && bundle.role_grants && bundle.role_grants.includes(perm);
  }

  function _hasTypeDeleg(bundle, type, level) {
    if (!bundle || !bundle.delegations) return false;
    const grants = (bundle.delegations.by_record_type || {})[type] || [];
    if (level === 'read') return grants.includes('read') || grants.includes('read_write');
    if (level === 'write') return grants.includes('read_write');
    return false;
  }

  function _hasRecordDeleg(bundle, type, id, level) {
    if (!bundle || !bundle.delegations || !id) return false;
    const list = bundle.delegations.by_specific_record || [];
    for (const g of list) {
      if (g.resource_type !== type) continue;
      if (g.resource_id !== id && g.resource_id !== Number(id)) continue;
      if (level === 'read') {
        if (g.permission === 'read' || g.permission === 'read_write') return true;
      } else if (level === 'write') {
        if (g.permission === 'read_write') return true;
      }
    }
    return false;
  }

  PC.canRead = function (targetType, targetId) {
    const b = PC.accessSync();
    if (!b) return false;
    if (b.role === 'super_admin') return true;
    if (_hasPerm(b, targetType + ':view')) return true;
    if (_hasTypeDeleg(b, targetType, 'read')) return true;
    if (_hasRecordDeleg(b, targetType, targetId, 'read')) return true;
    if (b.user_kind === 'tech' && b.scope === 'assigned_records_only') {
      if (['visit','fs_audit','fs_exception','kpi_score','kpi_flag','payslip'].includes(targetType)) {
        return true;
      }
    }
    if (b.user_kind === 'customer' && b.scope === 'own_records_only') {
      if (['customer','invoice','visit','equipment','payment'].includes(targetType)) {
        return true;
      }
    }
    return false;
  };

  PC.canWrite = function (targetType, targetId) {
    const b = PC.accessSync();
    if (!b) return false;
    if (b.role === 'super_admin') return true;
    if (_hasPerm(b, targetType + ':edit')) return true;
    if (_hasPerm(b, targetType + ':write')) return true;
    if (_hasTypeDeleg(b, targetType, 'write')) return true;
    if (_hasRecordDeleg(b, targetType, targetId, 'write')) return true;
    return false;
  };

  // ── Gate render helpers ───────────────────────────────────
  PC.gateLink = function (targetType, targetId, label, opts) {
    opts = opts || {};
    if (PC.canRead(targetType, targetId)) {
      const a = document.createElement('a');
      a.className = 'pc-link';
      a.textContent = String(label);
      a.setAttribute('data-pc-target', targetType + ':' + (targetId || ''));
      if (opts.title) a.title = opts.title;
      if (opts.href) {
        a.href = opts.href;
      } else {
        a.href = '#' + targetType + '/' + (targetId || '');
      }
      if (opts.onClick) {
        a.addEventListener('click', function (e) {
          e.preventDefault();
          e.stopPropagation();
          opts.onClick(e);
        });
      } else {
        a.addEventListener('click', function (e) { e.stopPropagation(); });
      }
      return a;
    } else {
      const span = document.createElement('span');
      span.className = 'pc-text-only';
      span.textContent = String(label);
      span.setAttribute('data-pc-no-access', targetType + ':' + (targetId || ''));
      return span;
    }
  };

  PC.gateLinkHtml = function (targetType, targetId, label, opts) {
    opts = opts || {};
    const safeLabel = String(label).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    if (PC.canRead(targetType, targetId)) {
      const href = opts.href || ('#' + targetType + '/' + (targetId || ''));
      const onclickAttr = opts.onClick
        ? ' onclick="event.preventDefault();event.stopPropagation();(' + opts.onClick + ')(event);"'
        : ' onclick="event.stopPropagation();"';
      const titleAttr = opts.title ? ' title="' + String(opts.title).replace(/"/g,'&quot;') + '"' : '';
      return '<a class="pc-link" data-pc-target="' + targetType + ':' + (targetId||'') + '" href="' + href + '"' + onclickAttr + titleAttr + '>' + safeLabel + '</a>';
    } else {
      return '<span class="pc-text-only" data-pc-no-access="' + targetType + ':' + (targetId||'') + '">' + safeLabel + '</span>';
    }
  };

  PC.gateRow = function (rowEl, targetType, targetId, opts) {
    if (!rowEl) return;
    opts = opts || {};
    if (PC.canRead(targetType, targetId)) {
      rowEl.classList.add('pc-row-clickable');
      rowEl.setAttribute('tabindex', '0');
      rowEl.setAttribute('role', 'button');
      rowEl.setAttribute('aria-label', opts.ariaLabel || ('Open ' + targetType + ' ' + (targetId || '')));
      rowEl.setAttribute('data-pc-target', targetType + ':' + (targetId || ''));
      const handler = function (e) {
        const t = e.target;
        if (t && (t.closest && t.closest('a, button, input, textarea, select, [data-stop-prop]'))) return;
        e.preventDefault();
        if (opts.onClick) {
          opts.onClick(e);
        } else {
          location.hash = '#' + targetType + '/' + (targetId || '');
        }
      };
      rowEl.addEventListener('click', handler);
      rowEl.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          handler(e);
        }
      });
      const children = rowEl.querySelectorAll('.pc-stop-prop, [data-stop-prop]');
      children.forEach(function (c) {
        c.addEventListener('click', function (e) { e.stopPropagation(); });
      });
    } else {
      rowEl.classList.remove('pc-row-clickable');
      rowEl.removeAttribute('tabindex');
      rowEl.removeAttribute('role');
    }
  };

  PC.gateBadge = function (badgeEl, count, targetType, filterFn) {
    if (!badgeEl) return;
    badgeEl.textContent = String(count == null ? '' : count);
    if (PC.canRead(targetType, null) && count && filterFn) {
      badgeEl.classList.add('pc-badge-clickable');
      badgeEl.setAttribute('role', 'button');
      badgeEl.setAttribute('tabindex', '0');
      const h = function (e) { e.preventDefault(); e.stopPropagation(); filterFn(e); };
      badgeEl.addEventListener('click', h);
      badgeEl.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' || e.key === ' ') h(e);
      });
    } else {
      badgeEl.classList.remove('pc-badge-clickable');
      badgeEl.removeAttribute('role');
      badgeEl.removeAttribute('tabindex');
    }
  };

  // ── Failure handling ──────────────────────────────────────
  // PC.handleAccessDenied(err) - call from any apiFetch .catch().
  PC.handleAccessDenied = function (err) {
    if (!err || !err.body) return false;
    if (err.body.code === 'access_denied') {
      const rid = err.body.request_id ? ' (ref ' + err.body.request_id + ')' : '';
      PC.toast('Access denied' + rid, 'warning');
      return true;
    }
    return false;
  };

  // ── In-app notification bell (A5) ─────────────────────────
  // A single shared widget used by all six SPAs. It gates on IDENTITY
  // only: a quick probe of /api/notifications/unread-count returns 401
  // when nobody is signed in, in which case the bell never appears. Any
  // signed-in subject (admin / technician / customer) gets the bell and
  // sees only their own rows (the server scopes by recipient).
  //
  // Mount target: if the host page provides an element with
  // [data-pc-notif-bell] the bell is injected there (so it can live in a
  // real top-bar); otherwise it floats fixed in the top-right corner as a
  // universal fallback. Either way nothing existing is removed.
  PC.notif = PC.notif || { unread: 0, open: false, _timer: null, _mounted: false };

  function _notifStyles() {
    if (document.getElementById('pc-notif-style')) return;
    const s = document.createElement('style');
    s.id = 'pc-notif-style';
    s.textContent =
      '.pc-bell-wrap{position:relative;display:inline-flex;}' +
      '.pc-bell-wrap.pc-bell-float{position:fixed;top:14px;right:18px;z-index:99990;}' +
      '.pc-bell-btn{position:relative;display:inline-flex;align-items:center;justify-content:center;' +
        'width:38px;height:38px;border-radius:50%;border:1px solid rgba(27,79,130,0.22);' +
        'background:#fff;color:#1B4F82;cursor:pointer;box-shadow:0 2px 8px rgba(15,42,74,0.12);' +
        'transition:background 140ms,box-shadow 140ms;}' +
      '.pc-bell-btn:hover{background:#EAF1F8;box-shadow:0 4px 14px rgba(15,42,74,0.2);}' +
      '.pc-bell-btn:focus-visible{outline:2px solid #22A08A;outline-offset:2px;}' +
      '.pc-bell-btn svg{width:19px;height:19px;}' +
      '.pc-bell-badge{position:absolute;top:-3px;right:-3px;min-width:17px;height:17px;padding:0 4px;' +
        'border-radius:9px;background:#B42318;color:#fff;font:700 10px/17px "IBM Plex Sans",system-ui,sans-serif;' +
        'text-align:center;box-shadow:0 0 0 2px #fff;display:none;}' +
      '.pc-bell-badge.show{display:block;}' +
      '.pc-notif-panel{position:absolute;top:46px;right:0;width:min(360px,calc(100vw - 28px));' +
        'max-height:min(70vh,520px);overflow:hidden;display:none;flex-direction:column;' +
        'background:#fff;border:1px solid rgba(27,79,130,0.18);border-radius:14px;' +
        'box-shadow:0 18px 48px rgba(15,42,74,0.28);z-index:99991;}' +
      '.pc-notif-panel.open{display:flex;}' +
      '.pc-notif-head{display:flex;align-items:center;justify-content:space-between;gap:8px;' +
        'padding:12px 14px;border-bottom:1px solid #EEF2F6;}' +
      '.pc-notif-head h4{margin:0;font:700 14px/1.2 "IBM Plex Sans",system-ui,sans-serif;color:#0B2545;}' +
      '.pc-notif-readall{border:0;background:none;color:#1B4F82;font:600 12px/1 inherit;cursor:pointer;padding:4px 6px;border-radius:6px;}' +
      '.pc-notif-readall:hover{background:#EAF1F8;}' +
      '.pc-notif-readall[disabled]{color:#9AA7B4;cursor:default;background:none;}' +
      '.pc-notif-list{overflow-y:auto;-webkit-overflow-scrolling:touch;}' +
      '.pc-notif-item{display:flex;gap:10px;padding:11px 14px;border-bottom:1px solid #F2F5F8;cursor:pointer;text-align:left;}' +
      '.pc-notif-item:last-child{border-bottom:0;}' +
      '.pc-notif-item:hover{background:#F6F9FC;}' +
      '.pc-notif-item.unread{background:#F0F7FF;}' +
      '.pc-notif-item.unread:hover{background:#E6F1FC;}' +
      '.pc-notif-dot{flex:0 0 auto;width:8px;height:8px;border-radius:50%;margin-top:5px;background:#1B4F82;}' +
      '.pc-notif-dot.info{background:#1B4F82;}.pc-notif-dot.success{background:#22A08A;}' +
      '.pc-notif-dot.warning{background:#E0A100;}.pc-notif-dot.critical,.pc-notif-dot.error{background:#B42318;}' +
      '.pc-notif-body{flex:1 1 auto;min-width:0;}' +
      '.pc-notif-title{font:600 13px/1.35 "IBM Plex Sans",system-ui,sans-serif;color:#0B2545;}' +
      '.pc-notif-sub{font:400 12px/1.4 "IBM Plex Sans",system-ui,sans-serif;color:#5B6B7B;margin-top:1px;' +
        'overflow:hidden;text-overflow:ellipsis;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;}' +
      '.pc-notif-time{font:400 11px/1 "IBM Plex Sans",system-ui,sans-serif;color:#90A0B0;margin-top:4px;}' +
      '.pc-notif-empty{padding:26px 14px;text-align:center;color:#90A0B0;font:400 13px/1.4 "IBM Plex Sans",system-ui,sans-serif;}' +
      '.pc-notif-foot{border-top:1px solid #EEF2F6;padding:9px 14px;}' +
      '.pc-notif-pushbtn{width:100%;border:1px solid rgba(27,79,130,0.25);background:#F6F9FC;color:#1B4F82;' +
        'font:600 12px/1.2 "IBM Plex Sans",system-ui,sans-serif;padding:8px 10px;border-radius:8px;cursor:pointer;}' +
      '.pc-notif-pushbtn:hover{background:#EAF1F8;}' +
      '.pc-notif-pushbtn[disabled]{color:#9AA7B4;cursor:default;background:#F6F9FC;}';
    (document.head || document.documentElement).appendChild(s);
  }

  function _notifEsc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function _notifRelTime(iso) {
    const d = _toDate(iso);
    if (!d || isNaN(d)) return '';
    const secs = Math.round((Date.now() - d.getTime()) / 1000);
    if (secs < 45) return 'just now';
    if (secs < 90) return '1 min ago';
    if (secs < 3600) return Math.round(secs / 60) + ' min ago';
    if (secs < 5400) return '1 hr ago';
    if (secs < 86400) return Math.round(secs / 3600) + ' hr ago';
    if (secs < 172800) return 'yesterday';
    if (secs < 604800) return Math.round(secs / 86400) + ' days ago';
    return PC.fmtDate ? PC.fmtDate(d) : d.toLocaleDateString();
  }

  PC._setBellBadge = function (n) {
    PC.notif.unread = n = Math.max(0, n | 0);
    const b = document.getElementById('pc-bell-badge');
    if (!b) return;
    b.textContent = n > 99 ? '99+' : String(n);
    b.classList.toggle('show', n > 0);
    const btn = document.getElementById('pc-bell-btn');
    if (btn) btn.setAttribute('aria-label', n > 0 ? (n + ' unread notifications') : 'Notifications');
  };

  PC.refreshNotifCount = async function () {
    try {
      const r = await fetch('/api/notifications/unread-count', { credentials: 'same-origin' });
      if (!r.ok) return null;            // 401 → not signed in; leave bell hidden
      const j = await r.json();
      PC._setBellBadge(j.unread || 0);
      return j.unread || 0;
    } catch (_) { return null; }
  };

  PC._renderNotifList = function (items) {
    const list = document.getElementById('pc-notif-list');
    if (!list) return;
    if (!items || !items.length) {
      list.innerHTML = '<div class="pc-notif-empty">You’re all caught up.</div>';
      return;
    }
    list.innerHTML = items.map(function (it) {
      const unread = !it.read_at;
      const sev = (it.severity || 'info').toLowerCase();
      const sub = it.body ? '<div class="pc-notif-sub">' + _notifEsc(it.body) + '</div>' : '';
      return '<button class="pc-notif-item' + (unread ? ' unread' : '') + '" data-nid="' + it.id +
        '" data-link="' + _notifEsc(it.link || '') + '">' +
        '<span class="pc-notif-dot ' + _notifEsc(sev) + '"></span>' +
        '<span class="pc-notif-body">' +
          '<span class="pc-notif-title">' + _notifEsc(it.title) + '</span>' + sub +
          '<span class="pc-notif-time">' + _notifEsc(_notifRelTime(it.created_at)) + '</span>' +
        '</span></button>';
    }).join('');
    list.querySelectorAll('.pc-notif-item').forEach(function (el) {
      el.addEventListener('click', function () {
        const nid = el.getAttribute('data-nid');
        const link = el.getAttribute('data-link');
        if (el.classList.contains('unread')) {
          el.classList.remove('unread');
          fetch('/api/notifications/' + nid + '/read', {
            method: 'POST', credentials: 'same-origin',
            headers: { 'Origin': location.origin },
          }).then(function (r) { return r.ok ? r.json() : null; })
            .then(function (j) { if (j && typeof j.unread === 'number') PC._setBellBadge(j.unread); })
            .catch(function () {});
        }
        if (link) { PC._closeNotifPanel(); location.href = link; }
      });
    });
  };

  PC._openNotifPanel = async function () {
    const panel = document.getElementById('pc-notif-panel');
    if (!panel) return;
    panel.classList.add('open');
    PC.notif.open = true;
    try { PC._refreshPushFooter(); } catch (_) {}
    const list = document.getElementById('pc-notif-list');
    if (list) list.innerHTML = '<div class="pc-notif-empty">Loading…</div>';
    try {
      const r = await fetch('/api/notifications?limit=25', { credentials: 'same-origin' });
      if (r.ok) {
        const j = await r.json();
        PC._renderNotifList(j.items || []);
        if (typeof j.unread === 'number') PC._setBellBadge(j.unread);
      } else if (list) {
        list.innerHTML = '<div class="pc-notif-empty">Could not load notifications.</div>';
      }
    } catch (_) {
      if (list) list.innerHTML = '<div class="pc-notif-empty">Could not load notifications.</div>';
    }
  };

  PC._closeNotifPanel = function () {
    const panel = document.getElementById('pc-notif-panel');
    if (panel) panel.classList.remove('open');
    PC.notif.open = false;
  };

  PC._toggleNotifPanel = function () {
    if (PC.notif.open) PC._closeNotifPanel(); else PC._openNotifPanel();
  };

  PC.markAllNotifsRead = async function () {
    try {
      const r = await fetch('/api/notifications/read-all', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Origin': location.origin },
      });
      if (r.ok) {
        PC._setBellBadge(0);
        document.querySelectorAll('#pc-notif-list .pc-notif-item.unread')
          .forEach(function (el) { el.classList.remove('unread'); });
      }
    } catch (_) {}
  };

  // ── Web Push opt-in (A5) ──────────────────────────────────
  // The browser-push half. Best-effort + progressive: if the browser lacks
  // service-worker/Push support, or the server has no VAPID key, or delivery
  // is disabled server-side, the footer button simply doesn't appear and the
  // in-app bell still works on its own.
  function _urlB64ToUint8(b64) {
    const pad = '='.repeat((4 - (b64.length % 4)) % 4);
    const s = (b64 + pad).replace(/-/g, '+').replace(/_/g, '/');
    const raw = atob(s);
    const out = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }
  PC.push = PC.push || { supported: false, configured: false, permission: 'default' };

  PC.pushSupported = function () {
    return ('serviceWorker' in navigator) && ('PushManager' in window) && ('Notification' in window);
  };

  PC.enablePush = async function () {
    if (!PC.pushSupported()) { PC.toast && PC.toast('Push not supported in this browser', 'warning'); return false; }
    try {
      const keyResp = await fetch('/api/push/vapid-public-key', { credentials: 'same-origin' });
      if (!keyResp.ok) return false;
      const kj = await keyResp.json();
      if (!kj.configured || !kj.key) { PC.toast && PC.toast('Push not configured yet', 'warning'); return false; }
      const perm = await Notification.requestPermission();
      PC.push.permission = perm;
      if (perm !== 'granted') { PC.toast && PC.toast('Notifications permission denied', 'warning'); PC._refreshPushFooter(); return false; }
      const reg = await navigator.serviceWorker.register('/sw.js');
      await navigator.serviceWorker.ready;
      let sub = await reg.pushManager.getSubscription();
      if (!sub) {
        sub = await reg.pushManager.subscribe({
          userVisibleOnly: true,
          applicationServerKey: _urlB64ToUint8(kj.key),
        });
      }
      const j = sub.toJSON();
      const r = await fetch('/api/push/subscribe', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'Origin': location.origin },
        body: JSON.stringify({ endpoint: j.endpoint, keys: j.keys || {} }),
      });
      if (r.ok) { PC.toast && PC.toast('Browser notifications enabled', 'success'); PC._refreshPushFooter(); return true; }
      return false;
    } catch (e) {
      PC.toast && PC.toast('Could not enable push notifications', 'error');
      return false;
    }
  };

  PC.disablePush = async function () {
    try {
      if (!PC.pushSupported()) return;
      const reg = await navigator.serviceWorker.getRegistration();
      if (!reg) { PC._refreshPushFooter(); return; }
      const sub = await reg.pushManager.getSubscription();
      if (sub) {
        const ep = sub.endpoint;
        await sub.unsubscribe();
        await fetch('/api/push/unsubscribe', {
          method: 'POST', credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json', 'Origin': location.origin },
          body: JSON.stringify({ endpoint: ep }),
        });
      }
      PC.toast && PC.toast('Browser notifications turned off', 'info');
      PC._refreshPushFooter();
    } catch (_) {}
  };

  // Reflect current push state in the panel footer. Hidden entirely when the
  // browser can't do push or the server has no VAPID key configured.
  PC._refreshPushFooter = async function () {
    const foot = document.getElementById('pc-notif-foot');
    const btn = document.getElementById('pc-notif-pushbtn');
    if (!foot || !btn) return;
    if (!PC.pushSupported()) { foot.style.display = 'none'; return; }
    let configured = false;
    try {
      const r = await fetch('/api/push/vapid-public-key', { credentials: 'same-origin' });
      if (r.ok) { const j = await r.json(); configured = !!j.configured; }
    } catch (_) {}
    if (!configured) { foot.style.display = 'none'; return; }
    foot.style.display = 'block';
    let subscribed = false;
    try {
      const reg = await navigator.serviceWorker.getRegistration();
      if (reg) { const s = await reg.pushManager.getSubscription(); subscribed = !!s; }
    } catch (_) {}
    if (Notification.permission === 'denied') {
      btn.textContent = 'Browser notifications blocked in site settings';
      btn.disabled = true;
      btn.onclick = null;
    } else if (subscribed) {
      btn.textContent = 'Turn off browser notifications';
      btn.disabled = false;
      btn.onclick = function (e) { e.stopPropagation(); PC.disablePush(); };
    } else {
      btn.textContent = 'Enable browser notifications';
      btn.disabled = false;
      btn.onclick = function (e) { e.stopPropagation(); PC.enablePush(); };
    }
  };

  // A page opts out of the floating-corner notification bell by setting
  // [data-pc-no-bell] on <body> (or window.PC_DISABLE_NOTIF_BELL = true) —
  // used by the staff home hub, which already surfaces alerts through its own
  // header + "Awaiting Your Action" feed. A page that provides an explicit
  // inline [data-pc-notif-bell] host is unaffected: the bell mounts there.
  PC._notifBellSuppressed = function () {
    try {
      return !!(document.querySelector('[data-pc-no-bell]')
             || window.PC_DISABLE_NOTIF_BELL === true);
    } catch (_) { return false; }
  };

  PC.mountNotificationBell = function () {
    if (PC.notif._mounted) return;
    const host = document.querySelector('[data-pc-notif-bell]');
    // No inline host and the page opted out → skip the floating fallback.
    if (!host && PC._notifBellSuppressed()) return;
    _notifStyles();
    const wrap = document.createElement('div');
    wrap.className = 'pc-bell-wrap';
    if (!host) wrap.classList.add('pc-bell-float');
    wrap.innerHTML =
      '<button class="pc-bell-btn" id="pc-bell-btn" type="button" aria-label="Notifications" aria-haspopup="true" aria-expanded="false">' +
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
        '<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path>' +
        '<path d="M13.73 21a2 2 0 0 1-3.46 0"></path></svg>' +
        '<span class="pc-bell-badge" id="pc-bell-badge"></span>' +
      '</button>' +
      '<div class="pc-notif-panel" id="pc-notif-panel" role="dialog" aria-label="Notifications">' +
        '<div class="pc-notif-head"><h4>Notifications</h4>' +
          '<button class="pc-notif-readall" id="pc-notif-readall" type="button">Mark all read</button></div>' +
        '<div class="pc-notif-list" id="pc-notif-list"></div>' +
        '<div class="pc-notif-foot" id="pc-notif-foot" style="display:none;">' +
          '<button class="pc-notif-pushbtn" id="pc-notif-pushbtn" type="button"></button>' +
        '</div>' +
      '</div>';
    (host || document.body).appendChild(wrap);
    PC.notif._mounted = true;

    const btn = wrap.querySelector('#pc-bell-btn');
    btn.addEventListener('click', function (e) {
      e.stopPropagation();
      const exp = !PC.notif.open;
      btn.setAttribute('aria-expanded', exp ? 'true' : 'false');
      PC._toggleNotifPanel();
    });
    wrap.querySelector('#pc-notif-readall').addEventListener('click', function (e) {
      e.stopPropagation();
      PC.markAllNotifsRead();
    });
    // Click-away + Escape close.
    document.addEventListener('click', function (e) {
      if (PC.notif.open && !wrap.contains(e.target)) {
        PC._closeNotifPanel();
        btn.setAttribute('aria-expanded', 'false');
      }
    });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && PC.notif.open) {
        PC._closeNotifPanel();
        btn.setAttribute('aria-expanded', 'false');
      }
    });
  };

  // Auto-init: probe identity, mount only if signed in, then poll the
  // unread count. Polling pauses while the tab is hidden (battery + load)
  // and does an immediate catch-up refresh when it becomes visible again.
  PC._initNotifBell = async function () {
    // Skip entirely when the page opts out and offers no inline mount host.
    if (PC._notifBellSuppressed() && !document.querySelector('[data-pc-notif-bell]')) return;
    const n = await PC.refreshNotifCount();
    if (n === null) return;              // not authenticated — no bell
    PC.mountNotificationBell();
    PC._setBellBadge(n);
    function schedule() {
      if (PC.notif._timer) { clearInterval(PC.notif._timer); PC.notif._timer = null; }
      PC.notif._timer = setInterval(function () {
        if (!document.hidden) PC.refreshNotifCount();
      }, 60000);
    }
    schedule();
    document.addEventListener('visibilitychange', function () {
      if (!document.hidden) PC.refreshNotifCount();
    });
  };
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { setTimeout(PC._initNotifBell, 300); });
  } else {
    setTimeout(PC._initNotifBell, 300);
  }

  // ───────────────────────────────────────────────────────────────────────
  // Shared bottom navigation bar.
  //
  // The staff home hub (staff_home.html) renders its own in-page `.bottomnav`
  // and drives it with showPanel() — so the bar is always present THERE. But
  // every other staff surface (Admin console, Tech portal, sub-pages) is a
  // separate document with no bar, so the bar "disappeared" the moment you
  // navigated off Home. This mounts the SAME bar on those pages, with links
  // that route back to the relevant /home#panel, giving continuous nav.
  //
  // Opt-out / dedupe rules:
  //   • If the page already has a native `.bottomnav` (i.e. staff_home), skip
  //     — we never want two bars.
  //   • If the page sets [data-pc-no-bottomnav] on <body>, skip (sign-in
  //     screens, kiosk views, etc.).
  //   • Only staff get it: we probe /api/staff/me; a 401 (logged-out, or a
  //     customer-portal session) yields no bar.
  // ───────────────────────────────────────────────────────────────────────
  PC.bottomNav = PC.bottomNav || { _mounted: false };

  PC._bottomNavSuppressed = function () {
    try {
      return !!(document.querySelector('.bottomnav')               // native bar present
             || document.querySelector('[data-pc-no-bottomnav]')   // explicit opt-out
             || window.PC_DISABLE_BOTTOMNAV === true);
    } catch (_) { return false; }
  };

  function _bottomNavStyles() {
    if (document.getElementById('pc-bottomnav-styles')) return;
    const css = document.createElement('style');
    css.id = 'pc-bottomnav-styles';
    css.textContent = `
      body.pc-has-bottomnav {
        padding-bottom: calc(64px + env(safe-area-inset-bottom,0px)) !important;
      }
      .pc-bottomnav {
        position: fixed; bottom: 0; left: 0; right: 0;
        background: var(--card, #ffffff);
        border-top: 1px solid var(--border-light, var(--border, #e6ebf1));
        height: calc(64px + env(safe-area-inset-bottom,0px));
        padding-bottom: env(safe-area-inset-bottom,0px);
        display: flex; z-index: 100;
        box-shadow: 0 -2px 10px rgba(11,37,69,.04);
        font-family: var(--font-body, system-ui, -apple-system, sans-serif);
      }
      .pc-bottomnav .pc-bn-item {
        flex: 1; display: flex; flex-direction: column;
        align-items: center; justify-content: center; gap: 3px;
        font-size: 11px; font-weight: 600;
        color: var(--muted, #6b7a90);
        text-decoration: none;
        padding: 6px 4px; position: relative; cursor: pointer;
        background: none; border: none;
        -webkit-tap-highlight-color: transparent;
      }
      .pc-bottomnav .pc-bn-ico {
        width: 34px; height: 34px; border-radius: 50%;
        display: inline-flex; align-items: center; justify-content: center;
        transition: background .14s ease, color .14s ease;
      }
      .pc-bottomnav .pc-bn-ico svg { width: 18px; height: 18px; }
      .pc-bottomnav .pc-bn-item.active { color: var(--ink, #0b2545); }
      .pc-bottomnav .pc-bn-item.active .pc-bn-ico {
        background: var(--navy, #0b2545); color: #fff;
      }
      .pc-bottomnav .pc-bn-item.active .pc-bn-ico svg { stroke: #fff; }
      @media (min-width:768px){
        .pc-bottomnav {
          left: 50%; transform: translateX(-50%);
          width: min(640px, 100%);
          border-left: 1px solid var(--border-light, var(--border, #e6ebf1));
          border-right: 1px solid var(--border-light, var(--border, #e6ebf1));
          border-top-left-radius: 16px; border-top-right-radius: 16px;
        }
      }
    `;
    document.head.appendChild(css);
  }

  // Icons mirror the staff_home bottom bar exactly.
  const _BN_ICONS = {
    home: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2h-4v-7h-6v7H5a2 2 0 0 1-2-2z"/></svg>',
    jobs: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 7h-4V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v2H4a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2Z"/><path d="M10 5h4v2h-4z"/></svg>',
    find: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg>',
    profile: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/></svg>',
    menu: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>',
  };

  PC.mountBottomNav = function (me) {
    if (PC.bottomNav._mounted) return;
    if (PC._bottomNavSuppressed()) return;
    _bottomNavStyles();

    const isTech = me && me.kind === 'tech';
    const items = [
      { key: 'dashboard', label: 'Home',    ico: 'home' },
      isTech ? { key: 'jobs', label: 'My Jobs', ico: 'jobs' } : null,
      { key: 'find',      label: 'Find',    ico: 'find' },
      { key: 'profile',   label: 'Profile', ico: 'profile' },
      { key: 'menu',      label: 'Menu',    ico: 'menu' },
    ].filter(Boolean);

    const nav = document.createElement('nav');
    nav.className = 'pc-bottomnav';
    nav.setAttribute('aria-label', 'Primary navigation');
    nav.setAttribute('data-pc-bottomnav', '');
    nav.innerHTML = items.map(function (it) {
      // Profile is the one item that lives at its own top-level page
      // (/profile = profile.html), NOT a /home tab. Everywhere else in the
      // app — the staff_home bottom bar, the avatar button, the "My Profile"
      // pill, and the admin "My Profile" nav — "Profile" opens /profile. The
      // shared bar must match, or the SAME icon lands you on two different
      // pages depending on which page rendered it (/home#profile is the
      // separate "My Records" panel, reached from /profile's own tile).
      const href = (it.key === 'profile') ? '/profile' : ('/home#' + it.key);
      return '<a class="pc-bn-item" href="' + href + '">'
           +   '<span class="pc-bn-ico">' + _BN_ICONS[it.ico] + '</span>'
           +   '<span>' + it.label + '</span>'
           + '</a>';
    }).join('');

    document.body.appendChild(nav);
    document.body.classList.add('pc-has-bottomnav');
    PC.bottomNav._mounted = true;
  };

  PC._initBottomNav = async function () {
    if (PC._bottomNavSuppressed()) return;
    let me = null;
    try {
      const res = await fetch('/api/staff/me', { credentials: 'include' });
      if (!res.ok) return;            // 401 → logged-out or customer → no bar
      me = await res.json();
    } catch (_) { return; }
    if (!me || !me.kind) return;
    PC.mountBottomNav(me);
  };
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { setTimeout(PC._initBottomNav, 300); });
  } else {
    setTimeout(PC._initBottomNav, 300);
  }

  // CSS-only additions: append a <style> with gate-related styling once on first use.
  (function injectStyles() {
    if (typeof document === 'undefined') return;
    if (document.getElementById('pc-shared-styles')) return;
    const css = document.createElement('style');
    css.id = 'pc-shared-styles';
    css.textContent = `
      .pc-link { color: #22A08A; cursor: pointer; text-decoration: underline; }
      .pc-link:hover { color: #1B8270; }
      .pc-link:focus-visible { outline: 2px solid #22A08A; outline-offset: 2px; }
      .pc-text-only { color: inherit; cursor: default; text-decoration: none; }
      .pc-row-clickable { cursor: pointer; transition: background 120ms; }
      .pc-row-clickable:hover { background: var(--surface-2, #f5f7fa); }
      .pc-row-clickable:focus-visible { outline: 2px solid #22A08A; outline-offset: -2px; }
      .pc-badge-clickable { cursor: pointer; }
      .pc-badge-clickable:hover { filter: brightness(1.1); }
      .pc-badge-clickable:focus-visible { outline: 2px solid #22A08A; outline-offset: 2px; }
    `;
    document.head.appendChild(css);
  })();

  // Eager-load the bundle so PC.canRead works on first render.
  if (typeof location !== 'undefined' && location.pathname &&
      (location.pathname.startsWith('/admin') || location.pathname.startsWith('/tech') || location.pathname.startsWith('/portal'))) {
    setTimeout(function () { try { PC.access(); } catch (_) {} }, 0);
  }
})();
