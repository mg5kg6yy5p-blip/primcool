// PrimeCool shared frontend helpers — used by admin.html, tech.html, portal_dashboard.html
// Loaded via <script src="/icons/pc_shared.js"></script> at the top of each SPA.
// Exports a global `PC` namespace; do not pollute window with bare identifiers.
//
// FIXME(static-mount): main.py does NOT mount /static (it mounts /images and /icons only).
// To avoid editing main.py during this refactor (concurrent agents), the canonical copy of
// this module lives at static/pc_shared.js but is *served* from icons/pc_shared.js via the
// existing `app.mount("/icons", StaticFiles(directory="icons"))` route. Keep the two copies
// in sync until a /static mount is added, at which point delete icons/pc_shared.js and
// update the three SPA <script> tags to /static/pc_shared.js.

(function () {
  if (typeof window === 'undefined') return;
  const PC = window.PC = window.PC || {};

  // ── Toast ─────────────────────────────────────────────────
  // PC.toast(message, kind?) — kind: 'info' (default) | 'success' | 'warning' | 'error'
  PC.toast = function (message, kind) {
    kind = kind || 'info';
    let host = document.getElementById('pc-toast-host');
    if (!host) {
      host = document.createElement('div');
      host.id = 'pc-toast-host';
      host.style.cssText = 'position:fixed;top:18px;right:18px;z-index:99999;display:flex;flex-direction:column;gap:8px;pointer-events:none;';
      document.body.appendChild(host);
    }
    const colors = {
      info:    { bg: '#0B2545', fg: '#fff' },
      success: { bg: '#22A08A', fg: '#fff' },
      warning: { bg: '#f59e0b', fg: '#1a2533' },
      error:   { bg: '#dc2626', fg: '#fff' },
    };
    const c = colors[kind] || colors.info;
    const el = document.createElement('div');
    el.setAttribute('role', 'status');
    el.setAttribute('aria-live', 'polite');
    el.style.cssText = 'background:' + c.bg + ';color:' + c.fg + ';padding:10px 14px;border-radius:8px;box-shadow:0 4px 14px rgba(0,0,0,0.18);font:14px Barlow,system-ui,sans-serif;max-width:380px;pointer-events:auto;transition:opacity 200ms ease;';
    el.textContent = String(message == null ? '' : message);
    host.appendChild(el);
    setTimeout(function () { el.style.opacity = '0'; }, 3200);
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

  // ── Date helpers ──────────────────────────────────────────
  PC.fmtDate = function (iso) {
    if (!iso) return '—';
    try { return new Date(iso).toISOString().slice(0, 10); } catch (_) { return iso; }
  };
  PC.fmtDateTime = function (iso) {
    if (!iso) return '—';
    try {
      const d = new Date(iso);
      return d.toISOString().slice(0, 10) + ' ' + d.toISOString().slice(11, 16);
    } catch (_) { return iso; }
  };

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
})();
