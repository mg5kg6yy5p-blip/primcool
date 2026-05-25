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
      success: { bg: '#0F2A4A', fg: '#fff',     ico: '✓', icoBg: '#B6E021',                icoFg: '#0F2A4A' },
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
      .pc-row-clickable:hover { background: #f5f7fa; }
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
