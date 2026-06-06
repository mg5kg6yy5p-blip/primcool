// PrimeCool service worker — PWA install + Web Push (A5) + field-app offline shell (#4).
//
// Caching strategy (v2):
//   • App shell + static assets (tech.html via /tech, pc_shared.js, icons, manifest,
//     Google fonts) are pre-cached on install and served cache-first so the field
//     app boots with no network.
//   • Same-origin navigations (e.g. /tech) use network-first with a cache fallback,
//     so techs always get the freshest shell when online but never a blank screen
//     when offline.
//   • API calls (/api/…) are NEVER cached here — the page layer (tech.html) owns
//     its own read-cache + write-queue with idempotency keys. The SW must not
//     shadow live data or replay POSTs.
//
// Bump CACHE_VERSION whenever the shell asset list or strategy changes; the
// activate handler purges every cache that doesn't match.

const CACHE_VERSION = 'pc-tech-v2';
const SHELL_CACHE    = CACHE_VERSION + '-shell';

// Assets that make up the bootable shell. Keep this list lean — only what's
// needed to render the app frame and let the page layer take over.
const SHELL_ASSETS = [
  '/tech',
  '/static/pc_shared.js',
  '/manifest-tech.json',
  '/icons/tech-192.png',
  '/icons/tech-512.png',
  '/icons/tech-apple.png',
];

// Pre-cache the shell on install. Use {cache:'reload'} so we never seed the
// SW cache from the HTTP cache (which could be stale). Tolerate individual
// failures (e.g. a missing optional icon) so install never hard-fails.
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(SHELL_CACHE).then(cache =>
      Promise.allSettled(
        SHELL_ASSETS.map(url =>
          cache.add(new Request(url, { cache: 'reload' })).catch(() => null)
        )
      )
    ).then(() => self.skipWaiting())
  );
});

// On activate, drop any cache that isn't the current shell cache.
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys.filter(k => k !== SHELL_CACHE).map(k => caches.delete(k))
      )
    ).then(() => self.clients.claim())
  );
});

// Treat the cross-origin Google Fonts hosts as cacheable static assets.
function isFontAsset(url) {
  return url.hostname === 'fonts.googleapis.com'
      || url.hostname === 'fonts.gstatic.com';
}

// Is this a same-origin static asset we want to keep fresh-but-available?
function isShellStatic(url) {
  return url.origin === self.location.origin && (
       url.pathname === '/static/pc_shared.js'
    || url.pathname === '/manifest-tech.json'
    || url.pathname.startsWith('/icons/')
  );
}

self.addEventListener('fetch', event => {
  const req = event.request;

  // Only ever handle GETs. POST/PUT/DELETE (job writes, logins, payments) must
  // pass straight through — the page layer queues writes itself.
  if (req.method !== 'GET') return;

  let url;
  try { url = new URL(req.url); } catch (_) { return; }

  // Never touch the API surface — live data + write-queue is the page's job.
  if (url.origin === self.location.origin && url.pathname.startsWith('/api/')) {
    return;
  }

  // Same-origin static shell assets → cache-first, ignoring the ?v= cache-bust
  // query so the pre-cached copy (stored without a query) still matches.
  if (isShellStatic(url)) {
    event.respondWith(cacheFirst(req, true));
    return;
  }

  // Google Fonts → cache-first, exact match (font URLs are unique per path/query).
  if (isFontAsset(url)) {
    event.respondWith(cacheFirst(req, false));
    return;
  }

  // Navigations to the field app shell → network-first, fall back to cached
  // shell when offline. We normalise to '/tech' so a deep refresh still boots.
  if (req.mode === 'navigate' && url.origin === self.location.origin) {
    event.respondWith(navigationHandler(req));
    return;
  }

  // Everything else: plain pass-through (no caching).
});

// Cache-first: serve from cache if present; otherwise fetch, cache a copy, return.
// When ignoreSearch is true, the ?v= cache-bust query is ignored on lookup so a
// versioned request (e.g. pc_shared.js?v=123) matches the query-less pre-cache.
async function cacheFirst(req, ignoreSearch) {
  const opts = ignoreSearch ? { ignoreSearch: true } : undefined;
  const cached = await caches.match(req, opts);
  if (cached) return cached;
  try {
    const res = await fetch(req);
    if (res && (res.ok || res.type === 'opaque')) {
      const cache = await caches.open(SHELL_CACHE);
      cache.put(req, res.clone());
    }
    return res;
  } catch (_) {
    // Last-ditch: any cached variant.
    return (await caches.match(req, opts)) || Response.error();
  }
}

// Network-first for navigations; refresh the cached '/tech' shell on success,
// fall back to it (or the requested page) when the network is unavailable.
async function navigationHandler(req) {
  try {
    const res = await fetch(req);
    if (res && res.ok) {
      const cache = await caches.open(SHELL_CACHE);
      // Cache under the canonical shell key so any /tech navigation can recover.
      cache.put('/tech', res.clone());
    }
    return res;
  } catch (_) {
    return (await caches.match(req))
        || (await caches.match('/tech'))
        || Response.error();
  }
}

// ── Web Push (RFC 8291) ──────────────────────────────────────────────
// The server sends an aes128gcm-encrypted JSON payload
// {title, body, link}. Show it as a notification.
self.addEventListener('push', function (event) {
  let data = { title: 'PrimeCool', body: '', link: '/' };
  try { if (event.data) data = Object.assign(data, event.data.json()); } catch (_) {}
  const title = data.title || 'PrimeCool';
  const opts = {
    body: data.body || '',
    tag: data.tag || undefined,
    data: { link: data.link || '/' },
    icon: data.icon || '/icons/customer-192.png',
    badge: '/icons/customer-192.png',
  };
  event.waitUntil(self.registration.showNotification(title, opts));
});

// Focus an existing PrimeCool tab (or open one) on the target link.
self.addEventListener('notificationclick', function (event) {
  event.notification.close();
  const link = (event.notification.data && event.notification.data.link) || '/';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function (wins) {
      for (const w of wins) {
        try {
          const u = new URL(w.url);
          if (u.origin === self.location.origin && 'focus' in w) {
            w.focus();
            if ('navigate' in w && link && link !== '/') { try { w.navigate(link); } catch (_) {} }
            return;
          }
        } catch (_) {}
      }
      if (clients.openWindow) return clients.openWindow(link);
    })
  );
});
