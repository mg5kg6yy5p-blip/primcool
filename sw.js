// PrimeCool service worker — enables PWA install + Web Push (A5).
// Network-first for everything (no offline caching in v1).
self.addEventListener('install',  e => self.skipWaiting());
self.addEventListener('activate', e => self.clients.claim());
self.addEventListener('fetch',    e => { /* pass-through */ });

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
