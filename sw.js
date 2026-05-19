// PrimeCool service worker — minimal, just enables PWA install on Chrome/Android.
// Network-first for everything (no offline caching in v1).
self.addEventListener('install',  e => self.skipWaiting());
self.addEventListener('activate', e => self.clients.claim());
self.addEventListener('fetch',    e => { /* pass-through */ });
