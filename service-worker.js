// service-worker.js
const VERSION = 'blackout-shell-v4';

// Detect the scope base (e.g., "/Hanserq.github.io" on GitHub Pages, or "" at root)
const SCOPE = (self.registration && self.registration.scope)
  ? new URL(self.registration.scope).pathname.replace(/\/$/, '')
  : '';

function p(path) {
  // Prefix with scope unless path is already absolute to this scope
  return (path.startsWith(SCOPE) ? path : (SCOPE + path));
}


const ASSETS_RAW = [
  '/',                       // index redirect
  '/index.html',
  '/blackoutv1.9.2.html',
  '/manifest.webmanifest',
  '/argon2.config.js',
  '/argon2.worker.js', '/argon2.config.js',
  '/argon2.min.js', '/argon2.wasm',
];

const ASSETS = ASSETS_RAW.map(p);

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(VERSION);

    // Fetch each asset individually so a single 404 doesn’t break install
    await Promise.allSettled(ASSETS.map(async (url) => {
      try {
        const resp = await fetch(url, { cache: 'no-store' });
        if (resp.ok) await cache.put(url, resp.clone());
      } catch (_) {
        // Ignore — asset not cached, SW still installs
      }
    }));

    await self.skipWaiting();
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter(k => k !== VERSION).map(k => caches.delete(k)));
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);

  // Only handle same-origin GET requests
  if (req.method !== 'GET' || url.origin !== location.origin) return;

  // Never touch blob:/data:
  if (url.protocol === 'blob:' || url.protocol === 'data:') return;

  // Only cache known app-shell assets
  // Normalize pathname relative to scope
  const path = url.pathname;
  if (!ASSETS.includes(path)) return;

  event.respondWith((async () => {
    const cache = await caches.open(VERSION);
    const hit = await cache.match(req);
    if (hit) return hit;

    const resp = await fetch(req, { cache: 'no-store' });
    if (resp.ok) cache.put(req, resp.clone());
    return resp;
  })());
});

// Optional: allow clients to request an update
self.addEventListener('message', (e) => {
  if (e.data === 'SW_UPDATE') self.skipWaiting();
});
