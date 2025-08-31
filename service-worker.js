// service-worker.js
const VERSION = 'blackout-shell-v18';

const SCOPE = (self.registration && self.registration.scope)
  ? new URL(self.registration.scope).pathname.replace(/\/$/, '')
  : '';

const p = (path) => (path.startsWith(SCOPE) ? path : (SCOPE + path));

// List only files you actually ship at the project root
const ASSETS_RAW = [
  '/',                        // index redirect
  '/index.html',
  '/blackoutv1.9.2.html',
  '/manifest.webmanifest',


  '/argon2.config.js',
  '/argon2.worker.js',
  '/argon2.min.js',


  '/particles.min.js',
  '/particlesjs-config.json',
  'particles-loader.js',
];

const ASSETS = ASSETS_RAW.map(p);

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(VERSION);

    // Cache one-by-one so a single 404 doesn't fail installation
    await Promise.allSettled(ASSETS.map(async (url) => {
      try {
        const resp = await fetch(url, { cache: 'no-store' });
        if (resp.ok) await cache.put(url, resp.clone());
      } catch (_) { /* ignore */ }
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

  // Skip blob:/data:
  if (url.protocol === 'blob:' || url.protocol === 'data:') return;

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

// Allow manual update nudges
self.addEventListener('message', (e) => {
  if (e.data === 'SW_UPDATE' || (e.data && e.data.type === 'SKIP_WAITING')) {
    self.skipWaiting();
  }
});
