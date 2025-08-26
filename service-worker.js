// SW v4 (cache-busted)
const CACHE='blackout-lock-v4';
const ASSETS=['./','./index.html','./styles.css','./lock.js?v=4','./manifest.webmanifest','./blackoutv1.9.2.html','./icons/icon-192.png','./icons/icon-512.png'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(CACHE).then(c=>c.addAll(ASSETS)))});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k)))))});
self.addEventListener('fetch',e=>{e.respondWith(caches.match(e.request).then(r=>r||fetch(e.request)))})
