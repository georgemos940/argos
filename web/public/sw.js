// app shell for offline starts. the api is never cached
const CACHE = 'argos-1';

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(['/', '/logo.png', '/icons/icon-192.png'])));
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))));
  self.clients.claim();
});

const put = (req, res) => { if (res.ok) { const copy = res.clone(); caches.open(CACHE).then((c) => c.put(req, copy)); } return res; };

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== location.origin || /^\/(api|hooks)\//.test(url.pathname)) return;
  if (e.request.mode === 'navigate') {
    e.respondWith(fetch(e.request).then((r) => put('/', r)).catch(() => caches.match('/')));
  } else if (/^\/(assets|icons)\//.test(url.pathname)) {
    // hashed or fixed files, cache first
    e.respondWith(caches.match(e.request).then((hit) => hit || fetch(e.request).then((r) => put(e.request, r))));
  }
});
