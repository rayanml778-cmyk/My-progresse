// MY PROGRESS service worker
// غيّر رقم VERSION عند كل نشر لتحديث التطبيق المثبت تلقائيًا
const VERSION = 'v1';
const CACHE = 'mp-' + VERSION;

self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)));
    await self.clients.claim();
  })());
});

// الشبكة أولًا دائمًا (بدون كاش المتصفح)، والكاش فقط عند انقطاع الإنترنت
self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;       // Firebase والخطوط وغيرها
  if (url.pathname.startsWith('/__/')) return;           // مسارات مصادقة Firebase Hosting
  e.respondWith((async () => {
    try {
      const res = await fetch(req, { cache: 'no-store' });
      if (res && res.ok && res.type === 'basic') {
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(req, copy)).catch(() => {});
      }
      return res;
    } catch (err) {
      const hit = await caches.match(req, { ignoreSearch: true });
      if (hit) return hit;
      if (req.mode === 'navigate') {
        const home = await caches.match(self.registration.scope) || await caches.match('./');
        if (home) return home;
      }
      return Response.error();
    }
  })());
});

// الضغط على الإشعار يفتح التطبيق
self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const target = (e.notification.data && e.notification.data.url) || self.registration.scope;
  e.waitUntil((async () => {
    const list = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of list) { if ('focus' in c) return c.focus(); }
    return self.clients.openWindow(target);
  })());
});
