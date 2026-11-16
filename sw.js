// MY PROGRESS service worker
// غيّر رقم VERSION عند كل نشر لتحديث التطبيق المثبت تلقائيًا
const VERSION = 'v16';
const CACHE = 'mp-' + VERSION;

// ملفات الواجهة الأساسية: تُحفظ عند التثبيت ليفتح التطبيق بدون إنترنت حتى لو لم تُزَر من قبل
const CORE = ['./', 'index.html', 'manifest.webmanifest', 'splash-wing.jpg', 'wing-dark.png'];
const NET_TIMEOUT = 4000; // شبكة بطيئة/وهمية: بعد 4 ثوانٍ نعرض النسخة المحفوظة بدل الانتظار

self.addEventListener('install', (e) => {
  e.waitUntil((async () => {
    try {
      const c = await caches.open(CACHE);
      await Promise.all(CORE.map((u) => c.add(new Request(u, { cache: 'reload' })).catch(() => {})));
    } catch (err) {}
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)));
    await self.clients.claim();
  })());
});

const timed = (p, ms) => !ms ? p : Promise.race([p, new Promise((_, no) => setTimeout(() => no(new Error('timeout')), ms))]);

const OFFLINE_HTML = '<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>MY PROGRESS</title>' +
  '<body style="margin:0;min-height:100vh;display:grid;place-items:center;background:#04070f;color:#e8eefc;font-family:system-ui,sans-serif;text-align:center;padding:24px">' +
  '<div><h2 style="margin:0 0 8px">أنت غير متصل بالإنترنت</h2><p style="margin:0 0 18px;opacity:.7">افتح التطبيق مرة واحدة مع الإنترنت ليُحفظ للعمل بدون اتصال.</p>' +
  '<button onclick="location.reload()" style="font:inherit;font-weight:700;padding:11px 22px;border-radius:99px;border:1px solid #3a4a73;background:#14203f;color:#fff">إعادة المحاولة</button></div></body></html>';

// الشبكة أولًا دائمًا (بدون كاش المتصفح)، والكاش عند الانقطاع أو بطء الشبكة
self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;       // Firebase والخطوط وغيرها
  if (url.pathname.startsWith('/__/')) return;           // مسارات مصادقة Firebase Hosting
  if (url.pathname.startsWith('/api/')) return;          // الخادم: لا كاش أبدًا
  e.respondWith((async () => {
    const cached = await caches.match(req, { ignoreSearch: true });
    try {
      const res = await timed(fetch(req, { cache: 'no-store' }), cached ? NET_TIMEOUT : 0);
      if (res && res.ok && res.type === 'basic') {
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(req, copy)).catch(() => {});
      }
      return res;
    } catch (err) {
      if (cached) return cached;
      if (req.mode === 'navigate') {
        const home = await caches.match(self.registration.scope) || await caches.match('./') || await caches.match('index.html');
        if (home) return home;
        return new Response(OFFLINE_HTML, { status: 503, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
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
