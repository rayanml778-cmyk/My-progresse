// MY PROGRESS service worker: required for notifications on Android Chrome and iOS (installed web app).
self.addEventListener('install',e=>self.skipWaiting());
self.addEventListener('activate',e=>e.waitUntil(clients.claim()));
self.addEventListener('notificationclick',e=>{e.notification.close();const u=(e.notification.data&&e.notification.data.url)||'./';e.waitUntil(clients.matchAll({type:'window',includeUncontrolled:true}).then(l=>{for(const c of l){if('focus' in c)return c.focus()}return clients.openWindow(u)}))});
// Ready for server push (e.g. Firebase Cloud Messaging) if you add a push backend later.
self.addEventListener('push',e=>{let d={};try{d=e.data.json()}catch(x){}e.waitUntil(self.registration.showNotification(d.title||'MY PROGRESS',{body:d.body||'',tag:d.tag,dir:'rtl',lang:'ar'}))});
