// api/_fb.js — التحقق من Firebase ID token + عدّاد الرصيد من جهة الخادم (Firestore REST بحساب خدمة، بلا مكتبات)
// المتغيرات: FIREBASE_SA = محتوى JSON لحساب الخدمة (Project settings › Service accounts)، FIREBASE_PROJECT_ID (اختياري)
const crypto = require('crypto');
const PROJECT = process.env.FIREBASE_PROJECT_ID || 'myprogress-6b9d9';
const b64 = (s) => Buffer.from(s, 'base64url');
let jwks = null, jwksAt = 0;
async function keys() {
  if (jwks && Date.now() - jwksAt < 36e5) return jwks;
  const r = await fetch('https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com');
  jwks = (await r.json()).keys || []; jwksAt = Date.now();
  return jwks;
}
async function verifyIdToken(t) { // يعيد uid أو null
  try {
    if (typeof t !== 'string' || t.length > 4000) return null;
    const [h, p, s] = t.split('.'); if (!s) return null;
    const hd = JSON.parse(b64(h).toString()), pl = JSON.parse(b64(p).toString());
    if (hd.alg !== 'RS256') return null;
    const k = (await keys()).find((x) => x.kid === hd.kid); if (!k) return null;
    const ok = crypto.verify('RSA-SHA256', Buffer.from(h + '.' + p), crypto.createPublicKey({ key: k, format: 'jwk' }), b64(s));
    if (!ok || pl.aud !== PROJECT || pl.iss !== 'https://securetoken.google.com/' + PROJECT || !(pl.exp > Date.now() / 1e3) || !pl.sub) return null;
    return pl.sub;
  } catch (e) { return null; }
}
// يقبل FIREBASE_SA كاملًا، أو مقسّمًا على FIREBASE_SA_1 و FIREBASE_SA_2 و … (تُدمج بالترتيب) لتسهيل اللصق من الجوال
const saRaw = () => {
  let v = process.env.FIREBASE_SA || '';
  for (let i = 1; i <= 9; i++) v += process.env['FIREBASE_SA_' + i] || '';
  return v.trim();
};
const sa = () => { try { return JSON.parse(saRaw()); } catch (e) { return null; } };
const saReady = () => !!(sa() && sa().private_key && sa().client_email);
let at = null, atExp = 0;
async function access() {
  const c = sa(); if (!c) throw new Error('sa');
  if (at && Date.now() < atExp) return at;
  const n = Math.floor(Date.now() / 1e3), e64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const h = e64({ alg: 'RS256', typ: 'JWT' }), p = e64({ iss: c.client_email, scope: 'https://www.googleapis.com/auth/datastore', aud: 'https://oauth2.googleapis.com/token', iat: n, exp: n + 3600 });
  const sig = crypto.sign('RSA-SHA256', Buffer.from(h + '.' + p), c.private_key).toString('base64url');
  const r = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'grant_type=' + encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer') + '&assertion=' + h + '.' + p + '.' + sig });
  const j = await r.json(); if (!j.access_token) throw new Error('token');
  at = j.access_token; atExp = Date.now() + (j.expires_in - 120) * 1e3; return at;
}
const base = () => `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents/`;
const enc = (o) => ({ fields: Object.fromEntries(Object.entries(o).map(([k, v]) => [k, typeof v === 'number' ? { integerValue: String(Math.round(v)) } : { stringValue: String(v) }])) });
const dec = (d) => { const o = {}; for (const [k, v] of Object.entries((d && d.fields) || {})) o[k] = v.integerValue !== undefined ? +v.integerValue : v.doubleValue !== undefined ? v.doubleValue : v.stringValue; return o; };
async function fsGet(path) {
  const r = await fetch(base() + path, { headers: { authorization: 'Bearer ' + await access() } });
  if (r.status === 404) return null; if (!r.ok) throw new Error('fs' + r.status); return dec(await r.json());
}
async function fsSet(path, o) { // PATCH بلا updateMask = استبدال المستند (وإنشاؤه إن لم يوجد)
  const r = await fetch(base() + path, { method: 'PATCH', headers: { authorization: 'Bearer ' + await access(), 'content-type': 'application/json' }, body: JSON.stringify(enc(o)) });
  if (!r.ok) throw new Error('fs' + r.status);
}
// ---- أدوات للنسخ الاحتياطي من الخادم ----
async function fsList(path, mask) { // يعيد [{id, f}] مع تقليب الصفحات؛ mask = أسماء الحقول المطلوبة فقط (توفيرًا للحجم)
  const out = []; let tok = '';
  do {
    const q = 'pageSize=300' + (tok ? '&pageToken=' + encodeURIComponent(tok) : '') + (mask || []).map((m) => '&mask.fieldPaths=' + encodeURIComponent(m)).join('');
    const r = await fetch(base() + path + '?' + q, { headers: { authorization: 'Bearer ' + await access() } });
    if (r.status === 404) break;
    if (!r.ok) throw new Error('fs' + r.status);
    const j = await r.json();
    for (const d of j.documents || []) out.push({ id: d.name.split('/').pop(), f: dec(d) });
    tok = j.nextPageToken || '';
  } while (tok);
  return out;
}
async function fsCreate(path, o) { // ينشئ المستند فقط إن لم يكن موجودًا (لا يستبدل نسخة قائمة). يعيد true/false
  const r = await fetch(base() + path + '?currentDocument.exists=false', { method: 'PATCH', headers: { authorization: 'Bearer ' + await access(), 'content-type': 'application/json' }, body: JSON.stringify(enc(o)) });
  if (r.ok) return true;
  const t = await r.text().catch(() => '');
  if (r.status === 409 || /ALREADY_EXISTS|FAILED_PRECONDITION/.test(t)) return false;
  throw new Error('fs' + r.status);
}
async function fsDel(path) {
  const r = await fetch(base() + path, { method: 'DELETE', headers: { authorization: 'Bearer ' + await access() } });
  if (!r.ok && r.status !== 404) throw new Error('fs' + r.status);
}
// ---- الرصيد (نفس حدود الواجهة) ----
// المجاني: عند استنفاد 1200 وحدة يُسجَّل وقت الاستنفاد (ex) من الخادم، ويبدأ حجر 5 ساعات، ثم تعود الحصة كاملة تلقائيًا.
// بريميوم وبرو لا يتأثران بالحجر أبدًا (ex يُتجاهل ويُصفَّر عند الترقية).
const LIM = { free: { d: 1200 }, premium: { d: 3000, tm: 8000, tw: 2000 }, pro: { td: 3000 } };
const COOLDOWN = 5 * 3600 * 1000;
const day = () => Math.floor(Date.now() / 864e5);
// دالة نقية (قابلة للاختبار): تطبّع مستند الرصيد حسب الباقة والوقت وتطبّق التصفير المستحق. تعيد {u, changed}
function normalize(raw, plan, ti, now) {
  const u = Object.assign({}, raw || {});
  const before = JSON.stringify([u.d, u.g, u.td, u.tm, u.ti, u.ex]);
  u.g = +u.g || 0; u.td = +u.td || 0; u.tm = +u.tm || 0; u.ex = +u.ex || 0;
  const dd = Math.floor(now / 864e5);
  if (u.ti !== ti) { u.ti = ti; u.tm = 0; }
  if (plan === 'free') {
    if (!u.ex && u.d !== dd) { u.d = dd; u.g = 0; }                      // التجديد اليومي فقط خارج الحجر (وإلا يُتحايل على الخمس ساعات)
    u.td = 0;
    if (!u.ex && u.g >= LIM.free.d) u.ex = now;                         // استُنفد ولم يُسجَّل الحجر بعد (مستندات قديمة)
    if (u.ex && now >= u.ex + COOLDOWN) { u.g = 0; u.ex = 0; u.d = dd; } // انتهى الحجر: عودة الحصة كاملة مرة واحدة
  } else {
    if (u.d !== dd) { u.d = dd; u.g = 0; u.td = 0; }
    u.ex = 0; // الترقية تفكّ أي حجر فورًا
  }
  return { u, changed: before !== JSON.stringify([u.d, u.g, u.td, u.tm, u.ti, u.ex]) };
}
const save = (uid, u) => fsSet('usage/' + uid, { d: u.d, g: u.g, td: u.td, tm: u.tm, ti: u.ti || 0, ex: u.ex || 0, at: Date.now() });
async function usage(uid, ti, plan) {
  let raw; try { raw = (await fsGet('usage/' + uid)) || {}; } catch (e) { return null; }
  const r = normalize(raw, plan || 'free', ti, Date.now());
  if (r.changed) { try { await save(uid, r.u); } catch (e) { /* يُعاد الحفظ عند أول احتساب */ } }
  return r.u;
}
const remaining = (u, plan, k, tutor) => { const L = LIM[plan]; if (tutor) return plan === 'pro' ? L.td - u.td : plan === 'premium' ? (k === 'w' ? L.tw : L.tm) - u.tm : 0; return plan === 'pro' ? Infinity : L.d - u.g; };
// حالة الحجر للواجهة: يُرسلها الخادم مع الوقت الرسمي كي لا يعتمد العدّاد على ساعة الجهاز
const quotaView = (u, plan) => ({ plan, now: Date.now(), ex: plan === 'free' ? u.ex : 0, resetAt: plan === 'free' && u.ex ? u.ex + COOLDOWN : 0, used: u.g, limit: LIM.free.d, cooldownMs: COOLDOWN });
const cost = (i, o) => Math.max(6, Math.ceil(o / 4) + Math.ceil(i / 8) + 4);
async function charge(u, uid, plan, tutor, c) {
  if (tutor) { if (plan === 'pro') u.td += c; else u.tm += c; } else u.g += c;
  if (plan === 'free' && !u.ex && u.g >= LIM.free.d) u.ex = Date.now(); // لحظة الاستنفاد الفعلية من الخادم
  await save(uid, u);
}
module.exports = { verifyIdToken, saReady, fsGet, fsSet, fsList, fsCreate, fsDel, usage, remaining, cost, charge, normalize, quotaView, COOLDOWN, LIM };
