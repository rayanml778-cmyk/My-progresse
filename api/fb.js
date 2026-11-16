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
const dec = (d) => { const o = {}; for (const [k, v] of Object.entries((d && d.fields) || {})) o[k] = v.integerValue !== undefined ? +v.integerValue : v.stringValue; return o; };
async function fsGet(path) {
  const r = await fetch(base() + path, { headers: { authorization: 'Bearer ' + await access() } });
  if (r.status === 404) return null; if (!r.ok) throw new Error('fs' + r.status); return dec(await r.json());
}
async function fsSet(path, o) { // PATCH بلا updateMask = استبدال المستند (وإنشاؤه إن لم يوجد)
  const r = await fetch(base() + path, { method: 'PATCH', headers: { authorization: 'Bearer ' + await access(), 'content-type': 'application/json' }, body: JSON.stringify(enc(o)) });
  if (!r.ok) throw new Error('fs' + r.status);
}
// ---- الرصيد (نفس حدود الواجهة) ----
const LIM = { free: { d: 1200 }, premium: { d: 3000, tm: 8000, tw: 2000 }, pro: { td: 3000 } };
const day = () => Math.floor(Date.now() / 864e5);
async function usage(uid, ti) {
  let u; try { u = (await fsGet('usage/' + uid)) || {}; } catch (e) { return null; }
  if (u.d !== day()) { u.d = day(); u.g = 0; u.td = 0; }
  if (u.ti !== ti) { u.ti = ti; u.tm = 0; }
  u.g = +u.g || 0; u.td = +u.td || 0; u.tm = +u.tm || 0; return u;
}
const remaining = (u, plan, k, tutor) => { const L = LIM[plan]; if (tutor) return plan === 'pro' ? L.td - u.td : plan === 'premium' ? (k === 'w' ? L.tw : L.tm) - u.tm : 0; return plan === 'pro' ? Infinity : L.d - u.g; };
const cost = (i, o) => Math.max(6, Math.ceil(o / 4) + Math.ceil(i / 8) + 4);
async function charge(u, uid, plan, tutor, c) {
  if (tutor) { if (plan === 'pro') u.td += c; else u.tm += c; } else u.g += c;
  await fsSet('usage/' + uid, { d: u.d, g: u.g, td: u.td, tm: u.tm, ti: u.ti || 0 });
}
module.exports = { verifyIdToken, saReady, fsSet, usage, remaining, cost, charge };
