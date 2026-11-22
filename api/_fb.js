// api/_fb.js — التحقق من Firebase ID token + عدّاد الرصيد من جهة الخادم (Firestore REST بحساب خدمة، بلا مكتبات)
// المتغيرات: FIREBASE_SA = محتوى JSON لحساب الخدمة (Project settings › Service accounts)، FIREBASE_PROJECT_ID (اختياري)
const crypto = require('crypto');
const PROJECT = process.env.FIREBASE_PROJECT_ID || 'myprogress-6b9d9';
const b64 = (s) => Buffer.from(s, 'base64url');
let jwks = null, jwksAt = 0;
async function keys(force) { // لا نخزّن استجابة فارغة/فاشلة، ونعيد الجلب مرة عند عدم وجود kid (تدوير مفاتيح Google)
  const now = Date.now();
  if (jwks && jwks.length && (force ? now - jwksAt < 6e4 : now - jwksAt < 36e5)) return jwks;
  try {
    const r = await fetch('https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com');
    const ks = r.ok ? ((await r.json()).keys || []) : [];
    if (ks.length) { jwks = ks; jwksAt = now; }
  } catch (e) { /* نُبقي المفاتيح القديمة إن وُجدت */ }
  return jwks || [];
}
async function verifyPayload(t) { // يعيد حمولة الرمز كاملة (uid=sub، email، email_verified، والـ Custom Claims مثل admin) أو null
  try {
    if (typeof t !== 'string' || t.length > 4000) return null;
    const [h, p, s] = t.split('.'); if (!s) return null;
    const hd = JSON.parse(b64(h).toString()), pl = JSON.parse(b64(p).toString());
    if (hd.alg !== 'RS256') return null;
    let k = (await keys()).find((x) => x.kid === hd.kid); if (!k) k = (await keys(true)).find((x) => x.kid === hd.kid); if (!k) return null;
    const ok = crypto.verify('RSA-SHA256', Buffer.from(h + '.' + p), crypto.createPublicKey({ key: k, format: 'jwk' }), b64(s));
    if (!ok || pl.aud !== PROJECT || pl.iss !== 'https://securetoken.google.com/' + PROJECT || !(pl.exp > Date.now() / 1e3) || !pl.sub) return null;
    if (await isDisabled(pl.sub)) return null; // حساب موقوف: لا ننتظر انتهاء الرمز (حتى ساعة)
    return pl;
  } catch (e) { return null; }
}
async function verifyIdToken(t) { const p = await verifyPayload(t); return p ? p.sub : null; } // يعيد uid أو null
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
// ---- حسابات موقوفة: رمز Firebase يبقى صالحًا حتى ساعة بعد الإيقاف، فنرفضه فورًا عبر disabled/{uid} (يكتبها admin.js عند الإيقاف). ذاكرة 60 ث لكل نسخة ----
const disC = new Map();
async function isDisabled(uid) {
  const h = disC.get(uid), n = Date.now();
  if (h && n - h.t < 60000) return h.v;
  let v;
  try { v = !!(await fsGet('disabled/' + uid)); } catch (e) { return h ? h.v : false; } // تعطّل Firestore/عدم تهيئة الخدمة: آخر قيمة معروفة، لا نحجب الجميع
  if (disC.size > 5000) disC.clear();
  disC.set(uid, { t: n, v });
  return v;
}
async function markDisabled(uid, on) {
  if (on) await fsSet('disabled/' + uid, { at: Date.now() }); else await fsDel('disabled/' + uid);
  disC.set(uid, { t: Date.now(), v: !!on });
}
// ---- حدود معدّل مشتركة بين نسخ الخادم (Firestore: ratelimit/{sha1}) — نافذة ثابتة؛ قراءة ثم كتابة بلا معاملة فيجوز تجاوز طفيف تحت سباق شديد ----
const rlId = (k) => 'ratelimit/' + crypto.createHash('sha1').update(String(k)).digest('hex').slice(0, 24);
async function rlCount(key, win) { const d = await fsGet(rlId(key)); return d && Date.now() - (d.w || 0) < win ? (d.n || 0) : 0; }
async function rlAdd(key, win) {
  const now = Date.now(), p = rlId(key), d = await fsGet(p), live = d && now - (d.w || 0) < win, n = live ? (d.n || 0) + 1 : 1;
  await fsSet(p, { w: live ? d.w : now, n });
  return n;
}

// ---- Firebase Authentication (إدارة الحسابات + Custom Claims) — نفس ما يفعله Admin SDK عبر REST ----
const CP = 'https://www.googleapis.com/auth/cloud-platform';
const scoped = {};
async function accessFor(scope) { // رمز وصول مستقل لكل نطاق (لا يمس رمز Firestore أعلاه)
  const c = sa(); if (!c) throw new Error('sa');
  const hit = scoped[scope]; if (hit && Date.now() < hit.exp) return hit.at;
  const n = Math.floor(Date.now() / 1e3), e64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const h = e64({ alg: 'RS256', typ: 'JWT' }), p = e64({ iss: c.client_email, scope, aud: 'https://oauth2.googleapis.com/token', iat: n, exp: n + 3600 });
  const sig = crypto.sign('RSA-SHA256', Buffer.from(h + '.' + p), c.private_key).toString('base64url');
  const r = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'grant_type=' + encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer') + '&assertion=' + h + '.' + p + '.' + sig });
  const j = await r.json(); if (!j.access_token) throw new Error('token');
  scoped[scope] = { at: j.access_token, exp: Date.now() + (j.expires_in - 120) * 1e3 }; return j.access_token;
}
async function idt(path, opt) {
  const r = await fetch('https://identitytoolkit.googleapis.com/v1/projects/' + PROJECT + path, Object.assign({ headers: { authorization: 'Bearer ' + await accessFor(CP), 'content-type': 'application/json' } }, opt));
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error('idt' + r.status + ':' + ((j.error && j.error.message) || ''));
  return j;
}
const userView = (u) => { let cl = {}; try { cl = JSON.parse(u.customAttributes || '{}') || {}; } catch (e) { cl = {}; }
  return { uid: u.localId, email: u.email || '', name: u.displayName || '', verified: !!u.emailVerified, disabled: !!u.disabled, created: +u.createdAt || 0, last: +u.lastLoginAt || 0, claims: cl }; };
async function authLookup(q) { // q = {email:[..]} أو {localId:[..]} (حتى 100)
  const j = await idt('/accounts:lookup', { method: 'POST', body: JSON.stringify(q) });
  return (j.users || []).map(userView);
}
async function authList(max, token) {
  const j = await idt('/accounts:batchGet?maxResults=' + Math.min(1000, Math.max(1, max | 0)) + (token ? '&nextPageToken=' + encodeURIComponent(token) : ''), { method: 'GET' });
  return { users: (j.users || []).map(userView), next: j.nextPageToken || '' };
}
async function authSetClaims(uid, claims, extra) { // يستبدل customAttributes كاملة: ادمج القديمة قبل الاستدعاء
  await idt('/accounts:update', { method: 'POST', body: JSON.stringify(Object.assign({ localId: uid, customAttributes: JSON.stringify(claims) }, extra || {})) });
}
// ---- الرصيد (نفس حدود الواجهة) ----
// المجاني: عند استنفاد الحصة يُسجَّل وقت الاستنفاد (ex) من الخادم، ويبدأ حجر، ثم تعود الحصة كاملة تلقائيًا.
// بريميوم وبرو: نافذة شحن. أول استهلاك يبدأ النافذة (ws)، وعند انتهائها (ws + hours) يُعاد الرصيد كاملًا تلقائيًا.
//   إن نفد الرصيد قبل انتهاء النافذة يتوقف Moon AI حتى موعد الشحن. القيم قابلة للتعديل من لوحة المطوّر (config/quota) وتسري خلال ~30 ثانية.
const LIM = { free: { d: 1200 }, premium: { d: 3000, td: 1000 }, pro: { d: 9000, td: 3000 } }; // احتياطي قديم
const QDEF = { free: { tokens: 1200, hours: 5 }, premium: { tokens: 3000, hours: 6, tutor: 1000 }, pro: { tokens: 9000, hours: 6, tutor: 3000 } };
const COOLDOWN = 5 * 3600 * 1000;
const clampN = (v, a, b, d) => { v = +v; return Number.isFinite(v) ? Math.min(b, Math.max(a, v)) : d; };
// يطبّع/يقيّد إعدادات الرصيد القادمة من Firestore أو من اللوحة (قيم غير صالحة ← الافتراضي)
function qcfgFrom(doc) {
  const o = {};
  for (const p of ['free', 'premium', 'pro']) {
    const s = (doc && doc[p]) || {}, d = QDEF[p];
    o[p] = { tokens: Math.round(clampN(s.tokens, 100, 1e7, d.tokens)), hours: Math.round(clampN(s.hours, 0.1, 720, d.hours) * 100) / 100 };
    if (p !== 'free') o[p].tutor = Math.round(clampN(s.tutor, 0, 1e7, d.tutor));
  }
  return o;
}
let QC = qcfgFrom(null), QCAt = 0;
async function qcfg(force) {
  if (!force && Date.now() - QCAt < 30000) return QC;
  try {
    const d = await fsGet('config/quota'); let o = d;
    if (d && typeof d.j === 'string') { try { o = JSON.parse(d.j); } catch (e) { o = null; } } // الصيغة الجديدة: JSON نصي (الكائنات المتداخلة لا تُخزَّن عبر enc)
    QC = qcfgFrom(o); QCAt = Date.now();
  } catch (e) { /* نُبقي آخر قيم معروفة */ }
  return QC;
}
const winMs = (plan, c) => Math.round(((c || QC)[plan] || QC.free).hours * 36e5);
const day = () => Math.floor(Date.now() / 864e5);
// دالة نقية (قابلة للاختبار): تطبّع مستند الرصيد حسب الباقة والوقت وتطبّق التصفير المستحق. تعيد {u, changed}
function normalize(raw, plan, ti, now, cfg) {
  const C = cfg || QC;
  const u = Object.assign({}, raw || {});
  const before = JSON.stringify([u.d, u.g, u.td, u.tm, u.ti, u.ex, u.ws]);
  u.g = +u.g || 0; u.td = +u.td || 0; u.tm = +u.tm || 0; u.ex = +u.ex || 0; u.ws = +u.ws || 0;
  const dd = Math.floor(now / 864e5);
  if (u.ti !== ti) { u.ti = ti; u.tm = 0; if (plan !== 'free') { u.g = 0; u.ws = 0; } } // اشتراك جديد/ترقية = رصيد جديد
  if (plan === 'free') {
    const W = winMs('free', C), T = C.free.tokens;
    if (!u.ex && u.d !== dd) { u.d = dd; u.g = 0; }                      // التجديد اليومي فقط خارج الحجر (وإلا يُتحايل على الحجر)
    u.td = 0; u.ws = 0;
    if (!u.ex && u.g >= T) u.ex = now;                                  // استُنفد ولم يُسجَّل الحجر بعد (مستندات قديمة)
    if (u.ex && now >= u.ex + W) { u.g = 0; u.ex = 0; u.d = dd; }       // انتهى الحجر: عودة الحصة كاملة مرة واحدة
  } else {
    const W = winMs(plan, C);
    if (u.d !== dd) { u.d = dd; u.td = 0; }                             // رصيد المعلّم يومي
    u.ex = 0;
    if (u.g > 0 && !u.ws) u.ws = now;                                   // مستند قديم: تبدأ النافذة الآن
    if (u.ws && now >= u.ws + W) { u.g = 0; u.ws = 0; }                 // انتهت النافذة: شحن تلقائي كامل
  }
  return { u, changed: before !== JSON.stringify([u.d, u.g, u.td, u.tm, u.ti, u.ex, u.ws]) };
}
const save = (uid, u) => fsSet('usage/' + uid, { d: u.d, g: u.g, td: u.td, tm: u.tm, ti: u.ti || 0, ex: u.ex || 0, ws: u.ws || 0, tt: +u.tt || 0, at: Date.now() });
async function usage(uid, ti, plan) {
  await qcfg();
  let raw; try { raw = (await fsGet('usage/' + uid)) || {}; } catch (e) { return null; }
  const r = normalize(raw, plan || 'free', ti, Date.now());
  if (r.changed) { try { await save(uid, r.u); } catch (e) { /* يُعاد الحفظ عند أول احتساب */ } }
  return r.u;
}
const remaining = (u, plan, k, tutor) => { const L = QC[plan] || QC.free; if (tutor) return plan === 'free' ? 0 : L.tutor - u.td; return L.tokens - u.g; };
// حالة الرصيد للواجهة: يُرسلها الخادم مع الوقت الرسمي وإعدادات كل الباقات كي لا يعتمد العدّاد على ساعة الجهاز
const quotaView = (u, plan) => {
  const free = plan === 'free', L = QC[plan] || QC.free, W = winMs(plan);
  const cfg = {}; for (const p of ['free', 'premium', 'pro']) cfg[p] = { t: QC[p].tokens, h: QC[p].hours, td: QC[p].tutor || 0 };
  return { plan, now: Date.now(), ex: free ? u.ex : 0, ws: free ? 0 : (u.ws || 0), resetAt: free ? (u.ex ? u.ex + W : 0) : (u.ws ? u.ws + W : 0), used: u.g, limit: L.tokens, cooldownMs: W, tutorUsed: free ? 0 : u.td, tutorLimit: free ? 0 : L.tutor, cfg };
};
const cost = (i, o) => Math.max(6, Math.ceil(o / 4) + Math.ceil(i / 8) + 4);
async function charge(u, uid, plan, tutor, c) {
  if (tutor) u.td += c; else u.g += c;
  u.tt = (+u.tt || 0) + c; // إجمالي الاستهلاك منذ بدء التتبع (للإحصائيات)
  const now = Date.now();
  if (plan === 'free') { if (!u.ex && u.g >= QC.free.tokens) u.ex = now; }  // لحظة الاستنفاد الفعلية من الخادم
  else if (!tutor && !u.ws) u.ws = now;                                       // أول استهلاك يبدأ نافذة الشحن
  await save(uid, u);
}


// ---- حدود اللغات لكل باقة (config/langs) — تُطبَّق من الخادم في /api/chat. n = عدد اللغات التي يختارها المستخدم، l = اللغات المسموحة للباقة ----
const LANGS = ['ar', 'fr', 'en'];
const LDEF = { free: { n: 0, l: LANGS.slice() }, premium: { n: 1, l: LANGS.slice() }, pro: { n: 3, l: LANGS.slice() } };
function lcfgFrom(doc) {
  const o = {};
  for (const p of ['free', 'premium', 'pro']) {
    const s = (doc && doc[p]) || {}, d = LDEF[p];
    const l = Array.isArray(s.l) ? LANGS.filter((x) => s.l.includes(x)) : d.l.slice();
    o[p] = { n: Math.round(clampN(s.n, 0, 3, d.n)), l };
  }
  return o;
}
let LC = lcfgFrom(null), LCAt = 0;
async function lcfg(force) {
  if (!force && Date.now() - LCAt < 30000) return LC;
  try {
    const d = await fsGet('config/langs'); let o = null;
    if (d && typeof d.j === 'string') { try { o = JSON.parse(d.j); } catch (e) { o = null; } }
    LC = lcfgFrom(o); LCAt = Date.now();
  } catch (e) { /* نُبقي آخر قيم معروفة */ }
  return LC;
}

// ---- أعلام ميزات التعلّم (config/learnflags): wk تتبّع نقاط الضعف، btn أزرار الدروس في المحادثة، adapt تكيّف التمارين، tel إحصاءات الاستخدام ----
const LFDEF = { wk: 1, btn: 1, adapt: 1, tel: 1 };
function lfFrom(doc) {
  let o = null;
  if (doc && typeof doc.j === 'string') { try { o = JSON.parse(doc.j); } catch (e) { o = null; } }
  const r = {};
  for (const k of Object.keys(LFDEF)) r[k] = o && typeof o === 'object' && k in o ? (o[k] ? 1 : 0) : LFDEF[k];
  return r;
}
let LF = lfFrom(null), LFAt = 0;
async function lfcfg(force) {
  if (!force && Date.now() - LFAt < 30000) return LF;
  try { LF = lfFrom(await fsGet('config/learnflags')); LFAt = Date.now(); } catch (e) { /* نُبقي آخر قيم معروفة */ }
  return LF;
}

// ---- إيقاف/تفعيل حساب في Firebase Auth ----
async function authDisable(uid, on) { await idt('/accounts:update', { method: 'POST', body: JSON.stringify({ localId: uid, disableUser: !!on }) }); }
// ---- سجل عمليات الإدارة (audit/{id}): t=الوقت، k=النوع، by=المسؤول، + حقول حرة نصية/رقمية ----
const rid = () => Date.now().toString(36) + crypto.randomBytes(3).toString('hex');
async function audit(kind, by, data) { await fsSet('audit/' + rid(), Object.assign({ t: Date.now(), k: String(kind).slice(0, 20), by: String(by || '').slice(0, 120) }, data || {})); }
// ---- سجل أخطاء الخادم (errors/{id}) — بحد أقصى 20 سجلًا/دقيقة لكل نسخة تشغيل كي لا يتضخم ----
const errT = [];
async function logErr(kind, msg, uid) {
  try {
    const n = Date.now();
    while (errT.length && n - errT[0] > 6e4) errT.shift();
    if (errT.length >= 20 || !saReady()) return;
    errT.push(n);
    await fsSet('errors/' + rid(), { t: n, k: String(kind).slice(0, 30), m: String(msg == null ? '' : msg).slice(0, 300), u: String(uid || '').slice(0, 128) });
  } catch (e) { /* التسجيل لا يجوز أن يكسر الطلب */ }
}
// ---- إشعار عام (config/notice) وتعليمات إضافية للبرومبت (config/prompts): ذاكرة 30 ثانية ----
let NT = null, NTAt = 0;
async function noticeGet(force) {
  if (!force && Date.now() - NTAt < 30000) return NT;
  try {
    const d = await fsGet('config/notice');
    NT = d && d.id && d.text && (!d.exp || d.exp > Date.now()) ? { id: d.id, title: d.title || '', text: d.text, lvl: d.lvl || 'info', at: d.at || 0 } : null;
    NTAt = Date.now();
  } catch (e) { /* نُبقي آخر قيمة */ }
  return NT;
}
let PR = {}, PRAt = 0;
async function promptsGet(force) {
  if (!force && Date.now() - PRAt < 30000) return PR;
  try {
    const d = (await fsGet('config/prompts')) || {};
    PR = { all: String(d.all || ''), ar: String(d.ar || ''), fr: String(d.fr || ''), en: String(d.en || '') };
    PRAt = Date.now();
  } catch (e) { /* نُبقي آخر قيمة */ }
  return PR;
}
// ---- مقاييس يومية مجمّعة (metrics/{YYYY-MM-DD}) — يكتبها الخادم فقط. عدّادات بلا أي نصوص أو بيانات شخصية.
//   rq طلبات Moon AI | ok ناجحة | er فاشلة | r_<plan> طلبات الباقة | t_<plan> وحدات الرصيد المخصومة | tu طلبات المعلّم | qx رفض بسبب نفاد الرصيد | af فشل دخول لوحة الإدارة
// قراءة ثم كتابة بلا معاملة: قد يُفقد عدّ طفيف تحت تزامن شديد (العرض إحصائي فقط، لا يُبنى عليه قرار مالي).
const dkey = (t) => new Date(t == null ? Date.now() : t).toISOString().slice(0, 10);
async function mtInc(delta) {
  try {
    if (!saReady()) return;
    const p = 'metrics/' + dkey(), cur = await fsGet(p).catch(() => null);
    let o = {}; try { o = JSON.parse((cur && cur.j) || '{}') || {}; } catch (e) { o = {}; }
    for (const [k, v] of Object.entries(delta || {})) if (/^[a-z_]{1,14}$/.test(k) && Number.isFinite(+v)) o[k] = (+o[k] || 0) + Math.round(+v);
    await fsSet(p, { j: JSON.stringify(o), at: Date.now() });
  } catch (e) { /* القياس لا يجوز أن يكسر الطلب */ }
}
async function mtRange(days) { // [{d:'YYYY-MM-DD', c:{...}}] تصاعديًا، آخر days يومًا فقط
  const rows = await fsList('metrics', ['j']);
  rows.sort((x, y) => (x.id < y.id ? -1 : 1));
  if (rows.length > 150) await Promise.all(rows.slice(0, rows.length - 150).slice(0, 50).map((r) => fsDel('metrics/' + r.id).catch(() => {})));
  return rows.slice(-Math.max(1, days | 0)).map(({ id, f }) => { let o = {}; try { o = JSON.parse(f.j || '{}') || {}; } catch (e) { o = {}; } return { d: id, c: o }; });
}
// استعلام مدى على حقل نصي واحد (مثل d='YYYY-MM-DD') عبر runQuery — فهرس الحقل الواحد تلقائي، فلا حاجة لفهرس مركّب
async function fsRange(coll, field, from, to, mask, limit) {
  const body = { structuredQuery: { from: [{ collectionId: coll }], limit: Math.min(+limit || 5000, 20000),
    where: { compositeFilter: { op: 'AND', filters: [{ fieldFilter: { field: { fieldPath: field }, op: 'GREATER_THAN_OR_EQUAL', value: { stringValue: String(from) } } }, { fieldFilter: { field: { fieldPath: field }, op: 'LESS_THAN_OR_EQUAL', value: { stringValue: String(to) } } }] } },
    select: { fields: (mask || []).map((m) => ({ fieldPath: m })) } } };
  const r = await fetch(base().replace(/\/$/, '') + ':runQuery', { method: 'POST', headers: { authorization: 'Bearer ' + await access(), 'content-type': 'application/json' }, body: JSON.stringify(body) });
  if (!r.ok) throw new Error('fs' + r.status);
  const j = await r.json(); const out = [];
  for (const x of j || []) if (x.document) out.push({ id: x.document.name.split('/').pop(), f: dec(x.document) });
  return out;
}
module.exports = { fsRange, mtInc, mtRange, dkey, authDisable, audit, logErr, noticeGet, promptsGet, verifyIdToken, verifyIdTokenFull: verifyPayload, authLookup, authList, authSetClaims, saReady, fsGet, fsSet, fsList, fsCreate, fsDel, usage, remaining, cost, charge, normalize, quotaView, COOLDOWN, LIM, QDEF, qcfg, qcfgFrom, winMs, LANGS, LDEF, lcfg, lcfgFrom, LFDEF, lfFrom, lfcfg, isDisabled, markDisabled, rlCount, rlAdd, rid };
