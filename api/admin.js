// api/admin.js — واجهة لوحة المطوّر (للمالك فقط). كل العمليات الإدارية تُنفَّذ هنا على الخادم.
// الدخول: Authorization: Bearer <Firebase ID token> لحساب المالك الوحيد (OWNER أدناه)، ويُشترط فيه:
//   1) توقيع Firebase سليم  2) البريد = OWNER ومُوثَّق  3) Custom Claim  admin:true  (يُمنح من الخادم فقط عبر action:'bootstrap')
// مسار قديم اختياري (ما زال يعمل): Authorization: Bearer <ADMIN_SECRET> (32 حرفًا فأكثر، منفصل عن PLAN_SECRET) — لأوامر mint/revoke/info وغيرها.
// كل الطلبات POST JSON { action, ... }:
//   whoami                      يتحقق من صلاحية المالك
//   bootstrap                   أول مرة فقط: يمنح الحساب admin:true. يتطلب رمز المالك + ترويسة x-admin-secret = ADMIN_SECRET
//   stats                       إحصائيات المستخدمين والأكواد والاشتراكات والمدفوعات
//   mint     { plan, period, count?:1..100, days?, valid_days?, note? }   أكواد فردية/جماعية (يعيد النص الصريح)
//   codes                       قائمة الأكواد وحالاتها (النص الصريح للأكواد غير المستخدمة فقط، لنسخها)
//   revoke   { uid } | { code } | { cid }   إلغاء اشتراك حساب، أو إبطال كود (وإلغاء الاشتراك الناتج عنه إن استُخدم)
//   info     { uid } | { code }
//   users    { q?, cursor? }    قائمة الحسابات مع اشتراكاتها (q = بريد أو uid)
//   grant    { uid, plan, period, days? }   منح اشتراك يدويًا
//   payments { status? }        طلبات الاشتراك بالتحويل البنكي
//   pay_proof { id }            صورة إثبات التحويل
//   pay_approve { id, days? }   قبول الطلب وتفعيل الاشتراك تلقائيًا (قفل ذري: لا يُفعَّل مرتين)
//   pay_reject  { id, reason? } رفض الطلب
//   bank_get / bank_set { text }   بيانات الحساب البنكي التي تظهر للمستخدمين
//   quota_get / quota_set { cfg:{free,premium,pro:{tokens,hours,tutor?}} }   قيم رصيد Moon AI وساعات الشحن لكل باقة (config/quota) — كل تغيير يُسجَّل في audit (القيمة السابقة/الجديدة/الوقت/المسؤول)
//   audit_list { kind? }        سجل عمليات الإدارة (quota | grant | revoke | disable | enable | notice | prompt …)
//   user_set { uid, disabled }  إيقاف/تفعيل حساب (Firebase Auth)
//   insights                    اللغات الأكثر اختيارًا + استهلاك التوكن (حالي/إجمالي/لكل باقة/الأعلى استهلاكًا)
//   notice_get / notice_set { title?, text, lvl?, days? } / notice_clear   إشعار لكل المستخدمين (يصل مع /api/quota)
//   prompts_get / prompts_set { lang: all|ar|fr|en, text }   تعليمات إضافية تُلحق ببرومبت النظام في /api/chat
//   errors_list / errors_clear  سجل أخطاء الخادم
//   lang_get / lang_set { cfg:{free,premium,pro:{n,l:['ar','fr','en']}} }   حدود لغات المعلّم لكل باقة (config/langs): n = عدد اللغات التي يختارها المستخدم، l = اللغات المسموحة. يُطبَّقان في /api/chat من الخادم.
//   reports_list { status? }   بلاغات المستخدمين (reports/{MP-XXXXXX}) + عدّاد الحالات   |   report_get { id }  تفاصيل + أخطاء الخادم لنفس الحساب
//   report_set { id, st }      الحالة: new | review | solved | closed   |   report_reply { id, text, st? }  ردّ يراه المستخدم في تطبيقه   |   report_note { id, text }  ملاحظة خاصة بالمطوّر
const crypto = require('crypto');
const { adminInfo, secretInfo, sign, codeId, codeNorm, genCode, forget, verifyToken } = require('./_plan');
const { saReady, fsGet, fsSet, fsCreate, fsDel, fsList, verifyIdTokenFull, authLookup, authList, authSetClaims, authDisable, audit, noticeGet, promptsGet, winMs, QDEF, qcfg, qcfgFrom, LDEF, lcfg, lcfgFrom, LFDEF, lfcfg, markDisabled, rlCount, rlAdd, mtInc, mtRange, logErr, fsRange } = require('./_fb');
const gh = require('./_gh'); // مدير الملفات عبر Git (GitHub REST)

const OWNER = 'rayanml778@gmail.com'; // المالك الوحيد
const DAY = 86400000;
const bad = new Map(), dbf = new Set();
const send = (res, code, obj) => {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(obj));
};
// تفصيل خطأ آمن للعرض للمالك: رمز Google فقط (مثل idt403:PERMISSION_DENIED أو sa أو token)، بلا أي نص آخر
const sdet = (e) => { const m = String((e && e.message) || ''); return /^(idt\d{3}:[A-Z_ ]{0,60}|sa|token)$/.test(m) ? m : 'unknown'; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
const safeEq = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const int = (v, d, lo, hi) => { const n = parseInt(v, 10); return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : d; };
const UID = /^[A-Za-z0-9_-]{6,128}$/, PID = /^[a-f0-9]{20}$/, CID = /^[a-f0-9]{64}$/;
const PLANS = ['premium', 'pro'];
const RST = ['new', 'review', 'solved', 'closed'], RID = /^MP-[A-Z2-9]{6}$/;

// ---- خزنة الأكواد: النص الصريح مشفّر (AES-256-GCM) بمفتاح مشتق من PLAN_SECRET، ليتمكن المالك من نسخ الأكواد غير المستخدمة لاحقًا ----
const vkey = (s) => crypto.createHash('sha256').update('mp-code-vault:' + s).digest();
function seal(text, id, s) {
  const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', vkey(s), iv);
  c.setAAD(Buffer.from(id));
  const enc = Buffer.concat([c.update(text, 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), enc]).toString('base64url');
}
function unseal(v, id, s) {
  try {
    const b = Buffer.from(String(v), 'base64url'), d = crypto.createDecipheriv('aes-256-gcm', vkey(s), b.subarray(0, 12));
    d.setAAD(Buffer.from(id)); d.setAuthTag(b.subarray(12, 28));
    return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString('utf8');
  } catch (e) { return ''; }
}

// ---- الاشتراكات ----
async function revokeUid(uid, cid) { // cid اختياري: لا يُلغى إلا اشتراك ناتج عن هذا الكود
  const ent = await fsGet('entitlements/' + uid);
  if (!ent || !ent.tok || +ent.rv) return false;
  if (cid && ent.cid !== cid) return false;
  await fsSet('entitlements/' + uid, { tok: '', at: Date.now(), cid: ent.cid || '', pl: ent.pl || '', exp: 0, rv: Date.now() });
  forget(uid);
  return true;
}
// يمنح اشتراكًا (يُوقَّع من الخادم ويُكتب في entitlements/{uid}؛ التطبيق يلتقطه فورًا عبر onSnapshot). نفس الباقة النشطة = تمديد.
async function grant(uid, plan, k, days, cid, now) {
  const cur = await fsGet('entitlements/' + uid);
  const start = cur && cur.tok && !+cur.rv && cur.exp > now && cur.pl === plan ? cur.exp : now;
  const exp = start + days * DAY;
  const token = sign({ p: plan, k, i: now, e: exp, u: uid, c: String(cid).slice(0, 16) });
  if (!token) throw new Error('sign');
  await fsSet('entitlements/' + uid, { tok: token, at: now, cid, pl: plan, exp, rv: 0 });
  forget(uid);
  return { exp };
}
async function setReq(uid, id, patch) { // حالة آخر طلب للمستخدم (payreq/{uid}) كي يراها في التطبيق
  const r = await fsGet('payreq/' + uid).catch(() => null);
  if (r && r.id === id) await fsSet('payreq/' + uid, Object.assign({}, r, patch));
}
async function emailsFor(uids) {
  const out = {};
  for (let i = 0; i < uids.length; i += 100) {
    try { for (const u of await authLookup({ localId: uids.slice(i, i + 100) })) out[u.uid] = u.email; } catch (e) { /* العرض فقط */ }
  }
  return out;
}
async function entMap() {
  const m = {};
  for (const r of await fsList('entitlements', ['pl', 'exp', 'rv', 'cid', 'at'])) m[r.id] = r.f;
  return m;
}
const activeOf = (e, now) => !!(e && +e.exp > now && !+e.rv);
// استهلاك الرصيد الحالي لحساب (نفس منطق insights: لا يُحتسب إلا إن كانت نافذة الشحن سارية)
function tokUse(f, e, now, cfg) {
  const pl = activeOf(e, now) ? (e.pl === 'pro' ? 'pro' : 'premium') : 'free', W = winMs(pl, cfg), dd = Math.floor(now / DAY);
  const g = pl === 'free' ? (+f.ex ? (now < f.ex + W ? +f.g || 0 : 0) : (f.d === dd ? +f.g || 0 : 0)) : (+f.ws && now < f.ws + W ? +f.g || 0 : 0);
  return { pl, g, td: pl !== 'free' && f.d === dd ? +f.td || 0 : 0, tt: +f.tt || 0 };
}
// ---- تحليلات الاستخدام: التجميع من وثائق ua/{uid}_{day} (وقت نشط/خامل بالثواني + زيارات ووقت كل قسم) ----
const DREG = /^\d{4}-\d{2}-\d{2}$/;
const wkKey = (d) => { const t = Date.parse(d + 'T00:00:00Z'), dow = (new Date(t).getUTCDay() + 6) % 7; return new Date(t - dow * DAY).toISOString().slice(0, 10); };
const bkOf = (d, b) => (b === 'month' ? d.slice(0, 7) : b === 'week' ? wkKey(d) : d);
function uaAgg(rows, bucket) {
  const tot = { a: 0, i: 0, n: 0 }, sec = {}, ser = {}, ssr = {}, us = {}, days = new Set(), wks = new Set(), mos = new Set();
  for (const { f } of rows) {
    let j = {}; try { j = JSON.parse(f.j || '{}') || {}; } catch (e) { j = {}; }
    const a = +f.a || 0, i = +f.i || 0, n = +f.n || 0, b = bkOf(f.d, bucket), T = j.t || {}, V = j.v || {};
    tot.a += a; tot.i += i; tot.n += n;
    if (a > 0) { days.add(f.u + f.d); wks.add(f.u + wkKey(f.d)); mos.add(f.u + f.d.slice(0, 7)); }
    const s = ser[b] || (ser[b] = { a: 0, i: 0, n: 0, u: new Set() }); s.a += a; s.i += i; s.n += n; if (a > 0) s.u.add(f.u);
    const sb = ssr[b] || (ssr[b] = {}), u = us[f.u] || (us[f.u] = { uid: f.u, a: 0, i: 0, n: 0, days: new Set(), sec: {}, last: 0 });
    u.a += a; u.i += i; u.n += n; if (a > 0) u.days.add(f.d); u.last = Math.max(u.last, +f.last || 0);
    for (const k of new Set([...Object.keys(T), ...Object.keys(V)])) {
      const e = sec[k] || (sec[k] = { k, s: 0, v: 0, u: new Set() }); e.s += +T[k] || 0; e.v += +V[k] || 0; e.u.add(f.u);
      sb[k] = (sb[k] || 0) + (+T[k] || 0); u.sec[k] = (u.sec[k] || 0) + (+T[k] || 0);
    }
  }
  const secS = Object.values(sec).sort((x, y) => y.s - x.s), sumS = secS.reduce((x, y) => x + y.s, 0), sumV = secS.reduce((x, y) => x + y.v, 0);
  const users = Object.values(us).sort((x, y) => y.a - x.a || y.i - x.i || (x.uid < y.uid ? -1 : 1)).map((u) => ({ uid: u.uid, a: u.a, i: u.i, n: u.n, days: u.days.size, avgSession: u.n ? Math.round(u.a / u.n) : 0, last: u.last,
    top: Object.entries(u.sec).sort((x, y) => y[1] - x[1])[0] ? Object.entries(u.sec).sort((x, y) => y[1] - x[1])[0][0] : '', sec: u.sec }));
  const avg = (x, d) => (d ? Math.round(x / d) : 0);
  return { totals: { a: tot.a, i: tot.i, n: tot.n, users: users.length, activeUsers: users.filter((u) => u.a > 0).length, avgSession: avg(tot.a, tot.n), avgDay: avg(tot.a, days.size), avgWeek: avg(tot.a, wks.size), avgMonth: avg(tot.a, mos.size), idleShare: tot.a + tot.i ? Math.round(tot.i / (tot.a + tot.i) * 100) : 0 },
    series: Object.keys(ser).sort().map((b) => ({ b, a: ser[b].a, i: ser[b].i, n: ser[b].n, u: ser[b].u.size })), secSeries: Object.keys(ssr).sort().map((b) => ({ b, t: ssr[b] })),
    sections: secS.map((e) => ({ k: e.k, s: e.s, v: e.v, u: e.u.size, shareT: sumS ? Math.round(e.s / sumS * 1000) / 10 : 0, shareV: sumV ? Math.round(e.v / sumV * 1000) / 10 : 0 })), users };
}
// عمليات تُسجَّل في audit حتى عند فشلها (kind='fail')
const SENS = new Set(['files_commit', 'mint', 'revoke', 'grant', 'pay_approve', 'pay_reject', 'bank_set', 'quota_set', 'lang_set', 'learn_set', 'learn_clear', 'user_set', 'notice_set', 'notice_clear', 'prompts_set', 'errors_clear', 'report_set', 'report_reply', 'report_note']);

// ---- المصادقة ----
async function authenticate(req) {
  const given = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!given) return null;
  if (given.split('.').length === 3) { // Firebase ID token
    const p = await verifyIdTokenFull(given);
    if (!p || String(p.email || '').toLowerCase() !== OWNER) return null;
    return { kind: 'token', uid: p.sub, email: OWNER, owner: p.admin === true && p.email_verified === true };
  }
  const ai = adminInfo();
  if (ai.ok && safeEq(given, ai.s)) return { kind: 'secret', owner: true };
  return null;
}

module.exports = async function handler(req, res) {
  let _by = '', _bu = '', _act = ''; // لتسجيل فشل العمليات الحساسة في الـ catch
  try {
    if (req.method !== 'POST') { res.setHeader('Allow', 'POST'); return send(res, 405, { code: 'method' }); }
    if (!saReady()) return send(res, 503, { code: 'conf' });

    const ip = String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'x').split(',')[0].trim();
    const now = Date.now();
    const fails = (bad.get(ip) || []).filter((t) => now - t < 10 * 60 * 1000);
    if (fails.length >= 10) return send(res, 429, { code: 'slow' });
    if ((await rlCount('adm:' + ip, 600000).catch(() => 0)) >= 10) return send(res, 429, { code: 'slow' }); // حدّ مشترك بين النسخ
    const fail = async (why) => { await mtInc({ af: 1 }); if (fails.length % 5 === 0) await logErr('admin_auth', 'forbidden', ''); /* سجل واحد لكل 5 محاولات من نفس العنوان: logErr له سقف 20/دقيقة لكل النسخة، فلا نسمح لهجوم تخمين بإغراقه وإخفاء أخطاء أخرى */ fails.push(Date.now()); bad.set(ip, fails); if (bad.size > 500) bad.clear(); await rlAdd('adm:' + ip, 600000).catch(() => {}); await sleep(700); return send(res, 403, why ? { code: 'forbidden', why } : { code: 'forbidden' }); };

    const a = await authenticate(req);
    if (!a) return fail();

    let body = req.body;
    if (typeof body === 'string') { try { body = JSON.parse(body); } catch (e) { body = null; } }
    if (!body || typeof body !== 'object') return send(res, 400, { code: 'bad' });
    const act = String(body.action || '');
    const by = a.kind === 'token' ? a.email : 'secret', bu = a.uid || ''; // المسؤول الذي ينفّذ العملية (لسجل التدقيق)
    _by = by; _bu = bu; _act = act;
    const aud = (k, d) => audit(k, by, Object.assign({ bu, r: 'ok' }, d)).catch((e) => console.error('[audit]', e && e.message)); // فشل السجل لا يُفشل العملية

    // أول مرة: منح حساب المالك صلاحية الإدارة. شرطان معًا: رمز المالك + ADMIN_SECRET (يعيّنه المالك في Vercel).
    if (act === 'bootstrap') {
      // الأسباب أدناه لا تُعاد إلا لمن اجتاز رمز Firebase الخاص بالمالك (a.kind === 'token' يعني بريد المالك وتوقيعًا سليمًا). لا قيم أسرار في السجل ولا في الرد.
      const deny = async (why) => { console.error('[admin] bootstrap denied:', why); return fail(why); };
      if (a.kind !== 'token') return deny('need_token');
      const ai = adminInfo();
      if (!ai.ok) return deny('secret_' + ai.why); // missing | short | reused
      const given = String(req.headers['x-admin-secret'] || '').trim();
      if (!given) return deny('header_missing');
      if (!safeEq(given, ai.s)) return deny('secret_mismatch');
      let u;
      try { [u] = await authLookup({ localId: [a.uid] }); }
      catch (e) { console.error('[admin] bootstrap lookup failed:', e && e.message); return send(res, 502, { code: 'err', why: 'lookup_failed', detail: sdet(e) }); }
      if (!u || String(u.email).toLowerCase() !== OWNER) return deny('email_mismatch');
      try { await authSetClaims(a.uid, Object.assign({}, u.claims, { admin: true }), { emailVerified: true }); }
      catch (e) { console.error('[admin] bootstrap claims failed:', e && e.message); return send(res, 502, { code: 'err', why: 'claims_failed', detail: sdet(e) }); }
      console.log('[admin] bootstrap ok: admin claim granted to owner');
      return send(res, 200, { ok: true });
    }
    if (!a.owner) return send(res, 403, { code: 'forbidden', need: a.kind === 'token' ? 'claim' : '' });

    if (act === 'whoami') return send(res, 200, { owner: true, email: OWNER, via: a.kind });

    // ---- إنشاء الأكواد ----
    if (act === 'mint') {
      const plan = PLANS.includes(body.plan) ? body.plan : '';
      const k = body.period === 'week' ? 'w' : body.period === 'month' ? 'm' : '';
      if (!plan || !k) return send(res, 400, { code: 'bad' });
      const count = int(body.count, 1, 1, 100);
      const days = int(body.days, k === 'w' ? 7 : 30, 1, 366);
      const xp = now + int(body.valid_days, 30, 1, 365) * DAY;
      const note = String(body.note || '').slice(0, 60);
      const bt = crypto.randomBytes(4).toString('hex'), si = secretInfo();
      const make = async () => {
        for (let t = 0; t < 5; t++) { // تصادم شبه مستحيل؛ المحاولة الإضافية للأمان فقط
          const c = genCode(), id = codeId(c), rec = { p: plan, k, days, xp, st: 'new', note, cr: now, bt };
          if (si.ok) rec.ce = seal(c, id, si.s);
          if (await fsCreate('codes/' + id, rec)) return c;
        }
        return null;
      };
      const codes = [];
      for (let i = 0; i < count; i += 10) for (const c of await Promise.all(Array.from({ length: Math.min(10, count - i) }, make))) if (c) codes.push(c);
      await aud('mint', { d: plan + ' · ' + k + ' · ' + codes.length + ' · ' + days + 'd · ' + bt });
      return send(res, 200, { codes, plan, period: k === 'w' ? 'week' : 'month', days, validUntil: xp, batch: bt });
    }

    if (act === 'codes') {
      const si = secretInfo();
      const rows = (await fsList('codes', ['p', 'k', 'days', 'xp', 'st', 'note', 'cr', 'u', 'at', 'bt', 'ce'])).sort((x, y) => (y.f.cr || 0) - (x.f.cr || 0)).slice(0, 600);
      const em = await emailsFor([...new Set(rows.map((r) => r.f.u).filter(Boolean))]);
      return send(res, 200, {
        codes: rows.map(({ id, f }) => {
          const state = f.st === 'new' && f.xp && f.xp < now ? 'expired' : f.st;
          return { id, p: f.p, k: f.k, days: f.days, xp: f.xp || 0, st: state, note: f.note || '', cr: f.cr || 0, at: f.at || 0, bt: f.bt || '',
            user: f.u ? { uid: f.u, email: em[f.u] || '' } : null,
            code: state === 'new' && f.ce && si.ok ? unseal(f.ce, id, si.s) : '' };
        }),
      });
    }

    // ---- إلغاء/معلومات (الأوامر القديمة كما هي + إلغاء بمعرّف الكود cid من القائمة) ----
    if (act === 'revoke' || act === 'info') {
      const wantInfo = act === 'info';
      if (body.uid) {
        const uid = String(body.uid);
        if (!UID.test(uid)) return send(res, 400, { code: 'bad' });
        if (wantInfo) {
          const e = await fsGet('entitlements/' + uid);
          return send(res, 200, { exists: !!e, plan: e && e.pl || '', exp: e && e.exp || 0, revokedAt: e && +e.rv || 0, active: !!(e && e.tok && !(+e.rv) && e.exp > now), code: e && e.cid ? e.cid.slice(0, 16) : '' });
        }
        const rvk = await revokeUid(uid); if (rvk) await aud('revoke', { u: uid, d: 'sub' });
        return send(res, 200, { revoked: rvk });
      }
      let id = '';
      if (body.cid) { if (!CID.test(String(body.cid))) return send(res, 400, { code: 'bad' }); id = String(body.cid); }
      else if (body.code) { const norm = codeNorm(body.code); if (norm.length < 16) return send(res, 400, { code: 'bad' }); id = codeId(norm); }
      if (id) {
        const rec = await fsGet('codes/' + id);
        if (!rec) return send(res, 404, { code: 'none' });
        const cl = await fsGet('redeemed/' + id).catch(() => null);
        if (wantInfo) return send(res, 200, { st: rec.st, plan: rec.p, days: rec.days, validUntil: rec.xp, usedBy: cl ? cl.u : '', usedAt: cl ? cl.at : 0, note: rec.note || '' });
        await fsSet('codes/' + id, Object.assign({}, rec, { st: 'revoked', rat: now, ce: '' }));
        const sub = cl && cl.u ? await revokeUid(cl.u, id) : false;
        await aud('revoke', { u: cl && cl.u ? cl.u : '', d: 'code ' + id.slice(0, 8) + (sub ? ' +sub' : '') });
        return send(res, 200, { revokedCode: true, revokedSubscription: sub });
      }
      return send(res, 400, { code: 'bad' });
    }

    // ---- المستخدمون ----
    if (act === 'users') {
      const q = String(body.q || '').trim().toLowerCase().slice(0, 128);
      let list = [], next = '';
      if (q) list = q.includes('@') ? await authLookup({ email: [q] }) : UID.test(q) ? await authLookup({ localId: [q] }) : [];
      else { const r = await authList(100, String(body.cursor || '').slice(0, 2000)); list = r.users; next = r.next; }
      const ents = await entMap();
      for (const u of list) if (u.disabled && !dbf.has(u.uid)) { dbf.add(u.uid); await markDisabled(u.uid, true).catch(() => dbf.delete(u.uid)); } // ترحيل الحسابات الموقوفة قبل هذا التحديث (مرة لكل نسخة)
      return send(res, 200, {
        next,
        users: list.map((u) => { const e = ents[u.uid]; return { uid: u.uid, email: u.email, name: u.name, verified: u.verified, disabled: u.disabled, created: u.created, last: u.last,
          plan: activeOf(e, now) ? e.pl : '', exp: e ? +e.exp || 0 : 0, revoked: e ? +e.rv || 0 : 0, owner: String(u.email).toLowerCase() === OWNER }; }),
      });
    }
    if (act === 'grant') {
      const uid = String(body.uid || ''), plan = PLANS.includes(body.plan) ? body.plan : '', k = body.period === 'week' ? 'w' : body.period === 'month' ? 'm' : '';
      if (!UID.test(uid) || !plan || !k) return send(res, 400, { code: 'bad' });
      const [u] = await authLookup({ localId: [uid] });
      if (!u) return send(res, 404, { code: 'none' });
      const dys = int(body.days, k === 'w' ? 7 : 30, 1, 366);
      const r = await grant(uid, plan, k, dys, 'adm-' + crypto.randomBytes(6).toString('hex'), now);
      await aud('grant', { u: uid, d: plan + ' · ' + dys });
      return send(res, 200, { granted: true, exp: r.exp });
    }

    // ---- طلبات الاشتراك بالتحويل البنكي ----
    if (act === 'payments') {
      const st = ['pending', 'approved', 'rejected'].includes(body.status) ? body.status : '';
      let rows = await fsList('payments', ['uid', 'email', 'p', 'k', 'amt', 'paid', 'ref', 'st', 'cr', 'rv', 'rn', 'ex', 'hp']);
      if (st) rows = rows.filter((r) => r.f.st === st);
      rows.sort((x, y) => (y.f.cr || 0) - (x.f.cr || 0));
      return send(res, 200, { payments: rows.slice(0, 300).map(({ id, f }) => Object.assign({ id }, f)) });
    }
    if (act === 'pay_proof') {
      const id = String(body.id || ''); if (!PID.test(id)) return send(res, 400, { code: 'bad' });
      const pr = await fsGet('paymentProofs/' + id);
      return pr && /^data:image\//.test(pr.img || '') ? send(res, 200, { img: pr.img }) : send(res, 404, { code: 'none' });
    }
    if (act === 'pay_approve' || act === 'pay_reject') {
      const id = String(body.id || ''); if (!PID.test(id)) return send(res, 400, { code: 'bad' });
      const pay = await fsGet('payments/' + id);
      if (!pay) return send(res, 404, { code: 'none' });
      if (pay.st !== 'pending') return send(res, 409, { code: 'done', st: pay.st });
      if (!(await fsCreate('payclaim/' + id, { at: now }))) return send(res, 409, { code: 'busy' }); // قفل ذري: قبول/رفض واحد فقط
      if (act === 'pay_reject') {
        const rn = String(body.reason || '').trim().slice(0, 200);
        try { await fsSet('payments/' + id, Object.assign({}, pay, { st: 'rejected', rv: now, rn })); }
        catch (e) { try { await fsDel('payclaim/' + id); } catch (e2) { /* يبقى القفل */ } throw e; }
        try { await setReq(pay.uid, id, { st: 'rejected', rv: now, rn }); } catch (e) { console.error('[admin] req', e && e.message); }
        await aud('pay_no', { u: pay.uid, d: id + (rn ? ' · ' + rn.slice(0, 100) : '') });
        return send(res, 200, { rejected: true });
      }
      if (!PLANS.includes(pay.p) || (pay.k !== 'w' && pay.k !== 'm') || !UID.test(String(pay.uid))) { try { await fsDel('payclaim/' + id); } catch (e) { /* */ } return send(res, 400, { code: 'bad' }); }
      let r;
      try { r = await grant(pay.uid, pay.p, pay.k, int(body.days, pay.k === 'w' ? 7 : 30, 1, 366), 'pay-' + id, now); }
      catch (e) { try { await fsDel('payclaim/' + id); } catch (e2) { /* يُحرَّر يدويًا */ } throw e; } // لم يُسلَّم اشتراك: يُحرَّر القفل لإعادة المحاولة
      try { await fsSet('payments/' + id, Object.assign({}, pay, { st: 'approved', rv: now, ex: r.exp })); await setReq(pay.uid, id, { st: 'approved', rv: now }); }
      catch (e) { console.error('[admin] mark', e && e.message); } // الاشتراك سُلِّم والقفل هو المرجع؛ الوسم للعرض فقط
      await aud('pay_ok', { u: pay.uid, d: id + ' · ' + pay.p + ' · ' + pay.k + ' · ' + (+pay.amt || 0) });
      return send(res, 200, { approved: true, exp: r.exp });
    }

    // ---- بيانات الحساب البنكي (تُعرض للمستخدم عند طلب الاشتراك) ----
    // ---- رصيد Moon AI: التوكن وساعات الشحن لكل باقة ----
    if (act === 'quota_get') return send(res, 200, { cfg: await qcfg(true), defaults: QDEF });
    if (act === 'quota_set') {
      const c = qcfgFrom(body.cfg);
      if (c.pro.tokens < c.premium.tokens) return send(res, 400, { code: 'bad', why: 'pro_lower' }); // قيم Pro يجب ألا تقل عن Premium
      const prev = await qcfg(true), pv = JSON.stringify(prev), nv = JSON.stringify(c);
      // الكائنات المتداخلة لا تُخزَّن عبر fsSet (يدعم الأرقام والنصوص فقط)، لذا تُحفظ كنص JSON في الحقل j
      await fsSet('config/quota', { j: nv, at: now, by });
      if (pv !== nv) await aud('quota', { pv, nv }); // سجل التغيير: السابق + الجديد + الوقت (t) + المسؤول (by/bu)
      return send(res, 200, { ok: true, cfg: await qcfg(true) });
    }
    if (act === 'bank_get') { const b = await fsGet('config/bank'); return send(res, 200, { text: b ? b.text || '' : '' }); }
    if (act === 'bank_set') { const bt = String(body.text || '').slice(0, 1500); await fsSet('config/bank', { text: bt, at: now }); await aud('bank', { d: 'len ' + bt.length + ' · sha ' + crypto.createHash('sha256').update(bt).digest('hex').slice(0, 8) }); return send(res, 200, { ok: true }); } // النص نفسه لا يُسجَّل (بيانات مالية)


    // ---- سجل العمليات ----
    if (act === 'audit_list') {
      const kind = String(body.kind || '').replace(/[^a-z_]/g, '').slice(0, 20);
      let rows = await fsList('audit', ['t', 'k', 'by', 'bu', 'u', 'd', 'pv', 'nv']);
      if (kind) rows = rows.filter((r) => r.f.k === kind);
      rows.sort((x, y) => (y.f.t || 0) - (x.f.t || 0));
      const items = rows.slice(0, 100).map(({ id, f }) => Object.assign({ id }, f));
      const em = await emailsFor([...new Set(items.map((x) => x.u).filter(Boolean))]);
      return send(res, 200, { items: items.map((x) => Object.assign(x, { ue: em[x.u] || '' })) });
    }

    // ---- إيقاف/تفعيل حساب ----
    if (act === 'user_set') {
      const uid = String(body.uid || '');
      if (!UID.test(uid) || typeof body.disabled !== 'boolean') return send(res, 400, { code: 'bad' });
      const [u] = await authLookup({ localId: [uid] });
      if (!u) return send(res, 404, { code: 'none' });
      if (String(u.email).toLowerCase() === OWNER) return send(res, 400, { code: 'bad', why: 'owner' }); // لا يُوقَف حساب المالك
      await authDisable(uid, body.disabled);
      await markDisabled(uid, body.disabled); // يُبطل رموز الحساب الحالية فورًا (لا ينتظر انتهاءها)
      await aud(body.disabled ? 'disable' : 'enable', { u: uid, d: u.email || '' });
      return send(res, 200, { ok: true, disabled: body.disabled });
    }

    // ---- رؤى: اللغات + استهلاك التوكن (يُحتسب الرصيد الحالي فقط إن كانت نافذته سارية، لأن الخادم لا يصفّر المستند إلا عند آخر استخدام) ----
    if (act === 'insights') {
      const [usg, lg, ents, cfg] = await Promise.all([fsList('usage', ['g', 'td', 'tt', 'd', 'ws', 'ex']), fsList('langs', ['l']), entMap(), qcfg()]);
      const langs = {}; for (const { f } of lg) if (f.l) langs[f.l] = (langs[f.l] || 0) + 1;
      const dd = Math.floor(now / DAY), byPlan = { free: { w: 0, l: 0, n: 0 }, premium: { w: 0, l: 0, n: 0 }, pro: { w: 0, l: 0, n: 0 } };
      const T = { window: 0, tutor: 0, life: 0, active: 0, byPlan };
      for (const { id, f } of usg) {
        const e = ents[id], pl = activeOf(e, now) ? (e.pl === 'pro' ? 'pro' : 'premium') : 'free';
        const W = winMs(pl, cfg);
        const g = pl === 'free' ? (+f.ex ? (now < f.ex + W ? +f.g || 0 : 0) : (f.d === dd ? +f.g || 0 : 0)) : (+f.ws && now < f.ws + W ? +f.g || 0 : 0);
        const td = pl !== 'free' && f.d === dd ? +f.td || 0 : 0, tt = +f.tt || 0;
        T.window += g; T.tutor += td; T.life += tt; if (g + td > 0) T.active++;
        byPlan[pl].w += g + td; byPlan[pl].l += tt; byPlan[pl].n++;
      }
      const top = usg.filter((x) => +x.f.tt > 0).sort((x, y) => y.f.tt - x.f.tt).slice(0, 5);
      const em = await emailsFor(top.map((x) => x.id));
      return send(res, 200, { langs, tokens: T, top: top.map((x) => ({ uid: x.id, email: em[x.id] || '', tt: x.f.tt })), usageDocs: usg.length });
    }

    // ---- إشعار لكل المستخدمين (يصل التطبيق عبر /api/quota → حقل notice) ----
    if (act === 'notice_get') {
      const d = await fsGet('config/notice');
      return send(res, 200, { notice: d && d.id && d.text ? Object.assign({}, d, { active: !d.exp || d.exp > now }) : null });
    }
    if (act === 'notice_set') {
      const text = String(body.text || '').trim().slice(0, 600), title = String(body.title || '').trim().slice(0, 80);
      if (!text) return send(res, 400, { code: 'bad' });
      const n = { id: crypto.randomBytes(6).toString('hex'), title, text, lvl: ['info', 'warn', 'ok'].includes(body.lvl) ? body.lvl : 'info', at: now, exp: now + int(body.days, 7, 1, 90) * DAY, by };
      await fsSet('config/notice', n); await noticeGet(true);
      await aud('notice', { d: (title ? title + ' — ' : '') + text.slice(0, 200) });
      return send(res, 200, { ok: true, notice: n });
    }
    if (act === 'notice_clear') {
      await fsSet('config/notice', { id: '', text: '', at: now, by }); await noticeGet(true);
      await aud('notice_clear', {});
      return send(res, 200, { ok: true });
    }

    // ---- تعليمات إضافية للـ AI (تُلحق ببرومبت النظام في /api/chat) ----
    if (act === 'prompts_get') { const d = (await fsGet('config/prompts')) || {}; return send(res, 200, { all: d.all || '', ar: d.ar || '', fr: d.fr || '', en: d.en || '' }); }
    if (act === 'prompts_set') {
      const lang = ['all', 'ar', 'fr', 'en'].includes(body.lang) ? body.lang : '';
      if (!lang || typeof body.text !== 'string') return send(res, 400, { code: 'bad' });
      const text = body.text.slice(0, 4000), d = (await fsGet('config/prompts')) || {}, pv = String(d[lang] || '');
      await fsSet('config/prompts', Object.assign({ all: '', ar: '', fr: '', en: '' }, d, { [lang]: text, at: now, by }));
      await promptsGet(true);
      if (pv !== text) await aud('prompt', { d: lang, pv: pv.slice(0, 600), nv: text.slice(0, 600) });
      return send(res, 200, { ok: true });
    }

    // ---- سجل أخطاء الخادم ----
    if (act === 'errors_list') {
      let rows = await fsList('errors', ['t', 'k', 'm', 'u']);
      rows.sort((x, y) => (y.f.t || 0) - (x.f.t || 0));
      if (rows.length > 500) { const old = rows.slice(500); rows = rows.slice(0, 500); await Promise.all(old.slice(0, 100).map((r) => fsDel('errors/' + r.id).catch(() => {}))); } // تقليم تلقائي
      const c24 = {}; for (const { f } of rows) if (f.t > now - DAY) c24[f.k] = (c24[f.k] || 0) + 1;
      return send(res, 200, { errors: rows.slice(0, 200).map(({ id, f }) => ({ id, t: f.t || 0, k: f.k || '', m: f.m || '', u: f.u || '' })), c24, total: rows.length });
    }
    if (act === 'errors_clear') {
      const rows = await fsList('errors', ['t']);
      for (let i = 0; i < rows.length && i < 500; i += 25) await Promise.all(rows.slice(i, Math.min(rows.length, i + 25)).map((r) => fsDel('errors/' + r.id).catch(() => {})));
      await aud('errors_clear', { d: String(Math.min(rows.length, 500)) });
      return send(res, 200, { ok: true, deleted: Math.min(rows.length, 500) });
    }

    // ---- حدود اللغات (config/langs) ----
    if (act === 'lang_get') return send(res, 200, { cfg: await lcfg(true), defaults: LDEF });
    if (act === 'lang_set') {
      const c = lcfgFrom(body.cfg);
      for (const p of ['free', 'premium', 'pro']) { if (c[p].n > c[p].l.length) c[p].n = c[p].l.length; } // لا معنى لعدد أكبر من القائمة المسموحة
      if (c.pro.n < c.premium.n) return send(res, 400, { code: 'bad', why: 'pro_lower' });
      const prev = await lcfg(true), pv = JSON.stringify(prev), nv = JSON.stringify(c);
      await fsSet('config/langs', { j: nv, at: now, by });
      if (pv !== nv) await aud('lang', { pv, nv });
      return send(res, 200, { ok: true, cfg: await lcfg(true) });
    }

    // ---- ميزات التعلّم: أعلام التشغيل + إحصاءات الاستخدام (config/learnflags، learnstats/{يوم}) ----
    if (act === 'learn_get') {
      // عتبات الإنذار (نافذة آخر 3 أيام؛ لا إنذار قبل حدّ أدنى من العيّنات حتى لا نُنذر على ضجيج)
      const TH = { win: 3, aiMin: 10, aiWarn: 0.2, aiCrit: 0.4, tagMin: 10, tagWarn: 0.6, tagCrit: 0.4, invMin: 10, invWarn: 0.25, btnMin: 10, btnWarn: 0.2 };
      const learnAlerts = (ds) => {
        const sm = {}; for (const d of ds.slice(0, TH.win)) for (const [k, v] of Object.entries(d.c || {})) sm[k] = (sm[k] || 0) + (+v || 0);
        const n = (k) => sm[k] || 0, A = [], pc = (x) => Math.round(x * 100) + '%';
        if (n('ac') >= TH.aiMin) { const r = n('af') / n('ac'); if (r >= TH.aiWarn) A.push({ id: 'ai', lv: r >= TH.aiCrit ? 'crit' : 'warn', msg: 'فشل توليد محتوى التعلّم بالذكاء الاصطناعي', val: pc(r), n: n('af') + '/' + n('ac') }); }
        if (n('rc') >= TH.tagMin) { const r = n('rt') / n('rc'); if (r < TH.tagWarn) A.push({ id: 'tags', lv: r < TH.tagCrit ? 'crit' : 'warn', msg: 'انخفاض التزام AI بوسم التصحيحات (لا تُحفظ نقاط الضعف للردود غير الموسومة)', val: pc(r), n: n('rt') + '/' + n('rc') }); }
        const tot = n('tw') + n('tl') + n('ti');
        if (tot >= TH.invMin) { const r = n('ti') / tot; if (r >= TH.invWarn) A.push({ id: 'inv', lv: 'warn', msg: 'نسبة عالية من الوسوم غير الصالحة (معرّفات دروس خاطئة)', val: pc(r), n: n('ti') + '/' + tot }); }
        const bt = n('bo') + n('be');
        if (bt >= TH.btnMin) { const r = n('bf') / bt; if (r >= TH.btnWarn) A.push({ id: 'btn', lv: 'warn', msg: 'فشل أزرار فتح الدرس/التمارين من المحادثة', val: pc(r), n: n('bf') + '/' + bt }); }
        return A;
      };
      const rows = await fsList('learnstats', ['j']);
      rows.sort((x, y) => (x.id < y.id ? 1 : -1));
      if (rows.length > 60) await Promise.all(rows.slice(60, 110).map((r) => fsDel('learnstats/' + r.id).catch(() => {}))); // تقليم تلقائي
      const days = rows.slice(0, 14).map(({ id, f }) => { let o = {}; try { o = JSON.parse(f.j || '{}'); } catch (e) { o = {}; } return { d: id, c: (o && o.c) || {}, w: (o && o.w) || {} }; });
      return send(res, 200, { flags: await lfcfg(true), defaults: LFDEF, days, alerts: learnAlerts(days), th: TH });
    }
    if (act === 'learn_set') {
      const prev = await lfcfg(true), fl = body.flags && typeof body.flags === 'object' ? body.flags : {}, next = {};
      for (const k of Object.keys(LFDEF)) next[k] = k in fl ? (fl[k] ? 1 : 0) : prev[k];
      const pv = JSON.stringify(prev), nv = JSON.stringify(next);
      await fsSet('config/learnflags', { j: nv, at: now, by });
      if (pv !== nv) await aud('learn', { d: pv + ' → ' + nv });
      return send(res, 200, { ok: true, flags: await lfcfg(true) });
    }
    if (act === 'learn_clear') {
      const rows = await fsList('learnstats', ['j']), n = Math.min(rows.length, 120);
      for (let i = 0; i < n; i += 25) await Promise.all(rows.slice(i, Math.min(n, i + 25)).map((r) => fsDel('learnstats/' + r.id).catch(() => {})));
      await aud('learn_clear', { d: String(n) });
      return send(res, 200, { ok: true, deleted: n });
    }

    // ---- البلاغات ----
    if (act === 'reports_list') {
      const st = RST.includes(body.status) ? body.status : '';
      const rows = await fsList('reports', ['ref', 'cat', 'st', 'at', 'up', 'em', 'ct', 'msg', 'sp', 'rat', 'uid']);
      const cnt = { new: 0, review: 0, solved: 0, closed: 0 };
      for (const { f } of rows) if (cnt[f.st] !== undefined) cnt[f.st]++;
      const items = rows.filter(({ f }) => !st || f.st === st).sort((x, y) => (y.f.at || 0) - (x.f.at || 0)).slice(0, 200)
        .map(({ id, f }) => ({ id, ref: f.ref || id, cat: f.cat || '', st: f.st || 'new', at: f.at || 0, up: f.up || 0, em: f.em || f.ct || '', anon: !f.uid, sp: f.sp || '', msg: String(f.msg || '').slice(0, 160), replied: (f.rat || 0) > 0 }));
      return send(res, 200, { items, cnt });
    }
    if (act === 'report_get') {
      const id = String(body.id || ''); if (!RID.test(id)) return send(res, 400, { code: 'bad' });
      const d = await fsGet('reports/' + id); if (!d) return send(res, 404, { code: 'none' });
      const js = (s) => { try { return JSON.parse(s || '{}') || {}; } catch (e) { return {}; } };
      let errs = [];
      if (d.uid) { try { errs = (await fsList('errors', ['t', 'k', 'm', 'u'])).filter((r) => r.f.u === d.uid).sort((x, y) => (y.f.t || 0) - (x.f.t || 0)).slice(0, 10).map(({ f }) => ({ t: f.t || 0, k: f.k || '', m: f.m || '' })); } catch (e) { errs = []; } }
      return send(res, 200, { r: { id, ref: d.ref || id, uid: d.uid || '', em: d.em || '', ct: d.ct || '', cat: d.cat || '', msg: d.msg || '', st: d.st || 'new', at: d.at || 0, up: d.up || 0, sp: d.sp || '', rep: d.rep || '', rat: d.rat || 0, nt: d.nt || '' }, tech: js(d.tech), q: js(d.q), errs });
    }
    if (act === 'report_set' || act === 'report_reply' || act === 'report_note') {
      const id = String(body.id || ''); if (!RID.test(id)) return send(res, 400, { code: 'bad' });
      const d = await fsGet('reports/' + id); if (!d) return send(res, 404, { code: 'none' });
      const o = Object.assign({}, d); let kind = '', info = '';
      if (act === 'report_set') {
        if (!RST.includes(body.st)) return send(res, 400, { code: 'bad' });
        o.st = body.st; kind = 'st'; info = d.st + '>' + o.st;
      } else if (act === 'report_reply') {
        const t = String(body.text == null ? '' : body.text).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, ' ').trim().slice(0, 1500);
        if (!t) return send(res, 400, { code: 'bad' });
        o.rep = t; o.rat = now;
        o.st = RST.includes(body.st) ? body.st : (d.st === 'new' ? 'review' : d.st);
        kind = 'reply'; info = 'reply;' + d.st + '>' + o.st;
      } else {
        o.nt = String(body.text == null ? '' : body.text).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, ' ').trim().slice(0, 1500);
        kind = 'note'; info = 'note';
      }
      if (act !== 'report_note') o.up = now;
      await fsSet('reports/' + id, o);
      await aud('report', { u: d.uid || '', d: id + ':' + info });
      return send(res, 200, { ok: true, st: o.st, up: o.up || 0, rat: o.rat || 0 });
    }

    // =====================================================================
    // لوحة المطوّر الاحترافية — إجراءات جديدة (قراءة فقط ما لم يُذكر). كلها بعد authenticate + a.owner أعلاه.
    // =====================================================================
    if (act === 'metrics_range') { // مقاييس Moon AI اليومية (metrics/*): تبدأ من تاريخ تفعيل هذا التحديث، ولا تُقدَّر بأثر رجعي
      const rows = await mtRange(int(body.days, 30, 1, 120));
      return send(res, 200, { days: rows, since: rows.length ? rows[0].d : '' });
    }
    if (act === 'health') { // اختبارات اتصال فعلية (لا مجرد وجود الإعدادات). لا تُعاد أي أسرار؛ أسماء/منطق فقط
      const timed = async (fn) => { const t = Date.now(); try { await fn(); return { ok: true, ms: Date.now() - t }; } catch (e) { const m = sdet(e); return { ok: false, ms: Date.now() - t, err: m !== 'unknown' ? m : String((e && e.message) || 'err').replace(/[^A-Za-z0-9_:. -]/g, '').slice(0, 40) }; } };
      const gnames = Object.keys(process.env).filter((n) => /^GROQ_KEY_\d+$/.test(n) && String(process.env[n]).trim());
      const gk = gnames.length ? String(process.env[gnames[0]]).trim().replace(/^["']|["']$/g, '') : '';
      const [fa, fs, groq, errs] = await Promise.all([
        timed(() => authList(1, '')),
        timed(() => fsGet('config/notice')),
        gk ? timed(async () => { const ac = new AbortController(), tm = setTimeout(() => ac.abort(), 5000); try { const r = await fetch('https://api.groq.com/openai/v1/models', { headers: { Authorization: 'Bearer ' + gk }, signal: ac.signal }); if (!r.ok) throw new Error('http' + r.status); } finally { clearTimeout(tm); } }) : Promise.resolve({ ok: null, why: 'no_key' }),
        fsList('errors', ['t', 'k']).then((r) => ({ ok: true, h1: r.filter((x) => x.f.t > now - 36e5).length, h24: r.filter((x) => x.f.t > now - DAY).length })).catch(() => ({ ok: false })),
      ]);
      return send(res, 200, { at: now, services: { auth: fa, firestore: fs, groq, api: { ok: true, ms: Date.now() - now } }, errors: errs,
        config: { sa: saReady(), plan_secret: secretInfo().ok, admin_secret: adminInfo().ok, cron_secret: String(process.env.CRON_SECRET || '').length >= 16, groq_keys: gnames.length, model: String(process.env.GROQ_MODEL || '').replace(/[^A-Za-z0-9_./:-]/g, '').slice(0, 60) } });
    }
    if (act === 'security') {
      const [er, dis, mt, au] = await Promise.all([fsList('errors', ['t', 'k', 'm', 'u']), fsList('disabled', ['at']), mtRange(14), fsList('audit', ['t', 'k', 'by', 'u', 'd'])]);
      const cnt = (since) => { const o = {}; for (const { f } of er) if (f.t > since) o[f.k] = (o[f.k] || 0) + 1; return o; };
      const c24 = cnt(now - DAY), c7 = cnt(now - 7 * DAY), today = new Date(now).toISOString().slice(0, 10);
      const tdy = (k) => { const r = mt.find((x) => x.d === today); return r ? +r.c[k] || 0 : 0; };
      const alerts = [], add = (lv, id, n) => alerts.push({ lv, id, n });
      if (c24.keys) add('crit', 'keys', c24.keys);
      if (c24.unhandled) add(c24.unhandled >= 5 ? 'crit' : 'warn', 'unhandled', c24.unhandled);
      if ((c24.upstream || 0) + (c24.upstream_http || 0) >= 10) add('warn', 'upstream', (c24.upstream || 0) + (c24.upstream_http || 0));
      if (c24.admin_auth >= 10) add(c24.admin_auth >= 30 ? 'crit' : 'warn', 'admin_auth', c24.admin_auth);
      if (c24.activate >= 10) add('warn', 'activate', c24.activate);
      if (c24.bill) add('warn', 'bill', c24.bill);
      if (tdy('qx') >= 20) add('info', 'quota', tdy('qx'));
      if (dis.length) add('info', 'disabled', dis.length);
      const em = await emailsFor(dis.slice(0, 100).map((r) => r.id));
      const SEC = /^(keys|unhandled|admin_auth|activate|lang|upstream|upstream_http|bill)$/;
      return send(res, 200, { alerts, c24, c7,
        disabled: dis.slice(0, 100).map((r) => ({ uid: r.id, email: em[r.id] || '', at: r.f.at || 0 })),
        series: { af: mt.map((x) => ({ d: x.d, v: +x.c.af || 0 })), qx: mt.map((x) => ({ d: x.d, v: +x.c.qx || 0 })) },
        events: er.filter(({ f }) => SEC.test(f.k)).sort((x, y) => (y.f.t || 0) - (x.f.t || 0)).slice(0, 100).map(({ id, f }) => ({ id, t: f.t || 0, k: f.k, m: f.m || '', u: f.u || '' })),
        admin: au.filter(({ f }) => /^(disable|enable|revoke|fail|bank)$/.test(f.k)).sort((x, y) => (y.f.t || 0) - (x.f.t || 0)).slice(0, 20).map(({ id, f }) => ({ id, t: f.t || 0, k: f.k, by: f.by || '', u: f.u || '', d: String(f.d || '').slice(0, 120) })),
        unavailable: ['login_failures', 'token_errors'] });
    }
    if (act === 'user_detail') {
      const uid = String(body.uid || ''); if (!UID.test(uid)) return send(res, 400, { code: 'bad' });
      const [u] = await authLookup({ localId: [uid] }); if (!u) return send(res, 404, { code: 'none' });
      const [ent, usg, pays, au, cfg] = await Promise.all([fsGet('entitlements/' + uid).catch(() => null), fsGet('usage/' + uid).catch(() => null),
        fsList('payments', ['uid', 'p', 'k', 'amt', 'st', 'cr', 'rv', 'ex', 'ref']), fsList('audit', ['t', 'k', 'by', 'u', 'd', 'r']), qcfg()]);
      const tu = tokUse(usg || {}, ent, now, cfg), L = cfg[tu.pl] || cfg.free;
      const src = ent && ent.cid ? (String(ent.cid).startsWith('pay-') ? 'bank' : String(ent.cid).startsWith('adm-') ? 'admin' : 'code') : '';
      return send(res, 200, {
        user: { uid, email: u.email, name: u.name, verified: u.verified, disabled: u.disabled, created: u.created, last: u.last, owner: String(u.email).toLowerCase() === OWNER },
        sub: { plan: activeOf(ent, now) ? ent.pl : '', exp: ent ? +ent.exp || 0 : 0, revoked: ent ? +ent.rv || 0 : 0, at: ent ? +ent.at || 0 : 0, src },
        usage: { plan: tu.pl, window: tu.g, tutor: tu.td, life: tu.tt, limit: L.tokens, tutorLimit: L.tutor || 0, started: usg ? +usg.ws || 0 : 0 },
        payments: pays.filter((r) => r.f.uid === uid).sort((x, y) => (y.f.cr || 0) - (x.f.cr || 0)).slice(0, 20).map(({ id, f }) => ({ id, p: f.p, k: f.k, amt: f.amt, st: f.st, cr: f.cr || 0, ex: f.ex || 0, ref: f.ref || '' })),
        actions: au.filter((r) => r.f.u === uid).sort((x, y) => (y.f.t || 0) - (x.f.t || 0)).slice(0, 30).map(({ id, f }) => ({ id, t: f.t || 0, k: f.k, by: f.by || '', d: String(f.d || '').slice(0, 160), r: f.r || 'ok' })) });
    }
    if (act === 'subs_list') {
      const rows = await fsList('entitlements', ['tok', 'pl', 'exp', 'rv', 'cid', 'at']);
      const em = await emailsFor(rows.map((r) => r.id).slice(0, 1000));
      const sum = { active: 0, expiring7: 0, expired: 0, revoked: 0, premium: 0, pro: 0, invalid: 0 };
      const items = rows.map(({ id, f }) => {
        const p = f.tok ? verifyToken(f.tok) : null, state = +f.rv ? 'revoked' : +f.exp > now ? 'active' : 'expired', valid = !!(p && p.u === id && !+f.rv);
        sum[state]++; if (state === 'active') { sum[f.pl === 'pro' ? 'pro' : 'premium']++; if (f.exp < now + 7 * DAY) sum.expiring7++; if (!valid) sum.invalid++; }
        const src = f.cid ? (String(f.cid).startsWith('pay-') ? 'bank' : String(f.cid).startsWith('adm-') ? 'admin' : 'code') : '';
        return { uid: id, email: em[id] || '', pl: f.pl || '', exp: +f.exp || 0, rv: +f.rv || 0, at: +f.at || 0, src, state, valid };
      }).sort((x, y) => y.exp - x.exp).slice(0, 800);
      return send(res, 200, { items, sum });
    }
    if (act === 'audit_page') { // سجل نشاط المطوّر: ترشيح + ترقيم من الخادم
      const kind = String(body.kind || '').replace(/[^a-z_]/g, '').slice(0, 20), rs = body.result === 'fail' ? 'fail' : body.result === 'ok' ? 'ok' : '';
      const q = String(body.q || '').trim().toLowerCase().slice(0, 80), from = +body.from || 0, to = +body.to || 0, off = int(body.offset, 0, 0, 100000), lim = int(body.limit, 25, 5, 100);
      let rows = await fsList('audit', ['t', 'k', 'by', 'bu', 'u', 'd', 'pv', 'nv', 'r', 'er']);
      rows = rows.filter(({ f }) => (!kind || f.k === kind || (kind === 'file' && /^file_/.test(f.k))) && (!rs || (f.r || 'ok') === rs) && (!from || f.t >= from) && (!to || f.t <= to) && (!q || [f.by, f.u, f.d, f.k].some((v) => String(v || '').toLowerCase().includes(q))));
      rows.sort((x, y) => (y.f.t || 0) - (x.f.t || 0));
      const items = rows.slice(off, off + lim).map(({ id, f }) => Object.assign({ id, r: 'ok' }, f));
      const em = await emailsFor([...new Set(items.map((x) => x.u).filter(Boolean))]);
      return send(res, 200, { total: rows.length, offset: off, items: items.map((x) => Object.assign(x, { ue: em[x.u] || '' })) });
    }
    if (act === 'ai_overview') {
      const [usg, ents, cfg, mt] = await Promise.all([fsList('usage', ['g', 'td', 'tt', 'd', 'ws', 'ex']), entMap(), qcfg(), mtRange(30)]);
      const near = [], byPlan = { free: { n: 0, w: 0 }, premium: { n: 0, w: 0 }, pro: { n: 0, w: 0 } };
      for (const { id, f } of usg) {
        const tu = tokUse(f, ents[id], now, cfg), lim = (cfg[tu.pl] || cfg.free).tokens, pct = lim ? tu.g / lim : 0;
        byPlan[tu.pl].n++; byPlan[tu.pl].w += tu.g;
        if (pct >= 0.8) near.push({ uid: id, pl: tu.pl, g: tu.g, lim, pct: Math.round(pct * 100) });
      }
      near.sort((x, y) => y.pct - x.pct); const top = near.slice(0, 15), em = await emailsFor(top.map((x) => x.uid));
      const anomalies = [];
      for (const x of near.filter((y) => y.pct >= 95).slice(0, 10)) anomalies.push({ lv: 'warn', id: 'near_limit', uid: x.uid, v: x.pct });
      const tot = (x) => (+x.c.t_free || 0) + (+x.c.t_premium || 0) + (+x.c.t_pro || 0);
      for (const x of mt) if ((+x.c.rq || 0) >= 20 && (+x.c.er || 0) / x.c.rq >= 0.2) anomalies.push({ lv: x.c.er / x.c.rq >= 0.4 ? 'crit' : 'warn', id: 'fail_rate', d: x.d, v: Math.round((x.c.er / x.c.rq) * 100) });
      if (mt.length >= 8) { const last = mt[mt.length - 1], prev = mt.slice(0, -1).map(tot), mean = prev.reduce((a, b) => a + b, 0) / prev.length, sd = Math.sqrt(prev.reduce((a, b) => a + (b - mean) ** 2, 0) / prev.length); if (tot(last) > mean + 3 * sd && tot(last) > 1000) anomalies.push({ lv: 'warn', id: 'token_spike', d: last.d, v: tot(last), mean: Math.round(mean) }); }
      const price = parseFloat(process.env.AI_PRICE_PER_MTOK), t30 = mt.reduce((a, x) => a + tot(x), 0);
      return send(res, 200, { near: top.map((x) => Object.assign(x, { email: em[x.uid] || '' })), byPlan, anomalies, limits: cfg, cost: Number.isFinite(price) && price > 0 ? { perMTok: price, est30: Math.round((t30 / 1e6) * price * 100) / 100 } : null });
    }
    if (act === 'report_data') {
      const n = int(body.days, 30, 7, 180), ds = (t) => new Date(t).toISOString().slice(0, 10), dates = [];
      for (let i = n - 1; i >= 0; i--) dates.push(ds(now - i * DAY));
      const ix = {}; dates.forEach((d, i) => { ix[d] = i; });
      const z = () => Array(n).fill(0), out = { dates, signups: z(), lastLogin: z(), revenueCents: z(), paysApproved: z(), subsGranted: z(), codesUsed: z(), errors: {}, partial: false };
      const users = []; let cur = '';
      for (let i = 0; i < 10; i++) { const r = await authList(1000, cur); users.push(...r.users); cur = r.next; if (!cur) break; }
      out.partial = !!cur;
      for (const u of users) { const a = ix[ds(u.created || 0)], b = ix[ds(u.last || 0)]; if (a !== undefined) out.signups[a]++; if (b !== undefined) out.lastLogin[b]++; }
      const [pays, au, codes, er, mt] = await Promise.all([fsList('payments', ['st', 'amt', 'rv']), fsList('audit', ['t', 'k']), fsList('codes', ['st', 'at']), fsList('errors', ['t', 'k']), mtRange(n)]);
      for (const { f } of pays) if (f.st === 'approved') { const i = ix[ds(f.rv || 0)]; if (i !== undefined) { out.revenueCents[i] += +f.amt || 0; out.paysApproved[i]++; } }
      for (const { f } of au) if (f.k === 'grant' || f.k === 'pay_ok') { const i = ix[ds(f.t || 0)]; if (i !== undefined) out.subsGranted[i]++; }
      for (const { f } of codes) if (f.st === 'used') { const i = ix[ds(f.at || 0)]; if (i !== undefined) out.codesUsed[i]++; }
      for (const { f } of er) { const i = ix[ds(f.t || 0)]; if (i === undefined) continue; (out.errors[f.k] = out.errors[f.k] || z())[i]++; }
      out.ai = mt;
      return send(res, 200, out);
    }
    if (act === 'export_log') { await aud('export', { d: String(body.what || '').replace(/[^a-z_]/g, '').slice(0, 30) }); return send(res, 200, { ok: true }); }

    // =====================================================================
    // الجولة 2: تحليلات استخدام المستخدمين (ua/*) + مدير الملفات عبر Git. للمالك فقط (تحقق الخادم أعلاه).
    // =====================================================================
    if (act === 'ua_overview' || act === 'ua_user') {
      const to = DREG.test(String(body.to || '')) ? body.to : new Date(now).toISOString().slice(0, 10);
      const from = DREG.test(String(body.from || '')) ? body.from : new Date(now - 29 * DAY).toISOString().slice(0, 10);
      if (from > to || Date.parse(to + 'T00:00:00Z') - Date.parse(from + 'T00:00:00Z') > 366 * DAY) return send(res, 400, { code: 'bad' });
      const bucket = ['day', 'week', 'month'].includes(body.bucket) ? body.bucket : 'day';
      let rows = await fsRange('ua', 'd', from, to, ['u', 'd', 'a', 'i', 'n', 'j', 'last'], 20000);
      const truncated = rows.length >= 20000;
      if (act === 'ua_user') {
        let uid = String(body.uid || ''); const q = String(body.q || '').trim();
        if (!UID.test(uid)) { if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(q)) { const [x] = await authLookup({ email: [q.toLowerCase()] }); uid = x ? x.uid : ''; } else uid = q; }
        if (!UID.test(uid)) return send(res, 404, { code: 'none' });
        const [u] = await authLookup({ localId: [uid] }); if (!u) return send(res, 404, { code: 'none' });
        rows = rows.filter((r) => r.f.u === uid);
        return send(res, 200, Object.assign(uaAgg(rows, bucket), { user: { uid, email: u.email, name: u.name, created: u.created, last: u.last }, from, to, bucket, truncated }));
      }
      const g = uaAgg(rows, bucket), top = g.users.slice(0, 50), em = await emailsFor(top.map((x) => x.uid));
      return send(res, 200, Object.assign(g, { users: top.map((x) => Object.assign(x, { email: em[x.uid] || '' })), usersTotal: g.users.length, rows: rows.length, from, to, bucket, truncated }));
    }
    if (act.startsWith('files_')) {
      if (a.kind !== 'token') return send(res, 403, { code: 'forbidden', need: 'token' }); // تعديل الكود لا يُسمح به عبر السرّ القديم ADMIN_SECRET: رمز Firebase للمالك فقط
      const C = gh.cfg();
      if (act === 'files_config') return send(res, 200, { enabled: C.enabled, missing: C.missing, repo: C.enabled ? C.repo : '', branch: C.branch, prod: C.prod, safe: C.branch !== C.prod, limits: { text: gh.MAX_TEXT, bin: gh.MAX_BIN, files: gh.MAX_FILES } });
      if (!C.enabled) return send(res, 503, { code: 'gh_off' });
      const deny = async (code, st, p) => { await audit('file_denied', by, { bu, r: 'fail', d: code + ' · ' + String(p || '').slice(0, 120) }).catch(() => {}); return send(res, st, { code }); };
      try {
        if (act === 'files_tree') {
          const s = await gh.snapshot(); let hidden = 0; const items = [];
          for (const x of s.tree) { const c = gh.classify(x.path); if (c.lv === 'blocked') { hidden++; continue; } items.push({ p: x.path, s: x.size || 0, sha: x.sha, lv: c.lv }); }
          return send(res, 200, { branch: C.branch, head: s.head, truncated: s.truncated, hidden, items: items.slice(0, 5000) });
        }
        if (act === 'files_read' || act === 'files_history') {
          const path = String(body.path || ''), c = gh.classify(path); if (c.lv === 'blocked') return deny('blocked', 403, path);
          if (act === 'files_history') return send(res, 200, { path, items: await gh.history(path) });
          const ref = String(body.ref || C.branch); if (ref !== C.branch && !/^[0-9a-f]{7,40}$/.test(ref)) return send(res, 400, { code: 'bad' });
          const r = await gh.readAt(path, ref), meta = { path, sha: r.sha, size: r.size, lv: c.lv, ref, text: gh.isText(path) };
          if (!meta.text) return send(res, 200, Object.assign(meta, { bin: true }));
          if (!r.buf) return send(res, 200, Object.assign(meta, { big: true }));
          const t = r.buf.toString('utf8'); if (gh.hasSecret(t)) return deny('secret', 403, path);
          if (c.lv === 'sensitive') await aud('file_read', { d: path });
          return send(res, 200, Object.assign(meta, { content: t }));
        }
        if (act === 'files_commit') {
          const list = Array.isArray(body.changes) ? body.changes : [];
          if (!list.length || list.length > gh.MAX_FILES) return send(res, 400, { code: 'bad' });
          const snap = await gh.snapshot(), at = new Map(snap.tree.map((x) => [x.path, x])), out = [], logs = [], seen = new Set(); let total = 0;
          for (const ch of list) {
            const op = String(ch.op || ''), path = String(ch.path || ''), cl = gh.classify(path), cur = at.get(path), ack = String(ch.ack || '');
            if (!['save', 'create', 'mkdir', 'rename', 'delete', 'upload', 'restore'].includes(op)) return send(res, 400, { code: 'bad' });
            if (cl.lv === 'blocked') return deny('blocked', 403, path);
            if (cl.lv === 'readonly') return deny('readonly', 403, path);
            if (seen.has(path)) return send(res, 400, { code: 'bad' }); seen.add(path);
            const needAck = (force) => (force || cl.lv === 'sensitive') && ack !== path;
            const base = String(ch.base || '');
            if (op === 'mkdir') {
              if (path.split('/').pop().startsWith('.')) return deny('bad_path', 400, path);
              if (snap.tree.some((x) => x.path.startsWith(path + '/'))) return send(res, 409, { code: 'exists' });
              out.push({ path: path + '/.gitkeep', buf: Buffer.alloc(0) }); logs.push(['file_mkdir', path, '']); continue;
            }
            if (op === 'rename') {
              const to = String(ch.to || ''), ct = gh.classify(to);
              if (ct.lv === 'blocked') return deny('blocked', 403, to); if (ct.lv === 'readonly') return deny('readonly', 403, to);
              if (!cur) return send(res, 404, { code: 'none' }); if (at.has(to) || seen.has(to)) return send(res, 409, { code: 'exists' });
              if (!gh.allowedExt(to) || gh.ext(to) !== gh.ext(path)) return send(res, 400, { code: 'bad_type' });
              if (base && base !== cur.sha) return send(res, 409, { code: 'conflict' });
              if ((cl.lv === 'sensitive' || ct.lv === 'sensitive') && ack !== path) return send(res, 400, { code: 'ack' });
              seen.add(to); out.push({ path, del: true }, { path: to, sha: cur.sha }); logs.push(['file_rename', path + ' → ' + to, cur.sha.slice(0, 7)]); continue;
            }
            if (op === 'delete') {
              if (!cur) return send(res, 404, { code: 'none' }); if (base !== cur.sha) return send(res, 409, { code: 'conflict' });
              if (ack !== path) return send(res, 400, { code: 'ack' });
              out.push({ path, del: true }); logs.push(['file_delete', path, cur.sha.slice(0, 7)]); continue;
            }
            let buf;
            if (op === 'create' || op === 'save') {
              if (typeof ch.text !== 'string') return send(res, 400, { code: 'bad' });
              buf = Buffer.from(ch.text, 'utf8');
              if (op === 'create') { if (cur) return send(res, 409, { code: 'exists' }); if (!gh.allowedExt(path)) return send(res, 400, { code: 'bad_type' }); if (needAck()) return send(res, 400, { code: 'ack' }); }
              else { if (!cur) return send(res, 404, { code: 'none' }); if (base !== cur.sha) return send(res, 409, { code: 'conflict' }); if (!gh.isText(path)) return send(res, 400, { code: 'bad_type' }); if (needAck()) return send(res, 400, { code: 'ack' }); }
            } else if (op === 'upload') {
              if (typeof ch.b64 !== 'string' || ch.b64.length > 4e6 || !/^[A-Za-z0-9+\/=\s]*$/.test(ch.b64)) return send(res, 400, { code: 'bad' });
              buf = Buffer.from(ch.b64, 'base64'); if (!gh.allowedExt(path)) return send(res, 400, { code: 'bad_type' });
              if (cur) { if (base !== cur.sha) return send(res, 409, { code: 'conflict' }); if (ack !== path) return send(res, 400, { code: 'ack' }); } else if (needAck()) return send(res, 400, { code: 'ack' });
            } else { // restore
              const ref = String(ch.ref || ''); if (!/^[0-9a-f]{7,40}$/.test(ref)) return send(res, 400, { code: 'bad' });
              if (cur && base !== cur.sha) return send(res, 409, { code: 'conflict' }); if (ack !== path) return send(res, 400, { code: 'ack' });
              const r = await gh.readAt(path, ref); if (!r.buf) return send(res, 400, { code: 'too_big' }); buf = r.buf;
            }
            const bad = gh.checkContent(path, buf);
            if (bad) return bad === 'secret' || bad === 'svg_script' ? deny(bad, 400, path) : send(res, 400, { code: bad });
            total += buf.length; if (total > gh.MAX_TOTAL) return send(res, 413, { code: 'too_big' });
            out.push({ path, buf }); logs.push(['file_' + op, path, cur ? cur.sha.slice(0, 7) : '']);
          }
          const sm = String(body.message || '').replace(/[\r\n]+/g, ' ').trim().slice(0, 120) || (logs.length === 1 ? logs[0][0].slice(5) + ' ' + logs[0][1] : logs.length + ' files');
          const sha = await gh.commit(out, '[dev-panel] ' + sm + '\n\nDev-Panel-Actor: ' + by);
          for (const [k, p, old] of logs) await aud(k, { d: p + ' · ' + sha.slice(0, 7), pv: old });
          return send(res, 200, { commit: sha, branch: C.branch, n: out.length, preview: C.branch !== C.prod, repo: C.repo });
        }
        return send(res, 400, { code: 'bad' });
      } catch (e) {
        if (e && /^gh_/.test(e.message)) { await audit('fail', by, { bu, r: 'fail', d: act, er: e.message }).catch(() => {}); return send(res, e.message === 'gh_conflict' ? 409 : 502, { code: e.message }); }
        throw e;
      }
    }

    // ---- الإحصائيات ----
    if (act === 'stats') {
      const users = []; let cur = '';
      for (let i = 0; i < 10; i++) { const r = await authList(1000, cur); users.push(...r.users); cur = r.next; if (!cur) break; }
      const [ents, codes, pays] = await Promise.all([entMap(), fsList('codes', ['p', 'st', 'xp']), fsList('payments', ['st', 'p', 'amt', 'cr'])]);
      const d0 = Math.floor(now / DAY), sign14 = Array(14).fill(0);
      let n7 = 0, n30 = 0, a7 = 0, a1 = 0, a30 = 0, dis = 0;
      for (const u of users) {
        if (u.created > now - 7 * DAY) n7++; if (u.created > now - 30 * DAY) n30++;
        if (u.last > now - 7 * DAY) a7++; if (u.last > now - DAY) a1++; if (u.last > now - 30 * DAY) a30++; if (u.disabled) dis++;
        const k = d0 - Math.floor(u.created / DAY); if (k >= 0 && k < 14) sign14[13 - k]++;
      }
      const sub = { premium: 0, pro: 0, expired: 0, revoked: 0 };
      for (const e of Object.values(ents)) { if (+e.rv) sub.revoked++; else if (+e.exp > now) sub[e.pl === 'pro' ? 'pro' : 'premium']++; else if (e.pl) sub.expired++; }
      const cd = { total: codes.length, new: 0, used: 0, revoked: 0, expired: 0, premium: 0, pro: 0 };
      for (const { f } of codes) { if (f.st === 'new' && f.xp && f.xp < now) cd.expired++; else if (cd[f.st] !== undefined) cd[f.st]++; if (cd[f.p] !== undefined) cd[f.p]++; }
      const py = { pending: 0, approved: 0, rejected: 0, revenueCents: 0, revenue30Cents: 0 };
      for (const { f } of pays) { if (py[f.st] !== undefined) py[f.st]++; if (f.st === 'approved') { py.revenueCents += +f.amt || 0; if (f.cr > now - 30 * DAY) py.revenue30Cents += +f.amt || 0; } }
      return send(res, 200, { users: { total: users.length, new7: n7, new30: n30, active7: a7, active1: a1, active30: a30, disabled: dis, signups14: sign14 }, subs: sub, codes: cd, payments: py, partial: !!cur });
    }
    return send(res, 400, { code: 'bad' });
  } catch (e) {
    console.error('[admin]', e && e.message);
    if (_by && SENS.has(_act)) await audit('fail', _by, { bu: _bu, r: 'fail', d: _act, er: sdet(e) }).catch(() => {});
    return send(res, 500, { code: 'err' });
  }
};
