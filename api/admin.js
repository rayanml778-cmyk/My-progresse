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
const crypto = require('crypto');
const { adminInfo, secretInfo, sign, codeId, codeNorm, genCode, forget } = require('./_plan');
const { saReady, fsGet, fsSet, fsCreate, fsDel, fsList, verifyIdTokenFull, authLookup, authList, authSetClaims } = require('./_fb');

const OWNER = 'rayanml778@gmail.com'; // المالك الوحيد
const DAY = 86400000;
const bad = new Map();
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

// ---- المصادقة ----
async function authenticate(req) {
  const given = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!given) return null;
  if (given.split('.').length === 3) { // Firebase ID token
    const p = await verifyIdTokenFull(given);
    if (!p || String(p.email || '').toLowerCase() !== OWNER) return null;
    return { kind: 'token', uid: p.sub, owner: p.admin === true && p.email_verified === true };
  }
  const ai = adminInfo();
  if (ai.ok && safeEq(given, ai.s)) return { kind: 'secret', owner: true };
  return null;
}

module.exports = async function handler(req, res) {
  try {
    if (req.method !== 'POST') { res.setHeader('Allow', 'POST'); return send(res, 405, { code: 'method' }); }
    if (!saReady()) return send(res, 503, { code: 'conf' });

    const ip = String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'x').split(',')[0].trim();
    const now = Date.now();
    const fails = (bad.get(ip) || []).filter((t) => now - t < 10 * 60 * 1000);
    if (fails.length >= 10) return send(res, 429, { code: 'slow' });
    const fail = async (why) => { fails.push(Date.now()); bad.set(ip, fails); if (bad.size > 500) bad.clear(); await sleep(700); return send(res, 403, why ? { code: 'forbidden', why } : { code: 'forbidden' }); };

    const a = await authenticate(req);
    if (!a) return fail();

    let body = req.body;
    if (typeof body === 'string') { try { body = JSON.parse(body); } catch (e) { body = null; } }
    if (!body || typeof body !== 'object') return send(res, 400, { code: 'bad' });
    const act = String(body.action || '');

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
        return send(res, 200, { revoked: await revokeUid(uid) });
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
      const r = await grant(uid, plan, k, int(body.days, k === 'w' ? 7 : 30, 1, 366), 'adm-' + crypto.randomBytes(6).toString('hex'), now);
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
        return send(res, 200, { rejected: true });
      }
      if (!PLANS.includes(pay.p) || (pay.k !== 'w' && pay.k !== 'm') || !UID.test(String(pay.uid))) { try { await fsDel('payclaim/' + id); } catch (e) { /* */ } return send(res, 400, { code: 'bad' }); }
      let r;
      try { r = await grant(pay.uid, pay.p, pay.k, int(body.days, pay.k === 'w' ? 7 : 30, 1, 366), 'pay-' + id, now); }
      catch (e) { try { await fsDel('payclaim/' + id); } catch (e2) { /* يُحرَّر يدويًا */ } throw e; } // لم يُسلَّم اشتراك: يُحرَّر القفل لإعادة المحاولة
      try { await fsSet('payments/' + id, Object.assign({}, pay, { st: 'approved', rv: now, ex: r.exp })); await setReq(pay.uid, id, { st: 'approved', rv: now }); }
      catch (e) { console.error('[admin] mark', e && e.message); } // الاشتراك سُلِّم والقفل هو المرجع؛ الوسم للعرض فقط
      return send(res, 200, { approved: true, exp: r.exp });
    }

    // ---- بيانات الحساب البنكي (تُعرض للمستخدم عند طلب الاشتراك) ----
    if (act === 'bank_get') { const b = await fsGet('config/bank'); return send(res, 200, { text: b ? b.text || '' : '' }); }
    if (act === 'bank_set') { await fsSet('config/bank', { text: String(body.text || '').slice(0, 1500), at: now }); return send(res, 200, { ok: true }); }

    // ---- الإحصائيات ----
    if (act === 'stats') {
      const users = []; let cur = '';
      for (let i = 0; i < 10; i++) { const r = await authList(1000, cur); users.push(...r.users); cur = r.next; if (!cur) break; }
      const [ents, codes, pays] = await Promise.all([entMap(), fsList('codes', ['p', 'st', 'xp']), fsList('payments', ['st', 'p', 'amt', 'cr'])]);
      const d0 = Math.floor(now / DAY), sign14 = Array(14).fill(0);
      let n7 = 0, n30 = 0, a7 = 0, dis = 0;
      for (const u of users) {
        if (u.created > now - 7 * DAY) n7++; if (u.created > now - 30 * DAY) n30++;
        if (u.last > now - 7 * DAY) a7++; if (u.disabled) dis++;
        const k = d0 - Math.floor(u.created / DAY); if (k >= 0 && k < 14) sign14[13 - k]++;
      }
      const sub = { premium: 0, pro: 0, expired: 0, revoked: 0 };
      for (const e of Object.values(ents)) { if (+e.rv) sub.revoked++; else if (+e.exp > now) sub[e.pl === 'pro' ? 'pro' : 'premium']++; else if (e.pl) sub.expired++; }
      const cd = { total: codes.length, new: 0, used: 0, revoked: 0, expired: 0, premium: 0, pro: 0 };
      for (const { f } of codes) { if (f.st === 'new' && f.xp && f.xp < now) cd.expired++; else if (cd[f.st] !== undefined) cd[f.st]++; if (cd[f.p] !== undefined) cd[f.p]++; }
      const py = { pending: 0, approved: 0, rejected: 0, revenueCents: 0, revenue30Cents: 0 };
      for (const { f } of pays) { if (py[f.st] !== undefined) py[f.st]++; if (f.st === 'approved') { py.revenueCents += +f.amt || 0; if (f.cr > now - 30 * DAY) py.revenue30Cents += +f.amt || 0; } }
      return send(res, 200, { users: { total: users.length, new7: n7, new30: n30, active7: a7, disabled: dis, signups14: sign14 }, subs: sub, codes: cd, payments: py, partial: !!cur });
    }
    return send(res, 400, { code: 'bad' });
  } catch (e) {
    console.error('[admin]', e && e.message);
    return send(res, 500, { code: 'err' });
  }
};
