// api/report.js — نظام البلاغات (من جهة المستخدم). المراجعة والرد وتغيير الحالة من لوحة المطوّر عبر api/admin.js.
// POST JSON. التوثيق اختياري للإرسال فقط: Authorization: Bearer <Firebase ID token> (بدونه = بلاغ مجهول بحدود أشد، ومفيد لمن لا يستطيع تسجيل الدخول).
//   { action:'submit', cat, msg, tech?, contact? }  → { ok:true, ref }      cat = ai | credit | login | tech | idea
//   { action:'mine' }                               → { items:[{ref,cat,st,at,up,msg,rep,rat}] }   (يتطلب تسجيل الدخول؛ آخر 10 بلاغات للمستخدم نفسه فقط)
// الأخطاء: 503 conf | 401 auth | 429 slow | 400 bad | 500 err
// الخصوصية: لا يُقبل من الواجهة إلا قائمة حقول تقنية محددة (بلا رموز/مفاتيح/محادثات)، ويُحجب أي نص يشبه كلمة مرور أو مفتاحًا أو رمز دخول حتى لو كتبه المستخدم بنفسه.
// الكتابة كلها من الخادم (حساب الخدمة): reports/{ref} + rptu/{uid} (فهرس بلاغات المستخدم). لا تحتاج قواعد Firestore جديدة (تبقى مغلقة على العملاء).
const crypto = require('crypto');
const { verifyIdTokenFull, saReady, fsGet, fsSet, fsCreate, usage, quotaView, logErr, lfcfg } = require('./_fb');
const { entitlementOf } = require('./_plan');

const CATS = ['ai', 'credit', 'login', 'tech', 'idea'];
const ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // بلا 0/O/1/I كي يسهل نطق الرقم المرجعي
const MIN_GAP = 60 * 1000, DAY_MAX = 5, tries = new Map(), anon = [];
const send = (res, code, obj) => {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(obj));
};
const limited = (key, max) => {
  const now = Date.now(), arr = (tries.get(key) || []).filter((t) => now - t < 10 * 60 * 1000);
  arr.push(now); tries.set(key, arr); if (tries.size > 2000) tries.clear();
  return arr.length > max;
};
const clean = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, ' ').trim().slice(0, n);

// حجب الأسرار: رموز JWT، مفاتيح Google/Groq/OpenAI/Stripe الشائعة، Bearer، المفاتيح الخاصة، "password: xxx"، والسلاسل الطويلة العشوائية
const SECRETS = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)/g,
  /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
  /\b(AIza[0-9A-Za-z_-]{20,}|gsk_[A-Za-z0-9]{16,}|sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|xox[abp]-[A-Za-z0-9-]{10,})\b/g,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{12,}/gi,
  /((?:password|passwd|pwd|secret|token|api[_ -]?key|كلمة\s*(?:ال)?(?:مرور|سر)|الرمز\s*السري|رمز\s*الدخول)\s*(?:[:=：]|هي|is)\s*)\S{3,}/gi,
  /\b[A-Za-z0-9+/_-]{40,}={0,2}/g,
];
const scrub = (s) => {
  let t = String(s == null ? '' : s);
  SECRETS.forEach((re, i) => { t = t.replace(re, i === 4 ? '$1[محجوب]' : '[محجوب]'); });
  return t;
};
const txt = (v, n) => scrub(clean(v, n)).slice(0, n);

// الحقول التقنية المسموحة فقط (قائمة بيضاء). أي مفتاح آخر يُهمل.
const TECH_STR = { app: 40, plan: 20, view: 30, ua: 180, lang: 20, ui: 20, scr: 30, tz: 40, theme: 20, net: 20 };
const TECH_BOOL = ['online', 'pwa', 'sw', 'signed'];
function techClean(t) {
  const o = {};
  if (!t || typeof t !== 'object' || Array.isArray(t)) return o;
  for (const [k, n] of Object.entries(TECH_STR)) if (t[k] != null && typeof t[k] !== 'object') o[k] = txt(t[k], n);
  for (const k of TECH_BOOL) if (typeof t[k] === 'boolean') o[k] = t[k];
  if (Array.isArray(t.errs)) o.errs = t.errs.slice(-5).map((e) => txt(String(e).replace(/https?:\/\/\S+/g, '[url]'), 160)).filter(Boolean);
  let j = JSON.stringify(o);
  if (j.length > 1500) { delete o.errs; j = JSON.stringify(o); }
  return o;
}
const refGen = () => { const b = crypto.randomBytes(6); let s = ''; for (let i = 0; i < 6; i++) s += ALPHA[b[i] % ALPHA.length]; return 'MP-' + s; };
const REF = /^MP-[A-Z2-9]{6}$/;
// عدّادات إحصاءات التعلّم المسموحة فقط (قائمة بيضاء): لا نصوص ولا محادثات ولا بيانات شخصية
// rc ردود فيها تصحيح | ce عدد التصحيحات | rt ردود وسمت التصحيح | rn ردود صحّحت بلا وسم | ti وسوم غير صالحة | tw وسوم ضعف مقبولة | tl وسوم دروس مقبولة
// bo فتح درس من زر | bl زر على درس مقفل | bc زر على درس مكتمل | be زر تمارين | bf فشل زر | er أخطاء محفوظة من التصحيح | ew إجابات خاطئة بتمارين | ax تمارين تكيّفت مع ضعف | wx ضعف زال
const TEL_KEYS = ['rc', 'ce', 'rt', 'rn', 'ti', 'tl', 'tw', 'bo', 'bl', 'bc', 'be', 'bf', 'er', 'ew', 'ax', 'wx'];
const WID = /^[a-z][\w.]{1,38}$/;
const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/;

module.exports = async function handler(req, res) {
  let uid = '';
  try {
    if (req.method !== 'POST') { res.setHeader('Allow', 'POST'); return send(res, 405, { code: 'method' }); }
    if (!saReady()) return send(res, 503, { code: 'conf' });
    const ip = String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'x').split(',')[0].trim();
    const authz = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    let p = null;
    if (authz) { p = await verifyIdTokenFull(authz); if (!p) return send(res, 401, { code: 'auth' }); uid = p.sub; }

    let body = req.body;
    if (typeof body === 'string') { try { body = JSON.parse(body); } catch (e) { body = null; } }
    if (!body || typeof body !== 'object') return send(res, 400, { code: 'bad' });
    const now = Date.now();

    // ---- بلاغاتي ----
    if (body.action === 'mine') {
      if (!uid) return send(res, 401, { code: 'auth' });
      if (limited('m' + uid, 30)) return send(res, 429, { code: 'slow' });
      const ix = await fsGet('rptu/' + uid).catch(() => null);
      let refs = []; try { refs = JSON.parse((ix && ix.j) || '[]'); } catch (e) { refs = []; }
      refs = refs.filter((x) => Array.isArray(x) && REF.test(x[0])).slice(0, 10);
      const docs = await Promise.all(refs.map((x) => fsGet('reports/' + x[0]).catch(() => null)));
      const items = docs.filter((d) => d && d.uid === uid).map((d) => ({ ref: d.ref, cat: d.cat, st: d.st, at: d.at, up: d.up || d.at, msg: String(d.msg || '').slice(0, 140), rep: d.rep || '', rat: d.rat || 0 }));
      return send(res, 200, { items });
    }

    // ---- إحصاءات التعلّم (مجمّعة يوميًا في learnstats/{YYYY-MM-DD}؛ تُقرأ من لوحة المطوّر فقط) ----
    if (body.action === 'tel') {
      if (!uid) return send(res, 401, { code: 'auth' });
      if (limited('t' + uid, 20)) return send(res, 429, { code: 'slow' });
      const lf = await lfcfg().catch(() => null);
      if (lf && !lf.tel) return send(res, 200, { ok: true, off: 1 });
      const C = {}, Wt = {};
      for (const k of TEL_KEYS) { const v = body.c && typeof body.c === 'object' ? Math.floor(+body.c[k]) : 0; if (v > 0) C[k] = Math.min(50, v); }
      if (body.w && typeof body.w === 'object' && !Array.isArray(body.w)) {
        for (const [id, v] of Object.entries(body.w).slice(0, 20)) { const n = Math.floor(+v); if (WID.test(id) && n > 0) Wt[id] = Math.min(50, n); }
      }
      if (!Object.keys(C).length && !Object.keys(Wt).length) return send(res, 200, { ok: true });
      const day = new Date(now).toISOString().slice(0, 10);
      const cur = await fsGet('learnstats/' + day).catch(() => null);
      let o = {}; try { o = JSON.parse((cur && cur.j) || '{}'); } catch (e) { o = {}; }
      if (!o || typeof o !== 'object') o = {};
      o.c = o.c || {}; o.w = o.w || {};
      for (const [k, v] of Object.entries(C)) o.c[k] = (o.c[k] || 0) + v;
      for (const [k, v] of Object.entries(Wt)) o.w[k] = (o.w[k] || 0) + v;
      const ks = Object.keys(o.w);
      if (ks.length > 40) ks.sort((a, b) => o.w[b] - o.w[a]).slice(40).forEach((k) => { delete o.w[k]; });
      await fsSet('learnstats/' + day, { j: JSON.stringify(o), at: now });
      return send(res, 200, { ok: true });
    }

    // ---- إرسال بلاغ ----
    if (body.action === 'submit') {
      if (uid ? limited('s' + uid, 10) : limited('a' + ip, 3)) return send(res, 429, { code: 'slow' });
      if (!uid) { // حارس عام ضد إغراق البلاغات المجهولة (لكل نسخة تشغيل: 30 في الساعة)
        while (anon.length && now - anon[0] > 36e5) anon.shift();
        if (anon.length >= 30) return send(res, 429, { code: 'slow' });
        anon.push(now);
      }
      const cat = CATS.includes(body.cat) ? body.cat : '';
      const msg = txt(body.msg, 2000);
      if (!cat || msg.replace(/\s/g, '').length < 10) return send(res, 400, { code: 'bad' });
      let contact = clean(body.contact, 120).toLowerCase();
      if (contact && !EMAIL.test(contact)) return send(res, 400, { code: 'bad' });
      if (!uid && !contact) contact = '';

      let ix = null, refs = [];
      if (uid) {
        ix = await fsGet('rptu/' + uid).catch(() => null);
        try { refs = JSON.parse((ix && ix.j) || '[]'); } catch (e) { refs = []; }
        refs = refs.filter((x) => Array.isArray(x) && REF.test(x[0]) && x[1] > 0);
        if (ix && now - (+ix.lt || 0) < MIN_GAP) return send(res, 429, { code: 'slow' });
        if (refs.filter((x) => now - x[1] < 864e5).length >= DAY_MAX) return send(res, 429, { code: 'slow', why: 'day' });
      }

      // سياق الخادم (موثوق، لا يعتمد على الواجهة): الباقة الفعلية وحالة الرصيد — للحالات من نوع "مشكلة رصيد"
      let plan = '', q = '';
      if (uid) {
        try {
          const e = await entitlementOf(uid), pi = e && e.p ? e.p : null;
          plan = pi ? pi.p : 'free';
          const U = await usage(uid, pi ? pi.i : 0, plan);
          if (U) { const v = quotaView(U, plan); q = JSON.stringify({ used: v.used, limit: v.limit, tu: v.tutorUsed, tl: v.tutorLimit, ex: v.ex, ws: v.ws, ra: v.resetAt }); }
        } catch (e) { plan = plan || 'unknown'; }
      }
      const tech = JSON.stringify(techClean(body.tech));

      let ref = '', ok = false;
      for (let i = 0; i < 4 && !ok; i++) {
        ref = refGen();
        ok = await fsCreate('reports/' + ref, { ref, uid, em: uid ? clean(p.email, 120).toLowerCase() : '', ct: contact, cat, msg, st: 'new', at: now, up: now, tech, sp: plan, q, rep: '', rat: 0, nt: '' });
      }
      if (!ok) { await logErr('report', 'ref collision'); return send(res, 500, { code: 'err' }); }
      if (uid) {
        refs.unshift([ref, now]);
        await fsSet('rptu/' + uid, { j: JSON.stringify(refs.slice(0, 20)), lt: now }).catch((e) => logErr('report', 'index: ' + (e && e.message), uid));
      }
      return send(res, 200, { ok: true, ref });
    }

    return send(res, 400, { code: 'bad' });
  } catch (e) {
    console.error('[report]', e && e.message);
    await logErr('report', e && e.message, uid);
    return send(res, 500, { code: 'err' });
  }
};
module.exports._test = { scrub, techClean, REF, TEL_KEYS, WID };
