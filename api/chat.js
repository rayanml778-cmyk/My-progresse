// api/chat.js — وسيط آمن (Vercel Serverless Function) بين Moon AI و Groq
// محرك تدوير مفاتيح وتجاوز أعطال تلقائي بالكامل.
//
// متغيرات البيئة (Vercel › Settings › Environment Variables):
//   GROQ_KEY_1 … GROQ_KEY_N   أي عدد من المفاتيح (بلا حد في الكود) — تُكتشف تلقائيًا عند كل طلب
//   GROQ_MODEL           الافتراضي: openai/gpt-oss-20b
//   GROQ_SEARCH          اكتب 0 لتعطيل البحث في الإنترنت
//   GROQ_HISTORY         آخر 2–10 رسائل تُرسل للنموذج (الافتراضي 6)
//   GROQ_DEFAULT_TOKENS  سقف الرد الافتراضي (1024)      GROQ_MAX_TOKENS  السقف الأقصى (3072)
//   GROQ_BACKOFF_MS      جدول الانتظار بين جولات التدوير (الافتراضي 1500,2500,4000,6000,8000,10000)
//   GROQ_RETRY_BUDGET_MS أقصى زمن للمحاولات قبل المحاولة الأخيرة (الافتراضي 48000)
//   ALLOWED_ORIGINS      نطاقات مسموح لها بالاتصال من موقع آخر، مفصولة بفاصلة
//   PLAN_SECRET          إلزامي: سر توقيع رموز الباقات (32+ حرفًا، منفصل عن DEV_CODE_HASH وADMIN_SECRET). بدونه الجميع مجاني
//   ADMIN_SECRET         إلزامي لـ api/admin.js (صنع الأكواد وإلغاء الاشتراكات)
//   PLAN_CHECK_TTL_MS    مدة تخزين التحقق من الإلغاء (الافتراضي 30000، 0 = فوري)
//   GROQ_CONCURRENCY     أقصى طلبات متزامنة لكل نسخة (الافتراضي: عدد المفاتيح × 2)
//   (عدّاد توكن بريميوم/برو: الكمية ومدة التعبئة تُضبط من لوحة المطوّر ← الإعدادات، وتُحفظ في config/ai)
//   FREE_DAILY_REQ       سقف طلبات المجاني يوميًا لكل IP (الافتراضي 300) — حماية احتياطية فقط

const crypto = require('crypto');
const { activePlan, planSecretOk, adminInfo } = require('./_plan');
const { verifyIdToken, saReady, usage, remaining, cost, charge, quotaView, fsGet, fsCreate, logErr, promptsGet, lcfg } = require('./_fb');
const GROQ_URL = 'https://api.groq.com/openai/v1/chat/completions';
const DEFAULT_MODEL = 'openai/gpt-oss-20b';

const num = (v, d, lo, hi) => {
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : d;
};

const MAX_HISTORY = num(process.env.GROQ_HISTORY, 6, 2, 10);
const DEFAULT_TOKENS = num(process.env.GROQ_DEFAULT_TOKENS, 1024, 128, 4096);
const MAX_TOKENS = num(process.env.GROQ_MAX_TOKENS, 3072, 256, 8192);
const MAX_USER_CONTENT = 12000;
const MAX_ASSISTANT_CONTENT = 3000;
const MAX_SYSTEM = 64000;   // البرومبت + سياق المدرب الرياضي + تحليل الخطة الملصوقة قد يتجاوز 48000
const RATE_LIMIT = 40;
const RATE_WINDOW = 60 * 1000;

const BACKOFF = String(process.env.GROQ_BACKOFF_MS || '1500,2500,4000,6000,8000,10000')
  .split(',').map((x) => parseInt(x, 10)).filter((x) => x > 0);
const RETRY_BUDGET = num(process.env.GROQ_RETRY_BUDGET_MS, 48000, 0, 55000);

const Q_BASE = 15 * 1000;      // أول حجر صحي لمفتاح أصابه 429
const Q_STEP = 10 * 1000;      // يزيد مع كل 429 متتالٍ
const Q_MAX = 45 * 1000;       // سقف الحجر العادي
const Q_EXHAUSTED = 15 * 60 * 1000; // مفتاح استُنفدت حصته (Retry-After طويل)
const BAD_KEY_MS = 10 * 60 * 1000;  // مفتاح مرفوض 401/403

// ---------- محدّد الطلبات لكل IP ----------
const hits = new Map();
function limited(ip) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter((t) => now - t < RATE_WINDOW);
  arr.push(now);
  hits.set(ip, arr);
  if (hits.size > 5000) hits.clear();
  return arr.length > RATE_LIMIT;
}


// ---------- الباقات: سقوف وأولوية ----------
const PLAN_CFG = {
  free:    { pri: 0, cap: 600,  tutorCap: 0,    maxEff: 0, eff: 'low' },
  premium: { pri: 1, cap: 1400, tutorCap: 1600, maxEff: 1, eff: 'low' },
  pro:     { pri: 2, cap: 3072, tutorCap: 2200, maxEff: 2, eff: 'medium' },
};
const EFF = ['low', 'medium', 'high'];

// بوابة أولوية: برو ثم بريميوم ثم المجاني (مع تقادم 10 ثوانٍ يعادل درجة كاملة كي لا يُجوَّع أحد)
const waitq = [];
let active = 0;
function pump(limit) {
  while (active < limit && waitq.length) {
    const now = Date.now();
    waitq.sort((a, b) => (b.pri * 10000 + now - b.t) - (a.pri * 10000 + now - a.t));
    const w = waitq.shift();
    clearTimeout(w.timer);
    active++;
    w.resolve(true);
  }
}
function acquire(pri, limit, signal, maxWait) {
  return new Promise((resolve, reject) => {
    if (active < limit && !waitq.length) { active++; return resolve(true); }
    const w = { pri, t: Date.now(), resolve };
    w.timer = setTimeout(() => { const i = waitq.indexOf(w); if (i >= 0) waitq.splice(i, 1); resolve(false); }, maxWait);
    signal.addEventListener('abort', () => { clearTimeout(w.timer); const i = waitq.indexOf(w); if (i >= 0) waitq.splice(i, 1); reject(new Error('aborted')); }, { once: true });
    waitq.push(w);
  });
}
function release(limit) { active = Math.max(0, active - 1); pump(limit); }

// حماية احتياطية للمجاني (ذاكرة النسخة الدافئة فقط؛ الحصة الفعلية تُحسب داخل التطبيق)
const dayHits = new Map();
function freeDaily(ip) {
  const day = new Date().toISOString().slice(0, 10);
  const k = day + '|' + ip;
  const n = (dayHits.get(k) || 0) + 1;
  dayHits.set(k, n);
  if (dayHits.size > 8000) dayHits.clear();
  return n > num(process.env.FREE_DAILY_REQ, 300, 20, 100000);
}

const allowedOrigins = () =>
  (process.env.ALLOWED_ORIGINS || '').split(',').map((s) => s.trim().replace(/\/$/, '')).filter(Boolean);

// رسائل صديقة فقط تصل للمستخدم — لا رموز HTTP ولا استثناءات ولا stack traces
const MSG = {
  busy: 'الخدمة مشغولة حاليًا. حاول مرة أخرى بعد لحظات.',
  slow: 'طلبات كثيرة، حاول بعد قليل.',
  bad: 'طلب غير صالح.',
  conn: 'تعذّر الاتصال بخدمة الذكاء الاصطناعي.',
  conf: 'الخدمة غير مهيّأة حاليًا.',
  err: 'حدث خطأ مؤقت. حاول مرة أخرى.',
  plan: 'هذه الميزة متاحة في بريميوم وبرو.',
  quota: 'انتهت حصتك المجانية.',
  tokens: 'انتهى رصيدك من التوكن. يُعاد الشحن تلقائيًا عند انتهاء المهلة.',
  auth: 'سجّل الدخول أولًا.',
  lang: 'لغة غير مدعومة.',
  langlimit: 'وصلت إلى حد اللغات في باقتك.',
};
// ---- حدود اللغات من الخادم ----------------------------------------------------------------
// كل لغة يختارها المستخدم تحجز "خانة" في مستند مستقل langs/{uid}_{n} عبر fsCreate (ذرّي: لا يستبدل ولا يتسابق).
// الخانات تُملأ بالترتيب ولا تُحذف أبدًا. الحد الفعّال = أول LIM خانات؛ عند التخفيض تبقى اللغات الأخرى محفوظة
// ومقفلة (لا حذف لأي بيانات) وتُفتح فور الترقية. ما يرسله المتصفح لا يُعتمد: المصدر الوحيد هو هذه الخانات.
const LANG_CODES = ['ar', 'fr', 'en'];
const SLOTS = 3;
const slotCache = new Map(); // uid -> { t, s: [code|''] } ذاكرة قصيرة لتقليل القراءات؛ لا تُمنح بها صلاحية زائدة (الحد يُطبَّق عند كل طلب)
const SLOT_TTL = 10 * 60 * 1000;
const slotPath = (uid, n) => 'langs/' + uid + '_' + n;
async function langSlots(uid) {
  const s = [];
  for (let n = 0; n < SLOTS; n++) { const d = await fsGet(slotPath(uid, n)); s.push(d && LANG_CODES.includes(d.l) ? d.l : ''); }
  slotCache.set(uid, { t: Date.now(), s });
  if (slotCache.size > 5000) slotCache.delete(slotCache.keys().next().value);
  return s;
}
// يعيد { ok:true } أو { ok:false, langs:[اللغات الفعّالة], limit }
async function langGate(uid, plan, l) {
  const C = (await lcfg())[plan] || { n: 0, l: [] };           // الحد والقائمة المسموحة من لوحة المطوّر (config/langs): تُقرأ من الخادم (ذاكرة 30 ث)
  const lim = Math.min(C.n | 0, SLOTS), okL = (x) => C.l.includes(x);
  const act = (s) => s.slice(0, lim).filter((x) => x && okL(x));
  const deny = (s) => ({ ok: false, langs: act(s), limit: lim, allowed: C.l });
  if (!lim || !okL(l)) { let s = []; try { s = await langSlots(uid); } catch (e) { /* يُعاد رفض بلا قائمة */ } return deny(s); }
  const c = slotCache.get(uid);
  if (c && Date.now() - c.t < SLOT_TTL && act(c.s).includes(l)) return { ok: true };
  let s = await langSlots(uid);
  if (act(s).includes(l)) return { ok: true };
  if (s.includes(l)) return deny(s); // محفوظة لكنها خارج الحد الحالي أو غير مسموحة بعد تغيير الإعدادات
  for (let n = 0; n < lim; n++) {
    if (s[n]) continue;
    if (await fsCreate(slotPath(uid, n), { l, at: Date.now() })) { s[n] = l; slotCache.set(uid, { t: Date.now(), s }); return { ok: true }; }
    s = await langSlots(uid); // خسرنا السباق على هذه الخانة: أعد القراءة ثم جرّب التالية
    if (act(s).includes(l)) return { ok: true };
    if (s.includes(l)) return deny(s);
  }
  return deny(s);
}
function send(res, code, obj) {
  if (res.headersSent) return;
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(obj));
}
const fail = (res, code, key) => send(res, code, { error: MSG[key], code: key });

// =====================================================================
// 1) اكتشاف المفاتيح ديناميكيًا (بلا حد أقصى) + سجل الصحة
// =====================================================================
const clean = (v) => String(v == null ? '' : v).trim().replace(/^["']|["']$/g, '').trim();

// يمسح process.env في كل طلب: أي GROQ_KEY_<عدد> يُلتقط تلقائيًا، حتى GROQ_KEY_100000
function discoverKeys() {
  const numbered = [];
  for (const name of Object.keys(process.env)) {
    const m = /^GROQ_KEY_(\d+)$/.exec(name);
    if (!m) continue;
    const key = clean(process.env[name]);
    if (key) numbered.push({ n: Number(m[1]), id: name, key });
  }
  numbered.sort((a, b) => a.n - b.n);
  const list = numbered.slice();

  const seen = new Set();
  const out = list.filter((x) => !seen.has(x.key) && seen.add(x.key));
  const live = new Set(out.map((x) => x.key));
  for (const k of registry.keys()) if (!live.has(k)) registry.delete(k); // مفاتيح أُزيلت من البيئة
  out.forEach((x) => { H(x.key).id = x.id; });
  return out.map((x) => x.key);
}

// سجل الصحة في ذاكرة النسخة الدافئة
const registry = new Map();
function H(key) {
  let h = registry.get(key);
  if (!h) {
    h = { id: '?', fails: 0, rl: 0, rl429: 0, until: 0, bad: 0, last: 0, inflight: 0, ok: 0 };
    registry.set(key, h);
  }
  return h;
}
const healthy = (k, now) => H(k).until <= now && H(k).bad <= now;

function onSuccess(k) {
  const h = H(k);
  h.fails = 0; h.rl = 0; h.until = 0; h.ok++;
}
function onRateLimited(k, retryAfter) {
  const h = H(k);
  h.rl++; h.rl429++; h.fails++;
  let ms = Math.min(Q_BASE + (h.rl - 1) * Q_STEP, Q_MAX); // 30s → 45s → 60s
  if (retryAfter > Q_MAX) ms = Math.min(retryAfter, Q_EXHAUSTED); // حصة يومية مستنفدة
  else ms = Math.max(ms, retryAfter);
  h.until = Date.now() + ms;
  console.warn('[moon] quarantine', h.id, Math.round(ms / 1000) + 's', '(429 x' + h.rl + ')');
}
function onFault(k) {
  const h = H(k);
  h.fails++;
  h.until = Date.now() + Math.min(2000 * 2 ** Math.min(h.fails, 5), Q_MAX); // 4s … 60s
}
function onBadKey(k, status) {
  H(k).bad = Date.now() + BAD_KEY_MS;
  console.error('[moon] key rejected', H(k).id, status);
}

// اختيار موزون عشوائي بين المفاتيح السليمة: يفضّل الأقل انشغالًا والأقدم استخدامًا والأقل أعطالًا
function pickKey(pool, tried, force) {
  const now = Date.now();
  let c = pool.filter((k) => !tried.has(k) && (force ? H(k).bad <= now : healthy(k, now)));
  if (force && !c.length) c = pool.filter((k) => !tried.has(k)); // كلها مرفوضة؟ جرّبها على أي حال
  if (!c.length) return null;
  const w = c.map((k) => {
    const h = H(k);
    return (1 + Math.min((now - h.last) / 5000, 4)) / (1 + h.inflight + 0.5 * h.fails);
  });
  let r = Math.random() * w.reduce((a, b) => a + b, 0);
  for (let i = 0; i < c.length; i++) if ((r -= w[i]) <= 0) return c[i];
  return c[c.length - 1];
}
const soonest = (pool, tried) =>
  pool.filter((k) => !tried.has(k) && H(k).bad <= Date.now()).sort((a, b) => H(a).until - H(b).until)[0] || null;

const retryAfterMs = (r) => {
  const v = parseFloat(r.headers.get('retry-after'));
  return Number.isFinite(v) && v > 0 ? v * 1000 : 0;
};
const drain = (r) => { try { r.body && r.body.cancel && r.body.cancel(); } catch (e) {} };
const sleep = (ms, signal) =>
  new Promise((resolve, reject) => {
    if (signal.aborted) return reject(new Error('aborted'));
    const t = setTimeout(() => { signal.removeEventListener('abort', onAbort); resolve(); }, ms);
    const onAbort = () => { clearTimeout(t); reject(new Error('aborted')); };
    signal.addEventListener('abort', onAbort, { once: true });
  });

// =====================================================================
// 2+3) استدعاء Groq: توزيع الحمل، حجر صحي صامت، تجاوز فوري، backoff أُسّي
// يعيد { res, key } (ناجح أو 4xx غير قابل لإعادة المحاولة) أو null عند الاستنفاد.
// opts.retries: عدد جولات الانتظار | opts.force: تجاهل الحجر الصحي | opts.deadline: مهلة زمنية مطلقة
// =====================================================================
async function callGroq(payload, pool, signal, opts = {}) {
  const retries = opts.retries == null ? BACKOFF.length : opts.retries;
  const body = JSON.stringify(payload);
  for (let round = 0; round <= retries; round++) {
    const tried = new Set();
    let probed = false;
    for (;;) {
      if (signal.aborted) throw new Error('aborted');
      let key = pickKey(pool, tried, opts.force);
      if (!key) {
        // لا مفتاح سليم: في أول المحاولة نفحص المفتاح الأقرب للتعافي بدل ترك الطلب يفشل
        if (!tried.size && !probed) { key = soonest(pool, tried); probed = true; }
        if (!key) break;
      }
      tried.add(key);
      const h = H(key);
      h.inflight++; h.last = Date.now();
      let r;
      try {
        r = await fetch(GROQ_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + key },
          body,
          signal,
        });
      } catch (e) {
        h.inflight--;
        if (signal.aborted) throw e;
        onFault(key);
        continue;
      }
      if (r.ok) { onSuccess(key); return { res: r, key }; } // inflight يُحرَّر عند انتهاء الرد
      h.inflight--;
      if (r.status === 429) { onRateLimited(key, retryAfterMs(r)); drain(r); continue; }
      if (r.status === 401 || r.status === 403) { onBadKey(key, r.status); drain(r); continue; }
      if (r.status >= 500 || r.status === 408 || r.status === 498) { onFault(key); drain(r); continue; }
      return { res: r, key: null }; // 4xx آخر: يعالجه المستدعي
    }
    if (!opts.force && pool.every((k) => H(k).bad > Date.now())) return null; // كل المفاتيح مرفوضة: لا فائدة من الانتظار
    if (round >= retries) break;
    const wait = BACKOFF[Math.min(round, BACKOFF.length - 1)];
    if (opts.deadline && Date.now() + wait > opts.deadline) break; // لا نتجاوز ميزانية الوقت
    await sleep(wait, signal); // 2s → 4s → 8s → 16s
  }
  return null;
}

// حمولة خفيفة للمحاولة الأخيرة: بلا أدوات بحث، بلا بيانات سياق التطبيق، آخر رسالتين فقط، سقف أقل
function leanPayload(p) {
  const msgs = p.messages.filter((m) => m.role !== 'system').slice(-2);
  while (msgs.length && msgs[0].role !== 'user') msgs.shift();
  const sys = p.messages.find((m) => m.role === 'system');
  const out = { ...p, messages: [], max_completion_tokens: Math.min(p.max_completion_tokens, 1024) };
  delete out.tools; delete out.tool_choice;
  // حدود Groq تُحسب لكل نموذج: عند استنفاد حصة النموذج الرئيسي نحوّل الطلب لنموذج احتياطي بحصة مستقلة
  const fb = process.env.GROQ_FALLBACK_MODEL || 'llama-3.1-8b-instant';
  if (fb !== '0' && fb !== p.model) { out.model = fb; delete out.reasoning_effort; }
  else if (out.reasoning_effort) out.reasoning_effort = 'low';
  if (sys) out.messages.push({ role: 'system', content: sys.content.split('\n\n[APP CONTEXT]')[0] });
  out.messages.push(...msgs);
  return out;
}

async function handle(req, res) {
  // ---- CORS / فحص المصدر ----
  const origin = (req.headers.origin || '').replace(/\/$/, '');
  const allow = allowedOrigins();
  // طلب من نفس النطاق (الموقع نفسه، ومنه روابط Preview المتغيّرة) لا يُحجب أبدًا؛ القائمة تقيّد المواقع الأخرى فقط
  const host = String(req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim().toLowerCase();
  let sameOrigin = false;
  try { sameOrigin = !!origin && new URL(origin).host.toLowerCase() === host; } catch (e) { sameOrigin = false; }
  if (origin && allow.length && !sameOrigin) {
    if (!allow.includes(origin)) return send(res, 403, { error: MSG.err, code: 'origin' });
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Max-Age', '86400');
  }
  if (req.method === 'OPTIONS') { res.statusCode = 204; return res.end(); }
  if (req.method === 'GET' && String(req.url || '').includes('diag')) {
    // التشخيص (عدد المفاتيح، النموذج، حالة الأسرار) لصاحب ADMIN_SECRET فقط؛ الزائر المجهول لا يرى إلا {ok:true}
    const ai = adminInfo(), got = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    const h = (s) => crypto.createHash('sha256').update(String(s)).digest();
    if (!(ai.ok && got && crypto.timingSafeEqual(h(got), h(ai.s)))) return send(res, 200, { ok: true });
    return send(res, 200, { keys: discoverKeys().length, model: process.env.GROQ_MODEL || DEFAULT_MODEL, requireAuth: process.env.REQUIRE_AUTH !== '0', serviceAccount: saReady(), planSecret: planSecretOk() });
  }
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST, OPTIONS');
    return send(res, 405, { error: MSG.err, code: 'method' });
  }

  const pool = discoverKeys(); // يُعاد المسح في كل طلب: المفاتيح الجديدة تدخل التدوير فورًا
  if (!pool.length) {
    console.error('[moon] no GROQ_KEY_n configured');
    return fail(res, 500, 'conf');
  }

  const ip = String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'x').split(',')[0].trim();
  if (limited(ip)) return fail(res, 429, 'slow');

  let body = req.body;
  if (typeof body === 'string') { try { body = JSON.parse(body); } catch (e) { body = null; } }
  if (!body || typeof body !== 'object') return fail(res, 400, 'bad');

  // الهوية: Firebase ID token إلزامي (REQUIRE_AUTH=0 لتعطيله). الرمز المرتبط بحساب آخر يُعامل كمجاني
  let uid = null;
  if (process.env.REQUIRE_AUTH !== '0') {
    uid = await verifyIdToken(String(req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
    if (!uid) return fail(res, 401, 'auth');
  }
  const pinfo = uid ? await activePlan(body.pt, uid) : null; // توقيع + حساب + عدم الإلغاء (entitlements/{uid})
  const plan = pinfo ? pinfo.p : 'free';
  const cfg = PLAN_CFG[plan];
  const tutor = body.tutor === true || ['ar', 'fr', 'en'].includes(body.tutor); // التطبيق يرسل رمز لغة المعلّم
  if (tutor && plan === 'free') return fail(res, 403, 'plan');
  if (tutor && uid && saReady()) {
    // المعلّم يلزمه رمز لغة صالح (tutor:true بلا لغة كان سيتجاوز الحدّ)، ثم تُحجز/تُتحقَّق الخانة من الخادم
    if (!LANG_CODES.includes(body.tutor)) return fail(res, 403, 'lang');
    let g; try { g = await langGate(uid, plan, body.tutor); } catch (e) { console.error('[lang]', e && e.message); await logErr('lang', e && e.message, uid); return fail(res, 503, 'err'); }
    if (!g.ok) return send(res, 403, { error: MSG.langlimit, code: 'langlimit', langs: g.langs, limit: g.limit, allowed: g.allowed, plan });
  }
  if (plan === 'free' && freeDaily(ip)) return fail(res, 429, 'quota');
  // الرصيد من جهة الخادم (Firestore): لا يتأثر بمسح المتصفح أو بتعديل الواجهة
  let U = null;
  if (uid && saReady()) {
    U = await usage(uid, pinfo ? pinfo.i : 0, plan);
    if (U && remaining(U, plan, pinfo && pinfo.k, tutor) <= 0) return send(res, 429, { error: plan === 'free' ? MSG.quota : MSG.tokens, code: 'quota', quota: quotaView(U, plan) }); // يحمل وقت الخادم وموعد التجديد للعدّاد
  }

  const valid = [];
  for (const m of Array.isArray(body.messages) ? body.messages : []) {
    if (!m || (m.role !== 'user' && m.role !== 'assistant')) continue;
    const lim = m.role === 'user' ? MAX_USER_CONTENT : MAX_ASSISTANT_CONTENT;
    const content = typeof m.content === 'string' ? m.content.slice(0, lim) : '';
    if (content) valid.push({ role: m.role, content });
  }
  const recent = valid.slice(-(tutor ? 8 : MAX_HISTORY));
  while (recent.length && recent[0].role !== 'user') recent.shift();
  if (!recent.length) return fail(res, 400, 'bad');

  const bill = async (o) => { if (!U) return; try { await charge(U, uid, plan, tutor, cost(recent[recent.length - 1].content.length, o)); } catch (e) { console.error('[bill]', e && e.message); await logErr('bill', e && e.message, uid); } };
  const messages = [];
  // تعليمات المطوّر (لوحة المطوّر › المحتوى): «all» لكل الطلبات، وتعليمات اللغة فقط لطلبات المعلّم (التطبيق يرسل لغته في body.tutor)
  let extra = '';
  if (saReady()) { try { const P = await promptsGet(); extra = [P.all, LANG_CODES.includes(body.tutor) ? P[body.tutor] : ''].filter(Boolean).join('\n\n'); } catch (e) { extra = ''; } }
  if (typeof body.system === 'string' && body.system.trim()) {
    messages.push({ role: 'system', content: body.system.slice(0, MAX_SYSTEM) + (extra ? '\n\n[ADMIN INSTRUCTIONS]\n' + extra : '') });
  } else if (extra) {
    messages.push({ role: 'system', content: '[ADMIN INSTRUCTIONS]\n' + extra });
  }
  messages.push(...recent);

  const model = process.env.GROQ_MODEL || DEFAULT_MODEL;
  const stream = body.stream === true;
  const payload = {
    model, messages, stream,
    temperature: (typeof body.temperature === 'number' && Number.isFinite(body.temperature)) ? Math.min(1, Math.max(0, body.temperature)) : 0.5,
    max_completion_tokens: Math.min(num(body.max_tokens, DEFAULT_TOKENS, 1, MAX_TOKENS), tutor ? cfg.tutorCap : cfg.cap),
  };
  const isOss = /^openai\/gpt-oss/.test(model);
  if (isOss) {
    const base = tutor ? 'medium' : (plan === 'free' ? (process.env.GROQ_REASONING || cfg.eff) : cfg.eff);
    const want = EFF.includes(body.effort) ? body.effort : base;
    payload.reasoning_effort = EFF[Math.min(EFF.indexOf(want), cfg.maxEff)];
  }
  const wantSearch = body.search === true && isOss && process.env.GROQ_SEARCH !== '0';
  const full = wantSearch ? { ...payload, tools: [{ type: 'browser_search' }], tool_choice: 'auto' } : payload;

  const ac = new AbortController();
  const limit = Math.max(3, num(process.env.GROQ_CONCURRENCY, pool.length * 2, 1, 500));
  let freed = false;
  const free = () => { if (!freed) { freed = true; release(limit); } };
  res.on('close', () => { if (!res.writableEnded) ac.abort(); free(); });

  // انتظار الدور حسب الأولوية (برو > بريميوم > مجاني)
  let slot = false;
  try { slot = await acquire(cfg.pri, limit, ac.signal, 22000); } catch (e) { return; }
  if (!slot) { freed = true; res.setHeader('Retry-After', '4'); return fail(res, 503, 'busy'); }

  let up = null;
  try {
    const deadline = Date.now() + RETRY_BUDGET;
    up = await callGroq(full, pool, ac.signal, { deadline });
    // أداة البحث مرفوضة (نموذج/حساب لا يدعمها): أعد بدونها
    if (up && !up.res.ok && wantSearch && [400, 404, 422].includes(up.res.status)) {
      drain(up.res);
      up = await callGroq(payload, pool, ac.signal, { deadline });
    }
    // السلسلة الأخيرة: استُنفدت كل المفاتيح والمحاولات → حمولة خفيفة تُمرَّر قسرًا عبر كل المفاتيح
    if (!up) {
      console.warn('[moon] all keys drained — lean fallback');
      up = await callGroq(leanPayload(payload), pool, ac.signal, { retries: 0, force: true });
    }
  } catch (e) {
    if (ac.signal.aborted) return;
    console.error('[moon] upstream failure:', e && e.message);
    await logErr('upstream', e && e.message, uid);
    return fail(res, 502, 'conn');
  }

  if (!up && pool.every((k) => H(k).bad > Date.now())) { console.error('[moon] ALL keys rejected (401/403) — تحقق من GROQ_KEY_n في Vercel'); await logErr('keys', 'all keys rejected (401/403)', uid); return fail(res, 503, 'conf'); }

  // كل المفاتيح مشغولة الآن: الواجهة لا تعرض خطأ، بل تنتظر بصمت وتعيد المحاولة تلقائيًا حتى يتحرر مفتاح
  if (!up) { res.setHeader('Retry-After', '4'); return fail(res, 503, 'busy'); }

  // ملاحظة: كان اسمه release فيحجب دالة release(limit) العامة، فلا تُحرَّر خانة التزامن أبدًا ويتحول الخادم إلى «مشغول»
  const releaseKey = () => { if (up.key) { const h = H(up.key); if (h.inflight > 0) h.inflight--; } };
  try {
    if (!up.res.ok) {
      let detail = '';
      try { detail = ((await up.res.json()).error || {}).message || ''; } catch (e) {}
      console.error('[moon] upstream error', up.res.status, String(detail).slice(0, 300));
      await logErr('upstream_http', up.res.status + ': ' + String(detail).slice(0, 200), uid);
      return up.res.status === 413 ? fail(res, 413, 'bad') : fail(res, 502, 'err');
    }
    if (!stream) {
      try { const j = await up.res.json(); await bill((((j.choices || [])[0] || {}).message || {}).content ? j.choices[0].message.content.length : 0); return send(res, 200, j); } catch (e) { return fail(res, 502, 'err'); }
    }
    res.statusCode = 200;
    res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('X-Accel-Buffering', 'no');
    let sb = '', oc = 0; const td = new TextDecoder();
    try {
      for await (const chunk of up.res.body) {
        res.write(chunk); sb += td.decode(chunk, { stream: true });
        let i; while ((i = sb.indexOf('\n')) >= 0) {
          const ln = sb.slice(0, i).trim(); sb = sb.slice(i + 1);
          if (ln.startsWith('data:')) { try { const d = JSON.parse(ln.slice(5)); oc += (((d.choices || [])[0] || {}).delta || {}).content ? d.choices[0].delta.content.length : 0; } catch (e) {} }
        }
      }
    } catch (e) { /* انقطاع */ }
    await bill(oc); // قبل إنهاء الرد: كي يرى طلب المزامنة التالي من التطبيق الرصيد بعد الخصم
    res.end();
  } finally {
    releaseKey();
    free(); // تحرير خانة التزامن فور انتهاء الرد (وليس فقط عند حدث close)
  }
}

module.exports = async function handler(req, res) {
  try {
    await handle(req, res);
  } catch (e) { // شبكة أمان أخيرة: لا استثناءات ولا stack traces للمستخدم
    console.error('[moon] unhandled:', e && e.stack);
    await logErr('unhandled', e && e.message, '');
    try { if (!res.headersSent) fail(res, 500, 'err'); else res.end(); } catch (x) {}
  }
};
module.exports._test = { discoverKeys, registry };
