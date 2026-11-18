// api/activate.js — تفعيل الاشتراك بكود فردي (استخدام واحد). الباقة والمدة من سجل الكود في Firestore، لا من الطلب.
//   codes/{sha256(الكود)}  = { p:'premium'|'pro', k:'w'|'m', days, xp:<آخر موعد للاستخدام ms>, st:'new'|'used'|'revoked', note, cr, u?, at? }
//   redeemed/{sha256}      = { u, at }  ← قفل ذري (إنشاء فقط إن لم يوجد): من ينشئه أولًا يفوز، فلا يُستخدم الكود مرتين حتى مع طلبين متزامنين
//   entitlements/{uid}     = { tok, at, cid, pl, exp, rv }  ← اشتراك الحساب (الخادم وحده يكتب)
// يتطلب Authorization: Bearer <Firebase ID token>.
// الطلب: POST { code }  (أي plan/period في الطلب تُتجاهل)  →  { token, plan, period, exp }
// الأخطاء: 503 conf | 401 auth | 429 slow | 400 bad | 403 invalid | 409 used | 410 expired
// يحتاج PLAN_SECRET (انظر _plan.js). لم يعد DEV_CODE_HASH مستخدمًا هنا.
const { sign, verifyToken, forget, secretInfo, codeNorm, codeId } = require('./_plan');
const { verifyIdToken, saReady, fsGet, fsSet, fsCreate, fsDel } = require('./_fb');

const DAY = 86400000;
const tries = new Map();
const MAX_TRIES = 8, WINDOW = 10 * 60 * 1000;

// يُحتسب المحاولات الفاشلة فقط (كود خاطئ/مستخدم/صيغة سيئة): التخمين هو الخطر. التفعيل الناجح لا يستهلك الحدّ،
// فلا يُحجب مستخدمون حقيقيون يشتركون في عنوان IP واحد (شبكة جوال/واي فاي مشترك).
const recent = (ip) => { const now = Date.now(); return (tries.get(ip) || []).filter((t) => now - t < WINDOW); };
const limited = (ip) => recent(ip).length >= MAX_TRIES;
function noteFail(ip) {
  const arr = recent(ip); arr.push(Date.now()); tries.set(ip, arr);
  if (tries.size > 2000) tries.clear();
}
const send = (res, code, obj) => {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(obj));
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

module.exports = async function handler(req, res) {
  try {
    if (req.method !== 'POST') { res.setHeader('Allow', 'POST'); return send(res, 405, { code: 'method' }); }
    if (!secretInfo().ok || !saReady()) return send(res, 503, { code: 'conf' }); // لا تشغيل بلا PLAN_SECRET سليم

    const ip = String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'x').split(',')[0].trim();
    if (limited(ip)) return send(res, 429, { code: 'slow' });

    const uid = await verifyIdToken(String(req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
    if (!uid) return send(res, 401, { code: 'auth' });

    let body = req.body;
    if (typeof body === 'string') { try { body = JSON.parse(body); } catch (e) { body = null; } }
    if (!body || typeof body !== 'object') { noteFail(ip); return send(res, 400, { code: 'bad' }); }

    const norm = codeNorm(body.code);
    if (!norm) { noteFail(ip); return send(res, 400, { code: 'bad' }); }
    const invalid = async () => { noteFail(ip); await sleep(700); return send(res, 403, { code: 'invalid' }); };
    if (norm.length < 16 || norm.length > 40) return invalid();

    const id = codeId(norm);
    const rec = await fsGet('codes/' + id);
    if (!rec || rec.st === 'revoked') return invalid();
    if ((rec.p !== 'premium' && rec.p !== 'pro') || !(rec.days > 0 && rec.days <= 366)) return invalid(); // سجل تالف: لا يُفعَّل

    // الكود مستخدَم سابقًا: نفس الحساب يعيد الإدخال (انقطع الرد مثلًا) فيستلم رمزه نفسه، وغيره يُرفض
    const again = async () => {
      const cl = await fsGet('redeemed/' + id).catch(() => null);
      if (cl && cl.u === uid) {
        const ent = await fsGet('entitlements/' + uid).catch(() => null);
        const p = ent && ent.cid === id && ent.tok && !(+ent.rv) ? verifyToken(ent.tok) : null;
        if (p && p.u === uid) return send(res, 200, { token: ent.tok, plan: p.p, period: p.k === 'w' ? 'week' : 'month', exp: p.e });
      }
      noteFail(ip);
      return send(res, 409, { code: 'used' });
    };
    if (rec.st === 'used') return again();

    const now = Date.now();
    if (rec.xp && now > rec.xp) return send(res, 410, { code: 'expired' });

    // القفل الذري: أول من ينشئ redeemed/{id} يفوز
    if (!(await fsCreate('redeemed/' + id, { u: uid, at: now }))) return again();

    try {
      const k = rec.k === 'w' ? 'w' : 'm';
      // نفس الباقة النشطة = تمديد من تاريخ انتهائها (لا تضيع الأيام المتبقية). باقة مختلفة = تحلّ محلّ الحالية.
      const cur = await fsGet('entitlements/' + uid).catch(() => null);
      const start = cur && cur.tok && !(+cur.rv) && cur.exp > now && cur.pl === rec.p ? cur.exp : now;
      const exp = start + rec.days * DAY;
      const token = sign({ p: rec.p, k, i: now, e: exp, u: uid, c: id.slice(0, 16) });
      if (!token) throw new Error('sign');
      await fsSet('entitlements/' + uid, { tok: token, at: now, cid: id, pl: rec.p, exp, rv: 0 }); // يحلّ محل اشتراك الحساب الحالي
      forget(uid);
      try { await fsSet('codes/' + id, Object.assign({}, rec, { st: 'used', u: uid, at: now })); }
      catch (e) { console.error('[activate] mark', e && e.message); } // القفل هو المرجع؛ الوسم للعرض فقط
      return send(res, 200, { token, plan: rec.p, period: k === 'w' ? 'week' : 'month', exp });
    } catch (e) {
      try { await fsDel('redeemed/' + id); } catch (e2) { /* يبقى القفل؛ يُحرَّر يدويًا من لوحة Firestore */ }
      throw e; // لم يُسلَّم اشتراك: يُحرَّر الكود ليعيد المستخدم المحاولة
    }
  } catch (e) {
    console.error('[activate]', e && e.message);
    return send(res, 500, { code: 'err' });
  }
};
