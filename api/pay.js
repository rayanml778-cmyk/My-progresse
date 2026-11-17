// api/pay.js — طلبات الاشتراك بالتحويل البنكي (من جهة المستخدم). المراجعة والقبول من لوحة المطوّر عبر api/admin.js.
// يتطلب Authorization: Bearer <Firebase ID token>. POST JSON:
//   { action:'info' }                                      → { bank, last:{id,st,p,k,at,rn}|null, prices }   (بيانات الحساب + حالة آخر طلب)
//   { action:'submit', plan, period, ref, paid?, proof }   → { ok:true, id }    proof = صورة data:image/jpeg|png|webp;base64 (≤ 700 ألف حرف)
// الأخطاء: 503 conf | 401 auth | 429 slow | 400 bad | 409 pending | 413 big
// الكتابة كلها من الخادم (حساب الخدمة): payments/{id} + paymentProofs/{id} + payreq/{uid}. لا تحتاج قواعد Firestore جديدة (تبقى مغلقة على العملاء).
const crypto = require('crypto');
const { verifyIdTokenFull, saReady, fsGet, fsSet } = require('./_fb');

const PRICE = { premium: { m: 499, w: 149 }, pro: { m: 999, w: 299 } }; // سنت أمريكي — طابق PRICE في index.html
const MAX_PROOF = 700000, MIN_GAP = 60 * 1000, tries = new Map();
const send = (res, code, obj) => {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(obj));
};
const limited = (key) => {
  const now = Date.now(), arr = (tries.get(key) || []).filter((t) => now - t < 10 * 60 * 1000);
  arr.push(now); tries.set(key, arr); if (tries.size > 2000) tries.clear();
  return arr.length > 20;
};
const imgOk = (s) => { // الشكل + البصمة الحقيقية للملف (JPEG/PNG/WEBP)
  const m = /^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/]+={0,2})$/.exec(s);
  if (!m) return false;
  const b = Buffer.from(m[2].slice(0, 24), 'base64');
  return m[1] === 'jpeg' ? b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff
    : m[1] === 'png' ? b.subarray(0, 4).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47]))
    : b.subarray(0, 4).toString() === 'RIFF' && b.subarray(8, 12).toString() === 'WEBP';
};
const clean = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, n);

module.exports = async function handler(req, res) {
  try {
    if (req.method !== 'POST') { res.setHeader('Allow', 'POST'); return send(res, 405, { code: 'method' }); }
    if (!saReady()) return send(res, 503, { code: 'conf' });
    const ip = String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'x').split(',')[0].trim();
    if (limited(ip)) return send(res, 429, { code: 'slow' });

    const p = await verifyIdTokenFull(String(req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
    if (!p) return send(res, 401, { code: 'auth' });
    const uid = p.sub;

    let body = req.body;
    if (typeof body === 'string') { try { body = JSON.parse(body); } catch (e) { body = null; } }
    if (!body || typeof body !== 'object') return send(res, 400, { code: 'bad' });

    const last = await fsGet('payreq/' + uid).catch(() => null);

    if (body.action === 'info') {
      const b = await fsGet('config/bank').catch(() => null);
      return send(res, 200, { bank: b ? b.text || '' : '', prices: PRICE, last: last ? { id: last.id, st: last.st, p: last.p, k: last.k, at: last.at, rn: last.rn || '' } : null });
    }

    if (body.action === 'submit') {
      const plan = body.plan === 'pro' ? 'pro' : body.plan === 'premium' ? 'premium' : '';
      const k = body.period === 'week' ? 'w' : body.period === 'month' ? 'm' : '';
      const ref = clean(body.ref, 80), paid = clean(body.paid, 30), proof = String(body.proof || '');
      if (!plan || !k || ref.length < 3) return send(res, 400, { code: 'bad' });
      if (proof.length > MAX_PROOF) return send(res, 413, { code: 'big' });
      if (!imgOk(proof)) return send(res, 400, { code: 'bad' });
      const now = Date.now();
      if (last && last.st === 'pending') return send(res, 409, { code: 'pending' });
      if (last && now - (last.at || 0) < MIN_GAP) return send(res, 429, { code: 'slow' });
      const id = crypto.randomBytes(10).toString('hex');
      await fsSet('paymentProofs/' + id, { img: proof, at: now });
      await fsSet('payments/' + id, { uid, email: String(p.email || '').slice(0, 120), p: plan, k, amt: PRICE[plan][k], paid, ref, st: 'pending', cr: now, hp: 1 });
      await fsSet('payreq/' + uid, { id, st: 'pending', p: plan, k, at: now, rn: '' });
      return send(res, 200, { ok: true, id });
    }
    return send(res, 400, { code: 'bad' });
  } catch (e) {
    console.error('[pay]', e && e.message);
    return send(res, 500, { code: 'err' });
  }
};
