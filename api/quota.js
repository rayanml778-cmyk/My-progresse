// api/quota.js — الحالة الرسمية للرصيد من الخادم: يطبّق التصفير المستحق (بعد 5 ساعات) مرة واحدة ويحفظه، ويعيد وقت الخادم للعدّاد.
// الطلب: GET/POST مع Authorization: Bearer <Firebase ID token> (+ pt اختياري في POST) →
//   { plan, now, ex, resetAt, used, limit, cooldownMs }
const { activePlan } = require('./_plan');
const { verifyIdToken, saReady, usage, quotaView } = require('./_fb');
const send = (res, code, obj) => {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(obj));
};
module.exports = async function handler(req, res) {
  try {
    if (req.method !== 'GET' && req.method !== 'POST') { res.setHeader('Allow', 'GET, POST'); return send(res, 405, { code: 'method' }); }
    if (!saReady()) return send(res, 503, { code: 'conf' });
    const uid = await verifyIdToken(String(req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
    if (!uid) return send(res, 401, { code: 'auth' });
    let body = req.body;
    if (typeof body === 'string') { try { body = JSON.parse(body); } catch (e) { body = null; } }
    const pinfo = await activePlan(body && body.pt, uid); // رمز حساب آخر أو ملغى أو منتهٍ = مجاني
    const plan = pinfo ? pinfo.p : 'free';
    const U = await usage(uid, pinfo ? pinfo.i : 0, plan);
    if (!U) return send(res, 503, { code: 'conf' });
    return send(res, 200, quotaView(U, plan));
  } catch (e) {
    console.error('[quota]', e && e.message);
    return send(res, 500, { code: 'err' });
  }
};
