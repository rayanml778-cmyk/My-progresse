// api/quota.js — الحالة الرسمية للرصيد من الخادم: يطبّق التصفير المستحق (بعد 5 ساعات) مرة واحدة ويحفظه، ويعيد وقت الخادم للعدّاد.
// الطلب: GET/POST مع Authorization: Bearer <Firebase ID token> (+ pt اختياري في POST) →
//   { plan, now, ex, resetAt, used, limit, cooldownMs, ai?, subOk, sub:{tok,p,k,e}|null }
//   ai (بريميوم/برو فقط) = { cap, used, left, ws, resetAt, ms }: رصيد التوكن، وresetAt = موعد التعبئة (0 = الرصيد كامل ولم تبدأ نافذة).
//   sub = اشتراك الحساب كما هو في الخادم (المرجع). يستعيده التطبيق عند كل دخول/تحديث دون الاعتماد على التخزين المحلي. subOk=true يعني أن الخادم تأكد من الحالة.
//   إن تعذّرت قراءة الاشتراك مؤقتًا: 503 { code:'busy' } (يعيد العميل المحاولة ولا يُنزَّل المشترك إلى المجاني).
const { activePlan, entitlementOf } = require('./_plan');
const { verifyIdToken, saReady, usage, quotaView, noticeGet, lfcfg } = require('./_fb');
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
    // الاشتراك من الخادم أولًا: رمز العميل (إن وُجد وصحّ) أو سجل entitlements/{uid}. رمز حساب آخر أو ملغى أو منتهٍ لا يُعتدّ به.
    let pinfo = await activePlan(body && body.pt, uid), tok = pinfo ? body.pt : '';
    if (!pinfo) {
      let e;
      try { e = await entitlementOf(uid); } catch (x) { return send(res, 503, { code: 'busy' }); }
      if (e) { pinfo = e.p; tok = e.tok; }
    }
    const plan = pinfo ? pinfo.p : 'free';
    const U = await usage(uid, pinfo ? pinfo.i : 0, plan);
    if (!U) return send(res, 503, { code: 'conf' });
    return send(res, 200, Object.assign(quotaView(U, plan), { subOk: true, sub: pinfo ? { tok, p: pinfo.p, k: pinfo.k, e: pinfo.e } : null, notice: await noticeGet(), lf: await lfcfg().catch(() => null) })); // notice = إشعار المطوّر الحالي (أو null)
  } catch (e) {
    console.error('[quota]', e && e.message);
    return send(res, 500, { code: 'err' });
  }
};
