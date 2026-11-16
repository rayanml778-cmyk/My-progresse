// api/activate.js — تفعيل الاشتراك بكود المطوّر (يُحفظ مجزّأً SHA-256 في متغير بيئة، لا يظهر في أي ملف أمامي)
//   DEV_CODE_HASH = SHA-256 (hex) لكود التفعيل بعد تحويله لأحرف كبيرة وإزالة المسافات
// يتطلب Authorization: Bearer <Firebase ID token>، ويربط الرمز بالحساب (u) ويحفظه في entitlements/{uid}
// الطلب: POST { code, plan:'premium'|'pro', period:'month'|'week' }  →  { token, plan, period, exp }
const crypto = require('crypto');
const { sign } = require('./_plan');
const { verifyIdToken, saReady, fsSet } = require('./_fb');

const DAY = 86400000;
const tries = new Map();
const MAX_TRIES = 8, WINDOW = 10 * 60 * 1000;

function limited(ip) {
  const now = Date.now();
  const arr = (tries.get(ip) || []).filter((t) => now - t < WINDOW);
  arr.push(now);
  tries.set(ip, arr);
  if (tries.size > 2000) tries.clear();
  return arr.length > MAX_TRIES;
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
    const hash = String(process.env.DEV_CODE_HASH || '').trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(hash) || !sign({ t: 1 }) || !saReady()) return send(res, 503, { code: 'conf' });

    const ip = String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'x').split(',')[0].trim();
    if (limited(ip)) return send(res, 429, { code: 'slow' });

    const uid = await verifyIdToken(String(req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
    if (!uid) return send(res, 401, { code: 'auth' });

    let body = req.body;
    if (typeof body === 'string') { try { body = JSON.parse(body); } catch (e) { body = null; } }
    if (!body || typeof body !== 'object') return send(res, 400, { code: 'bad' });

    const plan = body.plan === 'pro' ? 'pro' : body.plan === 'premium' ? 'premium' : '';
    const period = body.period === 'week' ? 'week' : body.period === 'month' ? 'month' : '';
    const code = String(body.code || '').trim().toUpperCase().replace(/\s+/g, '').slice(0, 120);
    if (!plan || !period || !code) return send(res, 400, { code: 'bad' });

    const got = crypto.createHash('sha256').update(code).digest();
    const want = Buffer.from(hash, 'hex');
    if (!crypto.timingSafeEqual(got, want)) { await sleep(700); return send(res, 403, { code: 'invalid' }); }

    const now = Date.now();
    const exp = now + (period === 'week' ? 7 : 30) * DAY;
    const token = sign({ p: plan, k: period === 'week' ? 'w' : 'm', i: now, e: exp, u: uid });
    await fsSet('entitlements/' + uid, { tok: token, at: now }); // الخادم وحده يكتب الاشتراك
    return send(res, 200, { token, plan, period, exp });
  } catch (e) {
    console.error('[activate]', e && e.message);
    return send(res, 500, { code: 'err' });
  }
};
