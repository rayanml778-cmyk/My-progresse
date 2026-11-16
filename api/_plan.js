// api/_plan.js — توقيع والتحقق من رموز الاشتراك (HMAC). الملفات التي تبدأ بـ _ لا تُنشر كدالة في Vercel.
// السر: PLAN_SECRET (اختياري) وإلا يُستخدم DEV_CODE_HASH. تغيير السر يُبطل كل الرموز الصادرة فورًا.
const crypto = require('crypto');

const secret = () => String(process.env.PLAN_SECRET || process.env.DEV_CODE_HASH || '').trim();
const mac = (body, s) => crypto.createHmac('sha256', s).update(body).digest('base64url');

function sign(payload) {
  const s = secret();
  if (!s) return null;
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return body + '.' + mac(body, s);
}

// يعيد { p:'premium'|'pro', k:'m'|'w', e:<ms>, i:<ms> } أو null إن كان الرمز مزوّرًا أو منتهيًا
function verify(tok) {
  const s = secret();
  if (!s || typeof tok !== 'string' || tok.length > 600) return null;
  const i = tok.indexOf('.');
  if (i < 1) return null;
  const body = tok.slice(0, i);
  const a = Buffer.from(tok.slice(i + 1));
  const b = Buffer.from(mac(body, s));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  let p;
  try { p = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')); } catch (e) { return null; }
  if (!p || (p.p !== 'premium' && p.p !== 'pro') || !(p.e > Date.now())) return null;
  return p;
}

module.exports = { sign, verify };
