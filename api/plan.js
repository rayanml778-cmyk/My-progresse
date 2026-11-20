// api/_plan.js — رموز الاشتراك (HMAC) + التحقق من الإلغاء + أدوات الأكواد. الملفات التي تبدأ بـ _ لا تُنشر كدالة في Vercel.
//
// الأسرار (متغيرات بيئة، كلها إلزامية وكلٌّ منها منفصل عن الآخر):
//   PLAN_SECRET   سر توقيع رموز الاشتراك: 32 حرفًا فأكثر، ولا يجوز أن يساوي DEV_CODE_HASH أو ADMIN_SECRET أو يحتويهما.
//   ADMIN_SECRET  سر لوحة الإدارة api/admin.js (صنع الأكواد وإلغاء الاشتراكات).
//   DEV_CODE_HASH متقاعد: لا يُقرأ للتفعيل ولا للتوقيع. يُستخدم هنا فقط للتأكد أن أحدًا لم يعد استخدامه سرًّا.
// إن كان PLAN_SECRET ناقصًا أو ضعيفًا أو مُعاد الاستخدام: التوقيع يفشل، والتفعيل يرد 503، ولا يُقبل أي رمز مدفوع (الكل مجاني).
//
// بنية الرمز: base64url(JSON{ p:'premium'|'pro', k:'m'|'w', i:<بداية ms>, e:<انتهاء ms>, u:<uid>, c:<معرّف الكود> }) + '.' + HMAC
// الإلغاء: الرمز وحده لا يكفي. لا يُقبل إلا إذا طابق entitlements/{uid}.tok ولم يُوسم بالإلغاء (rv).
const crypto = require('crypto');
const { fsGet } = require('./_fb');

const norm = (v) => String(v || '').trim().toLowerCase();
const MIN_LEN = 32;

// سر قوي ومنفصل: طويل، ولا يساوي أي سر آخر ولا يحتويه (ولا يحتويه الآخر)
function strong(value, others) {
  const s = String(value || '').trim();
  if (!s) return { ok: false, why: 'missing' };
  if (s.length < MIN_LEN) return { ok: false, why: 'short' };
  const a = norm(s);
  for (const o of others) {
    const b = norm(o);
    if (b.length >= 8 && (a === b || a.includes(b) || b.includes(a))) return { ok: false, why: 'reused' };
  }
  return { ok: true, s };
}
const secretInfo = () => strong(process.env.PLAN_SECRET, [process.env.DEV_CODE_HASH, process.env.ADMIN_SECRET]);
const adminInfo = () => strong(process.env.ADMIN_SECRET, [process.env.DEV_CODE_HASH, process.env.PLAN_SECRET]);
const planSecretOk = () => secretInfo().ok;

const mac = (body, s) => crypto.createHmac('sha256', s).update(body).digest('base64url');

function sign(payload) {
  const si = secretInfo();
  if (!si.ok) return null;
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return body + '.' + mac(body, si.s);
}

// تحقق تشفيري فقط (توقيع + انتهاء + شكل الحمولة). لا يعرف بالإلغاء: استخدم activePlan للقرارات.
function verifyToken(tok) {
  const si = secretInfo();
  if (!si.ok || typeof tok !== 'string' || tok.length > 600) return null;
  const i = tok.indexOf('.');
  if (i < 1) return null;
  const body = tok.slice(0, i);
  const a = Buffer.from(tok.slice(i + 1));
  const b = Buffer.from(mac(body, si.s));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  let p;
  try { p = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')); } catch (e) { return null; }
  if (!p || (p.p !== 'premium' && p.p !== 'pro') || !(p.e > Date.now())) return null;
  if (typeof p.u !== 'string' || !p.u || typeof p.c !== 'string' || !p.c) return null; // رموز الصيغة القديمة (بلا حساب/كود) مرفوضة
  return p;
}

// ذاكرة قصيرة للنتائج الإيجابية فقط، كي لا نقرأ Firestore عند كل رسالة. الإلغاء يسري خلال PLAN_CHECK_TTL_MS (الافتراضي 30 ثانية، 0 = فوري).
const cache = new Map();
const ttl = () => { const n = parseInt(process.env.PLAN_CHECK_TTL_MS, 10); return Number.isFinite(n) ? Math.min(300000, Math.max(0, n)) : 30000; };
const GRACE = 10 * 60 * 1000; // عند تعطّل Firestore: نثق بآخر نتيجة إيجابية حتى 10 دقائق، وإلا مجاني

// يعيد حمولة الرمز إن كان صالحًا ولحساب uid ولم يُلغَ، وإلا null (= مجاني)
async function activePlan(tok, uid) {
  const p = verifyToken(tok);
  if (!p || !uid || p.u !== uid) return null;
  const hit = cache.get(uid);
  const fresh = hit && hit.tok === tok;
  if (fresh && Date.now() - hit.at < ttl()) return p;
  let doc;
  try { doc = await fsGet('entitlements/' + uid); }
  catch (e) { return fresh && Date.now() - hit.at < GRACE ? p : null; }
  if (!doc || !doc.tok || doc.tok !== tok || +doc.rv) { cache.delete(uid); return null; }
  if (cache.size > 5000) cache.clear();
  cache.set(uid, { tok, at: Date.now() });
  return p;
}
// المرجع الوحيد لاشتراك الحساب: يقرأ entitlements/{uid} ويتحقق من التوقيع والانتهاء والإلغاء وملكية الحساب، ثم يعيد الرمز.
// يُستدعى عند كل تسجيل دخول/إعادة تحميل (عبر /api/quota) فلا يعتمد الاشتراك على التخزين المحلي ولا على قراءة العميل لـ Firestore.
// يعيد null = لا اشتراك فعّال (مؤكَّد من الخادم). يرمي خطأ transient إن تعذّرت قراءة Firestore (لا نقول للمشترك "مجاني" بسبب عطل مؤقت).
async function entitlementOf(uid) {
  if (!uid) return null;
  let doc, err;
  for (let i = 0; i < 2 && !doc && !err; i++) { // محاولة ثانية عند عطل عابر
    try { doc = (await fsGet('entitlements/' + uid)) || 0; } catch (e) { if (i) err = e; }
  }
  if (err) { const t = new Error('entitlements_unavailable'); t.transient = true; throw t; }
  if (!doc || !doc.tok || +doc.rv) return null;
  const p = verifyToken(doc.tok);
  if (!p || p.u !== uid) return null;
  return { tok: doc.tok, p };
}
const forget = (uid) => { cache.delete(uid); }; // بعد التفعيل/الإلغاء في نفس النسخة (النسخ الأخرى تنتظر انتهاء الذاكرة)

// ---- الأكواد الفردية ----
// الكود يُحفظ في Firestore مجزّأً فقط (codes/{sha256}). النص الصريح يظهر مرة واحدة عند الصنع. 20 حرفًا من 31 رمزًا ≈ 99 بت.
const ALPHA = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'; // بلا I وL وO و0 و1 لتفادي الالتباس
const codeNorm = (s) => String(s || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 64);
const codeId = (s) => crypto.createHash('sha256').update(codeNorm(s)).digest('hex');
function genCode() {
  let s = '';
  for (let i = 0; i < 20; i++) s += ALPHA[crypto.randomInt(ALPHA.length)];
  return s.match(/.{5}/g).join('-');
}

module.exports = { sign, verifyToken, activePlan, entitlementOf, forget, secretInfo, adminInfo, planSecretOk, codeNorm, codeId, genCode };
