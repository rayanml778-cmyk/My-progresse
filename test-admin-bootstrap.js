// اختبار شامل لمسار bootstrap (محاكاة كاملة لـ Google/Firebase، بلا شبكة ولا أسرار حقيقية)
const crypto = require('crypto');
const PROJECT = 'myprogress-6b9d9', OWNER = 'rayanml778@gmail.com';
const kp = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const sak = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = Object.assign(kp.publicKey.export({ format: 'jwk' }), { kid: 'k1' });
process.env.FIREBASE_SA = JSON.stringify({ client_email: 'sa@x.iam', private_key: sak.privateKey.export({ type: 'pkcs8', format: 'pem' }) });
const GOOD = 'A'.repeat(20) + 'b'.repeat(20) + '1234';        // ADMIN_SECRET تجريبي 44 حرفًا
const PLAN = 'P'.repeat(20) + 'q'.repeat(20) + '9876';
const logs = [];
for (const k of ['log', 'error']) { const o = console[k]; console[k] = (...a) => { logs.push(a.join(' ')); }; }
const e64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
function idToken(email, claims) {
  const h = e64({ alg: 'RS256', kid: 'k1', typ: 'JWT' });
  const p = e64(Object.assign({ aud: PROJECT, iss: 'https://securetoken.google.com/' + PROJECT, sub: 'uid_owner_123', email, email_verified: true, exp: Math.floor(Date.now() / 1e3) + 3600 }, claims || {}));
  return h + '.' + p + '.' + crypto.sign('RSA-SHA256', Buffer.from(h + '.' + p), kp.privateKey).toString('base64url');
}
let idtMode = 'ok', claimsSet = null, lookupEmail = OWNER;
global.fetch = async (url, o) => {
  const J = (c, b) => ({ ok: c < 300, status: c, json: async () => b });
  url = String(url);
  if (url.includes('service_accounts/v1/jwk')) return J(200, { keys: [jwk] });
  if (url.includes('oauth2.googleapis.com/token')) return J(200, { access_token: 'at', expires_in: 3600 });
  if (url.includes('accounts:lookup')) return J(200, { users: [{ localId: 'uid_owner_123', email: lookupEmail, customAttributes: '{"x":1}' }] });
  if (url.includes('accounts:update')) {
    if (idtMode === 'iam') return J(403, { error: { message: 'PERMISSION_DENIED' } });
    claimsSet = JSON.parse(o.body); return J(200, {});
  }
  return J(404, {});
};
const mod = () => require('./api/admin.js'); // يُحمَّل مرة واحدة (الأسرار تُقرأ من process.env عند كل طلب)
let n = 0, fails = 0;
const ok = (c, m) => { n++; if (!c) { fails++; process.stdout.write('  ✗ ' + m + '\n'); } else process.stdout.write('  ✓ ' + m + '\n'); };
async function call(env, token, action, hdr, ip) {
  for (const k of ['ADMIN_SECRET', 'PLAN_SECRET', 'DEV_CODE_HASH']) delete process.env[k];
  Object.assign(process.env, env);
  const h = mod();
  const req = { method: 'POST', headers: Object.assign({ authorization: 'Bearer ' + token, 'x-forwarded-for': ip }, hdr || {}), body: { action }, socket: {} };
  let status, body = ''; const res = { setHeader() {}, set statusCode(v) { status = v; }, end(b) { body = b; } };
  await h(req, res); return { status, json: JSON.parse(body) };
}
(async () => {
  const T = idToken(OWNER);
  const base = { ADMIN_SECRET: GOOD, PLAN_SECRET: PLAN };
  let r;
  console.info = () => {};
  const P = (s) => process.stdout.write(s + '\n');
  P('1) المسار الصحيح');
  claimsSet = null; r = await call(base, T, 'bootstrap', { 'x-admin-secret': GOOD }, '1.1.1.1');
  ok(r.status === 200 && r.json.ok, 'bootstrap يرجع 200');
  const ca = claimsSet && JSON.parse(claimsSet.customAttributes);
  ok(ca && ca.admin === true && ca.x === 1, 'منح Custom Claim admin:true مع دمج claims القديمة');
  ok(claimsSet.localId === 'uid_owner_123' && claimsSet.emailVerified === true, 'الحساب الصحيح + emailVerified');
  r = await call(base, idToken(OWNER, { admin: true }), 'whoami', {}, '1.1.1.2');
  ok(r.status === 200 && r.json.owner === true, 'whoami بعد تحديث الرمز (admin:true) ينجح');
  r = await call(base, T, 'whoami', {}, '1.1.1.3');
  ok(r.status === 403 && r.json.need === 'claim', 'whoami بلا claim يرجع need:claim (فتح شاشة التفعيل)');
  P('2) أسباب الفشل صريحة');
  r = await call({ PLAN_SECRET: PLAN }, T, 'bootstrap', { 'x-admin-secret': GOOD }, '2.2.2.1'); ok(r.status === 403 && r.json.why === 'secret_missing', 'ADMIN_SECRET غير موجود → secret_missing');
  r = await call({ ADMIN_SECRET: 'short-secret', PLAN_SECRET: PLAN }, T, 'bootstrap', { 'x-admin-secret': 'short-secret' }, '2.2.2.2'); ok(r.json.why === 'secret_short', 'أقصر من 32 → secret_short');
  r = await call({ ADMIN_SECRET: PLAN + 'zzzzzzzz', PLAN_SECRET: PLAN }, T, 'bootstrap', { 'x-admin-secret': PLAN + 'zzzzzzzz' }, '2.2.2.3'); ok(r.json.why === 'secret_reused', 'يحتوي PLAN_SECRET → secret_reused');
  r = await call(base, T, 'bootstrap', { 'x-admin-secret': GOOD + 'x' }, '2.2.2.4'); ok(r.status === 403 && r.json.why === 'secret_mismatch', 'قيمة خاطئة → secret_mismatch');
  r = await call(base, T, 'bootstrap', {}, '2.2.2.5'); ok(r.json.why === 'header_missing', 'بلا ترويسة → header_missing');
  r = await call(base, T, 'bootstrap', { 'x-admin-secret': '  ' + GOOD + '\n' }, '2.2.2.6'); ok(r.status === 200, 'مسافات/سطر جديد حول السر مُهمَلة');
  P('3) الحماية لم تضعف');
  r = await call(base, idToken('other@x.com'), 'bootstrap', { 'x-admin-secret': GOOD }, '3.3.3.1'); ok(r.status === 403 && !r.json.why, 'حساب غير المالك: 403 بلا أي سبب مكشوف');
  r = await call(base, GOOD, 'bootstrap', { 'x-admin-secret': GOOD }, '3.3.3.2'); ok(r.status === 403 && r.json.why === 'need_token', 'Bearer=ADMIN_SECRET وحده لا يكفي للـ bootstrap');
  r = await call(base, 'garbage', 'bootstrap', { 'x-admin-secret': GOOD }, '3.3.3.3'); ok(r.status === 403 && !r.json.why, 'بلا مصادقة: 403 بلا سبب');
  lookupEmail = 'evil@x.com'; r = await call(base, T, 'bootstrap', { 'x-admin-secret': GOOD }, '3.3.3.4'); lookupEmail = OWNER; ok(r.json.why === 'email_mismatch', 'تحقق البريد من Firebase Auth ما زال مطبّقًا');
  let last; for (let i = 0; i < 11; i++) last = await call(base, T, 'bootstrap', { 'x-admin-secret': 'bad' + i }, '4.4.4.4'); ok(last.status === 429, 'تحديد المحاولات (10/10 دقائق) ما زال يعمل');
  P('4) فشل Firebase (صلاحيات حساب الخدمة)');
  idtMode = 'iam'; r = await call(base, T, 'bootstrap', { 'x-admin-secret': GOOD }, '5.5.5.5'); idtMode = 'ok';
  ok(r.status === 502 && r.json.why === 'claims_failed' && r.json.detail === 'idt403:PERMISSION_DENIED', 'رفض IAM يظهر كـ claims_failed + idt403:PERMISSION_DENIED');
  P('5) السجلات لا تكشف أسرارًا');
  const all = logs.join('\n');
  ok(!all.includes(GOOD) && !all.includes(PLAN), 'لا ADMIN_SECRET ولا PLAN_SECRET في السجلات');
  ok(/bootstrap denied: secret_mismatch/.test(all) && /bootstrap ok/.test(all) && /bootstrap claims failed: idt403/.test(all), 'السجلات تُظهر سبب الفشل بوضوح');
  P(`\n${n - fails}/${n} نجحت`); process.exit(fails ? 1 : 0);
})();
