// api/backup.js — نسخ ليلي حقيقي من الخادم: ينسخ users/{uid} إلى backups/{uid}/snaps/{YYYY-MM-DD} (UTC)
// يُستدعى من Vercel Cron (vercel.json: 0 0 * * *) ويرسل الترويسة Authorization: Bearer <CRON_SECRET> تلقائيًا.
// المتغيرات: CRON_SECRET (إلزامي، 16 حرفًا فأكثر) + FIREBASE_SA أو FIREBASE_SA_1..N (كما في _fb.js)
// لا يستبدل نسخة قائمة بنفس التاريخ (نسخة التطبيق أحدث غالبًا)، ولا ينسخ الحسابات الفارغة،
// ويحتفظ بآخر 14 نسخة يومية و5 نسخ "-pre" لكل مستخدم.
const crypto = require('crypto');
const { saReady, fsGet, fsList, fsCreate, fsDel } = require('./_fb');

const KEEP_DAILY = 14, KEEP_PRE = 5, MAX_BYTES = 9e5, BUDGET_MS = 50000, CONC = 5;
const send = (res, code, obj) => {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(obj));
};
const authorized = (req) => {
  const s = String(process.env.CRON_SECRET || '');
  if (s.length < 16) return false;
  const got = Buffer.from(String(req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
  const want = Buffer.from(s);
  return got.length === want.length && crypto.timingSafeEqual(got, want);
};
// نفس منطق hasData في الواجهة: لا نحفظ نسخًا فارغة
function hasData(o) {
  if (!o || typeof o !== 'object') return false;
  const n = (x) => (x && typeof x === 'object' ? Object.keys(x).length : 0), m = o.moon || {};
  return !!(String(o.name || '').trim() || o.avatar || (o.notes || []).length || (o.wo || []).length ||
    n(o.hlog) || n(o.wlog) || n(o.wsk) || n(o.wcfg) || n(o.cplan) || n(o.focus) || n(o.rev) || n(o.arc) ||
    Object.values(o.tasks || {}).some((a) => a && a.length) ||
    (o.habits || []).some((h) => h && (h.df === 0 || !/^p_(pray|quran|read|study)$/.test(h.id))) ||
    (m.ss || []).length || m.cur || (m.mem || []).length || (o.cal && (o.cal.w || o.cal.h)));
}

module.exports = async function handler(req, res) {
  try {
    if (req.method !== 'GET' && req.method !== 'POST') { res.setHeader('Allow', 'GET, POST'); return send(res, 405, { code: 'method' }); }
    if (!authorized(req)) return send(res, 401, { code: 'auth' });
    if (!saReady()) return send(res, 503, { code: 'conf' });

    const t0 = Date.now(), now = Date.now(), day = new Date(now).toISOString().slice(0, 10);
    const users = await fsList('users', ['updated']);
    const st = { users: users.length, backed: 0, existed: 0, skipped: 0, pruned: 0, failed: 0, partial: false };
    let i = 0;
    const worker = async () => {
      while (i < users.length) {
        if (Date.now() - t0 > BUDGET_MS) { st.partial = true; return; }
        const uid = users[i++].id;
        try {
          const u = await fsGet('users/' + uid);
          if (!u || typeof u.data !== 'string' || Buffer.byteLength(u.data) > MAX_BYTES) { st.skipped++; continue; }
          let o = null; try { o = JSON.parse(u.data); } catch (e) {}
          if (!hasData(o)) { st.skipped++; continue; }
          const made = await fsCreate('backups/' + uid + '/snaps/' + day, { data: u.data, updated: u.updated || 0, size: Buffer.byteLength(u.data), at: now, src: 'cron' });
          if (!made) { st.existed++; continue; }
          st.backed++;
          const ids = (await fsList('backups/' + uid + '/snaps', ['size'])).map((x) => x.id).sort().reverse();
          const del = ids.filter((x) => /^\d{4}-\d\d-\d\d$/.test(x)).slice(KEEP_DAILY).concat(ids.filter((x) => /-pre$/.test(x)).slice(KEEP_PRE));
          for (const id of del) { await fsDel('backups/' + uid + '/snaps/' + id); st.pruned++; }
        } catch (e) { st.failed++; console.error('[backup]', uid.slice(0, 6), e && e.message); }
      }
    };
    await Promise.all(Array.from({ length: CONC }, worker));
    console.log('[backup]', JSON.stringify(st));
    return send(res, 200, { ok: true, day, ...st });
  } catch (e) {
    console.error('[backup]', e && e.message);
    return send(res, 500, { code: 'err' });
  }
};
