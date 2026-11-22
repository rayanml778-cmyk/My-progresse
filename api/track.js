// api/track.js — تتبّع استخدام التطبيق لتحليلات لوحة المطوّر: وقت نشط/خامل + زيارات ووقت كل قسم.
// أرقام فقط (لا نصوص ولا محتوى مستخدم). يتحقق من رمز Firebase، ويقصّ القيم، ويكتب بحساب الخدمة في ua/{uid}_{YYYY-MM-DD}.
// الأيام بتوقيت UTC. العدّ غير ذري (لو أرسل تبويبان معًا قد يضيع تحديث صغير) — للإحصاء لا للفوترة.
const { verifyIdToken, saReady, fsGet, fsSet, logErr } = require('./_fb');
const SECS = ['dash', 'study', 'tasks', 'habits', 'workouts', 'quiz', 'reports', 'moon', 'settings', 'other'];
const send = (res, s, o) => { res.statusCode = s; res.setHeader('Content-Type', 'application/json'); res.setHeader('Cache-Control', 'no-store'); res.end(JSON.stringify(o)); };
const num = (x, max) => { x = +x; return Number.isFinite(x) && x > 0 ? Math.min(max, Math.round(x)) : 0; };
module.exports = async function handler(req, res) {
  try {
    if (req.method !== 'POST') return send(res, 405, { code: 'method' });
    if (!saReady()) return send(res, 503, { code: 'conf' });
    const uid = await verifyIdToken(String(req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
    if (!uid) return send(res, 401, { code: 'auth' });
    let b = req.body; if (typeof b === 'string') { try { b = JSON.parse(b); } catch (e) { b = null; } }
    if (!b || typeof b !== 'object' || JSON.stringify(b).length > 3000) return send(res, 400, { code: 'bad' });
    const sid = String(b.sid || ''); if (!/^[A-Za-z0-9]{8,24}$/.test(sid)) return send(res, 400, { code: 'bad' });
    let a = num(b.a, 900), idle = num(b.i, 900); const t = {}, v = {}; let sumT = 0;
    for (const k of SECS) { const x = num(b.t && b.t[k], 900), y = num(b.v && b.v[k], 100); if (x) { t[k] = x; sumT += x; } if (y) v[k] = y; }
    if (sumT > a + 10) return send(res, 400, { code: 'bad' }); // وقت الأقسام لا يتجاوز الوقت النشط الكلي
    if (!a && !idle && !Object.keys(v).length) return send(res, 200, { ok: true });
    const now = Date.now(), day = new Date(now).toISOString().slice(0, 10), path = 'ua/' + uid + '_' + day;
    const cur = (await fsGet(path).catch(() => null)) || {};
    if (cur.lt && now - cur.lt < 3000) return send(res, 429, { code: 'slow' });
    // لا يمكن أن يزيد الوقت النشط المُرسَل عن الزمن الفعلي المنقضي منذ آخر إرسال (منع التضخيم)
    const cap = cur.lt ? Math.min(900, Math.round((now - cur.lt) / 1000 * 1.25) + 15) : 900;
    if (a > cap) { const k = cap / a; a = cap; for (const s of Object.keys(t)) t[s] = Math.floor(t[s] * k); }
    if (idle > cap) idle = cap;
    let j = {}; try { j = JSON.parse(cur.j || '{}') || {}; } catch (e) { j = {}; }
    j.t = j.t || {}; j.v = j.v || {};
    for (const s of Object.keys(t)) j.t[s] = (+j.t[s] || 0) + t[s];
    for (const s of Object.keys(v)) j.v[s] = (+j.v[s] || 0) + v[s];
    const ss = String(cur.ss || '').split(',').filter(Boolean); let n = +cur.n || 0;
    if (!ss.includes(sid)) { n++; ss.push(sid); }
    await fsSet(path, { u: uid, d: day, a: (+cur.a || 0) + a, i: (+cur.i || 0) + idle, n, ss: ss.slice(-12).join(','), j: JSON.stringify(j), lt: now, last: a > 0 ? now : (+cur.last || 0) });
    return send(res, 200, { ok: true });
  } catch (e) { console.error('[track]', e && e.message); try { await logErr('track', e && e.message, ''); } catch (x) { /* */ } return send(res, 500, { code: 'err' }); }
};
