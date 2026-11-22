// api/_gh.js — مدير ملفات المشروع عبر Git (GitHub REST API). لا يكتب على نظام ملفات Vercel (وقت التشغيل للقراءة فقط).
// كل تعديل = Commit على فرع مخصّص (GH_BRANCH، الافتراضي dev-panel) فيُنشئ Vercel نسخة Preview تلقائيًا؛ والوصول للإنتاج بدمج الفرع يدويًا.
// سياسة المسارات والمحتوى هنا (تُطبَّق على الخادم دائمًا؛ الواجهة لا تُعتمد للحماية).
const MAX_TEXT = 512 * 1024, MAX_BIN = 1000000, MAX_TOTAL = 2500000, MAX_FILES = 20;
const TEXT_EXT = new Set(['js', 'mjs', 'cjs', 'json', 'html', 'htm', 'css', 'md', 'txt', 'svg', 'webmanifest', 'xml', 'csv', 'rules']);
const BIN_EXT = new Set(['png', 'jpg', 'jpeg', 'gif', 'webp', 'ico', 'woff2']);
const cfg = () => {
  const token = String(process.env.GH_TOKEN || '').trim(), repo = String(process.env.GH_REPO || '').trim(),
    branch = String(process.env.GH_BRANCH || 'dev-panel').trim(), prod = String(process.env.GH_PROD_BRANCH || 'main').trim();
  const okBr = (b) => /^[A-Za-z0-9._\/-]{1,60}$/.test(b) && !b.includes('..') && !b.startsWith('/') && !b.endsWith('/');
  const okRepo = /^[A-Za-z0-9_.-]{1,60}\/[A-Za-z0-9_.-]{1,100}$/.test(repo);
  const missing = []; if (!token) missing.push('GH_TOKEN'); if (!okRepo) missing.push('GH_REPO');
  return { token, repo, branch, prod, enabled: !missing.length && okBr(branch) && okBr(prod), missing };
};
const ext = (p) => { const b = String(p).split('/').pop(), i = b.lastIndexOf('.'); return i > 0 ? b.slice(i + 1).toLowerCase() : ''; };

/* ---------- سياسة المسارات ---------- */
function normPath(p) {
  if (typeof p !== 'string' || !p || p.length > 200) return null;
  if (/[\\\0\x00-\x1f]/.test(p) || p.startsWith('/') || p.endsWith('/') || p.includes('//')) return null;
  if (!/^[A-Za-z0-9._@()+ \-\u0600-\u06FF\/]+$/.test(p)) return null;
  const segs = p.split('/'); if (segs.length > 12) return null;
  if (segs.some((s) => s === '.' || s === '..' || !s.trim() || s !== s.trim())) return null;
  return p;
}
// blocked: لا قراءة ولا كتابة | readonly: قراءة فقط (قد يغيّر البناء/ينفّذ أوامر) | sensitive: كتابة بتأكيد مكتوب إضافي | normal
function classify(p) {
  const n = normPath(p); if (!n) return { lv: 'blocked', why: 'path' };
  const segs = n.split('/'), low = n.toLowerCase(), base = segs[segs.length - 1].toLowerCase();
  if (segs.some((s) => /^\.env/i.test(s) || s === '.git' || s === 'node_modules' || s === '.vercel' || /^\.(npmrc|netrc|htpasswd)$/i.test(s))) return { lv: 'blocked', why: 'env' };
  if (/\.(pem|key|p12|pfx|jks|keystore|crt|cer|der)$/.test(base) || /^id_(rsa|dsa|ecdsa|ed25519)/.test(base)) return { lv: 'blocked', why: 'key' };
  if (/secret|credential|serviceaccount|service[-_]account|adminsdk|private[-_]?key|api[-_]?key/.test(low)) return { lv: 'blocked', why: 'secret' };
  if (/^(package(-lock)?\.json|yarn\.lock|pnpm-lock\.yaml|vercel\.json|\.vercelignore|\.gitignore|\.gitattributes|\.gitmodules|dockerfile)$/.test(base) || segs[0] === '.github' || /\.(sh|bash|bat|cmd|ps1)$/.test(base)) return { lv: 'readonly', why: 'build' };
  if (segs[0] === 'api' || ['firebase.json', 'firestore.rules', 'firestore.indexes.json', 'index.html', 'sw.js', 'manifest.webmanifest', 'dev-panel.html'].includes(low) || /\.rules$/.test(base)) return { lv: 'sensitive', why: 'core' };
  return { lv: 'normal', why: '' };
}
/* ---------- سياسة المحتوى ---------- */
const SECRET_RES = [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, /\bgsk_[A-Za-z0-9]{20,}/, /\bsk-[A-Za-z0-9_-]{20,}/, /\bgh[pousr]_[A-Za-z0-9]{30,}/, /\bgithub_pat_[A-Za-z0-9_]{30,}/, /\bAKIA[0-9A-Z]{16}\b/, /\bxox[baprs]-[A-Za-z0-9-]{10,}/, /"private_key"\s*:\s*"/];
const hasSecret = (t) => SECRET_RES.some((r) => r.test(t));
const SVG_BAD = /<script|\bon[a-z]+\s*=|javascript:|<foreignObject|<iframe|<object|<embed/i;
const MAGIC = { png: (b) => b.length > 8 && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47, jpg: (b) => b.length > 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff, gif: (b) => b.length > 6 && b.slice(0, 4).toString() === 'GIF8',
  webp: (b) => b.length > 12 && b.slice(0, 4).toString() === 'RIFF' && b.slice(8, 12).toString() === 'WEBP', ico: (b) => b.length > 4 && b[0] === 0 && b[1] === 0 && b[2] === 1 && b[3] === 0, woff2: (b) => b.length > 4 && b.slice(0, 4).toString() === 'wOF2' };
MAGIC.jpeg = MAGIC.jpg;
// يعيد null إن سلم، أو رمز الخطأ
function checkContent(path, buf) {
  const e = ext(path);
  if (TEXT_EXT.has(e)) {
    if (buf.length > MAX_TEXT) return 'too_big'; if (buf.includes(0)) return 'bad_type';
    const t = buf.toString('utf8'); if (t.includes('\ufffd')) return 'bad_type';
    if (hasSecret(t)) return 'secret'; if (e === 'svg' && SVG_BAD.test(t)) return 'svg_script';
    if (e === 'json' || e === 'webmanifest') { try { JSON.parse(t); } catch (x) { return 'bad_json'; } }
    return null;
  }
  if (BIN_EXT.has(e)) { if (buf.length > MAX_BIN) return 'too_big'; return MAGIC[e](buf) ? null : 'bad_type'; }
  return 'bad_type';
}
const allowedExt = (p) => TEXT_EXT.has(ext(p)) || BIN_EXT.has(ext(p));
const isText = (p) => TEXT_EXT.has(ext(p));

/* ---------- GitHub REST ---------- */
async function gh(method, path, body) {
  const c = cfg(), ac = new AbortController(), tm = setTimeout(() => ac.abort(), 15000);
  try {
    const r = await fetch('https://api.github.com/repos/' + c.repo + path, { method, signal: ac.signal, body: body ? JSON.stringify(body) : undefined,
      headers: { Authorization: 'Bearer ' + c.token, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'content-type': 'application/json', 'User-Agent': 'myprogress-dev-panel' } });
    const t = await r.text(); let j = null; try { j = t ? JSON.parse(t) : null; } catch (e) { j = null; }
    if (!r.ok) { const e = new Error(r.status === 401 || r.status === 403 ? 'gh_auth' : r.status === 404 ? 'gh_404' : (r.status === 409 || r.status === 422) ? 'gh_conflict' : 'gh_err'); e.status = r.status; throw e; }
    return j;
  } catch (e) { if (e && e.name === 'AbortError') throw new Error('gh_timeout'); throw e; } finally { clearTimeout(tm); }
}
const refSha = async (b) => { try { return (await gh('GET', '/git/ref/heads/' + b)).object.sha; } catch (e) { if (e.message === 'gh_404') return null; throw e; } };
async function ensureBranch() { // ينشئ فرع العمل من فرع الإنتاج عند أول استخدام (لا ينشئ الإنتاج نفسه)
  const c = cfg(); const s = await refSha(c.branch); if (s) return s;
  if (c.branch === c.prod) throw new Error('gh_404');
  const base = await refSha(c.prod); if (!base) throw new Error('gh_404');
  await gh('POST', '/git/refs', { ref: 'refs/heads/' + c.branch, sha: base }); return base;
}
async function snapshot() {
  const head = await ensureBranch(), cm = await gh('GET', '/git/commits/' + head), t = await gh('GET', '/git/trees/' + cm.tree.sha + '?recursive=1');
  return { head, tree: (t.tree || []).filter((x) => x.type === 'blob'), truncated: !!t.truncated };
}
async function readAt(path, ref) {
  const j = await gh('GET', '/contents/' + path.split('/').map(encodeURIComponent).join('/') + '?ref=' + encodeURIComponent(ref));
  if (!j || Array.isArray(j) || j.type !== 'file') throw new Error('gh_404');
  if (j.size > MAX_TEXT && isText(path)) return { sha: j.sha, size: j.size, buf: null };
  if (j.encoding !== 'base64' || typeof j.content !== 'string') return { sha: j.sha, size: j.size, buf: null };
  return { sha: j.sha, size: j.size, buf: Buffer.from(j.content.replace(/\n/g, ''), 'base64') };
}
async function history(path) {
  const c = cfg(), j = await gh('GET', '/commits?sha=' + encodeURIComponent(c.branch) + '&path=' + path.split('/').map(encodeURIComponent).join('/') + '&per_page=30');
  return (j || []).map((x) => { const m = String((x.commit && x.commit.message) || ''), a = /Dev-Panel-Actor:\s*(.+)/.exec(m);
    return { sha: x.sha, date: Date.parse((x.commit && x.commit.committer && x.commit.committer.date) || (x.commit && x.commit.author && x.commit.author.date) || '') || 0, msg: m.split('\n')[0].slice(0, 160), actor: a ? a[1].trim().slice(0, 80) : String((x.commit && x.commit.author && x.commit.author.name) || '').slice(0, 60), panel: !!a }; });
}
// changes: [{path, del:true} | {path, buf} | {path, sha}]  — Commit واحد ذري
async function commit(changes, message) {
  const c = cfg(), head = await ensureBranch(), cm = await gh('GET', '/git/commits/' + head), entries = [];
  for (const ch of changes) {
    if (ch.del) entries.push({ path: ch.path, mode: '100644', type: 'blob', sha: null });
    else if (ch.sha) entries.push({ path: ch.path, mode: '100644', type: 'blob', sha: ch.sha });
    else { const b = await gh('POST', '/git/blobs', { content: ch.buf.toString('base64'), encoding: 'base64' }); entries.push({ path: ch.path, mode: '100644', type: 'blob', sha: b.sha }); }
  }
  const t = await gh('POST', '/git/trees', { base_tree: cm.tree.sha, tree: entries }), n = await gh('POST', '/git/commits', { message, tree: t.sha, parents: [head] });
  await gh('PATCH', '/git/refs/heads/' + c.branch, { sha: n.sha, force: false });
  return n.sha;
}
module.exports = { cfg, normPath, classify, checkContent, hasSecret, allowedExt, isText, ext, snapshot, readAt, history, commit, MAX_TEXT, MAX_BIN, MAX_TOTAL, MAX_FILES };
