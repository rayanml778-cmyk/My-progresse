// api/chat.js — وسيط آمن (Vercel Serverless Function) بين Moon AI و Groq
// المفتاح يُقرأ فقط من متغير البيئة GROQ_API_KEY ولا يصل للمتصفح أبدًا.
//
// متغيرات البيئة (Vercel › Settings › Environment Variables):
//   GROQ_API_KEY     (إلزامي)  مفتاح Groq
//   GROQ_MODEL       (اختياري) الافتراضي: openai/gpt-oss-120b
//   ALLOWED_ORIGINS  (اختياري) نطاقات مسموح لها بالاتصال من موقع آخر، مفصولة بفاصلة
//                    مثال: https://myprogress-6b9d9.web.app,https://myprogress-6b9d9.firebaseapp.com

const GROQ_URL = 'https://api.groq.com/openai/v1/chat/completions';
const DEFAULT_MODEL = 'openai/gpt-oss-120b';

const MAX_MESSAGES = 40;
const MAX_CONTENT = 20000;   // أقصى طول لكل رسالة
const MAX_SYSTEM = 40000;    // أقصى طول لتعليمات النظام
const MAX_TOKENS = 4096;
const RATE_LIMIT = 20;       // طلبات لكل IP في الدقيقة (بحد أقصى على نفس النسخة الدافئة)
const RATE_WINDOW = 60 * 1000;

const hits = new Map();
function limited(ip) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter((t) => now - t < RATE_WINDOW);
  arr.push(now);
  hits.set(ip, arr);
  if (hits.size > 5000) hits.clear();
  return arr.length > RATE_LIMIT;
}

function allowedOrigins() {
  return (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map((s) => s.trim().replace(/\/$/, ''))
    .filter(Boolean);
}

function send(res, code, obj) {
  if (res.headersSent) return;
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(obj));
}

module.exports = async function handler(req, res) {
  // ---- CORS / فحص المصدر ----
  const origin = (req.headers.origin || '').replace(/\/$/, '');
  const allow = allowedOrigins();
  if (origin && allow.length) {
    if (!allow.includes(origin)) return send(res, 403, { error: 'Origin not allowed' });
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Max-Age', '86400');
  }
  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    return res.end();
  }
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST, OPTIONS');
    return send(res, 405, { error: 'Method not allowed' });
  }

  const key = process.env.GROQ_API_KEY;
  if (!key) return send(res, 500, { error: 'الخادم غير مهيّأ: GROQ_API_KEY غير موجود' });

  const ip = String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'x').split(',')[0].trim();
  if (limited(ip)) return send(res, 429, { error: 'طلبات كثيرة، حاول بعد قليل' });

  // ---- قراءة الطلب والتحقق منه ----
  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch (e) { body = null; }
  }
  if (!body || typeof body !== 'object') return send(res, 400, { error: 'طلب غير صالح' });

  const msgs = Array.isArray(body.messages) ? body.messages.slice(-MAX_MESSAGES) : [];
  const messages = [];
  if (typeof body.system === 'string' && body.system.trim()) {
    messages.push({ role: 'system', content: body.system.slice(0, MAX_SYSTEM) });
  }
  for (const m of msgs) {
    if (!m || (m.role !== 'user' && m.role !== 'assistant')) continue;
    const content = typeof m.content === 'string' ? m.content.slice(0, MAX_CONTENT) : '';
    if (content) messages.push({ role: m.role, content });
  }
  if (!messages.some((m) => m.role === 'user')) return send(res, 400, { error: 'لا توجد رسالة' });

  const model = process.env.GROQ_MODEL || DEFAULT_MODEL;
  const stream = body.stream === true;
  const payload = {
    model,
    messages,
    stream,
    temperature: 0.6,
    max_completion_tokens: Math.min(Math.max(parseInt(body.max_tokens, 10) || 2048, 1), MAX_TOKENS),
  };
  if (/^openai\/gpt-oss/.test(model)) payload.reasoning_effort = process.env.GROQ_REASONING || 'low';

  // ---- إرسال إلى Groq ----
  const ac = new AbortController();
  res.on('close', () => { if (!res.writableEnded) ac.abort(); });

  let up;
  try {
    up = await fetch(GROQ_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + key },
      body: JSON.stringify(payload),
      signal: ac.signal,
    });
  } catch (e) {
    return send(res, 502, { error: 'تعذّر الاتصال بخدمة الذكاء الاصطناعي' });
  }

  if (!up.ok) {
    let msg = 'خطأ من الخدمة (' + up.status + ')';
    try {
      const j = await up.json();
      if (j && j.error && j.error.message) msg = j.error.message;
    } catch (e) {}
    return send(res, up.status === 429 ? 429 : 502, { error: msg });
  }

  if (!stream) {
    const j = await up.json();
    return send(res, 200, j);
  }

  // ---- بث مباشر (SSE) كما يصل من Groq ----
  res.statusCode = 200;
  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('X-Accel-Buffering', 'no');
  try {
    for await (const chunk of up.body) res.write(chunk);
  } catch (e) {
    // انقطاع من العميل أو من الخدمة
  }
  res.end();
};
