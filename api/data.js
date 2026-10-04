// Guarda y lee los 12 meses del presupuesto en Upstash Redis (vía su API REST).
// Variables de entorno en Vercel:
//   KV_REST_API_URL / KV_REST_API_TOKEN  (o UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN)
//   APP_PIN  — PIN que pide la página para ver y guardar los datos
const crypto = require('crypto');

const KEY = 'presupuesto2026';
const DOC_ID = /^m(0[1-9]|1[0-2])$/;
const MAX_DOC = 100000;

function config() {
  return {
    url: process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL,
    token: process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN,
    pin: process.env.APP_PIN,
  };
}

async function redis(cfg, command) {
  const r = await fetch(cfg.url, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + cfg.token, 'Content-Type': 'application/json' },
    body: JSON.stringify(command),
  });
  const out = await r.json().catch(() => ({}));
  if (!r.ok || out.error) throw new Error(out.error || 'Redis ' + r.status);
  return out.result;
}

function samePin(a, b) {
  const x = crypto.createHash('sha256').update(String(a)).digest();
  const y = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
}

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  const cfg = config();
  if (!cfg.url || !cfg.token || !cfg.pin) {
    return res.status(503).json({ error: 'not_configured' });
  }
  if (!samePin(req.headers['x-pin'] || '', cfg.pin)) {
    return res.status(401).json({ error: 'bad_pin' });
  }

  try {
    if (req.method === 'GET') {
      const flat = (await redis(cfg, ['HGETALL', KEY])) || [];
      const docs = {};
      for (let i = 0; i + 1 < flat.length; i += 2) {
        try { docs[flat[i]] = JSON.parse(flat[i + 1]); } catch (e) {}
      }
      return res.status(200).json({ docs });
    }

    if (req.method === 'PUT') {
      let body = req.body;
      if (typeof body === 'string') body = JSON.parse(body);
      const id = body && body.id, data = body && body.data;
      if (!DOC_ID.test(String(id)) || !data || typeof data !== 'object') {
        return res.status(400).json({ error: 'bad_request' });
      }
      const json = JSON.stringify(data);
      if (json.length > MAX_DOC) return res.status(413).json({ error: 'too_large' });
      await redis(cfg, ['HSET', KEY, id, json]);
      return res.status(200).json({ ok: true });
    }

    res.setHeader('Allow', 'GET, PUT');
    return res.status(405).json({ error: 'method_not_allowed' });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server_error' });
  }
};
