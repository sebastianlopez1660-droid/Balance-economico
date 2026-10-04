// Guarda y lee los 12 meses del presupuesto en Upstash Redis (vía su API REST).
// Variables de entorno en Vercel:
//   KV_REST_API_URL / KV_REST_API_TOKEN  (o UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN)
//   APP_PIN  — (opcional) PIN fijo. Si no existe, la página pide crear uno la primera
//              vez y se guarda cifrado (scrypt) en la base de datos.
const crypto = require('crypto');

const KEY = 'presupuesto2026';
const AUTH_KEY = 'presupuesto2026:auth';
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

function hashPin(pin, salt) {
  return crypto.scryptSync(String(pin), salt, 32).toString('hex');
}

function readBody(req) {
  let body = req.body;
  if (typeof body === 'string') body = JSON.parse(body);
  return body || {};
}

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  const cfg = config();
  if (!cfg.url || !cfg.token) {
    return res.status(503).json({ error: 'not_configured' });
  }

  try {
    let stored = null;
    if (!cfg.pin) {
      stored = await redis(cfg, ['GET', AUTH_KEY]);
      if (!stored) {
        // Aún no hay PIN: solo se permite crearlo.
        if (req.method === 'POST') {
          const pin = String(readBody(req).pin || '');
          if (!/^\d{4,12}$/.test(pin)) return res.status(400).json({ error: 'bad_pin_format' });
          const salt = crypto.randomBytes(16).toString('hex');
          const created = await redis(cfg, ['SET', AUTH_KEY, salt + ':' + hashPin(pin, salt), 'NX']);
          if (!created) return res.status(409).json({ error: 'pin_exists' });
          return res.status(200).json({ ok: true });
        }
        return res.status(428).json({ error: 'pin_not_set' });
      }
    }

    const given = String(req.headers['x-pin'] || '');
    let ok;
    if (cfg.pin) ok = samePin(given, cfg.pin);
    else {
      const [salt, hash] = String(stored).split(':');
      ok = samePin(hashPin(given, salt), hash);
    }
    if (!ok) return res.status(401).json({ error: 'bad_pin' });

    if (req.method === 'GET') {
      const flat = (await redis(cfg, ['HGETALL', KEY])) || [];
      const docs = {};
      for (let i = 0; i + 1 < flat.length; i += 2) {
        try { docs[flat[i]] = JSON.parse(flat[i + 1]); } catch (e) {}
      }
      return res.status(200).json({ docs });
    }

    if (req.method === 'PUT') {
      const body = readBody(req);
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
