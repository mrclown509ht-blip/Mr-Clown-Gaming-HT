// Vérifie un ID de joueur Free Fire (serveur Global) via RapidAPI « ID Game Checker ».
// Appel du site : /api/ff-verify?id=123456789
// La clé est lue dans la variable d'environnement RAPIDAPI_KEY (jamais dans le code du site).

const HOST = 'id-game-checker.p.rapidapi.com';
const TIMEOUT_MS = 8500;
const CACHE_MS = 10 * 60 * 1000;
const cache = new Map();
const hits = new Map(); // ip -> horodatages (protège le quota gratuit)

const send = (res, code, body) => {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.status(code).send(JSON.stringify(body));
};

function tooMany(ip) {
  const now = Date.now();
  const list = (hits.get(ip) || []).filter(t => now - t < 10 * 60 * 1000);
  list.push(now);
  hits.set(ip, list);
  if (hits.size > 500) hits.clear();
  return list.length > 25;
}

module.exports = async (req, res) => {
  const id = String((req.query && (req.query.id || req.query.uid)) || '').trim();
  if (!/^\d{5,15}$/.test(id)) return send(res, 400, { error: 'bad_id' });

  const KEY = process.env.RAPIDAPI_KEY || '';
  if (!KEY) return send(res, 503, { error: 'not_configured' });

  const ip = String((req.headers && (req.headers['x-forwarded-for'] || '')) || '').split(',')[0].trim() || 'x';
  if (tooMany(ip)) return send(res, 429, { error: 'rate_limited' });

  const hit = cache.get(id);
  if (hit && Date.now() - hit.time < CACHE_MS) return send(res, 200, hit.data);

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const r = await fetch(`https://${HOST}/ff-global/${encodeURIComponent(id)}`, {
      method: 'GET',
      headers: { 'x-rapidapi-host': HOST, 'x-rapidapi-key': KEY, 'Accept': 'application/json' },
      signal: ctrl.signal
    });
    const text = await r.text();
    let body = null;
    try { body = JSON.parse(text); } catch (e) { body = null; }

    if (r.status === 429) return send(res, 429, { error: 'rate_limited' });
    if (r.status === 401 || r.status === 403) return send(res, 502, { error: 'unavailable', debug: 'auth_' + r.status });

    const name = body && body.data && typeof body.data.username === 'string' ? body.data.username.trim() : '';
    if (r.ok && body && body.error === false && name) {
      const out = { id, nickname: name, region: '', level: null };
      cache.set(id, { time: Date.now(), data: out });
      return send(res, 200, out);
    }
    const msg = String((body && body.msg) || '');
    if (r.status === 404 || (body && (body.status === 404 || (body.error === true && /not.?found|invalid|no.?data|tidak/i.test(msg))))) {
      return send(res, 404, { error: 'invalid_id' });
    }
    return send(res, 502, { error: 'unavailable', debug: 'http_' + r.status });
  } catch (e) {
    return send(res, 502, { error: 'unavailable', debug: e && e.name === 'AbortError' ? 'timeout' : 'network' });
  } finally {
    clearTimeout(timer);
  }
};
