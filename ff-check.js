// Vercel Serverless Function : vérifie un UID Free Fire avec l'API publique NF Token.
// Appel du site : /api/ff-check?id=123456789

const BASE_URL = (process.env.FF_API_BASE || 'https://api2.nftoken.info').replace(/\/+$/, '');
const TIMEOUT_MS = 8500;
const CACHE_MS = 5 * 60 * 1000;
const cache = new Map();

const send = (res, statusCode, body) => {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.status(statusCode).send(JSON.stringify(body));
};

async function getJson(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json', 'User-Agent': 'MrClownTopUp/1.0' },
      signal: controller.signal
    });
    const text = await response.text();
    let data;
    try { data = JSON.parse(text); } catch { data = null; }
    return { ok: response.ok, status: response.status, data };
  } finally {
    clearTimeout(timer);
  }
}

function normalizePlayer(data, id) {
  if (!data || typeof data !== 'object') return null;
  const account = data.AccountInfo || data.accountInfo || data.account_info || {};
  const nickname = data.nickname || data.name || data.AccountName || account.AccountName || account.accountName;
  if (typeof nickname !== 'string' || !nickname.trim()) return null;
  return {
    id,
    nickname: nickname.trim(),
    region: String(data.region || data.AccountRegion || account.AccountRegion || '').trim().toUpperCase(),
    level: data.level ?? account.AccountLevel ?? null
  };
}

module.exports = async (req, res) => {
  const params = req.query || {};
  const id = String(params.id || params.uid || '').trim();
  if (!/^\d{5,15}$/.test(id)) return send(res, 400, { error: 'bad_id' });

  const hit = cache.get(id);
  if (hit && Date.now() - hit.time < CACHE_MS) return send(res, 200, hit.data);

  const endpoints = ['player-info?uid=', 'checkbanned?id='];
  const attempts = endpoints.map(async (ep) => {
    const name = ep.split('?')[0];
    try {
      const result = await getJson(`${BASE_URL}/${ep}${encodeURIComponent(id)}`);
      const player = result.ok && normalizePlayer(result.data, id);
      if (player) return { player };
      return { fail: { endpoint: name, status: result.status } };
    } catch (error) {
      return { fail: { endpoint: name, message: error.name === 'AbortError' ? 'timeout' : 'network_error' } };
    }
  });

  const results = await Promise.all(attempts);
  const found = results.find(r => r.player);
  if (found) {
    cache.set(id, { time: Date.now(), data: found.player });
    return send(res, 200, found.player);
  }

  const fails = results.map(r => r.fail);
  if (fails.some(f => f && f.status === 404)) return send(res, 404, { error: 'invalid_id' });

  return send(res, 502, { error: 'unavailable', message: 'Le service public de vérification ne répond pas.', debug: fails });
};
