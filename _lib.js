// Bibliothèque commune du serveur Mr CLOWN Top Up (Vercel, Node 18+, aucune dépendance).
// Ici vivent : l'accès sécurisé à la base Firebase, les sessions signées, le hachage des mots de passe
// et le catalogue de référence (les prix sont toujours calculés ICI, jamais crus du navigateur).

const crypto = require('crypto');
const DEFAULTS = require('./_defaults.json');

const DB_URL = (process.env.FIREBASE_DB_URL || 'https://mr-clown-top-up-gaming-default-rtdb.firebaseio.com').replace(/\/+$/, '');
const DB_SECRET = process.env.FIREBASE_DB_SECRET || '';
const SERVICE_ACCOUNT = process.env.FIREBASE_SERVICE_ACCOUNT || '';
const SESSION_SECRET = process.env.SESSION_SECRET || '';

class HttpError extends Error {
    constructor(status, code, message) { super(message || code); this.status = status; this.code = code; }
}
const fail = (status, code, message) => { throw new HttpError(status, code, message); };

// ------------------------------------------------------------------ base de données (Firebase REST)
let oauthCache = { token: '', exp: 0 };

async function oauthToken() {
    if (oauthCache.token && Date.now() < oauthCache.exp - 60000) return oauthCache.token;
    const sa = JSON.parse(SERVICE_ACCOUNT);
    const b64 = o => Buffer.from(JSON.stringify(o)).toString('base64url');
    const now = Math.floor(Date.now() / 1000);
    const head = b64({ alg: 'RS256', typ: 'JWT' });
    const claim = b64({
        iss: sa.client_email, sub: sa.client_email, aud: 'https://oauth2.googleapis.com/token',
        scope: 'https://www.googleapis.com/auth/firebase.database https://www.googleapis.com/auth/userinfo.email',
        iat: now, exp: now + 3600
    });
    const sig = crypto.createSign('RSA-SHA256').update(head + '.' + claim).sign(sa.private_key).toString('base64url');
    const r = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'grant_type=' + encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer') + '&assertion=' + head + '.' + claim + '.' + sig
    });
    const j = await r.json();
    if (!j.access_token) throw new Error('oauth_failed');
    oauthCache = { token: j.access_token, exp: Date.now() + (j.expires_in || 3600) * 1000 };
    return oauthCache.token;
}

async function dbFetch(path, opts = {}) {
    if (!DB_SECRET && !SERVICE_ACCOUNT) fail(500, 'not_configured', 'Serveur non configuré (FIREBASE_DB_SECRET manquant).');
    const headers = Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {});
    // chaque segment est encodé : une clé comme « alice@x%2ecom » doit rester littérale côté Firebase
    let url = `${DB_URL}/${path.split('/').map(encodeURIComponent).join('/')}.json`;
    if (SERVICE_ACCOUNT) headers.Authorization = 'Bearer ' + await oauthToken();
    else url += '?auth=' + encodeURIComponent(DB_SECRET);
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 8000);
    try {
        return await fetch(url, { method: opts.method || 'GET', headers, body: opts.body, signal: ctrl.signal });
    } finally { clearTimeout(timer); }
}

const db = {
    async get(path) {
        const r = await dbFetch(path);
        if (!r.ok) fail(502, 'db_error', 'Base de données indisponible (' + r.status + ').');
        return r.json();
    },
    async getE(path) {
        const r = await dbFetch(path, { headers: { 'X-Firebase-ETag': 'true' } });
        if (!r.ok) fail(502, 'db_error', 'Base de données indisponible (' + r.status + ').');
        return { val: await r.json(), etag: r.headers.get('etag') || 'null_etag' };
    },
    async put(path, val) {
        const r = await dbFetch(path, { method: 'PUT', body: JSON.stringify(val) });
        if (!r.ok) fail(502, 'db_error', 'Écriture impossible (' + r.status + ').');
    },
    // Écriture conditionnelle : false si quelqu'un a modifié la donnée entre-temps
    async putIf(path, val, etag) {
        const r = await dbFetch(path, { method: 'PUT', body: JSON.stringify(val), headers: { 'if-match': etag } });
        if (r.status === 412) return false;
        if (!r.ok) fail(502, 'db_error', 'Écriture impossible (' + r.status + ').');
        return true;
    },
    async patch(path, val) {
        const r = await dbFetch(path, { method: 'PATCH', body: JSON.stringify(val) });
        if (!r.ok) fail(502, 'db_error', 'Écriture impossible (' + r.status + ').');
    },
    async del(path) {
        const r = await dbFetch(path, { method: 'DELETE' });
        if (!r.ok) fail(502, 'db_error', 'Suppression impossible (' + r.status + ').');
    },
    // Crée seulement si la clé n'existe pas encore (réservation atomique)
    async create(path, val) {
        return db.putIf(path, val, 'null_etag');
    },
    // Lecture-modification-écriture atomique (réessaie en cas de conflit)
    async txn(path, fn) {
        for (let i = 0; i < 8; i++) {
            const { val, etag } = await db.getE(path);
            const next = fn(val);
            if (next === undefined) return val;
            if (await db.putIf(path, next, etag)) return next;
            await new Promise(r => setTimeout(r, 25 + Math.random() * 50));
        }
        fail(409, 'busy', 'Serveur occupé, réessayez.');
    }
};

// ------------------------------------------------------------------ outils
const safeKey = k => String(k).replace(/[.$#\[\]\/%]/g, c => '%' + c.charCodeAt(0).toString(16));
const ukeyOf = email => safeKey(String(email).trim().toLowerCase());
const digits = s => String(s || '').replace(/\D/g, '');
const str = (v, max = 200) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max);
const norm = t => String(t || '').trim().toLowerCase().replace(/\s+/g, ' ');
const values = o => (o && typeof o === 'object') ? Object.values(o) : [];
const arr = a => Array.isArray(a) ? a : values(a);

function nowStr() {
    const d = new Date();
    const date = d.toLocaleDateString('fr-FR', { timeZone: 'America/Port-au-Prince' });
    const time = d.toLocaleTimeString('fr-FR', { timeZone: 'America/Port-au-Prince', hour: '2-digit', minute: '2-digit' });
    return date + ' ' + time;
}

// Même algorithme que le navigateur (code client "MC-XXXXXX")
function clientCodeFor(email, salt) {
    const s = String(email || '').toLowerCase() + (salt || '');
    let h1 = 0x811c9dc5, h2 = 0x1b873593;
    for (let i = 0; i < s.length; i++) {
        const c = s.charCodeAt(i);
        h1 = Math.imul(h1 ^ c, 16777619) >>> 0;
        h2 = Math.imul(h2 ^ c, 2246822519) >>> 0;
    }
    const n = ((h1 ^ (h2 >>> 7)) >>> 0) % 2176782336;
    return 'MC-' + n.toString(36).toUpperCase().padStart(6, '0');
}

// ------------------------------------------------------------------ mots de passe (scrypt) et sessions (HMAC)
const scrypt = (pw, salt) => new Promise((res, rej) => crypto.scrypt(pw, salt, 64, (e, k) => e ? rej(e) : res(k)));

async function hashPassword(pw) {
    const salt = crypto.randomBytes(16);
    return salt.toString('hex') + ':' + (await scrypt(String(pw), salt)).toString('hex');
}
async function verifyPassword(pw, stored) {
    try {
        const [s, h] = String(stored || '').split(':');
        if (!s || !h) return false;
        const k = await scrypt(String(pw), Buffer.from(s, 'hex'));
        const a = Buffer.from(h, 'hex');
        return a.length === k.length && crypto.timingSafeEqual(a, k);
    } catch (e) { return false; }
}

function signToken(payload, ttlSec) {
    if (!SESSION_SECRET || SESSION_SECRET.length < 16) fail(500, 'not_configured', 'Serveur non configuré (SESSION_SECRET manquant).');
    const body = Buffer.from(JSON.stringify({ ...payload, exp: Date.now() + ttlSec * 1000 })).toString('base64url');
    const sig = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
    return body + '.' + sig;
}
function readToken(token) {
    try {
        if (!SESSION_SECRET || !token) return null;
        const [body, sig] = String(token).split('.');
        const good = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
        const a = Buffer.from(sig || ''), b = Buffer.from(good);
        if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
        const p = JSON.parse(Buffer.from(body, 'base64url').toString());
        return p.exp > Date.now() ? p : null;
    } catch (e) { return null; }
}

// ------------------------------------------------------------------ comptes gérants (variable MANAGERS)
function managers() {
    try { return JSON.parse(process.env.MANAGERS || '{}'); } catch (e) { return {}; }
}

// ------------------------------------------------------------------ limitation de débit (par instance)
const hits = new Map();
function rateLimit(key, max, windowMs) {
    const now = Date.now();
    const list = (hits.get(key) || []).filter(t => now - t < windowMs);
    if (list.length >= max) { hits.set(key, list); fail(429, 'rate_limited', 'Trop de tentatives. Réessayez dans quelques minutes.'); }
    list.push(now); hits.set(key, list);
    if (hits.size > 5000) for (const [k, v] of hits) if (!v.length || now - v[v.length - 1] > windowMs) hits.delete(k);
}
const ipOf = req => String((req.headers['x-forwarded-for'] || '').split(',')[0] || (req.socket && req.socket.remoteAddress) || 'ip').trim();

// ------------------------------------------------------------------ catalogue de référence (prix côté serveur)
let catCache = { t: 0, data: null };
async function loadCatalog(force) {
    if (!force && catCache.data && Date.now() - catCache.t < 5000) return catCache.data;
    const read = async p => { const v = await db.get('mrclown/' + p); const a = values(v); return a.length ? a : null; };
    const [products, catalog, games, ranks] = await Promise.all(['products', 'catalog', 'games', 'ranks'].map(read));
    const data = {
        products: products || DEFAULTS.products,
        catalog: catalog || DEFAULTS.catalog,
        games: (games || DEFAULTS.games).sort((a, b) => (a.order || 0) - (b.order || 0)),
        ranks: (ranks || DEFAULTS.ranks).sort((a, b) => a.min - b.min)
    };
    catCache = { t: Date.now(), data };
    return data;
}
const productGame = p => p.game || 'freefire';
const productName = p => p.fullName ? p.fullName : (p.category === 'diamonds' ? p.total + 'D' : p.title);

// ------------------------------------------------------------------ règles métier partagées
const normalizePromoCode = c => String(c || '').trim().toUpperCase().replace(/\s+/g, '');
function promoProblem(p, userKey) {
    if (!p) return 'Code promo invalide.';
    if (!p.active) return 'Ce code promo est désactivé.';
    if (p.expires && Date.now() > new Date(p.expires + 'T23:59:59').getTime()) return 'Ce code promo a expiré.';
    if (p.maxUses > 0 && (p.uses || 0) >= p.maxUses) return "Ce code promo a atteint sa limite d'utilisation.";
    if (arr(p.usedBy).includes(userKey)) return 'Vous avez déjà utilisé ce code promo.';
    return null;
}
function promoDiscountFor(p, subtotal) {
    const d = p.type === 'percent' ? Math.floor(subtotal * p.value / 100) : p.value;
    return Math.max(0, Math.min(d, subtotal));
}
const isDelivered = o => /^LIVR[ÉE]/i.test(o.status || '');
function rankFor(ranks, total) {
    let idx = 0;
    ranks.forEach((r, i) => { if (total >= r.min) idx = i; });
    return { rank: ranks[idx], idx };
}

module.exports = {
    HttpError, fail, db, safeKey, ukeyOf, digits, str, norm, values, arr, nowStr, clientCodeFor,
    hashPassword, verifyPassword, signToken, readToken, managers, rateLimit, ipOf,
    loadCatalog, productGame, productName, normalizePromoCode, promoProblem, promoDiscountFor,
    isDelivered, rankFor, DEFAULTS
};
