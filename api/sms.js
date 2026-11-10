// Réception des SMS Natcash transférés par l'application du téléphone (Android).
// Protégé par un code secret (SMS_WEBHOOK_KEY) : sans lui, la requête est refusée.
const crypto = require('crypto');
const L = require('./_lib');
const S = require('./server');

const same = (a, b) => {
    const x = Buffer.from(String(a || '')), y = Buffer.from(String(b || ''));
    return x.length === y.length && crypto.timingSafeEqual(x, y);
};

module.exports = async (req, res) => {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    try {
        if (req.method !== 'POST') L.fail(405, 'method', 'Méthode non autorisée.');
        const KEY = process.env.SMS_WEBHOOK_KEY || '';
        if (KEY.length < 16) L.fail(503, 'not_configured', 'Webhook SMS non configuré.');
        L.rateLimit('sms:' + L.ipOf(req), 120, 600000);
        const given = req.headers['x-sms-key'] || (req.query && req.query.key) || '';
        if (!same(given, KEY)) L.fail(401, 'unauthorized', 'Accès refusé.');
        let b = req.body;
        if (typeof b === 'string') { try { b = JSON.parse(b); } catch (e) { b = { text: b }; } }
        b = b && typeof b === 'object' ? b : {};
        const text = b.text || b.message || b.body || b.msg || b.content || b.sms || '';
        const out = await S.smsIngest(String(text).slice(0, 1000));
        res.status(200).send(JSON.stringify({ ok: true, ...out }));
    } catch (e) {
        if (e instanceof L.HttpError) {
            // trace des appels refusés (au plus une ligne par minute) pour que l'admin voie le problème
            if (e.code === 'unauthorized' || e.code === 'not_configured') await S.smsLog(e.code, {}, 'refus-' + Math.floor(Date.now() / 60000));
            return res.status(e.status).send(JSON.stringify({ ok: false, error: e.code }));
        }
        console.error('sms error', e);
        res.status(500).send(JSON.stringify({ ok: false, error: 'server' }));
    }
};
