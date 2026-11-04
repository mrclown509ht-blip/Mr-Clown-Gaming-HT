// Serveur Mr CLOWN Top Up : comptes, argent, commandes, dépôts, admin.
// Le navigateur ne voit JAMAIS les mots de passe ni les données des autres clients.
// Toutes les actions arrivent en POST sur /api/srv avec { action, ... }.

const crypto = require('crypto');
const L = require('./_lib');
const { fail, db, safeKey, ukeyOf, digits, str, norm, values, arr, nowStr } = L;

const ROLE_LABELS = { admin: 'ADMINISTRATEUR', manager: 'GÉRANT COMMANDES & FINANCES' };
// Seuls ces deux rôles existent. Tout autre rôle présent dans MANAGERS est refusé.
const STAFF_ROLES = new Set(['admin', 'manager']);
const staffOf = email => { const m = L.managers()[email]; return m && STAFF_ROLES.has(m.role) ? m : null; };
const FINAL = status => /^LIVR[ÉE]/i.test(status || '') || /^ANNUL/i.test(status || '');
const rid = () => crypto.randomBytes(5).toString('hex');
const normTx = c => String(c || '').replace(/\s+/g, '').toUpperCase();
const txKey = c => 'TX_' + safeKey(normTx(c));

const pub = u => ({
    firstname: u.firstname, lastname: u.lastname, email: u.email, phone: u.phone,
    playerId: u.playerId || '', balance: u.balance || 0, code: u.code, claimedRanks: arr(u.claimedRanks),
    ...(u.blocked ? { blocked: true } : {}),
    ...(u.walletOff ? { walletOff: true } : {})
});
const stripOrder = o => { const { gsecret, ...rest } = o; return rest; };

// ------------------------------------------------------------------ authentification
const bearer = req => { const h = String(req.headers.authorization || ''); return h.startsWith('Bearer ') ? h.slice(7) : ''; };

async function authenticate(req) {
    const ctx = {};
    const ct = bearer(req);
    if (ct) {
        const p = L.readToken(ct);
        if (!p || p.t !== 'c') ctx.clientInvalid = true;
        else {
            const u = await db.get('sec/users/' + p.k);
            if (!u || (u.tv || 0) !== p.v) ctx.clientInvalid = true;
            else { ctx.ukey = p.k; ctx.user = u; }
        }
    }
    const at = req.headers['x-admin-token'];
    if (at) {
        const p = L.readToken(at);
        const m = p && p.t === 'a' ? staffOf(p.k) : null;
        if (!m) ctx.adminInvalid = true; else ctx.admin = { email: p.k, role: m.role };
    }
    return ctx;
}
const needUser = ctx => {
    if (!ctx.user) fail(401, 'auth', ctx.clientInvalid ? 'Session expirée : reconnectez-vous.' : 'Connexion requise.');
    if (ctx.user.blocked) fail(403, 'blocked', 'Ce compte a été bloqué. Contactez le support WhatsApp.');
    return ctx.user;
};
const needStaff = (ctx, roles) => {
    if (!ctx.admin) fail(401, 'admin_auth', 'Session gérant expirée : reconnectez-vous.');
    if (roles && !roles.includes(ctx.admin.role)) fail(403, 'forbidden', "Action non autorisée pour votre rôle.");
    return ctx.admin;
};

async function addWallet(ukey, email, type, ref, amount, status, date) {
    const hid = 'H-' + Date.now() + '-' + rid();
    await db.put(`sec/wallet/${ukey}/${hid}`, { hid, userEmail: email, date: date || nowStr(), type, ref, amount, status, _ts: Date.now() });
}

async function creditUser(ukey, amount) {
    return db.txn('sec/users/' + ukey, u => {
        if (!u) fail(404, 'no_user', 'Compte introuvable.');
        u.balance = Math.round(((u.balance || 0) + amount) * 100) / 100;
        return u;
    });
}

async function topUpTotal(ukey) {
    const o = values(await db.get('sec/orders/' + ukey));
    return o.filter(L.isDelivered).reduce((s, x) => s + (Number(x.numericPrice) || 0), 0);
}

// ------------------------------------------------------------------ comptes
async function register(req, b) {
    L.rateLimit('reg:' + L.ipOf(req), 8, 3600000);
    const firstname = str(b.firstname, 40), lastname = str(b.lastname, 40);
    const email = str(b.email, 120).toLowerCase();
    const phone = str(b.phone, 30);
    const password = String(b.password || '');
    if (!firstname || !lastname) fail(400, 'bad_input', 'Nom et prénom obligatoires.');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) fail(400, 'bad_input', 'Email invalide.');
    if (digits(phone).length < 6) fail(400, 'bad_input', 'Téléphone invalide.');
    if (password.length < 6 || password.length > 100) fail(400, 'bad_input', 'Mot de passe : 6 caractères minimum.');
    if (L.managers()[email]) fail(409, 'reserved', "Cet email est réservé à l'équipe de gestion.");

    const ukey = ukeyOf(email), pkey = digits(phone);
    if (!(await db.create('sec/idx_phone/' + pkey, ukey))) fail(409, 'exists', 'Un compte avec cet email ou téléphone existe déjà.');
    let salt = 0, code = L.clientCodeFor(email);
    while (!(await db.create('sec/idx_code/' + code, ukey))) code = L.clientCodeFor(email, ++salt);
    const user = {
        firstname, lastname, email, phone, playerId: '', pw: await L.hashPassword(password),
        code, balance: 0, claimedRanks: [], tv: 0, created: Date.now()
    };
    if (!(await db.create('sec/users/' + ukey, user))) {
        await db.del('sec/idx_phone/' + pkey); await db.del('sec/idx_code/' + code);
        fail(409, 'exists', 'Un compte avec cet email ou téléphone existe déjà.');
    }
    return { token: L.signToken({ t: 'c', k: ukey, v: 0 }, 30 * 86400), user: pub(user) };
}

async function findUser(identifier) {
    const id = str(identifier, 120);
    if (id.includes('@')) { const k = ukeyOf(id); const u = await db.get('sec/users/' + k); return u ? { ukey: k, user: u } : null; }
    const pk = digits(id);
    if (pk.length >= 6) {
        const k = await db.get('sec/idx_phone/' + pk);
        if (k) { const u = await db.get('sec/users/' + k); if (u) return { ukey: k, user: u }; }
    }
    return null;
}

async function login(req, b) {
    L.rateLimit('login:' + L.ipOf(req), 15, 600000);
    const identifier = str(b.identifier, 120);
    L.rateLimit('loginid:' + identifier.toLowerCase(), 8, 600000);
    const found = await findUser(identifier);
    const ok = found ? await L.verifyPassword(String(b.password || ''), found.user.pw) : (await L.verifyPassword('x', '00:00'), false);
    if (!ok) fail(401, 'bad_credentials', 'Identifiants incorrects.');
    if (found.user.blocked) fail(403, 'blocked', 'Ce compte a été bloqué. Contactez le support WhatsApp.');
    return { token: L.signToken({ t: 'c', k: found.ukey, v: found.user.tv || 0 }, 30 * 86400), user: pub(found.user) };
}

async function adminLogin(req, b) {
    L.rateLimit('alogin:' + L.ipOf(req), 10, 600000);
    const email = str(b.email, 120).toLowerCase();
    const m = staffOf(email);
    const ok = m ? await L.verifyPassword(String(b.password || ''), m.hash) : (await L.verifyPassword('x', '00:00'), false);
    if (!ok) fail(401, 'bad_credentials', 'Email ou mot de passe administrateur incorrect.');
    return { token: L.signToken({ t: 'a', k: email }, 12 * 3600), email, role: m.role, label: ROLE_LABELS[m.role] || 'GÉRANT' };
}

// Mot de passe oublié -------------------------------------------------------
async function findForReset(identifier) {
    const direct = await findUser(identifier);
    if (direct) return direct;
    const q = norm(identifier);
    if (!q) return null;
    const all = await db.get('sec/users');
    const hits = Object.entries(all || {}).filter(([, u]) => norm(`${u.firstname} ${u.lastname}`) === q || norm(`${u.lastname} ${u.firstname}`) === q);
    if (hits.length === 1) return { ukey: hits[0][0], user: hits[0][1] };
    if (hits.length > 1) fail(409, 'ambiguous', 'Plusieurs comptes portent ce nom : utilisez votre email ou votre téléphone.');
    return null;
}
async function forgotCheck(req, b) {
    L.rateLimit('fg:' + L.ipOf(req), 15, 600000);
    const f = await findForReset(b.identifier);
    if (!f) fail(404, 'not_found', 'Nom de compte incorrect : opération annulée.');
    if (f.user.blocked) fail(403, 'blocked', 'Ce compte a été bloqué. Contactez le support WhatsApp.');
    return { ok: true };
}
async function forgotSubmit(req, b) {
    L.rateLimit('fgs:' + L.ipOf(req), 8, 3600000);
    const f = await findForReset(b.identifier);
    if (!f) fail(404, 'not_found', 'Compte introuvable : opération annulée.');
    if (f.user.blocked) fail(403, 'blocked', 'Ce compte a été bloqué. Contactez le support WhatsApp.');
    const pw = String(b.newPassword || '');
    if (pw.length < 6 || pw.length > 100) fail(400, 'bad_input', 'Mot de passe : 6 caractères minimum.');
    const old = await db.get('sec/resets');
    for (const [k, r] of Object.entries(old || {})) if (r.email === f.user.email) await db.del('sec/resets/' + k);
    const id = 'R-' + Date.now().toString(36) + rid().slice(0, 3);
    await db.put('sec/resets/' + id, {
        id, email: f.user.email, phone: f.user.phone || '', name: `${f.user.firstname} ${f.user.lastname}`.trim(),
        pw: await L.hashPassword(pw), date: nowStr(), _ts: Date.now()
    });
    return { ok: true, ref: id, name: `${f.user.firstname} ${f.user.lastname}`.trim() };
}

// ------------------------------------------------------------------ commandes
async function orderCreate(ctx, req, b) {
    L.rateLimit('order:' + L.ipOf(req), 25, 60000);
    if (ctx.clientInvalid) fail(401, 'auth', 'Session expirée : reconnectez-vous.');
    const user = ctx.user || null;
    if (user && user.blocked) fail(403, 'blocked', 'Ce compte a été bloqué. Contactez le support WhatsApp.');

    const lines = arr(b.lines).slice(0, 30);
    if (!lines.length) fail(400, 'empty', 'Panier vide.');
    const cat = await L.loadCatalog(true);
    const all = [...cat.products, ...cat.catalog];
    // Jeu ou dossier « sans ID » : pas d'ID de compte demandé (infos de contact dans extraInfo)
    const gameOf = p => cat.games.find(g => g.key === L.productGame(p)) || {};
    const sectionOf = p => Object.values(gameOf(p).sections || {}).find(x => x.key === (p.section || 'std')) || {};
    const NOID_BUILTIN = ['efootball:std', 'dls:jetons'];
    const noId = p => !!(gameOf(p).noId || sectionOf(p).noId || NOID_BUILTIN.includes(L.productGame(p) + ':' + (p.section || 'std')));
    const items = lines.map(l => {
        const p = all.find(x => x.id === Number(l.id));
        if (!p) fail(409, 'product_gone', "Un article du panier n'existe plus : actualisez le panier.");
        const qty = Math.floor(Number(l.qty));
        if (!(qty >= 1 && qty <= 50)) fail(400, 'bad_qty', 'Quantité invalide.');
        if (!(Number(p.price) > 0)) fail(409, 'bad_price', 'Article indisponible.');
        let pid = '';
        if (!noId(p)) {
            pid = digits(l.pid);
            if (!/^\d{6,15}$/.test(pid)) fail(400, 'bad_pid', `ID de compte invalide pour : ${L.productName(p)}.`);
        }
        return { p, qty, pid, pname: str(l.pname, 40) };
    });
    const subtotal = items.reduce((s, i) => s + Number(i.p.price) * i.qty, 0);

    // Infos supplémentaires exigées par certains jeux
    const extra = str(b.extraInfo, 120);
    const needs = items.flatMap(i => [gameOf(i.p).needsExtra, sectionOf(i.p).needsExtra]).filter(Boolean);
    if (needs.length && !extra) fail(400, 'extra_required', 'Information requise : ' + [...new Set(needs)].join(' + ') + '.');

    // Code promo
    const promoCode = L.normalizePromoCode(b.promoCode);
    const firstPid = (items.find(i => i.pid) || {}).pid;
    const userKey = user ? user.email.toLowerCase() : (firstPid ? 'ff:' + firstPid : 'wa:' + digits(extra));
    let promo = null, discount = 0;
    if (promoCode) {
        promo = await db.get('sec/promos/' + safeKey(promoCode));
        const problem = L.promoProblem(promo, userKey);
        if (problem) fail(409, 'promo', problem);
        discount = L.promoDiscountFor(promo, subtotal);
    }
    // Remise de rang
    let rankDiscount = 0, rankName = '';
    if (user) {
        const { rank } = L.rankFor(cat.ranks, await topUpTotal(ctx.ukey));
        const pct = Number(rank.discount) || 0;
        if (pct > 0) { rankDiscount = Math.min(Math.floor((subtotal - discount) * pct / 100), subtotal - discount); rankName = rank.name; }
    }
    const total = subtotal - discount - rankDiscount;
    if (b.expectedTotal !== undefined && Number(b.expectedTotal) !== total)
        fail(409, 'price_changed', `Les prix ont changé : le total est maintenant ${total} G. Vérifiez votre panier.`);

    // Identifiant de commande unique
    let id;
    for (let i = 0; i < 20; i++) {
        id = 'FF-' + (100000 + crypto.randomInt(900000));
        if (await db.create('sec/oidx/' + id, user ? ctx.ukey : '_guest')) break;
        id = null;
    }
    if (!id) fail(503, 'busy', 'Serveur occupé, réessayez.');

    const payment = b.payment === 'wallet' ? 'wallet' : 'natcash';
    let txid = '', txReserved = false, debited = false;
    const rollback = async () => {
        if (debited) await creditUser(ctx.ukey, total).catch(() => {});
        if (txReserved) await db.del('sec/txids/' + txKey(txid)).catch(() => {});
        await db.del('sec/oidx/' + id).catch(() => {});
    };
    try {
        if (payment === 'wallet') {
            if (!user) fail(401, 'auth', 'Connectez-vous pour payer avec Mr Wallet.');
            await db.txn('sec/users/' + ctx.ukey, u => {
                if (!u || u.blocked) fail(403, 'blocked', 'Compte indisponible.');
                if (u.walletOff) fail(403, 'wallet_off', 'Votre Mr Wallet est désactivé. Contactez le support.');
                if ((u.balance || 0) < total) fail(402, 'insufficient', `Solde Mr Wallet insuffisant (${u.balance || 0} G). Veuillez recharger.`);
                u.balance = Math.round(((u.balance || 0) - total) * 100) / 100;
                return u;
            });
            debited = true;
        } else {
            txid = str(b.txid, 40);
            if (txid.length < 4) fail(400, 'bad_tx', 'Code de transaction invalide.');
            if (!(await db.create('sec/txids/' + txKey(txid), 'order:' + id))) fail(409, 'tx_used', 'Ce code de transaction est déjà utilisé.');
            txReserved = true;
        }
        if (promo) {
            await db.txn('sec/promos/' + safeKey(promoCode), p => {
                const problem = L.promoProblem(p, userKey);
                if (problem) fail(409, 'promo', problem);
                p.uses = (p.uses || 0) + 1; p.usedBy = [...arr(p.usedBy), userKey];
                return p;
            });
        }
    } catch (e) { await rollback(); throw e; }

    const orderLines = items.map(i => {
        const line = { name: L.productName(i.p), qty: i.qty, playerId: i.pid || '—' };
        if (i.pname) line.playerName = i.pname;
        return line;
    });
    const order = {
        id, userEmail: user ? user.email : 'Invité',
        playerId: [...new Set(items.map(i => i.pid || '—'))].join(' / '),
        lines: orderLines,
        items: orderLines.map(l => `${l.qty}x ${l.name}`).join(', '),
        price: `${total} G`, numericPrice: total,
        payment: payment === 'wallet' ? 'Solde Mr Wallet' : `Natcash (${txid})`,
        date: nowStr(), status: payment === 'wallet' ? 'LIVRAISON EN COURS' : 'EN ATTENTE VALIDATION', _ts: Date.now()
    };
    if (payment === 'natcash') order.txid = txid;
    if (promo && discount > 0) { order.promoCode = promoCode; order.discount = discount; }
    if (rankDiscount > 0) { order.rankName = rankName; order.rankDiscount = rankDiscount; }
    if (extra) order.extraInfo = extra;
    let gsecret = '';
    if (!user) { gsecret = crypto.randomBytes(12).toString('hex'); order.gsecret = gsecret; }
    try {
        await db.put(`sec/orders/${user ? ctx.ukey : '_guest'}/${id}`, order);
        if (payment === 'wallet') await addWallet(ctx.ukey, user.email, 'Achat Top Up', 'DEBIT-' + id, `-${total} G`, 'PAYÉ');
    } catch (e) { await rollback(); throw e; }

    const fresh = user ? pub(await db.get('sec/users/' + ctx.ukey)) : null;
    return { order: stripOrder(order), gsecret, user: fresh };
}

async function guestOrders(b) {
    const out = [];
    for (const it of arr(b.items).slice(0, 40)) {
        const id = str(it.id, 20);
        if (!/^FF-\d{6}$/.test(id)) continue;
        const o = await db.get(`sec/orders/_guest/${id}`);
        if (!o || !o.gsecret) continue;
        const a = Buffer.from(String(it.gsecret || '')), c = Buffer.from(o.gsecret);
        if (a.length === c.length && crypto.timingSafeEqual(a, c)) out.push(stripOrder(o));
    }
    return { orders: out };
}

async function orderDecide(ctx, b) {
    needStaff(ctx, ['admin', 'manager']);
    const id = str(b.id, 20);
    const owner = await db.get('sec/oidx/' + id);
    if (!owner) fail(404, 'not_found', 'Commande introuvable.');
    const approve = b.decision === 'approve';
    const order = await db.txn(`sec/orders/${owner}/${id}`, o => {
        if (!o) fail(404, 'not_found', 'Commande introuvable.');
        if (FINAL(o.status)) fail(409, 'final', 'Cette commande est déjà traitée (' + o.status + ').');
        o.status = approve ? 'LIVRÉ ✅' : 'ANNULÉ ❌';
        return o;
    });
    // Commande payée avec Mr Wallet puis annulée : remboursement automatique
    if (!approve && order.payment === 'Solde Mr Wallet' && owner !== '_guest') {
        await creditUser(owner, Number(order.numericPrice) || 0);
        await addWallet(owner, order.userEmail, 'Remboursement commande', 'REFUND-' + id, `+${order.numericPrice} G`, 'CONFIRMÉ');
    }
    return { order: stripOrder(order) };
}

// ------------------------------------------------------------------ portefeuille
// ------------------------------------------------------------------ crédit automatique par SMS Natcash
const SMS_AUTO_MAX = Number(process.env.SMS_AUTO_MAX) || 25000;   // au-dessus : validation manuelle
const SMS_MAX_AGE = 3 * 24 * 3600 * 1000;                          // SMS plus vieux que 3 jours : manuel

// Lit un SMS « Ou te ajoute 1,000 HTG ... Transcode: 123... » ou « Ou resevwa 135 HTG ... » (reçus uniquement)
function parseNatcashSms(text) {
    const t = String(text || '').replace(/\s+/g, ' ').trim();
    if (!/\bOu\s+(te\s+ajoute|resevwa)\b/i.test(t)) return null;
    const tx = (t.match(/Transcode\s*:?\s*([0-9]{8,})/i) || [])[1];
    const am = (t.match(/([0-9][0-9.,]*)\s*HTG/i) || [])[1];
    if (!tx || !am) return null;
    const amount = Math.round(parseFloat(am.replace(/,/g, '')) * 100) / 100;
    if (!(amount > 0)) return null;
    return { txid: tx, amount, text: t.slice(0, 300) };
}

const smsMatches = (sms, amount) => !!sms && !sms.used && Math.abs(Number(sms.amount) - Number(amount)) < 0.01
    && Number(amount) <= SMS_AUTO_MAX && Date.now() - Number(sms.ts || 0) <= SMS_MAX_AGE;

async function autoSettle(id) {
    let dep = null;
    const d0 = await db.get('sec/deposits/' + id);
    if (!d0) return false;
    const u0 = await db.get('sec/users/' + ukeyOf(d0.userEmail));
    if (!u0 || u0.walletOff || u0.blocked) return false; // wallet inactif : le dépôt reste en attente
    try { await db.txn('sec/deposits/' + id, v => { if (!v) fail(404, 'not_found', 'x'); dep = v; return null; }); } catch (e) { return false; }
    try { await creditUser(ukeyOf(dep.userEmail), Number(dep.amount)); }
    catch (e) { await db.put('sec/deposits/' + id, dep); return false; }
    await addWallet(ukeyOf(dep.userEmail), dep.userEmail, 'Dépôt Natcash', dep.txid, `+${dep.amount} G`, 'CONFIRMÉ', dep.date);
    await db.put('sec/txids/' + txKey(dep.txid), 'wallet');
    return true;
}

// Réserve le SMS pour ce dépôt puis crédite. Retourne true si le client a été crédité automatiquement.
async function tryAutoDeposit(dep) {
    const key = 'sec/sms/' + txKey(dep.txid);
    let claimed = false;
    await db.txn(key, v => {
        claimed = false;
        if (!smsMatches(v, dep.amount)) return undefined;
        claimed = true; v.used = dep.id; v.usedBy = dep.userEmail; return v;
    });
    if (!claimed) return false;
    const ok = await autoSettle(dep.id);
    if (!ok) await db.txn(key, v => { if (v) { delete v.used; delete v.usedBy; return v; } return undefined; }).catch(() => {});
    return ok;
}

// Appelé par /api/sms à l'arrivée d'un SMS de Natcash
async function smsIngest(text) {
    const sms = parseNatcashSms(text);
    if (!sms) return { ignored: true };
    const key = txKey(sms.txid);
    const rec = { txid: sms.txid, amount: sms.amount, ts: Date.now(), text: sms.text, used: false };
    if (!(await db.create('sec/sms/' + key, rec))) return { duplicate: true };
    const owner = await db.get('sec/txids/' + key);
    if (typeof owner === 'string' && owner.startsWith('deposit:')) {
        const dep = await db.get('sec/deposits/' + owner.slice(8));
        if (dep && smsMatches(rec, dep.amount)) return { stored: true, credited: await tryAutoDeposit(dep) };
    }
    return { stored: true, credited: false };
}

async function depositCreate(ctx, req, b) {
    L.rateLimit('dep:' + L.ipOf(req), 10, 600000);
    const user = needUser(ctx);
    if (user.walletOff) fail(403, 'wallet_off', 'Votre Mr Wallet est désactivé. Contactez le support.');
    const amount = Math.round(Number(b.amount) * 100) / 100;
    if (!(amount >= 1 && amount <= 1000000)) fail(400, 'bad_amount', 'Montant invalide.');
    const txid = str(b.txid, 40);
    if (txid.length < 4) fail(400, 'bad_tx', 'Code de transaction invalide.');
    const id = 'DEP-' + Date.now() + '-' + rid().slice(0, 3);
    if (!(await db.create('sec/txids/' + txKey(txid), 'deposit:' + id))) fail(409, 'tx_used', 'Ce code de transaction est déjà utilisé.');
    const dep = {
        id, user: `${user.firstname} ${user.lastname}`.trim(), userEmail: user.email, phone: user.phone,
        amount, txid, date: nowStr(), _ts: Date.now()
    };
    await db.put('sec/deposits/' + id, dep);
    let auto = false;
    try { auto = await tryAutoDeposit(dep); } catch (e) { console.error('auto deposit', e); }
    return { deposit: dep, auto };
}

async function depositDecide(ctx, b) {
    needStaff(ctx, ['admin', 'manager']);
    const id = str(b.id, 40);
    if (b.decision === 'approve') {
        const d0 = await db.get('sec/deposits/' + id);
        const u0 = d0 && await db.get('sec/users/' + ukeyOf(d0.userEmail));
        if (u0 && u0.walletOff) fail(403, 'wallet_off', 'Le Mr Wallet de ce client est inactif : réactivez-le avant de valider ce dépôt.');
    }
    let dep = null;
    await db.txn('sec/deposits/' + id, v => { if (!v) fail(404, 'not_found', 'Dépôt introuvable ou déjà traité.'); dep = v; return null; });
    if (b.decision !== 'approve') { await db.del('sec/txids/' + txKey(dep.txid)); return { ok: true }; }
    try {
        await creditUser(ukeyOf(dep.userEmail), Number(dep.amount));
    } catch (e) { await db.put('sec/deposits/' + id, dep); throw e; }
    await addWallet(ukeyOf(dep.userEmail), dep.userEmail, 'Dépôt Natcash', dep.txid, `+${dep.amount} G`, 'CONFIRMÉ', dep.date);
    await db.put('sec/txids/' + txKey(dep.txid), 'wallet');
    return { ok: true };
}

async function rankClaim(ctx, b) {
    const user = needUser(ctx);
    const cat = await L.loadCatalog();
    const total = await topUpTotal(ctx.ukey);
    const { idx } = L.rankFor(cat.ranks, total);
    const ri = cat.ranks.findIndex(r => r.key === str(b.key, 30));
    if (ri < 0 || ri > idx) fail(400, 'locked', "Ce rang n'est pas encore atteint.");
    const rk = cat.ranks[ri], bonus = Number(rk.bonus) || 0;
    if (bonus <= 0) fail(400, 'no_bonus', 'Aucun bonus pour ce rang.');
    const u = await db.txn('sec/users/' + ctx.ukey, x => {
        if (x.walletOff) fail(403, 'wallet_off', 'Votre Mr Wallet est désactivé. Contactez le support.');
        if (arr(x.claimedRanks).includes(rk.key)) fail(409, 'claimed', 'Récompense déjà réclamée.');
        x.claimedRanks = [...arr(x.claimedRanks), rk.key];
        x.balance = Math.round(((x.balance || 0) + bonus) * 100) / 100;
        return x;
    });
    await addWallet(ctx.ukey, user.email, `Récompense rang ${rk.name}`, 'RANG-' + rk.key.toUpperCase(), `+${bonus} G`, 'CONFIRMÉ');
    return { user: pub(u), bonus };
}

async function promoCheck(ctx, req, b) {
    L.rateLimit('promo:' + L.ipOf(req), 30, 60000);
    const code = L.normalizePromoCode(b.code);
    if (!code) fail(400, 'bad_input', 'Saisissez un code promo.');
    const userKey = ctx.user ? ctx.user.email.toLowerCase() : 'ff:' + digits(b.pid);
    const p = await db.get('sec/promos/' + safeKey(code));
    const problem = L.promoProblem(p, userKey);
    if (problem) fail(409, 'promo', problem);
    return { promo: { code: p.code, type: p.type, value: p.value, active: true } };
}

// ------------------------------------------------------------------ état (données autorisées pour l'appelant)
const flatten = tree => Object.values(tree || {}).flatMap(v => values(v));
const byTs = (a, b) => (b._ts || 0) - (a._ts || 0);

async function state(ctx) {
    const out = { serverNow: Date.now(), me: ctx.user ? pub(ctx.user) : null, role: ctx.admin ? ctx.admin.role : null, users: [], orders: [], wallet: [], deposits: [] };
    if (ctx.clientInvalid) out.clientInvalid = true;
    if (ctx.adminInvalid) out.adminInvalid = true;
    const role = ctx.admin && ctx.admin.role;
    const jobs = [];
    const orderMap = new Map(), walletMap = new Map(), depMap = new Map();
    const add = (m, list) => list.forEach(x => m.set(x.id || x.hid, x));

    if (ctx.user) {
        out.users = [pub(ctx.user)];
        jobs.push(db.get('sec/orders/' + ctx.ukey).then(v => add(orderMap, values(v).map(stripOrder))));
        jobs.push(db.get('sec/wallet/' + ctx.ukey).then(v => add(walletMap, values(v))));
        jobs.push(db.get('sec/deposits').then(v => add(depMap, values(v).filter(d => d.userEmail === ctx.user.email))));
    }
    if (role) {
        jobs.push(db.get('sec/orders').then(v => add(orderMap, flatten(v).map(stripOrder))));
        if (role === 'admin' || role === 'manager') {
            jobs.push(db.get('sec/wallet').then(v => add(walletMap, flatten(v))));
            jobs.push(db.get('sec/deposits').then(v => add(depMap, values(v))));
        }
        if (role === 'admin') {
            out.resets = [];
            jobs.push(db.get('sec/users').then(v => { out.users = values(v).map(u => ({ ...pub(u) })); }));
            jobs.push(db.get('sec/resets').then(v => { out.resets = values(v).map(({ pw, ...r }) => r).sort(byTs); }));
            jobs.push(db.get('sec/promos').then(v => { out.promos = values(v); }));
            jobs.push(db.get('sec/presence').then(v => { out.presence = v || {}; }));
        }
    }
    await Promise.all(jobs);
    out.orders = [...orderMap.values()].sort(byTs);
    out.wallet = [...walletMap.values()].sort(byTs);
    out.deposits = [...depMap.values()].sort(byTs);
    return out;
}

// ------------------------------------------------------------------ présence et chat
async function presence(ctx, b) {
    const user = needUser(ctx);
    await db.put('sec/presence/' + safeKey(user.code), { t: Date.now(), off: !!b.off });
    return { ok: true };
}

const threadOf = email => 'c_' + String(email).toLowerCase();
async function chatList(ctx) {
    if (ctx.admin) return { messages: flatten(await db.get('sec/chat')).sort((a, b) => a._ts - b._ts) };
    const user = needUser(ctx);
    const v = await db.get('sec/chat/' + safeKey(threadOf(user.email)));
    return { messages: values(v).sort((a, b) => a._ts - b._ts) };
}
async function chatSend(ctx, req, b) {
    L.rateLimit('chat:' + L.ipOf(req), 30, 60000);
    const text = str(b.text, 500);
    if (!text) fail(400, 'empty', 'Message vide.');
    let thread, from, fromName;
    if (ctx.admin) {
        thread = str(b.thread, 160);
        if (thread !== 'staff' && !/^c_.+/.test(thread)) fail(400, 'bad_thread', 'Conversation invalide.');
        from = ctx.admin.email; fromName = ROLE_LABELS[ctx.admin.role] || 'Gérant';
    } else {
        const user = needUser(ctx);
        thread = threadOf(user.email); from = user.email; fromName = `${user.firstname} ${user.lastname}`.trim() || user.email;
    }
    const now = Date.now(), d = new Date(now);
    const msg = {
        id: 'M-' + now + '-' + rid(), thread, from, fromName, text, _ts: now,
        date: d.toLocaleDateString('fr-FR', { timeZone: 'America/Port-au-Prince' }) + ' ' + d.toLocaleTimeString('fr-FR', { timeZone: 'America/Port-au-Prince', hour: '2-digit', minute: '2-digit' })
    };
    await db.put(`sec/chat/${safeKey(thread)}/${msg.id}`, msg);
    return { message: msg };
}

// ------------------------------------------------------------------ administration
async function clientBlock(ctx, b) {
    needStaff(ctx, ['admin']);
    const ukey = ukeyOf(b.email);
    const u = await db.txn('sec/users/' + ukey, x => {
        if (!x) fail(404, 'not_found', 'Client introuvable.');
        if (b.blocked) { x.blocked = true; x.tv = (x.tv || 0) + 1; } else delete x.blocked;
        return x;
    });
    return { user: pub(u) };
}

async function walletToggle(ctx, b) {
    needStaff(ctx, ['admin']);
    const ukey = ukeyOf(b.email);
    const u = await db.txn('sec/users/' + ukey, x => {
        if (!x) fail(404, 'not_found', 'Client introuvable.');
        if (b.off) x.walletOff = true; else delete x.walletOff;
        return x;
    });
    return { user: pub(u) };
}

async function resetDecide(ctx, b) {
    needStaff(ctx, ['admin']);
    const id = str(b.id, 40);
    const r = await db.get('sec/resets/' + id);
    if (!r) fail(404, 'not_found', 'Demande introuvable.');
    if (b.decision === 'approve') {
        await db.txn('sec/users/' + ukeyOf(r.email), u => {
            if (!u) fail(404, 'not_found', 'Compte introuvable.');
            u.pw = r.pw; u.tv = (u.tv || 0) + 1;
            return u;
        });
    }
    await db.del('sec/resets/' + id);
    return { ok: true };
}

async function promoWrite(ctx, b) {
    needStaff(ctx, ['admin']);
    const patch = b.patch && typeof b.patch === 'object' ? b.patch : {};
    const keys = Object.keys(patch).slice(0, 200);
    for (const code of keys) {
        const c = L.normalizePromoCode(code);
        if (!/^[A-Z0-9_-]{3,20}$/.test(c)) fail(400, 'bad_input', 'Code promo invalide.');
        const key = safeKey(c), v = patch[code];
        if (v === null) { await db.del('sec/promos/' + key); continue; }
        const old = (await db.get('sec/promos/' + key)) || {};
        const type = v.type === 'fixed' || v.type === 'amount' ? v.type : 'percent';
        const value = Number(v.value);
        if (!(value > 0) || (type === 'percent' && value > 100)) fail(400, 'bad_input', 'Valeur de remise invalide.');
        await db.put('sec/promos/' + key, {
            code: c, type: v.type || type, value, maxUses: Math.max(0, parseInt(v.maxUses, 10) || 0),
            expires: str(v.expires, 10), active: v.active !== false,
            uses: old.uses || 0, usedBy: arr(old.usedBy), _ts: v._ts || old._ts || Date.now()
        });
    }
    return { ok: true };
}

const CATALOG_KEYS = ['products', 'catalog', 'games', 'ranks'];
async function dataWrite(ctx, b) {
    needStaff(ctx, ['admin']);
    if (!CATALOG_KEYS.includes(b.key)) fail(400, 'bad_key', 'Collection inconnue.');
    const patch = b.patch && typeof b.patch === 'object' ? b.patch : {};
    const keys = Object.keys(patch);
    if (!keys.length || keys.length > 1500) fail(400, 'bad_input', 'Modification invalide.');
    for (const k of keys) {
        if (!/^[A-Za-z0-9_%\-]{1,80}$/.test(k)) fail(400, 'bad_input', 'Clé invalide.');
        const v = patch[k];
        if (v !== null && (typeof v !== 'object' || Array.isArray(v))) fail(400, 'bad_input', 'Valeur invalide.');
    }
    await db.patch('mrclown/' + b.key, patch);
    await L.loadCatalog(true).catch(() => {});
    return { ok: true };
}

// Reprise des anciennes données (base publique /mrclown) vers le coffre sécurisé (/sec)
async function migrate(ctx) {
    needStaff(ctx, ['admin']);
    const count = { users: 0, orders: 0, deposits: 0, wallet: 0, promos: 0, chat: 0, skipped: 0 };
    const legacy = async p => values(await db.get('mrclown/' + p));
    const existingUsers = (await db.get('sec/users')) || {};

    const newUsers = {};
    for (const u of await legacy('users')) {
        if (!u || !u.email) continue;
        const ukey = ukeyOf(u.email);
        if (existingUsers[ukey]) { count.skipped++; continue; }
        const email = String(u.email).toLowerCase();
        let salt = 0, code = u.code || L.clientCodeFor(email);
        while (!(await db.create('sec/idx_code/' + code, ukey))) {
            const cur = await db.get('sec/idx_code/' + code);
            if (cur === ukey) break;
            code = L.clientCodeFor(email, ++salt);
        }
        const pk = digits(u.phone);
        if (pk.length >= 6) await db.create('sec/idx_phone/' + pk, ukey);
        newUsers[ukey] = {
            firstname: str(u.firstname, 40), lastname: str(u.lastname, 40), email, phone: str(u.phone, 30),
            playerId: str(u.playerId, 20), pw: await L.hashPassword(u.password || crypto.randomBytes(9).toString('hex')),
            code, balance: Number(u.balance) || 0, claimedRanks: arr(u.claimedRanks), tv: 0,
            ...(u.blocked ? { blocked: true } : {}), created: Date.now()
        };
        count.users++;
    }
    if (Object.keys(newUsers).length) await db.patch('sec/users', newUsers);

    const groupBy = (list, fnKey) => { const g = {}; list.forEach(x => { const k = fnKey(x); (g[k] = g[k] || {})[x._id] = x; }); return g; };
    const txs = {};
    const orders = (await legacy('orders')).filter(o => o && o.id);
    const og = {}; const oidx = {};
    orders.forEach(o => {
        const owner = o.userEmail && o.userEmail !== 'Invité' ? ukeyOf(o.userEmail) : '_guest';
        (og[owner] = og[owner] || {})[o.id] = o; oidx[o.id] = owner; count.orders++;
        const m = o.txid || (/^Natcash \((.*)\)$/.exec(o.payment || '') || [])[1];
        if (m) txs[txKey(m)] = 'order:' + o.id;
    });
    for (const [owner, set] of Object.entries(og)) await db.patch('sec/orders/' + owner, set);
    if (Object.keys(oidx).length) await db.patch('sec/oidx', oidx);

    const deps = (await legacy('deposits')).filter(d => d && d.id);
    const dset = {};
    deps.forEach(d => { dset[d.id] = d; txs[txKey(d.txid)] = 'deposit:' + d.id; count.deposits++; });
    if (deps.length) await db.patch('sec/deposits', dset);

    const wg = {};
    (await legacy('wallet')).filter(h => h && h.userEmail).forEach(h => {
        const hid = h.hid || 'H-' + Date.now() + '-' + rid();
        (wg[ukeyOf(h.userEmail)] = wg[ukeyOf(h.userEmail)] || {})[hid] = { ...h, hid };
        if (h.type === 'Dépôt Natcash') txs[txKey(h.ref)] = 'wallet';
        count.wallet++;
    });
    for (const [owner, set] of Object.entries(wg)) await db.patch('sec/wallet/' + owner, set);
    if (Object.keys(txs).length) await db.patch('sec/txids', txs);

    const pset = {};
    (await legacy('promos')).filter(p => p && p.code).forEach(p => { pset[safeKey(p.code)] = p; count.promos++; });
    if (Object.keys(pset).length) await db.patch('sec/promos', pset);

    const cg = {};
    (await legacy('chat')).filter(m => m && m.id && m.thread).forEach(m => { (cg[safeKey(m.thread)] = cg[safeKey(m.thread)] || {})[m.id] = m; count.chat++; });
    for (const [t, set] of Object.entries(cg)) await db.patch('sec/chat/' + t, set);
    return { ok: true, count };
}

async function purgeLegacy(ctx, b) {
    needStaff(ctx, ['admin']);
    if (b.confirm !== 'SUPPRIMER') fail(400, 'confirm', 'Confirmation requise.');
    for (const p of ['users', 'orders', 'deposits', 'wallet', 'resets', 'promos', 'chat', 'presence', 'presence_clock']) await db.del('mrclown/' + p);
    return { ok: true };
}

// ------------------------------------------------------------------ routeur
module.exports = async (req, res) => {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    try {
        if (req.method !== 'POST') fail(405, 'method', 'Méthode non autorisée.');
        let b = req.body;
        if (typeof b === 'string') { try { b = JSON.parse(b); } catch (e) { b = {}; } }
        b = b && typeof b === 'object' ? b : {};
        const ctx = await authenticate(req);
        let out;
        switch (b.action) {
            case 'register': out = await register(req, b); break;
            case 'login': out = await login(req, b); break;
            case 'admin_login': out = await adminLogin(req, b); break;
            case 'forgot_check': out = await forgotCheck(req, b); break;
            case 'forgot_submit': out = await forgotSubmit(req, b); break;
            case 'state': out = await state(ctx); break;
            case 'order_create': out = await orderCreate(ctx, req, b); break;
            case 'guest_orders': out = await guestOrders(b); break;
            case 'order_decide': out = await orderDecide(ctx, b); break;
            case 'deposit_create': out = await depositCreate(ctx, req, b); break;
            case 'deposit_decide': out = await depositDecide(ctx, b); break;
            case 'rank_claim': out = await rankClaim(ctx, b); break;
            case 'promo_check': out = await promoCheck(ctx, req, b); break;
            case 'presence': out = await presence(ctx, b); break;
            case 'chat_list': out = await chatList(ctx); break;
            case 'chat_send': out = await chatSend(ctx, req, b); break;
            case 'client_block': out = await clientBlock(ctx, b); break;
            case 'wallet_toggle': out = await walletToggle(ctx, b); break;
            case 'reset_decide': out = await resetDecide(ctx, b); break;
            case 'promo_write': out = await promoWrite(ctx, b); break;
            case 'data_write': out = await dataWrite(ctx, b); break;
            case 'migrate': out = await migrate(ctx); break;
            case 'purge_legacy': out = await purgeLegacy(ctx, b); break;
            default: fail(400, 'bad_action', 'Action inconnue.');
        }
        res.status(200).send(JSON.stringify({ ok: true, ...out }));
    } catch (e) {
        if (e instanceof L.HttpError) return res.status(e.status).send(JSON.stringify({ ok: false, error: e.code, message: e.message }));
        console.error('srv error', e);
        res.status(500).send(JSON.stringify({ ok: false, error: 'server', message: 'Erreur serveur.' }));
    }
};
module.exports.smsIngest = smsIngest;
module.exports.parseNatcashSms = parseNatcashSms;
