// Fabrique l'empreinte (hash) d'un mot de passe de gérant pour la variable MANAGERS.
// Usage :  node tools/hash-password.js "MonNouveauMotDePasse"
const crypto = require('crypto');
const pw = process.argv[2];
if (!pw || pw.length < 8) { console.error('Usage : node tools/hash-password.js "mot-de-passe-de-8-caracteres-minimum"'); process.exit(1); }
const salt = crypto.randomBytes(16);
console.log(salt.toString('hex') + ':' + crypto.scryptSync(pw, salt, 64).toString('hex'));
