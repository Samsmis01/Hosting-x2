// server.js
// Serveur de couplage multi-utilisateurs — 4 serveurs (workers) — version SÉCURISÉE
//
// 🔐 VARIABLES D'ENVIRONNEMENT (Render → Environment) :
//   ADMIN_KEY             (obligatoire, 24+ caractères) clé partagée avec les workers (header x-admin-key)
//   ENCRYPTION_KEY        (optionnel, 64 caractères hexadécimaux) chiffre users.json sur le disque
//   ALLOWED_ORIGINS       (optionnel) sites autorisés à appeler l'API, ex: https://mon-site.com
//   MAX_USERS_PER_SERVER  (optionnel, défaut 10)
//   DATA_DIR              (optionnel, défaut ./data) dossier de users.json (utilise un Disk Render pour garder les données)
//   ADMIN_PANEL_USERNAME  (optionnel, défaut "arcaneM11") identifiant de connexion à /admin
//   ADMIN_PANEL_PASSWORD  (obligatoire pour activer /admin, 12+ caractères) mot de passe de connexion à /admin
//
// 🖥️ Chaque worker doit définir : SERVER_URL, ADMIN_KEY (même valeur) et SERVER_ID (1, 2, 3 ou 4)

const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ==================== CONFIGURATION ====================
const SERVER_IDS = [1, 2, 3, 4];
const MAX_USERS_PER_SERVER = parseInt(process.env.MAX_USERS_PER_SERVER || '10', 10);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const ADMIN_KEY = process.env.ADMIN_KEY || '';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map(s => s.trim().replace(/\/$/, '')).filter(Boolean);
const WORKER_ONLINE_WINDOW = 30 * 1000; // un worker est "en ligne" s'il a envoyé ses stats il y a < 30 s
const PAIR_TIMEOUT = 90 * 1000;

// 🆕 ==================== PANNEAU ADMINISTRATEUR ====================
const ADMIN_PANEL_USERNAME = process.env.ADMIN_PANEL_USERNAME || '';
const ADMIN_PANEL_PASSWORD = process.env.ADMIN_PANEL_PASSWORD || '';
const ADMIN_SESSION_TTL = 12 * 60 * 60 * 1000; // 12h, glissant à chaque requête authentifiée

if (ADMIN_KEY.length < 24) {
  console.error('❌ ADMIN_KEY manquante ou trop courte (min 24 caractères). Définis-la dans les variables d\'environnement.');
  process.exit(1);
}
if (ENCRYPTION_KEY && !/^[0-9a-fA-F]{64}$/.test(ENCRYPTION_KEY)) {
  console.error('❌ ENCRYPTION_KEY invalide : 64 caractères hexadécimaux attendus (32 octets).');
  process.exit(1);
}
// 🆕 On ne bloque PAS le démarrage du service si le panneau admin n'est pas configuré
// (le couplage WhatsApp doit continuer à fonctionner) — on désactive juste /admin proprement.
if (!ADMIN_PANEL_PASSWORD || ADMIN_PANEL_PASSWORD.length < 12) {
  console.error('⚠️ ADMIN_PANEL_PASSWORD absente ou trop courte (min 12 caractères) : le panneau /admin est désactivé jusqu\'à ce qu\'elle soit définie.');
}

// ==================== OUTILS DE SÉCURITÉ ====================
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
const safeEqual = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const hashToken = (t) => crypto.createHash('sha256').update(String(t)).digest('hex');
const maskPhone = (p) => String(p).length > 5 ? String(p).slice(0, 3) + '****' + String(p).slice(-2) : '***';

const hits = new Map();
function rateLimited(bucket, key, max, windowMs) {
  const k = bucket + ':' + key;
  const now = Date.now();
  let e = hits.get(k);
  if (!e || now > e.reset) {
    e = { count: 0, reset: now + windowMs };
    hits.set(k, e);
  }
  e.count++;
  return e.count > max;
}
const limit = (bucket, max, windowMs) => (req, res, next) => {
  if (rateLimited(bucket, req.ip, max, windowMs)) {
    return res.status(429).json({ error: 'Trop de requêtes, réessayez plus tard' });
  }
  next();
};

// Blocage temporaire des IP qui se trompent de clé worker
const authFails = new Map();
const AUTH_MAX_FAILS = 10, AUTH_WINDOW = 10 * 60 * 1000, AUTH_LOCK = 15 * 60 * 1000;
function authLocked(ip) {
  const e = authFails.get(ip);
  return !!(e && e.lockUntil && Date.now() < e.lockUntil);
}
function authFail(ip) {
  const now = Date.now();
  let e = authFails.get(ip);
  if (!e || now - e.first > AUTH_WINDOW) { e = { count: 0, first: now, lockUntil: 0 }; authFails.set(ip, e); }
  e.count++;
  if (e.count >= AUTH_MAX_FAILS) e.lockUntil = now + AUTH_LOCK;
}

// 🆕 ==================== SESSIONS DU PANNEAU ADMIN ====================
// Jetons en mémoire (perdus au redémarrage du serveur -> l'admin doit se reconnecter, c'est voulu).
const adminSessions = new Map(); // token -> { expiresAt }

function createAdminSession() {
  const token = crypto.randomBytes(32).toString('hex');
  adminSessions.set(token, { expiresAt: Date.now() + ADMIN_SESSION_TTL });
  return token;
}
function adminSessionValid(token) {
  if (!token) return false;
  const s = adminSessions.get(token);
  if (!s) return false;
  if (Date.now() > s.expiresAt) { adminSessions.delete(token); return false; }
  return true;
}
// Middleware : protège toutes les routes /api/admin/* (sauf /login)
function adminAuth(req, res, next) {
  const m = /^Bearer ([A-Za-z0-9]{64})$/.exec(req.headers.authorization || '');
  const token = m ? m[1] : null;
  if (!adminSessionValid(token)) {
    return res.status(401).json({ error: 'Session admin invalide ou expirée, reconnectez-vous.' });
  }
  adminSessions.get(token).expiresAt = Date.now() + ADMIN_SESSION_TTL; // expiration glissante
  req.adminToken = token;
  next();
}

// ==================== MIDDLEWARES ====================
app.disable('x-powered-by');
app.set('trust proxy', 1); // Render est derrière un proxy

// En-têtes de sécurité
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  if (req.secure) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    `connect-src 'self' ${ALLOWED_ORIGINS.join(' ')}`.trim(),
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'"
  ].join('; '));
  next();
});

// CORS : plus de "*" — uniquement les origines autorisées
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin.replace(/\/$/, ''))) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Max-Age', '600');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.use(express.json({ limit: '20kb' }));

// ==================== BASE DE DONNÉES SIMPLE (chiffrée si ENCRYPTION_KEY) ====================
function encryptData(text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
  const enc = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return 'enc:' + iv.toString('hex') + ':' + tag.toString('hex') + ':' + enc.toString('hex');
}
function decryptData(text) {
  const [, ivHex, tagHex, encHex] = text.split(':');
  const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(ENCRYPTION_KEY, 'hex'), Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  return Buffer.concat([decipher.update(Buffer.from(encHex, 'hex')), decipher.final()]).toString('utf8');
}

function loadUsers() {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
    if (!fs.existsSync(USERS_FILE)) return {};
    const raw = fs.readFileSync(USERS_FILE, 'utf8');
    try {
      if (raw.startsWith('enc:')) {
        if (!ENCRYPTION_KEY) throw new Error('fichier chiffré mais ENCRYPTION_KEY absente');
        return JSON.parse(decryptData(raw));
      }
      return JSON.parse(raw);
    } catch (e) {
      // On garde une copie au lieu d'écraser des données illisibles
      const bak = USERS_FILE + '.corrupt-' + Date.now();
      try { fs.copyFileSync(USERS_FILE, bak); } catch (_) {}
      console.error('❌ users.json illisible (copie sauvegardée) :', e.message);
      return {};
    }
  } catch (e) {
    console.error('❌ Erreur chargement users:', e.message);
    return {};
  }
}

let users = loadUsers();

function saveUsers() {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
    const json = JSON.stringify(users);
    const data = ENCRYPTION_KEY ? encryptData(json) : json;
    const tmp = USERS_FILE + '.tmp';
    fs.writeFileSync(tmp, data, { mode: 0o600 });
    fs.renameSync(tmp, USERS_FILE); // écriture atomique
  } catch (e) {
    console.error('❌ Erreur sauvegarde users:', e.message);
  }
}

// ==================== ÉTAT DES 4 SERVEURS ====================
const workers = {}; // id -> { cpu, ram, users, uptime, lastSeen }

function serverInfo(id) {
  const w = workers[id];
  const online = !!(w && Date.now() - w.lastSeen < WORKER_ONLINE_WINDOW);
  const registered = Object.values(users)
    .filter(u => u.serverId === id && (u.status === 'connected' || u.status === 'pending')).length;
  const current = Math.max(online ? (w.users || 0) : 0, registered);
  return {
    id,
    name: `Serveur ${id}`,
    online,
    current,
    max: MAX_USERS_PER_SERVER,
    cpu: online ? w.cpu : 0,
    ram: online ? w.ram : 0
  };
}

function pickServer() {
  // Serveur en ligne le moins chargé qui n'est pas plein
  return SERVER_IDS.map(serverInfo)
    .filter(s => s.online && s.current < s.max)
    .sort((a, b) => a.current - b.current)[0] || null;
}

// ==================== SYSTÈME DE QUEUE ====================
const pendingRequests = new Map();

function createRequest(phone, serverId) {
  return new Promise((resolve, reject) => {
    const requestId = crypto.randomBytes(8).toString('hex');
    const timeout = setTimeout(() => {
      if (pendingRequests.has(requestId)) {
        pendingRequests.delete(requestId);
        reject(new Error('Timeout : aucun worker disponible'));
      }
    }, PAIR_TIMEOUT);
    pendingRequests.set(requestId, { phone, serverId, resolve, reject, timeout, createdAt: Date.now() });
  });
}

function hasPendingRequest(phone) {
  for (const r of pendingRequests.values()) if (r.phone === phone) return true;
  return false;
}

// ==================== VÉRIFICATION DU JETON UTILISATEUR ====================
function userTokenValid(req, user) {
  const m = /^Bearer ([A-Za-z0-9_-]{20,100})$/.exec(req.headers.authorization || '');
  if (!m || !user || !user.tokenHash) return false;
  return safeEqual(hashToken(m[1]), user.tokenHash);
}

const PHONE_RE = /^\d{9,15}$/;

// ==================== ROUTES PUBLIQUES ====================

// Site web : on sert UNIQUEMENT index.html (plus tout le dossier du projet)
app.get(['/', '/index.html'], limit('web', 120, 60 * 1000), (req, res) => {
  res.setHeader('Cache-Control', 'no-cache');
  res.sendFile(path.join(__dirname, 'index.html'), (err) => {
    if (err) res.status(404).send('Introuvable');
  });
});

// 🆕 Panneau admin : on sert la coquille HTML (aucune donnée dedans tant que le login n'est pas fait)
app.get(['/admin', '/arcaney.html'], limit('web', 120, 60 * 1000), (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.sendFile(path.join(__dirname, 'arcaney.html'), (err) => {
    if (err) res.status(404).send('Introuvable');
  });
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

// Les 4 serveurs (affichés sur le site)
app.get('/api/servers', limit('servers', 120, 60 * 1000), (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json({ servers: SERVER_IDS.map(serverInfo) });
});

// Couplage
app.post('/api/pair', limit('pair-ip', 5, 10 * 60 * 1000), async (req, res) => {
  const { phone, consent, serverId } = req.body || {};

  if (consent !== true) return res.status(400).json({ error: 'Consentement requis' });
  if (typeof phone !== 'string' || !PHONE_RE.test(phone)) {
    return res.status(400).json({ error: 'Numéro invalide (9-15 chiffres)' });
  }

  let sid = null;
  if (serverId !== undefined && serverId !== null) {
    sid = Number(serverId);
    if (!Number.isInteger(sid) || !SERVER_IDS.includes(sid)) {
      return res.status(400).json({ error: 'Serveur invalide' });
    }
  }

  if (rateLimited('pair-phone', phone, 3, 10 * 60 * 1000)) {
    return res.status(429).json({ error: 'Trop de demandes pour ce numéro, réessayez plus tard' });
  }

  const existing = users[phone];

  if (existing && existing.status === 'connected') {
    return res.status(409).json({ error: 'Ce numéro est déjà couplé. Déconnectez-le d\'abord.' });
  }
  if (existing && existing.status === 'disconnect_requested') {
    return res.status(409).json({ error: 'Déconnexion en cours, réessayez dans un instant.' });
  }
  if (existing && existing.status === 'pending') {
    // Code déjà généré : seul le propriétaire de la demande (jeton) peut le revoir
    if (existing.code && userTokenValid(req, existing)) {
      return res.json({
        success: true, code: existing.code, phone, status: 'pending', serverId: existing.serverId,
        message: 'Code déjà généré, entrez-le dans WhatsApp'
      });
    }
    return res.status(409).json({ error: 'Une demande est déjà en cours pour ce numéro.' });
  }
  if (hasPendingRequest(phone)) {
    return res.status(409).json({ error: 'Une demande est déjà en cours pour ce numéro.' });
  }

  // Choix / vérification du serveur
  let target;
  if (sid === null) {
    target = pickServer();
    if (!target) return res.status(503).json({ error: 'Aucun serveur disponible pour le moment' });
  } else {
    target = serverInfo(sid);
    if (!target.online) return res.status(503).json({ error: 'Ce serveur est hors ligne' });
    if (target.current >= target.max) {
      return res.status(403).json({ error: `Limite de ${target.max} utilisateurs atteinte sur ce serveur` });
    }
  }

  // Jeton secret renvoyé UNE seule fois ; on ne stocke que son empreinte
  const token = crypto.randomBytes(32).toString('base64url');

  users[phone] = {
    phone,
    serverId: target.id,
    createdAt: Date.now(),
    status: 'pending',
    code: null,
    tokenHash: hashToken(token),
    ip: req.ip || null // 🆕 IP de la personne qui couple ce numéro (visible dans /admin)
  };
  saveUsers();

  try {
    const code = await createRequest(phone, target.id);
    if (!code) throw new Error('Aucun code retourné');

    users[phone].code = String(code);
    users[phone].status = 'pending';
    saveUsers();

    console.log(`✅ Code généré pour ${maskPhone(phone)} (serveur ${target.id})`);

    res.json({
      success: true,
      code,
      phone,
      status: 'pending',
      serverId: target.id,
      token,
      instructions: 'Ouvrez WhatsApp > Appareils liés > Lier avec un numéro'
    });
  } catch (e) {
    users[phone].status = 'error';
    users[phone].error = String(e.message).slice(0, 200);
    saveUsers();

    console.error(`❌ Erreur pour ${maskPhone(phone)}:`, e.message);
    const safe = /^Timeout/.test(e.message) || e.message === 'Limite atteinte'
      ? e.message
      : 'Impossible de générer le code, réessayez.';
    res.status(500).json({ error: safe });
  }
});

// Statut d'un utilisateur (jeton requis)
app.get('/api/status/:phone', limit('status', 60, 60 * 1000), (req, res) => {
  const { phone } = req.params;
  const user = PHONE_RE.test(phone) ? users[phone] : null;

  // Même réponse que le numéro existe ou non (anti-énumération)
  if (!user || !userTokenValid(req, user)) {
    return res.status(401).json({ error: 'Non autorisé' });
  }

  res.json({
    phone: user.phone,
    status: user.status,
    createdAt: user.createdAt,
    connectedAt: user.connectedAt || null
  });
});

// Déconnexion (jeton requis)
app.post('/api/disconnect/:phone', limit('disconnect', 10, 60 * 1000), (req, res) => {
  const { phone } = req.params;
  const user = PHONE_RE.test(phone) ? users[phone] : null;

  if (!user || !userTokenValid(req, user)) {
    return res.status(401).json({ error: 'Non autorisé' });
  }

  user.status = 'disconnect_requested';
  user.disconnectAt = Date.now();
  saveUsers();

  console.log(`🚪 Déconnexion demandée pour ${maskPhone(phone)}`);
  res.json({ success: true, message: 'Déconnexion en cours...' });
});

// 🆕 ==================== ROUTES ADMIN (protégées par login) ====================

// Connexion : identifiant + mot de passe -> jeton de session (12h, glissant)
app.post('/api/admin/login', limit('admin-login', 10, 10 * 60 * 1000), (req, res) => {
  const ip = req.ip;
  if (authLocked(ip)) return res.status(429).json({ error: 'Trop de tentatives, réessayez plus tard' });

  if (!ADMIN_PANEL_PASSWORD || ADMIN_PANEL_PASSWORD.length < 12) {
    return res.status(503).json({ error: 'Panneau admin non configuré côté serveur (ADMIN_PANEL_PASSWORD manquante).' });
  }

  const { username, password } = req.body || {};
  const okUser = typeof username === 'string' && username.length > 0 && safeEqual(username, ADMIN_PANEL_USERNAME);
  const okPass = typeof password === 'string' && password.length > 0 && safeEqual(password, ADMIN_PANEL_PASSWORD);

  if (!okUser || !okPass) {
    authFail(ip);
    console.log(`⚠️ Connexion admin refusée depuis ${ip}`);
    return res.status(401).json({ error: 'Identifiant ou mot de passe incorrect' });
  }

  const token = createAdminSession();
  console.log(`🔑 Connexion admin réussie depuis ${ip}`);
  res.json({ success: true, token, expiresIn: ADMIN_SESSION_TTL });
});

// Déconnexion : invalide le jeton côté serveur
app.post('/api/admin/logout', adminAuth, (req, res) => {
  adminSessions.delete(req.adminToken);
  res.json({ success: true });
});

// Vérifie si le jeton stocké côté navigateur est encore valide (pour rester connecté après un refresh)
app.get('/api/admin/me', adminAuth, (req, res) => {
  res.json({ success: true, username: ADMIN_PANEL_USERNAME });
});

// Liste complète des utilisateurs (téléphone, IP, dates, statut, serveur)
app.get('/api/admin/users', adminAuth, limit('admin-api', 120, 60 * 1000), (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const list = Object.values(users)
    .map(u => ({
      phone: u.phone,
      status: u.status,
      serverId: u.serverId ?? null,
      ip: u.ip || null,
      createdAt: u.createdAt || null,
      connectedAt: u.connectedAt || null,
      disconnectAt: u.disconnectAt || null,
      disconnectedAt: u.disconnectedAt || null,
      error: u.error || null
    }))
    .sort((a, b) => (b.connectedAt || b.createdAt || 0) - (a.connectedAt || a.createdAt || 0));

  res.json({ users: list, count: list.length });
});

// État détaillé des 4 serveurs (CPU/RAM/uptime/dernier ping)
app.get('/api/admin/servers', adminAuth, limit('admin-api', 120, 60 * 1000), (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const list = SERVER_IDS.map(id => {
    const info = serverInfo(id);
    const w = workers[id];
    return { ...info, uptime: w ? w.uptime : 0, lastSeen: w ? w.lastSeen : null };
  });
  res.json({ servers: list });
});

// Déconnecter un utilisateur (demande transmise au worker concerné, comme /api/disconnect mais sans jeton utilisateur)
app.post('/api/admin/users/:phone/disconnect', adminAuth, limit('admin-api', 60, 60 * 1000), (req, res) => {
  const { phone } = req.params;
  const user = PHONE_RE.test(phone) ? users[phone] : null;
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });

  user.status = 'disconnect_requested';
  user.disconnectAt = Date.now();
  saveUsers();

  console.log(`🚪 [ADMIN] Déconnexion demandée pour ${maskPhone(phone)}`);
  res.json({ success: true });
});

// Supprimer un utilisateur immédiatement (ménage forcé : n'avertit pas le worker, à utiliser après déconnexion idéalement)
app.delete('/api/admin/users/:phone', adminAuth, limit('admin-api', 60, 60 * 1000), (req, res) => {
  const { phone } = req.params;
  if (!PHONE_RE.test(phone) || !users[phone]) return res.status(404).json({ error: 'Utilisateur introuvable' });

  delete users[phone];
  saveUsers();

  console.log(`🗑️ [ADMIN] Suppression forcée: ${maskPhone(phone)}`);
  res.json({ success: true });
});

// ==================== ROUTES WORKER (protégées, par serveur) ====================
// Le worker appelle /api/worker/<SERVER_ID>/... avec x-admin-key et x-worker-id

function workerAuth(req, res, next) {
  const ip = req.ip;
  if (authLocked(ip)) return res.status(429).json({ error: 'Trop de tentatives, réessayez plus tard' });

  const id = Number(req.params.id);
  if (!Number.isInteger(id) || !SERVER_IDS.includes(id)) {
    return res.status(404).json({ error: 'Serveur inconnu' });
  }

  const key = req.headers['x-admin-key'];
  if (typeof key !== 'string' || key.length === 0 || !safeEqual(key, ADMIN_KEY)) {
    authFail(ip);
    console.log(`⚠️ Clé worker invalide depuis ${ip}`);
    return res.status(401).json({ error: 'Non autorisé' });
  }

  // Un worker ne peut agir que pour son propre serveur
  if (String(req.headers['x-worker-id']) !== String(id)) {
    return res.status(403).json({ error: 'Identifiant worker incorrect' });
  }

  req.workerId = id;
  next();
}

const workerLimit = limit('worker', 600, 60 * 1000);
app.use('/api/worker/:id', workerLimit, workerAuth);

// Le worker vérifie s'il y a des demandes pour LUI
app.get('/api/worker/:id/pending', (req, res) => {
  const requests = [];
  for (const [id, r] of pendingRequests.entries()) {
    if (r.serverId === req.workerId) requests.push({ id, phone: r.phone });
  }
  res.json(requests);
});

// Le worker renvoie le résultat
app.post('/api/worker/:id/result', (req, res) => {
  const { requestId, code, error } = req.body || {};

  if (typeof requestId === 'string' && pendingRequests.has(requestId)) {
    const r = pendingRequests.get(requestId);
    if (r.serverId !== req.workerId) return res.status(403).json({ error: 'Demande d\'un autre serveur' });

    clearTimeout(r.timeout);
    pendingRequests.delete(requestId);

    if (error) r.reject(new Error(String(error).slice(0, 200)));
    else if (typeof code === 'string' && code.length > 0 && code.length <= 32) r.resolve(code);
    else r.reject(new Error('Code invalide'));
  }

  res.json({ success: true });
});

// Le worker signale une connexion réussie
app.post('/api/worker/:id/connected', (req, res) => {
  const { phone } = req.body || {};
  if (typeof phone !== 'string' || !PHONE_RE.test(phone)) return res.status(400).json({ error: 'Numéro invalide' });

  if (!users[phone]) {
    // Session restaurée par le worker (ex: données perdues après redémarrage du serveur)
    users[phone] = { phone, serverId: req.workerId, createdAt: Date.now(), tokenHash: null };
  }
  users[phone].serverId = req.workerId;
  users[phone].status = 'connected';
  users[phone].connectedAt = Date.now();
  users[phone].code = null; // le code n'est plus utile
  saveUsers();
  console.log(`✅ ${maskPhone(phone)} connecté (serveur ${req.workerId})`);

  res.json({ success: true });
});

// Le worker signale une déconnexion
app.post('/api/worker/:id/disconnected', (req, res) => {
  const { phone } = req.body || {};
  if (typeof phone !== 'string' || !PHONE_RE.test(phone)) return res.status(400).json({ error: 'Numéro invalide' });

  if (users[phone]) {
    users[phone].status = 'disconnected';
    users[phone].disconnectedAt = Date.now();
    saveUsers();
    console.log(`⚠️ ${maskPhone(phone)} déconnecté`);
  }
  res.json({ success: true });
});

// Le worker demande quels utilisateurs (de son serveur) doivent être déconnectés
app.get('/api/worker/:id/disconnect-list', (req, res) => {
  const list = Object.keys(users).filter(p =>
    users[p].status === 'disconnect_requested' && users[p].serverId === req.workerId);
  res.json(list);
});

// Nettoyage après déconnexion
app.post('/api/worker/:id/disconnect-done', (req, res) => {
  const { phone } = req.body || {};
  if (typeof phone !== 'string' || !PHONE_RE.test(phone)) return res.status(400).json({ error: 'Numéro invalide' });

  if (users[phone]) {
    delete users[phone];
    saveUsers();
    console.log(`🗑️ Utilisateur supprimé: ${maskPhone(phone)}`);
  }
  res.json({ success: true });
});

// Statistiques envoyées par le worker toutes les 5 s (CPU, RAM, sessions)
app.post('/api/worker/:id/stats', (req, res) => {
  const { cpu, ram, uptime, users: count } = req.body || {};
  const num = (v, max) => (Number.isFinite(Number(v)) ? Math.min(max, Math.max(0, Math.round(Number(v)))) : 0);

  workers[req.workerId] = {
    cpu: num(cpu, 100),
    ram: num(ram, 100),
    uptime: num(uptime, 31536000),
    users: num(count, 1000),
    lastSeen: Date.now()
  };
  res.json({ success: true });
});

// ==================== NETTOYAGE AUTOMATIQUE ====================
setInterval(() => {
  const now = Date.now();
  let changed = false;

  for (const phone of Object.keys(users)) {
    const u = users[phone];
    // Erreurs et codes non utilisés : supprimés après 1 h (les codes WhatsApp expirent en quelques minutes)
    if ((u.status === 'error' || u.status === 'pending') && now - u.createdAt > 60 * 60 * 1000) {
      delete users[phone];
      changed = true;
      console.log(`🧹 Supprimé (${u.status}): ${maskPhone(phone)}`);
    }
  }
  if (changed) saveUsers();

  for (const [k, e] of hits) if (now > e.reset) hits.delete(k);
  for (const [ip, e] of authFails) if (now - e.first > AUTH_WINDOW && now >= e.lockUntil) authFails.delete(ip);
  for (const [token, s] of adminSessions) if (now > s.expiresAt) adminSessions.delete(token); // 🆕
}, 10 * 60 * 1000);

// ==================== ERREURS ====================
app.use((req, res) => {
  if (req.path.startsWith('/api')) return res.status(404).json({ error: 'Introuvable' });
  res.status(404).send('Introuvable');
});

app.use((err, req, res, next) => {
  if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'Contenu trop volumineux' });
  if (err instanceof SyntaxError) return res.status(400).json({ error: 'Requête invalide' });
  console.error('❌ Erreur serveur:', err && err.message);
  res.status(500).json({ error: 'Erreur interne' });
});

// ==================== DÉMARRAGE ====================
app.listen(PORT, '0.0.0.0', () => {
  console.log('════════════════════════════════════════');
  console.log(`🚀 Serveur de couplage sur le port ${PORT}`);
  console.log(`🖥️ Serveurs : ${SERVER_IDS.length} (max ${MAX_USERS_PER_SERVER} utilisateurs chacun)`);
  console.log(`🔒 Données chiffrées : ${ENCRYPTION_KEY ? 'oui' : 'non (ENCRYPTION_KEY absente)'}`);
  console.log('════════════════════════════════════════');
});

process.on('SIGTERM', () => {
  console.log('🛑 Arrêt du serveur...');
  saveUsers();
  process.exit(0);
});
