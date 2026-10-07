// server.js
// Serveur de contrôle pour bot WhatsApp - Version robuste et SÉCURISÉE (durcie)
//
// 🔐 VARIABLES D'ENVIRONNEMENT (Render → Environment) :
//   API_KEY          (obligatoire, 24+ caractères)  clé utilisée par le BOT (header x-api-key / socket auth)
//   ADMIN_PASSWORD   (obligatoire, 12+ caractères)  mot de passe de l'administrateur
//   ADMIN_USER       (optionnel, défaut "admin")    identifiant administrateur
//   SESSION_SECRET   (recommandé, 32+ caractères)   signe les cookies de session admin
//   ALLOWED_ORIGINS  (optionnel) ex: https://last-judment.onrender.com,https://mon-site.com
//
// 👤 Connexion administrateur : https://TON-DOMAINE/admin/login

const express = require('express');
const http = require('http');
const crypto = require('crypto');
const { Server } = require('socket.io');
const path = require('path');

// ==================== CONFIGURATION ====================
const PORT = process.env.PORT || 3000;
const STATIC_FOLDER = 'public';
const BOT_HEARTBEAT_TIMEOUT = 90 * 1000;

// 🔐 Plus AUCUN secret dans le code : tout vient de l'environnement
const API_KEY = process.env.API_KEY || '';
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map(s => s.trim().replace(/\/$/, '')).filter(Boolean);
const SESSION_TTL = 8 * 60 * 60 * 1000; // 8 heures
const COOKIE_NAME = 'hx_admin';

if (API_KEY.length < 24) {
  console.error('❌ API_KEY manquante ou trop courte (min 24 caractères). Définis-la dans les variables d\'environnement.');
  process.exit(1);
}
if (ADMIN_PASSWORD.length < 12) {
  console.error('❌ ADMIN_PASSWORD manquant ou trop court (min 12 caractères). Définis-le dans les variables d\'environnement.');
  process.exit(1);
}
if (!process.env.SESSION_SECRET) {
  console.warn('⚠️ SESSION_SECRET non défini : les sessions admin seront perdues à chaque redémarrage.');
}

// ==================== OUTILS DE SÉCURITÉ ====================
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
function safeEqual(a, b) {
  return crypto.timingSafeEqual(sha(a), sha(b));
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  header.split(';').forEach(part => {
    const i = part.indexOf('=');
    if (i < 0) return;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    try { out[k] = decodeURIComponent(v); } catch { out[k] = v; }
  });
  return out;
}

// --- Sessions admin (cookie signé HMAC + révocation côté serveur) ---
const sessions = new Map(); // sid -> expiration

function sign(data) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('base64url');
}
function createSession() {
  const sid = crypto.randomBytes(24).toString('base64url');
  const exp = Date.now() + SESSION_TTL;
  sessions.set(sid, exp);
  const payload = Buffer.from(JSON.stringify({ sid, exp })).toString('base64url');
  return payload + '.' + sign(payload);
}
function verifySession(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payload, sig] = parts;
  const a = Buffer.from(sig);
  const b = Buffer.from(sign(payload));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const { sid, exp } = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (!sessions.has(sid) || Date.now() > exp) return null;
    return sid;
  } catch {
    return null;
  }
}

// Retourne { role: 'key' } (bot / clé API), { role: 'admin' } (cookie) ou null
function getAuth(req) {
  const key = req.headers['x-api-key'];
  if (typeof key === 'string' && key.length > 0 && safeEqual(key, API_KEY)) return { role: 'key' };
  const sid = verifySession(parseCookies(req.headers.cookie)[COOKIE_NAME]);
  if (sid) return { role: 'admin', sid };
  return null;
}

function originAllowed(origin, host) {
  if (!origin || typeof origin !== 'string') return false;
  const o = origin.replace(/\/$/, '');
  if (ALLOWED_ORIGINS.includes(o)) return true;
  return o === 'https://' + host || o === 'http://' + host;
}

// --- Limiteurs ---
const hits = new Map(); // "bucket:ip" -> { count, reset }
function rateLimited(bucket, ip, max, windowMs) {
  const k = bucket + ':' + ip;
  const now = Date.now();
  let e = hits.get(k);
  if (!e || now > e.reset) {
    e = { count: 0, reset: now + windowMs };
    hits.set(k, e);
  }
  e.count++;
  return e.count > max;
}

function createLimiter({ max, windowMs, lockMs }) {
  const m = new Map();
  return {
    locked(ip) {
      const e = m.get(ip);
      return !!(e && e.lockUntil && Date.now() < e.lockUntil);
    },
    fail(ip) {
      const now = Date.now();
      let e = m.get(ip);
      if (!e || now - e.first > windowMs) {
        e = { count: 0, first: now, lockUntil: 0 };
        m.set(ip, e);
      }
      e.count++;
      if (e.count >= max) e.lockUntil = now + lockMs;
    },
    reset(ip) { m.delete(ip); },
    sweep() {
      const now = Date.now();
      for (const [ip, e] of m) {
        if (now - e.first > windowMs && now >= e.lockUntil) m.delete(ip);
      }
    }
  };
}
const loginLimiter = createLimiter({ max: 5, windowMs: 15 * 60 * 1000, lockMs: 15 * 60 * 1000 });
const authFailLimiter = createLimiter({ max: 10, windowMs: 10 * 60 * 1000, lockMs: 15 * 60 * 1000 });

// --- Validation d'entrées ---
const isStr = (v, max = 4096) => typeof v === 'string' && v.length > 0 && v.length <= max;

// ==================== INITIALISATION ====================
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1); // Render est derrière un proxy (IP réelle + HTTPS)
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: ALLOWED_ORIGINS.length ? ALLOWED_ORIGINS : false,
    methods: ['GET', 'POST'],
    credentials: true
  },
  maxHttpBufferSize: 1e8
});

// ==================== EN-TÊTES DE SÉCURITÉ ====================
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  if (req.secure) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  const connectExtra = ALLOWED_ORIGINS.join(' ');
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://cdn.socket.io",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com",
    "font-src 'self' data: https://fonts.gstatic.com",
    "img-src 'self' data: blob: https:",
    "media-src 'self' data: blob:",
    `connect-src 'self' ws: wss: ${connectExtra}`.trim(),
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'"
  ].join('; '));
  next();
});

// Limite globale par IP sur les pages web
app.use((req, res, next) => {
  if (req.path.startsWith('/api')) return next();
  if (rateLimited('web', req.ip, 300, 60 * 1000)) {
    return res.status(429).send('Trop de requêtes');
  }
  next();
});

// ==================== ADMINISTRATION (LOGIN PAR COOKIE) ====================
function loginPage(msg) {
  return `<!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex,nofollow"><title>Connexion administrateur</title>
<style>
*{box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#080a10;color:#e2e8f0;padding:20px}
.box{width:100%;max-width:380px;background:#0f131a;border:1px solid #1e2532;border-radius:14px;padding:28px;display:flex;flex-direction:column;gap:14px}
h1{font-size:1.2rem;color:#00c8ff}
input{width:100%;padding:13px;background:#080a10;border:1px solid #1e2532;border-radius:8px;color:#e2e8f0;font-size:.95rem}
input:focus{outline:none;border-color:#00c8ff}
button{padding:14px;border:none;border-radius:8px;font-weight:700;color:#fff;cursor:pointer;background:linear-gradient(135deg,#00c8ff,#7b2ff7)}
.err{color:#ff006e;background:rgba(255,0,110,.1);border:1px solid #ff006e;border-radius:6px;padding:10px;font-size:.85rem}
</style></head><body>
<form class="box" method="POST" action="/admin/login" autocomplete="off">
<h1>🔐 Connexion administrateur</h1>
${msg ? `<div class="err">${msg}</div>` : ''}
<input type="text" name="username" placeholder="Identifiant" required autocomplete="username" maxlength="64">
<input type="password" name="password" placeholder="Mot de passe" required autocomplete="current-password" maxlength="128">
<button type="submit">Se connecter</button>
</form></body></html>`;
}

function setSessionCookie(req, res, token) {
  const secure = req.secure ? '; Secure' : '';
  res.setHeader('Set-Cookie',
    `${COOKIE_NAME}=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL / 1000}${secure}`);
}
function clearSessionCookie(req, res) {
  const secure = req.secure ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure}`);
}

app.get('/admin', (req, res) => {
  const auth = getAuth(req);
  res.redirect(auth ? `/${STATIC_FOLDER}/dashboard.html` : '/admin/login');
});

app.get('/admin/login', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (getAuth(req)) return res.redirect(`/${STATIC_FOLDER}/dashboard.html`);
  res.type('html').send(loginPage(''));
});

app.post('/admin/login', express.urlencoded({ extended: false, limit: '2kb' }), async (req, res) => {
  const ip = req.ip;
  res.setHeader('Cache-Control', 'no-store');
  if (loginLimiter.locked(ip)) {
    return res.status(429).type('html').send(loginPage('Trop de tentatives. Réessayez dans 15 minutes.'));
  }
  const origin = req.headers.origin;
  if (origin && !originAllowed(origin, req.headers.host)) {
    return res.status(403).send('Interdit');
  }

  const { username, password } = req.body || {};
  const okUser = typeof username === 'string' && safeEqual(username, ADMIN_USER);
  const okPass = typeof password === 'string' && safeEqual(password, ADMIN_PASSWORD);

  if (okUser && okPass) {
    loginLimiter.reset(ip);
    setSessionCookie(req, res, createSession());
    console.log(`🔐 Connexion admin réussie depuis ${ip}`);
    return res.redirect(`/${STATIC_FOLDER}/dashboard.html`);
  }

  loginLimiter.fail(ip);
  console.log(`⚠️ Échec de connexion admin depuis ${ip}`);
  await new Promise(r => setTimeout(r, 700)); // ralentit le brute force
  res.status(401).type('html').send(loginPage('Identifiants incorrects.'));
});

app.post('/admin/logout', (req, res) => {
  const origin = req.headers.origin;
  if (origin && !originAllowed(origin, req.headers.host)) return res.status(403).send('Interdit');
  const sid = verifySession(parseCookies(req.headers.cookie)[COOKIE_NAME]);
  if (sid) sessions.delete(sid);
  clearSessionCookie(req, res);
  res.redirect('/admin/login');
});

app.get('/admin/session', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json({ authenticated: !!getAuth(req) });
});

// ==================== PROTECTION DU DASHBOARD ====================
// Le dashboard n'est accessible qu'à l'administrateur connecté.
app.use((req, res, next) => {
  let p = req.path;
  try { p = decodeURIComponent(p); } catch { return res.status(400).send('Requête invalide'); }
  if (/(^|\/)dashboard(\.html)?\/?$/i.test(p)) {
    res.setHeader('Cache-Control', 'no-store');
    if (!getAuth(req)) return res.redirect('/admin/login');
  }
  next();
});

// ==================== MIDDLEWARES ====================
app.use(express.static(path.join(__dirname, STATIC_FOLDER), { dotfiles: 'deny' }));

// 🔑 Authentification de l'API AVANT de lire le corps (anti-DoS), puis lecture du corps
app.use('/api', (req, res, next) => {
  const ip = req.ip;
  if (authFailLimiter.locked(ip)) {
    return res.status(429).json({ error: 'Trop de tentatives, réessayez plus tard' });
  }

  const auth = getAuth(req);
  if (!auth) {
    authFailLimiter.fail(ip);
    console.log(`⚠️ Accès refusé depuis ${ip} sur /api${req.path}`);
    return res.status(401).json({ error: 'Non autorisé' });
  }

  if (auth.role === 'admin') {
    // L'admin (cookie) ne peut pas utiliser les routes réservées au bot
    if (req.path.startsWith('/bot/')) {
      return res.status(403).json({ error: 'Interdit' });
    }
    // Protection CSRF : les requêtes qui modifient doivent venir de notre propre site
    if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method) && !originAllowed(req.headers.origin, req.headers.host)) {
      return res.status(403).json({ error: 'Origine non autorisée' });
    }
  }

  if (rateLimited('api', ip, auth.role === 'key' ? 6000 : 600, 60 * 1000)) {
    return res.status(429).json({ error: 'Trop de requêtes' });
  }

  req.auth = auth;
  next();
}, express.json({ limit: '50mb' }), express.urlencoded({ extended: true, limit: '50mb' }));

// ==================== STOCKAGE ====================
const dataStore = {
  messages: [],
  contacts: [],
  groups: [],
  statuses: [],
  botStatus: 'deconnecte',
  lastPing: null,
  botSocketId: null,
  startedAt: Date.now()
};

const MAX_MESSAGES = 500;
const viewOnceStore = [];
const MAX_VIEW_ONCE = 50;
const pendingRequests = new Map();

// ==================== HELPERS ====================
function normalizeGroups(body) {
  if (!body) return [];
  if (Array.isArray(body)) return body;
  if (Array.isArray(body.groups)) return body.groups;
  return [];
}

// ==================== ROUTES DE BASE ====================
app.get('/', (req, res) => {
  res.redirect(`/${STATIC_FOLDER}/dashboard.html`);
});

// Compatibilité : l'URL /public/dashboard.html (déjà protégée par le contrôle d'accès plus haut)
app.get(`/${STATIC_FOLDER}/dashboard.html`, (req, res, next) => {
  res.sendFile(path.join(__dirname, STATIC_FOLDER, 'dashboard.html'), (err) => {
    if (err) next();
  });
});

app.get('/health', (req, res) => {
  // Public : infos minimales. Détails uniquement pour le bot / l'admin.
  if (!getAuth(req)) return res.json({ status: 'ok' });
  res.json({
    status: 'ok',
    botStatus: dataStore.botStatus,
    uptime: Math.floor((Date.now() - dataStore.startedAt) / 1000),
    messagesCount: dataStore.messages.length,
    groupsCount: dataStore.groups.length,
    viewOnceCount: viewOnceStore.length,
    lastPingAgo: dataStore.lastPing ? Math.round((Date.now() - dataStore.lastPing) / 1000) + 's' : null
  });
});

// ==================== API BOT ====================

app.post('/api/bot/message', (req, res) => {
  try {
    const message = req.body;
    if (!message || !message.from) return res.status(400).json({ error: 'Message invalide' });
    
    dataStore.messages.push({ ...message, receivedAt: Date.now() });
    if (dataStore.messages.length > MAX_MESSAGES) {
      dataStore.messages = dataStore.messages.slice(-MAX_MESSAGES);
    }
    
    console.log(`📩 Message reçu de ${message.from}`);
    io.emit('new-message', message);
    res.json({ success: true });
  } catch (e) {
    console.error('❌ Erreur /api/bot/message:', e.message);
    res.status(500).json({ error: 'Erreur interne' });
  }
});

app.post('/api/bot/contacts', (req, res) => {
  try {
    const body = req.body;
    dataStore.contacts = Array.isArray(body) ? body : (body.contacts || []);
    console.log(`👥 ${dataStore.contacts.length} contacts reçus`);
    io.emit('contacts-update', dataStore.contacts);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Erreur interne' });
  }
});

app.post('/api/bot/groups', (req, res) => {
  try {
    const groups = normalizeGroups(req.body);
    console.log(`📋 Réception groupes : ${groups.length} (depuis ${req.ip})`);
    
    if (!groups.length) {
      console.warn('⚠️ Aucun groupe dans le body reçu.');
      return res.status(400).json({ error: 'Aucun groupe fourni' });
    }
    
    // Stats admin pour les logs
    const admins = groups.filter(g => g.isAdmin).length;
    console.log(`📊 dont ${admins} où je suis admin`);
    
    dataStore.groups = groups;
    
    if (dataStore.botStatus !== 'connecte') {
      dataStore.botStatus = 'connecte';
      io.emit('bot-status', 'connecte');
      console.log('🤖 Bot marqué connecté (via /api/bot/groups)');
    }
    dataStore.lastPing = Date.now();
    
    io.emit('groups-update', dataStore.groups);
    res.json({ success: true, count: groups.length, admins });
  } catch (e) {
    console.error('❌ Erreur /api/bot/groups:', e.message);
    res.status(500).json({ error: 'Erreur interne' });
  }
});

app.post('/api/bot/status', (req, res) => {
  try {
    const body = req.body;
    let status;
    if (typeof body === 'string') status = body;
    else if (body && typeof body.status === 'string') status = body.status;
    else status = 'inconnu';
    status = status.slice(0, 50);
    
    dataStore.botStatus = status;
    dataStore.lastPing = Date.now();
    io.emit('bot-status', status);
    console.log(`🤖 Statut bot mis à jour : ${status}`);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Erreur interne' });
  }
});

// ==================== VUES UNIQUES ====================

app.post('/api/bot/viewonce', (req, res) => {
  try {
    const data = req.body;
    if (!data || !data.buffer) return res.status(400).json({ error: 'Données manquantes' });
    
    const viewOnce = {
      id: Date.now() + '_' + crypto.randomBytes(6).toString('hex'),
      type: data.type || 'image',
      buffer: data.buffer,
      caption: data.caption || '',
      from: data.from || 'Inconnu',
      sender: data.sender || 'Inconnu',
      time: data.time || Date.now(),
      receivedAt: Date.now()
    };
    
    viewOnceStore.push(viewOnce);
    if (viewOnceStore.length > MAX_VIEW_ONCE) viewOnceStore.shift();
    
    console.log(`📸 Vue unique reçue (${viewOnce.type}) de ${viewOnce.sender}`);
    io.emit('new-viewonce', {
      id: viewOnce.id, type: viewOnce.type, caption: viewOnce.caption,
      sender: viewOnce.sender, from: viewOnce.from, time: viewOnce.time
    });
    
    res.json({ success: true, id: viewOnce.id });
  } catch (e) {
    console.error('❌ Erreur /api/bot/viewonce:', e.message);
    res.status(500).json({ error: 'Erreur interne' });
  }
});

app.get('/api/viewonce/list', (req, res) => {
  res.json(viewOnceStore.map(v => ({
    id: v.id, type: v.type, caption: v.caption,
    sender: v.sender, from: v.from, time: v.time
  })));
});

app.get('/api/viewonce/:id', (req, res) => {
  const vo = viewOnceStore.find(v => v.id === req.params.id);
  if (!vo) return res.status(404).json({ error: 'Vue unique non trouvée' });
  res.json(vo);
});

// ==================== API DASHBOARD ====================

app.get('/api/data', (req, res) => {
  res.json({
    messages: dataStore.messages.slice(-50),
    contacts: dataStore.contacts,
    groups: dataStore.groups,
    botStatus: dataStore.botStatus,
    lastPing: dataStore.lastPing,
    uptime: Math.floor((Date.now() - dataStore.startedAt) / 1000),
    viewOnce: viewOnceStore.map(v => ({
      id: v.id, type: v.type, caption: v.caption, sender: v.sender, time: v.time
    }))
  });
});

app.post('/api/send/message', (req, res) => {
  const { to, text } = req.body || {};
  if (!isStr(to, 100) || !isStr(text, 4096)) return res.status(400).json({ error: 'Paramètres manquants' });
  io.emit('bot-command', { action: 'send-message', to, text });
  console.log(`📤 Commande : message à ${to}`);
  res.json({ success: true });
});

app.post('/api/join/group', (req, res) => {
  const { inviteCode } = req.body || {};
  if (!isStr(inviteCode, 300)) return res.status(400).json({ error: 'Code manquant' });
  io.emit('bot-command', { action: 'join-group', inviteCode });
  res.json({ success: true });
});

app.post('/api/leave/group', (req, res) => {
  const { groupId } = req.body || {};
  if (!isStr(groupId, 100)) return res.status(400).json({ error: 'groupId manquant' });
  io.emit('bot-command', { action: 'leave-group', groupId });
  res.json({ success: true });
});

app.post('/api/join/channel', (req, res) => {
  const { channelLink } = req.body || {};
  if (!isStr(channelLink, 300)) return res.status(400).json({ error: 'Lien manquant' });
  io.emit('bot-command', { action: 'join-channel', channelLink });
  res.json({ success: true });
});

app.post('/api/send/group', (req, res) => {
  const { groupId, text } = req.body || {};
  if (!isStr(groupId, 100) || !isStr(text, 4096)) return res.status(400).json({ error: 'Paramètres manquants' });
  io.emit('bot-command', { action: 'send-group-message', groupId, text });
  res.json({ success: true });
});

app.post('/api/clear/messages', (req, res) => {
  dataStore.messages = [];
  io.emit('messages-cleared');
  res.json({ success: true });
});

// ==================== GESTION GROUPES ====================

app.post('/api/group/create', (req, res) => {
  const { name, members } = req.body || {};
  if (!isStr(name, 100) || !members || !Array.isArray(members) || members.length === 0
      || members.length > 1024 || !members.every(m => isStr(m, 64))) {
    return res.status(400).json({ error: 'Nom et membres requis' });
  }
  io.emit('bot-command', { action: 'create-group', name, members });
  console.log(`📤 Commande : créer groupe "${name}"`);
  res.json({ success: true });
});

app.post('/api/group/add', (req, res) => {
  const { groupId, number } = req.body || {};
  if (!isStr(groupId, 100) || !isStr(String(number || ''), 64)) return res.status(400).json({ error: 'Paramètres manquants' });
  io.emit('bot-command', { action: 'add-member', groupId, number });
  res.json({ success: true });
});

app.post('/api/group/promote', (req, res) => {
  const { groupId, number } = req.body || {};
  if (!isStr(groupId, 100) || !isStr(String(number || ''), 64)) return res.status(400).json({ error: 'Paramètres manquants' });
  io.emit('bot-command', { action: 'promote-admin', groupId, number });
  res.json({ success: true });
});

app.post('/api/group/demote', (req, res) => {
  const { groupId, number } = req.body || {};
  if (!isStr(groupId, 100) || !isStr(String(number || ''), 64)) return res.status(400).json({ error: 'Paramètres manquants' });
  io.emit('bot-command', { action: 'demote-admin', groupId, number });
  res.json({ success: true });
});

app.post('/api/group/kick', (req, res) => {
  const { groupId, number } = req.body || {};
  if (!isStr(groupId, 100) || !isStr(String(number || ''), 64)) return res.status(400).json({ error: 'Paramètres manquants' });
  io.emit('bot-command', { action: 'kick-member', groupId, number });
  res.json({ success: true });
});

// ==================== ACTIONS GLOBALES ====================

app.post('/api/group/add-all', (req, res) => {
  const { number } = req.body || {};
  if (!isStr(String(number || ''), 64)) return res.status(400).json({ error: 'Numéro manquant' });
  
  const taskId = 'task_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex');
  io.emit('bot-command', { action: 'add-member-all-groups', number, taskId });
  console.log(`📤 GLOBAL [${taskId}] : ajouter ${number}`);
  res.json({ success: true, taskId });
});

app.post('/api/group/promote-all', (req, res) => {
  const { number } = req.body || {};
  if (!isStr(String(number || ''), 64)) return res.status(400).json({ error: 'Numéro manquant' });
  
  const taskId = 'task_' + Date.now() + '_' + crypto.randomBytes(4).toString('hex');
  io.emit('bot-command', { action: 'promote-admin-all-groups', number, taskId });
  console.log(`📤 GLOBAL [${taskId}] : promouvoir ${number}`);
  res.json({ success: true, taskId });
});

// ==================== STATUTS ====================

app.post('/api/status/post', (req, res) => {
  const { type, text, buffer, mimetype, caption } = req.body || {};
  if (!isStr(type, 30)) return res.status(400).json({ error: 'Type manquant' });
  if ((text && typeof text !== 'string') || (caption && typeof caption !== 'string')
      || (buffer && typeof buffer !== 'string') || (mimetype && typeof mimetype !== 'string')) {
    return res.status(400).json({ error: 'Paramètres invalides' });
  }
  io.emit('bot-command', {
    action: 'post-status', type, text: text || '',
    buffer: buffer || null, mimetype: mimetype || null, caption: caption || ''
  });
  console.log(`📤 Commande : publier statut (${type})`);
  res.json({ success: true });
});

// ==================== CHAÎNES ====================

app.post('/api/channel/broadcast', (req, res) => {
  const { channelLink, text } = req.body || {};
  if (!isStr(channelLink, 300) || !isStr(text, 4096)) return res.status(400).json({ error: 'Paramètres manquants' });
  io.emit('bot-command', { action: 'broadcast-channel', channelLink, text });
  res.json({ success: true });
});

// ==================== GESTION DES ERREURS ====================
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

// ==================== WEBSOCKET ====================

function socketIp(handshake) {
  const xff = handshake.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length) return xff.split(',')[0].trim();
  return handshake.address;
}

io.use((socket, next) => {
  const ip = socketIp(socket.handshake);
  if (authFailLimiter.locked(ip)) return next(new Error('Non autorisé'));

  // 1) Le BOT : clé API (secret serveur-à-serveur)
  const apiKey = socket.handshake.auth && socket.handshake.auth.apiKey;
  if (typeof apiKey === 'string' && apiKey.length > 0 && safeEqual(apiKey, API_KEY)) {
    socket.data.role = 'key';
    return next();
  }

  // 2) Le DASHBOARD : session admin (cookie) + origine du site vérifiée
  const sid = verifySession(parseCookies(socket.handshake.headers.cookie)[COOKIE_NAME]);
  const origin = socket.handshake.headers.origin;
  if (sid && origin && originAllowed(origin, socket.handshake.headers.host)) {
    socket.data.role = 'admin';
    return next();
  }

  authFailLimiter.fail(ip);
  console.log(`⚠️ Connexion Socket.io refusée depuis ${ip}`);
  next(new Error('Non autorisé'));
});

io.on('connection', (socket) => {
  console.log(`🖥️ Client connecté : ${socket.id} (${socket.data.role})`);
  const isBot = () => socket.data.role === 'key'; // seuls les clients avec la clé API peuvent piloter l'état du bot
  
  socket.emit('init', {
    messages: dataStore.messages.slice(-50),
    contacts: dataStore.contacts,
    groups: dataStore.groups,
    botStatus: dataStore.botStatus,
    viewOnce: viewOnceStore.map(v => ({
      id: v.id, type: v.type, caption: v.caption, sender: v.sender, time: v.time
    }))
  });
  
  socket.on('bot-register', () => {
    if (!isBot()) return;
    dataStore.botSocketId = socket.id;
    dataStore.botStatus = 'connecte';
    dataStore.lastPing = Date.now();
    io.emit('bot-status', 'connecte');
    console.log(`🤖 Bot enregistré (socket ${socket.id})`);
  });
  
  socket.on('bot-heartbeat', () => {
    if (!isBot()) return;
    dataStore.lastPing = Date.now();
    if (dataStore.botStatus !== 'connecte') {
      dataStore.botStatus = 'connecte';
      dataStore.botSocketId = socket.id;
      io.emit('bot-status', 'connecte');
      console.log('🤖 Bot reconnecté (heartbeat)');
    }
  });
  
  socket.on('bulk-progress', (data) => {
    if (!isBot() || !data || typeof data !== 'object') return;
    console.log(`📊 Progression [${data.taskId}] ${data.current}/${data.total} - ${data.groupName || ''} ${data.success ? '✅' : '❌'}`);
    io.emit('bulk-progress', data);
  });

  socket.on('bulk-done', (data) => {
    if (!isBot() || !data || typeof data !== 'object') return;
    console.log(`✅ Terminé [${data.taskId}] : ${data.ok} succès, ${data.fail} échecs`);
    io.emit('bulk-done', data);
  });
  
  socket.on('bot-response', (data) => {
    if (!isBot() || !data || typeof data !== 'object') return;
    console.log('📬 Réponse bot reçue');
    const { requestId, success, message } = data;
    if (requestId && pendingRequests.has(requestId)) {
      const cb = pendingRequests.get(requestId);
      cb({ success, message });
      pendingRequests.delete(requestId);
    }
    io.emit('bot-response', data);
  });
  
  socket.on('bot-groups', (groups) => {
    if (!isBot()) return;
    const list = Array.isArray(groups) ? groups : (groups?.groups || []);
    if (!list.length) return;
    
    dataStore.groups = list;
    dataStore.lastPing = Date.now();
    
    if (dataStore.botStatus !== 'connecte') {
      dataStore.botStatus = 'connecte';
      dataStore.botSocketId = socket.id;
      io.emit('bot-status', 'connecte');
    }
    
    io.emit('groups-update', dataStore.groups);
    console.log(`📋 ${list.length} groupes via Socket.IO`);
  });
  
  socket.on('disconnect', () => {
    console.log(`🖥️ Client déconnecté : ${socket.id}`);
    if (socket.id === dataStore.botSocketId) {
      dataStore.botSocketId = null;
      dataStore.botStatus = 'deconnecte';
      io.emit('bot-status', 'deconnecte');
      console.log('🔴 Bot déconnecté (socket fermée)');
    }
  });
});

// ==================== TIMEOUT BOT ====================
setInterval(() => {
  if (dataStore.botStatus === 'connecte' && dataStore.lastPing) {
    const elapsed = Date.now() - dataStore.lastPing;
    if (elapsed > BOT_HEARTBEAT_TIMEOUT) {
      console.log(`⏱️ Bot inactif ${Math.round(elapsed / 1000)}s → déconnecté`);
      dataStore.botStatus = 'deconnecte';
      dataStore.botSocketId = null;
      io.emit('bot-status', 'deconnecte');
    }
  }
}, 15000);

// ==================== NETTOYAGE VUES UNIQUES ====================
setInterval(() => {
  const now = Date.now();
  const before = viewOnceStore.length;
  for (let i = viewOnceStore.length - 1; i >= 0; i--) {
    if (now - viewOnceStore[i].receivedAt > 24 * 60 * 60 * 1000) viewOnceStore.splice(i, 1);
  }
  const after = viewOnceStore.length;
  if (before !== after) console.log(`🧹 ${before - after} vue(s) nettoyée(s)`);
}, 60 * 60 * 1000);

// ==================== NETTOYAGE SÉCURITÉ (sessions, limiteurs) ====================
setInterval(() => {
  const now = Date.now();
  for (const [sid, exp] of sessions) if (now > exp) sessions.delete(sid);
  for (const [k, e] of hits) if (now > e.reset) hits.delete(k);
  loginLimiter.sweep();
  authFailLimiter.sweep();
}, 10 * 60 * 1000);

// ==================== DÉMARRAGE ====================
server.listen(PORT, '0.0.0.0', () => {
  console.log('════════════════════════════════════════════');
  console.log(`🚀 Serveur démarré sur le port ${PORT}`);
  console.log(`🔐 Connexion admin : /admin/login`);
  console.log(`📊 Dashboard : /${STATIC_FOLDER}/dashboard.html (réservé à l'administrateur)`);
  console.log(`⏱️ Timeout heartbeat : ${BOT_HEARTBEAT_TIMEOUT / 1000}s`);
  console.log('════════════════════════════════════════════');
});

process.on('SIGTERM', () => {
  console.log('🛑 Arrêt du serveur...');
  server.close(() => process.exit(0));
});
