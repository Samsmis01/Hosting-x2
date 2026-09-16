// server.js
// Serveur maître HEXTECH - Gère 4 workers KataBump
// 🔒 SÉCURISÉ : rate-limit + IP logging + API key + CORS strict

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ==================== CONFIGURATION ====================
const MAX_USERS_PER_SERVER = 14;
const USERS_FILE = './users.json';
const IP_LOGS_FILE = './ip_logs.json';
const BLACKLIST_FILE = './blacklist.json';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
const ADMIN_KEY = process.env.ADMIN_KEY || 'xenoban-admin-2026';

// 🔒 NOUVELLES VARIABLES DE SÉCURITÉ
const API_KEY = process.env.HEXTECH_SECRET_KEY || 'change-moi-en-prod-2026';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '*').split(',').map(s => s.trim());
const TRUST_PROXY = process.env.TRUST_PROXY === 'true' || true; // Render + Cloudflare

// 🔒 CONFIGURATION RATE-LIMIT
const RATE_LIMIT = {
  global: { windowMs: 60 * 1000, max: 120 },      // 120 req/min par IP (tous endpoints)
  pair:   { windowMs: 60 * 1000, max: 3 },        // 3 tentatives de couplage/min par IP
  status: { windowMs: 60 * 1000, max: 30 },       // 30 vérifications/min par IP
  disconnect: { windowMs: 60 * 1000, max: 5 }     // 5 déconnexions/min par IP
};

// 🔒 BAN AUTOMATIQUE
const BAN_CONFIG = {
  maxViolations: 5,          // 5 dépassements avant ban
  banDurationMs: 24 * 60 * 60 * 1000, // Ban 24h
  violationWindowMs: 10 * 60 * 1000   // Fenêtre de 10 min
};

// ==================== CONFIGURATION DES 4 SERVEURS ====================
// ⚠️ Les URLs doivent correspondre à tes 4 workers déployés
const SERVERS = [
  {
    id: 1,
    name: 'Serveur 1 - Web',
    url: process.env.SERVER_1_URL || 'https://last-judment.onrender.com',
    lastPing: 0,
    online: false,
    cpu: 0,
    ram: 0,
    uptime: 0
  },
  {
    id: 2,
    name: 'Serveur 2 - Database',
    url: process.env.SERVER_2_URL || '',
    lastPing: 0,
    online: false,
    cpu: 0,
    ram: 0,
    uptime: 0
  },
  {
    id: 3,
    name: 'Serveur 3 - Game',
    url: process.env.SERVER_3_URL || '',
    lastPing: 0,
    online: false,
    cpu: 0,
    ram: 0,
    uptime: 0
  },
  {
    id: 4,
    name: 'Serveur 4 - App',
    url: process.env.SERVER_4_URL || '',
    lastPing: 0,
    online: false,
    cpu: 0,
    ram: 0,
    uptime: 0
  }
];

// ==================== 🔒 TRUST PROXY ====================
// Important derrière Cloudflare/Render pour récupérer la vraie IP client
if (TRUST_PROXY) {
  app.set('trust proxy', 1);
}

// ==================== 🔒 HELPER : RÉCUPÉRER LA VRAIE IP ====================
function getClientIP(req) {
  // Cloudflare envoie l'IP dans CF-Connecting-IP
  const cfIP = req.headers['cf-connecting-ip'];
  if (cfIP) return cfIP;
  
  const xForwarded = req.headers['x-forwarded-for'];
  if (xForwarded) {
    return xForwarded.split(',')[0].trim();
  }
  
  const xRealIP = req.headers['x-real-ip'];
  if (xRealIP) return xRealIP;
  
  return req.ip || req.connection?.remoteAddress || 'unknown';
}

// ==================== 🔒 GESTION DES FICHIERS DE LOG ====================
function loadJSON(file, defaultValue = {}) {
  try {
    if (fs.existsSync(file)) {
      return JSON.parse(fs.readFileSync(file, 'utf8'));
    }
  } catch (e) {
    console.error(`Erreur lecture ${file}:`, e.message);
  }
  return defaultValue;
}

function saveJSON(file, data) {
  try {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
  } catch (e) {
    console.error(`Erreur sauvegarde ${file}:`, e.message);
  }
}

// ==================== 🔒 ENREGISTREMENT DES IPs ====================
const ipLogs = loadJSON(IP_LOGS_FILE, { logs: [], stats: {} });

function logIP(req, endpoint, extra = {}) {
  const ip = getClientIP(req);
  const now = Date.now();
  const ua = req.headers['user-agent'] || 'unknown';

  // Log détaillé (limité aux 5000 dernières entrées pour éviter la saturation)
  ipLogs.logs.push({
    ip,
    endpoint,
    method: req.method,
    userAgent: ua,
    timestamp: new Date(now).toISOString(),
    country: req.headers['cf-ipcountry'] || 'unknown',
    referer: req.headers['referer'] || null,
    ...extra
  });

  // Limiter la taille
  if (ipLogs.logs.length > 5000) {
    ipLogs.logs = ipLogs.logs.slice(-5000);
  }

  // Stats par IP
  if (!ipLogs.stats[ip]) {
    ipLogs.stats[ip] = {
      firstSeen: now,
      lastSeen: now,
      count: 0,
      endpoints: {},
      blocked: false,
      violations: []
    };
  }
  ipLogs.stats[ip].lastSeen = now;
  ipLogs.stats[ip].count++;
  ipLogs.stats[ip].endpoints[endpoint] = (ipLogs.stats[ip].endpoints[endpoint] || 0) + 1;

  // Sauvegarde asynchrone (toutes les 30 secondes)
  scheduleSaveIPLogs();
}

let ipLogsSaveTimer = null;
function scheduleSaveIPLogs() {
  if (ipLogsSaveTimer) return;
  ipLogsSaveTimer = setTimeout(() => {
    saveJSON(IP_LOGS_FILE, ipLogs);
    ipLogsSaveTimer = null;
  }, 30000);
}

// Force save au shutdown
process.on('SIGTERM', () => {
  try { saveJSON(IP_LOGS_FILE, ipLogs); } catch (e) {}
});

// ==================== 🔒 BLACKLIST / BAN ====================
const blacklist = loadJSON(BLACKLIST_FILE, { ips: {}, violations: {} });

function isBlacklisted(ip) {
  const entry = blacklist.ips[ip];
  if (!entry) return false;
  if (entry.bannedUntil && entry.bannedUntil > Date.now()) return true;
  // Expiré → nettoyer
  if (entry.bannedUntil && entry.bannedUntil <= Date.now()) {
    delete blacklist.ips[ip];
    saveJSON(BLACKLIST_FILE, blacklist);
  }
  return false;
}

function recordViolation(ip, reason) {
  const now = Date.now();
  if (!blacklist.violations[ip]) {
    blacklist.violations[ip] = [];
  }
  
  // Nettoyer les vieilles violations
  blacklist.violations[ip] = blacklist.violations[ip].filter(
    v => now - v.time < BAN_CONFIG.violationWindowMs
  );
  
  blacklist.violations[ip].push({ time: now, reason });
  
  // Ban si trop de violations
  if (blacklist.violations[ip].length >= BAN_CONFIG.maxViolations) {
    blacklist.ips[ip] = {
      bannedUntil: now + BAN_CONFIG.banDurationMs,
      reason: `Trop de violations: ${reason}`,
      bannedAt: now
    };
    console.warn(`🚫 IP BANNIE: ${ip} pour ${BAN_CONFIG.banDurationMs / 1000 / 60} minutes`);
    saveJSON(BLACKLIST_FILE, blacklist);
  }
}

// ==================== 🔒 RATE-LIMIT CUSTOM ====================
const rateLimitStore = new Map();

function rateLimit(config, endpointName) {
  return (req, res, next) => {
    const ip = getClientIP(req);

    // Vérifier blacklist
    if (isBlacklisted(ip)) {
      return res.status(403).json({ error: 'Accès refusé (IP bannie)' });
    }

    const key = `${ip}:${endpointName}`;
    const now = Date.now();
    const entry = rateLimitStore.get(key) || { count: 0, resetAt: now + config.windowMs };

    // Reset si fenêtre expirée
    if (now > entry.resetAt) {
      entry.count = 0;
      entry.resetAt = now + config.windowMs;
    }

    entry.count++;
    rateLimitStore.set(key, entry);

    // Headers standards
    res.setHeader('X-RateLimit-Limit', config.max);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, config.max - entry.count));
    res.setHeader('X-RateLimit-Reset', Math.ceil(entry.resetAt / 1000));

    if (entry.count > config.max) {
      recordViolation(ip, `rate-limit:${endpointName}`);
      console.warn(`⚠️ Rate-limit dépassé: ${ip} sur ${endpointName} (${entry.count}/${config.max})`);
      res.setHeader('Retry-After', Math.ceil((entry.resetAt - now) / 1000));
      return res.status(429).json({
        error: 'Trop de requêtes. Veuillez patienter.',
        retryAfter: Math.ceil((entry.resetAt - now) / 1000)
      });
    }

    next();
  };
}

// Nettoyer le store toutes les 5 min
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitStore.entries()) {
    if (now > entry.resetAt + 60000) rateLimitStore.delete(key);
  }
}, 5 * 60 * 1000);

// ==================== 🔒 VÉRIFICATION API KEY ====================
function requireApiKey(req, res, next) {
  const providedKey = req.headers['x-api-key'];
  if (!providedKey || providedKey !== API_KEY) {
    const ip = getClientIP(req);
    recordViolation(ip, 'invalid-api-key');
    console.warn(`🚫 API KEY invalide depuis ${ip}`);
    return res.status(401).json({ error: 'Non autorisé' });
  }
  next();
}

// ==================== 🔒 DÉTECTION USER-AGENT SUSPECT ====================
const SUSPICIOUS_UA = [
  /curl/i, /wget/i, /python/i, /python-requests/i,
  /scrapy/i, /postman/i, /insomnia/i, /httpie/i,
  /go-http-client/i, /java\//i, /okhttp/i
];

function detectSuspiciousClient(req, res, next) {
  const ua = req.headers['user-agent'] || '';
  const isSuspicious = SUSPICIOUS_UA.some(pattern => pattern.test(ua));

  if (isSuspicious && process.env.ALLOW_SUSPICIOUS_UA !== 'true') {
    const ip = getClientIP(req);
    recordViolation(ip, 'suspicious-ua');
    console.warn(`🚫 User-Agent suspect bloqué: ${ip} → ${ua}`);
    return res.status(403).json({ error: 'Accès refusé' });
  }
  next();
}

// ==================== 🔒 HEADERS DE SÉCURITÉ ====================
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.removeHeader('X-Powered-By');
  next();
});

// ==================== 🔒 CORS STRICT ====================
app.use(cors({
  origin: function (origin, callback) {
    // Autoriser si pas d'origin (requêtes server-to-server type worker)
    if (!origin) return callback(null, true);
    // Autoriser si wildcard configuré
    if (ALLOWED_ORIGINS.includes('*')) return callback(null, true);
    // Autoriser si domaine dans la liste
    if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    console.warn(`🚫 CORS bloqué pour origin: ${origin}`);
    return callback(new Error('CORS non autorisé'));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-API-KEY', 'X-ADMIN-KEY', 'CF-Turnstile-Response'],
  credentials: false,
  maxAge: 86400
}));

// ==================== 🔒 BODY PARSER ====================
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));

// ==================== 🔒 MIDDLEWARE GLOBAL : LOG + RATE-LIMIT ====================
app.use((req, res, next) => {
  // Log toutes les requêtes sauf /health
  if (req.path !== '/health' && !req.path.startsWith('/static')) {
    logIP(req, req.path);
  }
  next();
});

// Rate-limit global sur toutes les routes /api
app.use('/api', rateLimit(RATE_LIMIT.global, 'global'));

// ==================== 🔒 STATIC FILES ====================
app.use(express.static(path.join(__dirname)));

// ==================== BASE DE DONNÉES ====================
function loadUsers() {
  try {
    if (fs.existsSync(USERS_FILE)) {
      return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    }
  } catch (e) {
    console.error('Erreur lecture users:', e.message);
  }
  return {};
}

function saveUsers(users) {
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
  } catch (e) {
    console.error('Erreur sauvegarde users:', e.message);
  }
}

// ==================== QUEUE DES REQUÊTES ====================
const pendingRequests = new Map();

function createRequest(phone, serverId) {
  return new Promise((resolve, reject) => {
    const requestId = crypto.randomBytes(8).toString('hex');
    
    const timeout = setTimeout(() => {
      if (pendingRequests.has(requestId)) {
        pendingRequests.delete(requestId);
        reject(new Error('Timeout : le worker n\'a pas répondu dans les 90 secondes'));
      }
    }, 90000);
    
    pendingRequests.set(requestId, {
      phone,
      serverId,
      resolve,
      reject,
      timeout,
      createdAt: Date.now()
    });
  });
}

// ==================== ROUTE HEALTH (pas de log, pas d'auth) ====================
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    uptime: Math.floor(process.uptime()),
    ip: getClientIP(req)
  });
});

// ==================== ROUTES PUBLIQUES ====================

// Page d'accueil
app.get('/', (req, res) => {
  const users = loadUsers();
  const connectedCount = Object.values(users).filter(u => u.status === 'connected').length;
  res.json({
    status: 'ok',
    total: Object.keys(users).length,
    connected: connectedCount,
    servers: SERVERS.length,
    maxPerServer: MAX_USERS_PER_SERVER,
    uptime: Math.floor(process.uptime())
  });
});

// ==================== ROUTE : LISTE DES SERVEURS ====================
app.get('/api/servers', (req, res) => {
  const users = loadUsers();

  const serversStatus = SERVERS.map(server => {
    const current = Object.values(users).filter(u =>
      u.serverId === server.id && u.status !== 'disconnected'
    ).length;

    return {
      id: server.id,
      name: server.name,
      current: current,
      max: MAX_USERS_PER_SERVER,
      online: server.online,
      cpu: server.cpu,
      ram: server.ram,
      uptime: server.uptime
    };
  });

  res.json({ servers: serversStatus });
});

// ==================== ROUTE : PAIRING (🔒 rate-limit strict) ====================
app.post('/api/pair',
  rateLimit(RATE_LIMIT.pair, 'pair'),
  async (req, res) => {
    const { phone, consent, serverId } = req.body;
    const clientIP = getClientIP(req);

    // Validation
    if (!consent) return res.status(400).json({ error: 'Consentement requis' });
    if (!phone || !/^\d{9,15}$/.test(phone)) return res.status(400).json({ error: 'Numéro invalide (9-15 chiffres)' });

    const users = loadUsers();

    // Auto-sélection du serveur si non précisé
    let targetServerId = serverId;
    if (!targetServerId || ![1, 2, 3, 4].includes(parseInt(targetServerId))) {
      for (const srv of SERVERS) {
        const currentOnServer = Object.values(users).filter(u =>
          u.serverId === srv.id && u.status !== 'disconnected'
        ).length;
        if (srv.online && currentOnServer < MAX_USERS_PER_SERVER) {
          targetServerId = srv.id;
          break;
        }
      }
      if (!targetServerId) {
        return res.status(503).json({ error: 'Aucun serveur disponible. Réessayez plus tard.' });
      }
    }

    targetServerId = parseInt(targetServerId);
    const server = SERVERS.find(s => s.id === targetServerId);

    if (!server) return res.status(404).json({ error: 'Serveur introuvable' });
    if (!server.online) return res.status(503).json({ error: `Le ${server.name} est actuellement hors ligne` });

    // Vérifier si le serveur est plein
    const currentOnServer = Object.values(users).filter(u =>
      u.serverId === targetServerId && u.status !== 'disconnected'
    ).length;

    if (currentOnServer >= MAX_USERS_PER_SERVER) {
      return res.status(503).json({
        error: `Le ${server.name} est plein (${currentOnServer}/${MAX_USERS_PER_SERVER}). Choisissez un autre serveur.`
      });
    }

    // Vérifier si déjà couplé
    if (users[phone] && users[phone].status === 'connected') {
      return res.status(409).json({ error: 'Ce numéro est déjà couplé. Déconnectez-le d\'abord.' });
    }

    // Réutiliser le code si existant
    if (users[phone] && users[phone].status === 'pending' && users[phone].code) {
      return res.json({
        success: true,
        code: users[phone].code,
        phone: phone,
        serverId: users[phone].serverId,
        status: 'pending',
        message: 'Code déjà généré'
      });
    }

    // Créer l'utilisateur
    users[phone] = {
      phone,
      serverId: targetServerId,
      createdAt: users[phone]?.createdAt || Date.now(),
      status: 'pending',
      code: null,
      ip: clientIP,
      userAgent: req.headers['user-agent'] || 'unknown'
    };
    saveUsers(users);

    // Demander le code au worker
    try {
      const code = await createRequest(phone, targetServerId);
      if (!code) throw new Error('Aucun code retourné par le worker');

      users[phone].code = code;
      users[phone].status = 'pending';
      saveUsers(users);

      console.log(`✅ Code généré pour ${phone} sur ${server.name}: ${code} (IP: ${clientIP})`);

      res.json({
        success: true,
        code: code,
        phone: phone,
        serverId: targetServerId,
        status: 'pending',
        instructions: 'Ouvrez WhatsApp > Appareils liés > Lier avec un numéro'
      });

    } catch (e) {
      users[phone].status = 'error';
      users[phone].error = e.message;
      saveUsers(users);
      console.error(`❌ Erreur pour ${phone}:`, e.message);
      res.status(500).json({ error: e.message });
    }
  }
);

// ==================== ROUTE : STATUT (🔒 rate-limit) ====================
app.get('/api/status/:phone',
  rateLimit(RATE_LIMIT.status, 'status'),
  (req, res) => {
    const { phone } = req.params;
    const users = loadUsers();

    if (!users[phone]) return res.status(404).json({ error: 'Numéro non enregistré' });

    res.json({
      phone: users[phone].phone,
      serverId: users[phone].serverId,
      status: users[phone].status,
      createdAt: users[phone].createdAt,
      connectedAt: users[phone].connectedAt || null
    });
  }
);

// ==================== ROUTE : DÉCONNEXION (🔒 rate-limit) ====================
app.post('/api/disconnect/:phone',
  rateLimit(RATE_LIMIT.disconnect, 'disconnect'),
  (req, res) => {
    const { phone } = req.params;
    const users = loadUsers();

    if (!users[phone]) return res.status(404).json({ error: 'Numéro non enregistré' });

    users[phone].status = 'disconnect_requested';
    users[phone].disconnectAt = Date.now();
    saveUsers(users);

    console.log(`🚪 Déconnexion demandée pour ${phone} (Server ${users[phone].serverId})`);
    res.json({ success: true, message: 'Déconnexion en cours...' });
  }
);

// ==================== ROUTES WORKER (par serveur) — protégées par ADMIN_KEY ====================

// Le worker demande les requêtes en attente
app.get('/api/worker/:serverId/pending', (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) return res.status(401).json({ error: 'Non autorisé' });

  const serverId = parseInt(req.params.serverId);
  if (![1, 2, 3, 4].includes(serverId)) return res.status(400).json({ error: 'Serveur invalide' });

  // Marquer le serveur comme en ligne (il vient de nous parler)
  const server = SERVERS.find(s => s.id === serverId);
  if (server) {
    server.lastPing = Date.now();
    server.online = true;
  }

  const requests = [];
  for (const [id, req] of pendingRequests.entries()) {
    if (req.serverId === serverId) {
      requests.push({ id, phone: req.phone });
    }
  }

  res.json(requests);
});

// Le worker renvoie le résultat
app.post('/api/worker/:serverId/result', (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) return res.status(401).json({ error: 'Non autorisé' });

  const { requestId, code, error } = req.body;

  if (pendingRequests.has(requestId)) {
    const { resolve, reject, timeout } = pendingRequests.get(requestId);
    clearTimeout(timeout);
    pendingRequests.delete(requestId);
    if (error) reject(new Error(error));
    else resolve(code);
  }

  res.json({ success: true });
});

// Le worker signale une connexion
app.post('/api/worker/:serverId/connected', (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) return res.status(401).json({ error: 'Non autorisé' });

  const { phone } = req.body;
  const users = loadUsers();

  if (users[phone]) {
    users[phone].status = 'connected';
    users[phone].connectedAt = Date.now();
    saveUsers(users);
    console.log(`✅ ${phone} connecté sur Server ${req.params.serverId}`);
  }

  res.json({ success: true });
});

// Le worker signale une déconnexion
app.post('/api/worker/:serverId/disconnected', (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) return res.status(401).json({ error: 'Non autorisé' });

  const { phone } = req.body;
  const users = loadUsers();

  if (users[phone]) {
    users[phone].status = 'disconnected';
    users[phone].disconnectedAt = Date.now();
    saveUsers(users);
    console.log(`⚠️ ${phone} déconnecté du Server ${req.params.serverId}`);
  }

  res.json({ success: true });
});

// Le worker demande les déconnexions
app.get('/api/worker/:serverId/disconnect-list', (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) return res.status(401).json({ error: 'Non autorisé' });

  const serverId = parseInt(req.params.serverId);
  const users = loadUsers();

  const toDisconnect = Object.keys(users).filter(p =>
    users[p].serverId === serverId && users[p].status === 'disconnect_requested'
  );

  res.json(toDisconnect);
});

// Le worker confirme la déconnexion
app.post('/api/worker/:serverId/disconnect-done', (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) return res.status(401).json({ error: 'Non autorisé' });

  const { phone } = req.body;
  const users = loadUsers();

  if (users[phone]) {
    delete users[phone];
    saveUsers(users);
    console.log(`🗑️ Utilisateur ${phone} supprimé (Server ${req.params.serverId})`);
  }

  res.json({ success: true });
});

// Le worker envoie ses stats (CPU/RAM)
app.post('/api/worker/:serverId/stats', (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) return res.status(401).json({ error: 'Non autorisé' });

  const serverId = parseInt(req.params.serverId);
  const { cpu, ram, uptime } = req.body;
  const server = SERVERS.find(s => s.id === serverId);

  if (server) {
    server.cpu = cpu || 0;
    server.ram = ram || 0;
    server.uptime = uptime || 0;
    server.lastPing = Date.now();
    server.online = true;
  }

  res.json({ success: true });
});

// ==================== 🔒 ROUTES ADMIN : CONSULTATION DES LOGS ====================
// Protégées par ADMIN_KEY pour consulter les IPs enregistrées

// Voir les stats d'une IP
app.get('/api/admin/ip-stats/:ip', (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) return res.status(401).json({ error: 'Non autorisé' });

  const ip = req.params.ip;
  const stats = ipLogs.stats[ip];
  const banned = blacklist.ips[ip];

  res.json({
    ip,
    stats: stats || null,
    banned: banned || null,
    isBlacklisted: isBlacklisted(ip)
  });
});

// Voir les top IPs (les plus actives)
app.get('/api/admin/top-ips', (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) return res.status(401).json({ error: 'Non autorisé' });

  const limit = parseInt(req.query.limit) || 20;
  const sorted = Object.entries(ipLogs.stats)
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, limit)
    .map(([ip, stats]) => ({ ip, ...stats }));

  res.json({ top: sorted });
});

// Voir toutes les IPs bannies
app.get('/api/admin/blacklist', (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) return res.status(401).json({ error: 'Non autorisé' });

  res.json(blacklist.ips);
});

// Bannir manuellement une IP
app.post('/api/admin/ban/:ip', (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) return res.status(401).json({ error: 'Non autorisé' });

  const ip = req.params.ip;
  const duration = parseInt(req.body?.duration) || BAN_CONFIG.banDurationMs;
  const reason = req.body?.reason || 'Ban manuel admin';

  blacklist.ips[ip] = {
    bannedUntil: Date.now() + duration,
    reason,
    bannedAt: Date.now()
  };
  saveJSON(BLACKLIST_FILE, blacklist);
  console.log(`🚫 Ban manuel: ${ip} (${reason})`);
  res.json({ success: true, ip, bannedUntil: blacklist.ips[ip].bannedUntil });
});

// Débannir une IP
app.post('/api/admin/unban/:ip', (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) return res.status(401).json({ error: 'Non autorisé' });

  const ip = req.params.ip;
  delete blacklist.ips[ip];
  delete blacklist.violations[ip];
  saveJSON(BLACKLIST_FILE, blacklist);
  console.log(`✅ Unban: ${ip}`);
  res.json({ success: true, ip });
});

// Voir les logs récents (filtrés)
app.get('/api/admin/logs', (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) return res.status(401).json({ error: 'Non autorisé' });

  const limit = Math.min(parseInt(req.query.limit) || 100, 1000);
  const endpoint = req.query.endpoint;

  let logs = ipLogs.logs;
  if (endpoint) logs = logs.filter(l => l.endpoint === endpoint);

  res.json({
    total: logs.length,
    logs: logs.slice(-limit).reverse()
  });
});

// ==================== PING DES SERVEURS ====================
async function pingServers() {
  for (const server of SERVERS) {
    // Si l'URL est vide, on skip (le serveur reste hors ligne)
    if (!server.url || server.url.trim() === '') {
      // On ne marque pas offline si on a reçu un ping récent
      if (Date.now() - server.lastPing > 90000) {
        server.online = false;
      }
      continue;
    }

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 8000);

      const baseUrl = server.url.endsWith('/') ? server.url.slice(0, -1) : server.url;
      const res = await fetch(`${baseUrl}/health`, {
        method: 'GET',
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (res.ok) {
        server.online = true;
        server.lastPing = Date.now();

        try {
          const data = await res.json();
          if (data.cpu !== undefined) server.cpu = data.cpu;
          if (data.ram !== undefined) server.ram = data.ram;
          if (data.uptime !== undefined) server.uptime = data.uptime;
        } catch (e) {}
      }
    } catch (e) {
      // Si pas de ping depuis plus de 60 secondes, on marque hors ligne
      if (Date.now() - server.lastPing > 60000) {
        server.online = false;
        server.cpu = 0;
        server.ram = 0;
      }
    }
  }
}

setInterval(pingServers, 30000);
pingServers();

// ==================== NETTOYAGE AUTOMATIQUE ====================
setInterval(() => {
  const now = Date.now();
  const users = loadUsers();
  let changed = false;

  for (const phone of Object.keys(users)) {
    if (users[phone].status === 'error' && now - users[phone].createdAt > 24 * 60 * 60 * 1000) {
      delete users[phone];
      changed = true;
      console.log(`🧹 Supprimé (erreur): ${phone}`);
    }
    if (users[phone].status === 'pending' && now - users[phone].createdAt > 24 * 60 * 60 * 1000) {
      delete users[phone];
      changed = true;
      console.log(`🧹 Supprimé (expiré): ${phone}`);
    }
  }

  if (changed) saveUsers(users);
}, 60 * 60 * 1000);

// ==================== 🔒 NETTOYAGE DES LOGS ANCIENS ====================
// Supprimer les logs de plus de 30 jours
setInterval(() => {
  const now = Date.now();
  const thirtyDaysAgo = now - 30 * 24 * 60 * 60 * 1000;

  // Logs détaillés
  ipLogs.logs = ipLogs.logs.filter(l => new Date(l.timestamp).getTime() > thirtyDaysAgo);

  // Stats IPs inactives depuis 30 jours
  for (const ip of Object.keys(ipLogs.stats)) {
    if (ipLogs.stats[ip].lastSeen < thirtyDaysAgo) {
      delete ipLogs.stats[ip];
    }
  }

  saveJSON(IP_LOGS_FILE, ipLogs);
}, 24 * 60 * 60 * 1000);

// ==================== DÉMARRAGE ====================
app.listen(PORT, '0.0.0.0', () => {
  console.log('════════════════════════════════════════');
  console.log(`🚀 Serveur maître HEXTECH démarré`);
  console.log(`📊 Port: ${PORT}`);
  console.log(`🖥️ ${SERVERS.length} serveurs workers configurés :`);
  SERVERS.forEach(s => {
    console.log(`   • Server ${s.id} (${s.name}) → ${s.url || 'Non configuré'}`);
  });
  console.log(`👥 Max par serveur: ${MAX_USERS_PER_SERVER}`);
  console.log('────────────────────────────────────────');
  console.log(`🔒 SÉCURITÉ ACTIVE :`);
  console.log(`   • Rate-limit global : ${RATE_LIMIT.global.max} req/min`);
  console.log(`   • Rate-limit /pair  : ${RATE_LIMIT.pair.max} req/min`);
  console.log(`   • Rate-limit /status: ${RATE_LIMIT.status.max} req/min`);
  console.log(`   • Ban auto après    : ${BAN_CONFIG.maxViolations} violations (${BAN_CONFIG.banDurationMs / 1000 / 60}min)`);
  console.log(`   • API Key requise   : ${API_KEY.substring(0, 8)}...`);
  console.log(`   • CORS origins      : ${ALLOWED_ORIGINS.join(', ')}`);
  console.log(`   • Trust proxy       : ${TRUST_PROXY}`);
  console.log('════════════════════════════════════════');
});

// ==================== GESTION ERREURS ====================
process.on('uncaughtException', (err) => {
  console.error('❌ Erreur non gérée:', err.message);
});

process.on('unhandledRejection', (err) => {
  console.error('❌ Promesse rejetée:', err?.message);
});

process.on('SIGTERM', () => {
  console.log('🛑 Arrêt du serveur...');
  try { saveJSON(IP_LOGS_FILE, ipLogs); } catch (e) {}
  try { saveJSON(BLACKLIST_FILE, blacklist); } catch (e) {}
  process.exit(0);
});
