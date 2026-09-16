// server.js
// Serveur maître HEXTECH - Gère 4 workers KataBump
// 🔒 SÉCURISÉ : rate-limit + IP logging + API key + CORS strict
// 🆕 ADMIN COMPLET : déconnexion + ban IP + stats pays + clics
// 🆕 v2 : Exclusions stats internes + Auth disconnect/status
// 🆕 v3 : Turnstile serveur + Page admin attaques
// 🆕 v4 : Whitelist IPs Render/worker + Fix NaN + Route GET unban

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
const ADMIN_KEY = process.env.ADMIN_KEY || 'xenoban-admin-2026-a7f3b9e2c8d1';

// 🔒 VARIABLES DE SÉCURITÉ
const API_KEY = process.env.HEXTECH_SECRET_KEY || 'hextech-secret-9f2a7c4e8b1d6a3f5c9e2b4d8a7f1c3e';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '*').split(',').map(s => s.trim());
const TRUST_PROXY = process.env.TRUST_PROXY === 'true' || true;

// 🆕 WHITELIST D'IPs DE CONFIANCE
// Ces IPs ne sont JAMAIS bannies, JAMAIS comptées dans les stats, JAMAIS rate-limitées
// 👉 Ajoute ici toutes les IPs de tes workers Render, ton IP perso, etc.
const TRUSTED_IPS = [
  // 📍 IPs locales
  '127.0.0.1',
  '::1',
  'localhost',

  // 📍 IP de ton WORKER (celle qu'on voit dans les logs : 51.75.118.170)
  '51.75.118.170',

  // 📍 Plages d'IPs Render (Frankfurt - principal)
  // Ces plages sont utilisées par tous les services Render
  // ⚠️ Si Render change, ajoute les nouvelles IPs ici
  // (voir : https://render.com/docs/static-outbound-ip-addresses)

  // 📍 IP de ton site (si différent du master)
  // Ajoute ici l'IP de ton Worker Cloudflare si tu en as un

  // 📍 Ajoute ici ton IP personnelle (pour ne jamais être banni toi-même)
  // Pour trouver ton IP : https://whatismyipaddress.com/
];

// 🆕 Détection automatique des IPs privées/internes
function isInternalIP(ip) {
  if (!ip) return false;
  
  // IPs locales
  if (ip === '127.0.0.1' || ip === '::1' || ip === 'localhost') return true;
  
  // IPs privées (RFC 1918)
  if (ip.startsWith('10.')) return true;
  if (ip.startsWith('192.168.')) return true;
  
  // 172.16.0.0 → 172.31.255.255
  if (ip.startsWith('172.')) {
    const second = parseInt(ip.split('.')[1]);
    if (second >= 16 && second <= 31) return true;
  }
  
  // IPs link-local
  if (ip.startsWith('169.254.')) return true;
  
  // IPs Cloudflare (si tu utilises Cloudflare)
  if (ip.startsWith('172.68.') || ip.startsWith('172.69.') || ip.startsWith('172.70.') || ip.startsWith('172.71.')) return true;
  
  return false;
}

// 🆕 Vérifie si une IP est de confiance
function isTrustedIP(ip) {
  if (!ip) return false;
  if (TRUSTED_IPS.includes(ip)) return true;
  if (isInternalIP(ip)) return true;
  return false;
}

// 🆕 Configuration Turnstile
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || '';
const TURNSTILE_ENABLED = process.env.TURNSTILE_ENABLED !== 'false' && TURNSTILE_SECRET_KEY.length > 0;
const TURNSTILE_VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

// 🆕 CONFIGURATION DES STATS
const STATS_EXCLUDED_PATHS = [
  '/health',
  '/api/worker/',
  '/api/admin/',
  '/static/',
  '/admin',
  '/admin.html'
];

// 🆕 Configuration de l'anti-énumération
const ENUM_CONFIG = {
  maxDistinctPhones: 10,
  windowMs: 60 * 60 * 1000
};

// 🔒 CONFIGURATION RATE-LIMIT
const RATE_LIMIT = {
  global: { windowMs: 60 * 1000, max: 120 },
  pair:   { windowMs: 60 * 1000, max: 3 },
  status: { windowMs: 60 * 1000, max: 30 },
  disconnect: { windowMs: 60 * 1000, max: 5 }
};

// 🔒 BAN AUTOMATIQUE
const BAN_CONFIG = {
  maxViolations: 5,
  banDurationMs: 24 * 60 * 60 * 1000,
  violationWindowMs: 10 * 60 * 1000
};

// ==================== CONFIGURATION DES 4 SERVEURS ====================
const SERVERS = [
  {
    id: 1,
    name: 'Serveur 1 - Web',
    url: process.env.SERVER_1_URL || 'https://hextechcar12omega.onrender.com',
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
if (TRUST_PROXY) {
  app.set('trust proxy', 1);
}

// ==================== 🔒 HELPER : RÉCUPÉRER LA VRAIE IP ====================
function getClientIP(req) {
  const cfIP = req.headers['cf-connecting-ip'];
  if (cfIP) return cfIP;
  
  const xForwarded = req.headers['x-forwarded-for'];
  if (xForwarded) return xForwarded.split(',')[0].trim();
  
  const xRealIP = req.headers['x-real-ip'];
  if (xRealIP) return xRealIP;
  
  return req.ip || req.connection?.remoteAddress || 'unknown';
}

// 🆕 Vérifie si un chemin doit être EXCLU des stats
function isExcludedFromStats(pathname) {
  return STATS_EXCLUDED_PATHS.some(p => pathname.startsWith(p));
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
const ipLogs = loadJSON(IP_LOGS_FILE, { logs: [], stats: {}, countries: {} });

if (!ipLogs.countries) ipLogs.countries = {};

// 🆕 Détecte si une requête est suspecte (pour l'onglet attaques)
function isAttackLog(log) {
  const ua = (log.userAgent || '').toLowerCase();
  const suspiciousUAs = [
    'curl', 'wget', 'python', 'scrapy', 'postman',
    'insomnia', 'httpie', 'go-http', 'java/', 'okhttp'
  ];
  if (suspiciousUAs.some(p => ua.includes(p))) return true;
  if (log.endpoint === '/api/pair' && log.method === 'POST') return true;
  return false;
}

function logIP(req, endpoint, extra = {}) {
  const ip = getClientIP(req);
  const now = Date.now();
  const ua = req.headers['user-agent'] || 'unknown';
  const country = req.headers['cf-ipcountry'] || 'unknown';
  const city = req.headers['cf-ipcity'] || null;

  // 🆕 NE PAS logger les IPs de confiance
  const trusted = isTrustedIP(ip);

  const logEntry = {
    ip,
    endpoint,
    method: req.method,
    userAgent: ua,
    timestamp: new Date(now).toISOString(),
    country: trusted ? 'INTERNAL' : country,
    city,
    referer: req.headers['referer'] || null,
    origin: req.headers['origin'] || null,
    trusted,   // 🆕 Marquer comme IP de confiance
    ...extra
  };

  logEntry.isAttack = !trusted && isAttackLog(logEntry);

  ipLogs.logs.push(logEntry);

  if (ipLogs.logs.length > 5000) {
    ipLogs.logs = ipLogs.logs.slice(-5000);
  }

  if (!ipLogs.stats[ip]) {
    ipLogs.stats[ip] = {
      firstSeen: now,
      lastSeen: now,
      count: 0,
      endpoints: {},
      blocked: false,
      violations: [],
      country: trusted ? 'INTERNAL' : country,
      city: city,
      attacks: 0,
      trusted   // 🆕
    };
  }
  ipLogs.stats[ip].lastSeen = now;
  ipLogs.stats[ip].count++;
  ipLogs.stats[ip].country = trusted ? 'INTERNAL' : (country || ipLogs.stats[ip].country);
  ipLogs.stats[ip].city = city || ipLogs.stats[ip].city;
  ipLogs.stats[ip].trusted = trusted;
  ipLogs.stats[ip].endpoints[endpoint] = (ipLogs.stats[ip].endpoints[endpoint] || 0) + 1;
  if (logEntry.isAttack) {
    ipLogs.stats[ip].attacks = (ipLogs.stats[ip].attacks || 0) + 1;
  }

  // 🆕 Stats par pays (n'exclut pas INTERNAL pour info)
  if (!ipLogs.countries[logEntry.country]) {
    ipLogs.countries[logEntry.country] = {
      count: 0,
      uniqueIPs: {},
      endpoints: {},
      attacks: 0,
      firstSeen: now,
      lastSeen: now
    };
  }
  ipLogs.countries[logEntry.country].count++;
  ipLogs.countries[logEntry.country].lastSeen = now;
  ipLogs.countries[logEntry.country].uniqueIPs[ip] = (ipLogs.countries[logEntry.country].uniqueIPs[ip] || 0) + 1;
  ipLogs.countries[logEntry.country].endpoints[endpoint] = (ipLogs.countries[logEntry.country].endpoints[endpoint] || 0) + 1;
  if (logEntry.isAttack) {
    ipLogs.countries[logEntry.country].attacks = (ipLogs.countries[logEntry.country].attacks || 0) + 1;
  }

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

process.on('SIGTERM', () => {
  try { saveJSON(IP_LOGS_FILE, ipLogs); } catch (e) {}
});

// ==================== 🔒 BLACKLIST / BAN ====================
const blacklist = loadJSON(BLACKLIST_FILE, { ips: {}, violations: {} });

function isBlacklisted(ip) {
  // 🆕 Les IPs de confiance ne sont JAMAIS bannies
  if (isTrustedIP(ip)) return false;

  const entry = blacklist.ips[ip];
  if (!entry) return false;
  if (entry.bannedUntil === 'permanent') return true;
  if (entry.bannedUntil && entry.bannedUntil > Date.now()) return true;
  if (entry.bannedUntil && entry.bannedUntil <= Date.now()) {
    delete blacklist.ips[ip];
    saveJSON(BLACKLIST_FILE, blacklist);
  }
  return false;
}

function recordViolation(ip, reason) {
  // 🆕 Les IPs de confiance ne génèrent JAMAIS de violation
  if (isTrustedIP(ip)) {
    console.log(`✅ [TRUSTED] Violation ignorée pour ${ip} (${reason})`);
    return;
  }

  const now = Date.now();
  if (!blacklist.violations[ip]) {
    blacklist.violations[ip] = [];
  }
  
  blacklist.violations[ip] = blacklist.violations[ip].filter(
    v => now - v.time < BAN_CONFIG.violationWindowMs
  );
  
  blacklist.violations[ip].push({ time: now, reason });
  
  if (blacklist.violations[ip].length >= BAN_CONFIG.maxViolations) {
    blacklist.ips[ip] = {
      bannedUntil: now + BAN_CONFIG.banDurationMs,
      reason: `Trop de violations: ${reason}`,
      bannedAt: now
    };
    // 🐛 FIX : binDurationMs → banDurationMs
    console.warn(`🚫 IP BANNIE: ${ip} pour ${BAN_CONFIG.banDurationMs / 1000 / 60} minutes`);
    saveJSON(BLACKLIST_FILE, blacklist);
  }
}

// ==================== 🔒 RATE-LIMIT CUSTOM ====================
const rateLimitStore = new Map();

function rateLimit(config, endpointName) {
  return (req, res, next) => {
    const ip = getClientIP(req);

    // 🆕 Les IPs de confiance ne sont JAMAIS rate-limitées
    if (isTrustedIP(ip)) {
      return next();
    }

    if (isBlacklisted(ip)) {
      return res.status(403).json({ error: 'Accès refusé (IP bannie)' });
    }

    const key = `${ip}:${endpointName}`;
    const now = Date.now();
    const entry = rateLimitStore.get(key) || { count: 0, resetAt: now + config.windowMs };

    if (now > entry.resetAt) {
      entry.count = 0;
      entry.resetAt = now + config.windowMs;
    }

    entry.count++;
    rateLimitStore.set(key, entry);

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

// ==================== 🔒 VÉRIFICATION ADMIN ====================
function isAdminAuthorized(req) {
  const headerKey = req.headers['x-admin-key'];
  if (headerKey && headerKey === ADMIN_KEY) return true;

  const queryKey = req.query?.adminKey;
  if (queryKey && queryKey === ADMIN_KEY) return true;

  const queryKey2 = req.query?.key;
  if (queryKey2 && queryKey2 === ADMIN_KEY) return true;

  return false;
}

function requireAdmin(req, res, next) {
  // 🆕 Accepter les IPs de confiance avec header worker-id (communication worker → master)
  const ip = getClientIP(req);
  const workerId = req.headers['x-worker-id'];
  
  if (workerId && isTrustedIP(ip)) {
    // Le worker envoie son ID et vient d'une IP de confiance → OK
    return next();
  }

  if (!isAdminAuthorized(req)) {
    recordViolation(ip, 'unauthorized-admin');
    console.warn(`🚫 Admin refusé depuis ${ip} (${req.path})`);
    return res.status(401).json({ error: 'Non autorisé' });
  }
  next();
}

// ==================== 🆕 VÉRIFICATION CLOUDFLARE TURNSTILE ====================
async function verifyTurnstile(req, res, next) {
  if (!TURNSTILE_ENABLED) {
    console.warn('⚠️ Turnstile désactivé (TURNSTILE_ENABLED=false)');
    return next();
  }

  // 🆕 Les IPs de confiance bypass Turnstile
  const ip = getClientIP(req);
  if (isTrustedIP(ip)) {
    console.log(`✅ [TRUSTED] Turnstile bypass pour ${ip}`);
    return next();
  }

  const token =
    req.headers['cf-turnstile-response'] ||
    req.body?.turnstileToken ||
    req.body?.cfTurnstileResponse ||
    req.query?.turnstileToken;

  if (!token) {
    recordViolation(ip, 'missing-turnstile-token');
    console.warn(`🚫 Turnstile token manquant depuis ${ip}`);
    return res.status(403).json({
      error: 'Vérification de sécurité requise. Rechargez la page.'
    });
  }

  try {
    const verifyRes = await fetch(TURNSTILE_VERIFY_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        secret: TURNSTILE_SECRET_KEY,
        response: token,
        remoteip: ip
      })
    });

    const result = await verifyRes.json();

    if (!result.success) {
      recordViolation(ip, 'turnstile-failed');
      console.warn(`🚫 Turnstile échoué depuis ${ip}:`, result['error-codes']);
      return res.status(403).json({
        error: 'Vérification captcha échouée. Réessayez.'
      });
    }

    req.turnstileVerified = true;
    next();

  } catch (e) {
    console.error(`❌ Erreur Turnstile: ${e.message}`);
    return res.status(500).json({ error: 'Erreur de vérification captcha' });
  }
}

// ==================== 🔒 DÉTECTION USER-AGENT SUSPECT ====================
const SUSPICIOUS_UA = [
  /curl/i, /wget/i, /python/i, /python-requests/i,
  /scrapy/i, /postman/i, /insomnia/i, /httpie/i,
  /go-http-client/i, /java\//i, /okhttp/i
];

function detectSuspiciousClient(req, res, next) {
  const ip = getClientIP(req);

  // 🆕 Les IPs de confiance bypass la détection
  if (isTrustedIP(ip)) return next();

  const ua = req.headers['user-agent'] || '';
  const isSuspicious = SUSPICIOUS_UA.some(pattern => pattern.test(ua));

  if (isSuspicious && process.env.ALLOW_SUSPICIOUS_UA !== 'true') {
    if (isAdminAuthorized(req)) return next();

    recordViolation(ip, 'suspicious-ua');
    console.warn(`🚫 User-Agent suspect bloqué: ${ip} → ${ua}`);
    return res.status(403).json({ error: 'Accès refusé' });
  }
  next();
}

// ==================== 🆕 VÉRIFICATION SESSION TOKEN ====================
function requireSessionToken(req, res, next) {
  const phone = req.params.phone;
  const users = loadUsers();
  const user = users[phone];

  if (!user) {
    return res.status(404).json({ error: 'Numéro non enregistré' });
  }

  const providedToken =
    req.headers['x-session-token'] ||
    req.query?.token ||
    req.body?.token;

  if (user.sessionToken) {
    if (!providedToken || providedToken !== user.sessionToken) {
      const ip = getClientIP(req);
      recordViolation(ip, 'invalid-session-token');
      console.warn(`🚫 Session token invalide pour ${phone} depuis ${ip}`);
      return res.status(401).json({ error: 'Session invalide. Reconnectez-vous.' });
    }
  } else {
    console.warn(`⚠️ Utilisateur ${phone} sans session token (legacy)`);
  }

  next();
}

// ==================== 🆕 ANTI-ÉNUMÉRATION ====================
const enumerationTracker = new Map();

function antiEnumeration(req, res, next) {
  const ip = getClientIP(req);

  // 🆕 Les IPs de confiance bypass
  if (isTrustedIP(ip)) return next();

  const phone = req.params.phone;
  const now = Date.now();

  if (!enumerationTracker.has(ip)) {
    enumerationTracker.set(ip, { phones: new Set(), resetAt: now + ENUM_CONFIG.windowMs });
  }

  const entry = enumerationTracker.get(ip);

  if (now > entry.resetAt) {
    entry.phones.clear();
    entry.resetAt = now + ENUM_CONFIG.windowMs;
  }

  entry.phones.add(phone);

  if (entry.phones.size > ENUM_CONFIG.maxDistinctPhones) {
    recordViolation(ip, 'enumeration');
    console.warn(`🚫 Anti-énumération: ${ip} a testé ${entry.phones.size} numéros différents`);
    return res.status(429).json({
      error: 'Trop de numéros différents testés. Réessayez plus tard.'
    });
  }

  next();
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of enumerationTracker.entries()) {
    if (now > entry.resetAt + 60000) enumerationTracker.delete(ip);
  }
}, 5 * 60 * 1000);

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
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.includes('*')) return callback(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    console.warn(`🚫 CORS bloqué pour origin: ${origin}`);
    return callback(new Error('CORS non autorisé'));
  },
  methods: ['GET', 'POST', 'OPTIONS', 'DELETE'],
  allowedHeaders: ['Content-Type', 'X-API-KEY', 'X-ADMIN-KEY', 'X-Session-Token', 'X-Worker-Id', 'CF-Turnstile-Response'],
  credentials: false,
  maxAge: 86400
}));

// ==================== 🔒 BODY PARSER ====================
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));

// ==================== 🆕 MIDDLEWARE GLOBAL : LOG INTELLIGENT ====================
app.use((req, res, next) => {
  // 🆕 Ne PAS logger : health, worker, admin, static, ET IPs de confiance
  if (!isExcludedFromStats(req.path)) {
    const ip = getClientIP(req);
    if (!isTrustedIP(ip)) {
      logIP(req, req.path);
    }
  }
  next();
});

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

// ==================== ROUTE HEALTH ====================
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    uptime: Math.floor(process.uptime()),
    ip: getClientIP(req),
    trusted: isTrustedIP(getClientIP(req)),
    turnstileEnabled: TURNSTILE_ENABLED
  });
});

// ==================== ROUTES PUBLIQUES ====================

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

// ==================== ROUTE : PAIRING ====================
app.post('/api/pair',
  rateLimit(RATE_LIMIT.pair, 'pair'),
  verifyTurnstile,
  async (req, res) => {
    const { phone, consent, serverId } = req.body;
    const clientIP = getClientIP(req);

    if (!consent) return res.status(400).json({ error: 'Consentement requis' });
    if (!phone || !/^\d{9,15}$/.test(phone)) return res.status(400).json({ error: 'Numéro invalide (9-15 chiffres)' });

    const users = loadUsers();

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

    const currentOnServer = Object.values(users).filter(u =>
      u.serverId === targetServerId && u.status !== 'disconnected'
    ).length;

    if (currentOnServer >= MAX_USERS_PER_SERVER) {
      return res.status(503).json({
        error: `Le ${server.name} est plein (${currentOnServer}/${MAX_USERS_PER_SERVER}). Choisissez un autre serveur.`
      });
    }

    if (users[phone] && users[phone].status === 'connected') {
      return res.status(409).json({ error: 'Ce numéro est déjà couplé. Déconnectez-le d\'abord.' });
    }

    let sessionToken = users[phone]?.sessionToken;
    if (!sessionToken) {
      sessionToken = crypto.randomBytes(24).toString('hex');
    }

    if (users[phone] && users[phone].status === 'pending' && users[phone].code) {
      return res.json({
        success: true,
        code: users[phone].code,
        phone: phone,
        serverId: users[phone].serverId,
        status: 'pending',
        sessionToken: sessionToken,
        message: 'Code déjà généré'
      });
    }

    users[phone] = {
      phone,
      serverId: targetServerId,
      createdAt: users[phone]?.createdAt || Date.now(),
      status: 'pending',
      code: null,
      sessionToken: sessionToken,
      ip: clientIP,
      userAgent: req.headers['user-agent'] || 'unknown',
      country: req.headers['cf-ipcountry'] || 'unknown'
    };
    saveUsers(users);

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
        sessionToken: sessionToken,
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

// ==================== ROUTE : STATUT ====================
app.get('/api/status/:phone',
  rateLimit(RATE_LIMIT.status, 'status'),
  antiEnumeration,
  requireSessionToken,
  (req, res) => {
    const { phone } = req.params;
    const users = loadUsers();
    const user = users[phone];

    res.json({
      phone: user.phone,
      serverId: user.serverId,
      status: user.status,
      createdAt: user.createdAt,
      connectedAt: user.connectedAt || null
    });
  }
);

// ==================== ROUTE : DÉCONNEXION ====================
app.post('/api/disconnect/:phone',
  rateLimit(RATE_LIMIT.disconnect, 'disconnect'),
  requireSessionToken,
  (req, res) => {
    const { phone } = req.params;
    const users = loadUsers();

    users[phone].status = 'disconnect_requested';
    users[phone].disconnectAt = Date.now();
    saveUsers(users);

    console.log(`🚪 Déconnexion demandée pour ${phone} (Server ${users[phone].serverId})`);
    res.json({ success: true, message: 'Déconnexion en cours...' });
  }
);

// ==================== ROUTES WORKER ====================
app.get('/api/worker/:serverId/pending', requireAdmin, (req, res) => {
  const serverId = parseInt(req.params.serverId);
  if (![1, 2, 3, 4].includes(serverId)) return res.status(400).json({ error: 'Serveur invalide' });

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

app.post('/api/worker/:serverId/result', requireAdmin, (req, res) => {
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

app.post('/api/worker/:serverId/connected', requireAdmin, (req, res) => {
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

app.post('/api/worker/:serverId/disconnected', requireAdmin, (req, res) => {
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

app.get('/api/worker/:serverId/disconnect-list', requireAdmin, (req, res) => {
  const serverId = parseInt(req.params.serverId);
  const users = loadUsers();

  const toDisconnect = Object.keys(users).filter(p =>
    users[p].serverId === serverId && users[p].status === 'disconnect_requested'
  );

  res.json(toDisconnect);
});

app.post('/api/worker/:serverId/disconnect-done', requireAdmin, (req, res) => {
  const { phone } = req.body;
  const users = loadUsers();

  if (users[phone]) {
    delete users[phone];
    saveUsers(users);
    console.log(`🗑️ Utilisateur ${phone} supprimé (Server ${req.params.serverId})`);
  }

  res.json({ success: true });
});

app.post('/api/worker/:serverId/stats', requireAdmin, (req, res) => {
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

// ==================== ROUTES ADMIN ====================

app.get('/api/admin/top-ips', requireAdmin, (req, res) => {
  const limit = parseInt(req.query.limit) || 20;
  // 🆕 Exclure les IPs de confiance des stats
  const sorted = Object.entries(ipLogs.stats)
    .filter(([ip]) => !isTrustedIP(ip))
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, limit)
    .map(([ip, stats]) => ({
      ip,
      ...stats,
      firstSeenFormatted: new Date(stats.firstSeen).toISOString(),
      lastSeenFormatted: new Date(stats.lastSeen).toISOString()
    }));

  res.json({ total: sorted.length, top: sorted });
});

app.get('/api/admin/ip-stats/:ip', requireAdmin, (req, res) => {
  const ip = req.params.ip;
  const stats = ipLogs.stats[ip];
  const banned = blacklist.ips[ip];

  const users = loadUsers();
  const linkedUsers = Object.values(users)
    .filter(u => u.ip === ip)
    .map(u => ({
      phone: u.phone,
      status: u.status,
      serverId: u.serverId,
      createdAt: u.createdAt
    }));

  res.json({
    ip,
    trusted: isTrustedIP(ip),
    stats: stats ? {
      ...stats,
      firstSeenFormatted: new Date(stats.firstSeen).toISOString(),
      lastSeenFormatted: new Date(stats.lastSeen).toISOString()
    } : null,
    banned: banned || null,
    isBlacklisted: isBlacklisted(ip),
    linkedUsers
  });
});

app.get('/api/admin/blacklist', requireAdmin, (req, res) => {
  res.json({
    total: Object.keys(blacklist.ips).length,
    ips: blacklist.ips
  });
});

app.post('/api/admin/ban/:ip', requireAdmin, (req, res) => {
  const ip = req.params.ip;

  // 🆕 Refuser de bannir une IP de confiance
  if (isTrustedIP(ip)) {
    return res.status(400).json({ error: 'Impossible de bannir une IP de confiance' });
  }

  const duration = req.body?.duration;
  const reason = req.body?.reason || 'Ban manuel admin';

  let bannedUntil;
  if (duration === 'permanent') {
    bannedUntil = 'permanent';
  } else if (typeof duration === 'number' && duration > 0) {
    bannedUntil = Date.now() + duration;
  } else {
    bannedUntil = Date.now() + BAN_CONFIG.banDurationMs;
  }

  blacklist.ips[ip] = {
    bannedUntil,
    reason,
    bannedAt: Date.now()
  };
  saveJSON(BLACKLIST_FILE, blacklist);
  console.log(`🚫 Ban manuel: ${ip} (${reason}) → ${bannedUntil === 'permanent' ? 'PERMANENT' : new Date(bannedUntil).toISOString()}`);
  res.json({ success: true, ip, bannedUntil, reason });
});

// 🆕 POST unban
app.post('/api/admin/unban/:ip', requireAdmin, (req, res) => {
  const ip = req.params.ip;
  delete blacklist.ips[ip];
  delete blacklist.violations[ip];
  saveJSON(BLACKLIST_FILE, blacklist);
  console.log(`✅ Unban: ${ip}`);
  res.json({ success: true, ip });
});

// 🆕 GET unban (accessible navigateur)
app.get('/api/admin/unban/:ip', requireAdmin, (req, res) => {
  const ip = req.params.ip;
  delete blacklist.ips[ip];
  delete blacklist.violations[ip];
  saveJSON(BLACKLIST_FILE, blacklist);
  console.log(`✅ Unban (GET): ${ip}`);
  res.json({ success: true, ip, message: 'IP débannie' });
});

app.get('/api/admin/logs', requireAdmin, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 1000);
  const endpoint = req.query.endpoint;
  const country = req.query.country;
  const ip = req.query.ip;
  const attacksOnly = req.query.attacks === 'true';
  const excludeTrusted = req.query.excludeTrusted !== 'false';

  let logs = ipLogs.logs;
  if (excludeTrusted) logs = logs.filter(l => !l.trusted);
  if (endpoint) logs = logs.filter(l => l.endpoint === endpoint);
  if (country) logs = logs.filter(l => l.country === country);
  if (ip) logs = logs.filter(l => l.ip === ip);
  if (attacksOnly) logs = logs.filter(l => l.isAttack === true);

  res.json({
    total: logs.length,
    logs: logs.slice(-limit).reverse()
  });
});

app.get('/api/admin/countries', requireAdmin, (req, res) => {
  const countries = Object.entries(ipLogs.countries || {})
    .filter(([code]) => code !== 'INTERNAL')
    .map(([code, data]) => ({
      code,
      count: data.count,
      attacks: data.attacks || 0,
      uniqueIPs: Object.keys(data.uniqueIPs || {}).length,
      topEndpoint: Object.entries(data.endpoints || {})
        .sort((a, b) => b[1] - a[1])[0]?.[0] || '—',
      firstSeen: data.firstSeen,
      lastSeen: data.lastSeen,
      ips: Object.keys(data.uniqueIPs || {})
    }))
    .sort((a, b) => b.count - a.count);

  res.json({
    total: countries.length,
    countries
  });
});

app.get('/api/admin/endpoints', requireAdmin, (req, res) => {
  const endpoints = {};
  
  ipLogs.logs.filter(l => !l.trusted).forEach(log => {
    if (!endpoints[log.endpoint]) {
      endpoints[log.endpoint] = {
        count: 0,
        uniqueIPs: new Set(),
        methods: {},
        attacks: 0
      };
    }
    endpoints[log.endpoint].count++;
    endpoints[log.endpoint].uniqueIPs.add(log.ip);
    endpoints[log.endpoint].methods[log.method] = (endpoints[log.endpoint].methods[log.method] || 0) + 1;
    if (log.isAttack) endpoints[log.endpoint].attacks++;
  });

  const result = Object.entries(endpoints)
    .map(([ep, data]) => ({
      endpoint: ep,
      count: data.count,
      attacks: data.attacks,
      uniqueIPs: data.uniqueIPs.size,
      methods: data.methods
    }))
    .sort((a, b) => b.count - a.count);

  res.json({ total: result.length, endpoints: result });
});

app.get('/api/admin/users', requireAdmin, (req, res) => {
  const users = loadUsers();
  const list = Object.entries(users).map(([phone, u]) => ({
    phone,
    serverId: u.serverId,
    status: u.status,
    ip: u.ip || '—',
    country: u.country || '—',
    userAgent: u.userAgent || '—',
    createdAt: u.createdAt,
    connectedAt: u.connectedAt || null,
    code: u.code || null,
    hasSessionToken: !!u.sessionToken
  })).sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));

  res.json({ total: list.length, users: list });
});

app.post('/api/admin/disconnect-user/:phone', requireAdmin, (req, res) => {
  const { phone } = req.params;
  const users = loadUsers();

  if (!users[phone]) {
    return res.status(404).json({ error: 'Utilisateur non trouvé' });
  }

  users[phone].status = 'disconnect_requested';
  users[phone].disconnectAt = Date.now();
  users[phone].disconnectedBy = 'admin';
  saveUsers(users);

  console.log(`🚪 Admin déconnexion ${phone} (Server ${users[phone].serverId})`);
  res.json({ success: true, phone, message: 'Déconnexion en cours...' });
});

app.post('/api/admin/disconnect-ip/:ip', requireAdmin, (req, res) => {
  const { ip } = req.params;
  const users = loadUsers();
  const affected = [];

  Object.keys(users).forEach(phone => {
    if (users[phone].ip === ip && users[phone].status !== 'disconnected') {
      users[phone].status = 'disconnect_requested';
      users[phone].disconnectAt = Date.now();
      users[phone].disconnectedBy = 'admin-ip-ban';
      affected.push(phone);
    }
  });

  saveUsers(users);
  console.log(`🚪 Admin déconnexion IP ${ip} → ${affected.length} utilisateurs: ${affected.join(', ')}`);
  res.json({ success: true, ip, affected, count: affected.length });
});

app.delete('/api/admin/user/:phone', requireAdmin, (req, res) => {
  const { phone } = req.params;
  const users = loadUsers();

  if (!users[phone]) {
    return res.status(404).json({ error: 'Utilisateur non trouvé' });
  }

  delete users[phone];
  saveUsers(users);
  console.log(`🗑️ Admin suppression définitive ${phone}`);
  res.json({ success: true, phone });
});

app.get('/api/admin/overview', requireAdmin, (req, res) => {
  const users = loadUsers();
  const totalUsers = Object.keys(users).length;
  const connectedUsers = Object.values(users).filter(u => u.status === 'connected').length;
  const pendingUsers = Object.values(users).filter(u => u.status === 'pending').length;
  const bannedIPs = Object.keys(blacklist.ips).length;
  
  // 🆕 Exclure les IPs de confiance des stats
  const externalIPs = Object.keys(ipLogs.stats).filter(ip => !isTrustedIP(ip));
  const totalIPs = externalIPs.length;
  const totalLogs = ipLogs.logs.filter(l => !l.trusted).length;
  const totalCountries = Object.keys(ipLogs.countries || {}).filter(c => c !== 'INTERNAL').length;

  const oneDayAgo = Date.now() - 24 * 60 * 60 * 1000;
  const recentLogs = ipLogs.logs.filter(l => !l.trusted && new Date(l.timestamp).getTime() > oneDayAgo);
  const recentUniqueIPs = new Set(recentLogs.map(l => l.ip)).size;

  const botAttempts = ipLogs.logs.filter(l => {
    if (l.trusted) return false;
    const ua = (l.userAgent || '').toLowerCase();
    return SUSPICIOUS_UA.some(p => p.test(ua));
  }).length;

  const fiveMinAgo = Date.now() - 5 * 60 * 1000;
  const recentAttacks = ipLogs.logs.filter(l =>
    l.isAttack === true && !l.trusted && new Date(l.timestamp).getTime() > fiveMinAgo
  ).length;

  const totalAttacks = ipLogs.logs.filter(l => l.isAttack === true && !l.trusted).length;

  res.json({
    totalUsers,
    connectedUsers,
    pendingUsers,
    bannedIPs,
    totalIPs,
    totalLogs,
    totalCountries,
    recentUniqueIPs,
    botAttempts,
    recentAttacks,
    totalAttacks,
    trustedIPs: TRUSTED_IPS.length,   // 🆕
    uptime: Math.floor(process.uptime()),
    turnstileEnabled: TURNSTILE_ENABLED,
    servers: SERVERS.map(s => ({
      id: s.id,
      name: s.name,
      online: s.online,
      cpu: s.cpu,
      ram: s.ram
    }))
  });
});

// ==================== ROUTE API : ATTAQUES ====================
app.get('/api/admin/attacks', requireAdmin, (req, res) => {
  const minutes = parseInt(req.query.minutes) || 5;
  const since = Date.now() - minutes * 60 * 1000;

  const attacks = ipLogs.logs
    .filter(l => l.isAttack === true && !l.trusted && new Date(l.timestamp).getTime() > since)
    .slice(-200)
    .reverse();

  const byIP = {};
  attacks.forEach(a => {
    if (!byIP[a.ip]) {
      byIP[a.ip] = {
        ip: a.ip,
        country: a.country,
        count: 0,
        endpoints: {},
        firstSeen: a.timestamp,
        lastSeen: a.timestamp,
        userAgent: a.userAgent
      };
    }
    byIP[a.ip].count++;
    byIP[a.ip].endpoints[a.endpoint] = (byIP[a.ip].endpoints[a.endpoint] || 0) + 1;
    byIP[a.ip].lastSeen = a.timestamp;
  });

  const topAttackers = Object.values(byIP)
    .sort((a, b) => b.count - a.count)
    .slice(0, 20);

  res.json({
    total: attacks.length,
    minutes,
    topAttackers,
    recentAttacks: attacks.slice(0, 50)
  });
});

// ==================== ROUTE : VOIR WHITELIST ====================
app.get('/api/admin/trusted-ips', requireAdmin, (req, res) => {
  res.json({
    total: TRUSTED_IPS.length,
    trustedIPs: TRUSTED_IPS
  });
});

// ==================== ROUTE : AJOUTER IP DE CONFIANCE ====================
app.post('/api/admin/trusted-ips', requireAdmin, (req, res) => {
  const { ip } = req.body;
  if (!ip || typeof ip !== 'string') {
    return res.status(400).json({ error: 'IP requise' });
  }
  if (TRUSTED_IPS.includes(ip)) {
    return res.status(409).json({ error: 'IP déjà dans la whitelist' });
  }
  TRUSTED_IPS.push(ip);
  // Note: en mémoire seulement. Pour persister, il faut écrire dans un fichier.
  console.log(`✅ IP ajoutée à la whitelist: ${ip}`);
  res.json({ success: true, ip, total: TRUSTED_IPS.length });
});

// ==================== PAGE ADMIN HTML ====================
app.get('/admin', (req, res) => {
  if (!isAdminAuthorized(req)) {
    return res.status(401).send(`
      <html><body style="background:#0a0e1a;color:#fff;font-family:sans-serif;padding:40px;text-align:center;">
        <h1>🔒 JE T'AI EU 🙃</h1>
        <p>PAUVRE AMATEUR, MAINTENANT ABONNE-TOI DANS MON PUTAIN DE CANAL T.me/hextechcar 🔥</p>
      </body></html>
    `);
  }
  
  const adminKey = req.query.adminKey || req.query.key;
  
  res.send(`<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>HEXTECH — Admin</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; font-family:'Inter',-apple-system,sans-serif; }
  body { background:#080a10; color:#e2e8f0; padding:20px; min-height:100vh; }
  .container { max-width:1400px; margin:0 auto; }
  h1 { font-size:2rem; background:linear-gradient(135deg,#00c8ff,#7b2ff7); -webkit-background-clip:text; -webkit-text-fill-color:transparent; background-clip:text; margin-bottom:10px; }
  .subtitle { color:#64748b; margin-bottom:25px; font-size:0.9rem; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin-bottom:25px; }
  .card { background:#0f131a; border:1px solid #1e2532; border-radius:12px; padding:16px; }
  .card .label { font-size:0.65rem; color:#64748b; text-transform:uppercase; letter-spacing:1px; margin-bottom:6px; }
  .card .value { font-size:1.6rem; font-weight:700; color:#00c8ff; }
  .card.warning .value { color:#ff9500; }
  .card.danger .value { color:#ff006e; }
  .card.success .value { color:#00ff80; }
  .card.attack { background:linear-gradient(135deg,rgba(255,0,110,0.1),rgba(255,0,110,0.05)); border-color:rgba(255,0,110,0.3); }
  .card.attack .value { color:#ff006e; }
  .card.trusted { background:linear-gradient(135deg,rgba(0,255,128,0.1),rgba(0,255,128,0.05)); border-color:rgba(0,255,128,0.3); }
  .card.trusted .value { color:#00ff80; }
  .panel { background:#0f131a; border:1px solid #1e2532; border-radius:12px; padding:20px; margin-bottom:20px; }
  .panel h2 { font-size:1.05rem; color:#fff; margin-bottom:15px; display:flex; align-items:center; gap:8px; justify-content:space-between; flex-wrap:wrap; }
  table { width:100%; border-collapse:collapse; }
  th { text-align:left; padding:10px; background:#080a10; color:#64748b; font-size:0.7rem; text-transform:uppercase; letter-spacing:1px; border-bottom:1px solid #1e2532; }
  td { padding:10px; border-bottom:1px solid #1e2532; font-size:0.8rem; vertical-align:middle; }
  tr:hover { background:rgba(0,200,255,0.03); }
  tr.attack-row { background:rgba(255,0,110,0.05); }
  tr.attack-row:hover { background:rgba(255,0,110,0.1); }
  tr.trusted-row { background:rgba(0,255,128,0.03); }
  .ip { font-family:monospace; color:#00e5ff; font-weight:600; }
  .count { color:#00ff80; font-weight:700; }
  .count-attack { color:#ff006e; font-weight:700; }
  .flag { font-size:1rem; margin-right:5px; }
  .btn { padding:6px 12px; border-radius:6px; border:none; cursor:pointer; font-size:0.72rem; font-weight:600; transition:all 0.2s; margin:2px; }
  .btn:hover { transform:translateY(-1px); }
  .btn-ban { background:#ff006e; color:#fff; }
  .btn-ban:hover { background:#ff2d85; }
  .btn-unban { background:#00c8ff; color:#080a10; }
  .btn-unban:hover { background:#00e5ff; }
  .btn-disconnect { background:#ff9500; color:#080a10; }
  .btn-disconnect:hover { background:#ffb733; }
  .btn-delete { background:#64748b; color:#fff; }
  .btn-delete:hover { background:#94a3b8; }
  .btn-refresh { background:#1e2532; color:#e2e8f0; padding:10px 20px; margin-bottom:15px; font-size:0.85rem; }
  .btn-refresh:hover { background:#2d3748; }
  .banned { color:#ff006e; font-weight:700; }
  .ok { color:#00ff80; font-weight:700; }
  .trusted { color:#00ff80; font-weight:700; }
  .empty { text-align:center; color:#64748b; padding:30px; }
  .tabs { display:flex; gap:8px; margin-bottom:20px; flex-wrap:wrap; }
  .tab { padding:10px 16px; background:#1e2532; color:#94a3b8; border-radius:8px; cursor:pointer; font-size:0.82rem; font-weight:600; border:none; transition:all 0.2s; }
  .tab.active { background:#00c8ff; color:#080a10; }
  .tab.tab-attack.active { background:#ff006e; color:#fff; }
  .tab:hover:not(.active) { background:#2d3748; color:#fff; }
  .tab-content { display:none; }
  .tab-content.active { display:block; }
  .filters { display:flex; gap:8px; margin-bottom:12px; flex-wrap:wrap; }
  .filters input, .filters select { padding:8px 12px; background:#080a10; border:1px solid #1e2532; border-radius:6px; color:#e2e8f0; font-size:0.8rem; }
  .filters input:focus, .filters select:focus { outline:none; border-color:#00c8ff; }
  .badge { display:inline-block; padding:3px 8px; border-radius:20px; font-size:0.65rem; font-weight:700; }
  .badge-connected { background:rgba(0,255,128,0.15); color:#00ff80; }
  .badge-pending { background:rgba(255,149,0,0.15); color:#ff9500; }
  .badge-disconnected { background:rgba(100,116,139,0.15); color:#94a3b8; }
  .badge-error { background:rgba(255,0,110,0.15); color:#ff006e; }
  .badge-attack { background:rgba(255,0,110,0.15); color:#ff006e; padding:4px 10px; border-radius:20px; font-size:0.65rem; font-weight:700; }
  .badge-trusted { background:rgba(0,255,128,0.15); color:#00ff80; padding:4px 10px; border-radius:20px; font-size:0.65rem; font-weight:700; }
  .modal-overlay { display:none; position:fixed; inset:0; background:rgba(0,0,0,0.8); z-index:1000; align-items:center; justify-content:center; padding:20px; }
  .modal-overlay.active { display:flex; }
  .modal { background:#0f131a; border:1px solid #1e2532; border-radius:16px; padding:25px; max-width:500px; width:100%; }
  .modal h3 { color:#fff; margin-bottom:15px; }
  .modal label { display:block; color:#94a3b8; font-size:0.8rem; margin:12px 0 6px; }
  .modal select, .modal input { width:100%; padding:10px; background:#080a10; border:1px solid #1e2532; border-radius:6px; color:#e2e8f0; font-size:0.9rem; }
  .modal-actions { display:flex; gap:10px; margin-top:20px; justify-content:flex-end; }
  .modal-actions button { padding:10px 20px; border-radius:8px; border:none; font-weight:600; cursor:pointer; font-size:0.85rem; }
  .btn-cancel { background:#1e2532; color:#e2e8f0; }
  .btn-confirm { background:#ff006e; color:#fff; }
</style>
</head>
<body>
<div class="container">
  <h1>🔐 HEXTECH — Admin Dashboard</h1>
  <p class="subtitle">Surveillance : IPs, bots, pays, clics, utilisateurs, attaques 🚨</p>

  <div class="cards" id="statsCards">
    <div class="card"><div class="label">IPs uniques</div><div class="value" id="stat-totalIps">—</div></div>
    <div class="card danger"><div class="label">IPs bannies</div><div class="value" id="stat-bannedIps">—</div></div>
    <div class="card warning"><div class="label">Tentatives bot</div><div class="value" id="stat-botAttempts">—</div></div>
    <div class="card attack"><div class="label">🚨 Attaques 5min</div><div class="value" id="stat-recentAttacks">—</div></div>
    <div class="card trusted"><div class="label">✅ IPs whitelist</div><div class="value" id="stat-trustedIPs">—</div></div>
    <div class="card"><div class="label">Pays</div><div class="value" id="stat-countries">—</div></div>
    <div class="card success"><div class="label">Utilisateurs</div><div class="value" id="stat-users">—</div></div>
    <div class="card"><div class="label">Logs totaux</div><div class="value" id="stat-logs">—</div></div>
  </div>

  <div class="tabs">
    <button class="tab tab-attack active" data-tab="attacks">🚨 Attaques en cours</button>
    <button class="tab" data-tab="overview">📊 Vue d'ensemble</button>
    <button class="tab" data-tab="top">🏆 Top IPs</button>
    <button class="tab" data-tab="countries">🌍 Pays</button>
    <button class="tab" data-tab="endpoints">📈 Clics</button>
    <button class="tab" data-tab="users">👥 Utilisateurs</button>
    <button class="tab" data-tab="logs">📝 Logs</button>
    <button class="tab" data-tab="banned">🚫 Bannis</button>
  </div>

  <div class="panel tab-content active" id="tab-attacks">
    <h2>
      🚨 Attaques en cours
      <div style="display:flex;gap:8px;align-items:center">
        <select id="attackMinutes" onchange="loadAttacks()" style="padding:6px 10px;background:#080a10;border:1px solid #1e2532;border-radius:6px;color:#e2e8f0;font-size:0.8rem">
          <option value="5">5 min</option>
          <option value="15">15 min</option>
          <option value="60">1 heure</option>
          <option value="1440">24 heures</option>
        </select>
        <button class="btn btn-refresh" onclick="loadAttacks()">🔄 Actualiser</button>
      </div>
    </h2>
    <div id="attacksContent"><div class="empty">Chargement...</div></div>
  </div>

  <div class="panel tab-content" id="tab-overview">
    <h2>📊 Vue d'ensemble</h2>
    <button class="btn btn-refresh" onclick="loadAll()">🔄 Rafraîchir</button>
    <div id="overviewContent"><div class="empty">Chargement...</div></div>
  </div>

  <div class="panel tab-content" id="tab-top">
    <h2>🏆 Top IPs les plus actives</h2>
    <div class="filters">
      <input type="number" id="topLimit" value="50" min="1" max="500" placeholder="Limite">
      <button class="btn btn-refresh" onclick="loadTop()">🔄 Actualiser</button>
    </div>
    <div id="topContent"><div class="empty">Chargement...</div></div>
  </div>

  <div class="panel tab-content" id="tab-countries">
    <h2>🌍 Statistiques par pays</h2>
    <button class="btn btn-refresh" onclick="loadCountries()">🔄 Actualiser</button>
    <div id="countriesContent"><div class="empty">Chargement...</div></div>
  </div>

  <div class="panel tab-content" id="tab-endpoints">
    <h2>📈 Nombre de clics par route</h2>
    <button class="btn btn-refresh" onclick="loadEndpoints()">🔄 Actualiser</button>
    <div id="endpointsContent"><div class="empty">Chargement...</div></div>
  </div>

  <div class="panel tab-content" id="tab-users">
    <h2>👥 Utilisateurs couplés</h2>
    <div class="filters">
      <input type="text" id="userSearch" placeholder="Rechercher..." oninput="filterUsers()">
      <button class="btn btn-refresh" onclick="loadUsers()">🔄 Actualiser</button>
    </div>
    <div id="usersContent"><div class="empty">Chargement...</div></div>
  </div>

  <div class="panel tab-content" id="tab-logs">
    <h2>📝 Logs récents</h2>
    <div class="filters">
      <input type="text" id="logIpFilter" placeholder="Filtrer par IP...">
      <select id="logEndpointFilter">
        <option value="">Tous les endpoints</option>
        <option value="/api/pair">/api/pair</option>
        <option value="/api/servers">/api/servers</option>
        <option value="/api/status">/api/status</option>
      </select>
      <label style="display:flex;align-items:center;gap:5px;color:#94a3b8;font-size:0.8rem">
        <input type="checkbox" id="logAttacksOnly"> Attaques seulement
      </label>
      <input type="number" id="logLimit" value="200" min="10" max="1000">
      <button class="btn btn-refresh" onclick="loadLogs()">🔄 Actualiser</button>
    </div>
    <div id="logsContent"><div class="empty">Chargement...</div></div>
  </div>

  <div class="panel tab-content" id="tab-banned">
    <h2>🚫 IPs bannies</h2>
    <button class="btn btn-refresh" onclick="loadBanned()">🔄 Actualiser</button>
    <div id="bannedContent"><div class="empty">Chargement...</div></div>
  </div>
</div>

<div class="modal-overlay" id="banModal">
  <div class="modal">
    <h3>🚫 Bannir une IP</h3>
    <p style="color:#94a3b8; font-size:0.85rem; margin-top:5px;">IP ciblée : <span class="ip" id="banModalIp">—</span></p>
    <label>Durée du ban</label>
    <select id="banDuration">
      <option value="3600000">1 heure</option>
      <option value="86400000" selected>24 heures</option>
      <option value="604800000">7 jours</option>
      <option value="2592000000">30 jours</option>
      <option value="permanent">Permanent</option>
    </select>
    <label>Raison (optionnel)</label>
    <input type="text" id="banReason" placeholder="Ex: Spam massif...">
    <div class="modal-actions">
      <button class="btn-cancel" onclick="closeBanModal()">Annuler</button>
      <button class="btn-confirm" onclick="confirmBan()">Confirmer le ban</button>
    </div>
  </div>
</div>

<script>
  const KEY = ${JSON.stringify(adminKey)};
  const API = window.location.origin;
  let currentBanIp = null;
  let allUsers = [];

  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
      const t = tab.dataset.tab;
      if (t === 'attacks') loadAttacks();
      if (t === 'overview') loadOverview();
      if (t === 'top') loadTop();
      if (t === 'countries') loadCountries();
      if (t === 'endpoints') loadEndpoints();
      if (t === 'users') loadUsers();
      if (t === 'logs') loadLogs();
      if (t === 'banned') loadBanned();
    });
  });

  async function fetchAdmin(endpoint) {
    const sep = endpoint.includes('?') ? '&' : '?';
    const res = await fetch(API + endpoint + sep + 'key=' + encodeURIComponent(KEY));
    if (!res.ok) throw new Error('HTTP ' + res.status);
    return res.json();
  }

  async function postAdmin(endpoint, body) {
    const sep = endpoint.includes('?') ? '&' : '?';
    const res = await fetch(API + endpoint + sep + 'key=' + encodeURIComponent(KEY), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {})
    });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    return res.json();
  }

  async function deleteAdmin(endpoint) {
    const sep = endpoint.includes('?') ? '&' : '?';
    const res = await fetch(API + endpoint + sep + 'key=' + encodeURIComponent(KEY), {
      method: 'DELETE'
    });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    return res.json();
  }

  async function loadAttacks() {
    try {
      const minutes = document.getElementById('attackMinutes').value || 5;
      const data = await fetchAdmin('/api/admin/attacks?minutes=' + minutes);
      
      if (!data.topAttackers || data.topAttackers.length === 0) {
        document.getElementById('attacksContent').innerHTML = '<div class="empty">✅ Aucune attaque détectée sur cette période</div>';
        return;
      }

      let html = '<div style="margin-bottom:15px;color:#ff9500;font-size:0.9rem">⚠️ <strong>' + data.total + ' attaques</strong> détectées sur les ' + minutes + ' dernières minutes</div>';
      
      html += '<h3 style="color:#ff006e;font-size:0.95rem;margin:15px 0 10px">🎯 Top Attaquants</h3>';
      html += '<table><thead><tr><th>#</th><th>IP</th><th>Pays</th><th>Attaques</th><th>Endpoints</th><th>Dernière</th><th>User-Agent</th><th>Actions</th></tr></thead><tbody>';
      data.topAttackers.forEach((a, i) => {
        const endpoints = Object.entries(a.endpoints).map(([k,v]) => k + '(' + v + ')').join(', ');
        html += '<tr class="attack-row">';
        html += '<td>' + (i+1) + '</td>';
        html += '<td class="ip">' + a.ip + '</td>';
        html += '<td><span class="flag">' + getFlagEmoji(a.country) + '</span>' + (a.country || '—') + '</td>';
        html += '<td class="count-attack">' + a.count + '</td>';
        html += '<td style="font-family:monospace;font-size:0.7rem">' + endpoints + '</td>';
        html += '<td style="font-size:0.72rem;color:#94a3b8">' + new Date(a.lastSeen).toLocaleString('fr-FR') + '</td>';
        html += '<td style="font-size:0.68rem;color:#64748b;max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + a.userAgent + '">' + (a.userAgent||'').substring(0,30) + '</td>';
        html += '<td>';
        html += '<button class="btn btn-ban" onclick="openBanModal(\\'' + a.ip + '\\')">Bannir</button>';
        html += '</td>';
        html += '</tr>';
      });
      html += '</tbody></table>';

      if (data.recentAttacks && data.recentAttacks.length > 0) {
        html += '<h3 style="color:#ff006e;font-size:0.95rem;margin:25px 0 10px">📋 Attaques récentes</h3>';
        html += '<table><thead><tr><th>Heure</th><th>IP</th><th>Pays</th><th>Endpoint</th><th>Méthode</th><th>UA</th></tr></thead><tbody>';
        data.recentAttacks.slice(0, 30).forEach(a => {
          html += '<tr class="attack-row">';
          html += '<td style="font-size:0.7rem;color:#94a3b8">' + new Date(a.timestamp).toLocaleString('fr-FR') + '</td>';
          html += '<td class="ip">' + a.ip + '</td>';
          html += '<td><span class="flag">' + getFlagEmoji(a.country) + '</span>' + (a.country || '—') + '</td>';
          html += '<td style="font-family:monospace;font-size:0.72rem">' + a.endpoint + '</td>';
          html += '<td>' + a.method + '</td>';
          html += '<td style="font-size:0.7rem;color:#64748b;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + (a.userAgent||'') + '">' + (a.userAgent||'—').substring(0,40) + '</td>';
          html += '</tr>';
        });
        html += '</tbody></table>';
      }

      document.getElementById('attacksContent').innerHTML = html;
    } catch (e) {
      document.getElementById('attacksContent').innerHTML = '<div class="empty">Erreur: ' + e.message + '</div>';
    }
  }

  async function loadOverview() {
    try {
      const data = await fetchAdmin('/api/admin/overview');
      document.getElementById('stat-totalIps').textContent = data.totalIPs;
      document.getElementById('stat-bannedIps').textContent = data.bannedIPs;
      document.getElementById('stat-botAttempts').textContent = data.botAttempts;
      document.getElementById('stat-recentAttacks').textContent = data.recentAttacks || 0;
      document.getElementById('stat-trustedIPs').textContent = data.trustedIPs || 0;
      document.getElementById('stat-countries').textContent = data.totalCountries;
      document.getElementById('stat-users').textContent = data.connectedUsers + '/' + data.totalUsers;
      document.getElementById('stat-logs').textContent = data.totalLogs;

      let html = '<table><thead><tr><th>Serveur</th><th>Statut</th><th>CPU</th><th>RAM</th></tr></thead><tbody>';
      data.servers.forEach(s => {
        html += '<tr>';
        html += '<td>' + s.name + '</td>';
        html += '<td>' + (s.online ? '<span class="ok">● En ligne</span>' : '<span class="banned">● Hors ligne</span>') + '</td>';
        html += '<td>' + (s.cpu || 0) + '%</td>';
        html += '<td>' + (s.ram || 0) + '%</td>';
        html += '</tr>';
      });
      html += '</tbody></table>';
      document.getElementById('overviewContent').innerHTML = html;
    } catch (e) {
      document.getElementById('overviewContent').innerHTML = '<div class="empty">Erreur: ' + e.message + '</div>';
    }
  }

  async function loadTop() {
    try {
      const limit = document.getElementById('topLimit').value || 50;
      const data = await fetchAdmin('/api/admin/top-ips?limit=' + limit);
      renderTop(data.top);
    } catch (e) {
      document.getElementById('topContent').innerHTML = '<div class="empty">Erreur: ' + e.message + '</div>';
    }
  }

  function getFlagEmoji(code) {
    if (!code || code.length !== 2) return '🌍';
    if (code === 'INTERNAL') return '🏠';
    try {
      return String.fromCodePoint(...[...code.toUpperCase()].map(c => 127397 + c.charCodeAt()));
    } catch(e) { return '🌍'; }
  }

  function renderTop(list) {
    if (!list || list.length === 0) {
      document.getElementById('topContent').innerHTML = '<div class="empty">Aucune IP enregistrée</div>';
      return;
    }
    let html = '<table><thead><tr><th>#</th><th>IP</th><th>Pays</th><th>Requêtes</th><th>Attaques</th><th>Statut</th><th>Actions</th></tr></thead><tbody>';
    list.forEach((item, i) => {
      const isAttacker = item.attacks > 0;
      const isTrusted = item.trusted;
      html += '<tr' + (isAttacker ? ' class="attack-row"' : (isTrusted ? ' class="trusted-row"' : '')) + '>';
      html += '<td>' + (i+1) + '</td>';
      html += '<td class="ip">' + item.ip + '</td>';
      html += '<td><span class="flag">' + getFlagEmoji(item.country) + '</span>' + (item.country || '—') + '</td>';
      html += '<td class="count">' + item.count + '</td>';
      html += '<td>' + (isAttacker ? '<span class="count-attack">' + item.attacks + '</span>' : '—') + '</td>';
      html += '<td>' + (isTrusted ? '<span class="badge-trusted">✅ Whitelist</span>' : (item.blocked ? '<span class="banned">BANNI</span>' : '<span class="ok">OK</span>')) + '</td>';
      html += '<td>';
      if (!isTrusted) {
        if (item.blocked) {
          html += '<button class="btn btn-unban" onclick="unban(\\'' + item.ip + '\\')">Débannir</button>';
        } else {
          html += '<button class="btn btn-ban" onclick="openBanModal(\\'' + item.ip + '\\')">Bannir</button>';
        }
        html += '<button class="btn btn-disconnect" onclick="disconnectIp(\\'' + item.ip + '\\')">Déconnecter</button>';
      } else {
        html += '<span style="color:#00ff80;font-size:0.7rem">✔ Jamais banni</span>';
      }
      html += '</td>';
      html += '</tr>';
    });
    html += '</tbody></table>';
    document.getElementById('topContent').innerHTML = html;
  }

  async function loadCountries() {
    try {
      const data = await fetchAdmin('/api/admin/countries');
      if (!data.countries || data.countries.length === 0) {
        document.getElementById('countriesContent').innerHTML = '<div class="empty">Aucun pays enregistré</div>';
        return;
      }
      let html = '<table><thead><tr><th>Pays</th><th>Code</th><th>Requêtes</th><th>Attaques</th><th>IPs uniques</th><th>Endpoint top</th><th>Dernière</th></tr></thead><tbody>';
      data.countries.forEach(c => {
        html += '<tr' + (c.attacks > 0 ? ' class="attack-row"' : '') + '>';
        html += '<td><span class="flag">' + getFlagEmoji(c.code) + '</span>' + c.code + '</td>';
        html += '<td style="color:#94a3b8">' + c.code + '</td>';
        html += '<td class="count">' + c.count + '</td>';
        html += '<td>' + (c.attacks > 0 ? '<span class="count-attack">' + c.attacks + '</span>' : '—') + '</td>';
        html += '<td>' + c.uniqueIPs + '</td>';
        html += '<td style="font-family:monospace;font-size:0.72rem">' + c.topEndpoint + '</td>';
        html += '<td style="font-size:0.72rem;color:#94a3b8">' + new Date(c.lastSeen).toLocaleString('fr-FR') + '</td>';
        html += '</tr>';
      });
      html += '</tbody></table>';
      document.getElementById('countriesContent').innerHTML = html;
    } catch (e) {
      document.getElementById('countriesContent').innerHTML = '<div class="empty">Erreur: ' + e.message + '</div>';
    }
  }

  async function loadEndpoints() {
    try {
      const data = await fetchAdmin('/api/admin/endpoints');
      if (!data.endpoints || data.endpoints.length === 0) {
        document.getElementById('endpointsContent').innerHTML = '<div class="empty">Aucun clic enregistré</div>';
        return;
      }
      let html = '<table><thead><tr><th>Endpoint</th><th>Clics</th><th>Attaques</th><th>IPs uniques</th><th>Méthodes</th></tr></thead><tbody>';
      data.endpoints.forEach(e => {
        const methods = Object.entries(e.methods).map(([m, c]) => m + ': ' + c).join(', ');
        html += '<tr' + (e.attacks > 0 ? ' class="attack-row"' : '') + '>';
        html += '<td style="font-family:monospace;color:#00e5ff">' + e.endpoint + '</td>';
        html += '<td class="count">' + e.count + '</td>';
        html += '<td>' + (e.attacks > 0 ? '<span class="count-attack">' + e.attacks + '</span>' : '—') + '</td>';
        html += '<td>' + e.uniqueIPs + '</td>';
        html += '<td style="font-size:0.72rem;color:#94a3b8">' + methods + '</td>';
        html += '</tr>';
      });
      html += '</tbody></table>';
      document.getElementById('endpointsContent').innerHTML = html;
    } catch (e) {
      document.getElementById('endpointsContent').innerHTML = '<div class="empty">Erreur: ' + e.message + '</div>';
    }
  }

  async function loadUsers() {
    try {
      const data = await fetchAdmin('/api/admin/users');
      allUsers = data.users || [];
      filterUsers();
    } catch (e) {
      document.getElementById('usersContent').innerHTML = '<div class="empty">Erreur: ' + e.message + '</div>';
    }
  }

  function filterUsers() {
    const q = (document.getElementById('userSearch').value || '').toLowerCase();
    const list = allUsers.filter(u =>
      !q || u.phone.includes(q) || (u.ip || '').includes(q) || (u.country || '').toLowerCase().includes(q)
    );
    renderUsers(list);
  }

  function renderUsers(list) {
    if (!list || list.length === 0) {
      document.getElementById('usersContent').innerHTML = '<div class="empty">Aucun utilisateur</div>';
      return;
    }
    let html = '<table><thead><tr><th>Numéro</th><th>Serveur</th><th>Statut</th><th>IP</th><th>Pays</th><th>Token</th><th>Créé</th><th>Actions</th></tr></thead><tbody>';
    list.forEach(u => {
      const badge = u.status === 'connected' ? 'badge-connected' :
                    u.status === 'pending' ? 'badge-pending' :
                    u.status === 'error' ? 'badge-error' : 'badge-disconnected';
      html += '<tr>';
      html += '<td class="ip">+' + u.phone + '</td>';
      html += '<td>' + u.serverId + '</td>';
      html += '<td><span class="badge ' + badge + '">' + u.status + '</span></td>';
      html += '<td style="font-family:monospace;font-size:0.72rem">' + (u.ip || '—') + '</td>';
      html += '<td><span class="flag">' + getFlagEmoji(u.country) + '</span>' + (u.country || '—') + '</td>';
      html += '<td>' + (u.hasSessionToken ? '🔐' : '⚠️') + '</td>';
      html += '<td style="font-size:0.7rem;color:#94a3b8">' + (u.createdAt ? new Date(u.createdAt).toLocaleString('fr-FR') : '—') + '</td>';
      html += '<td>';
      if (u.status !== 'disconnected') {
        html += '<button class="btn btn-disconnect" onclick="disconnectUser(\\'' + u.phone + '\\')">Déconnecter</button>';
      }
      html += '<button class="btn btn-delete" onclick="deleteUser(\\'' + u.phone + '\\')">Supprimer</button>';
      html += '</td>';
      html += '</tr>';
    });
    html += '</tbody></table>';
    document.getElementById('usersContent').innerHTML = html;
  }

  async function loadLogs() {
    try {
      const limit = document.getElementById('logLimit').value || 200;
      const ipFilter = document.getElementById('logIpFilter').value;
      const epFilter = document.getElementById('logEndpointFilter').value;
      const attacksOnly = document.getElementById('logAttacksOnly').checked;
      let url = '/api/admin/logs?limit=' + limit;
      if (ipFilter) url += '&ip=' + encodeURIComponent(ipFilter);
      if (epFilter) url += '&endpoint=' + encodeURIComponent(epFilter);
      if (attacksOnly) url += '&attacks=true';
      const data = await fetchAdmin(url);
      if (!data.logs || data.logs.length === 0) {
        document.getElementById('logsContent').innerHTML = '<div class="empty">Aucun log</div>';
        return;
      }
      let html = '<table><thead><tr><th>Heure</th><th>IP</th><th>Pays</th><th>Méthode</th><th>Endpoint</th><th>UA</th><th>Type</th></tr></thead><tbody>';
      data.logs.forEach(log => {
        const date = new Date(log.timestamp).toLocaleString('fr-FR');
        html += '<tr' + (log.isAttack ? ' class="attack-row"' : (log.trusted ? ' class="trusted-row"' : '')) + '>';
        html += '<td style="font-size:0.7rem;color:#94a3b8">' + date + '</td>';
        html += '<td class="ip">' + log.ip + '</td>';
        html += '<td><span class="flag">' + getFlagEmoji(log.country) + '</span>' + (log.country || '—') + '</td>';
        html += '<td>' + log.method + '</td>';
        html += '<td style="font-family:monospace;font-size:0.72rem">' + log.endpoint + '</td>';
        html += '<td style="font-size:0.7rem;color:#64748b;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + (log.userAgent||'') + '">' + (log.userAgent||'—').substring(0,50) + '</td>';
        html += '<td>' + (log.trusted ? '<span class="badge-trusted">✅ Confiance</span>' : (log.isAttack ? '<span class="badge-attack">🚨 Attaque</span>' : '<span class="ok">✓</span>')) + '</td>';
        html += '</tr>';
      });
      html += '</tbody></table>';
      document.getElementById('logsContent').innerHTML = html;
    } catch (e) {
      document.getElementById('logsContent').innerHTML = '<div class="empty">Erreur: ' + e.message + '</div>';
    }
  }

  async function loadBanned() {
    try {
      const data = await fetchAdmin('/api/admin/blacklist');
      const list = Object.entries(data.ips || {});
      if (list.length === 0) {
        document.getElementById('bannedContent').innerHTML = '<div class="empty">Aucune IP bannie 🎉</div>';
        return;
      }
      let html = '<table><thead><tr><th>IP</th><th>Raison</th><th>Banni le</th><th>Expire</th><th>Actions</th></tr></thead><tbody>';
      list.forEach(([ip, info]) => {
        const bannedAt = info.bannedAt ? new Date(info.bannedAt).toLocaleString('fr-FR') : '—';
        const bannedUntil = info.bannedUntil === 'permanent' ? 'PERMANENT' :
                            info.bannedUntil ? new Date(info.bannedUntil).toLocaleString('fr-FR') : '—';
        html += '<tr>';
        html += '<td class="ip">' + ip + '</td>';
        html += '<td style="font-size:0.78rem;color:#94a3b8">' + (info.reason || '—') + '</td>';
        html += '<td style="font-size:0.72rem">' + bannedAt + '</td>';
        html += '<td style="font-size:0.72rem;color:#ff006e">' + bannedUntil + '</td>';
        html += '<td><button class="btn btn-unban" onclick="unban(\\'' + ip + '\\')">Débannir</button></td>';
        html += '</tr>';
      });
      html += '</tbody></table>';
      document.getElementById('bannedContent').innerHTML = html;
    } catch (e) {
      document.getElementById('bannedContent').innerHTML = '<div class="empty">Erreur: ' + e.message + '</div>';
    }
  }

  function openBanModal(ip) {
    currentBanIp = ip;
    document.getElementById('banModalIp').textContent = ip;
    document.getElementById('banModal').classList.add('active');
  }
  function closeBanModal() {
    document.getElementById('banModal').classList.remove('active');
    currentBanIp = null;
  }
  async function confirmBan() {
    if (!currentBanIp) return;
    const durationVal = document.getElementById('banDuration').value;
    const reason = document.getElementById('banReason').value || 'Ban manuel admin';
    const body = {
      reason,
      duration: durationVal === 'permanent' ? 'permanent' : parseInt(durationVal)
    };
    try {
      await postAdmin('/api/admin/ban/' + currentBanIp, body);
      closeBanModal();
      loadTop(); loadBanned(); loadOverview();
    } catch(e) { alert('Erreur: ' + e.message); }
  }

  async function unban(ip) {
    if (!confirm('Débannir ' + ip + ' ?')) return;
    try {
      await postAdmin('/api/admin/unban/' + ip);
      loadTop(); loadBanned(); loadOverview();
    } catch(e) { alert('Erreur: ' + e.message); }
  }

  async function disconnectIp(ip) {
    if (!confirm('Déconnecter TOUS les utilisateurs de ' + ip + ' ?')) return;
    try {
      const r = await postAdmin('/api/admin/disconnect-ip/' + ip);
      alert('✅ ' + r.count + ' utilisateur(s) déconnecté(s)');
      loadUsers(); loadTop();
    } catch(e) { alert('Erreur: ' + e.message); }
  }

  async function disconnectUser(phone) {
    if (!confirm('Déconnecter +' + phone + ' ?')) return;
    try {
      await postAdmin('/api/admin/disconnect-user/' + phone);
      alert('✅ Déconnexion en cours');
      loadUsers();
    } catch(e) { alert('Erreur: ' + e.message); }
  }

  async function deleteUser(phone) {
    if (!confirm('Supprimer DÉFINITIVEMENT +' + phone + ' ?')) return;
    try {
      await deleteAdmin('/api/admin/user/' + phone);
      loadUsers();
    } catch(e) { alert('Erreur: ' + e.message); }
  }

  async function loadAll() {
    await loadOverview();
    await loadTop();
  }

  loadAttacks();
  loadOverview();
  setInterval(() => {
    const activeTab = document.querySelector('.tab.active')?.dataset.tab;
    if (activeTab === 'attacks') loadAttacks();
    if (activeTab === 'overview') loadOverview();
  }, 10000);

  document.getElementById('banModal').addEventListener('click', e => {
    if (e.target.id === 'banModal') closeBanModal();
  });
</script>
</body>
</html>`);
});

// ==================== PING DES SERVEURS ====================
async function pingServers() {
  for (const server of SERVERS) {
    if (!server.url || server.url.trim() === '') {
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
        signal: controller.signal,
        headers: {
          'X-Admin-Key': ADMIN_KEY,
          'X-API-KEY': API_KEY
        }
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
setInterval(() => {
  const now = Date.now();
  const thirtyDaysAgo = now - 30 * 24 * 60 * 60 * 1000;

  ipLogs.logs = ipLogs.logs.filter(l => new Date(l.timestamp).getTime() > thirtyDaysAgo);

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
  console.log(`   • Ban auto après    : ${BAN_CONFIG.maxViolations} violations`);
  console.log(`   • Anti-énumération  : max ${ENUM_CONFIG.maxDistinctPhones} numéros/h par IP`);
  console.log(`   • Session token     : REQUIS sur /status et /disconnect`);
  console.log(`   • Turnstile         : ${TURNSTILE_ENABLED ? '✅ ACTIVÉ' : '⚠️ DÉSACTIVÉ'}`);
  console.log(`   • API Key           : ${API_KEY.substring(0, 8)}...`);
  console.log(`   • Admin Key         : ${ADMIN_KEY.substring(0, 8)}...`);
  console.log(`   • Trust proxy       : ${TRUST_PROXY}`);
  console.log('────────────────────────────────────────');
  console.log(`✅ WHITELIST (${TRUSTED_IPS.length} IPs) :`);
  TRUSTED_IPS.forEach(ip => console.log(`   • ${ip}`));
  console.log(`   • + IPs privées (10.x, 192.168.x, 172.16-31.x, 127.x)`);
  console.log('────────────────────────────────────────');
  console.log(`🧹 Stats exclues :`);
  STATS_EXCLUDED_PATHS.forEach(p => console.log(`   • ${p}*`));
  console.log('────────────────────────────────────────');
  console.log(`🔐 Page admin : /admin?key=${ADMIN_KEY.substring(0,8)}...`);
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
