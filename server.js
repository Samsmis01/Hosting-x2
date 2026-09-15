// server.js
// Serveur maître HEXTECH - Gère 4 workers KataBump

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ==================== CONFIGURATION ====================
const MAX_USERS_PER_SERVER = 4;
const USERS_FILE = './users.json';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
const ADMIN_KEY = process.env.ADMIN_KEY || 'xenoban-admin-2026';

// ==================== CONFIGURATION DES 4 SERVEURS ====================
// ⚠️ L'URL est celle de ton serveur Render
// Tu dois remplacer les URLs par celles de tes 4 workers KataBump
const SERVERS = [
  {
    id: 1,
    name: 'Serveur 1',
    url: 'https://last-judment.onrender.com/',
    lastPing: 0,
    online: false,
    cpu: 0,
    ram: 0,
    uptime: 0
  },
  {
    id: 2,
    name: 'Serveur 2',
    url: 'https://last-judment.onrender.com/',
    lastPing: 0,
    online: false,
    cpu: 0,
    ram: 0,
    uptime: 0
  },
  {
    id: 3,
    name: 'Serveur 3',
    url: 'https://last-judment.onrender.com/',
    lastPing: 0,
    online: false,
    cpu: 0,
    ram: 0,
    uptime: 0
  },
  {
    id: 4,
    name: 'Serveur 4',
    url: 'https://last-judment.onrender.com/',
    lastPing: 0,
    online: false,
    cpu: 0,
    ram: 0,
    uptime: 0
  }
];

// ==================== SÉCURITÉ ====================
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
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

// ==================== CHIFFREMENT AES-256 ====================
function encrypt(text) {
  try {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
  } catch (e) {
    return null;
  }
}

function decrypt(text) {
  try {
    const [ivHex, encryptedHex] = text.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
    let decrypted = decipher.update(Buffer.from(encryptedHex, 'hex'));
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
  } catch (e) {
    return null;
  }
}

// ==================== SYSTÈME DE QUEUE ====================
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

// ==================== ROUTES PUBLIQUES ====================

// Page d'accueil (JSON si pas de index.html)
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
app.post('/api/pair', async (req, res) => {
  const { phone, consent, serverId } = req.body;

  // ========== VALIDATION ==========
  if (!consent) {
    return res.status(400).json({ error: 'Consentement requis' });
  }

  if (!phone || !/^\d{9,15}$/.test(phone)) {
    return res.status(400).json({ error: 'Numéro invalide (9-15 chiffres)' });
  }

  // ========== AUTO-SÉLECTION DU SERVEUR ==========
  let targetServerId = serverId;
  const users = loadUsers();

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

  if (!server) {
    return res.status(404).json({ error: 'Serveur introuvable' });
  }

  if (!server.online) {
    return res.status(503).json({ error: `Le ${server.name} est actuellement hors ligne` });
  }

  // ========== VÉRIFIER SI LE SERVEUR EST PLEIN ==========
  const currentOnServer = Object.values(users).filter(u =>
    u.serverId === targetServerId && u.status !== 'disconnected'
  ).length;

  if (currentOnServer >= MAX_USERS_PER_SERVER) {
    return res.status(503).json({
      error: `Le ${server.name} est plein (${currentOnServer}/${MAX_USERS_PER_SERVER}). Choisissez un autre serveur.`
    });
  }

  // ========== VÉRIFIER SI DÉJÀ COUPLÉ ==========
  if (users[phone] && users[phone].status === 'connected') {
    return res.status(409).json({
      error: 'Ce numéro est déjà couplé. Déconnectez-le d\'abord.'
    });
  }

  // ========== RÉUTILISER LE CODE SI EXISTANT ==========
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

  // ========== CRÉER L'UTILISATEUR ==========
  users[phone] = {
    phone,
    serverId: targetServerId,
    createdAt: users[phone]?.createdAt || Date.now(),
    status: 'pending',
    code: null,
    ip: req.ip
  };
  saveUsers(users);

  // ========== DEMANDER LE CODE AU WORKER ==========
  try {
    const code = await createRequest(phone, targetServerId);

    if (!code) throw new Error('Aucun code retourné par le worker');

    users[phone].code = code;
    users[phone].status = 'pending';
    saveUsers(users);

    console.log(`✅ Code généré pour ${phone} sur ${server.name}: ${code}`);

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
});

// ==================== ROUTE : STATUT ====================
app.get('/api/status/:phone', (req, res) => {
  const { phone } = req.params;
  const users = loadUsers();

  if (!users[phone]) {
    return res.status(404).json({ error: 'Numéro non enregistré' });
  }

  res.json({
    phone: users[phone].phone,
    serverId: users[phone].serverId,
    status: users[phone].status,
    createdAt: users[phone].createdAt,
    connectedAt: users[phone].connectedAt || null
  });
});

// ==================== ROUTE : DÉCONNEXION ====================
app.post('/api/disconnect/:phone', (req, res) => {
  const { phone } = req.params;
  const users = loadUsers();

  if (!users[phone]) {
    return res.status(404).json({ error: 'Numéro non enregistré' });
  }

  users[phone].status = 'disconnect_requested';
  users[phone].disconnectAt = Date.now();
  saveUsers(users);

  console.log(`🚪 Déconnexion demandée pour ${phone} (Server ${users[phone].serverId})`);
  res.json({ success: true, message: 'Déconnexion en cours...' });
});

// ==================== ROUTES WORKER ====================

// ========== LE WORKER DEMANDE LES REQUÊTES ==========
app.get('/api/worker/:serverId/pending', (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) {
    return res.status(401).json({ error: 'Non autorisé' });
  }

  const serverId = parseInt(req.params.serverId);
  if (![1, 2, 3, 4].includes(serverId)) {
    return res.status(400).json({ error: 'Serveur invalide' });
  }

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

// ========== LE WORKER RENVOIE LE RÉSULTAT ==========
app.post('/api/worker/:serverId/result', (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) {
    return res.status(401).json({ error: 'Non autorisé' });
  }

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

// ========== LE WORKER SIGNALE UNE CONNEXION ==========
app.post('/api/worker/:serverId/connected', (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) {
    return res.status(401).json({ error: 'Non autorisé' });
  }

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

// ========== LE WORKER SIGNALE UNE DÉCONNEXION ==========
app.post('/api/worker/:serverId/disconnected', (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) {
    return res.status(401).json({ error: 'Non autorisé' });
  }

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

// ========== LE WORKER DEMANDE LES DÉCONNEXIONS ==========
app.get('/api/worker/:serverId/disconnect-list', (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) {
    return res.status(401).json({ error: 'Non autorisé' });
  }

  const serverId = parseInt(req.params.serverId);
  const users = loadUsers();

  const toDisconnect = Object.keys(users).filter(p =>
    users[p].serverId === serverId && users[p].status === 'disconnect_requested'
  );

  res.json(toDisconnect);
});

// ========== LE WORKER CONFIRME LA DÉCONNEXION ==========
app.post('/api/worker/:serverId/disconnect-done', (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) {
    return res.status(401).json({ error: 'Non autorisé' });
  }

  const { phone } = req.body;
  const users = loadUsers();

  if (users[phone]) {
    delete users[phone];
    saveUsers(users);
    console.log(`🗑️ Utilisateur ${phone} supprimé (Server ${req.params.serverId})`);
  }

  res.json({ success: true });
});

// ========== LE WORKER ENVOIE SES STATS ==========
app.post('/api/worker/:serverId/stats', (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) {
    return res.status(401).json({ error: 'Non autorisé' });
  }

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

// ==================== PING DES SERVEURS ====================
async function pingServers() {
  for (const server of SERVERS) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 8000);

      const res = await fetch(`${server.url}/health`, {
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
      } else {
        server.online = false;
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

// ==================== DÉMARRAGE ====================
app.listen(PORT, '0.0.0.0', () => {
  console.log('════════════════════════════════════════');
  console.log(`🚀 Serveur maître HEXTECH démarré`);
  console.log(`📊 Port : ${PORT}`);
  console.log(`🔐 Clé API Admin : ${ADMIN_KEY.substring(0, 8)}...`);
  console.log(`🖥️ ${SERVERS.length} serveurs workers configurés :`);
  SERVERS.forEach(s => {
    console.log(`   • Server ${s.id} (${s.name}) → ${s.url}`);
  });
  console.log(`👥 Max par serveur : ${MAX_USERS_PER_SERVER}`);
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
  process.exit(0);
});
