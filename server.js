// server.js
// Serveur maître HEXTECH - Gère 4 workers KataBump
// 🔐 Avec admin intégré + whitelist + stats temps réel

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ==================== CONFIGURATION ====================
const MAX_USERS_PER_SERVER = 9;
const USERS_FILE = './users.json';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
const ADMIN_KEY = process.env.ADMIN_KEY || 'xenoban-admin-2026';

// 🆕 WHITELIST IPs de confiance
const TRUSTED_IPS = [
  '127.0.0.1',
  '::1',
  'localhost',
  '51.75.118.170',   // Worker Render
];

function isTrustedIP(ip) {
  if (!ip) return false;
  if (TRUSTED_IPS.includes(ip)) return true;
  if (ip === '127.0.0.1' || ip === '::1') return true;
  if (ip.startsWith('10.')) return true;
  if (ip.startsWith('192.168.')) return true;
  if (ip.startsWith('172.')) {
    const s = parseInt(ip.split('.')[1]);
    if (s >= 16 && s <= 31) return true;
  }
  return false;
}

function getClientIP(req) {
  const cfIP = req.headers['cf-connecting-ip'];
  if (cfIP) return cfIP;
  const xff = req.headers['x-forwarded-for'];
  if (xff) return xff.split(',')[0].trim();
  const xri = req.headers['x-real-ip'];
  if (xri) return xri;
  return req.ip || req.connection?.remoteAddress || 'unknown';
}

// ==================== CONFIGURATION DES 4 SERVEURS ====================
const SERVERS = [
  { id: 1, name: 'Serveur 1', url: process.env.SERVER_1_URL || 'https://last-judment.onrender.com/', lastPing: 0, online: false, cpu: 0, ram: 0, uptime: 0 },
  { id: 2, name: 'Serveur 2', url: process.env.SERVER_2_URL || 'https://last-judment.onrender.com/', lastPing: 0, online: false, cpu: 0, ram: 0, uptime: 0 },
  { id: 3, name: 'Serveur 3', url: process.env.SERVER_3_URL || 'https://last-judment.onrender.com/', lastPing: 0, online: false, cpu: 0, ram: 0, uptime: 0 },
  { id: 4, name: 'Serveur 4', url: process.env.SERVER_4_URL || 'https://last-judment.onrender.com/', lastPing: 0, online: false, cpu: 0, ram: 0, uptime: 0 }
];

// ==================== SÉCURITÉ ====================
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname)));

// ==================== BASE DE DONNÉES ====================
function loadUsers() {
  try {
    if (fs.existsSync(USERS_FILE)) return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  } catch (e) { console.error('Erreur lecture users:', e.message); }
  return {};
}

function saveUsers(users) {
  try { fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2)); }
  catch (e) { console.error('Erreur sauvegarde users:', e.message); }
}

// ==================== CHIFFREMENT AES-256 ====================
function encrypt(text) {
  try {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
  } catch (e) { return null; }
}

function decrypt(text) {
  try {
    const [ivHex, encryptedHex] = text.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
    let decrypted = decipher.update(Buffer.from(encryptedHex, 'hex'));
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
  } catch (e) { return null; }
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
    pendingRequests.set(requestId, { phone, serverId, resolve, reject, timeout, createdAt: Date.now() });
  });
}

// ==================== 🔐 AUTH ADMIN ====================
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
  if (!isAdminAuthorized(req)) {
    return res.status(401).json({ error: 'Non autorisé' });
  }
  next();
}

// ==================== 🔒 AUTH WORKER ====================
function checkWorkerAuth(req, res, next) {
  const adminKey = req.headers['x-admin-key'];
  const ip = getClientIP(req);
  if (adminKey === ADMIN_KEY) return next();
  if (isTrustedIP(ip)) return next();
  console.log(`🚫 Worker refusé : ip=${ip}`);
  return res.status(401).json({ error: 'Non autorisé' });
}

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

// 🆕 HEALTH — pour le ping du worker
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    uptime: Math.floor(process.uptime()),
    ip: getClientIP(req)
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

  if (!consent) return res.status(400).json({ error: 'Consentement requis' });
  if (!phone || !/^\d{9,15}$/.test(phone)) return res.status(400).json({ error: 'Numéro invalide (9-15 chiffres)' });

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
    if (!targetServerId) return res.status(503).json({ error: 'Aucun serveur disponible. Réessayez plus tard.' });
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

  users[phone] = {
    phone,
    serverId: targetServerId,
    createdAt: users[phone]?.createdAt || Date.now(),
    status: 'pending',
    code: null,
    ip: getClientIP(req)
  };
  saveUsers(users);

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
  if (!users[phone]) return res.status(404).json({ error: 'Numéro non enregistré' });
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
  if (!users[phone]) return res.status(404).json({ error: 'Numéro non enregistré' });

  users[phone].status = 'disconnect_requested';
  users[phone].disconnectAt = Date.now();
  saveUsers(users);

  console.log(`🚪 Déconnexion demandée pour ${phone} (Server ${users[phone].serverId})`);
  res.json({ success: true, message: 'Déconnexion en cours...' });
});

// ==================== ROUTES WORKER ====================

app.get('/api/worker/:serverId/pending', checkWorkerAuth, (req, res) => {
  const serverId = parseInt(req.params.serverId);
  if (![1, 2, 3, 4].includes(serverId)) return res.status(400).json({ error: 'Serveur invalide' });

  const server = SERVERS.find(s => s.id === serverId);
  if (server) { server.lastPing = Date.now(); server.online = true; }

  const requests = [];
  for (const [id, req] of pendingRequests.entries()) {
    if (req.serverId === serverId) requests.push({ id, phone: req.phone });
  }
  res.json(requests);
});

app.post('/api/worker/:serverId/result', checkWorkerAuth, (req, res) => {
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

app.post('/api/worker/:serverId/connected', checkWorkerAuth, (req, res) => {
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

app.post('/api/worker/:serverId/disconnected', checkWorkerAuth, (req, res) => {
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

app.get('/api/worker/:serverId/disconnect-list', checkWorkerAuth, (req, res) => {
  const serverId = parseInt(req.params.serverId);
  const users = loadUsers();
  const toDisconnect = Object.keys(users).filter(p =>
    users[p].serverId === serverId && users[p].status === 'disconnect_requested'
  );
  res.json(toDisconnect);
});

app.post('/api/worker/:serverId/disconnect-done', checkWorkerAuth, (req, res) => {
  const { phone } = req.body;
  const users = loadUsers();
  if (users[phone]) {
    delete users[phone];
    saveUsers(users);
    console.log(`🗑️ Utilisateur ${phone} supprimé (Server ${req.params.serverId})`);
  }
  res.json({ success: true });
});

// 🔥 ROUTE CRITIQUE POUR CPU/RAM
app.post('/api/worker/:serverId/stats', checkWorkerAuth, (req, res) => {
  const serverId = parseInt(req.params.serverId);
  const { cpu, ram, uptime } = req.body;
  const server = SERVERS.find(s => s.id === serverId);

  if (server) {
    server.cpu = cpu || 0;
    server.ram = ram || 0;
    server.uptime = uptime || 0;
    server.lastPing = Date.now();
    server.online = true;
    console.log(`📊 [Server ${serverId}] CPU=${server.cpu}% RAM=${server.ram}%`);
  }
  res.json({ success: true, serverId, cpu: server?.cpu, ram: server?.ram });
});

// ==================== 🔐 ROUTES ADMIN ====================

app.get('/api/admin/overview', requireAdmin, (req, res) => {
  const users = loadUsers();
  res.json({
    totalUsers: Object.keys(users).length,
    connectedUsers: Object.values(users).filter(u => u.status === 'connected').length,
    pendingUsers: Object.values(users).filter(u => u.status === 'pending').length,
    uptime: Math.floor(process.uptime()),
    servers: SERVERS.map(s => ({
      id: s.id, name: s.name, online: s.online, cpu: s.cpu, ram: s.ram, uptime: s.uptime
    }))
  });
});

app.get('/api/admin/users', requireAdmin, (req, res) => {
  const users = loadUsers();
  const list = Object.entries(users).map(([phone, u]) => ({
    phone, serverId: u.serverId, status: u.status,
    ip: u.ip || '—', createdAt: u.createdAt, connectedAt: u.connectedAt || null, code: u.code || null
  })).sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  res.json({ total: list.length, users: list });
});

app.post('/api/admin/disconnect-user/:phone', requireAdmin, (req, res) => {
  const { phone } = req.params;
  const users = loadUsers();
  if (!users[phone]) return res.status(404).json({ error: 'Utilisateur non trouvé' });

  users[phone].status = 'disconnect_requested';
  users[phone].disconnectAt = Date.now();
  saveUsers(users);
  console.log(`🚪 Admin déconnexion ${phone}`);
  res.json({ success: true, phone });
});

app.delete('/api/admin/user/:phone', requireAdmin, (req, res) => {
  const { phone } = req.params;
  const users = loadUsers();
  if (!users[phone]) return res.status(404).json({ error: 'Utilisateur non trouvé' });
  delete users[phone];
  saveUsers(users);
  console.log(`🗑️ Admin suppression ${phone}`);
  res.json({ success: true, phone });
});

// ==================== 🔐 PAGE ADMIN HTML ====================
app.get('/admin', (req, res) => {
  if (!isAdminAuthorized(req)) {
    return res.status(401).send(`
      <html><body style="background:#0a0e1a;color:#fff;font-family:sans-serif;padding:40px;text-align:center;">
        <h1>🔒 JE T'AI EU 😂 </h1>
        <p>AMATEUR, MAINTENANT TU VAS T'ABONNER DANS MON PUTAIN DE CANAL https://t.me/hextechcar OU SINON JE PEUT TE TRAQUER EN TOUT MOMENT CAR J'AI TES CORDONNÉES 😉</p>
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
  .container { max-width:1200px; margin:0 auto; }
  h1 { font-size:2rem; background:linear-gradient(135deg,#00c8ff,#7b2ff7); -webkit-background-clip:text; -webkit-text-fill-color:transparent; background-clip:text; margin-bottom:10px; }
  .subtitle { color:#64748b; margin-bottom:25px; font-size:0.9rem; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin-bottom:25px; }
  .card { background:#0f131a; border:1px solid #1e2532; border-radius:12px; padding:16px; }
  .card .label { font-size:0.65rem; color:#64748b; text-transform:uppercase; letter-spacing:1px; margin-bottom:6px; }
  .card .value { font-size:1.6rem; font-weight:700; color:#00c8ff; }
  .card.success .value { color:#00ff80; }
  .card.warning .value { color:#ff9500; }
  .panel { background:#0f131a; border:1px solid #1e2532; border-radius:12px; padding:20px; margin-bottom:20px; }
  .panel h2 { font-size:1.05rem; color:#fff; margin-bottom:15px; }
  table { width:100%; border-collapse:collapse; }
  th { text-align:left; padding:10px; background:#080a10; color:#64748b; font-size:0.7rem; text-transform:uppercase; letter-spacing:1px; border-bottom:1px solid #1e2532; }
  td { padding:10px; border-bottom:1px solid #1e2532; font-size:0.8rem; }
  tr:hover { background:rgba(0,200,255,0.03); }
  .ip { font-family:monospace; color:#00e5ff; font-weight:600; }
  .ok { color:#00ff80; font-weight:700; }
  .off { color:#ff006e; font-weight:700; }
  .btn { padding:6px 12px; border-radius:6px; border:none; cursor:pointer; font-size:0.72rem; font-weight:600; margin:2px; }
  .btn-disconnect { background:#ff9500; color:#080a10; }
  .btn-delete { background:#ff006e; color:#fff; }
  .btn-refresh { background:#1e2532; color:#e2e8f0; padding:10px 20px; margin-bottom:15px; font-size:0.85rem; }
  .badge { display:inline-block; padding:3px 8px; border-radius:20px; font-size:0.65rem; font-weight:700; }
  .badge-connected { background:rgba(0,255,128,0.15); color:#00ff80; }
  .badge-pending { background:rgba(255,149,0,0.15); color:#ff9500; }
  .badge-error { background:rgba(255,0,110,0.15); color:#ff006e; }
  .empty { text-align:center; color:#64748b; padding:30px; }
</style>
</head>
<body>
<div class="container">
  <h1>🔐 HEXTECH — Admin</h1>
  <p class="subtitle">Gestion des utilisateurs et surveillance des serveurs</p>

  <div class="cards">
    <div class="card"><div class="label">Utilisateurs</div><div class="value" id="stat-totalUsers">—</div></div>
    <div class="card success"><div class="label">Connectés</div><div class="value" id="stat-connected">—</div></div>
    <div class="card warning"><div class="label">En attente</div><div class="value" id="stat-pending">—</div></div>
    <div class="card"><div class="label">Uptime</div><div class="value" id="stat-uptime" style="font-size:1.1rem">—</div></div>
  </div>

  <div class="panel">
    <h2>🖥️ Serveurs</h2>
    <button class="btn btn-refresh" onclick="loadAll()">🔄 Rafraîchir</button>
    <div id="serversContent"><div class="empty">Chargement...</div></div>
  </div>

  <div class="panel">
    <h2>👥 Utilisateurs</h2>
    <div id="usersContent"><div class="empty">Chargement...</div></div>
  </div>
</div>

<script>
  const KEY = ${JSON.stringify(adminKey)};
  const API = window.location.origin;

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
    const res = await fetch(API + endpoint + sep + 'key=' + encodeURIComponent(KEY), { method: 'DELETE' });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    return res.json();
  }

  async function loadOverview() {
    try {
      const data = await fetchAdmin('/api/admin/overview');
      document.getElementById('stat-totalUsers').textContent = data.totalUsers;
      document.getElementById('stat-connected').textContent = data.connectedUsers;
      document.getElementById('stat-pending').textContent = data.pendingUsers;
      const u = Math.floor(data.uptime);
      document.getElementById('stat-uptime').textContent = Math.floor(u / 86400) + 'j ' + Math.floor((u % 86400) / 3600) + 'h ' + Math.floor((u % 3600) / 60) + 'm';

      let html = '<table><thead><tr><th>Serveur</th><th>Statut</th><th>CPU</th><th>RAM</th><th>Uptime</th></tr></thead><tbody>';
      data.servers.forEach(s => {
        html += '<tr>';
        html += '<td>' + s.name + '</td>';
        html += '<td>' + (s.online ? '<span class="ok">● En ligne</span>' : '<span class="off">● Hors ligne</span>') + '</td>';
        html += '<td>' + (s.cpu || 0) + '%</td>';
        html += '<td>' + (s.ram || 0) + '%</td>';
        html += '<td>' + Math.floor((s.uptime || 0) / 60) + ' min</td>';
        html += '</tr>';
      });
      html += '</tbody></table>';
      document.getElementById('serversContent').innerHTML = html;
    } catch (e) {
      document.getElementById('serversContent').innerHTML = '<div class="empty">Erreur: ' + e.message + '</div>';
    }
  }

  async function loadUsers() {
    try {
      const data = await fetchAdmin('/api/admin/users');
      if (!data.users || data.users.length === 0) {
        document.getElementById('usersContent').innerHTML = '<div class="empty">Aucun utilisateur</div>';
        return;
      }
      let html = '<table><thead><tr><th>Numéro</th><th>Serveur</th><th>Statut</th><th>IP</th><th>Créé</th><th>Actions</th></tr></thead><tbody>';
      data.users.forEach(u => {
        const badge = u.status === 'connected' ? 'badge-connected' : u.status === 'pending' ? 'badge-pending' : 'badge-error';
        html += '<tr>';
        html += '<td class="ip">+' + u.phone + '</td>';
        html += '<td>' + u.serverId + '</td>';
        html += '<td><span class="badge ' + badge + '">' + u.status + '</span></td>';
        html += '<td style="font-family:monospace;font-size:0.72rem">' + (u.ip || '—') + '</td>';
        html += '<td style="font-size:0.7rem;color:#94a3b8">' + (u.createdAt ? new Date(u.createdAt).toLocaleString('fr-FR') : '—') + '</td>';
        html += '<td>';
        if (u.status !== 'disconnected') html += '<button class="btn btn-disconnect" onclick="disconnectUser(\\'' + u.phone + '\\')">Déconnecter</button>';
        html += '<button class="btn btn-delete" onclick="deleteUser(\\'' + u.phone + '\\')">Supprimer</button>';
        html += '</td></tr>';
      });
      html += '</tbody></table>';
      document.getElementById('usersContent').innerHTML = html;
    } catch (e) {
      document.getElementById('usersContent').innerHTML = '<div class="empty">Erreur: ' + e.message + '</div>';
    }
  }

  async function disconnectUser(phone) {
    if (!confirm('Déconnecter +' + phone + ' ?')) return;
    try { await postAdmin('/api/admin/disconnect-user/' + phone); loadUsers(); }
    catch(e) { alert('Erreur: ' + e.message); }
  }

  async function deleteUser(phone) {
    if (!confirm('Supprimer ' + phone + ' ?')) return;
    try { await deleteAdmin('/api/admin/user/' + phone); loadUsers(); }
    catch(e) { alert('Erreur: ' + e.message); }
  }

  async function loadAll() {
    await loadOverview();
    await loadUsers();
  }

  loadAll();
  setInterval(loadAll, 15000);
</script>
</body>
</html>`);
});

// ==================== PING DES SERVEURS ====================
async function pingServers() {
  for (const server of SERVERS) {
    if (!server.url || server.url.trim() === '') {
      if (Date.now() - server.lastPing > 90000) server.online = false;
      continue;
    }
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 8000);

      const baseUrl = server.url.endsWith('/') ? server.url.slice(0, -1) : server.url;
      const res = await fetch(`${baseUrl}/health`, {
        method: 'GET',
        signal: controller.signal,
        headers: { 'X-Admin-Key': ADMIN_KEY }
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
      delete users[phone]; changed = true;
      console.log(`🧹 Supprimé (erreur): ${phone}`);
    }
    if (users[phone].status === 'pending' && now - users[phone].createdAt > 24 * 60 * 60 * 1000) {
      delete users[phone]; changed = true;
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
  SERVERS.forEach(s => console.log(`   • Server ${s.id} (${s.name}) → ${s.url}`));
  console.log(`👥 Max par serveur : ${MAX_USERS_PER_SERVER}`);
  console.log(`✅ IPs de confiance : ${TRUSTED_IPS.join(', ')}`);
  console.log(`🔐 Admin : /admin?key=${ADMIN_KEY.substring(0,8)}...`);
  console.log('════════════════════════════════════════');
});

// ==================== GESTION ERREURS ====================
process.on('uncaughtException', (err) => console.error('❌ Erreur non gérée:', err.message));
process.on('unhandledRejection', (err) => console.error('❌ Promesse rejetée:', err?.message));
process.on('SIGTERM', () => { console.log('🛑 Arrêt du serveur...'); process.exit(0); });
