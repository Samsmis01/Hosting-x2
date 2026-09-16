// server.js
// Serveur de couplage multi-utilisateurs (version privée, 10 users max)

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ==================== CONFIGURATION ====================
const MAX_USERS = 10;
const USERS_FILE = './users.json';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
const ADMIN_KEY = process.env.ADMIN_KEY || 'xenoban-admin-2026';

// ==================== SÉCURITÉ ====================
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10mb' }));

// Servir le site web
app.use(express.static(path.join(__dirname)));

// ==================== BASE DE DONNÉES SIMPLE ====================
function loadUsers() {
  try {
    if (fs.existsSync(USERS_FILE)) {
      return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    }
  } catch (e) {}
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

// ==================== SYSTÈME DE QUEUE ====================
const pendingRequests = new Map();

function createRequest(phone) {
  return new Promise((resolve, reject) => {
    const requestId = crypto.randomBytes(8).toString('hex');
    const timeout = setTimeout(() => {
      if (pendingRequests.has(requestId)) {
        pendingRequests.delete(requestId);
        reject(new Error('Timeout : aucun worker disponible'));
      }
    }, 90000);
    
    pendingRequests.set(requestId, { phone, resolve, reject, timeout, createdAt: Date.now() });
  });
}

// ==================== ROUTES PUBLIQUES ====================

// Page d'accueil
app.get('/', (req, res) => {
  const users = loadUsers();
  const connectedCount = Object.values(users).filter(u => u.status === 'connected').length;
  res.json({
    status: 'ok',
    total: Object.keys(users).length,
    connected: connectedCount,
    max: MAX_USERS,
    available: MAX_USERS - Object.keys(users).length
  });
});

// Couplage
app.post('/api/pair', async (req, res) => {
  const { phone, consent } = req.body;
  
  if (!consent) return res.status(400).json({ error: 'Consentement requis' });
  if (!phone || !/^\d{9,15}$/.test(phone)) return res.status(400).json({ error: 'Numéro invalide (9-15 chiffres)' });
  
  const users = loadUsers();
  
  // Vérifier la limite
  if (Object.keys(users).length >= MAX_USERS) {
    return res.status(403).json({ error: `Limite de ${MAX_USERS} utilisateurs atteinte` });
  }
  
  // Vérifier si déjà couplé
  if (users[phone] && users[phone].status === 'connected') {
    return res.status(409).json({ error: 'Ce numéro est déjà couplé. Déconnectez-le d\'abord.' });
  }
  
  // Vérifier si un code est déjà en attente
  if (users[phone] && users[phone].status === 'pending' && users[phone].code) {
    return res.json({ 
      success: true, 
      code: users[phone].code,
      phone,
      status: 'pending',
      message: 'Code déjà généré, entrez-le dans WhatsApp'
    });
  }
  
  // Créer/mettre à jour l'utilisateur
  users[phone] = {
    phone,
    createdAt: users[phone]?.createdAt || Date.now(),
    status: 'pending',
    code: null,
    ip: req.ip
  };
  saveUsers(users);
  
  try {
    const code = await createRequest(phone);
    
    if (!code) throw new Error('Aucun code retourné');
    
    users[phone].code = code;
    users[phone].status = 'pending';
    saveUsers(users);
    
    console.log(`✅ Code généré pour ${phone}: ${code}`);
    
    res.json({ 
      success: true, 
      code,
      phone,
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

// Statut d'un utilisateur
app.get('/api/status/:phone', (req, res) => {
  const { phone } = req.params;
  const users = loadUsers();
  
  if (!users[phone]) {
    return res.status(404).json({ error: 'Numéro non enregistré' });
  }
  
  res.json({
    phone: users[phone].phone,
    status: users[phone].status,
    createdAt: users[phone].createdAt,
    connectedAt: users[phone].connectedAt || null
  });
});

// Déconnexion
app.post('/api/disconnect/:phone', (req, res) => {
  const { phone } = req.params;
  const users = loadUsers();
  
  if (!users[phone]) {
    return res.status(404).json({ error: 'Numéro non enregistré' });
  }
  
  // Marquer pour déconnexion
  users[phone].status = 'disconnect_requested';
  users[phone].disconnectAt = Date.now();
  saveUsers(users);
  
  console.log(`🚪 Déconnexion demandée pour ${phone}`);
  res.json({ success: true, message: 'Déconnexion en cours...' });
});

// ==================== ROUTES WORKER (protégées) ====================

// Le worker vérifie s'il y a des demandes
app.get('/api/worker/pending', (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) {
    return res.status(401).json({ error: 'Non autorisé' });
  }
  
  const requests = [];
  for (const [id, req] of pendingRequests.entries()) {
    requests.push({ id, phone: req.phone });
  }
  res.json(requests);
});

// Le worker renvoie le résultat
app.post('/api/worker/result', (req, res) => {
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

// Le worker signale une connexion réussie
app.post('/api/worker/connected', (req, res) => {
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
    console.log(`✅ ${phone} connecté avec succès`);
  }
  
  res.json({ success: true });
});

// Le worker signale une déconnexion
app.post('/api/worker/disconnected', (req, res) => {
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
    console.log(`⚠️ ${phone} déconnecté`);
  }
  
  res.json({ success: true });
});

// Le worker demande quels utilisateurs doivent être déconnectés
app.get('/api/worker/disconnect-list', (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) {
    return res.status(401).json({ error: 'Non autorisé' });
  }
  
  const users = loadUsers();
  const toDisconnect = Object.keys(users).filter(p => users[p].status === 'disconnect_requested');
  res.json(toDisconnect);
});

// Nettoyage après déconnexion
app.post('/api/worker/disconnect-done', (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== ADMIN_KEY) {
    return res.status(401).json({ error: 'Non autorisé' });
  }
  
  const { phone } = req.body;
  const users = loadUsers();
  
  if (users[phone]) {
    delete users[phone];
    saveUsers(users);
    console.log(`🗑️ Utilisateur supprimé: ${phone}`);
  }
  
  res.json({ success: true });
});

// ==================== NETTOYAGE AUTOMATIQUE ====================
setInterval(() => {
  const now = Date.now();
  const users = loadUsers();
  let changed = false;
  
  for (const phone of Object.keys(users)) {
    // Supprimer les utilisateurs en erreur > 24h
    if (users[phone].status === 'error' && now - users[phone].createdAt > 24 * 60 * 60 * 1000) {
      delete users[phone];
      changed = true;
      console.log(`🧹 Supprimé (erreur): ${phone}`);
    }
    // Supprimer les codes non utilisés > 24h
    if (users[phone].status === 'pending' && now - users[phone].createdAt > 24 * 60 * 60 * 1000) {
      delete users[phone];
      changed = true;
      console.log(`🧹 Supprimé (expiré): ${phone}`);
    }
  }
  
  if (changed) saveUsers(users);
}, 60 * 60 * 1000); // Toutes les heures

// ==================== DÉMARRAGE ====================
app.listen(PORT, '0.0.0.0', () => {
  console.log('════════════════════════════════════════');
  console.log(`🚀 Serveur de couplage sur le port ${PORT}`);
  console.log(`👥 Utilisateurs max : ${MAX_USERS}`);
  console.log(`🔐 Clé API Admin : ${ADMIN_KEY.substring(0, 8)}...`);
  console.log('════════════════════════════════════════');
});

process.on('SIGTERM', () => {
  console.log('🛑 Arrêt du serveur...');
  process.exit(0);
});
