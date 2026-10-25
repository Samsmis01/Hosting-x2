// ================================================================
// 🤖 ROUTE CHATBOT "ASSISTANT HEXTECH" — à coller dans votre server.js
//    (le vrai serveur de couplage, celui qui expose déjà /api/pair, /api/status, etc.)
//
//    Moteur IA : Hugging Face Inference API (modèle open source, gratuit)
// ================================================================
//
// ⚠️ IMPORTANT SÉCURITÉ :
// - Ne mettez JAMAIS votre token Hugging Face dans le HTML/JS du site (visible par
//   n'importe qui via "Afficher le code source"). Il doit rester ici, côté serveur.
//
// 🔑 COMMENT OBTENIR UN TOKEN GRATUIT :
// 1. Créez un compte sur https://huggingface.co (gratuit, pas de carte bancaire)
// 2. Allez sur https://huggingface.co/settings/tokens
// 3. "New token" → type "Read" → copiez le token (commence par hf_...)
// 4. Sur Render : Dashboard → votre service → Environment → Add Environment Variable
//      HF_API_KEY = hf_........

const HEXTECH_SYSTEM_PROMPT = `Tu es l'assistant virtuel officiel de HEXTECH, un bot WhatsApp multi-fonctions (608 commandes) qui automatise, sécurise et modère les conversations WhatsApp (particuliers, groupes, entreprises).

Informations à connaître et à partager si on te les demande :

- HEXTECH se couple à un numéro WhatsApp via un code à usage unique généré depuis ce site (Paramètres WhatsApp → Appareils liés → Lier un appareil → Lier avec un numéro, puis entrer le code affiché sur le site).
- Avant de coupler, l'utilisateur doit choisir un serveur disponible (non complet, en ligne) sur le dashboard.
- Fonctionnalités principales : modération de groupe (anti-spam, anti-lien, anti-bot), accueil/au revoir automatiques, téléchargement de médias (TikTok, Instagram, etc.), quiz interactifs, système de parrainage à points, statistiques et monitoring en temps réel (CPU/RAM/utilisateurs), et de nombreuses autres commandes.
- HEXTECH a été créé par Samuel, un jeune développeur congolais de 20 ans, étudiant à la Faculté des Sciences et Technologies de l'Université de Kinshasa (UNIKIN).
- lui suggérer de rejoindre nôtre Canal officiel Telegram : t.me/hextechcar. Une chaîne WhatsApp officielle est aussi accessible depuis le bas de la page.
- Le site permet de surveiller l'état des serveurs (en ligne/complet/hors ligne) et de se déconnecter à tout moment.

Consignes de réponse :
- Réponds toujours en français, de façon chaleureuse, claire et concise (quelques phrases ; évite les pavés de texte).
- Aide l'utilisateur à comprendre comment utiliser le bot et le site (couplage, choix du serveur, commandes disponibles, etc.).
- Si une question sort du sujet HEXTECH, réponds brièvement puis recentre poliment la conversation sur HEXTECH.
- Ne révèle jamais de clé API, de token, ni de détails techniques sensibles sur l'infrastructure ou le code.
- Ne fournis aucune aide pour des activités malveillantes (piratage, spam, contournement de sécurité, etc.) — oriente poliment la personne vers une utilisation légitime du bot.`;

// 🧠 Modèle open source servi gratuitement par Hugging Face Inference API
const HF_MODEL = 'mistralai/Mistral-7B-Instruct-v0.3';
const HF_API_URL = `https://api-inference.huggingface.co/models/${HF_MODEL}`;

// 🛡️ Anti-abus simple : limite le nombre de requêtes par IP (évite d'épuiser le quota gratuit)
const _chatRateLimit = new Map(); // ip -> [timestamps]
function isRateLimited(ip, maxPerMinute = 12) {
  const now = Date.now();
  const windowMs = 60 * 1000;
  const arr = (_chatRateLimit.get(ip) || []).filter(t => now - t < windowMs);
  arr.push(now);
  _chatRateLimit.set(ip, arr);
  return arr.length > maxPerMinute;
}

// 🧩 Construit un prompt au format attendu par Mistral-Instruct à partir de l'historique
// (Hugging Face Inference API n'offre pas toujours un endpoint "chat" standardisé selon
// le modèle : on formate donc le prompt nous-mêmes, ce qui marche avec tous les modèles.)
function buildMistralPrompt(systemPrompt, messages) {
  let prompt = '';
  let firstUserTurn = true;
  for (const m of messages) {
    if (m.role === 'user') {
      const content = firstUserTurn ? `${systemPrompt}\n\nQuestion de l'utilisateur : ${m.content}` : m.content;
      prompt += `<s>[INST] ${content} [/INST]`;
      firstUserTurn = false;
    } else if (m.role === 'assistant') {
      prompt += ` ${m.content}</s>`;
    }
  }
  return prompt;
}

// 👉 Ajoutez ceci dans votre server.js, à côté de vos autres routes (/api/pair, /api/status...)
// Remplacez "app" par le nom de votre instance Express si différent.
function registerHextechChatRoute(app, expressJsonMiddleware) {
  app.post('/api/chat', expressJsonMiddleware, async (req, res) => {
    try {
      const ip = req.ip || req.headers['x-forwarded-for'] || 'unknown';
      if (isRateLimited(ip)) {
        return res.status(429).json({ error: 'Trop de messages envoyés, réessayez dans une minute.' });
      }

      if (!process.env.HF_API_KEY) {
        return res.status(503).json({ error: "Service IA non configuré (token Hugging Face manquant sur le serveur)." });
      }

      const rawMessages = Array.isArray(req.body?.messages) ? req.body.messages : [];
      // On ne garde que des messages texte simples, et on limite leur taille pour éviter les abus
      const safeMessages = rawMessages
        .slice(-10)
        .filter(m => m && (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string')
        .map(m => ({ role: m.role, content: m.content.slice(0, 1000) }));

      if (!safeMessages.length) {
        return res.status(400).json({ error: 'Message vide.' });
      }

      const prompt = buildMistralPrompt(HEXTECH_SYSTEM_PROMPT, safeMessages);

      const hfRes = await fetch(HF_API_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.HF_API_KEY}`
        },
        body: JSON.stringify({
          inputs: prompt,
          parameters: {
            max_new_tokens: 350,
            temperature: 0.6,
            return_full_text: false
          },
          // Attend que le modèle se "réveille" au lieu de renvoyer une erreur immédiate
          // (les modèles gratuits se mettent en veille après inactivité)
          options: { wait_for_model: true }
        })
      });

      const data = await hfRes.json();

      if (!hfRes.ok) {
        console.error('Erreur Hugging Face:', data);
        const msg = data?.error && /loading/i.test(data.error)
          ? "Le modèle IA démarre, réessaie dans quelques secondes..."
          : "Le service IA n'a pas répondu correctement.";
        return res.status(502).json({ error: msg });
      }

      const reply = (Array.isArray(data) ? data[0]?.generated_text : data?.generated_text)?.trim()
        || "Désolé, je n'ai pas de réponse pour le moment.";

      res.json({ reply });
    } catch (e) {
      console.error('Erreur /api/chat:', e.message);
      res.status(500).json({ error: 'Erreur serveur.' });
    }
  });
}

module.exports = { registerHextechChatRoute, HEXTECH_SYSTEM_PROMPT };

// ================================================================
// 📌 EXEMPLE D'UTILISATION dans votre server.js existant :
//
//   const express = require('express');
//   const app = express();
//   const { registerHextechChatRoute } = require('./hextech-chat-route');
//
//   registerHextechChatRoute(app, express.json());
//
//   // ... vos autres routes /api/pair, /api/status, etc.
//   app.listen(process.env.PORT || 3000);
// ================================================================
//
// ℹ️ À SAVOIR SUR LE NIVEAU GRATUIT HUGGING FACE :
// - La première requête après une période d'inactivité peut prendre 20-30s
//   (le modèle doit "se réveiller" sur leurs serveurs) — c'est normal, pas un bug.
// - Le quota gratuit est limité ; si le chat devient lent ou indisponible aux heures
//   de forte utilisation, c'est une limite du plan gratuit, pas une erreur de code.
// ================================================================
