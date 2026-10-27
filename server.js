const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const { customAlphabet } = require('nanoid');
const config = require('./config');
const { Key, Admin } = require('./models');

const genKey = customAlphabet('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', 16);
function formatKey() {
  const r = genKey();
  return `${r.slice(0,4)}-${r.slice(4,8)}-${r.slice(8,12)}-${r.slice(12,16)}`;
}
function planSeconds(plan, custom = 0) {
  switch (plan) {
    case '1h': return 3600;
    case '2h': return 7200;
    case 'daily': return 86400;
    case 'weekly': return 604800;
    case 'custom': return Math.max(60, parseInt(custom, 10) || 60);
    default: return 86400;
  }
}

function formatDate(d) {
  if (!d) return '-';
  try {
    const date = new Date(d);
    return date.toLocaleString('uz-UZ', {
      timeZone: 'Asia/Tashkent',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false
    });
  } catch (e) {
    return new Date(d).toISOString().slice(0, 16).replace('T', ' ');
  }
}

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
  secret: config.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 3600 * 1000 },
}));

// ---------- API ----------
app.post('/api/activate', async (req, res) => {
  try {
    const { key, device_id, secret } = req.body || {};
    if (secret && secret !== config.API_SECRET) return res.status(403).json({ ok: false, msg: 'forbidden' });
    if (!key || !device_id) return res.status(400).json({ ok: false, msg: 'missing fields' });

    const doc = await Key.findOne({ keyCode: String(key).trim().toUpperCase() });
    if (!doc) return res.status(404).json({ ok: false, msg: 'invalid key', uz_msg: "Noto'g'ri kalit kiritildi" });
    if (doc.status === 'revoked') return res.status(403).json({ ok: false, msg: 'key revoked', uz_msg: 'Kalit administrator tomonidan bekor qilingan' });

    const now = new Date();
    if (!doc.activatedAt) {
      doc.activatedAt = now;
      doc.expiresAt = new Date(now.getTime() + doc.durationSeconds * 1000);
      doc.status = 'active';
    } else if (doc.expiresAt && now > doc.expiresAt) {
      doc.status = 'expired';
      await doc.save();
      return res.status(403).json({ ok: false, msg: 'key expired', uz_msg: 'Kalit muddati tugagan' });
    }

    const existing = doc.devices.find(d => d.deviceId === device_id);
    if (!existing) {
      if (doc.devices.length >= doc.maxDevices) {
        return res.status(403).json({ ok: false, msg: 'device limit reached', uz_msg: 'Ushbu kalitga ulanish chegarasi (max devices) to\'lgan' });
      }
      doc.devices.push({ deviceId: device_id, firstSeen: now, lastSeen: now });
    } else {
      existing.lastSeen = now;
    }
    await doc.save();

    return res.json({
      ok: true,
      msg: 'ok',
      uz_msg: 'Kalit muvaffaqiyatli aktivlashtirildi',
      key: doc.keyCode,
      expires_at: doc.expiresAt,
      expires_ts: Math.floor(doc.expiresAt.getTime() / 1000),
      duration_seconds: doc.durationSeconds,
      plan: doc.plan,
      devices_count: doc.devices.length,
      max_devices: doc.maxDevices,
      server_time: Math.floor(Date.now() / 1000),
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, msg: 'server error' });
  }
});

app.post('/api/validate', async (req, res) => {
  try {
    const { key, device_id, secret } = req.body || {};
    if (secret && secret !== config.API_SECRET) return res.status(403).json({ ok: false, msg: 'forbidden' });
    if (!key || !device_id) return res.status(400).json({ ok: false, msg: 'missing fields' });

    const doc = await Key.findOne({ keyCode: String(key).trim().toUpperCase(), 'devices.deviceId': device_id });
    if (!doc) return res.status(404).json({ ok: false, msg: 'not activated', uz_msg: 'Ushbu qurilma uchun kalit aktivlashtirilmagan' });
    if (doc.status === 'revoked') return res.status(403).json({ ok: false, msg: 'key revoked', uz_msg: 'Kalit bekor qilingan' });

    const now = new Date();
    if (!doc.expiresAt || now > doc.expiresAt) {
      doc.status = 'expired';
      await doc.save();
      return res.status(403).json({ ok: false, msg: 'key expired', uz_msg: 'Kalit muddati tugagan' });
    }
    const d = doc.devices.find(x => x.deviceId === device_id);
    if (d) d.lastSeen = now;
    await doc.save();

    return res.json({
      ok: true,
      expires_at: doc.expiresAt,
      expires_ts: Math.floor(doc.expiresAt.getTime() / 1000),
      plan: doc.plan,
      server_time: Math.floor(Date.now() / 1000),
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, msg: 'server error' });
  }
});

// ---------- CLIENT IN-APP / WEB LOGIN PAGE ----------
const clientLoginHTML = `<!DOCTYPE html>
<html lang="uz">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>Benzware • OxiCore VIP Access</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #07090e;
      --card-bg: rgba(15, 23, 42, 0.75);
      --card-border: rgba(99, 102, 241, 0.25);
      --primary: #6366f1;
      --primary-glow: rgba(99, 102, 241, 0.5);
      --accent: #a855f7;
      --success: #10b981;
      --danger: #ef4444;
      --text: #f8fafc;
      --text-muted: #94a3b8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: radial-gradient(circle at 50% 0%, rgba(99, 102, 241, 0.2), transparent 45%),
                  radial-gradient(circle at 80% 80%, rgba(168, 85, 247, 0.15), transparent 40%),
                  var(--bg);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: 'Plus Jakarta Sans', sans-serif;
      color: var(--text);
      padding: 16px;
    }
    .wrapper {
      width: 100%;
      max-width: 420px;
      perspective: 1000px;
    }
    .card {
      background: var(--card-bg);
      backdrop-filter: blur(24px);
      -webkit-backdrop-filter: blur(24px);
      border: 1px solid var(--card-border);
      border-radius: 28px;
      padding: 32px 26px;
      box-shadow: 0 25px 60px -15px rgba(0, 0, 0, 0.7),
                  0 0 35px -5px var(--primary-glow);
      position: relative;
      overflow: hidden;
    }
    .card::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0; height: 3px;
      background: linear-gradient(90deg, #6366f1, #a855f7, #ec4899);
    }
    .brand {
      text-align: center;
      margin-bottom: 26px;
    }
    .logo-badge {
      width: 68px;
      height: 68px;
      margin: 0 auto 14px;
      background: linear-gradient(135deg, rgba(99, 102, 241, 0.2), rgba(168, 85, 247, 0.25));
      border: 1px solid rgba(255, 255, 255, 0.15);
      border-radius: 22px;
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 10px 25px rgba(99, 102, 241, 0.35);
      animation: float 4s ease-in-out infinite;
    }
    @keyframes float {
      0%, 100% { transform: translateY(0); }
      50% { transform: translateY(-5px); }
    }
    .brand h1 {
      font-size: 24px;
      font-weight: 800;
      letter-spacing: -0.5px;
      background: linear-gradient(135deg, #ffffff, #cbd5e1);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .brand p {
      font-size: 13px;
      color: var(--text-muted);
      margin-top: 4px;
      text-transform: uppercase;
      letter-spacing: 1.5px;
      font-weight: 600;
    }
    .input-group {
      margin-bottom: 18px;
      text-align: left;
    }
    .input-label {
      display: block;
      font-size: 12px;
      font-weight: 600;
      color: var(--text-muted);
      margin-bottom: 7px;
      text-transform: uppercase;
      letter-spacing: 0.8px;
    }
    .input-box {
      width: 100%;
      padding: 15px 16px;
      background: rgba(15, 23, 42, 0.85);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 16px;
      color: #fff;
      font-size: 16px;
      font-family: 'JetBrains Mono', monospace;
      letter-spacing: 2px;
      text-align: center;
      text-transform: uppercase;
      outline: none;
      transition: all 0.25s ease;
    }
    .input-box:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 4px rgba(99, 102, 241, 0.25);
      background: rgba(15, 23, 42, 1);
    }
    .device-info {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 10px 14px;
      background: rgba(255, 255, 255, 0.03);
      border-radius: 12px;
      margin-bottom: 22px;
      font-size: 12px;
      color: var(--text-muted);
    }
    .device-info code {
      font-family: 'JetBrains Mono', monospace;
      color: #cbd5e1;
      font-size: 11px;
    }
    .btn-submit {
      width: 100%;
      padding: 16px;
      background: linear-gradient(135deg, #6366f1, #8b5cf6, #d946ef);
      background-size: 200% 200%;
      border: none;
      border-radius: 16px;
      color: #fff;
      font-size: 15px;
      font-weight: 700;
      font-family: inherit;
      cursor: pointer;
      box-shadow: 0 10px 25px -5px rgba(99, 102, 241, 0.5);
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
    }
    .btn-submit:hover {
      transform: translateY(-2px);
      box-shadow: 0 15px 30px -5px rgba(99, 102, 241, 0.65);
    }
    .btn-submit:active { transform: translateY(0); }
    .btn-submit:disabled { opacity: 0.6; cursor: not-allowed; }
    .status-card {
      display: none;
      margin-top: 20px;
      padding: 16px;
      border-radius: 16px;
      font-size: 13px;
      text-align: left;
      animation: fadeIn 0.3s ease;
    }
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(8px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .status-card.success {
      background: rgba(16, 185, 129, 0.1);
      border: 1px solid rgba(16, 185, 129, 0.3);
      color: #6ee7b7;
    }
    .status-card.error {
      background: rgba(239, 68, 68, 0.1);
      border: 1px solid rgba(239, 68, 68, 0.3);
      color: #fca5a5;
    }
    .stat-row {
      display: flex;
      justify-content: space-between;
      margin-top: 8px;
      font-size: 12px;
      color: #cbd5e1;
    }
    .stat-row strong { color: #fff; }
    .countdown-timer {
      margin-top: 10px;
      padding: 10px;
      background: rgba(0, 0, 0, 0.3);
      border-radius: 10px;
      text-align: center;
      font-family: 'JetBrains Mono', monospace;
      font-size: 16px;
      font-weight: 700;
      color: #10b981;
    }
    .footer {
      margin-top: 24px;
      text-align: center;
      font-size: 12px;
      color: var(--text-muted);
    }
    .footer a {
      color: var(--primary);
      text-decoration: none;
      font-weight: 600;
    }
    .footer a:hover { text-decoration: underline; }
    .spinner {
      width: 18px;
      height: 18px;
      border: 2px solid rgba(255,255,255,0.3);
      border-top-color: #fff;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      display: none;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="card">
      <div class="brand">
        <div class="logo-badge">
          <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
          </svg>
        </div>
        <h1>BENZWARE • VIP</h1>
        <p>Xavfsiz Kirish Tizimi</p>
      </div>

      <form id="keyForm" onsubmit="handleActivate(event)">
        <div class="input-group">
          <label class="input-label">Maxfiy Litsenziya Kaliti</label>
          <input type="text" id="keyInput" class="input-box" placeholder="XXXX-XXXX-XXXX-XXXX" maxlength="19" autocomplete="off" required>
        </div>

        <div class="device-info">
          <span>Qurilma ID:</span>
          <code id="devIdText">Yuklanmoqda...</code>
        </div>

        <button type="submit" id="submitBtn" class="btn-submit">
          <div class="spinner" id="btnSpinner"></div>
          <span id="btnText">TIZIMGA KIRISH</span>
          <svg id="btnIcon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="9 18 15 12 9 6"></polyline>
          </svg>
        </button>
      </form>

      <div id="statusBox" class="status-card"></div>

      <div class="footer">
        OxiCore Security 2.0 • <a href="https://t.me" target="_blank">Telegram Yordam</a>
      </div>
    </div>
  </div>

  <script>
    // Device ID handling
    let deviceId = localStorage.getItem('oxikey_device_id');
    if (!deviceId) {
      deviceId = 'DEV-' + Math.random().toString(36).substring(2, 10).toUpperCase() + '-' + Date.now().toString(36).toUpperCase();
      localStorage.setItem('oxikey_device_id', deviceId);
    }
    document.getElementById('devIdText').innerText = deviceId;

    // Auto format key input with hyphens
    const keyInput = document.getElementById('keyInput');
    keyInput.addEventListener('input', function(e) {
      let val = e.target.value.replace(/[^A-Za-z0-9]/g, '').toUpperCase().slice(0, 16);
      let parts = [];
      for (let i = 0; i < val.length; i += 4) {
        parts.push(val.slice(i, i + 4));
      }
      e.target.value = parts.join('-');
    });

    // Check if previously active key exists
    const savedKey = localStorage.getItem('oxikey_active_key');
    if (savedKey) keyInput.value = savedKey;

    let countdownInterval = null;

    function startTimer(expiresTs) {
      if (countdownInterval) clearInterval(countdownInterval);
      const timerEl = document.getElementById('countdownVal');
      if (!timerEl) return;

      function update() {
        const now = Math.floor(Date.now() / 1000);
        const diff = expiresTs - now;
        if (diff <= 0) {
          timerEl.innerText = "Muddati tugadi!";
          clearInterval(countdownInterval);
          return;
        }
        const h = Math.floor(diff / 3600);
        const m = Math.floor((diff % 3600) / 60);
        const s = diff % 60;
        timerEl.innerText = \`\${h}s \${m}m \${s}s qoldi\`;
      }
      update();
      countdownInterval = setInterval(update, 1000);
    }

    async function handleActivate(e) {
      e.preventDefault();
      const key = keyInput.value.trim().toUpperCase();
      const statusBox = document.getElementById('statusBox');
      const submitBtn = document.getElementById('submitBtn');
      const spinner = document.getElementById('btnSpinner');
      const btnIcon = document.getElementById('btnIcon');
      const btnText = document.getElementById('btnText');

      submitBtn.disabled = true;
      spinner.style.display = 'block';
      btnIcon.style.display = 'none';
      btnText.innerText = 'Tekshirilmoqda...';
      statusBox.style.display = 'none';

      try {
        const res = await fetch('/api/activate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ key, device_id: deviceId })
        });
        const data = await res.json();

        statusBox.style.display = 'block';
        if (data.ok) {
          localStorage.setItem('oxikey_active_key', key);
          statusBox.className = 'status-card success';
          statusBox.innerHTML = \`
            <strong>✓ Ruxsat berildi!</strong>
            <div class="stat-row"><span>Tarif:</span> <strong>\${data.plan}</strong></div>
            <div class="stat-row"><span>Qurilmalar:</span> <strong>\${data.devices_count} / \${data.max_devices}</strong></div>
            <div class="stat-row"><span>Tugash vaqti:</span> <strong>\${new Date(data.expires_at).toLocaleTimeString()}</strong></div>
            <div class="countdown-timer" id="countdownVal">Hisoblanmoqda...</div>
          \`;
          startTimer(data.expires_ts);
        } else {
          statusBox.className = 'status-card error';
          statusBox.innerHTML = \`<strong>✕ Xatolik:</strong> \${data.uz_msg || data.msg}\`;
        }
      } catch (err) {
        statusBox.style.display = 'block';
        statusBox.className = 'status-card error';
        statusBox.innerHTML = '<strong>✕ Tarmoq xatosi:</strong> Serverga ulanib bo\\'lmadi';
      } finally {
        submitBtn.disabled = false;
        spinner.style.display = 'none';
        btnIcon.style.display = 'block';
        btnText.innerText = 'TIZIMGA KIRISH';
      }
    }
  </script>
</body>
</html>`;

app.get('/login', (req, res) => res.send(clientLoginHTML));
app.get('/app', (req, res) => res.send(clientLoginHTML));
app.get('/', (req, res) => res.send(clientLoginHTML));

// ---------- ADMIN AUTH ----------
function requireAdmin(req, res, next) {
  if (req.session && req.session.admin) return next();
  return res.redirect('/admin/login');
}

app.get('/admin/login', (req, res) => {
  const isErr = req.query.error === '1';
  res.send(`<!DOCTYPE html>
<html lang="uz">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OxiKey • Admin Login</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #090d16;
      --card-bg: rgba(17, 24, 39, 0.85);
      --card-border: rgba(99, 102, 241, 0.25);
      --primary: #6366f1;
      --primary-glow: rgba(99, 102, 241, 0.45);
      --text: #f8fafc;
      --text-muted: #94a3b8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: radial-gradient(circle at 50% 0%, rgba(99, 102, 241, 0.25), transparent 50%),
                  radial-gradient(circle at 20% 80%, rgba(139, 92, 246, 0.15), transparent 40%),
                  var(--bg);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: 'Plus Jakarta Sans', sans-serif;
      color: var(--text);
      padding: 16px;
    }
    .login-card {
      width: 100%;
      max-width: 380px;
      background: var(--card-bg);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border: 1px solid var(--card-border);
      border-radius: 24px;
      padding: 36px 30px;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.8),
                  0 0 30px -5px var(--primary-glow);
    }
    .header { text-align: center; margin-bottom: 28px; }
    .icon-box {
      width: 60px; height: 60px;
      margin: 0 auto 14px;
      background: linear-gradient(135deg, rgba(99, 102, 241, 0.2), rgba(168, 85, 247, 0.2));
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 18px;
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 10px 20px rgba(99, 102, 241, 0.3);
    }
    .header h2 { font-size: 22px; font-weight: 800; color: #fff; }
    .header p { font-size: 13px; color: var(--text-muted); margin-top: 4px; }
    .form-group { margin-bottom: 18px; }
    .label { display: block; font-size: 12px; font-weight: 600; color: var(--text-muted); margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px; }
    .input-control {
      width: 100%;
      padding: 13px 16px;
      background: rgba(15, 23, 42, 0.9);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 14px;
      color: #fff;
      font-size: 14px;
      font-family: inherit;
      outline: none;
      transition: all 0.2s ease;
    }
    .input-control:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.25);
    }
    .btn-login {
      width: 100%;
      padding: 14px;
      background: linear-gradient(135deg, #6366f1, #8b5cf6);
      border: none;
      border-radius: 14px;
      color: #fff;
      font-size: 15px;
      font-weight: 700;
      cursor: pointer;
      box-shadow: 0 10px 20px -3px rgba(99, 102, 241, 0.5);
      transition: all 0.2s ease;
      margin-top: 8px;
    }
    .btn-login:hover { transform: translateY(-2px); box-shadow: 0 14px 25px -3px rgba(99, 102, 241, 0.65); }
    .error-msg {
      padding: 10px 14px;
      background: rgba(239, 68, 68, 0.15);
      border: 1px solid rgba(239, 68, 68, 0.3);
      color: #fca5a5;
      border-radius: 12px;
      font-size: 12px;
      margin-bottom: 18px;
      text-align: center;
    }
  </style>
</head>
<body>
  <div class="login-card">
    <div class="header">
      <div class="icon-box">
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#6366f1" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
        </svg>
      </div>
      <h2>OxiKey Dashboard</h2>
      <p>Boshqaruv paneliga kirish</p>
    </div>

    ${isErr ? '<div class="error-msg">Login yoki parol noto\'g\'ri kiritildi!</div>' : ''}

    <form method="POST" action="/admin/login">
      <div class="form-group">
        <label class="label">Foydalanuvchi nomi</label>
        <input name="username" class="input-control" placeholder="admin" required autofocus>
      </div>
      <div class="form-group">
        <label class="label">Parol</label>
        <input name="password" type="password" class="input-control" placeholder="••••••••" required>
      </div>
      <button class="btn-login" type="submit">Kirish</button>
    </form>
  </div>
</body>
</html>`);
});

app.post('/admin/login', async (req, res) => {
  const { username, password } = req.body || {};
  const admin = await Admin.findOne({ username });
  if (!admin || !(await bcrypt.compare(password || '', admin.passwordHash))) {
    return res.redirect('/admin/login?error=1');
  }
  req.session.admin = admin.username;
  res.redirect('/admin');
});

app.get('/admin/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/admin/login'));
});

// ---------- ADMIN DASHBOARD (PREMIUM) ----------
app.get('/admin', requireAdmin, async (req, res) => {
  const keys = await Key.find().sort({ createdAt: -1 }).limit(300).lean();
  
  // Stats calculation
  const totalCount = keys.length;
  const activeCount = keys.filter(k => k.status === 'active').length;
  const expiredCount = keys.filter(k => k.status === 'expired').length;
  const revokedCount = keys.filter(k => k.status === 'revoked').length;

  const rows = keys.map(k => {
    const devs = (k.devices || []).length;
    let badgeClass = 'badge-unused';
    let statusText = 'Ishlatilmagan';

    if (k.status === 'active') {
      badgeClass = 'badge-active';
      statusText = 'Faol';
    } else if (k.status === 'expired') {
      badgeClass = 'badge-expired';
      statusText = 'Tugagan';
    } else if (k.status === 'revoked') {
      badgeClass = 'badge-revoked';
      statusText = 'Bekor qilingan';
    }

    return `<tr data-status="${k.status}" data-search="${k.keyCode} ${k.note || ''}">
      <td class="key-cell">
        <span class="key-code" id="code_${k._id}">${k.keyCode}</span>
        <button type="button" class="btn-copy" onclick="copyKey('${k.keyCode}', this)" title="Nusxa olish">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
        </button>
      </td>
      <td><span class="plan-pill">${k.plan} (${Math.round(k.durationSeconds / 3600)}s)</span></td>
      <td><span class="badge ${badgeClass}">${statusText}</span></td>
      <td><span class="device-pill">${devs} / ${k.maxDevices}</span></td>
      <td class="date-cell">${formatDate(k.activatedAt)}</td>
      <td class="date-cell">${formatDate(k.expiresAt)}</td>
      <td class="note-cell">${k.note || '<span style="opacity:0.3">-</span>'}</td>
      <td class="actions-cell">
        <form class="act-form" method="POST" action="/admin/extend">
          <input type="hidden" name="id" value="${k._id}">
          <button class="btn-act btn-extend" title="+1 soat qo'shish">+1s</button>
        </form>
        <form class="act-form" method="POST" action="/admin/extend">
          <input type="hidden" name="id" value="${k._id}">
          <input type="hidden" name="add_seconds" value="86400">
          <button class="btn-act btn-extend" title="+24 soat qo'shish">+1k</button>
        </form>
        <form class="act-form" method="POST" action="/admin/reset">
          <input type="hidden" name="id" value="${k._id}">
          <button class="btn-act btn-reset" title="Hozirdan boshlab 24 soatga qayta tiklash">Qayta</button>
        </form>
        <form class="act-form" method="POST" action="/admin/revoke">
          <input type="hidden" name="id" value="${k._id}">
          <button class="btn-act btn-revoke" title="Kalitni bekor qilish">✕</button>
        </form>
      </td>
    </tr>`;
  }).join('');

  res.send(`<!DOCTYPE html>
<html lang="uz">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OxiCore • Admin Panel</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #090d16;
      --card-bg: rgba(17, 24, 39, 0.7);
      --card-border: rgba(255, 255, 255, 0.08);
      --primary: #6366f1;
      --primary-light: #818cf8;
      --accent: #a855f7;
      --success: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
      --text: #f8fafc;
      --text-muted: #94a3b8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: radial-gradient(circle at 50% 0%, rgba(99, 102, 241, 0.15), transparent 40%),
                  radial-gradient(circle at 90% 90%, rgba(168, 85, 247, 0.1), transparent 40%),
                  var(--bg);
      min-height: 100vh;
      font-family: 'Plus Jakarta Sans', sans-serif;
      color: var(--text);
      padding: 24px;
    }
    .container { max-width: 1280px; margin: 0 auto; }
    
    /* Topbar */
    .topbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 16px 24px;
      background: var(--card-bg);
      backdrop-filter: blur(20px);
      border: 1px solid var(--card-border);
      border-radius: 20px;
      margin-bottom: 24px;
    }
    .brand-group { display: flex; align-items: center; gap: 14px; }
    .brand-icon {
      width: 44px; height: 44px;
      background: linear-gradient(135deg, #6366f1, #a855f7);
      border-radius: 14px;
      display: flex; align-items: center; justify-content: center;
      box-shadow: 0 8px 16px rgba(99, 102, 241, 0.4);
    }
    .brand-title { font-size: 18px; font-weight: 800; }
    .brand-sub { font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; }
    .user-pill {
      display: flex; align-items: center; gap: 12px;
      background: rgba(255, 255, 255, 0.04);
      padding: 6px 14px;
      border-radius: 12px;
      border: 1px solid rgba(255, 255, 255, 0.08);
      font-size: 13px;
    }
    .btn-logout {
      color: #fca5a5;
      text-decoration: none;
      font-weight: 600;
      padding: 4px 8px;
      border-radius: 8px;
      transition: background 0.2s;
    }
    .btn-logout:hover { background: rgba(239, 68, 68, 0.2); }

    /* Stats Grid */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .stat-card {
      background: var(--card-bg);
      backdrop-filter: blur(16px);
      border: 1px solid var(--card-border);
      border-radius: 20px;
      padding: 20px;
      display: flex;
      align-items: center;
      gap: 16px;
    }
    .stat-icon {
      width: 48px; height: 48px;
      border-radius: 14px;
      display: flex; align-items: center; justify-content: center;
    }
    .stat-val { font-size: 26px; font-weight: 800; font-family: 'JetBrains Mono', monospace; }
    .stat-lbl { font-size: 12px; color: var(--text-muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }

    /* New Key Generator Card */
    .section-card {
      background: var(--card-bg);
      backdrop-filter: blur(20px);
      border: 1px solid var(--card-border);
      border-radius: 20px;
      padding: 24px;
      margin-bottom: 24px;
    }
    .card-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 18px;
    }
    .card-head h3 { font-size: 16px; font-weight: 700; }
    
    .gen-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 12px;
      align-items: end;
    }
    .field label { display: block; font-size: 11px; font-weight: 600; color: var(--text-muted); margin-bottom: 6px; text-transform: uppercase; }
    .field input, .field select {
      width: 100%;
      padding: 11px 14px;
      background: rgba(15, 23, 42, 0.85);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 12px;
      color: #fff;
      font-size: 13px;
      font-family: inherit;
      outline: none;
      transition: all 0.2s;
    }
    .field input:focus, .field select:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.25);
    }
    .btn-create {
      padding: 12px 24px;
      background: linear-gradient(135deg, #6366f1, #8b5cf6);
      border: none;
      border-radius: 12px;
      color: #fff;
      font-size: 14px;
      font-weight: 700;
      font-family: inherit;
      cursor: pointer;
      box-shadow: 0 8px 16px rgba(99, 102, 241, 0.4);
      transition: all 0.2s;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
    }
    .btn-create:hover { transform: translateY(-2px); box-shadow: 0 12px 20px rgba(99, 102, 241, 0.55); }

    /* Filter & Search Bar */
    .filter-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      margin-bottom: 16px;
      flex-wrap: wrap;
    }
    .search-input {
      padding: 10px 16px;
      background: rgba(15, 23, 42, 0.85);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 12px;
      color: #fff;
      font-size: 13px;
      min-width: 260px;
      outline: none;
    }
    .filter-tabs { display: flex; gap: 8px; }
    .tab-btn {
      padding: 8px 16px;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 10px;
      color: var(--text-muted);
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
    }
    .tab-btn.active {
      background: var(--primary);
      color: #fff;
      border-color: var(--primary);
      box-shadow: 0 4px 12px rgba(99, 102, 241, 0.4);
    }

    /* Table Styles */
    .table-responsive {
      overflow-x: auto;
      border-radius: 16px;
      border: 1px solid var(--card-border);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 13px;
      background: rgba(15, 23, 42, 0.5);
    }
    th {
      background: rgba(15, 23, 42, 0.95);
      padding: 14px 16px;
      color: var(--text-muted);
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      border-bottom: 1px solid var(--card-border);
    }
    td {
      padding: 14px 16px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
      vertical-align: middle;
    }
    tr:hover td { background: rgba(255, 255, 255, 0.02); }
    
    .key-cell { display: flex; align-items: center; gap: 8px; }
    .key-code {
      font-family: 'JetBrains Mono', monospace;
      font-weight: 600;
      color: #818cf8;
      background: rgba(99, 102, 241, 0.1);
      padding: 4px 8px;
      border-radius: 8px;
      border: 1px solid rgba(99, 102, 241, 0.2);
    }
    .btn-copy {
      background: rgba(255, 255, 255, 0.06);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 6px;
      color: #cbd5e1;
      width: 26px; height: 26px;
      display: flex; align-items: center; justify-content: center;
      cursor: pointer;
      transition: all 0.2s;
    }
    .btn-copy:hover { background: var(--primary); color: #fff; }
    
    .badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 20px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .badge-active { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
    .badge-expired { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }
    .badge-revoked { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
    .badge-unused { background: rgba(148, 163, 184, 0.12); color: #94a3b8; border: 1px solid rgba(148, 163, 184, 0.2); }
    
    .plan-pill {
      font-size: 12px;
      font-weight: 600;
      color: #cbd5e1;
    }
    .device-pill {
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      color: #94a3b8;
    }
    .date-cell { font-size: 12px; color: #94a3b8; }
    
    .actions-cell { display: flex; gap: 6px; }
    .act-form { display: inline; }
    .btn-act {
      padding: 6px 10px;
      border-radius: 8px;
      font-size: 11px;
      font-weight: 700;
      border: 1px solid transparent;
      cursor: pointer;
      transition: all 0.2s;
    }
    .btn-extend { background: rgba(99, 102, 241, 0.15); color: #a5b4fc; border-color: rgba(99, 102, 241, 0.3); }
    .btn-extend:hover { background: #6366f1; color: #fff; }
    .btn-reset { background: rgba(16, 185, 129, 0.15); color: #6ee7b7; border-color: rgba(16, 185, 129, 0.3); }
    .btn-reset:hover { background: #10b981; color: #fff; }
    .btn-revoke { background: rgba(239, 68, 68, 0.15); color: #fca5a5; border-color: rgba(239, 68, 68, 0.3); }
    .btn-revoke:hover { background: #ef4444; color: #fff; }

    /* Toast */
    #toast {
      position: fixed;
      bottom: 24px;
      right: 24px;
      background: #10b981;
      color: #fff;
      padding: 12px 20px;
      border-radius: 12px;
      font-size: 13px;
      font-weight: 700;
      box-shadow: 0 10px 25px rgba(0,0,0,0.5);
      display: none;
      z-index: 9999;
    }
  </style>
</head>
<body>
  <div class="container">
    <!-- Topbar -->
    <div class="topbar">
      <div class="brand-group">
        <div class="brand-icon">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.2">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
          </svg>
        </div>
        <div>
          <div class="brand-title">OxiCore VIP Server</div>
          <div class="brand-sub">Kalitlar boshqaruvi</div>
        </div>
      </div>
      <div class="user-pill">
        <span>Admin: <strong>${req.session.admin}</strong></span>
        <a href="/admin/logout" class="btn-logout">Chiqish</a>
      </div>
    </div>

    <!-- Stats Grid -->
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-icon" style="background: rgba(99, 102, 241, 0.15); color: #818cf8;">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M7 7h10M7 12h10M7 17h10"/></svg>
        </div>
        <div>
          <div class="stat-val">${totalCount}</div>
          <div class="stat-lbl">Jami kalitlar</div>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-icon" style="background: rgba(16, 185, 129, 0.15); color: #34d399;">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
        </div>
        <div>
          <div class="stat-val" style="color: #34d399;">${activeCount}</div>
          <div class="stat-lbl">Faol kalitlar</div>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-icon" style="background: rgba(245, 158, 11, 0.15); color: #fbbf24;">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
        </div>
        <div>
          <div class="stat-val" style="color: #fbbf24;">${expiredCount}</div>
          <div class="stat-lbl">Tugagan kalitlar</div>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-icon" style="background: rgba(239, 68, 68, 0.15); color: #f87171;">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
        </div>
        <div>
          <div class="stat-val" style="color: #f87171;">${revokedCount}</div>
          <div class="stat-lbl">Bekor qilingan</div>
        </div>
      </div>
    </div>

    <!-- Key Generator Card -->
    <div class="section-card">
      <div class="card-head">
        <h3>+ Yangi kalit(lar) yaratish</h3>
      </div>
      <form method="POST" action="/admin/create">
        <div class="gen-grid">
          <div class="field">
            <label>Tarif rejasi</label>
            <select name="plan" id="planSelect" onchange="toggleCustom(this.value)">
              <option value="1h">1 soat</option>
              <option value="2h">2 soat</option>
              <option value="daily" selected>1 kun (24 soat)</option>
              <option value="weekly">1 hafta (7 kun)</option>
              <option value="custom">Custom (sekund)</option>
            </select>
          </div>
          <div class="field" id="customField" style="display: none;">
            <label>Custom vaqt (sekund)</label>
            <input name="custom_seconds" type="number" value="3600" min="60">
          </div>
          <div class="field">
            <label>Max qurilma (devices)</label>
            <input name="max_devices" type="number" value="1" min="1" max="10">
          </div>
          <div class="field">
            <label>Soni (nechta kalit)</label>
            <input name="count" type="number" value="1" min="1" max="50">
          </div>
          <div class="field" style="grid-column: span 2;">
            <label>Mijoz / Izoh (ixtiyoriy)</label>
            <input name="note" placeholder="Masalan: Ali (Telegram: @ali)">
          </div>
          <div>
            <button class="btn-create" type="submit">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
              Yaratish
            </button>
          </div>
        </div>
      </form>
    </div>

    <!-- Filter & Keys List -->
    <div class="section-card">
      <div class="filter-bar">
        <input type="text" class="search-input" id="searchBox" placeholder="Qidirish (kalit yoki mijoz)..." onkeyup="filterRows()">
        <div class="filter-tabs">
          <button class="tab-btn active" onclick="setFilter('all', this)">Hammasi (${totalCount})</button>
          <button class="tab-btn" onclick="setFilter('active', this)">Faol (${activeCount})</button>
          <button class="tab-btn" onclick="setFilter('expired', this)">Tugagan (${expiredCount})</button>
          <button class="tab-btn" onclick="setFilter('revoked', this)">Bekor qilingan (${revokedCount})</button>
        </div>
      </div>

      <div class="table-responsive">
        <table>
          <thead>
            <tr>
              <th>Kalit kodi</th>
              <th>Tarif</th>
              <th>Status</th>
              <th>Qurilmalar</th>
              <th>Aktivlashgan</th>
              <th>Tugash vaqti</th>
              <th>Mijoz izohi</th>
              <th>Amallar</th>
            </tr>
          </thead>
          <tbody id="keysTableBody">
            ${rows || '<tr><td colspan="8" style="text-align:center;padding:30px;color:#94a3b8">Hali hech qanday kalit yaratilmagan.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <div id="toast">Nusxa olindi! ✓</div>

  <script>
    function toggleCustom(val) {
      document.getElementById('customField').style.display = val === 'custom' ? 'block' : 'none';
    }

    function copyKey(text, btn) {
      navigator.clipboard.writeText(text).then(() => {
        const toast = document.getElementById('toast');
        toast.style.display = 'block';
        setTimeout(() => toast.style.display = 'none', 2000);
      });
    }

    let currentFilter = 'all';
    function setFilter(status, btn) {
      currentFilter = status;
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      filterRows();
    }

    function filterRows() {
      const q = document.getElementById('searchBox').value.toLowerCase();
      const rows = document.querySelectorAll('#keysTableBody tr');
      rows.forEach(r => {
        const rowStatus = r.getAttribute('data-status');
        const rowSearch = (r.getAttribute('data-search') || '').toLowerCase();
        const matchesFilter = (currentFilter === 'all' || rowStatus === currentFilter);
        const matchesSearch = rowSearch.includes(q);
        r.style.display = (matchesFilter && matchesSearch) ? '' : 'none';
      });
    }
  </script>
</body>
</html>`);
});

app.post('/admin/create', requireAdmin, async (req, res) => {
  const plan = req.body.plan || 'daily';
  const custom = parseInt(req.body.custom_seconds || '0', 10);
  const maxDevices = Math.max(1, parseInt(req.body.max_devices || '1', 10));
  const count = Math.min(50, Math.max(1, parseInt(req.body.count || '1', 10)));
  const note = (req.body.note || '').trim();
  const durationSeconds = planSeconds(plan, custom);
  for (let i = 0; i < count; i++) {
    let code = formatKey();
    try {
      await Key.create({ keyCode: code, plan, durationSeconds, maxDevices, note });
    } catch (e) {
      i--; // retry on collision
    }
  }
  res.redirect('/admin');
});

app.post('/admin/revoke', requireAdmin, async (req, res) => {
  await Key.findByIdAndUpdate(req.body.id, { status: 'revoked' });
  res.redirect('/admin');
});

app.post('/admin/extend', requireAdmin, async (req, res) => {
  const add = Math.max(60, parseInt(req.body.add_seconds || '3600', 10));
  const doc = await Key.findById(req.body.id);
  if (doc) {
    const now = new Date();
    let base = doc.expiresAt && doc.expiresAt > now ? doc.expiresAt : now;
    doc.expiresAt = new Date(base.getTime() + add * 1000);
    doc.durationSeconds += add;
    doc.status = 'active';
    await doc.save();
  }
  res.redirect('/admin');
});

app.post('/admin/reset', requireAdmin, async (req, res) => {
  const add = Math.max(60, parseInt(req.body.add_seconds || '86400', 10));
  const now = new Date();
  await Key.findByIdAndUpdate(req.body.id, {
    activatedAt: now,
    expiresAt: new Date(now.getTime() + add * 1000),
    durationSeconds: add,
    status: 'active',
  });
  res.redirect('/admin');
});

async function start() {
  await mongoose.connect(config.MONGO_URI);
  console.log('MongoDB connected');
  const existing = await Admin.findOne({ username: config.ADMIN_USER });
  if (!existing) {
    const passwordHash = await bcrypt.hash(config.ADMIN_PASS, 10);
    await Admin.create({ username: config.ADMIN_USER, passwordHash });
    console.log('Admin created:', config.ADMIN_USER, config.ADMIN_PASS);
  }
  app.listen(config.PORT, () => console.log('OxiKey on :' + config.PORT));
}
start().catch(e => { console.error(e); process.exit(1); });
