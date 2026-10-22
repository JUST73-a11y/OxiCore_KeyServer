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
    if (secret !== config.API_SECRET) return res.status(403).json({ ok: false, msg: 'forbidden' });
    if (!key || !device_id) return res.status(400).json({ ok: false, msg: 'missing fields' });

    const doc = await Key.findOne({ keyCode: String(key).trim() });
    if (!doc) return res.status(404).json({ ok: false, msg: 'invalid key' });
    if (doc.status === 'revoked') return res.status(403).json({ ok: false, msg: 'key revoked' });

    const now = new Date();
    if (!doc.activatedAt) {
      doc.activatedAt = now;
      doc.expiresAt = new Date(now.getTime() + doc.durationSeconds * 1000);
      doc.status = 'active';
    } else if (doc.expiresAt && now > doc.expiresAt) {
      doc.status = 'expired';
      await doc.save();
      return res.status(403).json({ ok: false, msg: 'key expired' });
    }

    const existing = doc.devices.find(d => d.deviceId === device_id);
    if (!existing) {
      if (doc.devices.length >= doc.maxDevices) {
        return res.status(403).json({ ok: false, msg: 'device limit reached' });
      }
      doc.devices.push({ deviceId: device_id, firstSeen: now, lastSeen: now });
    } else {
      existing.lastSeen = now;
    }
    await doc.save();

    return res.json({
      ok: true,
      msg: 'ok',
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

app.post('/api/validate', async (req, res) => {
  try {
    const { key, device_id, secret } = req.body || {};
    if (secret !== config.API_SECRET) return res.status(403).json({ ok: false, msg: 'forbidden' });
    if (!key || !device_id) return res.status(400).json({ ok: false, msg: 'missing fields' });

    const doc = await Key.findOne({ keyCode: String(key).trim(), 'devices.deviceId': device_id });
    if (!doc) return res.status(404).json({ ok: false, msg: 'not activated' });
    if (doc.status === 'revoked') return res.status(403).json({ ok: false, msg: 'key revoked' });

    const now = new Date();
    if (!doc.expiresAt || now > doc.expiresAt) {
      doc.status = 'expired';
      await doc.save();
      return res.status(403).json({ ok: false, msg: 'key expired' });
    }
    const d = doc.devices.find(x => x.deviceId === device_id);
    if (d) d.lastSeen = now;
    await doc.save();

    return res.json({
      ok: true,
      expires_at: doc.expiresAt,
      expires_ts: Math.floor(doc.expiresAt.getTime() / 1000),
      server_time: Math.floor(Date.now() / 1000),
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, msg: 'server error' });
  }
});

// ---------- ADMIN ----------
function requireAdmin(req, res, next) {
  if (req.session && req.session.admin) return next();
  return res.redirect('/admin/login');
}

app.get('/admin/login', (req, res) => {
  res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>OxiKey</title>
<style>body{font-family:sans-serif;max-width:360px;margin:80px auto}input,button{width:100%;padding:10px;margin:6px 0}</style>
</head><body><h2>OxiKey Admin</h2>
<form method="POST" action="/admin/login">
<input name="username" placeholder="username" required>
<input name="password" type="password" placeholder="password" required>
<button>Login</button></form></body></html>`);
});

app.post('/admin/login', async (req, res) => {
  const { username, password } = req.body || {};
  const admin = await Admin.findOne({ username });
  if (!admin || !(await bcrypt.compare(password || '', admin.passwordHash))) {
    return res.status(401).send('wrong login <a href="/admin/login">back</a>');
  }
  req.session.admin = admin.username;
  res.redirect('/admin');
});

app.get('/admin/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/admin/login'));
});

app.get('/admin', requireAdmin, async (req, res) => {
  const keys = await Key.find().sort({ createdAt: -1 }).limit(200).lean();
  const rows = keys.map(k => {
    const devs = (k.devices || []).length;
    return `<tr>
<td>${k._id}</td>
<td><code>${k.keyCode}</code></td>
<td>${k.plan} (${k.durationSeconds}s)</td>
<td>${k.status}</td>
<td>${devs}/${k.maxDevices}</td>
<td>${k.activatedAt ? new Date(k.activatedAt).toISOString() : '-'}</td>
<td>${k.expiresAt ? new Date(k.expiresAt).toISOString() : '-'}</td>
<td>${k.note || ''}</td>
<td>
<form class="i" method="POST" action="/admin/revoke"><input type="hidden" name="id" value="${k._id}"><button>revoke</button></form>
<form class="i" method="POST" action="/admin/extend"><input type="hidden" name="id" value="${k._id}">
<input name="add_seconds" type="number" value="3600" style="width:80px"><button>extend</button></form>
<form class="i" method="POST" action="/admin/reset"><input type="hidden" name="id" value="${k._id}">
<input name="add_seconds" type="number" value="86400" style="width:80px"><button>reset now</button></form>
</td></tr>`;
  }).join('');

  res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>OxiKey Admin</title>
<style>
body{font-family:sans-serif;margin:20px;font-size:14px}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ccc;padding:6px;text-align:left;vertical-align:top}
form.i{display:inline}
input,select,button{padding:6px;margin:2px}
</style></head><body>
<h2>OxiKey Admin — ${req.session.admin}</h2>
<p><a href="/admin/logout">logout</a></p>
<h3>Yangi key</h3>
<form method="POST" action="/admin/create">
plan <select name="plan">
<option value="1h">1 soat</option><option value="2h">2 soat</option>
<option value="daily" selected>1 kun</option><option value="weekly">1 hafta</option>
<option value="custom">custom</option></select>
custom sekund <input name="custom_seconds" type="number" value="3600" style="width:100px">
max device <input name="max_devices" type="number" value="1" style="width:60px">
soni <input name="count" type="number" value="1" style="width:60px">
note <input name="note" placeholder="mijoz">
<button>Yaratish</button>
</form>
<h3>Keys</h3>
<table>
<tr><th>ID</th><th>Key</th><th>Plan</th><th>Status</th><th>Devices</th><th>Activated</th><th>Expires</th><th>Note</th><th>Actions</th></tr>
${rows}
</table>
</body></html>`);
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
      i--; // retry on rare collision
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

app.get('/', (req, res) => res.send('OxiKey server OK'));

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
