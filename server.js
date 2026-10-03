const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const ADMIN_KEY = process.env.ADMIN_KEY || 'change-me-please';
const DB_FILE = path.join(__dirname, 'license-db.json');

let DB = {
  users: {},
  sessions: {},
  stats: {
    totalRequests: 0,
    totalDenied: 0,
    totalAllowed: 0,
    startedAt: Date.now(),
  },
};

if (fs.existsSync(DB_FILE)) {
  try { DB = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch (e) { console.error('[DB] Failed to load:', e.message); }
}

function saveDB() {
  try { fs.writeFileSync(DB_FILE, JSON.stringify(DB, null, 2)); }
  catch (e) { /* read-only fs on free tier */ }
}
setInterval(saveDB, 30000);

function generateToken(userId, gameId) {
  const raw = `${userId}:${gameId}:${Date.now()}:${crypto.randomBytes(8).toString('hex')}`;
  const token = crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16);
  const expires = Date.now() + 3600000;
  DB.sessions[token] = { userId, gameId, expires };
  const now = Date.now();
  for (const t of Object.keys(DB.sessions)) {
    if (DB.sessions[t].expires < now) delete DB.sessions[t];
  }
  return token;
}

const app = express();
app.use(express.json());
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} - ${req.ip}`);
  next();
});

app.get('/', (req, res) => {
  res.send('FLOREX License Server — running');
});

app.get('/api/key', (req, res) => {
  DB.stats.totalRequests++;
  const userId = String(req.query.u || '');
  const gameId = String(req.query.g || '');

  if (!userId || userId === '0') {
    DB.stats.totalDenied++;
    return res.status(400).send('no_user');
  }

  let user = DB.users[userId];

  if (!user) {
    user = DB.users[userId] = {
      allowed: true,
      banned: false,
      firstSeen: Date.now(),
      lastSeen: Date.now(),
      gameIds: [],
      requestCount: 0,
    };
  }

  user.lastSeen = Date.now();
  user.requestCount = (user.requestCount || 0) + 1;
  if (gameId && !user.gameIds.includes(gameId)) {
    user.gameIds.push(gameId);
  }

  if (user.banned || !user.allowed) {
    DB.stats.totalDenied++;
    return res.status(403).send('banned');
  }

  const token = generateToken(userId, gameId);
  DB.stats.totalAllowed++;
  res.send(token.slice(0, 8));
});

app.get('/api/heartbeat', (req, res) => {
  const token = String(req.query.t || '');
  const session = DB.sessions[token];
  if (!session) return res.status(403).send('revoked');
  if (session.expires < Date.now()) {
    delete DB.sessions[token];
    return res.status(403).send('expired');
  }
  res.send('ok');
});

app.use('/admin', (req, res, next) => {
  const key = req.headers['x-admin-key'] || req.query.key;
  if (key !== ADMIN_KEY) return res.status(403).send('forbidden');
  next();
});

app.post('/admin/ban', (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).send('need userId');
  DB.users[userId] = DB.users[userId] || {};
  DB.users[userId].banned = true;
  DB.users[userId].allowed = false;
  for (const t of Object.keys(DB.sessions)) {
    if (DB.sessions[t].userId === String(userId)) delete DB.sessions[t];
  }
  saveDB();
  res.json({ ok: true, banned: userId });
});

app.post('/admin/unban', (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).send('need userId');
  if (DB.users[userId]) {
    DB.users[userId].banned = false;
    DB.users[userId].allowed = true;
  }
  saveDB();
  res.json({ ok: true, unbanned: userId });
});

app.get('/admin/stats', (req, res) => {
  res.json({
    stats: DB.stats,
    usersCount: Object.keys(DB.users).length,
    sessionsCount: Object.keys(DB.sessions).length,
    uptime: Date.now() - DB.stats.startedAt,
  });
});

app.get('/admin/users', (req, res) => {
  res.json(DB.users);
});

app.listen(PORT, () => {
  console.log(`[FLOREX License Server] listening on port ${PORT}`);
  console.log(`[FLOREX] admin key: ${ADMIN_KEY.slice(0, 4)}****`);
});
