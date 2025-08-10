// server.js
require('dotenv').config();
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');

const app = express();
app.use(helmet());
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// Basic rate limit
app.use(rateLimit({ windowMs: 60_000, max: 200 }));

// Config / env
const PORT = process.env.PORT || 3000;
const DB_FILE = process.env.DB_FILE || './data.db';
const JWT_SECRET = process.env.JWT_SECRET || 'replace_this_jwt_secret';
const ADMIN_KEY = process.env.ADMIN_KEY || 'replace_admin_key';
const FRONTEND_URL = process.env.FRONTEND_URL || `http://localhost:${PORT}`;

// Email (Nodemailer) setup (optional)
let transporter = null;
if (process.env.SMTP_HOST && process.env.SMTP_USER) {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '587', 10),
    secure: process.env.SMTP_SECURE === 'true',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });
  transporter.verify()
    .then(() => console.log('SMTP configured'))
    .catch(err => console.warn('SMTP verify failed:', err.message));
} else {
  console.log('SMTP not configured; email sending is disabled until env set.');
}

// Open SQLite DB
let db;
(async () => {
  db = await open({ filename: DB_FILE, driver: sqlite3.Database });
  await db.exec(`
    CREATE TABLE IF NOT EXISTS passwords (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      hash TEXT NOT NULL,
      label TEXT,
      created_at INTEGER NOT NULL
    );
  `);

  await db.exec(`
    CREATE TABLE IF NOT EXISTS email_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT,
      subject TEXT,
      body TEXT,
      sent_at INTEGER
    );
  `);

  // Insert test password on first run if none exist
  const row = await db.get('SELECT COUNT(1) as cnt FROM passwords');
  if (row && row.cnt === 0) {
    const testPlain = 'TestAccess123';
    const hash = await bcrypt.hash(testPlain, 10);
    await db.run('INSERT INTO passwords (hash, label, created_at) VALUES (?, ?, ?)', [hash, 'Test password (delete in prod)', Date.now()]);
    console.log('Inserted test password ->', testPlain);
  }
})();

// Helpers
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

async function verifyPasswordAgainstDB(plain) {
  const rows = await db.all('SELECT id, hash FROM passwords');
  for (const r of rows) {
    const ok = await bcrypt.compare(plain, r.hash);
    if (ok) return { ok: true, id: r.id };
  }
  return { ok: false };
}

function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'missing authorization header' });
  const token = auth.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'invalid or expired token' });
  }
}

function requireAdmin(req, res, next) {
  const key = req.headers['x-admin-key'] || req.query.admin_key;
  if (!key || key !== ADMIN_KEY) return res.status(403).json({ error: 'admin auth required' });
  next();
}

// Public endpoints

// Login with purchase password -> returns JWT
app.post('/api/login', async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'password required' });

  try {
    const r = await verifyPasswordAgainstDB(password);
    if (!r.ok) return res.status(401).json({ error: 'invalid password' });

    const token = signToken({ access: true, issuedAt: Date.now() });
    return res.json({ token, expiresIn: 7 * 24 * 3600 });
  } catch (err) {
    console.error('login error', err);
    return res.status(500).json({ error: 'internal error' });
  }
});

// Protected test route
app.get('/api/protected', requireAuth, (req, res) => {
  res.json({ ok: true, message: 'You have access to protected API.' });
});

// Send password by email (admin or manual trigger)
app.post('/api/send-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'email required' });

  // retrieve a password to send: for simplicity we send the first password plaintext only in test mode
  // PRODUCTION: generate unique password per user and store hashed entry instead
  const row = await db.get('SELECT id, hash, label FROM passwords ORDER BY created_at ASC LIMIT 1');
  if (!row) return res.status(500).json({ error: 'no password available' });

  // We cannot reverse hash. For production, generate and store plaintext->hash when creating.
  // For convenience in this test bundle we assume the test password is TestAccess123.
  const testPlain = process.env.TEST_PASSWORD || 'TestAccess123'; // used for send-email convenience

  if (!transporter) {
    // Log to DB and return success note but instruct operator to enable SMTP
    await db.run('INSERT INTO email_log (email, subject, body, sent_at) VALUES (?, ?, ?, ?)', [
      email, 'Access password', `Password: ${testPlain}`, Date.now()
    ]);
    return res.json({ ok: true, message: 'SMTP not configured — password logged. Enable SMTP to send real emails.' });
  }

  try {
    const info = await transporter.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: email,
      subject: 'Your Reels Auto-Poster Access Password',
      text: `Hello,\n\nYour access password is: ${testPlain}\n\nLogin at: ${FRONTEND_URL}/login.html`,
      html: `<p>Hello,</p><p>Your access password is: <strong>${testPlain}</strong></p><p>Login at: <a href="${FRONTEND_URL}/login.html">${FRONTEND_URL}/login.html</a></p>`
    });

    await db.run('INSERT INTO email_log (email, subject, body, sent_at) VALUES (?, ?, ?, ?)', [
      email, 'Access password', `Password: ${testPlain}`, Date.now()
    ]);

    return res.json({ ok: true, message: 'Email sent', info });
  } catch (err) {
    console.error('email send failed', err);
    return res.status(500).json({ error: 'email send failed' });
  }
});

// Admin endpoints (protected by ADMIN_KEY header)
app.get('/admin/passwords', requireAdmin, async (req, res) => {
  const rows = await db.all('SELECT id, label, created_at FROM passwords ORDER BY created_at DESC');
  res.json({ ok: true, passwords: rows });
});

app.post('/admin/add-password', requireAdmin, express.json(), async (req, res) => {
  const { password, label } = req.body;
  if (!password) return res.status(400).json({ error: 'password required' });

  const hash = await bcrypt.hash(password, 10);
  await db.run('INSERT INTO passwords (hash, label, created_at) VALUES (?, ?, ?)', [hash, label || null, Date.now()]);
  res.json({ ok: true });
});

app.post('/admin/remove-password', requireAdmin, express.json(), async (req, res) => {
  const { id } = req.body;
  if (!id) return res.status(400).json({ error: 'id required' });
  await db.run('DELETE FROM passwords WHERE id = ?', [id]);
  res.json({ ok: true });
});

// Health
app.get('/ping', (req, res) => res.json({ ok: true }));

// Serve admin page
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

// Start
app.listen(PORT, () => {
  console.log(`Server listening on ${PORT}`);
  console.log(`Open ${FRONTEND_URL}/login.html`);
});
