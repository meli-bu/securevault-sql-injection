require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const crypto = require('node:crypto');
const db = require('./database');
const { encrypt, decrypt, hashToken } = require('./security');

const app = express();
const PORT = Number(process.env.PORT) || 3000;

app.use(helmet());
app.use(express.json({ limit: '20kb' }));

function requireAdmin(req, res, next) {
  const provided = req.get('x-admin-secret') || '';
  const expected = process.env.ADMIN_SECRET || '';
  if (!expected || provided.length !== expected.length ||
      !crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(expected))) {
    return res.status(401).json({ error: 'First security layer failed: administrator authentication required.' });
  }
  next();
}

function requireCapability(req, res, next) {
  const code = req.get('x-capability-code') || '';
  if (!code) return res.status(401).json({ error: 'Second security layer failed: capability code required.' });
  const row = db.prepare('SELECT id, expires_at, used_at FROM capability_codes WHERE token_hash = ?')
    .get(hashToken(code));
  if (!row || row.used_at || row.expires_at < Date.now()) {
    return res.status(403).json({ error: 'Capability code is invalid, expired, or already used.' });
  }
  db.prepare('UPDATE capability_codes SET used_at = ? WHERE id = ?').run(Date.now(), row.id);
  next();
}

app.get('/', (req, res) => res.json({
  name: 'SecureVault API',
  status: 'running',
  security: ['Parameterized SQL queries', 'AES-256-GCM encryption', 'Two-layer write authorization'],
  endpoints: ['GET /api/users', 'POST /api/security/capability', 'POST /api/users']
}));

// Public read. Search text is bound as a parameter, never concatenated into SQL.
app.get('/api/users', (req, res) => {
  const search = String(req.query.search || '').slice(0, 80);
  const rows = search
    ? db.prepare('SELECT id, full_name, email_encrypted, sensitive_note_encrypted, created_at FROM users WHERE full_name LIKE ? ORDER BY id DESC').all(`%${search}%`)
    : db.prepare('SELECT id, full_name, email_encrypted, sensitive_note_encrypted, created_at FROM users ORDER BY id DESC').all();

  res.json(rows.map(row => ({
    id: row.id,
    fullName: row.full_name,
    email: decrypt(row.email_encrypted),
    sensitiveNote: decrypt(row.sensitive_note_encrypted),
    createdAt: row.created_at
  })));
});

// Layer 1: admin secret. Issue a random, short-lived, one-time capability code.
app.post('/api/security/capability', requireAdmin, (req, res) => {
  const code = crypto.randomBytes(24).toString('base64url');
  const ttl = Math.min(Math.max(Number(process.env.CAPABILITY_TTL_MINUTES) || 5, 1), 15);
  const expiresAt = Date.now() + ttl * 60 * 1000;
  db.prepare('INSERT INTO capability_codes (token_hash, expires_at) VALUES (?, ?)').run(hashToken(code), expiresAt);
  res.status(201).json({ message: 'Temporary capability code created. It can be used once.', capabilityCode: code, expiresInMinutes: ttl });
});

// Both layers are required to write a record.
app.post('/api/users', requireAdmin, requireCapability, (req, res) => {
  const { fullName, email, sensitiveNote } = req.body || {};
  if (![fullName, email, sensitiveNote].every(v => typeof v === 'string' && v.trim())) {
    return res.status(400).json({ error: 'fullName, email, and sensitiveNote are required strings.' });
  }
  if (fullName.length > 100 || email.length > 254 || sensitiveNote.length > 2000) {
    return res.status(400).json({ error: 'One or more fields exceed the allowed length.' });
  }
  const result = db.prepare(
    'INSERT INTO users (full_name, email_encrypted, sensitive_note_encrypted) VALUES (?, ?, ?)'
  ).run(fullName.trim(), encrypt(email.trim()), encrypt(sensitiveNote.trim()));
  res.status(201).json({ message: 'User record saved securely.', id: result.lastInsertRowid });
});

app.use((err, req, res, next) => {
  console.error(err.message);
  res.status(500).json({ error: 'Internal server error.' });
});

app.listen(PORT, '0.0.0.0', () => console.log(`SecureVault API running on port ${PORT}`));