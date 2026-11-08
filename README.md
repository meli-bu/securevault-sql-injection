# SecureVault – SQL Injection Protection and Data Security

A lightweight Express API demonstrating SQL injection prevention, AES-256-GCM encryption, capability codes, and two-layer authorization.

## Assignment requirements

1. **SQL injection protection:** SQL statements use prepared/parameterized queries (`?`). User input is never joined into SQL command text.
2. **AES-256 encryption:** email addresses and sensitive notes are encrypted with AES-256-GCM before storage. GCM also authenticates encrypted data.
3. **Capability code:** an administrator can generate a random, short-lived, one-time code. Only its SHA-256 hash is stored.
4. **Double-layer security:** write operations require both an administrator secret (`x-admin-secret`) and a valid one-time capability code (`x-capability-code`).
5. **Internet-ready:** Express listens on `0.0.0.0` and uses the hosting platform's `PORT`.

## Requirements

- Node.js 20+
- npm

## Run locally

```bash
npm install
```

Copy `.env.example` to `.env`. Set a long random `ADMIN_SECRET` and an `AES_256_KEY` containing exactly 64 hexadecimal characters.

Generate the AES key:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Start:

```bash
npm start
```

Open `http://localhost:3000`.

## API

- `GET /` – health check
- `GET /api/users` – list records
- `GET /api/users?search=Sara` – parameterized name search
- `POST /api/security/capability` – generate one-time code; send `x-admin-secret`
- `POST /api/users` – save encrypted record; send both `x-admin-secret` and `x-capability-code`

Example create body:

```json
{
  "fullName": "Sara Example",
  "email": "sara@example.com",
  "sensitiveNote": "Example private information"
}
```

Generate a fresh capability code for every create request. The code expires after a few minutes and is consumed once.

## SQL injection test

Try `GET /api/users?search=%25%27%20OR%201%3D1--`. The string is treated as ordinary search text because it is bound as a SQL parameter. It cannot change the SQL query structure.

## Deploy

Deploy as a Node.js service on Render, Railway, or another Node host. Build command: `npm install`. Start command: `npm start`. Configure `ADMIN_SECRET` and `AES_256_KEY` as environment variables in the host dashboard, never in GitHub.

**Persistence warning:** SQLite files on many free hosts can be erased on restart/redeploy. Use a persistent disk or managed database for persistent production data.

## Security notes

- Passwords must be hashed with Argon2id or scrypt, not reversibly encrypted. This demo encrypts private profile fields, not passwords.
- Use HTTPS in production.
- Add rate limiting, audit logs, backups, and managed persistent storage before real-world use.
- The capability code is an extra authorization layer, not a replacement for proper user authentication.

## Structure

```text
securevault-sql-injection/
├── src/
│   ├── database.js
│   ├── security.js
│   └── server.js
├── postman/
│   └── SecureVault.postman_collection.json
├── .env.example
├── .gitignore
├── package.json
└── README.md
```
