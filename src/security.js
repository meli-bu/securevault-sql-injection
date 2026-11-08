const crypto = require('node:crypto');

function getEncryptionKey() {
  const value = process.env.AES_256_KEY || '';
  if (!/^[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error('AES_256_KEY must contain exactly 64 hexadecimal characters (32 bytes).');
  }
  return Buffer.from(value, 'hex');
}

function encrypt(plainText) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', getEncryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(String(plainText), 'utf8'), cipher.final()]);
  return [iv.toString('hex'), cipher.getAuthTag().toString('hex'), encrypted.toString('hex')].join(':');
}

function decrypt(payload) {
  const [ivHex, tagHex, dataHex] = String(payload).split(':');
  if (!ivHex || !tagHex || !dataHex) throw new Error('Invalid encrypted value.');
  const decipher = crypto.createDecipheriv('aes-256-gcm', getEncryptionKey(), Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  return Buffer.concat([decipher.update(Buffer.from(dataHex, 'hex')), decipher.final()]).toString('utf8');
}

function hashToken(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

module.exports = { encrypt, decrypt, hashToken };