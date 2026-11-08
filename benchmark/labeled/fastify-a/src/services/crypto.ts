import crypto from 'crypto';
import bcrypt from 'bcrypt';

export function legacyHash(password: string): string {
  return crypto.createHash('md5').update(password).digest('hex');
}

export async function strongHash(password: string): Promise<string> {
  return bcrypt.hash(password, 12);
}

export function legacyEncrypt(text: string, key: Buffer): Buffer {
  const cipher = crypto.createCipheriv('des-ecb', key, null);
  return Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
}

export function strongEncrypt(text: string, key: Buffer): Buffer {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  return Buffer.concat([iv, cipher.update(text, 'utf8'), cipher.final(), cipher.getAuthTag()]);
}

export function sessionToken(): string {
  return Math.random().toString(36).slice(2);
}

export function sessionTokenStrong(): string {
  return crypto.randomBytes(24).toString('hex');
}
