// ZS-TS-042: weak symmetric cipher — crypto.createCipheriv('des-ede3')
import crypto from 'crypto';
function encrypt(data: string, key: Buffer, iv: Buffer): string {
  const cipher = crypto.createCipheriv('des-ede3', key, iv);
  return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}
