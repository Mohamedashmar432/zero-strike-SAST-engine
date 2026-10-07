// Precision fixtures for log forging (ZS-TS-081), weak PRNG (ZS-TS-021),
// hardcoded secrets (ZS-TS-012), empty catch (ZS-TS-005) and jwt.decode
// (ZS-TS-013). Each construct below fired before its rule was narrowed.
import * as jwt from 'jsonwebtoken';
import { randomBytes } from 'crypto';

// A logger wrapper: `message` is only a parameter, not request data, so there
// is no untrusted party to forge log lines (require_real_source).
export const logger = {
  info(message: string): void {
    console.log(`[ops] ${message}`);
  },
};

// Math.random() for a captcha operand, a shuffle and a display id.
export function captcha() {
  const firstTerm = Math.floor(Math.random() * 10 + 1);
  const secondTerm = Math.floor(Math.random() * 10 + 1);
  return { firstTerm, secondTerm };
}
export function shuffle<T>(items: T[]): T[] {
  return items.sort(() => Math.random() - 0.5);
}
export function generateMrn(): string {
  return `MRN-${Math.floor(100000 + Math.random() * 899999)}`;
}

// Credential-looking names that are not credentials.
const BeeTokenAddress = '0x3643b7a9f6338115159a4d3a2cc678c99ad657aa';
const tokenUrl = 'https://auth.example.com/oauth/token';
const csrfToken = '{{ csrf_token }}';
export function newApiKey(): string {
  const secret = randomBytes(24).toString('base64url');
  const token = `zs_${secret}`;
  return token;
}

// Deliberate, documented swallows and parse-or-fallback.
export function readPrefs(raw: string) {
  try {
    return JSON.parse(raw);
  } catch (e) {
  }
  try {
    notifyPartner();
  } catch (e) {
    // best effort: the partner callback is optional
  }
  return {};
}

// jwt.decode to read the header before verifying in the same function.
export function checkToken(token: string, key: string) {
  const decoded = jwt.decode(token, { complete: true });
  jwt.verify(token, key);
  return decoded;
}

declare function notifyPartner(): void;
export { BeeTokenAddress, tokenUrl, csrfToken };
