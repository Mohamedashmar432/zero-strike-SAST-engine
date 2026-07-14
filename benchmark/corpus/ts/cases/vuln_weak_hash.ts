// ZS-TS-024: weak cryptographic hash algorithm — crypto.createHash('md5')
import crypto from 'crypto';
const input: string = "some-input";
const hash: string = crypto.createHash('md5').update(input).digest('hex');
