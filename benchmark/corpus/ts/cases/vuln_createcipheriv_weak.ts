// ZS-TS-086: crypto.createCipheriv weak cipher algorithm
import * as crypto from 'crypto';
const cipher = crypto.createCipheriv('des', key, iv);
