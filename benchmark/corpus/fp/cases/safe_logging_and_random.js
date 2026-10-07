// JavaScript mirror of safe_logging_and_random.ts: log forging (ZS-JS-083),
// weak PRNG (ZS-JS-023), hardcoded secrets (ZS-JS-007), empty catch
// (ZS-JS-010), jwt.decode (ZS-JS-008) and MD5 checksums (ZS-JS-026).
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');

function gracefulShutdown(msg, cb) {
  console.log(`Mongoose disconnected through ${msg}`);
  cb();
}

function captcha() {
  const firstTerm = Math.floor(Math.random() * 10 + 1);
  return firstTerm;
}

const BeeTokenAddress = '0x3643b7a9f6338115159a4d3a2cc678c99ad657aa';
const csrfToken = "{{ csrf_token }}";

function parseMetadata(req) {
  try {
    JSON.parse(req.body.metadata);
  } catch (e) {
  }
  try {
    doThing();
  } catch (e) {
    // ignore
  }
}

function checkToken(token, key) {
  const decoded = jwt.decode(token);
  jwt.verify(token, key);
  return decoded;
}

function writeChecksum() {
  const md5 = crypto.createHash('md5');
  md5.update(fs.readFileSync('dist/app.zip'));
  fs.writeFileSync('dist/app.zip.md5', md5.digest('hex'));
  console.log('Checksum written');
}

module.exports = { gracefulShutdown, captcha, BeeTokenAddress, csrfToken, parseMetadata, checkToken, writeChecksum };
