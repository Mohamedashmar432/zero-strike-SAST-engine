// ZS-JS-023: weak PRNG — Math.random() used to generate a security-sensitive token
function generatePasswordResetToken() {
  return Math.random().toString(36).slice(2);
}
