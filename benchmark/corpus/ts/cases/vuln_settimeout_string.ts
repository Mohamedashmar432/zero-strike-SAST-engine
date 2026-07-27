// ZS-TS-054: setTimeout() with a tainted string argument (eval-like)
const code = location.hash.slice(1);
setTimeout(code, 100);
