// ZS-TS-055: setInterval() with a tainted string argument (eval-like)
const code = location.hash.slice(1);
setInterval(code, 100);
