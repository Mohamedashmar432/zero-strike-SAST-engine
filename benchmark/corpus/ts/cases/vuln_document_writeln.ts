// ZS-TS-047: DOM XSS via document.writeln() with a tainted value
const msg = location.hash.slice(1);
document.writeln(msg);
