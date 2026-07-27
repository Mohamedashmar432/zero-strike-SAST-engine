// ZS-TS-050: DOM open redirect via window.open() with a tainted URL
const target = location.hash.slice(1);
window.open(target);
