// ZS-JS-050: DOM open redirect via location.assign() with a tainted destination
const dest = location.hash.slice(1);
location.assign(dest);
