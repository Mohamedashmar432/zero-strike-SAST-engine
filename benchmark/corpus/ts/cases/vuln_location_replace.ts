// ZS-TS-049: DOM open redirect via location.replace() with a tainted destination
const dest = location.hash.slice(1);
location.replace(dest);
