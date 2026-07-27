// ZS-TS-051: DOM XSS via iframe srcdoc assigned from a tainted value
const html = location.hash.slice(1);
frame.srcdoc = html;
