// "<" is escaped before the JSON is embedded in the inline script.
function render(res, state) {
  res.type('html');
  const json = JSON.stringify(state).replace(/</g, '\\u003c');
  res.end(`<html><body><script>window.__INITIAL_STATE__=${json}</script></body></html>`);
}
module.exports = render;
