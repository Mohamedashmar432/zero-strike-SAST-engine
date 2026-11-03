// Server-rendered state embedded in an inline script without escaping "<".
function render(res, state) {
  res.type('html');
  res.end(`<html><body><script>window.__INITIAL_STATE__=${JSON.stringify(state)}</script></body></html>`);
}
module.exports = render;
