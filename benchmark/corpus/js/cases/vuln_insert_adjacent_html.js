// ZS-JS-047: DOM XSS — el.insertAdjacentHTML() with request-derived HTML
function showBanner(req, res, el) {
  const html = req.query.msg;
  el.insertAdjacentHTML('beforeend', html);
}
