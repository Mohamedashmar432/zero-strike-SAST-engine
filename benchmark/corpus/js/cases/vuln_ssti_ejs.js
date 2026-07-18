// ZS-JS-041: SSTI — ejs.render() with a template string from the request
const ejs = require('ejs');
function renderPage(req, res) {
  const tpl = req.body.template;
  ejs.render(tpl, {});
}
