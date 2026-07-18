// ZS-JS-042: SSTI — pug.render() with a template string sourced inline from req.body
const pug = require('pug');
function renderCard(req, res) {
  pug.render(req.body.tpl);
}
