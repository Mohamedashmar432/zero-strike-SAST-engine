// ZS-TS-040: SSTI — pug.render() with a template string sourced inline from req.body
import pug from 'pug';
function renderCard(req: any, res: any) {
  pug.render(req.body.tpl);
}
