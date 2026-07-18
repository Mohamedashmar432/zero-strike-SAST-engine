// ZS-TS-039: SSTI — ejs.render() with a template string from the request
import ejs from 'ejs';
function renderPage(req: any, res: any) {
  const tpl: string = req.body.template;
  ejs.render(tpl, {});
}
