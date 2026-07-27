// ZS-JS-081: SSTI via nunjucks.renderString() with a tainted template
const tpl = req.body.tpl;
nunjucks.renderString(tpl, {});
