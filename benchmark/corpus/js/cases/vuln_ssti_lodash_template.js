// ZS-JS-079: SSTI via lodash _.template() with a tainted template
const tpl = req.body.tpl;
_.template(tpl)({});
