// ZS-TS-078: SSTI via handlebars.compile() with a tainted template
const tpl = req.body.tpl;
handlebars.compile(tpl);
