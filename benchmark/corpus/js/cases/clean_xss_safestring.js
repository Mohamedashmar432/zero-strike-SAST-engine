// Every interpolated value is escaped before being marked safe.
const Handlebars = require('handlebars');
Handlebars.registerHelper('bold', function (text) {
  return new Handlebars.SafeString('<b>' + Handlebars.Utils.escapeExpression(text) + '</b>');
});
