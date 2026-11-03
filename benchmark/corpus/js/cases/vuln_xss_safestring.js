// Handlebars helper marking concatenated, unescaped markup as safe.
const Handlebars = require('handlebars');
Handlebars.registerHelper('link', function (url, text) {
  return new Handlebars.SafeString('<a href="' + url + '">' + text + '</a>');
});
