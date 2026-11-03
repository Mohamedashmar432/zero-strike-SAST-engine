declare const Handlebars: any;

export function boldHelper(t: string) {
  return new Handlebars.SafeString('<b>' + Handlebars.Utils.escapeExpression(t) + '</b>');
}
