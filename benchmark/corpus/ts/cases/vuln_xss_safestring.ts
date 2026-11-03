declare const Handlebars: any;

export function linkHelper(url: string, text: string) {
  return new Handlebars.SafeString('<a href="' + url + '">' + text + '</a>');
}
