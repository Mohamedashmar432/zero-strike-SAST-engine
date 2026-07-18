// ZS-TS-045: DOM XSS — el.insertAdjacentHTML() with request-derived HTML
function showBanner(req: any, res: any, el: HTMLElement) {
  const html: string = req.query.msg;
  el.insertAdjacentHTML('beforeend', html);
}
