// ZS-TS-035: SSRF — global fetch() with a URL taken from the request
function proxy(req: any, res: any) {
  const target: string = req.query.url;
  fetch(target);
}
