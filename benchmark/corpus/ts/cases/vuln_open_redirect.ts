// ZS-TS-019: open redirect — target traces back to req.query (untrusted input)
function redirect(req: any, res: any) {
  const target: string = req.query.url;
  if (target) {
    res.redirect(target);
  }
}
