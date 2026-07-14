// ZS-TS-026: CORS misconfiguration — res.setHeader() reflects the request's origin
// directly into Access-Control-Allow-Origin (source: req.query, inline, no
// intermediate variable)
function setCors(req: any, res: any) {
  res.setHeader('Access-Control-Allow-Origin', req.query.origin);
}
