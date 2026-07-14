// ZS-TS-025: CORS misconfiguration — res.header() reflects the request's origin
// directly into Access-Control-Allow-Origin (source: req.query, inline, no
// intermediate variable)
function setCors(req: any, res: any) {
  res.header('Access-Control-Allow-Origin', req.query.origin);
}
