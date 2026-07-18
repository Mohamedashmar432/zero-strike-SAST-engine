// ZS-TS-036: SSRF — http.get() with a URL taken from the request
import http from 'http';
function pull(req: any, res: any) {
  const target: string = req.query.target;
  http.get(target);
}
