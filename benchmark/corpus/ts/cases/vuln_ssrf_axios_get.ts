// ZS-TS-033: SSRF — axios.get() with a URL taken from the request
import axios from 'axios';
function fetchRemote(req: any, res: any) {
  const target: string = req.query.url;
  axios.get(target);
}
