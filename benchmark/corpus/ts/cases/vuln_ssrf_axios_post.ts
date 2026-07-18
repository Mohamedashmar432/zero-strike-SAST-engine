// ZS-TS-034: SSRF — axios.post() with the endpoint sourced inline from req.body
import axios from 'axios';
function postRemote(req: any, res: any) {
  axios.post(req.body.endpoint, { ok: true });
}
