// ZS-TS-083: SSRF — axios.delete() to a tainted URL
const url = req.query.url;
axios.delete(url);
