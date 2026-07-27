// ZS-JS-084: SSRF — axios.put() to a tainted URL
const url = req.query.url;
axios.put(url, data);
