// ZS-JS-085: SSRF — axios.delete() to a tainted URL
const url = req.query.url;
axios.delete(url);
