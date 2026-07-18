// ZS-JS-039: NoSQL injection — collection.find() with a request-derived filter
function search(req, res, collection) {
  const term = req.query.q;
  collection.find(term);
}
