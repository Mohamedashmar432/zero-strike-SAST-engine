// ZS-TS-037: NoSQL injection — collection.find() with a request-derived filter
function search(req: any, res: any, collection: any) {
  const term: string = req.query.q;
  collection.find(term);
}
