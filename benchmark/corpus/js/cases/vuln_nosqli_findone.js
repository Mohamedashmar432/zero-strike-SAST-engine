// ZS-JS-060: NoSQL injection via findOne() with a tainted filter
const name = req.query.name;
collection.findOne({ name: name });
