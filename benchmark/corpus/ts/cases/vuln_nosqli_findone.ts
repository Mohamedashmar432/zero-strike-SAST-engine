// ZS-TS-058: NoSQL injection via findOne() with a tainted filter
const name = req.query.name;
collection.findOne({ name: name });
