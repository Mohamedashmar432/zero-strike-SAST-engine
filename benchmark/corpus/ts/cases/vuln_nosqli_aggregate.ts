// ZS-TS-059: NoSQL injection via aggregate() with a tainted pipeline
const name = req.query.name;
const pipeline = [{ $match: { name: name } }];
collection.aggregate(pipeline);
