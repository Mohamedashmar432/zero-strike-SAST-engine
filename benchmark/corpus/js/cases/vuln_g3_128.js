// ZS-JS-128: CWE-943: request value used directly as a MongoDB update filter
function edit(req, res, db) {
  db.reviewsCollection.update({ _id: req.body.id }, { $set: { message: req.body.message } });
}
