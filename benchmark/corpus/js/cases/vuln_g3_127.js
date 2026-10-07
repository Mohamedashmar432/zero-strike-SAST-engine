// ZS-JS-127: CWE-943: $where assembled by string concatenation
function byProduct(db, id) {
  return db.reviewsCollection.find({ $where: 'this.product == ' + id });
}
