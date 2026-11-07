// True negative for ZS-TS-128: req.params is always a string in Express, so it
// cannot smuggle a $-operator object into the filter.
export async function renameUser(req: any, db: any) {
  const id = req.params.id;
  return db.collection("users").updateOne({ _id: id }, { $set: { name: "x" } });
}
