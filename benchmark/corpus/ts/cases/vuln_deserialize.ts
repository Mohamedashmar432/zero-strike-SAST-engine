// ZS-TS-018: insecure deserialization — node-serialize reconstructs arbitrary objects
function loadProduct(raw: string) {
  return serialize.unserialize(raw);
}
