// ZS-JS-014: insecure deserialization — node-serialize reconstructs arbitrary objects
const serialize = require('node-serialize');
function loadProduct(raw) {
  return serialize.unserialize(raw);
}
