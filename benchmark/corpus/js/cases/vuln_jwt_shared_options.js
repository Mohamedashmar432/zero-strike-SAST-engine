// ZS-JS-048: the algorithms list with 'none' sits in one options object that two
// verify calls read; it is reported once, at the declaration.
const jwt = require('jsonwebtoken');
const options = {
  algorithms: ['HS256', 'none'],
};
function userFromToken(token, key) {
  return jwt.verify(token, key, options);
}
function adminFromToken(token, key) {
  return jwt.verify(token, key, options);
}
