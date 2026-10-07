// ZS-JS-090: cleartext http:// request. The URL is a module-level constant;
// argument_literal_matches resolves it to the literal it is bound to.
const http = require('http');
const PARTNER_API = 'http://partner.example.com/v1/orders';
function fetchOrders(cb) {
  http.get(PARTNER_API, cb);
}
module.exports = { fetchOrders };
