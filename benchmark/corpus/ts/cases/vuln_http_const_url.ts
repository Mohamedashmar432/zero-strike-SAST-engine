// ZS-TS-088: cleartext http:// request. The URL is a module-level constant;
// argument_literal_matches resolves it to the literal it is bound to.
import http from 'http';
const PARTNER_API = 'http://partner.example.com/v1/orders';
export function fetchOrders(cb: (r: any) => void) {
  http.get(PARTNER_API, cb);
}
