// SSRF family negative fixture (ZS-TS-033/034/035/036/080/082/083).
//
// TypeScript mirror of safe_ssrf_js.js. Every call below sends its request to
// a destination that is a build-time constant; what is attacker-controlled is
// the request body, a header, a query parameter, or something inside a
// response callback. None of those decide where the request goes, so none is
// CWE-918.
//
// Before the rules were pinned with tainted_argument_index, "tainted_argument:
// true" was satisfied by any tainted identifier anywhere in the call's
// subtree, so every one of these was reported as SSRF.

import axios from 'axios';
import http from 'http';
import https from 'https';

const AUDIT_URL = 'https://audit.internal.example.com/v1/events';
const HEALTH_URL = 'http://127.0.0.1:9000/healthz';

// axios.post(url, data, config): the body at argument 1 is user data being
// forwarded to a fixed, trusted collector. This is the canonical case.
export function forwardEvent(req: any) {
  return axios.post(AUDIT_URL, req.body.payload);
}

// axios.put(url, data, config): same shape, PUT verb.
export function replaceRecord(req: any) {
  return axios.put(AUDIT_URL, { record: req.body.record });
}

// axios.get(url, config): a user-supplied search term becomes a query
// parameter on a fixed endpoint. It cannot move the request off that host.
export function search(req: any) {
  return axios.get(AUDIT_URL, { params: { q: req.query.q } });
}

// axios.delete(url, config): a request-derived correlation id in a header.
export function removeRecord(req: any) {
  return axios.delete(AUDIT_URL, { headers: { 'X-Trace': req.query.trace } });
}

// fetch(resource, options): the init object at argument 1 carries the method,
// headers and body. A tainted body posted to a constant URL is not SSRF.
export function submit(req: any) {
  return fetch(AUDIT_URL, {
    method: 'POST',
    headers: { 'X-Trace': req.query.trace },
    body: JSON.stringify(req.body),
  });
}

// https.get(url, options, callback): the destination is argument 0. The taint
// here lives in the response callback, two arguments away.
export function proxyHealth(req: any, res: any) {
  https.get(AUDIT_URL, { headers: { 'X-Trace': req.query.trace } }, (upstream: any) => {
    res.json({ trace: req.query.trace, status: upstream.statusCode });
  });
}

// http.get(url, callback): same, for the cleartext sibling rule.
export function localHealth(req: any, res: any) {
  http.get(HEALTH_URL, (upstream: any) => {
    res.json({ trace: req.query.trace, status: upstream.statusCode });
  });
}
