// SSRF family negative fixture (ZS-JS-035/036/037/038/082/084/085).
//
// Every call below sends its request to a destination that is a build-time
// constant. What is attacker-controlled is the request *body*, a header, a
// query parameter, or something inside a response callback -- none of which
// decide where the request goes, so none of them is CWE-918.
//
// Before the rules were pinned with tainted_argument_index, "tainted_argument:
// true" was satisfied by any tainted identifier anywhere in the call's
// subtree, so every one of these was reported as SSRF.

const axios = require('axios');
const http = require('http');
const https = require('https');

const AUDIT_URL = 'https://audit.internal.example.com/v1/events';
const HEALTH_URL = 'http://127.0.0.1:9000/healthz';

// axios.post(url, data, config): the body at argument 1 is user data being
// forwarded to a fixed, trusted collector. This is the canonical case.
function forwardEvent(req) {
  return axios.post(AUDIT_URL, req.body.payload);
}

// axios.put(url, data, config): same shape, PUT verb.
function replaceRecord(req) {
  return axios.put(AUDIT_URL, { record: req.body.record });
}

// axios.get(url, config): a user-supplied search term becomes a query
// parameter on a fixed endpoint. It cannot move the request off that host.
function search(req) {
  return axios.get(AUDIT_URL, { params: { q: req.query.q } });
}

// axios.delete(url, config): a request-derived correlation id in a header.
function removeRecord(req) {
  return axios.delete(AUDIT_URL, { headers: { 'X-Trace': req.query.trace } });
}

// fetch(resource, options): the init object at argument 1 carries the method,
// headers and body. A tainted body posted to a constant URL is not SSRF.
function submit(req) {
  return fetch(AUDIT_URL, {
    method: 'POST',
    headers: { 'X-Trace': req.query.trace },
    body: JSON.stringify(req.body),
  });
}

// https.get(url, options, callback): the destination is argument 0. The taint
// here lives in the response callback, two arguments away.
function proxyHealth(req, res) {
  https.get(AUDIT_URL, { headers: { 'X-Trace': req.query.trace } }, (upstream) => {
    res.json({ trace: req.query.trace, status: upstream.statusCode });
  });
}

// http.get(url, callback): same, for the cleartext sibling rule.
function localHealth(req, res) {
  http.get(HEALTH_URL, (upstream) => {
    res.json({ trace: req.query.trace, status: upstream.statusCode });
  });
}

module.exports = {
  forwardEvent,
  replaceRecord,
  search,
  removeRecord,
  submit,
  proxyHealth,
  localHealth,
};
