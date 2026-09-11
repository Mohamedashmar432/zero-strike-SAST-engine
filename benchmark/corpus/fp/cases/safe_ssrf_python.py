# SSRF family negative fixture (ZS-PY-015/025/026/073/074).
#
# Every call below sends its request to a destination that is a module-level
# constant. What is attacker-controlled is the request body, a query
# parameter, or a header -- none of which decide where the request goes, so
# none of them is CWE-918.
#
# Before the rules were pinned with tainted_argument_index, "tainted_argument:
# true" was satisfied by any tainted identifier anywhere in the call's
# subtree, so every one of these was reported as SSRF.
import urllib.request

import requests
from flask import request

AUDIT_URL = "https://audit.internal.example.com/v1/events"


def forward_event():
    # requests.post(url, data=...): the body is user data being forwarded to a
    # fixed, trusted collector. This is the canonical case.
    payload = request.form["payload"]
    return requests.post(AUDIT_URL, data={"payload": payload}, timeout=5)


def replace_record():
    # requests.put(url, data=...): same shape, PUT verb.
    record = request.form["record"]
    return requests.put(AUDIT_URL, data=record, timeout=5)


def search():
    # requests.get(url, params=...): a user-supplied search term becomes a
    # query parameter on a fixed endpoint; it cannot move the request off
    # that host.
    term = request.args["q"]
    return requests.get(AUDIT_URL, params={"q": term}, timeout=5)


def remove_record():
    # requests.delete(url, headers=...): a request-derived correlation id.
    trace = request.headers["X-Trace"]
    return requests.delete(AUDIT_URL, headers={"X-Trace": trace}, timeout=5)


def push_blob():
    # urlopen(url, data): argument 1 is the POST body, not the destination.
    blob = request.form["blob"].encode("utf-8")
    return urllib.request.urlopen(AUDIT_URL, blob, timeout=5)
