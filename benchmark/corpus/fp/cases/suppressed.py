# Phase 5: inline suppressions the author wrote and justified.
#
# Both handlers below are genuine findings the author has explicitly accepted
# by rule ID. Two things are being verified: that an annotation on the except
# clause suppresses a finding the engine anchors at the `try:` line, and that a
# foreign tool's code (# noqa: BLE001) does NOT suppress a ZeroStrike finding,
# which is why these name ZS-PY-024 explicitly.
#
# The bodies deliberately avoid calling anything that is itself a sink, so a
# failure here can only mean suppression broke.
import logging

log = logging.getLogger(__name__)

CACHE = {"a": 1}


def lookup(name):
    try:
        return CACHE[name]
    except KeyError:  # zs-ignore: ZS-PY-024 -- a missing entry is not an error
        pass
    return None


def parse_count(raw):
    # zs-ignore: ZS-PY-024 -- a malformed admin value must not reject the form
    try:
        return int(raw)
    except ValueError:
        pass
    return None
