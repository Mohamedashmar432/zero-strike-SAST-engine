# ZS-PY-015: urllib.request.urlopen() with an attacker-controlled target (SSRF)
#
# The target must come from a real taint source. The rule deliberately no
# longer fires on urlopen(constant) or on a URL read from deploy-time config:
# an operator-supplied webhook URL sits at the same trust level as the code,
# and reporting it as SSRF is what produced the teams.py false positive.
import urllib.request

from flask import request


def fetch_user_supplied():
    url = request.args.get("u")
    return urllib.request.urlopen(url)
