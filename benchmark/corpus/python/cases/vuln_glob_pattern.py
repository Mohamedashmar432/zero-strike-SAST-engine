# ZS-PY-091: request data concatenated into a pathlib glob pattern.
from pathlib import Path

from flask import request


def find_key_files():
    key = request.headers["X-API-KEY"]
    return [f.name for f in Path("/var/keys").glob("apikey." + key + ".*")]
