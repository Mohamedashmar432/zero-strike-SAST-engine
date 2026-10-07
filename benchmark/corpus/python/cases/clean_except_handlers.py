# True negatives for ZS-PY-023 / ZS-PY-024.
import os

# EAFP "delete if present": a narrow exception type, swallowed on purpose.
try:
    os.remove("app.db")
except FileNotFoundError:
    pass

# Narrow lookup failure.
config = {}
try:
    debug = config["debug"]
except KeyError:
    pass

# A catch-all with a comment documenting the fallback.
try:
    country = geoip_lookup()
except Exception:
    pass  # fall back to the unknown-country default below

# A typed handler that does something is neither rule's concern.
try:
    value = int("12")
except ValueError:
    value = 0
