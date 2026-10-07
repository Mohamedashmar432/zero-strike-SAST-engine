# ZS-PY-024: a catch-all handler silently discards every failure
try:
    do_other_thing()
except Exception:
    pass
