# ZS-PY-024: caught exception is silently discarded
try:
    do_other_thing()
except ValueError:
    pass
