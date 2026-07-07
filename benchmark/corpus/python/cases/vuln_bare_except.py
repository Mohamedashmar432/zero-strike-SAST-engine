# ZS-PY-023: bare except swallows every exception, including KeyboardInterrupt
try:
    do_thing()
except:
    log.error("failed")
