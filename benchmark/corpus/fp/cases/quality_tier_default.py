# Default output excludes the quality tier: a bare except that handles the
# error is ZS-PY-023 (CWE-396, quality), which is counted in
# Stats.TierExcluded but not reported without --include-hardening.
try:
    do_thing()
except:
    log_failure()
