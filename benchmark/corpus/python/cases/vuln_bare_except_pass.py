# ZS-PY-024: an empty bare except is a swallowed error. It is reported once,
# as ZS-PY-024; ZS-PY-023 (bare except, quality tier) leaves an empty bare
# clause to ZS-PY-024 so the same clause is never reported twice.
try:
    verify_signature(payload)
except:
    pass
