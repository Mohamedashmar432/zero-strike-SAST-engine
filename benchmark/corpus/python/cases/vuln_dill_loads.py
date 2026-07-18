# ZS-PY-048: dill.loads on bytes that crossed a trust boundary
import dill


def restore(payload):
    return dill.loads(payload)
