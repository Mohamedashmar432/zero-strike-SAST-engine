# ZS-PY-047: marshal.loads on bytes that crossed a trust boundary
import marshal


def read_blob(blob):
    return marshal.loads(blob)
