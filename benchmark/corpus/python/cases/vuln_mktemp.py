# ZS-PY-014: tempfile.mktemp() is vulnerable to a TOCTOU race
import tempfile
path = tempfile.mktemp()
