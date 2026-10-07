# ZS-PY-056: hashlib.new with a weak algorithm named through a module-level
# constant; argument_literal_matches resolves ALGORITHM to 'sha1'.
import hashlib

ALGORITHM = 'sha1'


def chain(seed):
    return hashlib.new(ALGORITHM, seed).hexdigest()
