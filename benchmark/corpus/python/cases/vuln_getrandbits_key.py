# ZS-PY-094: a 2048-bit API key drawn from the Mersenne Twister. The receiving
# variable is plain "key", which the name-keyed ZS-PY-069 does not match.
import hashlib
import random


def keygen():
    key = hashlib.sha256(str(random.getrandbits(2048)).encode()).hexdigest()
    return key
