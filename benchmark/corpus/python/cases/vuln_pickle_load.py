# ZS-PY-049: pickle.load on a file object an attacker could have written
import pickle


def load_session(fh):
    return pickle.load(fh)
