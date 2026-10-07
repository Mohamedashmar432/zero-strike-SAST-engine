# ZS-PY-095: an API-key generator that returns random-module output directly.
import random
import string


def generate_api_key():
    chars = string.ascii_letters + string.digits
    return "".join(random.choices(chars, k=32))
