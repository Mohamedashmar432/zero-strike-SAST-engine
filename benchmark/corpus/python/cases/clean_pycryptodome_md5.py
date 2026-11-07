from Crypto.Hash import SHA256

def token(email):
    h = SHA256.new()
    h.update(email)
    return h.hexdigest()
