from Crypto.Hash import MD5

def token(email):
    h = MD5.new()
    h.update(email)
    return h.hexdigest()
