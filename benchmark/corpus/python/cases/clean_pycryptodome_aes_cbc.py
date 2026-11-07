from Crypto.Cipher import AES

def enc(key, value):
    aes = AES.new(key, AES.MODE_GCM)
    return aes.encrypt_and_digest(value)
