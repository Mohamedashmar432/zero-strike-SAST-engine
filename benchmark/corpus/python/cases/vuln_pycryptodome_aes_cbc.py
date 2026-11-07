from Crypto.Cipher import AES

def enc(key, iv, value):
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(value)
