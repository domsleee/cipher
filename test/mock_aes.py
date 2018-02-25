AES_SECRET = b'12'*16

class Aes:
    def __init__(self, secret):
        pass

    def encrypt(self, data):
        return b'1'+data[::-1]

    def decrypt(self, data):
        return data[1:][::-1]

def generate_secret():
    return AES_SECRET