AES_SECRET = b'12'*16

class Aes:
    def __init__(self, secret):
        pass

    def encrypt(self, data):
        return data[::-1]

    def decrypt(self, data):
        return self.encrypt(data)

def generate_secret():
    return AES_SECRET