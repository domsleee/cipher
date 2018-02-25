class Rsa:
    def __init__(self, **kwargs):
        pass

    def encrypt(self, data):
        return b'1'+data[::-1]

    def can_encrypt(self):
        return True

    def decrypt(self, data):
        return data[1:][::-1]

    def can_decrypt(self):
        return True

def generate_keypair(**kwargs):
    return b'1', b'1'