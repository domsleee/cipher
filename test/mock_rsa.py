class Rsa:
    def __init__(self, **kwargs):
        pass

    def encrypt(self, data):
        return data[::-1]

    def decrypt(self, data):
        return self.encrypt(data)

def generate_keypair(**kwargs):
    return b'1', b'1'