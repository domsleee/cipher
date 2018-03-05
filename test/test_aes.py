import lib.aes as lib_aes

TEXT_DEC = b'12345'
TEXT_ENC = b'\x1c)\xc5M\xbd'


class TestAes(object):
    def setup(self):
        self.aes = lib_aes.Aes(b'1'*32)

    def test_encrypt(self):
        assert(TEXT_ENC == self.aes.encrypt(TEXT_DEC))

    def test_decrypt(self):
        assert(TEXT_DEC == self.aes.decrypt(TEXT_ENC))


def test_generate_secret():
    assert(len(lib_aes.generate_secret()) == 32)
