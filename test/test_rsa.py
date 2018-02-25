import os
import src.lib.rsa as lib_rsa
import pytest


myPath = os.path.dirname(os.path.abspath(__file__))


def _relpath(*args):
    newPath = '.'
    for arg in args:
        newPath = os.path.join(newPath, arg)
    return os.path.join(myPath, newPath)


PUBLIC_KEY_FILE = _relpath('test_rsa', 'rsa.pub')
PRIVATE_KEY_FILE = _relpath('test_rsa', 'rsa.key')
PRIVATE_KEY_PASS = 'password'
PRIVATE_KEY = open(PRIVATE_KEY_FILE, 'rb').read()
PUBLIC_KEY = open(PUBLIC_KEY_FILE, 'rb').read()
TXT_DEC = open(_relpath('test_rsa', 'text'), 'rb').read()
TXT_ENC = open(_relpath('test_rsa', 'text.enc'), 'rb').read()


class TestRsa(object):
    def test_encrypt_decrypt(self):
        rsa = lib_rsa.Rsa(public_key=PUBLIC_KEY, private_key=PRIVATE_KEY,
                          passphrase=PRIVATE_KEY_PASS)
        enc = rsa.encrypt(TXT_DEC)
        dec = rsa.decrypt(enc)
        assert(dec == TXT_DEC)

    def test_decrypt(self):
        rsa = lib_rsa.Rsa(private_key=PRIVATE_KEY, passphrase=PRIVATE_KEY_PASS)
        dec = rsa.decrypt(TXT_ENC)
        assert(dec == TXT_DEC)

    def test_encrypt_no_public_key_raises_value_error(self):
        rsa = lib_rsa.Rsa(private_key=PRIVATE_KEY, passphrase=PRIVATE_KEY_PASS)
        with pytest.raises(ValueError):
            rsa.encrypt(TXT_DEC)

    def test_decrypt_no_private_key_raises_value_error(self):
        rsa = lib_rsa.Rsa(public_key=PUBLIC_KEY)
        with pytest.raises(ValueError):
            rsa.decrypt(TXT_ENC)

    def test_can_encrypt(self):
        rsa = lib_rsa.Rsa(public_key=PUBLIC_KEY)
        assert(rsa.can_encrypt())
        rsa = lib_rsa.Rsa()
        assert(not rsa.can_encrypt())

    def test_can_decrypt(self):
        rsa = lib_rsa.Rsa(private_key=PRIVATE_KEY, passphrase=PRIVATE_KEY_PASS)
        assert(rsa.can_decrypt())
        rsa = lib_rsa.Rsa()
        assert(not rsa.can_decrypt())



def test_generate_keypair_no_pass(fs):
    private, public = lib_rsa.generate_keypair(modulo=1024)
    lib_rsa.Rsa(public_key=public, private_key=private)


def test_generate_keypair_with_pass(fs):
    private, public = lib_rsa.generate_keypair(modulo=1024, passphrase='txt')
    lib_rsa.Rsa(public_key=public, private_key=private, passphrase='txt')


def test_generate_keypair_with_wrong_pass(fs):
    private, public = lib_rsa.generate_keypair(modulo=1024, passphrase='txt')
    with pytest.raises(ValueError):
        lib_rsa.Rsa(public_key=public, private_key=private, passphrase='wrong')
