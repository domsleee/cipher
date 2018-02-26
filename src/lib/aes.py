"""Simple AES interface.

Allows for generating AES secrets and encrypting/decrypting.

"""

from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter
import logging
import os
_logger = logging.getLogger('rsa')


class Aes:
    def __init__(self, secret):
        """AES cipher class.
        """
        self._secret = secret

    def _get_aes(self):
        ctr = Counter.new(128, initial_value=int(self._secret[0]) % 128)
        return AES.new(self._secret, AES.MODE_CTR, counter=ctr)

    def encrypt(self, data):
        """Encrypts data using AES with secret
        """
        aes = self._get_aes()
        ciphertext = aes.encrypt(data)
        return ciphertext

    def decrypt(self, data):
        """Decrypts data using AES with secret
        """
        return self.encrypt(data)


def generate_secret():
    """Generates a 256-bit AES secret.
    """
    return os.urandom(32)
