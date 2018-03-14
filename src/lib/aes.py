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

    def encrypt(self, data):
        """Encrypts data using AES with secret
        """
        aes = self._get_aes()
        return aes.encrypt(data)

    def _get_aes(self):
        initial = self._get_int(self._secret[0])
        ctr = Counter.new(128, initial_value=initial % 128)
        return AES.new(self._secret, AES.MODE_CTR, counter=ctr)

    def _get_int(self, s0):
        """Get ascii value of byte. Python is bad.
        """
        return ord(s0) if isinstance(s0, str) else int(s0)

    def decrypt(self, data):
        """Decrypts data using AES with secret
        """
        return self.encrypt(data)


def generate_secret():
    """Generates a 256-bit AES secret.
    """
    return os.urandom(32)
