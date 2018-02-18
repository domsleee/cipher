"""Simple RSA interface.

Allows for generating RSA keypairs and encrypting/decrypting.

Attributes:
    _logger (Logger): Module-level logging.

"""

from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter
import logging
import os
_logger = logging.getLogger('rsa')


class Aes:
    def __init__(self, secret):
        """AES cipher class.

        Args:
            secret (string): Secret to be used with AES.

        Attributes:
            _secret (bytestring): Secret used with AES cipher.

        """
        self._secret = secret

    def _get_aes(self):
        ctr = Counter.new(128, initial_value=int(self._secret[0]) % 128)
        return AES.new(self._secret, AES.MODE_CTR, counter=ctr)

    def encrypt(self, data):
        """Encrypts data using AES `self._aes`.

        Args:
            data (string): Data to be encrypted.

        Returns:
            String: The result of encrypting `data`.

        """
        aes = self._get_aes()
        ciphertext = aes.encrypt(data)
        return ciphertext

    def decrypt(self, data):
        """Decrypts data using AES `self._aes`.

        Args:
            data (string): Data to be encrypted.

        Returns:
            String: The result of encrypting `data`.

        """
        return self.encrypt(data)


def generate_secret():
    """Generates a 256-bit AES secret.

    Returns:
        bytestring: The resultant key.

    """
    return os.urandom(32)
