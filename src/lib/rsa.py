"""Simple RSA interface.

Allows for generating RSA keypairs and encrypting/decrypting.

Attributes:
    _logger (Logger): Module-level logging

"""

from Cryptodome.IO import PKCS8
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
import logging
_logger = logging.getLogger('rsa')


class Rsa:
    def __init__(self, public_key=None, private_key=None, passphrase=None):
        """RSA cipher class.

        Handles encryption/decryption with a RSA keypair with an optional
        passphrase protecting the private key.

        Args:
            public_key (string): Public key to be used with the cipher.
            private_key (string): Private key to be used with the cipher.
            phassphrase (string): Passphrase paired with the private key.

        Attributes:
            _public_key (PKCS1_OAEP): Object that can be used to encrypt.
            _private_key (PKCS1_OAEP): Object that can be used to decrypt.

        """
        self._public_key = self._private_key = None
        if public_key:
            self._public_key = PKCS1_OAEP.new(RSA.importKey(public_key))
        if private_key:
            s1, raw, s2 = PKCS8.unwrap(private_key, passphrase=passphrase)
            self._private_key = PKCS1_OAEP.new(RSA.importKey(raw))

    def encrypt(self, data):
        """Encrypts data using rsa public key.

        Args:
            data (string): Data to be encrypted.

        Raises:
            ValueError: If `self._public_key` is None.

        Returns:
            String: The result of encrypting `data`.

        """
        if not self._public_key:
            raise ValueError('Public key required to encrypt')
        return self._public_key.encrypt(data)

    def can_encrypt(self):
        return self._public_key != None

    def decrypt(self, data):
        """Decrypts data using rsa private key.

        Args:
            data (string): Data to be decrypted.

        Raises:
            ValueError: If `self._private_key` is None.

        Returns:
            String: The result of decrypting `data`.

        """
        if not self._private_key:
            raise ValueError('Private key required to decrypt')
        return self._private_key.decrypt(data)

    def can_decrypt(self):
        return self._private_key != None


def generate_keypair(passphrase=None, modulo=8912):
    """Generates an RSA keypair.

    The private key can optinally be protected by a passphrase.

    Args:
        passphrase (string): Password paired with private key.
        modulo (int): Size of RSA modulo.

    Returns:
        (private, public): The RSA object generated from the arguments.

    """
    key = RSA.generate(modulo)
    private = key.exportKey(format='DER')
    private = PKCS8.wrap(private, RSA.oid, passphrase=passphrase)
    public = key.publickey().exportKey(format='DER')
    return (private, public)
