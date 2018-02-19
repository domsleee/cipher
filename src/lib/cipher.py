"""Main entry module.

Handles encryption/decryption with RSA/AES hybrid. Also
manages hidden folders.

Attributes:
    _logger (Logger): Module-level logging.

Todo:
    * encrypt/decrypt implementations.

"""

import src.lib.aes as lib_aes
import src.lib.rsa as lib_rsa
import logging
import os
import random
import string
import re
logger = logging.getLogger('cipher')

class Cipher:
    def __init__(self, aes_dir, **kwargs):
        """High-level cipher class.

        Args:
            aes_dir (string): Directory of aes secrets.
            **kwargs: Optional arguments, default to None:
                rsa_pub (string): Public key path.
                rsa_priv (string): Private key path.
                rsa_pass (string): Private key password.
                aes_filename (string): Filename of AES secret

        Attributes:
            header (string): Prepend to every encrypted file
            aes (Aes): AES cipher object

        """
        __fields = ['rsa_pub', 'rsa_priv', 'rsa_pass', 'aes_filename']
        d = {key: None for key in __fields}
        for key in kwargs:
            d[key] = kwargs[key]
        self.aes, aes_filename = self.__get_aes_info(aes_dir, d)
        return
        self.header = self.__get_header(aes_filename)


    def __get_aes_info(self, aes_dir, d):
        aes, aes_filename = None, None
        if d['aes_filename']:
            aes_filename = d['aes_filename']
            private_key = open(d['rsa_priv'], 'rb').read()
            rsa = lib_rsa.Rsa(private_key=private_key, passphrase=d['rsa_pass'])
            aes = self.__open_aes_secret(aes_dir, aes_filename, rsa)
        else:
            public_key = open(d['rsa_pub'], 'rb').read()
            rsa = lib_rsa.Rsa(public_key=public_key)
            aes_filename, aes = self.__get_aes_secret(aes_dir, rsa)
        return aes, aes_filename


    def __get_aes_secret(self, aes_dir, rsa):
        secret = lib_aes.generate_secret()
        secret_encrypted = rsa.encrypt(secret)
        while True:
            aes_filename = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
            aes_path = os.path.join(aes_dir, aes_filename)
            if not os.path.isdir(aes_path):
                with open(aes_path, 'wb') as file:
                    file.write(secret_encrypted)
                return aes_filename, lib_aes.Aes(secret)


    def __open_aes_secret(self, aes_dir, filename, rsa):
        with open(os.path.join(aes_dir, filename), 'rb') as file:
            secret_encrypted = file.read()
            secret = rsa.decrypt(secret_encrypted)
            return lib_aes.Aes(secret)


    def encrypt_file(self, path):
        """Encrypts a file.

        Requires:
            `self.rsa_pub`.

        Args:
            filename (string): Name of file to encrypt.
            aes (Aes): AES object used to encrypt files.
            header (bytestring): Header bytestring to prepend before each file

        """
        re_hidden_file = re.compile(r'-h($|\.)')

        if re_hidden_file.match(path):
            hidden_files.append(path)
        elif os.path.isdir(path):
            for child in os.listdir(path):
                self.encrypt_file(os.path.join(path, child))
        elif not path.endswith('.enc'):
            path_enc = path+'.enc'
            if os.path.isfile(path_enc):
                logger.info('%s already exists, refusing' % path_enc)
                print('um')
                return
            
            with open(path_enc, 'wb') as fout:
                with open(path, 'rb') as fin:
                    #fout.write(header.to_string())
                    fout.write(self.aes.encrypt(fin.read()))
            _copy_modified_time(path, path_enc)
            os.remove(path)

    def decrypt_file(self, filename):
        """Decrypts a file.

        Requires:
            `self.rsa_priv`.

        Args:
            filename (string): Name of file to encrypt.

        """
        pass

def _copy_modified_time(file, file_enc):
    modified_time = os.path.getmtime(file)
    os.utime(file_enc, times=(0, modified_time))

class _Header:
    def __init__(self, data=None):
        self.data = data
        self.length = None


    def encode(self, data):
        pass

    def decode(self, next_byte):
        pass

    def to_string(self):
        encoded = self.encode(data)
        return self.length + self.data
