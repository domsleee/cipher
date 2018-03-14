"""AES layer of cipher.

Encrypts/decrypts using AES, and works with aes filenames
and the RSA encrypted aes secrets in the filesystem

"""
from lib.connection import Connection
import lib.rsa as lib_rsa
import lib.aes as lib_aes
from lib.config import Config
import random
import string
import os
import logging
import re

logger = logging.getLogger('aes_layer')
AES_FILENAME_LENGTH = 10

class AesLayer(Connection):
    def __init__(self, config, passphrase=None):
        Connection.__init__(self)
        if not isinstance(config, Config):
            raise ValueError('Config must be an instance of Config()')
        public_key = private_key = None
        if config.public_key:
            with open(config.public_key, 'rb') as file:
                public_key = file.read()
        if config.private_key:
            with open(config.private_key, 'rb') as file:
                private_key = file.read()
        self.aes_dir = config.aes_dir
        self.rsa = lib_rsa.Rsa(private_key=private_key, public_key=public_key,
                               passphrase=passphrase)
        self.aes, self.aes_filename = self.__get_aes_info()

    def __get_aes_info(self, aes_filename=None):
        if aes_filename:
            aes = self.__open_aes_secret(aes_filename)
        else:
            aes_filename, aes = self.__get_aes_secret()
        return aes, aes_filename

    def __get_aes_secret(self):
        if self.rsa.can_decrypt():
            arr = os.listdir(self.aes_dir)
            if len(arr):
                return arr[0], self.__open_aes_secret(arr[0])

        secret = lib_aes.generate_secret()
        secret_encrypted = self.rsa.encrypt(secret)
        while True:
            aes_filename = ''.join(random.choice(string.ascii_lowercase + string.digits) for i in range(AES_FILENAME_LENGTH))
            aes_path = os.path.join(self.aes_dir, aes_filename)
            if not os.path.isdir(aes_path):
                with open(aes_path, 'wb') as file:
                    file.write(secret_encrypted)
                return aes_filename, lib_aes.Aes(secret)

    def __open_aes_secret(self, filename):
        with open(os.path.join(self.aes_dir, filename), 'rb') as file:
            secret_encrypted = file.read()
            secret = self.rsa.decrypt(secret_encrypted)
            return lib_aes.Aes(secret)

    def _encode(self, data):
        return {'data': self.aes.encrypt(data), 'aes_filename': self.aes_filename}

    def _decode(self, aes_filename, data):
        self.__get_aes_info(aes_filename)
        print('decrypt', data)
        return {'data': self.aes.decrypt(data)}
