from src.lib.connection import Connection
import src.lib.rsa as lib_rsa
import src.lib.aes as lib_aes
import random
import string
import os
import logging
import re
logger = logging.getLogger('aes_layer')

class AesLayer(Connection):
    def __init__(self, aes_dir, rsa_pub=None, rsa_priv=None, passphrase=None):
        Connection.__init__(self)
        public_key = private_key = None
        if rsa_pub:
            with open(rsa_pub, 'rb') as file:
                public_key = file.read()
        if rsa_priv:
            with open(rsa_priv, 'rb') as file:
                private_key = file.read()
        self.aes_dir = aes_dir
        self.rsa = lib_rsa.Rsa(private_key=private_key, public_key=public_key, passphrase=passphrase)
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
            aes_filename = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
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

    def _encode(self, child_data=None):
        data = child_data
        return {'data': self.aes.encrypt(data), 'aes_filename': self.aes_filename}

    def _decode(self, parent_data=None):
        aes_filename = parent_data['aes_filename']
        self.__get_aes_info(aes_filename)
        print('decrypt', parent_data['data'])
        return self.aes.decrypt(parent_data['data'])
