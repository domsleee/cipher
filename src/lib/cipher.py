"""Main entry module.

Handles encryption/decryption with RSA/AES hybrid. Also
manages hidden folders.

Todo:
    * decrypt implementation

"""

import lib.aes as lib_aes
from lib.aes_layer import AesLayer
from lib.header_layer import HeaderLayer
from lib.fs_parser import parse_fs
import logging
import os
import shutil
logger = logging.getLogger('cipher')
HIDDEN_FILE = '.hidden'

class Cipher:
    def __init__(self, aes_dir, rsa_pub=None, rsa_priv=None, passphrase=None):
        self.aes_layer = AesLayer(aes_dir, rsa_pub=rsa_pub, rsa_priv=rsa_priv, passphrase=passphrase)
        self.header_layer = HeaderLayer()
        self.aes_layer.attach(self.header_layer)
        #self.hidden_layer = HiddenLayer()
        #self.hidden_layer.attach(self.aes_layer)

    def encrypt_file(self, path):
        """Encrypts a file/folder
        """

        for obj in parse_fs(path):
            self.encrypt_regular_filenames(obj.root, obj.regular_filenames)
            self.encrypt_hidden_filenames(obj.root, obj.hidden_filenames)

    def encrypt_regular_filenames(self, path, regular_filenames):
        for filename in regular_filenames:
            filepath = os.path.join(path, filename)
            path_enc = filepath+'.enc'
            if os.path.isfile(path_enc):
                logger.info('%s already exists, refusing' % path_enc)
                return
            
            with open(path_enc, 'wb') as fout:
                with open(filepath, 'rb') as fin:
                    out_data = self.aes_layer.do_encode(data=fin.read())
                    fout.write(out_data['data'])
            _copy_modified_time(filepath, path_enc)
            os.remove(filepath)

    def encrypt_hidden_filenames(self, path, hidden_filenames):
        if len(hidden_filenames):
            hidden_dir = os.path.join(path, HIDDEN_FILE)
            os.mkdir(hidden_dir)
            for filename in hidden_filenames:
                filepath = os.path.join(path, filename)
                os.rename(filepath, os.path.join(hidden_dir, filename))
            tmp_file = hidden_dir+'.tmp'
            with open(tmp_file, 'wb') as fout:
                fout.write(b'1')#self.hidden_layer.encode(hidden_dir)
            shutil.rmtree(hidden_dir)
            os.rename(tmp_file, hidden_dir)


    def decrypt_file(self, filename):
        """Decrypts a file/folder.
        """
        pass

def _copy_modified_time(file, file_enc):
    modified_time = os.path.getmtime(file)
    os.utime(file_enc, times=(0, modified_time))
