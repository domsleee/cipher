"""Main entry module.

Handles encryption/decryption with RSA/AES hybrid. Also
manages hidden folders.

Todo:
    * decrypt implementation

"""

import src.lib.aes as lib_aes
from src.lib.aes_layer import AesLayer
from src.lib.header_layer import HeaderLayer
import logging
import os
import re
import ntpath
from collections import deque
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
        def handle_reg_file(filepath):
            path_enc = filepath+'.enc'
            if os.path.isfile(path_enc):
                logger.info('%s already exists, refusing' % path_enc)
                return
            
            with open(path_enc, 'wb') as fout:
                with open(filepath, 'rb') as fin:
                    print("AES_LAYER")
                    out_data = self.aes_layer.do_encode(data=fin.read())
                    fout.write(out_data['data'])
            _copy_modified_time(filepath, path_enc)
            os.remove(filepath)

        def handle_hidden_filenames(path, hidden_filenames):
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

        walk_override = None
        if os.path.isfile(path):
            walk_override = [(os.path.dirname(path), [], [ntpath.basename(path)])]

        re_hidden_file = re.compile(r'-h($|\.)')
        re_encrypted_file = re.compile(r'(\.enc$)|(^'+HIDDEN_FILE+r'\d*$)')
        use_walk = walk_override if walk_override else os.walk(path)
        for root, dirs, files in use_walk:
            hidden_filenames = []
            for file in dirs + files:
                filepath = os.path.join(root, file)
                if re_encrypted_file.search(file):
                    pass
                elif re_hidden_file.search(file):
                    hidden_filenames.append(file)
                    if os.path.isdir(filepath):
                        dirs.remove(file)
                elif os.path.isfile(filepath):
                    handle_reg_file(filepath)
            handle_hidden_filenames(root, hidden_filenames)


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
