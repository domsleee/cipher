import sys
import os
import configobj

CONFIG_FILE = os.path.expanduser('~/.cipher/cipher.conf')

class Config:
    _fields = ['private_key', 'public_key', 'aes_dir']
    def __init__(self):
        for field in self._fields:
            setattr(self, field, None)

    def get_config(self, config_file=CONFIG_FILE):
        with open(config_file, 'r') as file:
            print(file.read())
        config = configobj.ConfigObj(config_file)
        for field in self._fields:
            if field in config:
                value = os.path.expanduser(config[field])
                setattr(self, field, value)
