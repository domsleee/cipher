from src.lib.connection import Connection
from hashlib import sha256
import logging
import re
logger = logging.getLogger('header_layer')

class HeaderLayer(Connection):
    def __init__(self, aes_filename):
        Connection.__init__(self)
        if not isinstance(aes_filename, (bytes, bytearray)):
            raise ValueError('aes_filename must be a bytestring')
        self.aes_filename = aes_filename

    def _encode(self, child_data=None):
        header = b'{aes_filename:' + self.aes_filename + b'}'
        return header + child_data

    def _decode(self, parent_data=None):
        re_header = re.compile(r'{aes_filename:([^}]*)}(.*)')
        m = re_header.match(parent_data.decode('UTF-8'))
        if not m:
            raise ValueError('Incorrect format type')
        aes_filename = m.group(1).encode('UTF-8')
        data = m.group(2).encode('UTF-8')
        return data
