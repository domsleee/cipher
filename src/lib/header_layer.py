"""Header layer of cipher.

Encapsulates the data with information about which aes_filename
was used. Has no responsibility for file system or filename
generation

"""
from lib.connection import Connection
from lib.aes_layer import AES_FILENAME_LENGTH
import logging
import re
logger = logging.getLogger('header_layer')
HEADER_LENGTH = len('{aes_filename:')+AES_FILENAME_LENGTH+len('}')

class HeaderLayer(Connection):
    def __init__(self):
        Connection.__init__(self)

    def _encode(self, aes_filename, data):
        header = b'{aes_filename:' + aes_filename + b'}'
        return {'data': header + data}

    def _decode(self, data):
        m = None
        if len(data) < HEADER_LENGTH:
            raise ValueError('Data must be at least the side of the header')

        header = data[:HEADER_LENGTH]
        re_header = re.compile(r'{aes_filename:([^}]*)}')
        m = re_header.match(data.decode('UTF-8'))
        if not m:
            raise ValueError('Incorrect format type')
        aes_filename = m.group(1).encode('UTF-8')
        data = data[HEADER_LENGTH:]
        return {'aes_filename': aes_filename, 'data': data}
