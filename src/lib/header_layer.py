from src.lib.connection import Connection
from src.lib.aes_layer import AES_FILENAME_LENGTH
import logging
import re
logger = logging.getLogger('header_layer')
HEADER_LENGTH = len('{aes_filename:')+AES_FILENAME_LENGTH+len('}')

class HeaderLayer(Connection):
    def __init__(self):
        Connection.__init__(self)

    def _encode(self, child_data=None):
        # in format {aes_filename:_, data:_}
        header = b'{aes_filename:' + child_data['aes_filename'] + b'}'
        return header + child_data['data']

    def _decode(self, parent_data=None):
        m = None
        if len(parent_data) < HEADER_LENGTH:
            raise ValueError('Data must be at least the side of the header')

        header = parent_data[:HEADER_LENGTH]
        re_header = re.compile(r'{aes_filename:([^}]*)}')
        m = re_header.match(parent_data.decode('UTF-8'))
        if not m:
            raise ValueError('Incorrect format type')
        aes_filename = m.group(1).encode('UTF-8')
        data = parent_data[HEADER_LENGTH:]
        return {'aes_filename': aes_filename, 'data': data}
