from src.lib.connection import Connection
import logging
import re
logger = logging.getLogger('header_layer')

class HeaderLayer(Connection):
    def __init__(self):
        Connection.__init__(self)

    def _encode(self, child_data=None):
        # in format {aes_filename:_, data:_}
        header = b'{aes_filename:' + child_data['aes_filename'] + b'}'
        return header + child_data['data']

    def _decode(self, parent_data=None):
        re_header = re.compile(r'{aes_filename:([^}]*)}(.*)')
        m = re_header.match(parent_data.decode('UTF-8'))
        if not m:
            raise ValueError('Incorrect format type')
        aes_filename = m.group(1).encode('UTF-8')
        data = m.group(2).encode('UTF-8')
        return {'aes_filename': aes_filename, 'data': data}
