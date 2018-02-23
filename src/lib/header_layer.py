from src.lib.connection import Connection
from hashlib import sha256
import logging
import re
logger = logging.getLogger('cipher')

class HeaderLayer(Connection):
    def __init__(self, aes_filename):
        Connection.__init__(self)
        if not isinstance(aes_filename, (bytes, bytearray)):
            raise ValueError('aes_filename must be a bytestring')
        self.aes_filename = aes_filename

    def _encode(self, child_data=None):
        sha = sha256(child_data).hexdigest().encode('UTF-8')
        header = b'{sha256:' + sha + b',aes_filename:' + self.aes_filename + b'}'
        return header + child_data

    def _decode(self, parent_data=None):
        re_header = re.compile(r'{sha256:([^,]*),aes_filename:([^}]*)}(.*)')
        m = re_header.match(parent_data.decode('UTF-8'))
        if not m:
            raise ValueError('Incorrect format type')
        sha = m.group(1)
        aes_filename = m.group(2).encode('UTF-8')
        data = m.group(3).encode('UTF-8')
        actual_sha = sha256(data).hexdigest()
        if sha != actual_sha:
            raise ValueError('Hash does not match %s vs %s' % (sha, actual_sha))
        return {'data': data, 'aes_filename': aes_filename}