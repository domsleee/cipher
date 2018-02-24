from src.lib.header_layer import HeaderLayer
import pytest

class TestHeaderLayer:
    def setup(self):
        self.aes_filename = b'b'*10
        self.header_layer = HeaderLayer(self.aes_filename)

    def _get_encoded_str(self, sha_data, data):
        return b'{aes_filename:'+self.aes_filename+b'}'+data

    def test_constructor_enforces_bytestring(self):
        with pytest.raises(ValueError):
            HeaderLayer('123')

    def test_encode(self):
        data = b'bbb'
        res = self.header_layer.do_encode(data)
        assert(res == self._get_encoded_str(data, data))

    def test_decode(self):
        data = b'abc'
        encoded = self._get_encoded_str(data, data)
        res = self.header_layer.do_decode(encoded)
        assert(res == data)
