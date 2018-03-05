from lib.header_layer import HeaderLayer
import pytest

class TestHeaderLayer:
    def setup(self):
        self.aes_filename = b'b'*10
        self.header_layer = HeaderLayer()

    def _get_encoded_str(self, data):
        return b'{aes_filename:'+self.aes_filename+b'}'+data

    def test_encode(self):
        data = b'bbb'
        res = self.header_layer.do_encode(aes_filename=self.aes_filename, data=data)
        assert(res == {'data': self._get_encoded_str(data)})

    def test_decode(self):
        data = b'abc'
        encoded = self._get_encoded_str(data)
        res = self.header_layer.do_decode(data=encoded)
        assert(res == {'aes_filename': self.aes_filename, 'data': data})

    def test_decode_wrong_format_type(self):
        with pytest.raises(ValueError):
            self.header_layer.do_decode(data=b'1'+self._get_encoded_str(b'1'))

    def test_decode_too_small(self):
        data = 'a'
        with pytest.raises(ValueError):
            self.header_layer.do_decode(data=data)
