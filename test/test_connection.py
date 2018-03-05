from lib.connection import Connection
from lib.connection import ENFORCE_ATTACH_MESSAGE
from argparse import Namespace
import pytest

CONN_ONE_ENCODE = {'data': 'a'}
CONN_ONE_DECODE = {'data': 'b'}
CONN_TWO_ENCODE = {'data': 'c'}
CONN_TWO_DECODE = {'data': 'd'}
CONN_THR_ENCODE = {'data': 'e'}
CONN_THR_DECODE = {'data': 'f'}

@pytest.fixture()
def mock_conn(request, mocker):
    obj = Namespace(conn1=Connection(), conn2=Connection(), conn3=Connection())
    obj.conn1._encode = lambda **kwargs: CONN_ONE_ENCODE
    obj.conn1._decode = lambda **kwargs: CONN_ONE_DECODE
    obj.conn2._encode = lambda **kwargs: CONN_TWO_ENCODE
    obj.conn2._decode = lambda **kwargs: CONN_TWO_DECODE
    obj.conn3._encode = lambda **kwargs: CONN_THR_ENCODE
    obj.conn3._decode = lambda **kwargs: CONN_THR_DECODE
    conns = [obj.conn1, obj.conn2, obj.conn3]
    methods = ['_encode', '_decode', 'do_encode', 'do_decode', 'attach']
    for conn in conns:
        for method in methods:
            mocker.spy(conn, method)
    return obj


class TestConnection:
    def test_basic(self, mock_conn):
        assert(mock_conn.conn1.do_encode() == CONN_ONE_ENCODE)
        assert(mock_conn.conn1.do_decode() == CONN_ONE_DECODE)
        assert(mock_conn.conn2.do_encode() == CONN_TWO_ENCODE)
        assert(mock_conn.conn2.do_decode() == CONN_TWO_DECODE)
        assert(mock_conn.conn3.do_encode() == CONN_THR_ENCODE)
        assert(mock_conn.conn3.do_decode() == CONN_THR_DECODE)

    def test_invalid_attach(self, mock_conn):
        with pytest.raises(ValueError) as excinfo:
            mock_conn.conn1.attach(None)
        assert(str(excinfo.value) == ENFORCE_ATTACH_MESSAGE)

    def test_encode_attach_two(self, mock_conn):
        mock_conn.conn1.attach(mock_conn.conn2)
        assert(mock_conn.conn1.do_encode() == CONN_TWO_ENCODE)
        assert(mock_conn.conn1.do_decode() == CONN_ONE_DECODE)
        mock_conn.conn1._encode.assert_called_once_with()
        mock_conn.conn2._encode.assert_called_once_with(**CONN_ONE_ENCODE)
        mock_conn.conn1._decode.assert_called_once_with(**CONN_TWO_DECODE)
        mock_conn.conn2._decode.assert_called_once_with()
        assert(mock_conn.conn2.do_encode() == CONN_TWO_ENCODE)
        assert(mock_conn.conn2.do_decode() == CONN_TWO_DECODE)

    def test_encode_attach_three(self, mock_conn):
        mock_conn.conn1.attach(mock_conn.conn2)
        mock_conn.conn2.attach(mock_conn.conn3)
        assert(mock_conn.conn1.do_encode() == CONN_THR_ENCODE)
        assert(mock_conn.conn1.do_decode() == CONN_ONE_DECODE)
        mock_conn.conn1._encode.assert_called_once_with()
        mock_conn.conn2._encode.assert_called_once_with(**CONN_ONE_ENCODE)
        mock_conn.conn3._encode.assert_called_once_with(**CONN_TWO_ENCODE)
        mock_conn.conn1._decode.assert_called_once_with(**CONN_TWO_DECODE)
        mock_conn.conn2._decode.assert_called_once_with(**CONN_THR_DECODE)
        assert(mock_conn.conn2.do_encode() == CONN_THR_ENCODE)
        assert(mock_conn.conn2.do_decode() == CONN_TWO_DECODE)

    def test_interface_functions(self):
        conn = Connection()
        conn._encode()
        conn._decode()
