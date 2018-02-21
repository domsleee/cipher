from src.lib.connection import Connection
from src.lib.connection import ENFORCE_ATTACH_MESSAGE
from types import SimpleNamespace
import pytest

CONN_ONE_ENCODE = 'a'
CONN_ONE_DECODE = 'b'
CONN_TWO_ENCODE = 'c'
CONN_TWO_DECODE = 'd'
CONN_THR_ENCODE = 'e'
CONN_THR_DECODE = 'f'

@pytest.fixture()
def mock_conn(request, mocker):
    obj = SimpleNamespace(**{'conn1': Connection(), 'conn2':Connection(), 'conn3':Connection()})
    obj.conn1._encode = lambda x: CONN_ONE_ENCODE
    obj.conn1._decode = lambda x: CONN_ONE_DECODE
    obj.conn2._encode = lambda x: CONN_TWO_ENCODE
    obj.conn2._decode = lambda x: CONN_TWO_DECODE
    obj.conn3._encode = lambda x: CONN_THR_ENCODE
    obj.conn3._decode = lambda x: CONN_THR_DECODE
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
        mock_conn.conn1._encode.assert_called_once_with(None)
        mock_conn.conn2._encode.assert_called_once_with(CONN_ONE_ENCODE)
        mock_conn.conn1._decode.assert_called_once_with(CONN_TWO_DECODE)
        mock_conn.conn2._decode.assert_called_once_with(None)
        assert(mock_conn.conn2.do_encode() == CONN_TWO_ENCODE)
        assert(mock_conn.conn2.do_decode() == CONN_TWO_DECODE)


    def test_encode_attach_three(self, mock_conn):
        mock_conn.conn1.attach(mock_conn.conn2)
        mock_conn.conn2.attach(mock_conn.conn3)
        assert(mock_conn.conn1.do_encode() == CONN_THR_ENCODE)
        assert(mock_conn.conn1.do_decode() == CONN_ONE_DECODE)
        mock_conn.conn1._encode.assert_called_once_with(None)
        mock_conn.conn2._encode.assert_called_once_with(CONN_ONE_ENCODE)
        mock_conn.conn3._encode.assert_called_once_with(CONN_TWO_ENCODE)
        mock_conn.conn1._decode.assert_called_once_with(CONN_TWO_DECODE)
        mock_conn.conn2._decode.assert_called_once_with(CONN_THR_DECODE)
        assert(mock_conn.conn2.do_encode() == CONN_THR_ENCODE)
        assert(mock_conn.conn2.do_decode() == CONN_TWO_DECODE)


