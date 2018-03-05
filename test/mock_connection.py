from lib.connection import Connection

class MockConnection(Connection):
    def __init__(self, *args, **kwargs):
        pass

    def do_encode(self, **kwargs):
        return {'data': b'1'}

    def do_decode(self, **kwargs):
        return {'data': b'1'}

    def attach(self, conn):
        pass