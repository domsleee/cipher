from src.lib.connection import Connection

class MockConnection(Connection):
    def __init__(self, *args, **kwargs):
        pass

    def do_encode(self, child_data=None):
        return b'1'

    def do_decode(self, parent_data=None):
        return b'1'

    def attach(self, conn):
        pass