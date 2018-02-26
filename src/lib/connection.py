"""Main entry module.

Connection layer class.

Allows for attachable layers.

"""

ENFORCE_ATTACH_MESSAGE = 'Attached object must be of type Connection'

class Connection:
    def __init__(self):
        self.__child = None

    def do_encode(self, **kwargs):
        new_data = self._encode(**kwargs)
        if self.__child:
            return self.__child.do_encode(**new_data)
        else:
            return new_data

    def _encode(self, **kwargs):
        pass

    def do_decode(self, **kwargs):
        new_data = kwargs
        if self.__child:
            new_data = self.__child.do_decode(**new_data)
        return self._decode(**new_data)

    def _decode(self, **kwargs):
        pass

    def attach(self, conn):
        if not isinstance(conn, Connection):
            raise ValueError(ENFORCE_ATTACH_MESSAGE)
        self.__child = conn
        conn.__parent = self
