"""Connection layer class.

Allows for attachable layers.

"""
ENFORCE_ATTACH_MESSAGE = 'Attached object must be of type Connection'

class Connection:
    def __init__(self):
        """Flexible parser class, following OSI principles.

        A low-level class that allows for other Connections (or
        subclasses of Connections) to be attached as children
        """
        self.__child = None

    def do_encode(self, **kwargs):
        """Encode using the base class and pass the result
        to the child (if such a child exists)
        """
        new_data = self._encode(**kwargs)
        if self.__child:
            return self.__child.do_encode(**new_data)
        else:
            return new_data

    def _encode(self, **kwargs):
        """Function to be implemented by subclass
        """
        pass

    def do_decode(self, **kwargs):
        """If a child exist, decode using that child and then
        decode with that result
        """
        new_data = kwargs
        if self.__child:
            new_data = self.__child.do_decode(**new_data)
        return self._decode(**new_data)

    def _decode(self, **kwargs):
        """Function to be implemented by subclass
        """
        pass

    def attach(self, conn):
        """Attach a connection as a child to the instance
        """
        if not isinstance(conn, Connection):
            raise ValueError(ENFORCE_ATTACH_MESSAGE)
        self.__child = conn
        conn.__parent = self
