import abc


class AbstractProtocol(metaclass=abc.abstractmethod):
    def tunneling(self):
        pass