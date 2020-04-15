import abc
from typing import Dict


class AbstractServerCredentials(metaclass=abc.ABCMeta):
    def __init__(self, protocol_number: int, protocol_name: str, connection_method: Dict[int: str]):
        self.protocol_number = protocol_number
        self.protocol_name = protocol_name
        self.connection_method = connection_method

    @abc.abstractmethod
    def verify_credentials(self, request_raw_data: bytes):
        pass
