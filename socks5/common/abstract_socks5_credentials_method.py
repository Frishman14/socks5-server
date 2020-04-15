import abc
from typing import Dict
from common.abstract_server_credentials import AbstractServerCredentials


class AbstractSocks5CredentialsMethod(AbstractServerCredentials, metaclass=abc.ABCMeta):
    def __init__(self, protocol_number: int, protocol_name: str, connection_method: Dict[int: str]):
        super().__init__(protocol_number, protocol_name, connection_method)
        self.protocol_name = 'Socks'
        self.protocol_number = 5
        self.connection_method = \
            {
                2: 'User/Password'
            }


