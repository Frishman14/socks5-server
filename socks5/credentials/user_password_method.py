import struct
from typing import Dict
from socks5.common.abstract_socks5_credentials_method import AbstractSocks5CredentialsMethod
from common.abstract_packet_parser import AbstractPacketParser


class UserPasswordSocks5Method(AbstractSocks5CredentialsMethod):
    def __init__(self, protocol_number: int, protocol_name: str, connection_method: Dict[int: str], password: str,
                 username: str, packet_parser: AbstractPacketParser):
        super().__init__(protocol_number, protocol_name, connection_method)
        self.username = username
        self.password = password
        self.packet_parser = packet_parser

    def verify_credentials(self, request_raw_data: bytes):
        version, client_usr_len, client_username, client_pass_len, client_pass = self.packet_parser.credentials()

        assert version == 1

        if client_username == self.username and client_pass == self.password:
            return True

        return False
