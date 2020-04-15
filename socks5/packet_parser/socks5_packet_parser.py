from common.abstract_packet_parser import AbstractPacketParser
from typing import Tuple, List, Any
import struct


class Socks5PacketParser(AbstractPacketParser):
    def __init__(self, raw_packet: bytes):
        super().__init__(raw_packet)

    def parser(self):
        protocol_version, connection_method = struct.unpack('!BB', self.raw_packet[:2])
        connection_method = self._get_available_methods(connection_method)
        version = ord(self.raw_packet[3:4])
        client_username_len = ord(self.raw_packet[4:5])
        client_username = self.raw_packet[5:5 + client_username_len].decode('utf-8')
        client_password_len = ord(self.raw_packet[5 + client_username_len:5 + client_username_len + 1])
        client_password = self.raw_packet[
                          5 + client_username_len + 1:5 + client_username_len + 1 + client_password_len].decode('utf-8')
        version, cmd, _, address_type = struct.unpack('!BBBB', self.raw_packet[
                                                               5 + client_username_len + 1 + client_password_len: 5 + client_username_len + 1 + client_password_len + 4])

    def header(self) -> Tuple[int, List[int]]:
        protocol_version, connection_method = struct.unpack('!BB', self.raw_packet[:2])
        return protocol_version, self._get_available_methods(connection_method)

    def _get_available_methods(self, n):
        methods = []
        for i in range(n):
            methods.append(ord(self.raw_packet[2:3]))
        return methods

    def credentials(self) -> List[Any]:
        version = ord(self.raw_packet[3:4])
        client_username_len = ord(self.raw_packet[4:5])
        client_username = self.raw_packet[5:5 + client_username_len].decode('utf-8')
        client_password_len = ord(self.raw_packet[5 + client_username_len:5 + client_username_len + 1])
        client_password = self.raw_packet[
                          5 + client_username_len + 1:5 + client_username_len + 1 + client_password_len].decode('utf-8')

        return [version, client_password_len, client_username, client_password_len, client_password]

    def client_details(self) -> List[Any]:
        version, cmd, _, address_type = struct.unpack('!BBBB', self.raw_packet[
                                                               5 + client_username_len + 1 + client_password_len: 5 + client_username_len + 1 + client_password_len + 4])
