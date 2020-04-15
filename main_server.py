from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler
import struct
import logging
from common.abstract_server_credentials import AbstractServerCredentials
from common.abstract_packet_parser import AbstractPacketParser


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    logging.info(f'Threading TCP server started')
    pass


class MainSocks5Server(StreamRequestHandler):
    def __init__(self, credentials: AbstractServerCredentials, packet_parser: AbstractPacketParser, request,
                 client_address, server):
        super().__init__(request, client_address, server)
        self.credentials = credentials
        self.packet_parser = packet_parser
        self.data = ''

    def handle(self):
        logging.info(f'handle {self.client_address} connection request')
        request_raw_data = self.connection.recv(2).strip()
        protocol_version, connection_methods = AbstractPacketParser(request_raw_data)

        logging.critical('protocol version is not match with the request')
        assert protocol_version == self.credentials.protocol_number

        if self.credentials.connection_method not in set(connection_methods):
            self.server.close_request(self.request)
            return

        self.connection.sendall(
            struct.pack("!BB", self.credentials.protocol_number, self.credentials.connection_method))

        # TODO: make it better
        if self.credentials.verify_credentials(request_raw_data):
            response = struct.pack("!BB", 1, 0)
            self.connection.sendall(response)
            logging.debug('client credentials is ok')

        # TODO: make it better
        response = struct.pack("!BB", 1, 0xff)
        self.connection.sendall(response)
        logging.debug('client credentials is not ok')
        self.server.close_request(self.request)



