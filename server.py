import logging
import select
import socket
import struct
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler
from server_details import ServerDetails

logging.basicConfig(level=logging.DEBUG)

SOCKS_VERSION = 5
FAILED = 0xff


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    logging.info(f'server established')
    pass


class SocksProxy(StreamRequestHandler):
    username = ServerDetails.user
    password = ServerDetails.password

    def handle(self):
        remote = ''
        address = ''
        bind_address = ''

        logging.info(f'Accepting connection from {self.client_address}')

        header = self.connection.recv(2)
        version, nmethods = struct.unpack("!BB", header)

        assert version == SOCKS_VERSION, 'not the right socks version'

        methods = self.get_available_methods(nmethods)

        if 2 not in set(methods):
            self.server.close_request(self.request)
            return

        self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 2))

        if not self.verify_credentials():
            return

        version, cmd, _, address_type = struct.unpack("!BBBB", self.connection.recv(4))

        if address_type == 1:
            address = socket.inet_ntoa(self.connection.recv(4))
        elif address_type == 3:
            domain_length = ord(self.connection.recv(1)[0])
            address = self.connection.recv(domain_length)

        port = struct.unpack('!H', self.connection.recv(2))[0]

        try:
            if cmd == 1:  # CONNECT
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((address, port))
                bind_address = remote.getsockname()
                logging.info(f'Connected to {address} {port}')
            else:
                self.server.close_request(self.request)

            addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
            port = bind_address[1]
            reply = struct.pack("!BBBBIH", SOCKS_VERSION, 0, 0, address_type,
                                addr, port)

        except Exception as err:
            logging.error(err)
            reply = struct.pack("!BBBBIH", SOCKS_VERSION, 5, 0, address_type, 0, 0)  # 5 = error_number

        self.connection.sendall(reply)
        logging.debug(reply)

        if reply[1] == 0 and cmd == 1:
            self.exchange_loop(self.connection, remote)

        self.server.close_request(self.request)

    def get_available_methods(self, n):
        methods = []
        for i in range(n):
            methods.append(ord(self.connection.recv(1)))
        return methods

    def verify_credentials(self):
        version = ord(self.connection.recv(1))
        assert version == 1

        username_len = ord(self.connection.recv(1))
        username = self.connection.recv(username_len).decode('utf-8')

        password_len = ord(self.connection.recv(1))
        password = self.connection.recv(password_len).decode('utf-8')

        if username == self.username and password == self.password:
            response = struct.pack("!BB", version, 0)
            self.connection.sendall(response)
            logging.debug(response)
            return True

        response = struct.pack("!BB", version, FAILED)
        self.connection.sendall(response)
        logging.debug(response)
        self.server.close_request(self.request)
        return False

    @staticmethod
    def exchange_loop(client, remote):

        while True:

            r, w, e = select.select([client, remote], [], [])

            if client in r:
                data = client.recv(1024)
                logging.debug(data)
                if remote.send(data) <= 0:
                    break

            if remote in r:
                data = remote.recv(1024)
                logging.debug(data)
                if client.send(data) <= 0:
                    break


if __name__ == '__main__':
    with ThreadingTCPServer(('127.0.0.1', 5555), SocksProxy) as server:
        server.serve_forever()
