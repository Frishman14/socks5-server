import paramiko

from common.protocol_abstract import AbstractProtocol


class sshTunnelProtocol(AbstractProtocol):
    def __init__(self, hostname):
        self.hostname = hostname

    def tunneling(self):
        print('start')
        try:
            port = 22
            client = paramiko.SSHClient()
            client.connect(self.hostname, port=port, username='user', password='123')
            (stdin, stdout, stderr) = client.exec_command('ls')
            cmd_output = stdout.read()
            print(cmd_output)

        finally:
            client.close()


hello = sshTunnelProtocol('192.168.1.136')
hello.tunnel()
