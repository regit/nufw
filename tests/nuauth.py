from process import Process
from socket import socket, AF_INET, SOCK_STREAM, error as socket_error

class Nuauth(Process):
    def __init__(self, program):
        Process.__init__(self, program)
        self.hostname = "localhost"
        self.nufw_port = 4129
        self.client_port = 4130
        if self.isReady():
            raise RuntimeError("nuauth is already running!")

    def isReady(self):
        """
        Check that nuauth is running
        """
        try:
            sock = socket(AF_INET, SOCK_STREAM)
            sock.connect((self.hostname, self.nufw_port))
            sock.close()

            sock = socket(AF_INET, SOCK_STREAM)
            sock.connect((self.hostname, self.client_port))
            sock.close()
        except socket_error:
            return False
        return True

