from process import Process
from mysocket import connectTcp

TIMEOUT = 0.100   # 100 ms

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
        return connectTcp(self.hostname, self.nufw_port, TIMEOUT) \
           and connectTcp(self.hostname, self.client_port, TIMEOUT)

