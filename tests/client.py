from process import Process
from config import NUTCPC_PROG, NUAUTH_HOST

class Client(Process):
    def __init__(self, username, password):
        self._username = username
        self._password = password
        self._hostname = NUAUTH_HOST
        Process.__init__(self, NUTCPC_PROG)
        self.updateArgs()

    def _setUsername(self, username):
        self._username = username
        self.updateArgs()
    def _getUsername(self):
        return self._username
    username = property(_getUsername, _setUsername)

    def _setPassword(self, password):
        self._password = password
        self.updateArgs()
    def _getPassword(self):
        return self._password
    password = property(_getPassword, _setPassword)
    hostname = property(lambda self: self._hostname)

    def updateArgs(self):
        self.program_args = [
            "-H", self._hostname,
            "-U", self._username,
            "-P", self._password,
            "-d"]

    def isReady(self):
        for line in self.readlines():
            if "Client is asked to send new connections" in line:
                self.warning("Client is ready")
                return True
        return False

