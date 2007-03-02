from process import Process

class Nuclient(Process):
    def __init__(self, program, hostname, username, password):
        self._username = username
        self._password = password
        self._hostname = hostname
        Process.__init__(self, program)
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

    def updateArgs(self):
        self.program_args = [
            "-H", self._hostname,
            "-U", self._username,
            "-P", self._password,
            "-d"]

    def isReady(self):
        while True:
            out = self.readline()
            if not out:
                break
            out = out.rstrip()
            if "Client is asked to send new connections" in out:
                return True
        return False

