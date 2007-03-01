from process import Process

class Nuclient(Process):
    def __init__(self, program, hostname, username, password):
        self._username = username
        self._password = password
        self._hostname = hostname
        Process.__init__(self, program)
        self.updateArgs()

    def setUsername(self, username):
        self._username = username
        self.updateArgs()

    def setPassword(self, password):
        self._password = password
        self.updateArgs()

    def updateArgs(self):
        self.program_args = [
            "-H", self._hostname,
            "-U", self._username,
            "-P", self._password,
            "-d"]

    def isReady(self):
        while self.isRunning():
            err = self.readlineStderr().rstrip()
            if "started" in err:
                return True
            if not err:
                return False

