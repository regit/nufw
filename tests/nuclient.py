from process import Process

class Nuclient(Process):
    def __init__(self, program, hostname, username, password):
        self.username = username
        self.password = password
        self.hostname = hostname
        args = [
            "-H", self.hostname,
            "-U", self.username,
            "-P", self.password,
            "-d"]
        Process.__init__(self, program, args)

    def isReady(self):
        while self.isRunning():
            err = self.readlineStderr().rstrip()
            if "started" in err:
                return True
            if not err:
                return False

