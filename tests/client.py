from inl_tests.process import Process
from config import NUTCPC_PROG, NUAUTH_HOST, NUTCPC_VERSION
from IPy import IP
from os import getenv
import re

STARTED_20_REGEX = re.compile("nutcpc .* started")

class Client(Process):
    def __init__(self, username, password, ip, more_args=None):
        self._username = username
        self._password = password
        self._hostname = NUAUTH_HOST
        if not more_args:
            more_args = tuple()
        self._more_args = more_args
        self.ip = IP(ip)
        Process.__init__(self, NUTCPC_PROG)
        home = getenv('HOME')
        self.setenv('HOME', home)
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
        args = self._more_args
        self.program_args = [ ]
        if not (args and "-H" in args):
            self.program_args += ["-H", self._hostname]
        if not (args and "-U" in args):
            self.program_args += ["-U", self._username]
        if not (args and "-P" in args):
            self.program_args += ["-P", self._password]
        if not (args and "-d" in args):
            self.program_args += ["-d"]
        self.program_args.extend(self._more_args)

    def isReady(self):
        if NUTCPC_VERSION <= 20200:
            # nutcpc < 2.2+
            for line in self.readlines():
                if STARTED_20_REGEX.match(line):
                    self.warning("Client is ready")
                    return True
        else:
            # nutcpc >= 2.2+
            for line in self.readlines():
                if "Client is asked to send new connections" in line:
                    self.warning("Client is ready")
                    return True
        return False

