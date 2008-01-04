# simple test program (from the XML-RPC specification)
from xmlrpclib import ServerProxy, Error
from config import RPC_PORT
from inl_tests.process import Process

class RPC(object):
    _instance = None

    def __new__(cls, host):
        if not cls._instance:
            cls._instance = object.__new__(cls, host)
        return cls._instance

    def __init__(self, host):
        self.host = host
        host = "localhost"
        self.server = ServerProxy("http://%s:%u" % (host, RPC_PORT))

    def _close(self):
        print "stop"
        self.server.stop()
        del self.server

    @classmethod
    def close(cls):
        print "close", cls._instance
        if not cls._instance:
            return
        cls._instance._close()
        cls._instance = None


class RemoteProcess(Process):
    def start(self, restart=True, timeout=None):
        # If it's already running, stop it
        if self.isRunning():
            if not restart:
                return False
            self.stop()

        # Run nuauth
        args = [self.program] + self.program_args
        self.warning("create process: %r" % args)
        try:
            self.process = Popen(args, **self.popen_args)
        except OSError, err:
            if err[0] == ENOENT:
                raise RuntimeError("No such program: %s" % self.program)
            else:
                raise

        # Wait until it's ready
        start = time()
        while not self.isReady():
            err = None
            if not err and not self.isRunning():
                err = "Unable to run %s (program exited)"
            if not err:
                try:
                    sleep(0.250)
                except KeyboardInterrupt:
                    err = "%s interrupted"
                if not err and timeout and timeout < time() - start:
                    err = "Unable to run %s (timeout)"
            if err:
                self.stop()
                raise RuntimeError(err % str(self))
        diff = time() - start
        self.warning("process started (%1.1f sec)" % diff)
        return True


def main():
    server = RPC("localhost")
    RPC.close()

main()

