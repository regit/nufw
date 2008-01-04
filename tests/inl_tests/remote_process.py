from xmlrpclib import ServerProxy, Error
from subprocess import call
from inl_tests.config import RPC_PORT, SSH_COMMAND, RPC_VERSION
from inl_tests.mysocket import connectTcp
from logging import warning
from log import setupLog # FIXME: Remove this line
from process import Process

def sshRemoteCommand(host, command):
    warning("SSH remote command on host %s: %s" % (host, command))
    return call([SSH_COMMAND, host, command])

class RemoteServer:
    def __init__(self, host):
        self.host = host
        self.port = RPC_PORT
        if not connectTcp(self.host, self.port, 1.0):
            self.warning("Start")
            ok = sshRemoteCommand(self.host, "python /home/haypo/inl/tools/inl_tests/inl_tests/rpc_server.py")
            print "SSH DONE"
            if not ok:
                raise RuntimeError("Unable to start remote RPC server on host %s" % self.host)
        self.warning("Connect to RPC server")
        self.rpc = ServerProxy("http://%s:%u" % (self.host, self.port))
        server_version = self.command("hello", RPC_VERSION)
        if server_version != RPC_VERSION:
            raise RuntimeError('Server version "%s" is different than client version "%s"' \
                % (server_version, RPC_VERSION))

    def warning(self, message):
        warning("Remote server %s:%u: %s" % (self.host, self.port, message))

    def isRunning(self):
        self.warning("Is running: %s" % ok)
        return ok

    def command(self, method, args=None):
        if not args:
            args = tuple()
        self.warning("Command %s%r" % (method, args))
        func = getattr(self.rpc, method)
        return func(*args)

    def test(self):
        print "test"
        print "result:", self.command("test")

    def stop(self):
        self.command("stop")

class RemoteProcess:
    def __init__(self, server, program, args=None, need_nobuffer=True):
        self.program = program
        self.process_args = args
        self.need_nobuffer = need_nobuffer
        self.server = server
        self.server.command("createProcess", program, args, need_nobuffer)

def main():
    setupLog(False)
    server = RemoteServer("localhost")
    server.test()
    server.stop()
    ls = RemoteProcess(server, "ls", ["-la"], False(server, "ls", ["-la"], False))

main()

