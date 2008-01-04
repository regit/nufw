from SimpleXMLRPCServer import SimpleXMLRPCServer
from config import RPC_PORT, RPC_VERSION
from sys import exit
from os import fork, close
from log import setupLog
from logging import warning
from time import sleep

LOG_FILENAME = "rpc_server.log"

class RPC_Server(SimpleXMLRPCServer):
    allow_reuse_address = True

    def __init__(self):
        SimpleXMLRPCServer.__init__(self, ('', RPC_PORT))
        self.is_running = True
        self.warning("Server started")

    def warning(self, message):
        warning("RCP server: %s" % message)

    def _dispatch(self, method, params):
        self.warning("Dispatch %s%r" % (method, params))
        try:
            if method == "hello":
                return self.hello(params[0])
            elif method == "stop":
                return self.stop()
            else:
                return ("unknown command %s" % method)
        except (ValueError, RuntimeError, TypeError), err:
            self.warning("ERROR: %s" % err)
            return "error: %s" % err

    def serve_forever(self):
        try:
            while self.is_running:
                self.handle_request()
        except KeyboardInterrupt:
            print "Interrupted (CTRL+C)."
            self.stop()
        self.socket.close()

    def stop(self):
        self.warning("Stop!")
        self.is_running = False
        return "Stop!"

def daemonize():
    pid = fork()
    if pid:
        exit(0)
    pid = fork()
    if pid:
        print "RPC server started, listening at port %s" % RPC_PORT
        print "Server pid: %s" % pid
        exit(0)
    setupLog(LOG_FILENAME)
    for fd in xrange(3):
        close(fd)

def main():
    if True:
        setupLog(False)
    else:
        daemonize()
    server = RPC_Server()
    server.serve_forever()

main()

