from process import Process
from mysocket import connectTcp

TIMEOUT = 0.100   # 100 ms

class Nuauth(Process):
    def __init__(self, program, use_coverage=True, debug_level=1):
        arg = ["-" + "v" * min(max(debug_level, 1), 9)]
        self.use_coverage = use_coverage
        if self.use_coverage:
            arg = ["--tool=callgrind", program] + arg
            program = "valgrind"
        Process.__init__(self, program, arg)
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

    def exited(self, status):
        if self.use_coverage:
            print "Callgrind logs written in callgrind.out.%s" % self.process.pid
        Process.exited(self, status)

