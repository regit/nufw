from inl_tests.process import Process
from config import config, NUFW_PROG
from os.path import abspath

USE_VALGRIND = False
DEBUG_LEVEL = 9

class Nufw(Process):
    def __init__(self, moreargs=None):
        self.args = moreargs
        self.is_connected_to_nuauth = False
        args = ["-"+"v"*DEBUG_LEVEL]
        if not moreargs or not "-d" in list(moreargs):
            args = args + ["-d", config.get("nuauth", "host")]
        if not moreargs or not "-k" in list(moreargs):
            args = args + ["-k", abspath(config.get("nufw", "tlskey"))]
        if not moreargs or not "-c" in list(moreargs):
            args = args + ["-c", abspath(config.get("nufw", "tlscert"))]
        if not moreargs or not "-a" in list(moreargs):
            args = args + ["-a", abspath(config.get("nufw", "cacert"))]
        if moreargs:
            args += list(moreargs)
        program = NUFW_PROG
        if USE_VALGRIND:
            args = ["--log-file-exactly=nufw.valgrind.log", "--verbose", program] + args
            program = "valgrind"
        Process.__init__(self, program, args)
        # FIXME: Load kernel modules?

    def isReady(self):
        for line in self.readlines(timeout=0.010):
            if "tls connection to nuauth established" in line.lower():
                self.is_connected_to_nuauth = True
            if "Device or resource busy" in line:
                raise RuntimeError("ERROR: nufw is already running")
            if "Packet server started" in line:
                return True

