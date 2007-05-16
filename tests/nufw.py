from inl_tests.process import Process
from config import NUFW_PROG

DEBUG_LEVEL = 9

class Nufw(Process):
    def __init__(self, moreargs=None):
        self.args = moreargs
        args = ["-"+"v"*DEBUG_LEVEL]
        if moreargs:
            args += list(moreargs)
        Process.__init__(self, NUFW_PROG, args)
        # FIXME: Load kernel modules?

    def isReady(self):
        for line in self.readlines(timeout=0.010):
            if "Device or resource busy" in line:
                raise RuntimeError("ERROR: nufw is already running")
            if "Packet server started" in line:
                return True

