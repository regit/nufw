from inl_tests.process import Process
from config import NUFW_PROG

class Nufw(Process):
    def __init__(self):
        Process.__init__(self, NUFW_PROG, ["-vvvvv"])
        # FIXME: Load kernel modules?

    def isReady(self):
        for line in self.readlines():
            if "Device or resource busy" in line:
                raise RuntimeError("ERROR: nufw is already running")
            if "Packet server started" in line:
                return True

