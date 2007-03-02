from process import Process

class Nufw(Process):
    def __init__(self, program):
        Process.__init__(self, program, "-vvvvv")
        # FIXME: Load kernel modules?

    def isReady(self):
        for line in self.readlines():
            if "Device or resource busy" in line:
                raise RuntimeError("ERROR: nufw is already running")
            if "Packet server started" in line:
                return True

