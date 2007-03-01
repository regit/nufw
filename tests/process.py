from os import kill, waitpid, P_NOWAIT
from subprocess import Popen, PIPE
from time import sleep, time
from signal import SIGINT
from os.path import basename
from select import select

class Process:
    def __init__(self, program, args=None):
        self.program = program
        self.process = None
        if args:
            self.program_args = list(args)
        else:
            self.program_args = []
        self.popen_args = {'stdin': PIPE, 'stdout': PIPE, 'stderr': PIPE}

    def start(self, restart=True):
        """
        Run process and waits until it is ready
        """
        # If it's already running, stop it
        if self.isRunning():
            if not restart:
                return
            self.stop()

        # Run nuauth
        args = [self.program] + self.program_args
        self.process = Popen(args, **self.popen_args)

        # Wait until it's ready
        while not self.isReady():
            sleep(0.250)
            if not self.isRunning():
                # Process failure
                self.stop()
                raise RuntimeError("Unable to run %s"
                    % basename(self.program))

    def _readline(self, name, blocking):
        if not self.isRunning():
            return ''
        out = getattr(self.process, name)
        if not blocking:
            out.flush()
            ready = select([out.fileno()], tuple(), tuple(), 0)[0]
            if not ready:
                return ''
        return out.readline()

    def readlineStdout(self, blocking=False):
        return self._readline('stdout', blocking)

    def readlineStderr(self, blocking=False):
        return self._readline('stderr', blocking)

    def isRunning(self):
        if not self.process:
            return False
        finished, status = waitpid(self.process.pid, P_NOWAIT)
        if finished == 0:
            return True
        self.process = None
        return False

    def isReady(self):
        raise NotImplementedError()

    def stop(self):
        """
        Send SIGINT signal and waiting until nuauth is stopped.
        """
        if not self.isRunning():
            return

        # Send first SIGINT
        kill(self.process.pid, SIGINT)

        # Wait until process ends
        step = 1
        start_time = time()
        while self.isRunning():
            if step == 1 and 2.0 < (time() - start_time):
                # Send second SIGINT
                kill(self.process.pid, SIGINT)
                step = 2
            sleep(0.250)
        self.process = None

