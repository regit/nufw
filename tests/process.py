from os import kill, waitpid, P_NOWAIT
from subprocess import Popen, PIPE, STDOUT
from time import sleep, time
from signal import SIGINT
from os.path import basename
from select import select
from logging import info, warning

class Process(object):
    def __init__(self, program, *args):
        self.program = program
        self.process = None
        self.program_args = list(args)
        self.popen_args = {'stdin': PIPE, 'stdout': PIPE, 'stderr': STDOUT}

    def _log(self, func, message):
        func("[%s] %s" % (basename(self.program), message))
    def info(self, message):
        self._log(info, message)
    def warning(self, message):
        self._log(warning, message)

    def __str__(self):
        return basename(self.program)

    def start(self, restart=True, timeout=None):
        """
        Run process and waits until it is ready
        """
        # If it's already running, stop it
        if self.isRunning():
            if not restart:
                return
            self.stop()

        # Run nuauth
        self.warning("start()")
        args = [self.program] + self.program_args
        self.process = Popen(args, **self.popen_args)

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

    def readline(self, timeout=0, stream="stdout"):
        """
        Read one line from specified stream ('stdout' by default).

        timeout argument:
        - 0 (default): non-blocking read
        - None: blocking read
        - (float value): read with specified timeout in second

        Return a string with new line or empty string if their is no data.

        Code based on this code:
           http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/440554
        """
        if not self.process:
            return ''

        out = getattr(self.process, stream)
        if timeout is not None:
            ready = select([out.fileno()], tuple(), tuple(), timeout)[0]
            if not ready:
                return ''
        line = out.readline()
        if line:
            line = line.rstrip()
            if line:
                self.info("stdout: %s" % line)
        return line

    def kill(self, signum, raise_error=True):
        if not self.process:
            if raise_error:
                raise RuntimeError("Unable to kill %s: it's not running" % self)
        else:
            kill(self.process.pid, signum)

    def readlines(self, timeout=0, stream="stdout"):
        while True:
            line = self.readline(timeout, stream)
            if not line:
                break
            yield line.rstrip()

    def _stop(self, status):
        # Log last output
        for line in self.readlines():
            pass
        self.warning("Exit (status %s)" % status)
        self.process = None

    def isRunning(self):
        if not self.process:
            return False
        finished, status = waitpid(self.process.pid, P_NOWAIT)
        if finished == 0:
            return True
        self._stop(status)
        return False

    def isReady(self):
        raise NotImplementedError()

    def stop(self):
        """
        Send SIGINT signal and waiting until nuauth is stopped.
        """
        if not self.isRunning():
            return
        self.warning("stop()")

        # Send first SIGINT
        self.kill(SIGINT)

        # Wait until process ends
        step = 1
        start_time = time()
        while self.isRunning():
            if step == 1 and 2.0 < (time() - start_time):
                # Send second SIGINT
                self.kill(SIGINT)
                step = 2
            try:
                sleep(0.250)
            except KeyboardInterrupt:
                step += 1

    def __del__(self):
        self.stop()

