from os import (kill, waitpid, P_NOWAIT,
    WCOREDUMP, WIFSIGNALED, WSTOPSIG, WIFEXITED, WEXITSTATUS)
from subprocess import Popen, PIPE, STDOUT
from time import sleep, time
from signal import SIGABRT, SIGFPE, SIGHUP, SIGINT, SIGSEGV, SIGKILL
from os.path import basename
from select import select
from logging import info, warning, error

SIGNAME = {
    SIGABRT: "SIGABRT",
    SIGINT: "SIGINT",
    SIGHUP: "SIGHUP",
    SIGFPE: "SIGFPE",
    SIGKILL: "SIGKILL",
    SIGSEGV: "SIGSEGV",
}

class Process(object):
    def __init__(self, program, args=None):
        self.program = program
        self.process = None
        if args:
            self.program_args = args
        else:
            self.program_args = []
        self.popen_args = {'stdin': PIPE, 'stdout': PIPE, 'stderr': STDOUT}

    def _log(self, func, message):
        if self.process:
            func("[%s:%s] %s" % (basename(self.program), self.process.pid, message))
        else:
            func("[%s] %s" % (basename(self.program), message))
    def info(self, message):
        self._log(info, message)
    def warning(self, message):
        self._log(warning, message)
    def error(self, message):
        self._log(error, message)

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
        args = [self.program] + self.program_args
        self.warning("create process: %r" % args)
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
        diff = time() - start
        self.warning("process started (%1.1f sec)" % diff)

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

        # Log action
        name = SIGNAME.get(signum, signum)
        if signum in (SIGINT, SIGHUP):
            log_func = self.warning
        else:
            log_func = self.error
        log_func("kill(%s)" % name)

        # Send signal
        kill(self.process.pid, signum)

    def readlines(self, timeout=0, stream="stdout"):
        while True:
            line = self.readline(timeout, stream)
            if not line:
                break
            yield line.rstrip()

    def exited(self, status):
        # Log last output
        for line in self.readlines():
            pass

        # Display exit code
        log_func = self.warning
        info = []
        if WCOREDUMP(status):
            info.append("core.%s dumped!" % self.process.pid)
            log_func = self.error
        if WIFSIGNALED(status):
            signal = WSTOPSIG(status)
            signal = SIGNAME.get(signal, signal)
            info.append("signal %s" % signal)
        if WIFEXITED(status):
            info.append("exitcode=%s" % WEXITSTATUS(status))
        if info:
            log_func("Exit (%s)" % ", ".join(info))
        else:
            log_func("Exit")

        # Delete process
        self.process = None

    def isRunning(self):
        if not self.process:
            return False
        finished, status = waitpid(self.process.pid, P_NOWAIT)
        if finished == 0:
            return True

        # Log exit code
        self.exited(status)
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

        # Log output
        for line in self.readlines():
            pass

        # Send first SIGINT
        self.kill(SIGINT)

        # Wait until process ends
        step = 1
        signal = False
        start_time = time()
        while self.isRunning():
            if 2.0 < (time() - start_time):
                signal = True
                start_time = time()
            if signal:
                step += 1
                if step <= 2:
                    self.kill(SIGINT)
                else:
                    self.kill(SIGKILL)
            try:
                sleep(0.250)
            except KeyboardInterrupt:
                self.info("Interrupted (CTRL+C)")
                signal = True

    def __del__(self):
        self.stop()

