from sys import hexversion
from os import kill, waitpid, P_NOWAIT,\
    WCOREDUMP, WIFSIGNALED, WTERMSIG, WIFEXITED, WEXITSTATUS
if hexversion < 0x02050000:
    # Python <= 2.3 has not module subprocess
    # Python 2.4 subprocess has a bug: process are really deleted on exit()
    import imp, os.path
    n, f, d = imp.find_module("subprocess_python25", [os.path.dirname(__file__),])
    subprocess = imp.load_module("subprocess", n, f, d)
else:
    import subprocess
from subprocess import Popen, PIPE, STDOUT
from errno import ENOENT, ECHILD, ESRCH
from time import sleep, time
from signal import SIGABRT, SIGFPE, SIGHUP, SIGINT, SIGSEGV, SIGKILL
from os.path import join as join_path, basename, dirname, normpath
from os import access, R_OK, X_OK, popen
from sys import exit
from select import select
from logging import info, warning, error

NOBUFFER_SRC_PATH = normpath(join_path(dirname(__file__), 'libnobuffer.so'))

SIGNAME = {
    SIGABRT: "SIGABRT",
    SIGINT: "SIGINT",
    SIGHUP: "SIGHUP",
    SIGFPE: "SIGFPE",
    SIGKILL: "SIGKILL",
    SIGSEGV: "SIGSEGV",
}

def callProcess(*args):
    return subprocess.call(*args)

class Process(object):
    def __init__(self, program, args=None, need_nobuffer=True):
        self.program = program
        self.process = None
        if args:
            self.program_args = args
        else:
            self.program_args = []
        self.popen_args = {
            'stdin': PIPE,
            'stdout': PIPE,
            'stderr': STDOUT,
        }
        NOBUFFER_LIBRARY = None
        if access(NOBUFFER_SRC_PATH, R_OK | X_OK):
            NOBUFFER_LIBRARY = NOBUFFER_SRC_PATH
        else:
            error("Unable to find nobuffer library (%s)!" % NOBUFFER_LIBRARY)
            if need_nobuffer:
                exit(1)
        if NOBUFFER_LIBRARY is not None:
            self.setenv("LD_PRELOAD", NOBUFFER_LIBRARY)
        self._pid = None

    def setenv(self, key, value):
        """
        Set environment variable. This function has no effect after
        process creation (call start() method).
        """
        if 'env' in self.popen_args:
            self.popen_args['env'][key] = value
        else:
            self.popen_args['env'] = {key: value}


    def _getPid(self):
        return self._pid
    pid = property(_getPid)

    def formatLog(self, message):
        if self._pid is None:
            return "[%s] %s" % (self, message)
        else:
            return "[%s:%s] %s" % (self, self._pid, message)
    def info(self, message):
        info(self.formatLog(message))
    def warning(self, message):
        warning(self.formatLog(message))
    def error(self, message):
        error(self.formatLog(message))

    def __str__(self):
        return basename(self.program)

    def start(self, restart=True, timeout=None):
        """
        Run process and waits until it is ready
        """
        # If it's already running, stop it
        if self.isRunning():
            if not restart:
                return False
            self.stop()

        # Run process
        args = [self.program] + self.program_args
        self.warning("create process: %r" % args)
        try:
            self.process = Popen(args, **self.popen_args)
            self._pid = self.process.pid
        except OSError, err:
            if err[0] == ENOENT:
                raise RuntimeError("No such program: %s" % self.program)
            else:
                raise

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
        return True

    def readline(self, timeout=0, stream="stdout"):
        """
        Read one line from specified stream ('stdout' by default).

        timeout argument:
        - 0 (default): non-blocking read
        - None: blocking read
        - (float value): read with specified timeout in second

        Return a string with new line or None if their is no data.

        Code based on this code:
           http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/440554
        """
        if not self.process:
            return None

        out = getattr(self.process, stream)
        if not out:
            raise RuntimeError("Stream %s of process %s is not a pipe" % (stream, self))
        if timeout is not None:
            ready = select([out.fileno()], [], [], timeout)[0]
            if not ready:
                return None
        line = out.readline()
        if not line:
            return None
        line = line.rstrip()
        self.info("%s: %s" % (stream, line))
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
        try:
            kill(self._pid, signum)
        except OSError, err:
            if err[0] == ESRCH:
                self.exited(None)
                raise RuntimeError(
                    "Unable to send signal %s to %s: process is dead"
                    % (name, self))
            else:
                raise

    def readlines(self, timeout=0, total_timeout=None, stream="stdout"):
        if total_timeout:
            stop = time() + total_timeout
        else:
            stop = None
        while True:
            if stop:
                timeout = stop - time()
            line = self.readline(timeout, stream)
            if stop:
                if line is not None:
                    yield line
                if stop < time():
                    break
            else:
                if line is None:
                    break
                yield line

    def exited(self, status):
        # Log last output
        for line in self.readlines():
            pass

        # Display exit code
        if status is not None:
            log_func = self.warning
            info = []
            if WCOREDUMP(status):
                info.append("core.%s dumped!" % self._pid)
                log_func = self.error
            if WIFSIGNALED(status):
                signal = WTERMSIG(status)
                signal = SIGNAME.get(signal, signal)
                info.append("signal %s" % signal)
            if WIFEXITED(status):
                info.append("exitcode=%s" % WEXITSTATUS(status))
            if info:
                log_func("Exit (%s)" % ", ".join(info))
            else:
                log_func("Exit")
        else:
            self.error("Process exited (ECHILD error)")

        # Delete process
        self.process = None
        self._pid = None

    def isRunning(self):
        if not self.process:
            return False
        try:
            finished, status = waitpid(self._pid, P_NOWAIT)
        except OSError, err:
            if err[0] == ECHILD:
                finished = True
                status = None
            else:
                raise
        if finished == 0:
            return True

        # Log exit code
        self.exited(status)
        return False

    def isReady(self):
        raise NotImplementedError()

    def stop(self):
        """
        Send SIGINT signal and waiting until process stop
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
                signal = False
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

    def __repr__(self):
        return '<Process name=%r>' % self.program

