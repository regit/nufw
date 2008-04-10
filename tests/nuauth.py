import atexit
from inl_tests.process import Process
from signal import SIGHUP
from mysocket import connectTcp
from config import config, NUAUTH_PROG, NUAUTH_START_TIMEOUT, USE_VALGRIND
from time import time

RELOAD_TIMEOUT = config.getfloat("nuauth", "reload_timeout")
INIT_TIMEOUT = 0.100   # 100 ms

class NuauthProcess(Process):
    __instance = None

    @classmethod
    def hasInstance(cls):
        return not(cls.__instance is None)

    @classmethod
    def getInstance(cls):
        if cls.__instance is None:
            cls.__instance = NuauthProcess()
            atexit.register(cls._reallyStop)
        return cls.__instance

    def __init__(self, debug_level=9):
        arg = ["-" + "v" * min(max(debug_level, 1), 9)]
        program = NUAUTH_PROG
        if USE_VALGRIND:
            #arg = ["--tool=callgrind", program] + arg
            #program = "valgrind"
            arg = ["--log-file-exactly=nuauth.valgrind.log", "--verbose", program] + arg
            program = "valgrind"
        Process.__init__(self, program, arg)
        self.hostname = "localhost"
        self.need_reload = False
        self.nufw_port = 4128
        self.client_port = 4129
        self.config_dirty = False
        self.need_restart = False
        if self.isReady():
            raise RuntimeError("nuauth is already running!")

    def isReady(self):
        """
        Check that nuauth is running
        """
        return connectTcp(self.hostname, self.nufw_port, INIT_TIMEOUT) \
           and connectTcp(self.hostname, self.client_port, INIT_TIMEOUT)

    def exited(self, status):
        if USE_VALGRIND:
            print "Callgrind logs written in callgrind.out.%s" % self.pid
        Process.exited(self, status)

    def reload(self, timeout=RELOAD_TIMEOUT):
        # Eat output before sending SIGHUP message
        for line in self.readlines():
            pass

        # Send SIGHUP signal
        self.info("Reload")
        self.kill(SIGHUP)
        self.need_reload = False

        # Wait until nuauth is reloaded
        message = "NuAuth server reloaded"
        self.waitline(message, timeout)
        self.warning('nuauth doesn\'t write message "%s"' % message)

    @classmethod
    def _reallyStop(cls):
        cls.__instance.stop()

class Nuauth:
    def __init__(self, conf=None):
        # Create attributes
        self.is_running = False
        self.conf = conf

        # Setup configuration
        self.installConf()

        # Do you need to restart running nuauth instance?
        need_restart = False
        if NuauthProcess.hasInstance():
            if NuauthProcess.getInstance().need_restart:
                need_restart = True
            elif self.conf:
                need_restart = self.conf.need_restart

        # Use running nuauth instance or create a new one?
        self.nuauth = NuauthProcess.getInstance()
        if need_restart:
            self.nuauth.warning("RESTART NUAUTH: Stop running server")
            self.nuauth.stop()
            self.nuauth.warning("RESTART NUAUTH: Start new server")
            self.nuauth = NuauthProcess.getInstance()
            print "(restart nuauth) ",
        self.nuauth.need_restart = False

        # Start nuauth process
        was_running = self.nuauth.start(restart=False, timeout=NUAUTH_START_TIMEOUT)
        self.is_running = True

        # Send SIGHUP if needed
        if not was_running and (self.conf or self.nuauth.config_dirty):
            self.reload()

        # Eat log output
        for line in self.nuauth.readlines():
            pass

    def reload(self, timeout=RELOAD_TIMEOUT):
        self.nuauth.reload(timeout)

    def installConf(self):
        if self.conf:
            self.conf.install()

    def __del__(self):
        self.stop()

    def stop(self):
        if not self.is_running:
            # avoid double call
            return
        if self.conf:
            self.conf.desinstall()
            self.nuauth.config_dirty = True
            self.nuauth.need_restart = self.conf.need_restart
        self.is_running = False

    def readline(self, timeout=0, stream="stdout"):
        return self.nuauth.readline(timeout, stream)

    def readlines(self, **kw):
        return self.nuauth.readlines(**kw)

