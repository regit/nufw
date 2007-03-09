from os import getcwd, path
from sys import stdout
from signal import SIGHUP
import atexit
from nufw import Nufw
from nuauth import Nuauth
from client import Client
from config import NuauthConf
from logging import basicConfig, DEBUG, ERROR, StreamHandler, getLogger

CONF_DIR = "/etc/nufw"
NUAUTH_CONF = path.join(CONF_DIR, "nuauth.conf")
ROOT_DIR = path.normpath(path.join(getcwd(), ".."))
USE_COVERAGE = False
USE_VALGRIND = USE_COVERAGE

NUFW_PROG = path.join(ROOT_DIR, "src", "nufw", "nufw")
NUAUTH_PROG = path.join(ROOT_DIR, "src", "nuauth", "nuauth")
NUTCPC_PROG = path.join(ROOT_DIR, "src", "clients", "nutcpc", "nutcpc")

# FIXME: Automatically get address
# It's important to connect with right nuauth IP
NUAUTH_HOST = "192.168.0.2"
USERNAME = "haypo"
PASSWORD = "haypo"
CLIENT_IP = NUAUTH_HOST
CLIENT_USER_ID = 1000

if USE_VALGRIND:
    NUAUTH_START_TIMEOUT = 60.0
else:
    NUAUTH_START_TIMEOUT = 5.0
NUFW_START_TIMEOUT = 5.0

LOG_FILENAME = 'tests.log'
#LOG_FORMAT = '%(asctime)s %(levelname)s %(message)s'
LOG_FORMAT = '%(created).3f| %(message)s'

IPTABLE_QUEUE = "NFQUEUE"

_nuauth = None
_nufw = None
_setup_log = False

class CustomLogHandler(StreamHandler):
    def __init__(self):
        StreamHandler.__init__(self)

    def emit(self, record):
        if record.levelno < ERROR:
            return
        print "%s: %s" % (record.levelname, record.msg)

def setupLog():
    """
    Setup log system
    """
    global _setup_log
    if _setup_log:
        return
    _setup_log = True
    basicConfig(
        level=DEBUG,
        format=LOG_FORMAT,
        filename=LOG_FILENAME,
        filemode='w')
    logger = getLogger()
    handler = CustomLogHandler()
    logger.addHandler(handler)
    atexit.register(lambda: stdout.write("Log written to %s\n" % LOG_FILENAME))

def startNuauth(debug_level=9):
    """
    Start nuauth. If nuauth is already running, do nothing.

    Return nuauth process (Nuauth class).
    """
    global _nuauth
    if _nuauth:
        return _nuauth
    _nuauth = Nuauth(NUAUTH_PROG, debug_level=debug_level, use_coverage=USE_COVERAGE)
    atexit.register(_stopNuauth)
    _nuauth.start(timeout=NUAUTH_START_TIMEOUT)
    # Log output
    for line in _nuauth.readlines():
        pass
    return _nuauth

def startNufw():
    """
    Start nufw server. If it's already running, do nothing.

    Return nufw process (Nufw class).
    """
    global _nufw
    if _nufw:
        return _nufw
    _nufw = Nufw(NUFW_PROG)
    atexit.register(_stopNufw)
    _nufw.start(timeout=NUFW_START_TIMEOUT)
    return _nufw

def reloadNuauth():
    """
    Reload nuauth configuration (send SIGHUP signal).
    Just start nuauth if it wasn't running

    Return nuauth process (Nuauth class).
    """
    global _nuauth
    was_running = bool(_nuauth)
    nuauth = startNuauth()
    if was_running:
        nuauth.need_reload = True
        nuauth.info("Program reload on next start()")
    return nuauth

def _stopNuauth():
    global _nuauth
    if not _nuauth:
        return
    _nuauth.stop()
    _nuauth = None

def _stopNufw():
    global _nufw
    if not _nufw:
        return
    _nufw.stop()
    _nufw = None

def createClient(username=USERNAME, password=PASSWORD):
    return Client(NUTCPC_PROG, NUAUTH_HOST, username, password)

def connectClient(client):
    client.info("connectClient()")
    try:
        client.start(timeout=10.0)
    except RuntimeError, err:
        client.warning("connectClient(): error: %s" % err)
        return False
    client.warning("connectClient(): connected")
    return True

def getNuauthConf():
    return NuauthConf(NUAUTH_CONF)

setupLog()

