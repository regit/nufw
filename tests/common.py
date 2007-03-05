from os import getcwd, path
from sys import stdout
from signal import SIGHUP
import atexit
from nufw import Nufw
from nuauth import Nuauth
from client import Client
from config import NuauthConf
from logging import basicConfig, DEBUG

CONF_DIR = "/etc/nufw"
NUAUTH_CONF = path.join(CONF_DIR, "nuauth.conf")
ROOT_DIR = path.normpath(path.join(getcwd(), ".."))

NUFW_PROG = path.join(ROOT_DIR, "src", "nufw", "nufw")
NUAUTH_PROG = path.join(ROOT_DIR, "src", "nuauth", "nuauth")
NUTCPC_PROG = path.join(ROOT_DIR, "src", "clients", "nutcpc", "nutcpc")

# FIXME: Automatically get address
# It's important to connect with right nuauth IP
NUAUTH_HOST = "192.168.0.2"
USERNAME = "haypo"
PASSWORD = "haypo"

LOG_FILENAME = 'tests.log'
#LOG_FORMAT = '%(asctime)s %(levelname)s %(message)s'
LOG_FORMAT = '%(created).3f| %(message)s'

_nuauth = None
_nufw = None
_setup_log = False

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
    atexit.register(lambda: stdout.write("Log written to %s\n" % LOG_FILENAME))

def startNuauth(debug_level=9):
    """
    Start nuauth. If nuauth is already running, do nothing.

    Return nuauth process (Nuauth class).
    """
    global _nuauth
    if _nuauth:
        return _nuauth
    setupLog()
    _nuauth = Nuauth(NUAUTH_PROG, debug_level)
    atexit.register(_stopNuauth)
    _nuauth.start()
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
    setupLog()
    _nufw = Nufw(NUFW_PROG)
    atexit.register(_stopNufw)
    _nufw.start()
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
        nuauth.kill(SIGHUP)
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
    setupLog()
    return Client(NUTCPC_PROG, NUAUTH_HOST, username, password)

def connectClient(client):
    client.warning("connectClient()")
    try:
        client.start(timeout=10.0)
    except RuntimeError, err:
        client.warning("connectClient(): error: %s" % err)
        return False
    client.warning("connectClient(): success")
    return True

def getNuauthConf():
    return NuauthConf(NUAUTH_CONF)

