from os import getcwd, path
from signal import SIGHUP
import atexit
from nuauth import Nuauth
from client import Client
from config import NuauthConf

CONF_DIR = "/etc/nufw"
NUAUTH_CONF = path.join(CONF_DIR, "nuauth.conf")
ROOT_DIR = path.normpath(path.join(getcwd(), ".."))
NUAUTH_PROG = path.join(ROOT_DIR, "src", "nuauth", "nuauth")
NUTCPC_PROG = path.join(ROOT_DIR, "src", "clients", "nutcpc", "nutcpc")
NUAUTH_HOST = "localhost"
USERNAME = "haypo"
PASSWORD = "haypo"

_nuauth = None

def startNuauth():
    """
    Start nuauth. If nuauth is already running, do nothing.

    Return nuauth process (Nuauth class).
    """
    global _nuauth
    if _nuauth:
        return _nuauth
    _nuauth = Nuauth(NUAUTH_PROG)
    atexit.register(_stopNuauth)
    _nuauth.start()
    return _nuauth

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

def createClient():
    return Client(NUTCPC_PROG, NUAUTH_HOST, USERNAME, PASSWORD)

def connectClient(client):
    try:
        client.start(timeout=10.0)
    except RuntimeError, err:
#        print "[!] connectClient() error: %s" % err
        return False
    return True

def getNuauthConf():
    return NuauthConf(NUAUTH_CONF)

