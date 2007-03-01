from os import getcwd, path, kill
from signal import SIGHUP
import atexit
from nuauth import Nuauth
from nuclient import Nuclient

NUAUTH_CONF = "/etc/nufw/nuauth.conf"
ROOT_DIR = path.normpath(path.join(getcwd(), ".."))
NUAUTH_PROG = path.join(ROOT_DIR, "src", "nuauth", "nuauth")
NUTCPC_PROG = path.join(ROOT_DIR, "src", "clients", "nutcpc", "nutcpc")
NUAUTH_HOST = "localhost"

_nuauth = None

def startNuauth():
    global _nuauth
    if _nuauth:
        return
    print "START NUAUTH"
    _nuauth = Nuauth(NUAUTH_PROG)
    atexit.register(_stopNuauth)
    _nuauth.start()
    return _nuauth

def reloadNuauth():
    """
    Reload nuauth configuration (send SIGHUP signal).
    Just start nuauth if it wasn't running
    """
    global _nuauth
    was_running = bool(_nuauth)
    nuauth = startNuauth()
    if was_running:
        kill(nuauth.process.pid, SIGHUP)

def _stopNuauth():
    global _nuauth
    if not _nuauth:
        return
    _nuauth.stop()
    _nuauth = None

def createClient():
    return Nuclient(NUTCPC_PROG, NUAUTH_HOST, "haypo", "haypo")

def connectClient(client):
    try:
        client.start()
    except RuntimeError, err:
        return False
    return True

