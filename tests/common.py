from os import getcwd, path
import atexit
from nuauth import Nuauth
from nuclient import Nuclient

ROOT_DIR = path.normpath(path.join(getcwd(), ".."))
NUAUTH_PROG = path.join(ROOT_DIR, "src", "nuauth", "nuauth")
NUTCPC_PROG = path.join(ROOT_DIR, "src", "clients", "nutcpc", "nutcpc")
NUAUTH_HOST = "localhost"

_nuauth = None

def startNuauth():
    global _nuauth
    if _nuauth:
        return
    _nuauth = Nuauth(NUAUTH_PROG)
    atexit.register(stopNuauth)
    _nuauth.start()
    return _nuauth

def stopNuauth():
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

