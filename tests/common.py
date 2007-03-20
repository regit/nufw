import atexit
from nufw import Nufw
from nuauth import Nuauth
from client import Client
from nuauth_conf import NuauthConf
from inl_tests.log import setupLog
from config import (USERNAME, PASSWORD,
    NUAUTH_START_TIMEOUT, NUFW_START_TIMEOUT)

_nuauth = None
_nufw = None

def startNufw():
    """
    Start nufw server. If it's already running, do nothing.

    Return nufw process (Nufw class).
    """
    global _nufw
    if _nufw:
        return _nufw
    _nufw = Nufw()
    atexit.register(_stopNufw)
    _nufw.start(timeout=NUFW_START_TIMEOUT)
    return _nufw

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
    return Client(username, password)

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
    return NuauthConf()

setupLog()

