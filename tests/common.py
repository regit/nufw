import atexit
from nufw import Nufw
from nuauth import Nuauth
from client import Client
from nuauth_conf import NuauthConf
from inl_tests.log import setupLog
from config import (config, USERNAME, PASSWORD,
    NUAUTH_START_TIMEOUT, NUFW_START_TIMEOUT, CLIENT_IP)
from time import time, sleep
from logging import warning
from os import nice
from os.path import abspath

_nuauth = None
_nufw = None

def startNufw(args=None):
    """
    Start nufw server. If it's already running, do nothing.

    Return nufw process (Nufw class).
    """
    global _nufw
    if _nufw:
        if args or _nufw.args or (not _nufw.isRunning()):
            # if command line arguments changed: restart nufw!
            _stopNufw()
        else:
            return _nufw
    _nufw = Nufw(args)
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

def createClient(username=USERNAME, password=PASSWORD, more_args=None):
    return Client(username, password, CLIENT_IP, more_args=more_args)

def createClientWithCerts(username=USERNAME, password=PASSWORD, more_args=None):
    nuconfig = NuauthConf()
    cacert = abspath(config.get("test_cert", "cacert"))
    cert = abspath(config.get("test_cert", "user_cert"))
    key = abspath(config.get("test_cert", "user_key"))
    args = ["-C", cert, "-K", key, "-A", cacert]
    if more_args:
        args = args.concat(more_args)
    return Client(username, password, CLIENT_IP, more_args=args)

def connectClient(client):
    client.info("connectClient()")
    try:
        client.start(timeout=connectClient.timeout)
    except RuntimeError, err:
        client.warning("connectClient(): error: %s" % err)
        return False
    client.warning("connectClient(): connected")
    return True
connectClient.timeout = config.getfloat('nutcpc', 'connect_timeout')

def getNuauthConf():
    return NuauthConf()

def retry(timeout=1.0, step=0.250):
    start = time()
    while True:
        when = time() - start
        yield when
        if timeout < when:
            raise RuntimeError("Timeout (%.1f sec)!" % timeout)
            return
        if step:
            warning("(retry) sleep(%.3f)" % step)
            sleep(step)

setupLog()
warning("Be nice: os.nice(15)")
nice(15)

