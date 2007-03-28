# Code to get directories
from os import getcwd, path
CONF_DIR = "/etc/nufw"
NUAUTH_CONF = path.join(CONF_DIR, "nuauth.conf")
ROOT_DIR = path.normpath(path.join(getcwd(), ".."))

# Version
NUFW_VERSION = 20000         # 2.0.0 (1.2.3 = 10203)
NUAUTH_VERSION = NUFW_VERSION
NUTCPC_VERSION = NUFW_VERSION

# Program names
NUFW_PROG = path.join(ROOT_DIR, "src", "nufw", "nufw")
NUAUTH_PROG = path.join(ROOT_DIR, "src", "nuauth", "nuauth")
NUTCPC_PROG = path.join(ROOT_DIR, "src", "clients", "nutcpc", "nutcpc")

# Nuauth options
NUAUTH_HOST = "192.168.0.2"   # FIXME: Automatically get address
USE_VALGRIND = False
if USE_VALGRIND:
    NUAUTH_START_TIMEOUT = 60.0*2
else:
    NUAUTH_START_TIMEOUT = 5.0

# Client options
USERNAME = "haypo"
PASSWORD = "haypo"
CLIENT_IP = NUAUTH_HOST
CLIENT_USER_ID = 1000

# Nufw options
NUFW_START_TIMEOUT = 5.0

# Iptables options
IPTABLE_QUEUE = "NFQUEUE"

