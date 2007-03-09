# Code to get directories
from os import getcwd, path
CONF_DIR = "/etc/nufw"
NUAUTH_CONF = path.join(CONF_DIR, "nuauth.conf")
ROOT_DIR = path.normpath(path.join(getcwd(), ".."))

# Program names
NUFW_PROG = path.join(ROOT_DIR, "src", "nufw", "nufw")
NUAUTH_PROG = path.join(ROOT_DIR, "src", "nuauth", "nuauth")
NUTCPC_PROG = path.join(ROOT_DIR, "src", "clients", "nutcpc", "nutcpc")

# Nuauth options
NUAUTH_HOST = "192.168.0.2"   # FIXME: Automatically get address
USE_COVERAGE = False
if USE_COVERAGE:
    NUAUTH_START_TIMEOUT = 60.0
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

