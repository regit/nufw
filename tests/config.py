from myconfig import ConfigParser
config = ConfigParser()
config.read(["defaults.cfg", "config.cfg"])
from os import getcwd, path
CONF_DIR = config.get("nuauth", "confdir")
NUAUTH_CONF = path.join(CONF_DIR, "nuauth.conf")

# Nuauth options
NUAUTH_VERSION = config.getint("nuauth", "version")
NUAUTH_PROG = config.get("nuauth", "prog")
NUAUTH_HOST = config.get("nuauth", "host")
USE_VALGRIND = config.getboolean("nuauth", "use_valgrind")
NUAUTH_START_TIMEOUT = config.getfloat("nuauth", "start_timeout")

# Client options
NUTCPC_VERSION = config.getint("nutcpc", "version")
NUTCPC_PROG = config.get("nutcpc", "prog")
USERNAME = config.get("nutcpc", "username")
PASSWORD = config.get("nutcpc", "password")
CLIENT_IP = config.get("nutcpc", "ip")
CLIENT_USER_ID = config.get("nutcpc", "userid")

# Nufw options
NUFW_VERSION = config.getint("nufw", "version")
NUFW_PROG = config.get("nufw", "prog")
NUFW_START_TIMEOUT = config.getfloat("nufw", "start_timeout")

# Iptables options
IPTABLE_QUEUE = config.get("iptables", "queue")

