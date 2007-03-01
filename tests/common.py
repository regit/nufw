from os import getcwd, path
from nuauth import Nuauth
from nuclient import Nuclient

ROOT_DIR = path.normpath(path.join(getcwd(), ".."))
NUAUTH_PROG = path.join(ROOT_DIR, "src", "nuauth", "nuauth")
NUTCPC_PROG = path.join(ROOT_DIR, "src", "clients", "nutcpc", "nutcpc")
NUAUTH_HOST = "localhost"

nuauth = Nuauth(NUAUTH_PROG)
client = Nuclient(NUTCPC_PROG, NUAUTH_HOST, "haypo", "haypo")

