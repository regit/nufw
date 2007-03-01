#!/usr/bin/python2.4
# Force Python 2.4 => required by subprocess module
from os import getcwd, path
from nuauth import Nuauth
from nuclient import Nuclient

ROOT_DIR = path.normpath(path.join(getcwd(), ".."))
NUAUTH_PROG = path.join(ROOT_DIR, "src", "nuauth", "nuauth")
NUTCPC_PROG = path.join(ROOT_DIR, "src", "clients", "nutcpc", "nutcpc")
NUAUTH_HOST = "localhost"


def main():
    print "[+] Start tests"
    try:
        nuauth = Nuauth(NUAUTH_PROG)
        client = Nuclient(NUTCPC_PROG, NUAUTH_HOST, "haypo", "haypo")
        try:
            nuauth.start()
            print "==> Nuauth is running <=="
            client.start()
            print "==> Client is connected <=="
        finally:
            print "[+] Stop nuauth and client"
            nuauth.stop()
            client.stop()
    except KeyboardInterrupt:
        print "[!] Interrupted"
    except RuntimeError, err:
        print "[!] Runtime error: %s" % err
    print "[+] Exit"

if __name__ == "__main__":
    main()

