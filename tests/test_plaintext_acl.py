#!/usr/bin/python2.4
from unittest import TestCase, main
from common import (CONF_DIR,
    startNufw,
    reloadNuauth, getNuauthConf,
    createClient, connectClient)
from iptables import Iptables
from os import path
from mysocket import connectTcp
from test_plaintext_auth import USER_FILENAME, USER, PASS, GID, USER_DB
from replace_file import ReplaceFile

ACL_FILENAME = path.join(CONF_DIR, "acls.nufw")
PORT = 80
PORT2 = 90
HOST = "www.google.com"
TIMEOUT = 1.0

ACLS = """[web]
decision=1
gid=%u
proto=6
SrcIP=0.0.0.0/0
SrcPort=1024-65535
DstIP=0.0.0.0/0
DstPort=%u""" % (GID, PORT)

class TestPlaintextAcl(TestCase):
    def setUp(self):
        self.iptables = Iptables()
        self.users = ReplaceFile(USER_FILENAME, USER_DB)
        self.acls = ReplaceFile(ACL_FILENAME, ACLS)
        self.config = getNuauthConf()
        self.config["plaintext_userfile"] = '"%s"' % USER_FILENAME
        self.config["plaintext_aclfile"] = '"%s"' % ACL_FILENAME
        self.config["nuauth_user_check_module"] = '"plaintext"'
        self.config["nuauth_acl_check_module"] = '"plaintext"'

        # Start nuauth with new config
        self.config.install()
        self.users.install()
        self.acls.install()
        self.nuauth = reloadNuauth()
        self.nufw = startNufw()

    def tearDown(self):
        # Restore user DB and nuauth config
        self.users.desinstall()
        self.acls.desinstall()
        self.config.desinstall()
        reloadNuauth()
        self.iptables.flush()

    def testFilter(self):
        # Enable iptables filtering (1/2)
        self.iptables.filterTcp(PORT)

        # Connect user
        client = createClient(USER, PASS)
        self.assert_(connectClient(client))

        # Create socket
        self.assert_(connectTcp(HOST, PORT, TIMEOUT))

        # Enable iptables filtering (2/2)
        self.iptables.filterTcp(PORT2)

        # Create socket
        self.assert_(not connectTcp(HOST, PORT2, TIMEOUT))

        # Disconnect user
        client.stop()

if __name__ == "__main__":
    print "Test nuauth module 'plaintext' for ACL"
    main()

