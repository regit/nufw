#!/usr/bin/python2.4
from unittest import TestCase, main
from config import CONF_DIR
from common import (
    startNufw,
    reloadNuauth, getNuauthConf,
    createClient, connectClient)
from iptables import Iptables
from os import path
from filter import testAllowPort, testDisallowPort, VALID_PORT
from test_plaintext_auth import USER_FILENAME, USER, PASS, GID, USER_DB
from replace_file import ReplaceFile

ACL_FILENAME = path.join(CONF_DIR, "acls.nufw")

ACLS = """[web]
decision=1
gid=%u
proto=6
SrcIP=0.0.0.0/0
SrcPort=1024-65535
DstIP=0.0.0.0/0
DstPort=%u""" % (GID, VALID_PORT)

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
        client = createClient(USER, PASS)
        testAllowPort(self, self.iptables, client)
        testDisallowPort(self, self.iptables, client)

if __name__ == "__main__":
    print "Test nuauth module 'plaintext' for ACL"
    main()

