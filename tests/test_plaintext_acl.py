#!/usr/bin/python2.4
from unittest import TestCase, main
from common import startNufw, connectClient
from nuauth import Nuauth
from nuauth_conf import NuauthConf
from inl_tests.iptables import Iptables
from filter import testAllowPort, testDisallowPort, VALID_PORT, HOST
from test_plaintext_auth import USERDB
from plaintext import PlaintextAcl
from socket import gethostbyname

class TestPlaintextAcl(TestCase):
    def setUp(self):
        self.iptables = Iptables()
        self.users = USERDB
        self.acls = PlaintextAcl()
    	self.host = gethostbyname(HOST)
        self.acls.addAclFull("web", self.host, VALID_PORT, self.users[0].gid)
        config = NuauthConf()

        # Start nuauth with new config
        self.users.install(config)
        self.acls.install(config)
        self.nuauth = Nuauth(config)
        self.nufw = startNufw()

    def tearDown(self):
        # Restore user DB and nuauth config
        self.users.desinstall()
        self.acls.desinstall()
        self.nuauth.stop()
        self.iptables.flush()

    def testFilter(self):
        user = self.users[0]
        client = user.createClient()
        testAllowPort(self, self.iptables, client, self.host)
        testDisallowPort(self, self.iptables, client, self.host)

if __name__ == "__main__":
    print "Test nuauth module 'plaintext' for ACL"
    main()

