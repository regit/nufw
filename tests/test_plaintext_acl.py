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
        self.config = NuauthConf()

        # Start nuauth with new config
        self.users.install(self.config)
        self.nufw = startNufw()

    def tearDown(self):
        # Restore user DB and nuauth config
        self.users.desinstall()
        self.nuauth.stop()
        self.iptables.flush()

    def testFilterByGroup(self):
        self.acls = PlaintextAcl()
        self.acls.addAclFull("Web group", self.host, VALID_PORT, self.users[0].gid)
        self.acls.install(self.config)
        self.nuauth = Nuauth(self.config)
        user = self.users[0]
        client = user.createClient()
        testAllowPort(self, self.iptables, client, self.host)
        testDisallowPort(self, self.iptables, client, self.host)
        self.acls.desinstall()

    def testFilterByUser(self):
        self.acls = PlaintextAcl()
        self.acls.addAclPerUid("Web user", self.host, VALID_PORT, self.users[0].uid)
        self.acls.install(self.config)
        self.nuauth = Nuauth(self.config)
        user = self.users[0]
        client = user.createClient()
        testAllowPort(self, self.iptables, client, self.host)
        testDisallowPort(self, self.iptables, client, self.host)
        self.acls.desinstall()

if __name__ == "__main__":
    print "Test nuauth module 'plaintext' for ACL"
    main()

