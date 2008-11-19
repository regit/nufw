#!/usr/bin/python
from unittest import TestCase, main
from common import startNufw, connectClient
from nuauth import Nuauth
from nuauth_conf import NuauthConf
from inl_tests.iptables import Iptables
from filter import testAllowPort, testPortFailure, VALID_PORT
from test_plaintext_auth import USERDB
from plaintext import PlaintextAcl
from errno import ETIMEDOUT, ENETUNREACH, EISCONN

class TestICMPReject(TestCase):
    def setUp(self):
        self.iptables = Iptables()
        self.users = USERDB
        self.acls = PlaintextAcl()
        self.acls.addAcl("web", VALID_PORT, self.users[0].gid+1)
        self.config = NuauthConf()
        self.config["nuauth_packet_timeout"] = "1"

        self.users.install(self.config)
        self.acls.install(self.config)
        self.nufw = startNufw(["-s"])

    def tearDown(self):
        # Restore user DB and nuauth config
        self.users.desinstall()
        self.acls.desinstall()
        self.nuauth.stop()
        self.iptables.flush()

    def testDrop(self):
        self.config["nuauth_reject_after_timeout"] = "0"
        self.config["nuauth_reject_authenticated_drop"] = "0"
        self.nuauth = Nuauth(self.config)
        user = self.users[0]
        client = user.createClient()
        testPortFailure(self, self.iptables, client, VALID_PORT, ETIMEDOUT)
        client.stop()

    def testRejectTimedout(self):
        self.config["nuauth_reject_after_timeout"] = "1"
        self.config["nuauth_reject_authenticated_drop"] = "0"
        self.nuauth = Nuauth(self.config)
        testPortFailure(self, self.iptables, None, VALID_PORT, ENETUNREACH)

    def testRejectAuthenticated(self):
        self.config["nuauth_reject_after_timeout"] = 0
        self.config["nuauth_reject_authenticated_drop"] = 1
        self.nuauth = Nuauth(self.config)
        user = self.users[0]
        client = user.createClient()
        testPortFailure(self, self.iptables, client, VALID_PORT, ENETUNREACH)
        client.stop()

if __name__ == "__main__":
    print "Test ICMP reject message"
    main()

