#!/usr/bin/python2.4
from unittest import TestCase, main
from common import createClient, connectClient
from nuauth import Nuauth
from nuauth_conf import NuauthConf
from plaintext import USERDB

class TestPlaintextAuth(TestCase):
    def setUp(self):
        config = NuauthConf()
        self.users = USERDB
        self.users.install(config)
        self.nuauth = Nuauth(config)

    def tearDown(self):
        self.nuauth.stop()
        self.users.desinstall()

    def testUser1(self):
        user = USERDB[0]
        client = user.createClient()
        self.assert_(connectClient(client))
        client.stop()

    def testUser2(self):
        user = USERDB[1]
        client = user.createClient()
        self.assert_(connectClient(client))
        client.stop()

    def testInvalidLogin(self):
        user = USERDB[0]
        client = createClient(user.login+"x", user.password)
        self.assert_(not connectClient(client))
        client.stop()

    def testInvalidPass(self):
        user = USERDB[1]
        client = createClient(user.login, user.password+"x")
        self.assert_(not connectClient(client))
        client.stop()

if __name__ == "__main__":
    print "Test nuauth module 'plaintext' for AUTH"
    main()

