#!/usr/bin/python2.4
from unittest import TestCase, main
from common import createClient, connectClient
from nuauth import Nuauth
from nuauth_conf import NuauthConf
from plaintext import USERDB

class TestPlaintextAuth(TestCase):
    def setUp(self):
        # Setup our user DB
        self.users = USERDB
        self.users.install()

        # Start nuauth with our config
        config = NuauthConf()
        config["plaintext_userfile"] = '"%s"' % self.users.filename
        config["nuauth_user_check_module"] = '"plaintext"'
        self.nuauth = Nuauth(config)

    def tearDown(self):
        # Restore user DB and nuauth config
        self.nuauth.stop()
        self.users.desinstall()

    def testUser1(self):
        user = USERDB[0]
        client = createClient(user.login, user.password)
        self.assert_(connectClient(client))
        client.stop()

    def testUser2(self):
        user = USERDB[1]
        client = createClient(user.login, user.password)
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

