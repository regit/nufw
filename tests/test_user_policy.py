#!/usr/bin/python2.4
from unittest import TestCase, main
from config import CONF_DIR
from common import createClient, connectClient
from nuauth import Nuauth
from nuauth_conf import NuauthConf
from os import path
from inl_tests.replace_file import ReplaceFile
from plaintext import USERDB

class TestPlaintextAuth(TestCase):
    def setUp(self):
        # Setup our user DB
        self.config = NuauthConf()
        self.users = USERDB
        self.userA = self.users[0]
        self.userB = self.users[1]
        self.users.install(self.config)

    def tearDown(self):
        # Restore user DB and nuauth config
        self.users.desinstall()
        self.nuauth.stop()

    def testLoginNormal(self):
        # Change login policy to 0
        self.config["nuauth_single_ip_client_limit"] = 0
        self.config["nuauth_single_user_client_limit"] = 0
        self.nuauth = Nuauth(self.config)

        # Test user1
        client1 = self.userA.createClient()
        self.assert_(connectClient(client1))

        # Test user2
        client2 = self.userB.createClient()
        self.assert_(connectClient(client2))

        client1.stop()
        client2.stop()

    def testLoginOne(self):
        # Change login policy to 1 login/user
        self.config["nuauth_single_ip_client_limit"] = 0
        self.config["nuauth_single_user_client_limit"] = 1
        self.nuauth = Nuauth(self.config)

        # User can't log twice
        # Test user1
        client1 = self.userA.createClient()
        self.assert_(connectClient(client1))

        # Test user1
        client2 = self.userA.createClient()
        self.assert_(not connectClient(client2))

        client1.stop()
        client2.stop()


    def testLoginIP(self):
        # Change login policy to 1 login/IP
        self.config["nuauth_single_ip_client_limit"] = 1
        self.config["nuauth_single_user_client_limit"] = 0
        self.nuauth = Nuauth(self.config)

        # Different users can't log from same IP
        # Test user1
        client1 = self.userA.createClient()
        self.assert_(connectClient(client1))

        # Test user2
        client2 = self.userB.createClient()
        self.assert_(not connectClient(client2))

        client1.stop()
        client2.stop()

if __name__ == "__main__":
    print "Test nuauth user policy with 'plaintext' AUTH"
    main()

