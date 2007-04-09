#!/usr/bin/python2.4
from unittest import TestCase, main
from config import CONF_DIR
from common import createClient, connectClient
from nuauth import Nuauth
from nuauth_conf import NuauthConf
from os import path
from inl_tests.replace_file import ReplaceFile

USER_FILENAME = path.join(CONF_DIR, "users.nufw")
USER, UID, GID, PASS = "username", 42, 42, "password"
USER2, PASS2 = "username2", "password2"
USER_DB  = "%s:%s:%u:%u\n" % (USER, PASS, UID, GID)
USER_DB += "%s:%s:1:2,3\n" % (USER2, PASS2)

class TestPlaintextAuth(TestCase):
    def setUp(self):
        # Setup our user DB
        self.users = ReplaceFile(USER_FILENAME, USER_DB)
        self.users.install()

        # Start nuauth with our config
        config = NuauthConf()
        config["plaintext_userfile"] = '"%s"' % USER_FILENAME
        config["nuauth_user_check_module"] = '"plaintext"'
        self.nuauth = Nuauth(config)

    def tearDown(self):
        # Restore user DB and nuauth config
        self.users.desinstall()
        self.nuauth.stop()

    def testLogin(self):
        # Change login policy to 0
        config = NuauthConf()
        config["nuauth_connect_policy"] = 0
        self.nuauth = Nuauth(config)

        # Test user1
        client1 = createClient(USER, PASS)
        self.assert_(connectClient(client))

        # Test user2
        client2 = createClient(USER2, PASS2)
        self.assert_(connectClient(client))

        client1.stop()
        client2.stop()

        # Change login policy to 1 
        # User can't log twice
        config = NuauthConf()
        config["nuauth_connect_policy"] = 1
        self.nuauth = Nuauth(config)

        # Test user1
        client1 = createClient(USER, PASS)
        self.assert_(connectClient(client))

        # Test user1
        client2 = createClient(USER, PASS)
        self.assert_(not connectClient(client))

        client1.stop()
        client2.stop()

        # Change login policy to 2
        # Different users can't log from same IP
        config = NuauthConf()
        config["nuauth_connect_policy"] = 2
        self.nuauth = Nuauth(config)

        # Test user1
        client1 = createClient(USER, PASS)
        self.assert_(connectClient(client))

        # Test user2
        client2 = createClient(USER2, PASS2)
        self.assert_(not connectClient(client))

        client1.stop()
        client2.stop()

if __name__ == "__main__":
    print "Test nuauth user policy with 'plaintext' AUTH"
    main()

