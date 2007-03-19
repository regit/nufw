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
        config = NuauthConf()

        # Start nuauth with our config
        config["plaintext_userfile"] = '"%s"' % USER_FILENAME
        config["nuauth_user_check_module"] = '"plaintext"'
        self.config.install()
        self.users.install()
        self.nuauth = Nuauth(config)

    def tearDown(self):
        # Restore user DB and nuauth config
        self.users.desinstall()
        self.nuauth.stop()

    def testLogin(self):
        # Test user1
        client = createClient(USER, PASS)
        self.assert_(connectClient(client))
        client.stop()

        # Test user2
        client = createClient(USER2, PASS2)
        self.assert_(connectClient(client))
        client.stop()

        # Test invalid username
        client = createClient(USER+"x", PASS)
        self.assert_(not connectClient(client))
        client.stop()

        # Test invalid password
        client = createClient(USER2, PASS2+"x")
        self.assert_(not connectClient(client))
        client.stop()

if __name__ == "__main__":
    print "Test nuauth module 'plaintext' for AUTH"
    main()

