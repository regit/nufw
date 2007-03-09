#!/usr/bin/python2.4
from unittest import TestCase, main
from config import CONF_DIR
from common import (
    reloadNuauth, getNuauthConf,
    createClient, connectClient)
from os import path
from replace_file import ReplaceFile

USER_FILENAME = path.join(CONF_DIR, "users.nufw")
USER, UID, GID, PASS = "username", 42, 42, "password"
USER2, PASS2 = "username2", "password2"
USER_DB  = "%s:%s:%u:%u\n" % (USER, PASS, UID, GID)
USER_DB += "%s:%s:1:2,3\n" % (USER2, PASS2)

class TestPlaintextAuth(TestCase):
    def setUp(self):
        # Setup our user DB
        self.users = ReplaceFile(USER_FILENAME, USER_DB)
        self.config = getNuauthConf()

        # Start nuauth with our config
        self.config["plaintext_userfile"] = '"%s"' % USER_FILENAME
        self.config["nuauth_user_check_module"] = '"plaintext"'
        self.config.install()
        self.users.install()
        self.nuauth = reloadNuauth()

    def tearDown(self):
        # Restore user DB and nuauth config
        self.users.desinstall()
        self.config.desinstall()
        reloadNuauth()

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

