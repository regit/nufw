#!/usr/bin/python2.4
from unittest import TestCase, main
from common import (CONF_DIR,
    reloadNuauth, getNuauthConf,
    createClient, connectClient)
from config import NuauthConf
from os import path
from replace_file import ReplaceFile

USER_FILENAME = path.join(CONF_DIR, "users.nufw")
USER1, PASS1 = "username", "password"
USER2, PASS2 = "username2", "password2"
USER_DB  = "%s:%s:42:4242,101\n" % (USER1, PASS1)
USER_DB += "%s:%s:1:2,3\n" % (USER2, PASS2)

class TestPlaintextAuth(TestCase):
    def setUp(self):
        # Prepare our user DB
        self.users = ReplaceFile(USER_FILENAME, USER_DB)

        # Start nuauth with new config
        self.config = getNuauthConf()
        self.config["plaintext_userfile"] = '"%s"' % USER_FILENAME
        self.config["nuauth_user_check_module"] = '"plaintext"'
        self.config.install()
        self.nuauth = reloadNuauth()

    def tearDown(self):
        # Restore user DB and nuauth config
        self.users.desinstall()
        self.config.desinstall()
        reloadNuauth()

    def testLogin(self):
        # Install our scripts
        self.users.install()

        # Test user1
        client = createClient()
        client.username = USER1
        client.password = PASS1
        self.assert_(connectClient(client))
        client.stop()

        # Test user2
        client = createClient()
        client.username = USER2
        client.password = PASS2
        self.assert_(connectClient(client))
        client.stop()

        # Test invalid username
        client = createClient()
        client.username = USER1+"x"
        client.password = PASS1
        self.assert_(not connectClient(client))
        client.stop()

        # Test invalid password
        client = createClient()
        client.username = USER2
        client.password = PASS2+"x"
        self.assert_(not connectClient(client))
        client.stop()

if __name__ == "__main__":
    print "Test nuauth module 'plaintext' for AUTH"
    main()

