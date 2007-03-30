#!/usr/bin/python2.4
from unittest import TestCase, main
from config import CONF_DIR, config
from common import createClient, connectClient
from nuauth import Nuauth
from nuauth_conf import NuauthConf
from os import path
from inl_tests.replace_file import ReplaceFile

class TestSystem(TestCase):
    def setUp(self):
        # Start nuauth with our config
        config = NuauthConf()
        config["nuauth_user_check_module"] = '"system"'
        self.nuauth = Nuauth(config)

    def tearDown(self):
        # Restore user DB and nuauth config
        self.nuauth.stop()

    def testLogin(self):
        username = config.get("test_system", "username")
        password = config.get("test_system", "password")
        client = createClient(username, password)
        self.assert_(connectClient(client))
        client.stop()

        client = createClient(username, "xxx%sxxx" % password)
        self.assert_(not connectClient(client))
        client.stop()

if __name__ == "__main__":
    print "Test nuauth module 'system' for AUTH"
    main()

