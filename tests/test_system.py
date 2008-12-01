#!/usr/bin/python
from unittest import TestCase, main
from config import CONF_DIR, config
from common import createClientWithCerts, connectClient
from nuauth import Nuauth
from nuauth_conf import NuauthConf
from os import path
from inl_tests.replace_file import ReplaceFile

class TestSystem(TestCase):
    def setUp(self):
        # Start nuauth with our config
        nuconfig = NuauthConf()
        nuconfig["nuauth_user_check_module"] = '"system"'
        self.nuauth = Nuauth(nuconfig)

    def tearDown(self):
        # Restore user DB and nuauth config
        self.nuauth.stop()

    def testLogin(self):
        username = config.get("test_system", "username")
        password = config.get("test_system", "password")
        client = createClientWithCerts(username, password)
        self.assert_(connectClient(client))
        client.stop()

        client = createClientWithCerts(username, "xxx%sxxx" % password)
        self.assert_(not connectClient(client))
        client.stop()

if __name__ == "__main__":
    print "Test nuauth module 'system' for AUTH"
    main()

