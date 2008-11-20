#!/usr/bin/python
from unittest import TestCase, main
from sys import stderr
from common import createClient, connectClient, PASSWORD
from logging import info
from nuauth import Nuauth
from nuauth_conf import NuauthConf
from config import config
from os.path import abspath

class TestClientAuth(TestCase):
    def setUp(self):
        # Load nuauth
        nuconfig = NuauthConf()
        self.config = nuconfig
        self.nuauth = Nuauth()

        # Create client
        cacert = abspath(config.get("test_cert", "cacert"))
        cert = abspath(config.get("test_cert", "user_cert"))
        key = abspath(config.get("test_cert", "user_key"))
        args = ["-C", cert, "-K", key, "-A", cacert]
        self.client = createClient(more_args=args)

    def tearDown(self):
        self.client.stop()
        self.nuauth.stop()

    def testValidPass(self):
        self.client.password = PASSWORD
        self.assert_(connectClient(self.client))

    def testInvalidPass(self):
        self.client.password = "xxx%sxxx" % PASSWORD
        self.assert_(not connectClient(self.client))

if __name__ == "__main__":
    print "Test nuauth client authentification"
    main()

