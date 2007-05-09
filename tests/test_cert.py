#!/usr/bin/python2.4
from unittest import TestCase, main
from sys import stderr
from common import createClient, connectClient
from nuauth import Nuauth
from config import config
from os.path import join as path_join

class TestClientCert(TestCase):
    def setUp(self):
        self.nuauth = Nuauth()

    def tearDown(self):
        self.client.stop()
        self.nuauth.stop()

    def testValidCert(self):
        cacert = config.get("test_cert", "user_valid_cacert")
        self.client = createClient(more_args=["-A", cacert])
        self.assert_(connectClient(self.client))

    def testInvalidCert(self):
        cacert = config.get("test_cert", "user_invalid_cacert")
        self.client = createClient(more_args=["-A", cacert])
        self.assert_(not connectClient(self.client))

if __name__ == "__main__":
    print "Test nuauth client authentification"
    main()

