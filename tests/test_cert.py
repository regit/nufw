#!/usr/bin/python2.4
from unittest import TestCase, main
from sys import stderr
from common import createClient, connectClient
from logging import info
from nuauth import Nuauth
from config import config, CONF_DIR
from os.path import expanduser, join as path_join

CERT_FILENAME = path_join(CONF_DIR, "test-cert.pem")
KEY_FILENAME = path_join(CONF_DIR, "test-key.pem")

class TestClientAuth(TestCase):
    def setUp(self):
        # Create ~/.nufw/cacert.pem
        # Create nuauth and client
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

