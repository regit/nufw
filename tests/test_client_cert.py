#!/usr/bin/python2.4
from unittest import TestCase, main
from sys import stderr
from common import createClient, connectClient
from nuauth import Nuauth
from nuauth_conf import NuauthConf
from config import config
from os.path import join as path_join

class TestClientCert(TestCase):
    def setUp(self):
        self.cacert = config.get("test_cert", "cacert")
        nuconfig = NuauthConf()
        nuconfig["nuauth_tls_auth_by_cert"] = "0"
        nuconfig["nuauth_tls_request_cert"] = "0"
        nuconfig["nuauth_tls_cacert"] = '"%s"' % self.cacert
        nuconfig["nuauth_tls_key"] = '"%s"' % config.get("test_cert", "nuauth_key")
        nuconfig["nuauth_tls_cert"] = '"%s"' % config.get("test_cert", "nuauth_cert")
        self.nuauth = Nuauth(nuconfig)

    def tearDown(self):
        self.client.stop()
        self.nuauth.stop()

    def testValidCert(self):
        self.client = createClient(more_args=["-A", self.cacert])
        self.assert_(connectClient(self.client))

    def testInvalidCert(self):
        cacert = config.get("test_cert", "invalid_cacert")
        self.client = createClient(more_args=["-A", cacert])
        self.assert_(not connectClient(self.client))

if __name__ == "__main__":
    print "Test nuauth client authentification"
    main()

