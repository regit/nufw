#!/usr/bin/python2.4
from compatibility import any
from unittest import TestCase, main
from sys import stderr
from common import createClient, startNufw
from nuauth import Nuauth
from config import config
from inl_tests.iptables import Iptables
from nuauth_conf import NuauthConf
from mysocket import connectTcp
from filter import HOST, VALID_PORT

# TODO: check -n=CN:...

TIMEOUT = 2.0

class TestClientCert(TestCase):
    def setUp(self):
        self.port = VALID_PORT
        self.cacert = config.get("test_cert", "cacert")
        self.iptables = Iptables()

        nuconfig = NuauthConf()
        nuconfig["nuauth_tls_auth_by_cert"] = "0"
        nuconfig["nuauth_tls_request_cert"] = "0"
        nuconfig["nuauth_tls_cacert"] = '"%s"' % self.cacert
        nuconfig["nuauth_tls_key"] = '"%s"' % config.get("test_cert", "nuauth_key")
        nuconfig["nuauth_tls_cert"] = '"%s"' % config.get("test_cert", "nuauth_cert")
        self.nuauth = Nuauth(nuconfig)

    def tearDown(self):
        self.nufw.stop()
        self.nuauth.stop()
        self.iptables.flush()

    def connectNuauthNufw(self):
        # Open TCP connection just to connect nufw to nuauth
        self.iptables.filterTcp(self.port)
        connectTcp(HOST, self.port, 0.100)


        # nufw side
        # "TLS connection to nuauth can NOT be restored"

    def testValidCert(self):
        self.nufw = startNufw(["-a", self.cacert])
        self.connectNuauthNufw()

        self.assert_(any("TLS connection to nuauth restored" in line
            for line in self.nufw.readlines(total_timeout=TIMEOUT)))

#    def testInvalidCert(self):
#        args = ["-a", config.get("test_cert", "invalid_cacert")]
#        self.nufw = startNufw(args)
#        self.connectNuauthNufw()
#
#        self.assert_(any("TLS: Invalid certificates received from nuauth server" in line
#            for line in self.nufw.readlines(total_timeout=TIMEOUT)))

if __name__ == "__main__":
    print "Test nuauth client authentification"
    main()

