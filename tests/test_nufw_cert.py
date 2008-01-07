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

        self.nuconfig = NuauthConf()
        self.nuconfig["nuauth_tls_auth_by_cert"] = "0"
        self.nuconfig["nuauth_tls_request_cert"] = "0"
        self.nuconfig["nuauth_tls_cacert"] = '"%s"' % self.cacert
        self.nuconfig["nuauth_tls_key"] = '"%s"' % config.get("test_cert", "nuauth_key")
        self.nuconfig["nuauth_tls_cert"] = '"%s"' % config.get("test_cert", "nuauth_cert")
        self.nuauth = Nuauth(self.nuconfig)

    def tearDown(self):
        self.nufw.stop()
        self.nuauth.stop()
        self.nuconfig.desinstall()
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

    def testInvalidCert(self):
        invalid_cacert = config.get("test_cert", "invalid_cacert")
        self.nufw = startNufw(["-a", invalid_cacert])
        self.connectNuauthNufw()

        self.assert_(any("tls: invalid certificates received from nuauth server" in line.lower()
            for line in self.nufw.readlines(total_timeout=TIMEOUT)))

if __name__ == "__main__":
    print "Test nuauth client authentification"
    main()

