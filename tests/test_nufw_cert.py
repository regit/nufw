#!/usr/bin/python
from compatibility import any
from unittest import TestCase, main
from sys import stderr
from common import createClient, connectClient, PASSWORD, startNufw
from nuauth import Nuauth
from config import config
from inl_tests.iptables import Iptables
from nuauth_conf import NuauthConf
from mysocket import connectTcp
from filter import testAllowPort, testPort, HOST, VALID_PORT
# We perform the cert check wether a client can connect or not
from plaintext import USERDB
from plaintext import PlaintextAcl

# TODO: check -n=CN:...

TIMEOUT = 2.0

class TestClientCert(TestCase):
    def setUp(self):
        self.iptables = Iptables()
        self.port = VALID_PORT
        self.host = HOST
        self.cacert = config.get("test_cert", "cacert")

        self.nuconfig = NuauthConf()
        self.nuconfig["nuauth_tls_auth_by_cert"] = "0"
        self.nuauth = Nuauth(self.nuconfig)

    def tearDown(self):
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
        self.nufw = startNufw()
        self.connectNuauthNufw()

        self.assert_(self.nufw_connection_is_established())

        self.nufw.stop()

    def get_tls_cert_invalid(self):
        for line in self.nufw.readlines(total_timeout=TIMEOUT):
            if line.lower().find('certificate verification failed') >= 0:
                return True
        return False

    def testInvalidCert(self):
        invalid_cacert = config.get("test_cert", "invalid_cacert")
        self.nufw = startNufw(["-a", invalid_cacert])
        self.connectNuauthNufw()

        self.assert_(self.get_tls_cert_invalid())
        self.nufw.stop()

    # If NuFW does not run under the strict mode, the provided certificates in svn
    # will be accepted and the client will be able to authenticate and then be
    # accepted by the firewall. This is what we want to check here
    def testNotStrictMode(self):

        self.nufw = startNufw(["-s"])
        self.connectNuauthNufw()

        self.assert_(self.nufw_connection_is_established())

        self.nufw.stop()

    def testStrictMode(self):

        self.nufw = startNufw(["-d","127.0.0.1"])
        self.connectNuauthNufw()

        self.assert_(not self.nufw_connection_is_established())

        self.nufw.stop()

    def nufw_connection_is_established(self):
        if self.nufw.is_connected_to_nuauth:
            return True
        for line in self.nufw.readlines(total_timeout=TIMEOUT):
            if line.lower().find("tls connection to nuauth established") >= 0:
                return True
            if line.lower().find("tls connection to nuauth restored") >= 0:
                return True
        return False

if __name__ == "__main__":
    print "Test nuauth client authentification"
    main()

