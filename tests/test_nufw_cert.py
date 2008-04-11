#!/usr/bin/python2.4
from compatibility import any
from unittest import TestCase, main
from sys import stderr
from common import createClient, connectClient, PASSWORD, startNufw
from nuauth import Nuauth
from config import config, USE_VALGRIND
from inl_tests.iptables import Iptables
from nuauth_conf import NuauthConf
from mysocket import connectTcp
from filter import testAllowPort, testPort, HOST, VALID_PORT
# We perform the cert check wether a client can connect or not
from plaintext import USERDB
from plaintext import PlaintextAcl

# TODO: check -n=CN:...

TIMEOUT = 10.0

if USE_VALGRIND:
    TIMEOUT *= 10

class TestClientCert(TestCase):
    def setUp(self):
        self.iptables = Iptables()
        self.port = VALID_PORT
        self.host = HOST
        self.cacert = config.get("test_cert", "cacert")

        self.nuconfig = NuauthConf()
        self.nuconfig["nuauth_tls_auth_by_cert"] = "0"
        self.nuconfig["nuauth_tls_request_cert"] = "0"
        self.nuconfig["nuauth_tls_cacert"] = '"%s"' % self.cacert
        self.nuconfig["nuauth_tls_key"] = '"%s"' % config.get("test_cert", "nuauth_key")
        self.nuconfig["nuauth_tls_cert"] = '"%s"' % config.get("test_cert", "nuauth_cert")
        self.nuauth = Nuauth(self.nuconfig)

    def tearDown(self):
        self.nuauth.stop()
        self.nuconfig.desinstall()
        self.iptables.flush()

    def connectNuauthNufw(self):
        # Open TCP connection just to connect nufw to nuauth
        self.iptables.filterTcp(self.port)
        if USE_VALGRIND:
                connectTcp(HOST, self.port, 10.0)
        else:
                connectTcp(HOST, self.port, 0.100)

        # nufw side
        # "TLS connection to nuauth can NOT be restored"

    def testValidCert(self):
        self.nufw = startNufw(["-a", self.cacert])
        self.connectNuauthNufw()

        self.assert_(self.nufw.waitline("TLS connection to nuauth restored", TIMEOUT))

        self.nufw.stop()

    def testInvalidCert(self):
        invalid_cacert = config.get("test_cert", "invalid_cacert")
        self.nufw = startNufw(["-a", invalid_cacert])
        self.connectNuauthNufw()

        self.assert_(self.nufw.waitline("Certificate authority verification failed:invalid, signer not found,", TIMEOUT))
        self.nufw.stop()

    # If NuFW does not run under the strict mode, the provided certificates in svn
    # will be accepted and the client will be able to authenticate and then be
    # accepted by the firewall. This is what we want to check here
    def testNotStrictMode(self):

        self.nufw = startNufw()
        self.connectNuauthNufw()

        self.assert_(self.nufw.waitline("TLS connection to nuauth restored", TIMEOUT))

        self.nufw.stop()

#    def testStrictMode(self):
#
#        self.nufw = startNufw(["-S"])
#        self.connectNuauthNufw()
#
#       self.assert_(any("tls: invalid certificates received from nuauth server" in line.lower()
#            for line in self.nufw.readlines(total_timeout=TIMEOUT)))
#
#        self.nufw.stop()


if __name__ == "__main__":
    print "Test nuauth client authentification"
    main()

