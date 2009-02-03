#!/usr/bin/python
from unittest import TestCase, main
from sys import stderr
from common import connectClient
from nuauth import Nuauth
from nuauth_conf import NuauthConf
from config import config
from plaintext import PlaintextUserDB, PlaintextUser

class TestClientCertAuth(TestCase):
    def setUp(self):
        self.nuconfig = NuauthConf()

        cacert = config.get("test_cert", "cacert")

        # Userdb
        self.user = PlaintextUser("user", "nopassword", 42, 42)
        self.userdb = PlaintextUserDB()
        self.userdb.addUser(self.user)
        self.userdb.install(self.nuconfig)

        # Server
        self.nuconfig["plaintext_userfile"] = '"%s"' % self.userdb.filename
        self.nuconfig["nuauth_tls_auth_by_cert"] = "2"
        self.nuconfig["nuauth_tls_request_cert"] = "2"
        self.nuconfig["nuauth_tls_cacert"] = '"%s"' % cacert
        self.nuconfig["nuauth_tls_key"] = '"%s"' % config.get("test_cert", "nuauth_key")
        self.nuconfig["nuauth_tls_cert"] = '"%s"' % config.get("test_cert", "nuauth_cert")
        self.nuauth = Nuauth(self.nuconfig)

    def tearDown(self):
        self.client.stop()
        self.nuauth.stop()
        self.userdb.desinstall()
        self.nuconfig.desinstall()

    def testValidCert(self):
        # Client
        cacert = config.get("test_cert", "cacert")
        cert = config.get("test_cert", "user_cert")
        key = config.get("test_cert", "user_key")

        args = ["-C", cert, "-K", key, "-A", cacert]

        self.client = self.user.createClient(more_args=args)
        self.client.password = "xx%sxx" % self.user.password
        self.assert_(connectClient(self.client))

    def testInvalidCert(self):
        # Expired certificate
        cacert = config.get("test_cert", "cacert")
        cert = config.get("test_cert", "user_invalid_cert")
        key = config.get("test_cert", "user_invalid_key")

        args = ["-C", cert, "-K", key, "-A", cacert]

        self.client = self.user.createClient(more_args=args)
        self.client.password = "xx%sxx" % self.user.password
        self.assert_(not connectClient(self.client))

if __name__ == "__main__":
    print "Test nuauth client authentication"
    main()

