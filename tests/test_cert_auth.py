#!/usr/bin/python2.4
from unittest import TestCase, main
from sys import stderr
from common import createClient, connectClient
from nuauth import Nuauth
from nuauth_conf import NuauthConf
from config import config
from plaintext import PlaintextUserDB, PlaintextUser

class TestClientCertAuth(TestCase):
    def setUp(self):
        nuconfig = NuauthConf()

        # Certs
        cert = config.get("test_cert", "user_cert")
        key = config.get("test_cert", "user_key")
        cacert = config.get("test_cert", "cacert")

        # Userdb
        self.user = PlaintextUser("user", "nopassword", 42, 42)
        self.userdb = PlaintextUserDB()
        self.userdb.addUser(self.user)
        self.userdb.install(nuconfig)

        # Server
        nuconfig["plaintext_userfile"] = '"%s"' % self.userdb.filename
        nuconfig["nuauth_tls_auth_by_cert"] = "2"
        nuconfig["nuauth_tls_request_cert"] = "2"
        nuconfig["nuauth_tls_cacert"] = cacert
        nuconfig["nuauth_user_check_module"] = '"plaintext"'
        self.nuauth = Nuauth(nuconfig)

        # Client
        args = ["-C", cert, "-K", key, "-A", cacert]
        self.client = createClient(more_args=args)

    def tearDown(self):
        self.client.stop()
        self.nuauth.stop()
        self.userdb.desinstall()

    def testValidCert(self):
        self.assert_(connectClient(self.client))

if __name__ == "__main__":
    print "Test nuauth client authentification"
    main()

