#!/usr/bin/python
from unittest import TestCase, main
from sys import stderr
from common import createClientWithCerts, connectClient
from nuauth import Nuauth
from nuauth_conf import NuauthConf
from config import config
from os.path import join as path_join
from plaintext import PlaintextUser, PlaintextUserDB

class TestClientCert(TestCase):
    def setUp(self):
        self.cacert = config.get("test_cert", "cacert")
        nuconfig = NuauthConf()
        nuconfig["nuauth_user_session_modify_module"]= "\"session_authtype\""
        nuconfig["nuauth_tls_auth_by_cert"] = "0"
        nuconfig["nuauth_tls_request_cert"] = "0"
        nuconfig["nuauth_tls_cacert"] = '"%s"' % self.cacert
        nuconfig["nuauth_tls_key"] = '"%s"' % config.get("test_cert", "nuauth_key")
        nuconfig["nuauth_tls_cert"] = '"%s"' % config.get("test_cert", "nuauth_cert")

        self.config = nuconfig

        # Userdb
        self.user = PlaintextUser("user", "nopassword", 42, 42)
        self.userdb = PlaintextUserDB()
        self.userdb.addUser(self.user)
        self.userdb.install(self.config)

    def tearDown(self):
        self.nuauth.stop()
        self.client.stop()

    def testCertAuthGroupOK(self):
        self.config["nuauth_tls_auth_by_cert"] = "2"
        self.config["session_authtype_ssl_groups"] = "\"42\""
        self.nuauth = Nuauth(self.config)
        # Client
        self.client = self.user.createClientWithCerts()
        self.client.password = "xx%sxx" % self.user.password
        self.assert_(connectClient(self.client))

    def testCertAuthGroupNOK(self):
        self.config["nuauth_tls_auth_by_cert"] = "2"
        self.config["session_authtype_ssl_groups"] = "\"100\""
        self.nuauth = Nuauth(self.config)
        # Client
        self.client = self.user.createClientWithCerts()
        self.client.password = "xx%sxx" % self.user.password
        self.assert_(not connectClient(self.client))

    def testWhitelistAuthOK(self):
        self.config["nuauth_tls_auth_by_cert"] = 0
        self.config["session_authtype_whitelist_groups"] = "\"42\""
        self.nuauth = Nuauth(self.config)

        self.client = self.user.createClientWithCerts()
        self.assert_(connectClient(self.client))

    def testWhitelistAuthNOK(self):
        self.config["nuauth_tls_auth_by_cert"] = 0
        self.config["session_authtype_whitelist_groups"] = "\"123\""
        self.nuauth = Nuauth(self.config)

        self.client = self.user.createClientWithCerts()
        self.assert_(not connectClient(self.client))

    def testBlacklistAuthOK(self):
        self.config["nuauth_tls_auth_by_cert"] = 0
        self.config["session_authtype_blacklist_groups"] = "\"123\""
        self.nuauth = Nuauth(self.config)

        self.client = self.user.createClientWithCerts()
        self.assert_(connectClient(self.client))

    def testBlacklistAuthNOK(self):
        self.config["nuauth_tls_auth_by_cert"] = 0
        self.config["session_authtype_blacklist_groups"] = "\"42\""
        self.nuauth = Nuauth(self.config)

        self.client = self.user.createClientWithCerts()
        self.assert_(not connectClient(self.client))

    def testSASLAuthOK(self):
        self.config["nuauth_tls_auth_by_cert"] = 0
        self.config["session_authtype_sasl_groups"] = "\"42\""
        self.nuauth = Nuauth(self.config)

        self.client = self.user.createClientWithCerts()
        self.assert_(connectClient(self.client))

    def testSASLAuthNOK(self):
        self.config["nuauth_tls_auth_by_cert"] = 0
        self.config["session_authtype_sasl_groups"] = "\"123\""
        self.nuauth = Nuauth(self.config)

        self.client = self.user.createClientWithCerts()
        self.assert_(not connectClient(self.client))

if __name__ == "__main__":
    print "Test nuauth authentication policy"
    main()

