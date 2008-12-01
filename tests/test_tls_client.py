#!/usr/bin/python
from unittest import TestCase, main
from sys import stderr
from common import createClient, createClientWithCerts, connectClient
from nuauth import Nuauth
from nuauth_conf import NuauthConf
from config import config
from os.path import join as path_join
from os.path import abspath
from logging import warning

class TestTLSClient(TestCase):
    def startNuauth(self, dict_args=None):
        self.cacert = abspath(config.get("test_cert", "cacert"))
        self.nuconfig = NuauthConf()
        if dict_args is None:
            dict_args = dict()
        for key in dict_args.keys():
            self.nuconfig[ key ] = dict_args[key]
        self.nuauth = Nuauth(self.nuconfig)


    def stopNuauth(self):
        self.nuauth.stop()

    def tearDown(self):
        #self.client.stop()
        pass

    def testClientFQDNCheck(self):
        self.startNuauth()
        client1 = createClient(more_args=["-H","nuauth.inl.fr","-A", self.cacert])
        client2 = createClient(more_args=["-H","localhost","-A", self.cacert])
        self.assert_(connectClient(client1))
        self.assert_(not connectClient(client2))
        client1.stop()
        client2.stop()
        self.stopNuauth()

    def testClientIgnoreFQDNCheck(self):
        self.startNuauth()
        client1 = createClient(more_args=["-H","nuauth.inl.fr","-A", self.cacert])
        client2 = createClient(more_args=["-H","localhost","-A", self.cacert,"-N"])
        self.assert_(connectClient(client1))
        self.assert_(connectClient(client2))
        client1.stop()
        client2.stop()
        self.stopNuauth()

    def testClientValidCA(self):
        self.startNuauth()
        client = createClient(more_args=["-A", self.cacert])
        self.assert_(connectClient(client))
        client.stop()
        self.stopNuauth()

    def testClientInvalidCA(self):
        self.startNuauth()
        cacert = config.get("test_cert", "invalid_cacert")
        client = createClient(more_args=["-A", cacert])
        self.assert_(not connectClient(client))
        client.stop()
        self.stopNuauth()

    def testClientValidCert(self):
        args = dict()
        args["nuauth_tls_request_cert"] = "2"
        self.startNuauth(args)
        tls_cert = abspath(config.get("test_cert", "user_cert"))
        tls_key  = abspath(config.get("test_cert", "user_key"))
        client = createClient(more_args=["-A", self.cacert,"-C",tls_cert,"-K",tls_key])
        self.assert_(connectClient(client))
        client.stop()
        self.stopNuauth()

    def testClientInvalidCert(self):
        args = dict()
        args["nuauth_tls_request_cert"] = "2"
        self.startNuauth(args)
        cacert = config.get("test_cert", "invalid_cacert")
        tls_cert = abspath(config.get("test_cert", "user_invalid_cert"))
        tls_key  = abspath(config.get("test_cert", "user_invalid_key"))
        client = createClient(more_args=["-A", self.cacert,"-C",tls_cert,"-K",tls_key])
        self.assert_(not connectClient(client))
        client.stop()
        self.stopNuauth()

    def testClientRevoked(self):
        args = dict()
        args["nuauth_tls_request_cert"] = "1"
        args["nuauth_tls_crl"] = '"%s"' % abspath(config.get("test_cert", "crl"))
        self.startNuauth(args)
        client1 = createClientWithCerts()
        self.assert_(connectClient(client1))
        tls_cert = abspath(config.get("test_cert", "user_revoked_cert"))
        tls_key  = abspath(config.get("test_cert", "user_revoked_key"))
        client2 = createClient(more_args=["-A", self.cacert,"-C",tls_cert,"-K",tls_key])
        self.assert_(not connectClient(client2))
        client1.stop()
        client2.stop()
        self.stopNuauth()

    def testClientExpired(self):
        self.startNuauth()
        client1 = createClientWithCerts()
        self.assert_(connectClient(client1))
        tls_cert = abspath(config.get("test_cert", "user_expired_cert"))
        tls_key  = abspath(config.get("test_cert", "user_expired_key"))
        client2 = createClient(more_args=["-A", self.cacert,"-C",tls_cert,"-K",tls_key])
        self.assert_(not connectClient(client2))
        client1.stop()
        client2.stop()
        self.stopNuauth()

    def testClientInvalidCRL(self):
        args = dict()
        args["nuauth_tls_request_cert"] = "2"
        self.startNuauth(args)
        invalid_crl = abspath(config.get("test_cert", "invalid_crl"))
        client = createClient(more_args=["-H","nuauth.inl.fr","-A",self.cacert,"-R",invalid_crl])
        self.assert_(not connectClient(client))
        client.stop()
        self.stopNuauth()

if __name__ == "__main__":
    print "Test TLS client capabilities"
    main()

