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

class TestTLSNuauth(TestCase):
    def startNuauth(self, dict_args=None):
        self.cacert = config.get("test_cert", "cacert")
        self.nuconfig = NuauthConf()
        self.nuconfig["nuauth_tls_request_cert"] = "2"
        self.nuconfig["nuauth_tls_crl"] = '"%s"' % abspath(config.get("test_cert", "crl"))
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

    def testNuauthValidCA(self):
        self.startNuauth()
        self.client = createClientWithCerts()
        self.assert_(connectClient(self.client))
        self.client.stop()
        self.stopNuauth()

    def testNuauthInvalidCA(self):
        cacert = abspath(config.get("test_cert", "invalid_cacert"))
        args = dict()
        args["nuauth_tls_cacert"] = "'%s'" % cacert
        # we must disable CRL for this one, else nuauth fails with an
        # error (CRL is not issued by CA)
        args["nuauth_tls_crl"] = None
        self.startNuauth(args)
        self.client = createClientWithCerts()
        self.assert_(not connectClient(self.client))
        self.client.stop()
        self.stopNuauth()

    def testNuauthRevoked(self):
        args = dict()
        args["nuauth_tls_key"] = '"%s"' % abspath(config.get("test_cert", "user_revoked_key"))
        args["nuauth_tls_cert"] = '"%s"' % abspath(config.get("test_cert", "user_revoked_cert"))
        self.startNuauth(args)
        self.client = createClient(more_args=["-H","nuauth.inl.fr","-A",self.cacert,"-R",abspath("./pki/crl.pem")])
        self.assert_(not connectClient(self.client))
        self.client.stop()
        self.stopNuauth()

    def testNuauthExpired(self):
        args = dict()
        args["nuauth_tls_key"] = '"%s"' % abspath(config.get("test_cert", "user_expired_key"))
        args["nuauth_tls_cert"] = '"%s"' % abspath(config.get("test_cert", "user_expired_cert"))
        self.startNuauth(args)
        self.client = createClient(more_args=["-H","nuauth.inl.fr","-A",self.cacert])
        self.assert_(not connectClient(self.client))
        self.client.stop()
        self.client = createClient(more_args=["-H","nuauth.inl.fr","-Q"])
        self.assert_(not connectClient(self.client))
        self.client.stop()
        self.stopNuauth()

    def testNuauthInvalidCRL(self):
        args = dict()
        args["nuauth_tls_request_cert"] = "2"
        args["nuauth_tls_crl"] = '"%s"' % abspath(config.get("test_cert", "invalid_crl"))
	mytest = False
	try:
            self.startNuauth(args)
	except:
	    mytest = True
	self.assert_(mytest)
	if not mytest:
            self.stopNuauth()


if __name__ == "__main__":
    print "Test TLS nuauth capabilities"
    main()

