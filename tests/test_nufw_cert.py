#!/usr/bin/python2.4
from unittest import TestCase, main
from sys import stderr
from common import createClient, startNufw
from nuauth import Nuauth
from config import config
from inl_tests.iptables import Iptables
from mysocket import connectTcp
from filter import HOST, VALID_PORT

class TestClientCert(TestCase):
    def setUp(self):
        args = [
            "-a", config.get("test_cert", "cacert"),
            "-c", config.get("test_cert", "nufw_cert"),
            "-k", config.get("test_cert", "nufw_key")]
        self.nufw = startNufw(args)
        self.nuauth = Nuauth()
        self.iptables = Iptables()

    def tearDown(self):
        self.nufw.stop()
        self.nuauth.stop()
        self.iptables.flush()

    def testCert(self):
        # Open TCP connection just to connect nufw to nuauth
        port = VALID_PORT
        self.iptables.filterTcp(port)
        connectTcp(HOST, port, 0.100)

if __name__ == "__main__":
    print "Test nuauth client authentification"
    main()

