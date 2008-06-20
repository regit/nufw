#!/usr/bin/python
from unittest import TestCase, main
from common import startNufw, connectClient
from nuauth import Nuauth
from nuauth_conf import NuauthConf
from inl_tests.iptables import Iptables
from mysocket import connectTcp
from filter import testAllowPort, HOST, VALID_PORT, TIMEOUT

class TestSYNACKignore(TestCase):
    def setUp(self):
        self.iptables = Iptables()
        self.iptables.command('-A OUTPUT -p tcp --sport %u -d %s --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE' % (VALID_PORT, HOST))
        config = NuauthConf()

        self.nuauth = Nuauth(config)
        self.nufw = startNufw()

    def tearDown(self):
        self.nuauth.stop()
        self.iptables.flush()

    def testsynack(self):
        # Create socket
        self.assertEqual(connectTcp(HOST, VALID_PORT, TIMEOUT), True)

if __name__ == "__main__":
    print "Test TCP SYN ACK packet"
    main()

