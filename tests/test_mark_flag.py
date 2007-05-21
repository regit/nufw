#!/usr/bin/python2.4
from unittest import TestCase, main
from sys import stderr
from logging import info
from nuauth import Nuauth
from nuauth_conf import NuauthConf
from common import startNufw, connectClient
from filter import HOST, VALID_PORT, TIMEOUT
from inl_tests.iptables import Iptables
from mysocket import connectTcp
from plaintext import PlaintextUserDB, PlaintextUser, PlaintextAcl

class TestClientAuth(TestCase):
    def setUp(self):
        self.port1 = VALID_PORT
        self.port2 = VALID_PORT+1
        self.mark1 = 1
        self.mark2 = 2
        self.shift = 8
        config = NuauthConf()

        # Userdb
        self.user = PlaintextUser("guest", "nopassword", 42, 42)
        self.userdb = PlaintextUserDB()
        self.userdb.addUser(self.user)
        self.userdb.install(config)

        self.acls = PlaintextAcl()
        self.acls.addAcl("port1", self.port1, self.user.gid, flags=(self.mark1 << self.shift))
        self.acls.addAcl("port2", self.port2, self.user.gid, flags=(self.mark2 << self.shift))
        self.acls.install(config)

        # Load nuauth
        config["nuauth_finalize_packet_module"] = '"mark_flag"'
        config["mark_flag_mark_shift"] = 0
        config["mark_flag_flag_shift"] = self.shift
        config["mark_flag_nbits"] = 16

        self.nuauth = Nuauth(config)
        self.iptables = Iptables()
        self.nufw = startNufw(["-m"])
        self.client = self.user.createClient()

    def tearDown(self):
        self.acls.desinstall()
        self.userdb.desinstall()
        self.nuauth.stop()
        self.iptables.flush()

    def testValid(self):
        # Connect client and filter port
        self.assert_(connectClient(self.client))
        self.iptables.filterTcp(self.port1)

        # Test connection without QoS (accept)
        self.assertEqual(connectTcp(HOST, self.port1, TIMEOUT), True)

        # Test connection with QoS (drop)
        self.iptables.command("-A POSTROUTING -t mangle -m mark --mark %s -j DROP" % self.mark1)
        self.assertEqual(connectTcp(HOST, self.port1, TIMEOUT), False)

if __name__ == "__main__":
    print "Test nuauth mark_flag module"
    main()

