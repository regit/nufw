#!/usr/bin/python2.4
from unittest import TestCase, main
from sys import stderr
from logging import info
from nuauth import Nuauth
from nuauth_conf import NuauthConf
from common import startNufw
from filter import HOST, VALID_PORT, TIMEOUT
from inl_tests.iptables import Iptables
from mysocket import connectTcp
from plaintext import PlaintextUserDB, PlaintextUser, PlaintextAcl

class TestClientAuth(TestCase):
    def setUp(self):
        self.port = VALID_PORT
        config = NuauthConf()

        # Userdb
        self.user = PlaintextUser("guest", "nopassword", 42, 42)
        self.userdb = PlaintextUserDB()
        self.userdb.addUser(self.user)
        self.userdb.install(config)

        self.acls = PlaintextAcl()
        self.acls.addAcl("web", self.port, self.user.gid)
        self.acls.install(config)

        # Load nuauth
        config["nuauth_do_ip_authentication"] = '1'
        config["nuauth_ip_authentication_module"] = '"ipauth_guest"'
        config["ipauth_guest_username"] = '"%s"' % self.user.login
        self.nuauth = Nuauth(config)
        self.iptables = Iptables()
        self.nufw = startNufw()

    def tearDown(self):
        self.acls.desinstall()
        self.userdb.desinstall()
        self.nuauth.stop()
        self.iptables.flush()

    def testValid(self):
        self.iptables.filterTcp(self.port)
        self.assertEqual(connectTcp(HOST, self.port, TIMEOUT), True)

if __name__ == "__main__":
    print "Test nuauth client authentification"
    main()

