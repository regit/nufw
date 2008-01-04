#!/usr/bin/python2.4
from unittest import TestCase, main
from common import startNufw, connectClient
from nuauth import Nuauth
from nuauth_conf import NuauthConf
from inl_tests.iptables import Iptables
from filter import testPort, testAllowPort, VALID_PORT
from test_plaintext_auth import USERDB
from plaintext import PlaintextAcl
import time
import os

class TestPlaintextAcl(TestCase):
    def setUp(self):
        self.iptables = Iptables()
        self.users = USERDB
        self.config = NuauthConf()
        self.config["xml_defs_periodfile"] = '"%s"' % os.path.join(os.getcwd(),"../conf/periods.xml")
        self.acls = PlaintextAcl()

        # Start nuauth with new config
        self.users.install(self.config)
        self.nufw = startNufw()

    def tearDown(self):
        # Restore user DB and nuauth config
        self.users.desinstall()
        self.acls.desinstall()
        self.nuauth.stop()
        self.iptables.flush()

    def testPeriodDrop(self):
        self.acls.desinstall()
        self.acls = PlaintextAcl()
        if time.localtime().tm_hour >= 12:
                period = "0-12"
        else:
                period = "12-24"
        self.acls.addAcl("web", VALID_PORT, self.users[0].gid, 1, period=period )
        self.acls.install(self.config)
        self.nuauth = Nuauth(self.config)

        user = self.users[0]
        client = user.createClient()
        testPort(self, self.iptables, client, VALID_PORT, False)

        self.acls.desinstall()

    def testPeriodAccept(self):
        self.acls.desinstall()
        self.acls = PlaintextAcl()
        if time.localtime().tm_hour < 12:
                period = "0-12"
        else:
                period = "12-24"
        self.acls.addAcl("web", VALID_PORT, self.users[0].gid, 1, period=period)
        self.acls.install(self.config)
        self.nuauth = Nuauth(self.config)

        user = self.users[0]
        client = user.createClient()
        testAllowPort(self, self.iptables, client)

        self.acls.desinstall()

if __name__ == "__main__":
    print "Test nuauth module 'periods' for ACL"
    main()

