#!/usr/bin/python
from unittest import TestCase, main
from common import startNufw, connectClient
from nuauth import Nuauth
from nuauth_conf import NuauthConf
from inl_tests.iptables import Iptables
from filter import testAllowPort, testDisallowPort, VALID_PORT, HOST
from test_plaintext_auth import USERDB
from sys import executable
from os import uname
from os.path import realpath

APPLICATION = realpath(executable)
OS = uname()
OS_NAME = OS[0]
OS_FULL = "%s;%s;%s" % (OS[0], OS[2], OS[3])

class TestAcl(object):
    def setUp(self):
        self.iptables = Iptables()
        self.users = USERDB
        self.host = HOST
        self.config = NuauthConf()
        self.acls = self.func_acls()

        # Start nuauth with new config
        self.users.install(self.config)
        self.nufw = startNufw()

    def tearDown(self):
        # Restore user DB and nuauth config
        self.users.desinstall()
        self.nuauth.stop()
        self.iptables.flush()
        self.acls.desinstall()

    def testFilterByGroup(self):
        self.acls.addAclFull("Web group", self.host, VALID_PORT, self.users[0].gid)
        self.acls.install(self.config)
        self.nuauth = Nuauth(self.config)
        user = self.users[0]
        client = user.createClient()
        testAllowPort(self, self.iptables, client, self.host)
        testDisallowPort(self, self.iptables, client, self.host)
        self.acls.desinstall()

    def testFilterByUser(self):
        self.acls.addAclPerUid("Web user", self.host, VALID_PORT, self.users[0].uid)
        self.acls.install(self.config)
        self.nuauth = Nuauth(self.config)
        user = self.users[0]
        client = user.createClient()
        testAllowPort(self, self.iptables, client, self.host)
        testDisallowPort(self, self.iptables, client, self.host)
        self.acls.desinstall()

    def testValidApplication(self):
        self.acls.addAclFull("application", self.host, VALID_PORT, self.users[0].gid, App=APPLICATION)
        self.acls.install(self.config)
        self.nuauth = Nuauth(self.config)
        user = self.users[0]
        client = user.createClient()
        testAllowPort(self, self.iptables, client, self.host)
        self.acls.desinstall()

    def testInvalidApplication(self):
        self.acls.addAclFull("application", self.host, VALID_PORT, self.users[0].gid, App=APPLICATION+"xxx")
        self.acls.install(self.config)
        self.nuauth = Nuauth(self.config)
        user = self.users[0]
        client = user.createClient()
        testAllowPort(self, self.iptables, client, self.host, allow=False)
        self.acls.desinstall()

    def testValidOS(self):
        self.acls.addAclFull("application", self.host, VALID_PORT, self.users[0].gid, OS=OS_FULL)
        self.acls.install(self.config)
        self.nuauth = Nuauth(self.config)
        user = self.users[0]
        client = user.createClient()
        testAllowPort(self, self.iptables, client, self.host)
        self.acls.desinstall()

    def testInvalidOS(self):
        self.acls.addAclFull("application", self.host, VALID_PORT, self.users[0].gid, OS=OS_NAME+"xxx")
        self.acls.install(self.config)
        self.nuauth = Nuauth(self.config)
        user = self.users[0]
        client = user.createClient()
        testAllowPort(self, self.iptables, client, self.host, allow=False)
        self.acls.desinstall()

    def testQualityOk(self):
        self.acls.addAclFull("auth quality", self.host, VALID_PORT, self.users[0].gid, authquality = 1)
        self.acls.install(self.config)
        self.nuauth = Nuauth(self.config)
        user = self.users[0]
        client = user.createClient()
        testAllowPort(self, self.iptables, client, self.host)
        self.acls.desinstall()

    def testQualityNOK(self):
        self.acls.addAclFull("auth quality", self.host, VALID_PORT, self.users[0].gid, authquality = 4)
        self.acls.install(self.config)
        self.nuauth = Nuauth(self.config)
        user = self.users[0]
        client = user.createClient()
        testAllowPort(self, self.iptables, client, self.host, allow=False)
        self.acls.desinstall()

