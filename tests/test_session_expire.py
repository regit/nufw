#!/usr/bin/python2.4
from compatibility import any
from unittest import TestCase, main
from common import createClient, startNufw, connectClient
from inl_tests.iptables import Iptables
from config import USERNAME, PASSWORD
from nuauth import Nuauth
from nuauth_conf import NuauthConf
from plaintext import PlaintextUserDB, PlaintextUser, PlaintextAcl
from time import sleep
from filter import testAllowPort, VALID_PORT, HOST
from mysocket import connectTcp

DELAY = 1.0
TIMEOUT = 2.0

class TestSessionExpire(TestCase):
    def setUp(self):
        self.expiration = 1
        self.host = HOST

        # Setup session_expire library
        nuconfig = NuauthConf()
        nuconfig['nuauth_user_session_modify_module']='"session_expire"'
        nuconfig['nuauth_session_duration'] = str(self.expiration)

        # Install temporary user database
        self.userdb = PlaintextUserDB()
        self.userdb.addUser( PlaintextUser(USERNAME, PASSWORD, 42, 42) )
        self.userdb.install(nuconfig)
        self.acls = PlaintextAcl()
        self.acls.addAclFull("Web group", self.host, VALID_PORT, self.userdb[0].gid)
        self.acls.install(nuconfig)

        # Start nuauth
        self.nuauth = Nuauth(nuconfig)
        self.nufw = startNufw()
        self.iptables = Iptables()

        # Create client
        self.client = createClient()

    def tearDown(self):
        self.client.stop()
        self.acls.desinstall()
        self.nuauth.stop()

    def testExpire(self):
        self.assert_(connectClient(self.client))
        if True:
            self.iptables.filterTcp(VALID_PORT)
            connectTcp(self.host, VALID_PORT, 0.5)
        else:
            testAllowPort(self, self.iptables, None, self.host)

        self.userdb.users = []
        self.userdb.install(self.nuauth.conf)
        self.nuauth.installConf()
        self.nuauth.reload()
        sleep(self.expiration+DELAY)

        connectTcp(self.host, VALID_PORT, 0.5)
        self.assert_(any("Session not connected" in line
            for line in self.client.readlines(total_timeout=TIMEOUT)))

if __name__ == "__main__":
    print "Test nuauth client authentification"
    main()

