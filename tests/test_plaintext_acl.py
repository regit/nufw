#!/usr/bin/python2.4
from unittest import TestCase, main
from common import startNufw, createClient, connectClient
from nuauth import Nuauth
from nuauth_conf import NuauthConf
from inl_tests.iptables import Iptables
from filter import testAllowPort, testDisallowPort, VALID_PORT
from test_plaintext_auth import USERDB
from plaintext import PlaintextAcl

USER = USERDB[0]

class TestPlaintextAcl(TestCase):
    def setUp(self):
        self.iptables = Iptables()
        self.users = USERDB
        self.acls = PlaintextAcl()
        self.acls.addAcl("web", VALID_PORT, self.users[0].gid)
        config = NuauthConf()
        config["plaintext_userfile"] = '"%s"' % self.users.filename
        config["plaintext_aclfile"] = '"%s"' % self.acls.filename
        config["nuauth_user_check_module"] = '"plaintext"'
        config["nuauth_acl_check_module"] = '"plaintext"'

        # Start nuauth with new config
        self.users.install()
        self.acls.install()
        self.nuauth = Nuauth(config)
        self.nufw = startNufw()

    def tearDown(self):
        # Restore user DB and nuauth config
        self.users.desinstall()
        self.acls.desinstall()
        self.nuauth.stop()
        self.iptables.flush()

    def testFilter(self):
        client = createClient(USER.login, USER.password)
        testAllowPort(self, self.iptables, client)
        testDisallowPort(self, self.iptables, client)

if __name__ == "__main__":
    print "Test nuauth module 'plaintext' for ACL"
    main()

