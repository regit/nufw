#!/usr/bin/python2.4
from unittest import TestCase, main
from config import CONF_DIR
from common import createClient, connectClient
from nuauth import Nuauth
from nuauth_conf import NuauthConf
from os import path
from inl_tests.replace_file import ReplaceFile

class PlaintextUser:
    def __init__(self, login, password, uid, gid):
        self.login = login
        self.password = password
        self.uid = uid
        self.gid = gid

    def __str__(self):
        return "%s:%s:%u:%u" % (self.login, self.password, self.uid, self.gid)

class PlaintextUserDB:
    def __init__(self):
        self.filename = path.join(CONF_DIR, "users.nufw")
        self.users = []
        self.replace = None

    def addUser(self, user):
        self.users.append(user)

    def install(self):
        text = []
        for user in self.users:
            text.append(str(user))
        text = "\n".join(text)+"\n"
        self.replace = ReplaceFile(self.filename, text)
        self.replace.install()

    def desinstall(self):
        if self.replace:
            self.replace.desinstall()

    def __getitem__(self, key):
        return self.users[key]

USERDB = PlaintextUserDB()
USERDB.addUser( PlaintextUser("username", "password", 42, 42) )
USERDB.addUser( PlaintextUser("username2", "password2", 43, 43) )

class TestPlaintextAuth(TestCase):
    def setUp(self):
        # Setup our user DB
        self.users = USERDB
        self.users.install()

        # Start nuauth with our config
        config = NuauthConf()
        config["plaintext_userfile"] = '"%s"' % self.users.filename
        config["nuauth_user_check_module"] = '"plaintext"'
        self.nuauth = Nuauth(config)

    def tearDown(self):
        # Restore user DB and nuauth config
        self.nuauth.stop()
        self.users.desinstall()

    def testUser1(self):
        user = USERDB[0]
        client = createClient(user.login, user.password)
        self.assert_(connectClient(client))
        client.stop()

    def testUser2(self):
        user = USERDB[1]
        client = createClient(user.login, user.password)
        self.assert_(connectClient(client))
        client.stop()

    def testInvalidLogin(self):
        user = USERDB[0]
        client = createClient(user.login+"x", user.password)
        self.assert_(not connectClient(client))
        client.stop()

    def testInvalidPass(self):
        user = USERDB[1]
        client = createClient(user.login, user.password+"x")
        self.assert_(not connectClient(client))
        client.stop()

if __name__ == "__main__":
    print "Test nuauth module 'plaintext' for AUTH"
    main()

