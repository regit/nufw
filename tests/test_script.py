#!/usr/bin/python2.4
from unittest import TestCase, main
from config import CONF_DIR, NUAUTH_VERSION
from common import createClient, connectClient
from os import path
from inl_tests.replace_file import ReplaceFile
from logging import warning
from nuauth import Nuauth
from nuauth_conf import NuauthConf

ECHO_BIN = '/bin/echo'
SCRIPT_UP = path.join(CONF_DIR, "user-up.sh")
SCRIPT_DOWN = path.join(CONF_DIR, "user-down.sh")

MODE = 0111
SCRIPT = "#!/bin/sh\necho \"SCRIPT %s COUNT=$# TEXT >>>$@<<<\"\n"

class TestScript(TestCase):
    def setUp(self):
        # Prepare our new scripts
        self.script_up = ReplaceFile(SCRIPT_UP, SCRIPT % "UP", MODE)
        self.script_down = ReplaceFile(SCRIPT_DOWN, SCRIPT % "DOWN", MODE)
        self.script_up.install()
        self.script_down.install()

        # Create nuauth
        config = NuauthConf()
        config["nuauth_user_session_logs_module"] = '"script"'
        self.nuauth = Nuauth(config)

    def tearDown(self):
        # Restore scripts and nuauth config
        self.script_up.desinstall()
        self.script_down.desinstall()
        self.nuauth.stop()

    def checkScript(self, match):
        warning("checkScript(%r)" % match)
        return self.nuauth.nuauth.waitline(match, 2.0)

    def testLogin(self):
        # Client login
        client = createClient()
        self.assert_(connectClient(client))

        # Check log output
        match = "SCRIPT UP COUNT=2 TEXT >>>%s %s<<<" \
            % (client.username, client.ip)
        self.assert_(self.checkScript(match))

        # Client logout
        client.stop()
        match = "SCRIPT DOWN COUNT=2 TEXT >>>%s %s<<<" \
            % (client.username, client.ip)
        self.assert_(self.checkScript(match))

if __name__ == "__main__":
    print "Test nuauth module 'log_script'"
    main()

