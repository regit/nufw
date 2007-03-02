#!/usr/bin/python2.4
from unittest import TestCase, main
from sys import stderr
from common import (CONF_DIR,
    startNuauth, reloadNuauth, NUAUTH_CONF,
    createClient, connectClient)
from config import NuauthConf
from os import rename, path, link, chmod
from tools import try_rename
from replace_file import ReplaceFile

ECHO_BIN = '/bin/echo'
SCRIPT_UP = path.join(CONF_DIR, "user-up.sh")
SCRIPT_DOWN = path.join(CONF_DIR, "user-down.sh")

MODE = 0111
SCRIPT = "#!/bin/sh\necho \"SCRIPT %s COUNT=$# TEXT >>>$@<<<\""

class TestLog(TestCase):
    def setUp(self):
        # Prepare our new scripts
        self.script_up = ReplaceFile(SCRIPT_UP, SCRIPT % "UP", MODE)
        self.script_down = ReplaceFile(SCRIPT_DOWN, SCRIPT % "DOWN", MODE)

        # Start nuauth with new config
        self.config = NuauthConf(NUAUTH_CONF)
        self.config["nuauth_user_session_logs_module"] = '"script"'
        self.config.install()
        self.nuauth = reloadNuauth()

    def tearDown(self):
        # Restore scripts and nuauth config
        self.script_up.desinstall()
        self.script_down.desinstall()
        self.config.desinstall()
        reloadNuauth()

    def checkScript(self, match):
        for line in self.nuauth.readlines():
            if line == match:
                return True
        return False

    def testLogin(self):
        # Install our scripts
        self.script_up.install()
        self.script_down.install()

        # Client login
        client = createClient()
        self.assert_(connectClient(client))

        # Check log output
        match = "SCRIPT UP COUNT=2 TEXT >>>%s ::ffff:127.0.0.1<<<" \
            % client.username
        self.assert_(self.checkScript(match))

        # Client logout
        client.stop()
        match = "SCRIPT DOWN COUNT=2 TEXT >>>%s ::ffff:127.0.0.1<<<" \
            % client.username
        self.assert_(self.checkScript(match))

if __name__ == "__main__":
    print "Test nuauth module 'log_script'"
    main()

