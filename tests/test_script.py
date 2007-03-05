#!/usr/bin/python2.4
from unittest import TestCase, main
from common import (CONF_DIR,
    startNuauth, reloadNuauth, getNuauthConf,
    createClient, connectClient)
from os import path
from replace_file import ReplaceFile
from logging import warning

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
        self.config = getNuauthConf()
        self.config["nuauth_user_session_logs_module"] = '"script"'

        # Start nuauth with new config
        self.config.install()
        self.script_up.install()
        self.script_down.install()
        self.nuauth = reloadNuauth()

    def tearDown(self):
        # Restore scripts and nuauth config
        self.script_up.desinstall()
        self.script_down.desinstall()
        self.config.desinstall()
        reloadNuauth()

    def checkScript(self, match):
        warning("checkScript(%r)" % match)
        for line in self.nuauth.readlines():
            if line == match:
                return True
        return False

    def testLogin(self):
        # Client login
        client = createClient()
        self.assert_(connectClient(client))

        # Check log output
        match = "SCRIPT UP COUNT=2 TEXT >>>%s ::ffff:%s<<<" \
            % (client.username, client.hostname)
        self.assert_(self.checkScript(match))

        # Client logout
        client.stop()
        match = "SCRIPT DOWN COUNT=2 TEXT >>>%s ::ffff:%s<<<" \
            % (client.username, client.hostname)
        self.assert_(self.checkScript(match))

if __name__ == "__main__":
    print "Test nuauth module 'log_script'"
    main()

