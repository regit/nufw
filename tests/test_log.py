#!/usr/bin/python2.4
from unittest import TestCase, main
from sys import stderr
from common import (
    startNuauth, reloadNuauth, NUAUTH_CONF,
    createClient, connectClient)
from config import NuauthConf

class TestLog(TestCase):
    def setUp(self):
        self.config = NuauthConf(NUAUTH_CONF)
        self.config["nuauth_user_logs_module"] = '"syslog"'
        self.config["nuauth_user_session_logs_module"] = '"syslog"'
        self.config.install()
        self.nuauth = reloadNuauth()

    def tearDown(self):
        self.config.desinstall()
        reloadNuauth()

    def findLog(self, match):
        matched = False
        for line in self.nuauth.readlines():
            if match in line:
                matched = True
        return matched

    def testLogin(self):
        # Client login
        client = createClient()
        self.assert_(connectClient(client))

        # Check log output
        self.assert_(self.findLog("[nuauth] User %s connect on " % client.username))

        # Client logout
        client.stop()
        self.assert_(self.findLog("[nuauth] User %s disconnect on " % client.username))

if __name__ == "__main__":
    print "Test nuauth module 'log_syslog'"
    main()

