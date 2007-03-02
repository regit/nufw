#!/usr/bin/python2.4
from unittest import TestCase, main
from sys import stderr
from common import (
    startNuauth, reloadNuauth, NUAUTH_CONF,
    createClient, connectClient)
from config import NuauthConf

SYSLOG = '/var/log/syslog'

class TestLog(TestCase):
    def setUp(self):
        self.config = NuauthConf(NUAUTH_CONF)
        self.config["nuauth_user_logs_module"] = '"syslog"'
        self.config["nuauth_user_session_logs_module"] = '"syslog"'
        self.config.install()
        self.nuauth = reloadNuauth()

    def tearDown(self):
        self.config.desinstall()
        #reloadNuauth()

    def testLogin(self):
        # Eat output
        while self.nuauth.readline():
            pass

        # Connect client
        client = createClient()
        client.username = "haypo"
        client.password = "haypo"

        self.assert_(connectClient(client))
        client.stop()

        # Check output
        matched = 0
        match_login = "[nuauth] User %s connect on " % client.username
        match_logout = "[nuauth] User %s disconnect on " % client.username
        while True:
            line = self.nuauth.readline()
            if not line:
                break
            line = line.rstrip()
            if match_login in line:
                matched += 1
            elif match_logout in line:
                matched += 1

if __name__ == "__main__":
    print "Test client authentification"
    main()

