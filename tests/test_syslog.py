#!/usr/bin/python
from unittest import TestCase, main
from common import getNuauthConf, createClient, connectClient
from nuauth import Nuauth
from nuauth_conf import NuauthConf
from logging import warning

class TestLog(TestCase):
    def setUp(self):
        config = getNuauthConf()
        config["nuauth_user_logs_module"] = '"syslog"'
        config["nuauth_user_session_logs_module"] = '"syslog"'
        self.nuauth = Nuauth(config)

    def tearDown(self):
        self.nuauth.stop()

    def findLog(self, match):
        warning("Search string >%s< in log" % match)
        return self.nuauth.nuauth.waitline(match, 2.0)

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

