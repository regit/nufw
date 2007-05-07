#!/usr/bin/python2.4
from unittest import TestCase, main
from sys import stderr
from common import createClient, connectClient
from logging import info
from nuauth import Nuauth
from inl_tests.tools import createPath
from inl_tests.replace_file import TempCopyFile
from config import config
from os.path import expanduser

class TestClientAuth(TestCase):
    def setUp(self):
        orig = expanduser("~/.nufw/cacert.pem")
        cacert = config.get("test_cert", "user_cacert")

        # Create ~/.nufw/cacert.pem
        createPath(orig)
        self.cacert = TempCopyFile(orig, cacert)
        self.cacert.install()

        # Create nuauth and client
        self.nuauth = Nuauth()
        self.client = createClient()

    def tearDown(self):
        self.client.stop()
        self.nuauth.stop()
        self.cacert.desinstall()

    def testAuth(self):
        self.assert_(connectClient(self.client))

if __name__ == "__main__":
    print "Test nuauth client authentification"
    main()

