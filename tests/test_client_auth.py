#!/usr/bin/python
from unittest import TestCase, main
from sys import stderr
from common import createClient, connectClient, PASSWORD
from logging import info
from nuauth import Nuauth

class TestClientAuth(TestCase):
    def setUp(self):
        # Load nuauth
        self.nuauth = Nuauth()

        # Create client
        self.client = createClient()

    def tearDown(self):
        self.client.stop()
        self.nuauth.stop()

    def testValidPass(self):
        self.client.password = PASSWORD
        self.assert_(connectClient(self.client))

    def testInvalidPass(self):
        self.client.password = "xxx%sxxx" % PASSWORD
        self.assert_(not connectClient(self.client))

if __name__ == "__main__":
    print "Test nuauth client authentification"
    main()

