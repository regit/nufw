#!/usr/bin/python2.4
from unittest import TestCase, main
from sys import stderr
from common import startNuauth, createClient, connectClient, PASSWORD

class TestClientAuth(TestCase):
    def setUp(self):
        # Load nuauth
        startNuauth()

        # Create client
        self.client = createClient()

    def tearDown(self):
        self.client.stop()

    def testValidPass(self):
        self.client.password = PASSWORD
        self.assert_(connectClient(self.client))

    def testInvalidPass(self):
        self.client.password = "xxx%sxxx" % PASSWORD
        self.assert_(not connectClient(self.client))

if __name__ == "__main__":
    print "Test client authentification"
    main()

