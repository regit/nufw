#!/usr/bin/python2.4
from unittest import TestCase, main
from sys import stderr
from common import startNuauth, createClient, connectClient

class TestClientAuth(TestCase):
    def setUp(self):
        # Load nuauth
        startNuauth()

        # Create client
        self.client = createClient()
        self.client.setUsername("haypo")

    def tearDown(self):
        self.client.stop()

    def testValidPass(self):
        self.client.setPassword("haypo")
        self.assert_(connectClient(self.client))

    def testInvalidPass(self):
        self.client.setPassword("xxxxx")
        self.assert_(not connectClient(self.client))

if __name__ == "__main__":
    print "Test client authentification"
    main()

