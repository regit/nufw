from unittest import TestCase, main
from sys import stderr
from common import nuauth, client

class TestClientAuth(TestCase):
    def connect(self):
        try:
            nuauth.start(False)
            try:
                client.start()
            except RuntimeError, err:
                return False
            return True
        finally:
            client.stop()

    def testValidPass(self):
        client.setUsername("haypo")
        client.setPassword("haypo")
        self.assert_(self.connect())

    def testInvalidPass(self):
        client.setUsername("haypo")
        client.setPassword("xxxxx")
        self.assert_(not self.connect())

    def __del__(self):
        nuauth.stop()
        assert not client.isRunning()

if __name__ == "__main__":
    print "Test client authentification"
    main()

