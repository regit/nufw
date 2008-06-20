#!/usr/bin/python
from unittest import TestCase, main
from test_acl import TestAcl
from plaintext import PlaintextAcl

class TestPlaintextAcl(TestAcl, TestCase):
    def func_acls(self):
        return PlaintextAcl()

if __name__ == "__main__":
    print "Test nuauth module 'plaintext' for ACL"
    main()

