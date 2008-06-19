#!/usr/bin/python2.5
from unittest import TestCase, main
from test_acl import TestAcl
from ldapacl import LDAPAcl

class TestLDAPAcl(TestAcl, TestCase):
    def func_acls(self):
        return LDAPAcl()

if __name__ == "__main__":
    print "Test nuauth module 'ldap' for ACL"
    main()

