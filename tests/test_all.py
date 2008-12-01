#!/usr/bin/python
from unittest import TestSuite, TestResult, TestLoader, TestCase
from imp import load_source
from os import getuid
from sys import exit, stderr
from random import randint, shuffle
from nufw_runner import NuFWTestRunner

FILES = (
    "test_client_auth",
    "test_plaintext_acl",
    "test_plaintext_auth",
    "test_ldap_acl",
    "test_script",
    "test_syslog",
    "test_mysql",
    "test_system",
    "test_user_policy",
    "test_client_cert",
    "test_ipauth_guest",
    "test_nufw_cert",
    "test_cert_auth",
    "test_mark_flag",
    "test_reject",
    "test_periods",
    "test_session_expire",
    "test_invalid_tcp",
    "test_session_authtype",
    "test_tls_client",
    "test_tls_nuauth",
    "test_tls_nufw",
)

def loadTestcases(module):
    for attrname in dir(module):
        attr = getattr(module, attrname)
        if isinstance(attr, type) \
        and issubclass(attr, TestCase) and attr != TestCase:
                yield attr

def loadTests(loader):
    for filepy in FILES:
        module = load_source(filepy, filepy+".py")
        for testcase in loadTestcases(module):
            yield loader(testcase)

def main():
    if getuid() != 0:
        print >>stderr, "Tests have to be run with root priviledges"
        exit(1)

    loader = TestLoader()
    suite = TestSuite()
    tests = list(loadTests(loader.loadTestsFromTestCase))
    shuffle(tests)
    for test in tests:
        suite.addTests(test)

    runner = NuFWTestRunner(descriptions=2, verbosity=2)
    result = runner.run(suite)
    if result.failures or result.errors:
        exit(1)

if __name__ == "__main__":
    main()

