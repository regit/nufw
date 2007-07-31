#!/usr/bin/python
from unittest import TestSuite, TestResult, TestLoader, TextTestRunner, TestCase
from imp import load_source
from os import getuid
from sys import exit, stderr
from random import randint, shuffle

FILES = (
    "test_client_auth",
    "test_plaintext_acl",
    "test_plaintext_auth",
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

    runner = TextTestRunner(descriptions=2, verbosity=2)
    result = runner.run(suite)
    if result.failures or result.errors:
        exit(1)

if __name__ == "__main__":
    main()

