#!/usr/bin/python2.4
from unittest import TestSuite, TestResult, TestLoader, TextTestRunner, TestCase
from imp import load_source
from test_script import TestScript
from os import getuid
from sys import exit, stderr

FILES = (
    "test_client_auth",
    "test_plaintext_acl", "test_plaintext_auth",
    "test_script", "test_log", "test_mysql_log",
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
    for test in loadTests(loader.loadTestsFromTestCase):
        suite.addTests(test)

    runner = TextTestRunner(descriptions=2, verbosity=2)
    result = runner.run(suite)
    if result.failures or result.errors:
        exit(1)

if __name__ == "__main__":
    main()

