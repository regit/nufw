from common import connectClient
from mysocket import connectTcp

TIMEOUT = 3.0
VALID_PORT = 80
INVALID_PORT = 90
HOST = "www.google.com"

def testPort(testcase, iptables, client, port, ok):
    # Enable iptables filtering
    iptables.filterTcp(VALID_PORT)

    # Connect user
    testcase.assert_(connectClient(client))

    # Create socket
    testcase.assertEqual(connectTcp(HOST, port, TIMEOUT), ok)

def testAllowPort(testcase, iptables, client):
    testPort(testcase, iptables, client, VALID_PORT, True)

def testDisallowPort(testcase, iptables, client):
    testPort(testcase, iptables, client, INVALID_PORT, False)

