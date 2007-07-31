from common import connectClient
from mysocket import connectTcp, connectTcpFail
from config import config

TIMEOUT = config.getfloat("filter", "timeout")
VALID_PORT = config.getint("filter", "valid_port")
INVALID_PORT = config.getint("filter", "invalid_port")
HOST = config.get("filter", "host")

def testPortFailure(testcase, iptables, client, port, err):
    # Enable iptables filtering
    iptables.filterTcp(VALID_PORT)

    # Connect user
    if (client != None):
    	testcase.assert_(connectClient(client))

    # Create socket
    testcase.assertEqual(connectTcpFail(HOST, port, TIMEOUT), err)


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

