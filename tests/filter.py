from common import connectClient
from mysocket import connectTcp, connectTcpFail
from config import config
from socket import gethostbyname

TIMEOUT = config.getfloat("filter", "timeout")
VALID_PORT = config.getint("filter", "valid_port")
INVALID_PORT = config.getint("filter", "invalid_port")
HOST = gethostbyname(config.get("filter", "host"))

def testPortFailure(testcase, iptables, client, port, err):
    # Enable iptables filtering
    iptables.filterTcp(VALID_PORT)

    # Connect user
    if client:
        testcase.assert_(connectClient(client))

    # Create socket
    testcase.assertEqual(connectTcpFail(HOST, port, TIMEOUT), err)

def testPort(testcase, iptables, client, port, ok, host=HOST):
    # Enable iptables filtering
    iptables.filterTcp(VALID_PORT)

    # Connect user
    if client:
        testcase.assert_(connectClient(client))

    # Create socket
    testcase.assertEqual(connectTcp(host, port, TIMEOUT), ok)

def testAllowPort(testcase, iptables, client, host=HOST, allow=True):
    testPort(testcase, iptables, client, VALID_PORT, allow, host)

def testDisallowPort(testcase, iptables, client, host=HOST, allow=False):
    testPort(testcase, iptables, client, INVALID_PORT, allow, host)

