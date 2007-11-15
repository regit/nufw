#!/usr/bin/python2.4
from unittest import TestCase, main
from common import createClient, connectClient, startNufw
from nuauth import Nuauth
from nuauth_conf import NuauthConf
from inl_tests.iptables import Iptables
from filter import HOST, VALID_PORT
from plaintext import USERDB, PlaintextAcl, PlainPeriodXML, Period
from pynetfilter_conntrack import NetfilterConntrack, CONNTRACK
from IPy import IP
import time, sys, os, socket, commands

def get_conntrack_conn(src_port, dest, port_dest):
	nf = NetfilterConntrack(CONNTRACK)
	table = nf.create_table(socket.AF_INET)
	table = table.filter(6, orig_dst = IP(HOST), orig_dst_port = VALID_PORT, orig_src_port = src_port)
	return table

class TestConntrack(TestCase):
    def setUp(self):
        self.config = NuauthConf()
	self.config["xml_defs_periodfile"] = "/etc/nufw/periods.xml"
        self.acls = PlaintextAcl()
        self.acls.addAclFull("web", HOST, VALID_PORT, USERDB[0].gid, 1, period='10 secs' )
        self.acls.install(self.config)

	self.period = PlainPeriodXML()
	self.period.addPeriod(Period("10 secs", duration = 10))
	self.period.install(self.config)

        self.users = USERDB
        self.users.install(self.config)
        self.nuauth = Nuauth(self.config)
	self.nufw = startNufw()

	self.iptables = Iptables()
	self.iptables.flush()
	self.iptables.command('-I OUTPUT -d %s -p tcp --dport 80 --syn -m state --state NEW -j NFQUEUE' % HOST)
	self.iptables.command('-I OUTPUT -d %s -p tcp --dport 80 ! --syn -m state --state NEW -j DROP' % HOST)

    def tearDown(self):
        self.nuauth.stop()
        self.users.desinstall()
	self.acls.desinstall()

    def testConnShutdown(self):
        user = USERDB[0]
        client = user.createClient()
        self.assert_(connectClient(client))

        start = time.time()
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((HOST, VALID_PORT))

	src_port = conn.getsockname()[1]

	ct_before = len(get_conntrack_conn(src_port, HOST, VALID_PORT))
	## Check that only one connection is opened to
	self.assert_(ct_before == 1)

	## The connection should be killed 10 seconds after being opened
	time.sleep(15)

	## Check that only one connection is opened to
	ct_after = len(get_conntrack_conn(0, HOST, VALID_PORT))
	self.assert_(ct_after == 0)

	conn.close()
        client.stop()

if __name__ == "__main__":
    print "Test conntrack functionnalities"
    main()

