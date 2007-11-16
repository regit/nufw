#!/usr/bin/python2.4
from unittest import TestCase, main
from common import createClient, connectClient, startNufw
from nuauth import Nuauth
from nuauth_conf import NuauthConf
from inl_tests.iptables import Iptables
from filter import HOST, VALID_PORT
from plaintext import USERDB, PlaintextAcl, PlainPeriodXML, Period
from IPy import IP
import time, sys, os, socket, commands, pynetfilter_conntrack 

def get_conntrack_conn(src_port, dest, port_dest):
    if pynetfilter_conntrack.__revision__ == '0.4.2':
        nf = pynetfilter_conntrack.Conntrack()
        table = nf.dump_table(socket.AF_INET)
        conn_list = []
        for conn in table:
            if src_port == conn.orig_port_src and IP(dest) == IP(conn.orig_ipv4_dst):
                conn_list.append(str(conn))
        return conn_list
    else:
        nf = pynetfilter_conntrack.NetfilterConntrack(pynetfilter_conntrack.CONNTRACK)
        table = nf.create_table(socket.AF_INET)
        table = table.filter(6, orig_dst = IP(dest), orig_dst_port = VALID_PORT, orig_src_port = src_port)
        return table

class TestConntrack(TestCase):
    def setUp(self):
	self.dst_host = socket.gethostbyname(HOST)

        self.config = NuauthConf()
        self.acls = PlaintextAcl()
        self.acls.addAclFull("web", self.dst_host, VALID_PORT, USERDB[0].gid, 1, period='10 secs' )
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
	self.iptables.command('-I OUTPUT -d %s -p tcp --dport 80 --syn -m state --state NEW -j NFQUEUE' % self.dst_host)
	self.iptables.command('-I OUTPUT -d %s -p tcp --dport 80 ! --syn -m state --state NEW -j DROP' % self.dst_host)

    def tearDown(self):
        self.nuauth.stop()
        self.users.desinstall()
	self.acls.desinstall()
	self.period.desinstall()

    def testConnShutdown(self):
        user = USERDB[0]
        client = user.createClient()
        self.assert_(connectClient(client))

        start = time.time()
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((self.dst_host, VALID_PORT))

	src_port = conn.getsockname()[1]

	ct_before = len(get_conntrack_conn(src_port, self.dst_host, VALID_PORT))
	## Check that only one connection is opened to
	self.assert_(ct_before == 1)

	## The connection should be killed 10 seconds after being opened
	time.sleep(15)

	## Check that only one connection is opened to
	ct_after = len(get_conntrack_conn(src_port, self.dst_host, VALID_PORT))
	self.assert_(ct_after == 0)

	conn.close()
        client.stop()

if __name__ == "__main__":
    print "Test conntrack functionnalities"
    main()

