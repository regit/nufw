#!/usr/bin/python2.4
from unittest import TestCase, main
from common import reloadNuauth, getNuauthConf, createClient, connectClient
from time import time
from iptables import Iptables
from common import CLIENT_IP, CLIENT_USER_ID
from socket import ntohl
from filter import testAllowPort, testDisallowPort, VALID_PORT, INVALID_PORT
from datetime import datetime
from socket import AF_INET
from IPy import IP
import MySQLdb
import platform
from os.path import basename
from sys import argv

MYSQL_PACKET_TABLE = "ulog"
MYSQL_USER_TABLE = "users"
MYSQL_SERVER = "localhost"
MYSQL_USER = "root"
MYSQL_PASSWORD = ""
MYSQL_DB = "nufw"

OS_SYSNAME = platform.system()    # 'Linux'
OS_RELEASE = platform.release()   # '2.6.19.2-haypo'
OS_VERSION = platform.version()   # '#2 Mon Feb 5 10:55:30 CET 2007'
CLIENT_OS = " ".join( (OS_SYSNAME, OS_RELEASE, OS_VERSION) )
CLIENT_APP = basename(argv[0])

class MysqlLogUser(TestCase):
    def setUp(self):
        self.conn = MySQLdb.Connect(
            host=MYSQL_SERVER,
            user=MYSQL_USER,
            passwd=MYSQL_PASSWORD,
            db=MYSQL_DB)
        self.config = getNuauthConf()
        self.config["nuauth_user_logs_module"] = '"mysql"'
        self.config["nuauth_user_session_logs_module"] = '"mysql"'
        self.config.install()
        self.nuauth = reloadNuauth()

    def tearDown(self):
        self.config.desinstall()
        reloadNuauth()
        self.conn.close()

    def _login(self, sql):
        cursor = self.conn.cursor()

        # Client login
        client = createClient()
        self.assert_(connectClient(client))
        cursor.execute(sql)

        # Check number of rows
        self.assertEqual(cursor.rowcount, 1)

        # Read row columns
        (ip_saddr, user_id, username, os_sysname,
            os_release, os_version, end_time) = cursor.fetchone()
        ip_saddr = ntohl(ip_saddr) & 0xFFFFFFFF

        # Check values
        self.assertEqual(IP(ip_saddr), IP(CLIENT_IP))
        self.assertEqual(user_id, CLIENT_USER_ID)
        self.assertEqual(username, client.username)
        self.assertEqual(os_sysname, OS_SYSNAME)
        self.assertEqual(os_release, OS_RELEASE)
        self.assertEqual(os_version, OS_VERSION)
        return client

    def _logout(self, sql, client):
        cursor = self.conn.cursor()

        # Client logout
        # Use datetime.fromtimestamp() with int(time()) to have microsecond=0
        logout_before = datetime.fromtimestamp(int(time()))
        client.stop()
        logout_after = datetime.now()

        # Get last MySQL row
        cursor.execute(sql)

        # Check number of rows
        self.assertEqual(cursor.rowcount, 1)

        # Read row columns
        (ip_saddr, user_id, username, os_sysname,
            os_release, os_version, end_time) = cursor.fetchone()

        # Check values
        self.assert_(logout_before <= end_time <= logout_after)

    def testUserLogin(self):
        start_time = int(time())
        sql = \
            "SELECT ip_saddr, user_id, username, " \
            "os_sysname, os_release, os_version, end_time " \
            "FROM %s WHERE start_time >= FROM_UNIXTIME(%s) " \
            "ORDER BY start_time DESC;" % (MYSQL_USER_TABLE, start_time)
        client = self._login(sql)
        self._logout(sql, client)

class MysqlLogPacket(MysqlLogUser):
    def setUp(self):
        self.iptables = Iptables()
        MysqlLogUser.setUp(self)

    def tearDown(self):
        MysqlLogUser.tearDown(self)
        self.iptables.flush()

    def testFilter(self):
        client = createClient()
        cursor = self.conn.cursor()

        # Open allowed port
        timestamp_before = int(time())
        testAllowPort(self, self.iptables, client)
        timestamp_after = int(time())

        # Read entry in database
        sql = \
            "SELECT username, user_id, client_os, client_app, " \
            "tcp_dport, ip_saddr, ip_daddr, oob_time_sec, ip_protocol, " \
            "timestamp, start_timestamp, end_timestamp, oob_prefix " \
            "FROM %s WHERE timestamp > from_unixtime(%s);" \
            % (MYSQL_PACKET_TABLE, timestamp_before)
        cursor.execute(sql)
        self.assertEqual(cursor.rowcount, 1)
        (username, user_id, client_os, client_app,
         tcp_dport, ip_saddr, oob_time_sec, ip_protocol,
         timestamp, start_timestamp, end_timestamp, oob_prefix) = cursor.fetchone()
        ip_saddr = ntohl(ip_saddr) & 0xFFFFFFFF

        # Check values
        self.assertEqual(username, client.username)
        self.assertEqual(user_id, CLIENT_USER_ID)
        self.assertEqual(client_os, CLIENT_OS)
        self.assertEqual(client_app, CLIENT_APP)
        self.assertEqual(tcp_dport, VALID_PORT)
        self.assertEqual(ip_saddr, IP(CLIENT_IP))
        self.assert_(timestamp_before <= oob_time_sec <= timestamp_after)
        self.assertEqual(oob_time_sec, timestamp)
        self.assertEqual(ip_protocol, AF_INET)
#        self.assertEqual(start_timestamp, ...)
#        self.assertEqual(end_timestamp, ...)
        self.assertEqual(oob_prefix, "Default: ACCEPT")

        # Open disallowed port
 #        testDisallowPort(self, self.iptables, client)

if __name__ == "__main__":
    print "Test nuauth module 'mysql' (log)"
    main()

