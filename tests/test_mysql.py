#!/usr/bin/python2.4
from unittest import TestCase, main
from common import createClient, connectClient, startNufw
from logging import info
from time import time, mktime
from inl_tests.iptables import Iptables
from config import CLIENT_IP, CLIENT_USER_ID
from socket import ntohl
from filter import testAllowPort, testDisallowPort, VALID_PORT, INVALID_PORT
from datetime import datetime
from IPy import IP
import MySQLdb
import platform
from os.path import basename
from sys import argv, executable
from nuauth import Nuauth
from nuauth_conf import NuauthConf

def datetime2unix(timestamp):
    tm = timestamp.timetuple()
    return int(mktime(tm))

MYSQL_PACKET_TABLE = "ulog"
MYSQL_USER_TABLE = "users"
MYSQL_SERVER = "localhost"
MYSQL_USER = "root"
MYSQL_PASSWORD = ""
MYSQL_DB = "nufw"

OS_SYSNAME = platform.system()    # 'Linux'
OS_RELEASE = platform.release()   # '2.6.19.2-haypo'
OS_VERSION = platform.version()   # '#2 Mon Feb 5 10:55:30 CET 2007'
CLIENT_OS = "-".join( (OS_SYSNAME, OS_VERSION, OS_RELEASE) )
CLIENT_APP = executable
OOB_PREFIX = "2: ACCEPT"

class MysqlLogUser(TestCase):
    def setUp(self):
        self.conn = MySQLdb.Connect(
            host=MYSQL_SERVER,
            user=MYSQL_USER,
            passwd=MYSQL_PASSWORD,
            db=MYSQL_DB)
        startNufw()
        config = NuauthConf()
        config["nuauth_user_logs_module"] = '"mysql"'
        config["nuauth_user_session_logs_module"] = '"mysql"'
        self.nuauth = Nuauth(config)
        self.start_time = int(time())

    def query(self, sql):
        info("MySQL query: %s" % sql)
        cursor = self.conn.cursor()
        cursor.execute(sql)
        info("MySQL result: %s rows" % cursor.rowcount)
        return cursor

    def fetchone(self, cursor):
        row = cursor.fetchone()
        info("MySQL fetchone(): %s" % repr(row))
        return row

    def tearDown(self):
        # Stop nuauth
        self.nuauth.stop()

        # Delete our entry in MySQL user session table
        self.query("DELETE FROM %s WHERE start_time >= FROM_UNIXTIME(%s);" \
            % (MYSQL_USER_TABLE, self.start_time))
        self.conn.close()

    def _login(self, sql):
        # Client login
        client = createClient()
        self.assert_(connectClient(client))
        cursor = self.query(sql)

        # Check number of rows
        self.assertEqual(cursor.rowcount, 1)

        # Read row columns
        (ip_saddr, user_id, username, os_sysname,
            os_release, os_version, end_time) = self.fetchone(cursor)
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
        # Client logout
        # Use datetime.fromtimestamp() with int(time()) to have microsecond=0
        logout_before = datetime.fromtimestamp(int(time()))
        client.stop()
        logout_after = datetime.now()

        # Get last MySQL row
        cursor = self.query(sql)

        # Check number of rows
        self.assertEqual(cursor.rowcount, 1)

        # Read row columns
        (ip_saddr, user_id, username, os_sysname,
            os_release, os_version, end_time) = self.fetchone(cursor)

        # Check values
        self.assert_(logout_before <= end_time <= logout_after)

    def testUserLogin(self):
        sql = \
            "SELECT ip_saddr, user_id, username, " \
            "os_sysname, os_release, os_version, end_time " \
            "FROM %s WHERE start_time >= FROM_UNIXTIME(%s) " \
            "ORDER BY start_time DESC;" % (MYSQL_USER_TABLE, self.start_time)
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
        time_before = int(time())
        timestamp_before = datetime.now()

        # Remove old entries
        self.query("DELETE FROM %s WHERE timestamp > FROM_UNIXTIME(%s);"
            % (MYSQL_PACKET_TABLE, time_before))

        # Open allowed port
        testAllowPort(self, self.iptables, client)
        timestamp_after = datetime.now()

        # Query DB
        sql = \
            "SELECT username, user_id, client_os, client_app, " \
            "tcp_dport, ip_saddr, ip_daddr, oob_time_sec, ip_protocol, " \
            "timestamp, start_timestamp, end_timestamp, oob_prefix " \
            "FROM %s WHERE timestamp > FROM_UNIXTIME(%s);" \
            % (MYSQL_PACKET_TABLE, time_before)
        cursor = self.query(sql)

        # Read result
        row = self.fetchone(cursor)
        self.assertEqual(cursor.rowcount, 1)
        (username, user_id, client_os, client_app,
         tcp_dport, ip_saddr, ip_daddr, oob_time_sec, ip_protocol,
         timestamp, start_timestamp, end_timestamp, oob_prefix) = row
        ip_saddr = ntohl(ip_saddr) & 0xFFFFFFFF

        # Check values
        self.assertEqual(username, client.username)
        self.assertEqual(user_id, CLIENT_USER_ID)
        self.assertEqual(client_os, CLIENT_OS)
        self.assertEqual(client_app, CLIENT_APP)
        self.assertEqual(tcp_dport, VALID_PORT)
        self.assertEqual(IP(ip_saddr), IP(CLIENT_IP))
        self.assert_(timestamp_before <= datetime.fromtimestamp(oob_time_sec) <= timestamp_after)
        self.assert_(timestamp_before <= timestamp <= timestamp_after)
        self.assertEqual(ip_protocol, 6)
        self.assertEqual(oob_prefix, OOB_PREFIX)
        # TODO: Check these timestamps
#        self.assertEqual(start_timestamp, ...)
#        self.assertEqual(end_timestamp, ...)

        # TODO: Open disallowed port
 #        testDisallowPort(self, self.iptables, client)

if __name__ == "__main__":
    print "Test nuauth module 'mysql' (log)"
    main()

