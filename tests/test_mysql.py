#!/usr/bin/python2.4
from unittest import TestCase, main
from common import connectClient, startNufw, retry
from logging import info
from time import time, mktime
from inl_tests.iptables import Iptables
from socket import ntohl
from filter import testAllowPort, testDisallowPort, VALID_PORT, INVALID_PORT
from datetime import datetime
from IPy import IP
import platform
from os.path import basename, realpath
from sys import argv, executable
from nuauth import Nuauth
from nuauth_conf import NuauthConf
from plaintext import USERDB, PlaintextAcl

def datetime2unix(timestamp):
    tm = timestamp.timetuple()
    return int(mktime(tm))

POSTGRESQL = False

config = NuauthConf()
if POSTGRESQL:
    import pgdb
    DB_PACKET_TABLE = config["pgsql_table_name"]
    DB_USER_TABLE = config["pgsql_users_table_name"]
    DB_SERVER = config["pgsql_server_addr"]
    DB_USER = config["pgsql_user"]
    DB_PASSWORD = config["pgsql_passwd"]
    DB_DBNAME = config["pgsql_db_name"]
else:
    import MySQLdb
    DB_PACKET_TABLE = config["mysql_table_name"]
    DB_USER_TABLE = config["mysql_users_table_name"]
    DB_SERVER = config["mysql_server_addr"]
    DB_USER = config["mysql_user"]
    DB_PASSWORD = config["mysql_passwd"]
    DB_DBNAME = config["mysql_db_name"]

OS_SYSNAME = platform.system()    # 'Linux'
OS_RELEASE = platform.release()   # '2.6.19.2-haypo'
OS_VERSION = platform.version()   # '#2 Mon Feb 5 10:55:30 CET 2007'
CLIENT_OS = "-".join( (OS_SYSNAME, OS_VERSION, OS_RELEASE) )
CLIENT_APP = realpath(executable)
LOG_PREFIX = 42
OOB_PREFIX = "%u: ACCEPT" % LOG_PREFIX

def datetime_now(delta=0):
    # Use datetime.fromtimestamp() with int(time()) to have microsecond=0
    return datetime.fromtimestamp(int(time()+delta))
def datetime_before():
    return datetime_now(-1.1)
def datetime_after():
    return datetime_now(1.1)

class MysqlLog(TestCase):
    def setUp(self):
        startNufw()
        config = NuauthConf()
        if POSTGRESQL:
            self.conn = pgdb.connect(
                host=DB_SERVER,
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_DBNAME)
            config["nuauth_user_logs_module"] = '"pgsql"'
            config["nuauth_user_session_logs_module"] = '"pgsql"'
        else:
            self.conn = MySQLdb.Connect(
                host=DB_SERVER,
                user=DB_USER,
                passwd=DB_PASSWORD,
                db=DB_DBNAME)
            config["nuauth_user_logs_module"] = '"mysql"'
            config["nuauth_user_session_logs_module"] = '"mysql"'
        self.users = USERDB
        self.user = self.users[0]
        self.acls = PlaintextAcl()
        self.acls.addAcl("web", VALID_PORT, self.user.gid, log_prefix=LOG_PREFIX)
        self.users.install(config)
        self.acls.install(config)
        self.nuauth = Nuauth(config)
        self.start_time = int(time())

    def query(self, sql):
        if POSTGRESQL:
            info("PostgreSQL query: %s" % sql)
            cursor = self.conn.cursor()
            cursor.execute(sql)
            info("PostgreSQL result: %s rows" % cursor.rowcount)
        else:
            info("MySQL query: %s" % sql)
            cursor = self.conn.cursor()
            cursor.execute(sql)
            info("MySQL result: %s rows" % cursor.rowcount)
        return cursor

    def fetchone(self, cursor):
        if POSTGRESQL:
            row = cursor.fetchone()
            info("PostgreSQL fetchone(): %s" % repr(row))
        else:
            row = cursor.fetchone()
            info("MySQL fetchone(): %s" % repr(row))
        return row

    def tearDown(self):
        # Stop nuauth
        self.nuauth.stop()
        self.conn.close()
        self.users.desinstall()
        self.acls.desinstall()

    def _login(self, sql):
        # Client login
        client = self.user.createClient()
        self.assert_(connectClient(client))
        cursor = self.query(sql)

        # Check number of rows
        self.assertEqual(cursor.rowcount, 1)

        # Read row columns
        (ip_saddr, user_id, username, os_sysname,
            os_release, os_version, end_time) = self.fetchone(cursor)
        ip_saddr = ntohl(ip_saddr) & 0xFFFFFFFF

        # Check values
        self.assertEqual(IP(ip_saddr), client.ip)
        self.assertEqual(user_id, self.user.uid)
        self.assertEqual(username, client.username)
        self.assertEqual(os_sysname, OS_SYSNAME)
        self.assertEqual(os_release, OS_RELEASE)
        self.assertEqual(os_version, OS_VERSION)
        return client

    def _logout(self, sql, client):
        # Client logout
        # Use datetime.fromtimestamp() with int(time()) to have microsecond=0
        logout_before = datetime_before()
        client.stop()

        for when in retry(timeout=2.0):
            # Get last MySQL row
            cursor = self.query(sql)

            # Check number of rows
            self.assertEqual(cursor.rowcount, 1)

            # Read row columns
            (ip_saddr, user_id, username, os_sysname,
                os_release, os_version, end_time) = self.fetchone(cursor)
            if not end_time:
                continue
            logout_after = datetime_after()

            # Check values
            self.assert_(logout_before <= end_time <= logout_after)
            break

class MysqlLogUser(MysqlLog):
    def testUserLogin(self):
        # Delete old entries in MySQL user session table
        self.query("DELETE FROM %s WHERE start_time >= FROM_UNIXTIME(%s);" \
            % (DB_USER_TABLE, self.start_time))

        sql = \
            "SELECT ip_saddr, user_id, username, " \
            "os_sysname, os_release, os_version, end_time " \
            "FROM %s WHERE start_time >= FROM_UNIXTIME(%s) " \
            "ORDER BY start_time DESC;" % (DB_USER_TABLE, self.start_time)
        client = self._login(sql)
        self._logout(sql, client)

class MysqlLogPacket(MysqlLog):
    def setUp(self):
        self.iptables = Iptables()
        MysqlLog.setUp(self)

    def tearDown(self):
        MysqlLog.tearDown(self)
        self.iptables.flush()

    def testFilter(self):
        client = self.user.createClient()
        time_before = int(time())
        timestamp_before = datetime_before()

        # Open allowed port
        testAllowPort(self, self.iptables, client)

        # Query DB
        sql = \
            "SELECT username, user_id, client_os, client_app, " \
            "tcp_dport, ip_saddr, ip_daddr, oob_time_sec, ip_protocol, " \
            "timestamp, start_timestamp, end_timestamp, oob_prefix " \
            "FROM %s WHERE timestamp >= FROM_UNIXTIME(%s) AND state=1;" \
            % (DB_PACKET_TABLE, time_before)
        cursor = self.query(sql)

        # Read result
        row = self.fetchone(cursor)
        timestamp_after = datetime_after()
        self.assertEqual(cursor.rowcount, 1)
        (username, user_id, client_os, client_app,
         tcp_dport, ip_saddr, ip_daddr, oob_time_sec, ip_protocol,
         timestamp, start_timestamp, end_timestamp, oob_prefix) = row

        # Check values
        self.assertEqual(username, client.username)
        self.assertEqual(user_id, self.user.uid)
        self.assertEqual(client_os, CLIENT_OS)
        self.assertEqual(client_app, CLIENT_APP)
        self.assertEqual(tcp_dport, VALID_PORT)
        self.assertEqual(IP(ip_saddr), client.ip)
        self.assert_(timestamp_before <= datetime.fromtimestamp(oob_time_sec) <= timestamp_after)
        self.assert_(timestamp and timestamp_before <= timestamp <= timestamp_after)
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

