#!/usr/bin/python2.4
from unittest import TestCase, main
from common import reloadNuauth, getNuauthConf, createClient, connectClient
from time import time
from common import CLIENT_IP, CLIENT_USER_ID
from socket import ntohl
from datetime import datetime
from IPy import IP
import MySQLdb
import platform

MYSQL_USER_TABLE = "users"
MYSQL_SERVER = "localhost"
MYSQL_USER = "root"
MYSQL_PASSWORD = ""
MYSQL_DB = "nufw"

OS_SYSNAME = platform.system()    # 'Linux'
OS_RELEASE = platform.release()   # '2.6.19.2-haypo'
OS_VERSION = platform.version()   # '#2 Mon Feb 5 10:55:30 CET 2007'

class TestMysqlLog(TestCase):
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

    def findLog(self, match):
        matched = False
        for line in self.nuauth.readlines():
            if match in line:
                matched = True
        return matched

    def testLogin(self):
        cursor = self.conn.cursor()
        start_time = int(time())

        # --- Login ---

        # Client login
        client = createClient()
        self.assert_(connectClient(client))

        # Get last MySQL row
        SQL = \
            "SELECT ip_saddr, user_id, username, " \
            "os_sysname, os_release, os_version, end_time " \
            "FROM %s WHERE start_time >= FROM_UNIXTIME(%s) " \
            "ORDER BY start_time DESC;" % (MYSQL_USER_TABLE, start_time)
        cursor.execute(SQL)

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

        # --- Logout ---

        # Client logout
        # Use datetime.fromtimestamp() with int(time()) to have microsecond=0
        logout_before = datetime.fromtimestamp(int(time()))
        client.stop()
        logout_after = datetime.now()

        # Get last MySQL row
        cursor.execute(SQL)

        # Check number of rows
        self.assertEqual(cursor.rowcount, 1)

        # Read row columns
        (ip_saddr, user_id, username, os_sysname,
            os_release, os_version, end_time) = cursor.fetchone()

        # Check values
        self.assert_(logout_before <= end_time <= logout_after)

if __name__ == "__main__":
    print "Test nuauth module 'mysql' (log)"
    main()

