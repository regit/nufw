#!/usr/bin/python2.4
from unittest import TestCase, main
from common import reloadNuauth, getNuauthConf, createClient, connectClient
from time import time
from common import CLIENT_IP, CLIENT_USER_ID
from socket import ntohl
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

        first_time = int(time())

        # Client login
        client = createClient()
        self.assert_(connectClient(client))

        # Get last MySQL row
        print first_time
        SQL = \
            "SELECT ip_saddr, user_id, username, " \
            "os_sysname, os_release, os_version " \
            "FROM %s WHERE start_time >= FROM_UNIXTIME(%s) " \
            "ORDER BY start_time DESC;" % (MYSQL_USER_TABLE, first_time)
        print SQL
        cursor.execute(SQL)

        # Check number of rows
        self.assertEqual(cursor.rowcount, 1)

        # Read read
        ip_saddr, user_id, username, os_sysname, os_release, os_version = cursor.fetchone()

        # Check values
#        self.assertEqual(IP(ntohl(ip_saddr)), IP(CLIENT_IP))
        self.assertEqual(user_id, CLIENT_USER_ID)
        self.assertEqual(username, client.username)
        self.assertEqual(os_sysname, OS_SYSNAME)
        self.assertEqual(os_release, OS_RELEASE)
        self.assertEqual(os_version, OS_VERSION)

#        # Client logout
#        client.stop()
#        self.assert_(self.findLog("[nuauth] User %s disconnect on " % client.username))

if __name__ == "__main__":
    print "Test nuauth module 'mysql' (log)"
    main()

