/* $Id: log_mysql.h,v 1.4 2004/01/13 23:19:41 gryzor Exp $ */

/*
** Copyright(C) 2003 Eric Leblond <eric@regit.org>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; version 2 of the License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include <sys/time.h>
#include <mysql/mysql.h>


#define MYSQL_SERVER "127.0.0.1"
#define MYSQL_SERVER_PORT 3306
/*#define LDAP_USER NULL
#define LDAP_CRED NULL */
#define MYSQL_USER "nufw"
#define MYSQL_PASSWD "mypassword" 
#define MYSQL_DB_NAME "nufw" 
#define MYSQL_TABLE_NAME "nufw-logs" 
#define MYSQL_REQUEST_TIMEOUT 10

//SSL options
#define MYSQL_USE_SSL 1 //use ssl by default
#define MYSQL_SSL_KEYFILE NULL
#define MYSQL_SSL_CERTFILE NULL
#define MYSQL_SSL_CA      NULL
#define MYSQL_SSL_CAPATH  NULL
#define MYSQL_SSL_CIPHER "ALL:!ADH:+RC4:@STRENGTH"

#define OSNAME_MAX_SIZE 64
#define APPNAME_MAX_SIZE 256

#define SHORT_REQUEST_SIZE 512
#define LONG_REQUEST_SIZE 1024

int mysql_request_timeout;
char * mysql_user;
char * mysql_passwd;
char * mysql_server;
char * mysql_db_name;
char * mysql_table_name;
int mysql_server_port;
int mysql_use_ssl;
char * mysql_ssl_keyfile;
char * mysql_ssl_certfile;
char * mysql_ssl_ca;
char * mysql_ssl_capath;
char * mysql_ssl_cipher;
