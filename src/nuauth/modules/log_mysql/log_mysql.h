/* $Id: log_mysql.h,v 1.1 2003/11/23 18:02:03 gryzor Exp $ */

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
#include <mysql.h>


#define MYSQL_SERVER "127.0.0.1"
#define MYSQL_SERVER_PORT 3306
/*#define LDAP_USER NULL
#define LDAP_CRED NULL */
#define MYSQL_USER "nufw"
#define MYSQL_PASSWD "mypassword" 
#define MYSQL_DB_NAME "nufw" 
#define MYSQL_REQUEST_TIMEOUT 10

int mysql_request_timeout;
char * mysql_user;
char * mysql_passwd;
char * mysql_server;
int mysql_server_port;
