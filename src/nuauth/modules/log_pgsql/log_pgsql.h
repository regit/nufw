/* $Id: log_pgsql.h,v 1.1 2003/11/23 18:02:04 gryzor Exp $ */

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
#include <lilbpq.h>


#define PGSQL_SERVER "127.0.0.1"
#define PGSQL_SERVER_PORT 5432
/*#define LDAP_USER NULL
#define LDAP_CRED NULL */
#define PGSQL_USER "nufw"
#define PGSQL_PASSWD "mypassword" 
#define PGSQL_SSL "prefer"
#define PGSQL_DB_NAME "nufw" 
#define PGSQL_REQUEST_TIMEOUT 10

int pgsql_request_timeout;
char * pgsql_user;
char * pgsql_passwd;
char * pgsql_server;
char * pgsql_ssl;
int pgsql_server_port;
