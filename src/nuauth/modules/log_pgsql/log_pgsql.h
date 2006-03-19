/* $Id: log_pgsql.h,v 1.3 2003/11/26 00:10:24 gryzor Exp $ */

/*
** Copyright(C) 2003 - 2004 Eric Leblond <eric@regit.org>
**                          Vincent Deffontaines <vincent@inl.fr>
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
#include <libpq-fe.h>


#define PGSQL_SERVER "127.0.0.1"
#define PGSQL_SERVER_PORT 5432
/*#define LDAP_USER NULL
#define LDAP_CRED NULL */
#define PGSQL_USER "nufw"
#define PGSQL_PASSWD "mypassword" 
#define PGSQL_SSL "prefer"
#define PGSQL_DB_NAME "nufw" 
#define PGSQL_REQUEST_TIMEOUT 10
#define PGSQL_TABLE_NAME "nufw_logs"

#define OSNAME_MAX_SIZE 64
#define APPNAME_MAX_SIZE 256

#define SHORT_REQUEST_SIZE 400 
#define INSERT_REQUEST_FIEDLS_SIZE 200
#define INSERT_REQUEST_VALUES_SIZE 800

struct log_pgsql_params {
    int pgsql_request_timeout;
    char * pgsql_user;
    char * pgsql_passwd;
    char * pgsql_server;
    char * pgsql_ssl;
    char * pgsql_db_name;
    char * pgsql_table_name;
    int pgsql_server_port;

    GPrivate* pgsql_priv; /* private pointer for pgsql database access */
};
