/*
 ** Copyright(C) 2005 INL
 ** Written by Eric Leblond <regit@inl.fr>
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation, version 2 of the License.
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

/* 
 * Initialize connection to mysql server
 */
#include "nutrackd.h"
#include <mysql/mysql.h>

MYSQL* mysql_conn_init(void){
	MYSQL *ld = NULL;

	/* init connection */
	ld = mysql_init(ld);     
	if (ld == NULL) {
		if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
			g_warning("mysql init error : %s\n",strerror(errno));
		return NULL;
	}
	if (!mysql_real_connect(ld,mysql_server,mysql_user,mysql_passwd,mysql_db_name,mysql_server_port,NULL,0)) {
		if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
			g_warning("mysql connection failed : %s\n",mysql_error(ld));
		return NULL;
	}
	return ld;
}


int update_sql_table(u_int32_t src, u_int32_t dst, u_int8_t proto, u_int16_t sport, u_int16_t dport)
{
        char request[LONG_REQUEST_SIZE];
        if (snprintf(request,SHORT_REQUEST_SIZE-1,"UPDATE %s SET state=%hu,end_timestamp=FROM_UNIXTIME(%lu) WHERE (protocol=%d AND ip_saddr=%lu AND ip_daddr=%lu AND (state=1 OR state=2)",
                        mysql_table_name,
                        STATE_CLOSE,
                        timestamp,
                        proto,
                        saddr,
                        daddr) >= SHORT_REQUEST_SIZE-1)
        {
            return -1;
        }
        switch (proto){
          case IPPROTO_TCP:
            {//add port conditions
            }
          case IPPROTO_UDP:
            {//add port conditions
            }
          default :
            {//just add ")" to the request
            }
        }
        if (mysql_real_query(ld, request, strlen(request)) != 0)
        {
            //log some error
        }
}


