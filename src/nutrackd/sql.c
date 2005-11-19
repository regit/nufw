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

MYSQL *ld = NULL;


int mysql_conn_init(MYSQL *ld){

	/* init connection */
	ld = mysql_init(ld);     
	if (ld == NULL) {
                //TODO : log stuff
		return -1;
	}
	if (!mysql_real_connect(ld,
                                (*params).host,
                                (*params).user,
                                (*params).pass,
                                (*params).database,
                                (*params).port,
                                NULL,
                                0)) {
                //TODO : log stuff
		return -1;
	}
	return 0;
}

void sql_close(void)
{
  mysql_close(ld);
}


int update_sql_table(u_int32_t src, u_int32_t dst, u_int8_t proto, u_int16_t sport, u_int16_t dport)
{
        time_t timestamp;

        if (ld == NULL)
            if (mysql_conn_init(ld))
            {
                // TODO log some stuff
                return -1;
            }

        timestamp=time(NULL);
        
        char request[LONG_REQUEST_SIZE];
        if (snprintf(request,SHORT_REQUEST_SIZE-1,"UPDATE %s SET state=%u,end_timestamp=FROM_UNIXTIME(%u) WHERE (protocol=%u AND ip_saddr=%u AND ip_daddr=%u AND (state=1 OR state=2)",
                        (*params).table,
                        STATE_CLOSE,
                        timestamp,
                        proto,
                        src,
                        dst) >= LONG_REQUEST_SIZE-1)
        {
            return -1;
        }
        switch (proto){
          case IPPROTO_TCP:
            {//add port conditions
                char subreq[LONG_REQUEST_SIZE];
                if (snprintf(subreq,SHORT_REQUEST_SIZE-1,"AND sport=%u AND dport=%u)",
                        sport,
                        dport) >= LONG_REQUEST_SIZE-1)
                {
                    //never occurs
                    return -1;
                }
                if ( ( strlen(request) + strlen(subreq) ) < LONG_REQUEST_SIZE-1)
                    strcat(request,subreq);
                else
                {
                    //TODO log stuff
                    return -1;
                }

                break;
            }
          case IPPROTO_UDP:
            {//add port conditions
            }
          default :
            {//just add ")" to the request
              if ( ( strlen(request) ) < LONG_REQUEST_SIZE-2)
                  strcat(request,")");
              else
              {
                  // TODO log stuff
                  return -1;
              }

            }
        }
        if (mysql_real_query(ld, request, strlen(request)) != 0)
        {
            //TODO log some error
        }
}


