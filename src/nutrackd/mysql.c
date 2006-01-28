/*
 ** Copyright(C) 2005 INL
 ** Written by Eric Leblond <regit@inl.fr>
 **            Vincent Deffontaines <gryzor@inl.fr>
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


MYSQL * mysql_conn_init(){

    /* init connection */
    ld = mysql_init(NULL);     
    if (ld == NULL) {
        //TODO : log stuff
        return 0;
    }
    if (!mysql_options(ld,MYSQL_OPT_CONNECT_TIMEOUT,params->timeout))
        syslog(LOG_NOTICE,"mysql_options : having trouble when setting timeout");
    if (!mysql_real_connect(ld,
          params->host,
          params->user,
          params->pass,
          params->database,
          params->port,
          NULL,
          0)) {
        //TODO : log stuff
        syslog(LOG_NOTICE,"Cannot init SQL with params : %s,%s,%s,%s,%d",params->host,params->user,params->pass,params->database,params->port);
        return NULL;
    }
    return ld;
}

void sql_close(void)
{
  mysql_close(ld);
}


int update_sql_table(u_int32_t src, u_int32_t dst, u_int8_t proto, u_int16_t sport, u_int16_t dport)
{
  time_t timestamp;
  //        printf ("sport %u\n",ntohs(sport));
  //        printf ("dport %u\n",ntohs(dport));
  //        return 0;

  if ((proto == IPPROTO_TCP )||(proto == IPPROTO_UDP)){
      char request[LONG_REQUEST_SIZE];
      char* prefix;
      
      memset((void*)request,0,LONG_REQUEST_SIZE);

      if (ld == NULL){
               ld = mysql_conn_init();
          if (! ld)
          {
              if (log_level > 2)
                  syslog(LOG_NOTICE,"Cannot init SQL connection!");
              return -1;
          }
      }

      timestamp=time(NULL);

      switch(proto){
        case IPPROTO_TCP:
          prefix="tcp";
          break;
        case IPPROTO_UDP:
          prefix="udp";
      }
      if (snprintf(request,SHORT_REQUEST_SIZE-1,"UPDATE %s SET state=%u,end_timestamp=FROM_UNIXTIME(%u) WHERE ip_protocol=%u AND ip_saddr=%u AND ip_daddr=%u AND (state=1 OR state=2) AND %s_sport=%u AND %s_dport=%u ",
            params->table,
            STATE_CLOSE,
            timestamp,
            proto,
            ntohl(src),
            ntohl(dst),
            prefix,
            ntohs(sport),
            prefix,
            ntohs(dport)) >= LONG_REQUEST_SIZE-1) {
          return -1;
      }

      if (mysql_real_query(ld, request, strlen(request)) != 0) {
          if (log_level > 2){
              syslog(LOG_ERR,"SQL query failed : %s",mysql_errno(ld));
          }
        return 1;
      }else{
        return 0;
      }
  } else {
      return 0;
  }
}


