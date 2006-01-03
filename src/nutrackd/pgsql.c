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
#include <libpq-fe.h>

PGconn *ld = NULL;


PGconn * pgsql_conn_init(){

    char *pgsql_conninfo;
    int pgsql_status; //,err,version=3;
    char port[15],timeout[15]; //,server_port[15];

    if (snprintf(port,14,"%d",params->port) >= 14){return NULL;}
    if (snprintf(timeout,14,"%d",params->timeout) >= 14){return NULL;};

    pgsql_conninfo = (char *)calloc(strlen(params->user) + strlen(params->pass) + 
        strlen(params->host) + strlen(port) + strlen(params->database) +
        strlen(timeout) +
        strlen("hostaddr='' port= dbname='' user='' password='' connect_timeout= sslmode='' ") + 1, 
        sizeof(char));
    if (pgsql_conninfo == NULL){return NULL;}
    //Build string we will pass to PQconnectdb
    strncat(pgsql_conninfo,"host='",6);
    strncat(pgsql_conninfo,params->host,strlen(params->host));
    strncat(pgsql_conninfo,"' port=",7);
    strncat(pgsql_conninfo,port,strlen(port));
    strncat(pgsql_conninfo," dbname='",9);
    strncat(pgsql_conninfo,params->database,strlen(params->database));
    strncat(pgsql_conninfo,"' user='",8);
    strncat(pgsql_conninfo,params->user,strlen(params->user));
    strncat(pgsql_conninfo,"' password='",12);
    strncat(pgsql_conninfo,params->pass,strlen(params->pass));
    strncat(pgsql_conninfo,"' connect_timeout=",18);
    strncat(pgsql_conninfo,timeout,strlen(timeout));

    ld = PQconnectdb(pgsql_conninfo);
    pgsql_status=PQstatus(ld);
    if(pgsql_status != CONNECTION_OK) {
        if (log_level > 1)
          syslog(LOG_WARNING,"Cannot init SQL connection:%s",strerror(errno));
//        syslog(LOG_DEBUG,"connection : %s",pgsql_conninfo);
        free(pgsql_conninfo);
        PQfinish(ld);
        return NULL;
    }
    free(pgsql_conninfo);
    return ld;
}

void sql_close(void)
{
  PQfinish(ld);
}


int update_sql_table(u_int32_t src, u_int32_t dst, u_int8_t proto, u_int16_t sport, u_int16_t dport)
{
  time_t timestamp;
  //        printf ("sport %u\n",ntohs(sport));
  //        printf ("dport %u\n",ntohs(dport));
  //        return 0;
  PGresult *Result;

  if ((proto == IPPROTO_TCP )||(proto == IPPROTO_UDP)){
      char request[LONG_REQUEST_SIZE];
      char* prefix=NULL;
      
      memset((void*)request,0,LONG_REQUEST_SIZE);

      if (ld == NULL){
               ld = pgsql_conn_init();
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
      if (snprintf(request,SHORT_REQUEST_SIZE-1,"UPDATE %s SET state=%u,end_timestamp=%lu WHERE ip_protocol=%u AND ip_saddr=%u AND ip_daddr=%u AND (state=1 OR state=2) AND %s_sport=%u AND %s_dport=%u ",
            params->table,
            STATE_CLOSE,
            timestamp,
            proto,
            ntohl(src),
            ntohl(dst),
            prefix,
            sport,
            //ntohs(sport),
            prefix,
            dport) >= LONG_REQUEST_SIZE-1) {
//            ntohs(dport)) >= LONG_REQUEST_SIZE-1) {
          return -1;
      }

      Result = PQexec(ld, request);
      if (!Result || PQresultStatus(Result) != PGRES_COMMAND_OK){
        if (log_level > 1)
          syslog(LOG_WARNING,"Can not update Data : %s\n",PQerrorMessage(ld));
        PQclear(Result);
        return 1;
      } else {
        PQclear(Result);
        return 0;
      }
  } else {
      return 0;
  }
}


