
/*
 ** Copyright(C) 2003 Eric Leblond <eric@regit.org>
 **		     Vincent Deffontaines <vincent@gryzor.com>
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

#include <auth_srv.h>
#include <log_pgsql.h>
#include <string.h>
#include <errno.h>


confparams pgsql_nuauth_vars[] = {
    { "pgsql_server_addr" , G_TOKEN_STRING, 0 , PGSQL_SERVER },
    { "pgsql_server_port" ,G_TOKEN_INT , PGSQL_SERVER_PORT,NULL },
    { "pgsql_user" , G_TOKEN_STRING , 0 ,PGSQL_USER},
    { "pgsql_passwd" , G_TOKEN_STRING , 0 ,PGSQL_PASSWD},
    { "pgsql_ssl" , G_TOKEN_STRING , 0 ,PGSQL_SSL},
    { "pgsql_db_name" , G_TOKEN_STRING , 0 ,PGSQL_DB_NAME},
    { "pgsql_table_name" , G_TOKEN_STRING , 0 ,PGSQL_TABLE_NAME},
    { "pgsql_request_timeout" , G_TOKEN_INT , PGSQL_REQUEST_TIMEOUT , NULL }
};

/* Init pgsql system */
G_MODULE_EXPORT gchar* 
g_module_check_init(GModule *module){
    char *configfile=DEFAULT_CONF_FILE;
    gpointer vpointer; 

    /* init global variables */
    pgsql_user=PGSQL_USER;
    pgsql_passwd=PGSQL_PASSWD;
    pgsql_server=PGSQL_SERVER;
    pgsql_server_port=PGSQL_SERVER_PORT;
    pgsql_ssl=PGSQL_SSL;
    pgsql_db_name=PGSQL_DB_NAME;
    pgsql_request_timeout=PGSQL_REQUEST_TIMEOUT;

    /* parse conf file */
    parse_conffile(configfile,sizeof(pgsql_nuauth_vars)/sizeof(confparams),pgsql_nuauth_vars);
    /* set variables */
    vpointer=get_confvar_value(pgsql_nuauth_vars,sizeof(pgsql_nuauth_vars)/sizeof(confparams),"pgsql_server_addr");
    pgsql_server=(char *)(vpointer?vpointer:pgsql_server);
    vpointer=get_confvar_value(pgsql_nuauth_vars,sizeof(pgsql_nuauth_vars)/sizeof(confparams),"pgsql_server_port");
    pgsql_server_port=*(int *)(vpointer?vpointer:&pgsql_server_port);
    vpointer=get_confvar_value(pgsql_nuauth_vars,sizeof(pgsql_nuauth_vars)/sizeof(confparams),"pgsql_user");
    pgsql_user=(char *)(vpointer?vpointer:pgsql_user);
    vpointer=get_confvar_value(pgsql_nuauth_vars,sizeof(pgsql_nuauth_vars)/sizeof(confparams),"pgsql_passwd");
    pgsql_passwd=(char *)(vpointer?vpointer:pgsql_passwd);

    vpointer=get_confvar_value(pgsql_nuauth_vars,sizeof(pgsql_nuauth_vars)/sizeof(confparams),"pgsql_ssl");
    pgsql_ssl=(char *)(vpointer?vpointer:pgsql_ssl);
    vpointer=get_confvar_value(pgsql_nuauth_vars,sizeof(pgsql_nuauth_vars)/sizeof(confparams),"pgsql_db_name");
    pgsql_db_name=(char *)(vpointer?vpointer:pgsql_db_name);
    vpointer=get_confvar_value(pgsql_nuauth_vars,sizeof(pgsql_nuauth_vars)/sizeof(confparams),"pgsql_table_name");
    pgsql_table_name=(char *)(vpointer?vpointer:pgsql_table_name);
    vpointer=get_confvar_value(pgsql_nuauth_vars,sizeof(pgsql_nuauth_vars)/sizeof(confparams),"pgsql_request_timeout");
    pgsql_request_timeout=*(int *)(vpointer?vpointer:&pgsql_request_timeout);

    /* init thread private stuff */
    pgsql_priv = g_private_new (g_free);

    return NULL;
}

/* 
 * Initialize connection to pgsql server
 */

G_MODULE_EXPORT PGconn *pgsql_conn_init(void){
    PGconn *ld = NULL;
    char *pgsql_conninfo;
    int pgsql_status; //,err,version=3;
    char port[15],timeout[15],server_port[15];

    if (snprintf(port,14,"%d",pgsql_server_port) >= 14){return NULL;}
    if (snprintf(timeout,14,"%d",pgsql_request_timeout) >= 14){return NULL;};
    if (snprintf(server_port,14,"%d",pgsql_server_port) >= 14){return NULL;};

    pgsql_conninfo = (char *)calloc(strlen(pgsql_user) + strlen(pgsql_passwd) + 
        strlen(pgsql_server) + strlen(pgsql_ssl) + strlen(server_port) + strlen(pgsql_db_name) +
        strlen(port) + strlen(timeout) +
        strlen("hostaddr='' port= dbname='' user='' password='' connect_timeout= sslmode='' ") + 1, 
        sizeof(char));
    if (pgsql_conninfo == NULL){return NULL;}
    //Build string we will pass to PQconnectdb
    strncat(pgsql_conninfo,"host='",6);
    strncat(pgsql_conninfo,pgsql_server,strlen(pgsql_server));
    strncat(pgsql_conninfo,"' port=",7);
    strncat(pgsql_conninfo,port,strlen(pgsql_conninfo));
    strncat(pgsql_conninfo," dbname='",9);
    strncat(pgsql_conninfo,pgsql_db_name,strlen(pgsql_db_name));
    strncat(pgsql_conninfo,"' user='",8);
    strncat(pgsql_conninfo,pgsql_user,strlen(pgsql_user));
    strncat(pgsql_conninfo,"' password='",12);
    strncat(pgsql_conninfo,pgsql_passwd,strlen(pgsql_passwd));
    strncat(pgsql_conninfo,"' connect_timeout=",18);
    strncat(pgsql_conninfo,timeout,strlen(timeout));
    /* strcat(pgsql_conninfo," sslmode='");
       strcat(pgsql_conninfo,pgsql_ssl); 
       strcat(pgsql_conninfo,"'"); */
    /* init connection */
    if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN))
        g_message("Going to init pgsql connection ");

    ld = PQconnectdb(pgsql_conninfo);

    if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN))
        g_message("...");
    pgsql_status=PQstatus(ld);

    if(pgsql_status != CONNECTION_OK) {
        if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
            g_warning("pgsql init error : %s\n",strerror(errno));
        if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN))
            g_message("connection : %s",pgsql_conninfo);
        free(pgsql_conninfo);
        PQfinish(ld);
        return NULL;
    }
    if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN))
        g_message("done");
    free(pgsql_conninfo);
    return ld;
}


G_MODULE_EXPORT gint user_packet_logs (connection element, int state){
    PGconn *ld = g_private_get (pgsql_priv);
    char request[512];
    struct in_addr ipone, iptwo;
    PGresult *Result;
    char tmp_inet1[41], tmp_inet2[41];
    if (ld == NULL){
        ld=pgsql_conn_init();
        if (ld == NULL){
            if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_MAIN))
                g_warning("Can not initiate PGSQL conn\n");
            return -1;
        }
        g_private_set(pgsql_priv,ld);
    }
    /* contruct request */
    switch (state){
      case STATE_OPEN:
        switch ((element.tracking_hdrs).protocol){
          case IPPROTO_TCP:
            //
            // FIELD          IN NUAUTH STRUCTURE               IN ULOG
            //user_id               u_int16_t                   integer
            //ip_protocol           u_int8_t                    smallint        2 bytes
            //ip_saddr              u_int32_t                   inet            12 or 24 bytes (ipv4 or ipv6)
            //ip_daddr              u_int32_t                   inet
            //tcp_sport             u_int16_t                   integer         4 bytes
            //tcp_dport             u_int16_t                   integer
            //udp_sport             u_int16_t                   integer
            //udp_dport             u_int16_t                   integer
            //icmp_type             u_int8_t                    smallint        2 bytes
            //icmp_code             u_int8_t                    smallint        2 bytes
            //start_timestamp       long                        bigint          8 bytes
            //end_timestamp         long                        bigint
            //
            //
            //
            ipone.s_addr=ntohl((element.tracking_hdrs).saddr);
            iptwo.s_addr=ntohl((element.tracking_hdrs).daddr);
            strncpy(tmp_inet1,inet_ntoa(ipone),40) ;
            strncpy(tmp_inet2,inet_ntoa(iptwo),40) ;
            if (snprintf(request,511,"INSERT INTO %s (user_id,oob_time_sec,ip_protocol,ip_saddr,ip_daddr,tcp_sport,tcp_dport,state,oob_prefix) VALUES (%u,%lu,%u,'%s','%s',%u,%u,%hu,'ACCEPT');",
                  pgsql_table_name,
                  (element.user_id),
                  element.timestamp,
                  (element.tracking_hdrs).protocol,
                  tmp_inet1,
                  tmp_inet2,
                  (element.tracking_hdrs).source,
                  (element.tracking_hdrs).dest,
                  STATE_OPEN
                  ) >= 511){
                if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_MAIN))
                    g_warning("Building pgsql insert query, the 511 limit was reached!\n");
                return -1;
            }
            if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN))
                g_message("Doing %s ...",request);

            Result = PQexec(ld, request);

            if (!Result == PGRES_TUPLES_OK){
                if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_MAIN))
                    g_warning("Can not insert Data : %s\n",PQerrorMessage(ld));
                return -1;
            } else {
                if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN))
                    g_message("done\n");
            }
            break;
          case IPPROTO_UDP:
            ipone.s_addr=ntohl((element.tracking_hdrs).saddr);
            iptwo.s_addr=ntohl((element.tracking_hdrs).daddr);
            strncpy(tmp_inet1,inet_ntoa(ipone),40) ;
            strncpy(tmp_inet2,inet_ntoa(iptwo),40) ;
            if (snprintf(request,511,"INSERT INTO %s (user_id,oob_time_sec,ip_protocol,ip_saddr,ip_daddr,udp_sport,udp_dport,state,oob_prefix) VALUES (%u,%lu,%u,'%s','%s',%u,%u,%hu,'ACCEPT');",
                  pgsql_table_name,
                  (element.user_id),
                  element.timestamp,
                  (element.tracking_hdrs).protocol,
                  tmp_inet1,
                  tmp_inet2,
                  (element.tracking_hdrs).source,
                  (element.tracking_hdrs).dest,
                  STATE_OPEN
                  ) >= 511 ){
                if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_MAIN))
                    g_warning("Building pgsql insert query, the 511 limit was reached!\n");
                return -1;
            }
            Result = PQexec(ld, request);
            if (!Result == PGRES_TUPLES_OK){
                if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_MAIN))
                    g_warning("Can not insert Data : %s\n",PQerrorMessage(ld));
                return -1;
            }
            return 0;
          default:
            ipone.s_addr=ntohl((element.tracking_hdrs).saddr);
            iptwo.s_addr=ntohl((element.tracking_hdrs).daddr);
            strncpy(tmp_inet1,inet_ntoa(ipone),40) ;
            strncpy(tmp_inet2,inet_ntoa(iptwo),40) ;
            if (snprintf(request,511,"INSERT INTO %s (user_id,oob_time_sec,ip_protocol,ip_saddr,ip_daddr,state,oob_prefix) VALUES (%u,%lu,%u,'%s','%s',%hu,'ACCEPT');",
                  pgsql_table_name,
                  (element.user_id),
                  element.timestamp,
                  (element.tracking_hdrs).protocol,
                  tmp_inet1,
                  tmp_inet2,
                  STATE_OPEN
                  ) >= 511){
                if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_MAIN))
                    g_warning("Building pgsql insert query, the 511 limit was reached!\n");
                return -1;
            }
            Result = PQexec(ld, request);
            if (!Result == PGRES_TUPLES_OK){
                if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_MAIN))
                    g_warning("Can not insert Data : %s\n",PQerrorMessage(ld));
                return -1;
            }
            return 0;
        }
        return 0;
      case STATE_ESTABLISHED:
        if ((element.tracking_hdrs).protocol == IPPROTO_TCP){
            int update_status = 0;
            while (update_status < 2){
              update_status++;
              ipone.s_addr=ntohl((element.tracking_hdrs).saddr);
              iptwo.s_addr=ntohl((element.tracking_hdrs).daddr);
              strncpy(tmp_inet1,inet_ntoa(ipone),40) ;
              strncpy(tmp_inet2,inet_ntoa(iptwo),40) ;
              if (snprintf(request,511,"UPDATE %s SET state=%lu, start_timestamp=%lu WHERE (ip_daddr='%s' and ip_saddr='%s' and tcp_dport=%u and tcp_sport=%u and state=%hu);",
                  pgsql_table_name,
                  STATE_ESTABLISHED,
                  element.timestamp,
                  tmp_inet1,
                  tmp_inet2,
                  (element.tracking_hdrs).source,
                  (element.tracking_hdrs).dest,
                  STATE_OPEN
                  ) >= 511){
                if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_MAIN))
                    g_warning("Building pgsql update query, the 511 limit was reached!\n");
                return -1;
            }
            Result = PQexec(ld, request);
            if (!Result == PGRES_TUPLES_OK){
                if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_MAIN))
                    g_warning("Can not update Data : %s\n",PQerrorMessage(ld));
                return -1;
            }
            if (atoi(PQcmdTuples(Result)) >= 1){
                return 0;
            }else{
                if (update_status <2){
                    usleep(33333); //Sleep for 1/3 sec
                }else{
                    if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
                        g_warning("Tried to update PGSQL entry twice, looks like data to update wasn't inserted\n");
                }
            }
          }
          return 0;
        }
        //Nothing will be done...
        return 0;
      case STATE_CLOSE:
        if ((element.tracking_hdrs).protocol == IPPROTO_TCP){
            int update_status = 0;
            while (update_status < 2){
              update_status++;
              ipone.s_addr=ntohl((element.tracking_hdrs).saddr);
              iptwo.s_addr=ntohl((element.tracking_hdrs).daddr);
              strncpy(tmp_inet1,inet_ntoa(ipone),40) ;
              strncpy(tmp_inet2,inet_ntoa(iptwo),40) ;
              if (snprintf(request,511,"UPDATE %s SET end_timestamp=%lu, state=%hu WHERE (ip_saddr='%s' and ip_daddr='%s' and tcp_sport=%u and tcp_dport=%u and state=%hu);",
                  pgsql_table_name,
                  element.timestamp,
                  STATE_CLOSE,
                  tmp_inet1,
                  tmp_inet2,
                  (element.tracking_hdrs).source,
                  (element.tracking_hdrs).dest,
                  STATE_ESTABLISHED
                  ) >= 511){
                if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_MAIN))
                    g_warning("Building pgsql update query, the 511 limit was reached!\n");
                return -1;
              }
              Result = PQexec(ld, request);
              if (!Result == PGRES_TUPLES_OK){
                if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_MAIN))
                    g_warning("Can not update Data : %s\n",PQerrorMessage(ld));
                return -1;
              }
              if (atoi(PQcmdTuples(Result)) >=1){
                return 0;
              }else{
                if (update_status <2){
                  usleep(66666); //Sleep for 2/3 sec
                }else{
                    if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
                        g_warning("Tried to update PGSQL entry twice, looks like data to update wasn't inserted\n");
                }
              }
            }
          return 0;
        }
        //Nothing will be done...
        return 0;
      case STATE_DROP:
        switch ((element.tracking_hdrs).protocol) {
          case IPPROTO_TCP:
            ipone.s_addr=ntohl((element.tracking_hdrs).saddr);
            iptwo.s_addr=ntohl((element.tracking_hdrs).daddr);
            strncpy(tmp_inet1,inet_ntoa(ipone),40) ;
            strncpy(tmp_inet2,inet_ntoa(iptwo),40) ;
            if (snprintf(request,511,"INSERT INTO %s (user_id,oob_time_sec,ip_protocol,ip_saddr,ip_daddr,tcp_sport,tcp_dport,state,oob_prefix) VALUES (%u,%lu,%u,'%s','%s',%u,%u,%hu,'DROP');",
                  pgsql_table_name,
                  (element.user_id),
                  element.timestamp,
                  (element.tracking_hdrs).protocol,
                  tmp_inet1,
                  tmp_inet2,
                  (element.tracking_hdrs).source,
                  (element.tracking_hdrs).dest,
                  STATE_DROP
                  ) >= 511 ){
                if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_MAIN))
                    g_warning("Building pgsql insert query, the 511 limit was reached!\n");
                return -1;
            }
            Result = PQexec(ld, request);
            if (!Result == PGRES_TUPLES_OK){
                if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_MAIN))
                    g_warning("Can not insert Data : %s\n",PQerrorMessage(ld));
                return -1;
            }
            return 0;
          case IPPROTO_UDP:
   ipone.s_addr=ntohl((element.tracking_hdrs).saddr);
            iptwo.s_addr=ntohl((element.tracking_hdrs).daddr);
            strncpy(tmp_inet1,inet_ntoa(ipone),40) ;
            strncpy(tmp_inet2,inet_ntoa(iptwo),40) ;
            if (snprintf(request,511,"INSERT INTO %s (user_id,oob_time_sec,ip_protocol,ip_saddr,ip_daddr,udp_sport,udp_dport,state,oob_prefix) VALUES (%u,%lu,%u,'%s','%s',%u,%u,%hu,'DROP');",
                  pgsql_table_name,
                  (element.user_id),
                  element.timestamp,
                  (element.tracking_hdrs).protocol,
                  tmp_inet1,
                  tmp_inet2,
                  (element.tracking_hdrs).source,
                  (element.tracking_hdrs).dest,
                  STATE_DROP
                  ) >= 511 ){
                if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_MAIN))
                    g_warning("Building pgsql insert query, the 511 limit was reached!\n");
                return -1;
            }
            Result = PQexec(ld, request);
            if (!Result == PGRES_TUPLES_OK){
                if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_MAIN))
                    g_warning("Can not insert Data : %s\n",PQerrorMessage(ld));
                return -1;
            }
            return 0;
          default:
            ipone.s_addr=ntohl((element.tracking_hdrs).saddr);
            iptwo.s_addr=ntohl((element.tracking_hdrs).daddr);
            strncpy(tmp_inet1,inet_ntoa(ipone),40) ;
            strncpy(tmp_inet2,inet_ntoa(iptwo),40) ;
            if (snprintf(request,511,"INSERT INTO %s (user_id,oob_time_sec,ip_protocol,ip_saddr,ip_daddr,state,oob_prefix) VALUES (%u,%lu,%u,'%s','%s',%lu,%hu,'DROP');",
                  pgsql_table_name,
                  (element.user_id),
                  element.timestamp,
                  (element.tracking_hdrs).protocol,
                  tmp_inet1,
                  tmp_inet2,
                  element.timestamp,
                  STATE_DROP
                  ) >= 511){
                if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_MAIN))
                    g_warning("Building pgsql insert query, the 511 limit was reached!\n");
                return -1;
            }
            Result = PQexec(ld, request);
            if (!Result == PGRES_TUPLES_OK){
                if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_MAIN))
                    g_warning("Can not insert Data : %s\n",PQerrorMessage(ld));
                return -1;
            }
            return 0;
        }
    }
    //This return is just here to please GCC, will never be reached
    return 0;
}

G_MODULE_EXPORT gint log_sql_disconnect(void){
    PGconn *ld = g_private_get (pgsql_priv);
    PQfinish(ld);
    return 0;
}
