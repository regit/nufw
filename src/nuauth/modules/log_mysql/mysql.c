
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
#include <log_mysql.h>
#include <string.h>
#include <errno.h>


confparams mysql_nuauth_vars[] = {
  { "mysql_server_addr" , G_TOKEN_STRING, 0 , MYSQL_SERVER },
  { "mysql_server_port" ,G_TOKEN_INT , MYSQL_SERVER_PORT,NULL },
  { "mysql_user" , G_TOKEN_STRING , 0 ,MYSQL_USER},
  { "mysql_password" , G_TOKEN_STRING , 0 ,MYSQL_PASSWD},
  { "mysql_db_name" , G_TOKEN_STRING , 0 ,MYSQL_DB_NAME},
  { "mysql_table_name" , G_TOKEN_STRING , 0 ,MYSQL_TABLE_NAME},
  { "mysql_request_timeout" , G_TOKEN_INT , MYSQL_REQUEST_TIMEOUT , NULL }
};

/* Init mysql system */
G_MODULE_EXPORT gchar* 
g_module_check_init(GModule *module){
  char *configfile=DEFAULT_CONF_FILE;
  gpointer vpointer; 
  //char *ldap_base_dn=LDAP_BASE;

  /* init global variables */
  mysql_user=MYSQL_USER;
  mysql_passwd=MYSQL_PASSWD;
  mysql_server=MYSQL_SERVER;
  mysql_server_port=MYSQL_SERVER_PORT;
  mysql_db_name=MYSQL_DB_NAME;
  mysql_table_name=MYSQL_TABLE_NAME;
  mysql_request_timeout=MYSQL_REQUEST_TIMEOUT;

  /* parse conf file */
  parse_conffile(configfile,sizeof(mysql_nuauth_vars)/sizeof(confparams),mysql_nuauth_vars);
  /* set variables */
  vpointer=get_confvar_value(mysql_nuauth_vars,sizeof(mysql_nuauth_vars)/sizeof(confparams),"mysql_server_addr");
  mysql_server=(char *)(vpointer?vpointer:mysql_server);
  vpointer=get_confvar_value(mysql_nuauth_vars,sizeof(mysql_nuauth_vars)/sizeof(confparams),"mysql_server_port");
  mysql_server_port=*(int *)(vpointer?vpointer:&mysql_server_port);
  vpointer=get_confvar_value(mysql_nuauth_vars,sizeof(mysql_nuauth_vars)/sizeof(confparams),"mysql_user");
  mysql_user=(char *)(vpointer?vpointer:mysql_user);
  vpointer=get_confvar_value(mysql_nuauth_vars,sizeof(mysql_nuauth_vars)/sizeof(confparams),"mysql_passwd");
  mysql_passwd=(char *)(vpointer?vpointer:mysql_passwd);
  vpointer=get_confvar_value(mysql_nuauth_vars,sizeof(mysql_nuauth_vars)/sizeof(confparams),"mysql_db_name");
  mysql_db_name=(char *)(vpointer?vpointer:mysql_db_name);
  vpointer=get_confvar_value(mysql_nuauth_vars,sizeof(mysql_nuauth_vars)/sizeof(confparams),"mysql_table_name");
  mysql_table_name=(char *)(vpointer?vpointer:mysql_table_name);
  vpointer=get_confvar_value(mysql_nuauth_vars,sizeof(mysql_nuauth_vars)/sizeof(confparams),"mysql_request_timeout");
  mysql_request_timeout=*(int *)(vpointer?vpointer:&mysql_request_timeout);

  /* init thread private stuff */
  mysql_priv = g_private_new (g_free);

  return NULL;
}

/* 
 * Initialize connection to mysql server
 */

G_MODULE_EXPORT MYSQL* mysql_conn_init(void){
  MYSQL *ld = NULL;
  int mysql_status,err,version=3;

  /* init connection */
  if (mysql_init(ld) == NULL) {
      if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
          g_warning("mysql init error : %s\n",strerror(errno));
      return NULL;
  }
  // Set MYSQL object properties
  if (mysql_options(ld,MYSQL_OPT_CONNECT_TIMEOUT,mysql_conninfo) != 0)
      if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
          g_warning("mysql options setting failed : %s\n",mysql_error(ld));
  
  if (!mysql_real_connect(ld,mysql_server_addr,mysql_user,mysql_passwd,mysql_db_name,mysql_server_port,NULL,0)) {
      if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
          g_warning("mysql connection failed : %s\n",mysql_error(ld));
      return NULL;
  }
  return ld;
}

G_MODULE_EXPORT gint user_packet_logs (connection *element, int state){
    MYSQL *ld = g_private_get (mysql_priv);
  char request[512];
  if (ld == NULL){
    ld=mysql_conn_init();
    if (ld == NULL){
      if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_MAIN))
          g_warning("Can not initiate MYSQL conn\n");
      return NULL;
    }
    g_private_set(mysql_priv,ld);
  }
  /* contruct request */
  if (state == 1){
      if ((element->tracking_hdrs).protocol == IPPROTO_TCP){
          //
          // FIELD          IN NUAUTH STRUCTURE               IN ULOG
          //user_id               u_int16_t                   SMALLINT UNSIGNED     2 bytes
          //ip_protocol           u_int8_t                    TINYINT UNSIGNED      1 byte
          //ip_saddr              u_int32_t                   INT UNSIGNED          4 bytes
          //ip_daddr              u_int32_t                   INT UNSIGNED
          //tcp_sport             u_int16_t                   SMALLINT UNSIGNED 
          //tcp_dport             u_int16_t                   SMALLINT UNSIGNED
          //udp_sport             u_int16_t                   SMALLINT UNSIGNED
          //udp_dport             u_int16_t                   SMALLINT UNSIGNED
          //icmp_type             u_int8_t                    TINYINT UNSIGNED        
          //icmp_code             u_int8_t                    TINYINT UNSIGNED    
          //start_timestamp       long                        BIGINT UNSIGNED       8 bytes
          //end_timestamp         long                        BIGINT UNSIGNED 
          //
          //
          //
          int Result;
          (element->tracking_hdrs).saddr;
          if (snprintf(request,511,"INSERT INTO %s (user_id,ip_protocol,ip_saddr,ip_daddr,tcp_sport,tcp_dport,start_timestamp) 
              VALUES (%u,%u,%lu,%lu,%u,%u,%lu)",
              mysql_table_name,
              (element->user_id),
              (element->tracking_hdrs).saddr,
              (element->tracking_hdrs).daddr,
              (element->tracking_hdrs).source,
              (element->tracking_hdrs).dest,
              element->timestamp
          ) >= 511){
              if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_MAIN))
                  g_warning("Building mysql insert query, the 511 limit was reached!\n");
              return -1;
          }
          Result = mysql_real_query(ld, request, strlen(request));
          if (Result != 0){
            if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_MAIN))
              g_warning("Can not insert Data : %s\n",mysql_error(ld));
            return -1;
          }
      }
      else if ((element->tracking_hdrs).protocol == IPPROTO_UDP){
          struct in_addr ipone, iptwo;
          int Result;
          ipone.s_addr=ntohl((element->tracking_hdrs).saddr);
          iptwo.s_addr=ntohl((element->tracking_hdrs).daddr);
          if (snprintf(request,511,"INSERT INTO %s (user_id,ip_protocol,ip_saddr,ip_daddr,udp_sport,udp_dport,start_timestamp) 
              VALUES (%u,%u,'%s','%s',%u,%u,%lu);",
              mysql_table_name,
              (element->user_id),
              inet_ntoa(ipone),
              inet_ntoa(iptwo),
              (element->tracking_hdrs).source,
              (element->tracking_hdrs).dest,
              element->timestamp
          ) >= 511){
              if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_MAIN))
                  g_warning("Building mysql insert query, the 511 limit was reached!\n");
              return -1;
          }
          Result = mysql_real_query(ld, request, strlen(request));
          if (Result != 0){
            if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_MAIN))
              g_warning("Can not insert Data : %s\n",mysql_error(ld));
            return -1;
          }
          return 0;
      }
      else {
          int Result;
          (element->tracking_hdrs).saddr;
          (element->tracking_hdrs).daddr;
          if (snprintf(request,511,"INSERT INTO %s (user_id,ip_protocol,ip_saddr,ip_daddr,start_timestamp) 
              VALUES (%u,%u,%lu,%lu,%lu);",
              mysql_table_name,
              (element->user_id),
              (element->tracking_hdrs).saddr,
              (element->tracking_hdrs).daddr,
              element->timestamp
          ) >= 511){
              if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_MAIN))
                  g_warning("Building mysql insert query, the 511 limit was reached!\n");
              return -1;
          }
          Result = mysql_real_query(ld, request,strlen(request));
          if (Result != 0){
            if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_MAIN))
              g_warning("Can not insert Data : %s\n",mysql_error(ld));
            return -1;
          }
          return 0;
      }
    }else if (state == 0){
      if ((element->tracking_hdrs).protocol == IPPROTO_TCP){
          int Result;
          if (snprintf(request,511,"UPDATE %s SET end_timestamp=%lu WHERE (ip_saddr=%lu,ip_daddr=%lu,tcp_sport=%u,tcp_dport=%u,end_timestamp=NULL)",
              mysql_table_name,
              element->timestamp,
              (element->tracking_hdrs).saddr,
              (element->tracking_hdrs).daddr,
              (element->tracking_hdrs).source,
              (element->tracking_hdrs).dest
          ) >= 511){
              if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_MAIN))
                  g_warning("Building mysql update query, the 511 limit was reached!\n");
              return -1;
          }
          Result = mysql_real_query(ld, request, strlen(request));
          if (Result != 0){
            if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_MAIN))
              g_warning("Can not update Data : %s\n",mysql_error(ld));
            return -1;
          }
          return 0;
      }
    }
}

