/*
 ** Copyright(C) 2003-2005 Eric Leblond <eric@regit.org>
 **		     Vincent Deffontaines <vincent@gryzor.com>
 **                   INL
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


// SSL notes :
/* the client cert needs to go in 
 *                $HOME/.postgresql/root.crt see the comments at the top of 
 *                               src/interfaces/libpq/fe-secure.c */

#include <auth_srv.h>
#include <log_pgsql.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include "security.h"

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

G_MODULE_EXPORT gchar* g_module_unload(void)
{
    PGconn *ld = g_private_get (pgsql_priv);
    PQfinish(ld);
    return NULL;
}
/* Init pgsql system */
G_MODULE_EXPORT gchar* g_module_check_init(GModule *module){
    unsigned int nb_params = sizeof(pgsql_nuauth_vars)/sizeof(confparams);

    /* parse conf file */
    parse_conffile(DEFAULT_CONF_FILE, nb_params, pgsql_nuauth_vars);

    /* set variables */
#define READ_CONF(KEY) \
    get_confvar_value(pgsql_nuauth_vars, nb_params, KEY)
#define READ_CONF_INT(VAR, KEY, DEFAULT) \
    do { gpointer vpointer = READ_CONF(KEY); if (vpointer) VAR = *(int *)vpointer; else VAR = DEFAULT; } while (0)

    pgsql_server = (char *)READ_CONF("pgsql_server_addr");
    READ_CONF_INT (pgsql_server_port, "pgsql_server_port", PGSQL_SERVER_PORT);
    pgsql_user = (char *)READ_CONF("pgsql_user");
    pgsql_passwd = (char *)READ_CONF("pgsql_passwd");
    pgsql_ssl = (char *)READ_CONF("pgsql_ssl");
    pgsql_db_name = (char *)READ_CONF("pgsql_db_name");
    pgsql_table_name = (char *)READ_CONF("pgsql_table_name");
    READ_CONF_INT(pgsql_request_timeout, "pgsql_request_timeout", PGSQL_REQUEST_TIMEOUT);

    /* init thread private stuff */
    pgsql_priv = g_private_new ((GDestroyNotify)PQfinish);

    return NULL;
}


/* 
 * Initialize connection to pgsql server
 */
G_MODULE_EXPORT PGconn *pgsql_conn_init(void){
    char *pgsql_conninfo;
    PGconn *ld = NULL;
    int pgsql_status;

    log_message (DEBUG, AREA_MAIN,
            "Going to init PostgreSQL connection.");

    pgsql_conninfo = g_strdup_printf(
            "host=%s port=%d dbname=%s user=%s password=%s connect_timeout=%d",
            /* " sslmode=%s" */
            pgsql_server,
            pgsql_server_port,
            pgsql_db_name,
            pgsql_user,
            pgsql_passwd,
            pgsql_request_timeout
            /* pgsql_ssl */
            );

    ld = PQconnectdb(pgsql_conninfo);
    pgsql_status=PQstatus(ld);
    if(pgsql_status != CONNECTION_OK) {
        log_message (WARNING, AREA_MAIN,
                "PostgreSQL init error: %s\n",
                strerror(errno));
        g_free(pgsql_conninfo);
        PQfinish(ld);
        return NULL;
    }
    log_message (DEBUG, AREA_MAIN, "PostgreSQL init done");
    g_free(pgsql_conninfo);
    return ld;
}

char* quote_string(char *text)
{
    unsigned int length = strlen(text);
    char *quoted = (char *)malloc(length*2 + 1);
    if (PQescapeString(quoted, text, length))
    {
        g_free(quoted);
        return NULL;
    }
    return quoted;
}    

static gchar* generate_osname(gchar *Name, gchar *Version, gchar *Release)
{
    char *all, *quoted;
    if (!Name || !Release || !Version 
        || OSNAME_MAX_SIZE < (strlen(Name)+strlen(Release)+strlen(Version)+3))
    {
        return g_strdup("");
    }
    all = g_strjoin("-",Name,Version,Release,NULL);
    quoted = quote_string(all);
    g_free(all);
    return quoted;
}

int pgsql_insert(PGconn *ld, connection_t element, char *oob_prefix, tcp_state_t state)
{
    char request_fields[INSERT_REQUEST_FIEDLS_SIZE];
    char request_values[INSERT_REQUEST_VALUES_SIZE];
    char tmp_buffer[INSERT_REQUEST_VALUES_SIZE];
    struct in_addr ip_addr;
    char ip_src[INET_ADDRSTRLEN+1], ip_dest[INET_ADDRSTRLEN+1];
    gboolean ok;
    PGresult *Result;
    char *sql_query;

    ip_addr.s_addr = ntohl(element.tracking.saddr);
    SECURE_STRNCPY(ip_src, inet_ntoa(ip_addr), sizeof(ip_src)) ;
    ip_addr.s_addr = ntohl(element.tracking.daddr);
    SECURE_STRNCPY(ip_dest, inet_ntoa(ip_addr), sizeof(ip_dest));

    /* Write common informations */
    ok = secure_snprintf(request_fields, sizeof(request_fields),
            "INSERT INTO %s (oob_prefix, state, oob_time_sec"
            "ip_protocol, ip_saddr, ip_daddr",
            pgsql_table_name
            );
    if (!ok) {
        return -1;
    }
    ok = secure_snprintf(request_values, sizeof(request_values),
            "VALUES ('%s', '%hu', '%lu', '%u','%s','%s'",
            oob_prefix,
            state,
            element.timestamp,
            element.tracking.protocol,
            ip_src,
            ip_dest
            );
    if (!ok) {
        return -1;
    }

    /* Add user informations */ 
    if (element.username) {
        /* Get OS and application names */
        char *quoted_username = quote_string(element.username);
        char *quoted_osname = generate_osname(
                element.os_sysname,
                element.os_version,
                element.os_release);
        char *quoted_appname;
        
        if (element.app_name != NULL  && strlen(element.app_name) < APPNAME_MAX_SIZE)
            quoted_appname = quote_string(element.app_name);
        else
            quoted_appname = g_strdup("");

        /* Quote strings send to MySQL */ 
        g_strlcat(
                request_fields, 
                ", user_id, username, client_os, client_app", 
                sizeof(request_fields));
        ok = secure_snprintf(tmp_buffer, sizeof(tmp_buffer),
                ", '%u', '%s', '%s', '%s'",
                element.user_id,
                quoted_username,
                quoted_osname,
                quoted_appname
                );
        g_free(quoted_username);
        g_free(quoted_osname);
        g_free(quoted_appname);
        if (!ok) {
            return -1;
        }
    }

    /* Add TCP/UDP parameters */
    if ((element.tracking.protocol == IPPROTO_TCP) 
            || (element.tracking.protocol == IPPROTO_UDP))
    {
        if (element.tracking.protocol == IPPROTO_TCP) {
            g_strlcat(
                    request_fields, 
                    ", tcp_sport, tcp_dport) ", 
                    sizeof(request_fields));
        } else {
            g_strlcat(
                    request_fields, 
                    ", udp_sport, udp_dport) ", 
                    sizeof(request_fields));
        }
        ok = secure_snprintf(tmp_buffer, sizeof(tmp_buffer),
                ", %hu, %hu);", 
                element.tracking.source,
                element.tracking.dest);
        if (!ok) {
            return -1;
        }
        g_strlcat(request_values, tmp_buffer, sizeof(request_values));
    } else {
        g_strlcat(request_fields, ") ", sizeof(request_fields));
        g_strlcat(request_values, ");", sizeof(request_values));
    }

    /* Check overflow */
    if (( (sizeof(request_fields)-1) <= strlen(request_fields) )
            ||
            ( (sizeof(request_values)-1) <= strlen(request_values) ))
    {
        return -1;
    }

    /* create the sql query */
    sql_query = g_strconcat(request_fields, request_values, NULL);
    if (sql_query == NULL) {
        log_message(SERIOUS_WARNING, AREA_MAIN,
                "Fail to build PostgreSQL query (maybe too long)!");
        return -1;
    }
    
    /* do the query */
    log_message(DEBUG, AREA_MAIN, "PostgreSQL: do insert \"%s\".", sql_query);
    Result = PQexec(ld, sql_query);

    /* check error */
    if (!Result || PQresultStatus(Result) != PGRES_COMMAND_OK){
        log_message (SERIOUS_WARNING, AREA_MAIN,
                "Can not insert Data in PostgreSQL: %s\n",
                PQerrorMessage(ld));
        PQclear(Result);
        return -1;
    }
    PQclear(Result);
    return 0;
}

int pgsql_update_close(PGconn *ld, connection_t element)
{
    struct in_addr addr;
    char ip_src[INET_ADDRSTRLEN+1];
    char request[SHORT_REQUEST_SIZE];
    PGresult *Result;
    gboolean ok;

    addr.s_addr = ntohl(element.tracking.saddr);
    SECURE_STRNCPY(ip_src, inet_ntoa(addr), sizeof(ip_src)) ;

    ok = secure_snprintf(request, sizeof(request),
            "UPDATE %s SET state='%hu', end_timestamp='%lu' "
            "WHERE (ip_saddr='%s' AND tcp_sport='%u' "
            "AND (state=1 OR state=2));",
            pgsql_table_name,
            TCP_STATE_CLOSE,
            element.timestamp,
            ip_src,
            element.tracking.source);
    if (!ok) {
        log_message (SERIOUS_WARNING, AREA_MAIN,
                "Fail to build PostgreSQL query (maybe too long)!");
        return -1;
    }

    Result = PQexec(ld, request);
    if (!Result || PQresultStatus(Result) != PGRES_COMMAND_OK){
        log_message (SERIOUS_WARNING, AREA_MAIN,
                "Can not update PostgreSQL data: %s\n",
                PQerrorMessage(ld));
        PQclear(Result);
        return -1;
    }
    PQclear(Result);
    return 0;
}    


int pgsql_update_state(PGconn *ld, connection_t element, 
        tcp_state_t old_state, tcp_state_t new_state, 
        int reverse)
{
    char request[SHORT_REQUEST_SIZE];
    PGresult *Result;
    struct in_addr ip_addr;
    char tmp_inet1[INET_ADDRSTRLEN+1], tmp_inet2[INET_ADDRSTRLEN+1];
    short int tcp_src, tcp_dst;
    char *ip_src, *ip_dst;
    int nb_try = 0;
    int nb_tuple;
    gboolean ok;

    /* setup IP/TCP parameters */
    ip_addr.s_addr=ntohl((element.tracking).saddr);
    SECURE_STRNCPY(tmp_inet1, inet_ntoa(ip_addr), sizeof(tmp_inet1)) ;
    ip_addr.s_addr=ntohl((element.tracking).daddr);
    SECURE_STRNCPY(tmp_inet2, inet_ntoa(ip_addr), sizeof(tmp_inet2));
    if (reverse) { 
        ip_src = tmp_inet2;
        ip_dst = tmp_inet1;
        tcp_src = element.tracking.dest;
        tcp_dst = element.tracking.source;
    } else {
        ip_src = tmp_inet1;
        ip_dst = tmp_inet2;
        tcp_src = element.tracking.source;
        tcp_dst = element.tracking.dest;
    }       

    /* build sql query */
    ok = secure_snprintf(request, sizeof(request),
            "UPDATE %s SET state='%hu', start_timestamp='%lu' "
            "WHERE (ip_daddr='%s' AND ip_saddr='%s' "
            "AND tcp_dport='%u' AND tcp_sport='%u' AND state='%hu');",
            pgsql_table_name,
            new_state, element.timestamp,
            ip_src, ip_dst,
            tcp_src, tcp_dst, old_state);
    if (!ok)
    {
        log_message (SERIOUS_WARNING, AREA_MAIN,
                "Fail to build PostgreSQL query (maybe too long)!");
        return -1;
    }

    while (nb_try < 2){
        /* build the query */
        nb_try++;

        /* do the query */
        Result = PQexec(ld, request);
        if (!Result || PQresultStatus(Result) != PGRES_COMMAND_OK){
            log_message (SERIOUS_WARNING, AREA_MAIN,
                "Can not update data: %s",
                PQerrorMessage(ld));
            PQclear(Result);
            return -1;
        }
        nb_tuple = atoi(PQcmdTuples(Result));
        PQclear(Result);
        
        /* ok */
        if (nb_tuple >= 1){
            return 0;
        }
        
        /* error */
        if (nb_try<2) {
            /* Sleep for 1/3 sec */
            struct timespec sleep;
            sleep.tv_sec = 0;
            sleep.tv_nsec = 333333333;
            nanosleep(&sleep, NULL);
        }
    }
    debug_log_message (WARNING, AREA_MAIN,
            "Tried to update PGSQL entry twice, looks like data to update wasn't inserted\n");
    return -1;
}    

G_MODULE_EXPORT gint user_packet_logs (connection_t element, tcp_state_t state)
{
    /* get/open postgresql connection */
    PGconn *ld = g_private_get (pgsql_priv);
    if (ld == NULL){
        ld=pgsql_conn_init();
        if (ld == NULL){
            log_message (SERIOUS_WARNING, AREA_MAIN,
                    "Can not initiate PGSQL connection!\n");
            return -1;
        }
        g_private_set(pgsql_priv,ld);
    }

    switch (state){
        case TCP_STATE_OPEN:
            if (element.tracking.protocol == IPPROTO_TCP 
                && nuauthconf->log_users_strict)
            {
                int ret = pgsql_update_close(ld, element);
                if (ret != 0) {
                    return ret;
                }
            }

            return pgsql_insert(ld, element, "ACCEPT", state);

        case TCP_STATE_ESTABLISHED:
            if (element.tracking.protocol == IPPROTO_TCP)
                return pgsql_update_state(ld, element, TCP_STATE_OPEN, TCP_STATE_ESTABLISHED, 0);
            else
                return 0;

        case TCP_STATE_CLOSE:
            if (element.tracking.protocol == IPPROTO_TCP)
                return pgsql_update_state(ld, element, TCP_STATE_ESTABLISHED, TCP_STATE_CLOSE, 1);
            else
                return 0;

        case TCP_STATE_DROP:
            return pgsql_insert(ld, element, "DROP", state);

            /* Skip other messages */
        default:
            return 0;
    }
}

G_MODULE_EXPORT gint log_sql_disconnect(void){
    PGconn *ld = g_private_get (pgsql_priv);
    PQfinish(ld);
    return 0;
}

