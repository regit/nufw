/*
 ** Copyright(C) 2003-2006 Eric Leblond <eric@regit.org>
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


/* SSL notes :
 * the client cert needs to go in 
 *                $HOME/.postgresql/root.crt see the comments at the top of 
 *                               src/interfaces/libpq/fe-secure.c */

#include <auth_srv.h>
#include <log_pgsql.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include "security.h"

static nu_error_t pgsql_close_open_user_sessions(struct log_pgsql_params* params);
static PGconn *pgsql_conn_init(struct log_pgsql_params* params);

/**
 *
 * \ingroup LoggingNuauthModules
 * \defgroup PGSQLModule PgSQL logging module
 *
 * @{ */

G_MODULE_EXPORT gboolean unload_module_with_params(gpointer params_p)
{
  struct log_pgsql_params *params = (struct log_pgsql_params*)params_p;
  if(params){
      if (! nuauth_is_reloading()){
          if ( pgsql_close_open_user_sessions(params) != NU_EXIT_OK){
              log_message(WARNING, AREA_MAIN,
                      "Could not close session when unloading module");
          }
      }

      g_free(params->pgsql_user);
      g_free(params->pgsql_passwd);
      g_free(params->pgsql_server);
      g_free(params->pgsql_ssl);
      g_free(params->pgsql_db_name);
      g_free(params->pgsql_table_name);
      g_free(params->pgsql_users_table_name);
  } 
  g_free(params);

  return TRUE;
}

/**
 * \brief Close all open user sessions
 *
 * \return A nu_error_t
 */

static nu_error_t pgsql_close_open_user_sessions(struct log_pgsql_params* params)
{
    PGconn* ld = pgsql_conn_init(params);
    char request[INSERT_REQUEST_VALUES_SIZE];
    gboolean ok;
    PGresult *Result;

    if (! ld){
        return NU_EXIT_ERROR;
    }

    ok = secure_snprintf(request, sizeof(request),
                    "UPDATE %s SET last_time=ABSTIME(%lu) WHERE last_time is NULL",
                    params->pgsql_users_table_name,
                    time(NULL));
    if (!ok) {
        if (ld){
            PQfinish(ld);
        }
        return NU_EXIT_ERROR;
    }

    /* do the query */
    Result = PQexec(ld, request);

    /* check error */
    if (!Result || PQresultStatus(Result) != PGRES_COMMAND_OK){
        log_message (SERIOUS_WARNING, AREA_MAIN,
                "Can not insert session in PostgreSQL: %s",
                PQerrorMessage(ld));
        PQclear(Result);
        PQfinish(ld);
        return NU_EXIT_ERROR;
    }
    PQclear(Result);
    PQfinish(ld);
    return NU_EXIT_OK;
}


/* Init pgsql system */
G_MODULE_EXPORT gboolean init_module_from_conf(module_t *module)
{
  confparams pgsql_nuauth_vars[] = {
      { "pgsql_server_addr" , G_TOKEN_STRING, 0 , g_strdup(PGSQL_SERVER) },
      { "pgsql_server_port" ,G_TOKEN_INT , PGSQL_SERVER_PORT,NULL },
      { "pgsql_user" , G_TOKEN_STRING , 0 ,g_strdup(PGSQL_USER)},
      { "pgsql_passwd" , G_TOKEN_STRING , 0 ,g_strdup(PGSQL_PASSWD)},
      { "pgsql_ssl" , G_TOKEN_STRING , 0 ,g_strdup(PGSQL_SSL)},
      { "pgsql_db_name" , G_TOKEN_STRING , 0 ,g_strdup(PGSQL_DB_NAME)},
      { "pgsql_table_name" , G_TOKEN_STRING , 0 ,g_strdup(PGSQL_TABLE_NAME)},
      { "pgsql_users_table_name" , G_TOKEN_STRING , 0, g_strdup(PGSQL_USERS_TABLE_NAME)},
      { "pgsql_request_timeout" , G_TOKEN_INT , PGSQL_REQUEST_TIMEOUT , NULL }
  };
    unsigned int nb_params = sizeof(pgsql_nuauth_vars)/sizeof(confparams);
    struct log_pgsql_params* params=g_new0(struct log_pgsql_params,1);
    module->params = params;

    /* parse conf file */
    if (module->configfile){
        parse_conffile(module->configfile, nb_params, pgsql_nuauth_vars);
    } else {
        parse_conffile(DEFAULT_CONF_FILE, nb_params, pgsql_nuauth_vars);
    }

    /* set variables */
#define READ_CONF(KEY) \
    get_confvar_value(pgsql_nuauth_vars, nb_params, KEY)
#define READ_CONF_INT(VAR, KEY, DEFAULT) \
    do { gpointer vpointer = READ_CONF(KEY); if (vpointer) VAR = *(int *)vpointer; else VAR = DEFAULT; } while (0)

    params->pgsql_server = (char *)READ_CONF("pgsql_server_addr");
    READ_CONF_INT (params->pgsql_server_port, "pgsql_server_port", PGSQL_SERVER_PORT);
    params->pgsql_user = (char *)READ_CONF("pgsql_user");
    params->pgsql_passwd = (char *)READ_CONF("pgsql_passwd");
    params->pgsql_ssl = (char *)READ_CONF("pgsql_ssl");
    params->pgsql_db_name = (char *)READ_CONF("pgsql_db_name");
    params->pgsql_table_name = (char *)READ_CONF("pgsql_table_name");
    params->pgsql_users_table_name = (char *)READ_CONF("pgsql_users_table_name");
    READ_CONF_INT(params->pgsql_request_timeout, "pgsql_request_timeout", PGSQL_REQUEST_TIMEOUT);

    /* free config struct */
    free_confparams(pgsql_nuauth_vars,sizeof(pgsql_nuauth_vars)/sizeof(confparams));
#undef READ_CONF
#undef READ_CONF_INT

    /* init thread private stuff */
    params->pgsql_priv = g_private_new ((GDestroyNotify)PQfinish);

    /* do initial update of user session if needed */
    if (! nuauth_is_reloading()){
        pgsql_close_open_user_sessions(params);
    }
    
    module->params=(gpointer)params;
    return TRUE;
}


/* 
 * Initialize connection to pgsql server
 */
static PGconn *pgsql_conn_init(struct log_pgsql_params* params){
    char *pgsql_conninfo;
    PGconn *ld = NULL;
    int pgsql_status;

    log_message (DEBUG, AREA_MAIN,
            "Going to init PostgreSQL connection.");

    pgsql_conninfo = g_strdup_printf(
            "host=%s port=%d dbname=%s user=%s password=%s connect_timeout=%d",
            /* " sslmode=%s" */
            params->pgsql_server,
            params->pgsql_server_port,
            params->pgsql_db_name,
            params->pgsql_user,
            params->pgsql_passwd,
            params->pgsql_request_timeout
            /* params->pgsql_ssl */
            );

    ld = PQconnectdb(pgsql_conninfo);
    pgsql_status=PQstatus(ld);
    if(pgsql_status != CONNECTION_OK) {
        log_message (WARNING, AREA_MAIN,
                "PostgreSQL init error: %s",
                strerror(errno));
        g_free(pgsql_conninfo);
        PQfinish(ld);
        return NULL;
    }
    log_message (DEBUG, AREA_MAIN, "PostgreSQL init done");
    g_free(pgsql_conninfo);
    return ld;
}

static char* quote_pgsql_string(char *text)
{
    unsigned int length = strlen(text);
    char *quoted = (char *)malloc(length*2 + 1);
    if (PQescapeString(quoted, text, length) == 0)
    {
        g_free(quoted);
        return NULL;
    }
    return quoted;
}    

static gchar* generate_osname(gchar *Name, gchar *Version, gchar *Release)
{
    char *all, *quoted;
    if (Name == NULL || Release == NULL || Version == NULL
        || OSNAME_MAX_SIZE < (strlen(Name)+strlen(Release)+strlen(Version)+3))
    {
        return g_strdup("");
    }
    all = g_strjoin("-",Name,Version,Release,NULL);
    quoted = quote_pgsql_string(all);
    g_free(all);
    return quoted;
}

static int pgsql_insert(PGconn *ld, connection_t *element, char *oob_prefix, tcp_state_t state,
        struct log_pgsql_params* params)
{
    char request_fields[INSERT_REQUEST_FIEDLS_SIZE];
    char request_values[INSERT_REQUEST_VALUES_SIZE];
    char tmp_buffer[INSERT_REQUEST_VALUES_SIZE];
    char ip_src[INET6_ADDRSTRLEN];
    char ip_dst[INET6_ADDRSTRLEN];
    gboolean ok;
    PGresult *Result;
    char *sql_query;

    if (inet_ntop(AF_INET6, &element->tracking.saddr, ip_src, sizeof(ip_src)) == NULL)
        return -1;
    if (inet_ntop(AF_INET6, &element->tracking.daddr, ip_dst, sizeof(ip_dst)) == NULL)
        return -1;

    /* Write common informations */
    ok = secure_snprintf(request_fields, sizeof(request_fields),
            "INSERT INTO %s (oob_prefix, state, "
            "oob_time_sec, oob_time_usec, start_timestamp, "
            "ip_protocol, ip_saddr, ip_daddr",
            params->pgsql_table_name
            );
    if (!ok) {
        return -1;
    }
    ok = secure_snprintf(request_values, sizeof(request_values),
            "VALUES ('%s', '%hu', "
            "'%lu', '0', '%lu', "
            "'%u', '%s', '%s'",
            oob_prefix, state,
            element->timestamp, element->timestamp,
            element->tracking.protocol, ip_src, ip_dst);
    if (!ok) {
        return -1;
    }

    /* Add user informations */ 
    if (element->username) {
        /* Get OS and application names */
        char *quoted_username = quote_pgsql_string(element->username);
        char *quoted_osname = generate_osname(
                element->os_sysname,
                element->os_version,
                element->os_release);
        char *quoted_appname;
        
        if (element->app_name != NULL  && strlen(element->app_name) < APPNAME_MAX_SIZE)
            quoted_appname = quote_pgsql_string(element->app_name);
        else
            quoted_appname = g_strdup("");

        /* Quote strings send to MySQL */ 
        g_strlcat(
                request_fields, 
                ", user_id, username, client_os, client_app", 
                sizeof(request_fields));
        ok = secure_snprintf(tmp_buffer, sizeof(tmp_buffer),
                ", '%u', '%s', '%s', '%s'",
                element->user_id,
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
        g_strlcat(request_values, tmp_buffer, sizeof(request_values));
    }

    /* Add TCP/UDP parameters */
    if ((element->tracking.protocol == IPPROTO_TCP) 
            || (element->tracking.protocol == IPPROTO_UDP))
    {
        if (element->tracking.protocol == IPPROTO_TCP) {
            g_strlcat(
                    request_fields, 
                    ", tcp_sport, tcp_dport)", 
                    sizeof(request_fields));
        } else {
            g_strlcat(
                    request_fields, 
                    ", udp_sport, udp_dport)", 
                    sizeof(request_fields));
        }
        ok = secure_snprintf(tmp_buffer, sizeof(tmp_buffer),
                ", '%hu', '%hu');", 
                element->tracking.source,
                element->tracking.dest);
        if (!ok) {
            return -1;
        }
        g_strlcat(request_values, tmp_buffer, sizeof(request_values));
    } else {
        g_strlcat(request_fields, ")", sizeof(request_fields));
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
    sql_query = g_strconcat(request_fields, "\n", request_values, NULL);
    if (sql_query == NULL) {
        log_message(SERIOUS_WARNING, AREA_MAIN,
                "Fail to build PostgreSQL query (maybe too long)!");
        return -1;
    }
    
    /* do the query */
    Result = PQexec(ld, sql_query);

    /* check error */
    if (!Result || PQresultStatus(Result) != PGRES_COMMAND_OK){
        log_message (SERIOUS_WARNING, AREA_MAIN,
                "Can not insert Data in PostgreSQL: %s",
                PQerrorMessage(ld));
        PQclear(Result);
        return -1;
    }
    PQclear(Result);
    return 0;
}

static int pgsql_update_close(PGconn *ld, connection_t *element,struct log_pgsql_params* params)
{
    char ip_src[INET6_ADDRSTRLEN];
    char request[SHORT_REQUEST_SIZE];
    PGresult *Result;
    gboolean ok;

    if (inet_ntop(AF_INET6, &element->tracking.saddr, ip_src, sizeof(ip_src)) == NULL)
        return -1;

    ok = secure_snprintf(request, sizeof(request),
            "UPDATE %s SET state='%hu', end_timestamp='%lu' "
            "WHERE (ip_saddr='%s' AND tcp_sport='%u' "
            "AND (state=1 OR state=2));",
            params->pgsql_table_name,
            TCP_STATE_CLOSE,
            element->timestamp,
            ip_src,
            element->tracking.source);
    if (!ok) {
        log_message (SERIOUS_WARNING, AREA_MAIN,
                "Fail to build PostgreSQL query (maybe too long)!");
        return -1;
    }
    
    /* do the query */
    Result = PQexec(ld, request);
    if (!Result || PQresultStatus(Result) != PGRES_COMMAND_OK){
        log_message (SERIOUS_WARNING, AREA_MAIN,
                "Can not update PostgreSQL data: %s",
                PQerrorMessage(ld));
        PQclear(Result);
        return -1;
    }
    PQclear(Result);
    return 0;
}    


static int pgsql_update_state(PGconn *ld, connection_t *element, 
        tcp_state_t old_state, tcp_state_t new_state, 
        int reverse,struct log_pgsql_params* params)
{
    char request[SHORT_REQUEST_SIZE];
    PGresult *Result;
    char tmp_inet1[INET_ADDRSTRLEN+1];
    char tmp_inet2[INET_ADDRSTRLEN+1];
    u_int16_t tcp_src, tcp_dst;
    char *ip_src, *ip_dst;
    int nb_try = 0;
    int nb_tuple;
    gboolean ok;

    /* setup IP/TCP parameters */
    if (inet_ntop(AF_INET6, &element->tracking.saddr, tmp_inet1, sizeof(tmp_inet1)) == NULL)
        return -1;
    if (inet_ntop(AF_INET6, &element->tracking.daddr, tmp_inet2, sizeof(tmp_inet2)) == NULL)
        return -1;

    if (reverse) { 
        ip_src = tmp_inet2;
        ip_dst = tmp_inet1;
        tcp_src = element->tracking.dest;
        tcp_dst = element->tracking.source;
    } else {
        ip_src = tmp_inet1;
        ip_dst = tmp_inet2;
        tcp_src = element->tracking.source;
        tcp_dst = element->tracking.dest;
    }       

    /* build sql query */
    ok = secure_snprintf(request, sizeof(request),
            "UPDATE %s SET state='%hu', start_timestamp='%lu' "
            "WHERE (ip_daddr='%s' AND ip_saddr='%s' "
            "AND tcp_dport='%hu' AND tcp_sport='%hu' AND state='%hu');",
            params->pgsql_table_name,
            new_state, element->timestamp,
            ip_src, ip_dst,
            tcp_src, tcp_dst, old_state);
    if (!ok)
    {
        log_message (SERIOUS_WARNING, AREA_MAIN,
                "Fail to build PostgreSQL query (maybe too long)!");
        return -1;
    }
    
    debug_log_message(DEBUG, AREA_MAIN, 
            "PostgreSQL: update state \"%s\".", request);

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
            "Tried to update PGSQL entry twice, looks like data to update wasn't inserted");
    return -1;
}    

static PGconn *get_pgsql_handler(struct log_pgsql_params *params)
{    
    /* get/open postgresql connection */
    PGconn *ld = g_private_get (params->pgsql_priv);
    if (ld == NULL){
        ld=pgsql_conn_init(params);
        if (ld == NULL){
            log_message (SERIOUS_WARNING, AREA_MAIN,
                    "Can not initiate PgSQL connection!");
            return NULL;
        }
        g_private_set(params->pgsql_priv,ld);
    }
    return ld;
}

G_MODULE_EXPORT gint user_packet_logs (connection_t* element, tcp_state_t state,gpointer params_p)
{
    struct log_pgsql_params *params = (struct log_pgsql_params*)params_p;
    PGconn *ld = get_pgsql_handler(params);
    if (ld == NULL)
        return -1;

    switch (state){
        case TCP_STATE_OPEN:
            if (element->tracking.protocol == IPPROTO_TCP 
                && nuauthconf->log_users_strict)
            {
                int ret = pgsql_update_close(ld, element,params);
                if (ret != 0) {
                    return ret;
                }
            }

            return pgsql_insert(ld, element, "ACCEPT", state,params);

        case TCP_STATE_ESTABLISHED:
            if (element->tracking.protocol == IPPROTO_TCP)
                return pgsql_update_state(ld, element, TCP_STATE_OPEN, TCP_STATE_ESTABLISHED, 0,params);
            else
                return 0;

        case TCP_STATE_CLOSE:
            if (element->tracking.protocol == IPPROTO_TCP)
                return pgsql_update_state(ld, element, TCP_STATE_ESTABLISHED, TCP_STATE_CLOSE, 1,params);
            else
                return 0;

        case TCP_STATE_DROP:
            return pgsql_insert(ld, element, "DROP", state,params);

            /* Skip other messages */
        default:
            return 0;
    }
}

G_MODULE_EXPORT int user_session_logs(user_session_t *c_session, session_state_t state,gpointer params_p)
{
    char request[INSERT_REQUEST_VALUES_SIZE];
    char addr_ascii[INET6_ADDRSTRLEN];
    struct log_pgsql_params *params = (struct log_pgsql_params*)params_p;
    gboolean ok;
    PGresult *Result;
    PGconn *ld = get_pgsql_handler(params);
    if (ld == NULL)
        return -1;

    if (inet_ntop(AF_INET6, &c_session->addr, addr_ascii, sizeof(addr_ascii)) == NULL)
        return -1;
    
    switch (state) {
        case SESSION_OPEN:
            /* create new user session */
            ok = secure_snprintf(request, sizeof(request),
                    "INSERT INTO %s (user_id, username, ip_saddr, "
                    "os_sysname, os_release, os_version, socket, first_time) "
                    "VALUES ('%lu', '%s', '%s', '%s', '%s', '%s', '%u', ABSTIME(%lu))",
                    params->pgsql_users_table_name,
                    c_session->user_id,
                    c_session->user_name,
                    addr_ascii,
                    c_session->sysname,
                    c_session->release,
                    c_session->version,
                    c_session->socket,
                    time(NULL));
            break;

        case SESSION_CLOSE:
            /* update existing user session */
            ok = secure_snprintf(request, sizeof(request),
                    "UPDATE %s SET last_time=ABSTIME(%lu) "
                    "WHERE socket=%u and ip_saddr=%u",
                    params->pgsql_users_table_name,
                    time(NULL),
                    c_session->socket,
                    addr_ascii);
            break;

        default:
            return -1;
    }
    if (!ok) {
        return -1;
    }

    /* do the query */
    Result = PQexec(ld, request);

    /* check error */
    if (!Result || PQresultStatus(Result) != PGRES_COMMAND_OK){
        log_message (SERIOUS_WARNING, AREA_MAIN,
                "Can not insert session in PostgreSQL: %s",
                PQerrorMessage(ld));
        PQclear(Result);
        return -1;
    }
    PQclear(Result);
    return 0;
}

/** @} */
