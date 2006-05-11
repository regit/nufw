/*
 ** Copyright(C) 2003-2006 Eric Leblond <eric@regit.org>
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

nu_error_t mysql_close_open_user_sessions(struct log_mysql_params* params);
MYSQL* mysql_conn_init(struct log_mysql_params* params);

/**
 *
 * \ingroup LoggingNuauthModules
 * \defgroup SQLModule MySQL logging module
 *
 * @{ */

G_MODULE_EXPORT gchar* unload_module_with_params(gpointer params_p)
{
  struct log_mysql_params* params = (struct log_mysql_params*)params_p;
  
  if (params){
    if (! nuauth_is_reloading()){
      if ( mysql_close_open_user_sessions(params) != NU_EXIT_OK){
            log_message(WARNING, AREA_MAIN,
                    "Could not close session when unloading module");
      }
    }
  g_free(params->mysql_user);
  g_free(params->mysql_passwd);
  g_free(params->mysql_server);
  g_free(params->mysql_db_name);
  g_free(params->mysql_table_name);
  g_free(params->mysql_users_table_name);
  g_free(params->mysql_ssl_keyfile);
  g_free(params->mysql_ssl_certfile);
  g_free(params->mysql_ssl_ca);
  g_free(params->mysql_ssl_capath);
  g_free(params->mysql_ssl_cipher);
  }
  g_free(params);
  return NULL;
}

/**
 * \brief Close all open user sessions
 *
 * \return A nu_error_t
 */

nu_error_t mysql_close_open_user_sessions(struct log_mysql_params* params)
{
    MYSQL* ld = mysql_conn_init(params);
    char request[LONG_REQUEST_SIZE];
    int mysql_ret;
    int ok;

    ok = secure_snprintf(request, sizeof(request),
                    "UPDATE %s SET last_time=FROM_UNIXTIME(%lu) where last_time is NULL",
                    params->mysql_users_table_name,
                    time(NULL));
    if (!ok) {
        return NU_EXIT_ERROR;
    }

    /* execute query */
    mysql_ret = mysql_real_query(ld, request, strlen(request));
    if (mysql_ret != 0){
        log_message (SERIOUS_WARNING, AREA_MAIN,
            "Can execute request : %s\n", mysql_error(ld));
        return NU_EXIT_ERROR;
    }
    return NU_EXIT_OK;

}

/* Init mysql system */
G_MODULE_EXPORT gboolean 
init_module_from_conf(module_t *module)
{
  confparams mysql_nuauth_vars[] = {
      { "mysql_server_addr" , G_TOKEN_STRING, 0 , g_strdup(MYSQL_SERVER) },
      { "mysql_server_port" ,G_TOKEN_INT , MYSQL_SERVER_PORT,NULL },
      { "mysql_user" , G_TOKEN_STRING , 0 ,g_strdup(MYSQL_USER)},
      { "mysql_passwd" , G_TOKEN_STRING , 0 ,g_strdup(MYSQL_PASSWD)},
      { "mysql_db_name" , G_TOKEN_STRING , 0 ,g_strdup(MYSQL_DB_NAME)},
      { "mysql_table_name" , G_TOKEN_STRING , 0 ,g_strdup(MYSQL_TABLE_NAME)},
      { "mysql_users_table_name" , G_TOKEN_STRING , 0 ,g_strdup(MYSQL_USERS_TABLE_NAME)},
      { "mysql_request_timeout" , G_TOKEN_INT , MYSQL_REQUEST_TIMEOUT , NULL },
      { "mysql_use_ssl" , G_TOKEN_INT , MYSQL_USE_SSL, NULL},
      { "mysql_ssl_keyfile" , G_TOKEN_STRING , 0, g_strdup(MYSQL_SSL_KEYFILE)},
      { "mysql_ssl_certfile" , G_TOKEN_STRING , 0, g_strdup(MYSQL_SSL_CERTFILE)},
      { "mysql_ssl_ca" , G_TOKEN_STRING , 0, g_strdup(MYSQL_SSL_CA)},
      { "mysql_ssl_capath" , G_TOKEN_STRING , 0, g_strdup(MYSQL_SSL_CAPATH)},
      { "mysql_ssl_cipher" , G_TOKEN_STRING , 0, g_strdup(MYSQL_SSL_CIPHER)}
  };
    char *configfile=DEFAULT_CONF_FILE;
    /* char *ldap_base_dn=LDAP_BASE; */
    struct log_mysql_params* params=g_new0(struct log_mysql_params,1);

    /* init global variables */
    params->mysql_ssl_cipher=MYSQL_SSL_CIPHER;

    /* parse conf file */
    if (module->configfile){
        parse_conffile(module->configfile,sizeof(mysql_nuauth_vars)/sizeof(confparams),mysql_nuauth_vars);
    } else {
        parse_conffile(configfile,sizeof(mysql_nuauth_vars)/sizeof(confparams),mysql_nuauth_vars);
    }
    /* set variables */

#define READ_CONF(KEY) \
    get_confvar_value(mysql_nuauth_vars, sizeof(mysql_nuauth_vars)/sizeof(confparams), KEY)
#define READ_CONF_INT(VAR, KEY, DEFAULT) \
    do { gpointer vpointer = READ_CONF(KEY); if (vpointer) VAR = *(int *)vpointer; else VAR = DEFAULT; } while (0)

    params->mysql_server = (char *)READ_CONF("mysql_server_addr");
    params->mysql_user = (char *)READ_CONF("mysql_user");
    params->mysql_passwd = (char *)READ_CONF("mysql_passwd");
    params->mysql_db_name = (char *)READ_CONF("mysql_db_name");
    params->mysql_table_name = (char *)READ_CONF("mysql_table_name");
    params->mysql_users_table_name = (char *)READ_CONF("mysql_users_table_name");
    params->mysql_ssl_keyfile = (char *)READ_CONF("mysql_ssl_keyfile");
    params->mysql_ssl_certfile = (char *)READ_CONF("mysql_ssl_certfile");
    params->mysql_ssl_ca = (char *)READ_CONF("mysql_ssl_ca");
    params->mysql_ssl_capath = (char *)READ_CONF("mysql_ssl_capath");
    params->mysql_ssl_cipher = (char *)READ_CONF("mysql_ssl_cipher");

    READ_CONF_INT(params->mysql_server_port, "mysql_server_port", MYSQL_SERVER_PORT);
    READ_CONF_INT(params->mysql_request_timeout, "mysql_request_timeout", MYSQL_REQUEST_TIMEOUT);
    READ_CONF_INT(params->mysql_use_ssl, "mysql_use_ssl", MYSQL_USE_SSL);


    /* free config struct */
    free_confparams(mysql_nuauth_vars,sizeof(mysql_nuauth_vars)/sizeof(confparams));

    /* init thread private stuff */
    params->mysql_priv = g_private_new ((GDestroyNotify)mysql_close); 
    log_message(DEBUG, AREA_MAIN, "mysql part of the config file is parsed\n");

    /* do initial update of user session if needed */
    if (! nuauth_is_reloading()){
        mysql_close_open_user_sessions(params);
    }
    
    module->params=(gpointer)params;
    return TRUE;
}

/* 
 * Initialize connection to mysql server
 */
MYSQL* mysql_conn_init(struct log_mysql_params* params)
{
    MYSQL *ld = NULL;

    /* init connection */
    ld = mysql_init(ld);     
    if (ld == NULL) {
        log_message(WARNING, AREA_MAIN, "mysql init error : %s\n",strerror(errno));
        return NULL;
    }
#if HAVE_MYSQL_SSL
    /* Set SSL options, if configured to do so */
    if (params->mysql_use_ssl)
        mysql_ssl_set(ld,params->mysql_ssl_keyfile,params->mysql_ssl_certfile,params->mysql_ssl_ca,params->mysql_ssl_capath,params->mysql_ssl_cipher);
#endif
#if 0
    /* Set MYSQL object properties */
    if (mysql_options(ld,MYSQL_OPT_CONNECT_TIMEOUT,mysql_conninfo) != 0){
        log_message(WARNING, AREA_MAIN, "mysql options setting failed : %s\n",mysql_error(ld));
    }
#endif
    if (!mysql_real_connect(ld,params->mysql_server,params->mysql_user,
                params->mysql_passwd,params->mysql_db_name,
                params->mysql_server_port,NULL,0)) {
        log_message(WARNING, AREA_MAIN, "mysql connection failed : %s\n",mysql_error(ld));
        return NULL;
    }
    return ld;
}

static gchar * generate_osname(gchar *Name, gchar *Version, gchar *Release)
{
    if (Name != NULL && Release != NULL && Version != NULL
            && ((strlen(Name)+strlen(Release)+strlen(Version)+3) <= OSNAME_MAX_SIZE)) {
        return g_strjoin("-",Name,Version,Release,NULL);
    } else {
        return g_strdup("");
    }
}

static gchar* generate_appname(gchar *appname)
{ 
    if (appname != NULL && strlen(appname) < APPNAME_MAX_SIZE) {
        return g_strdup(appname);
    } else {
        return g_strdup("");
    }
}

char* quote_string(MYSQL *mysql, char *text)
{
    unsigned int length = strlen(text);
    char *quoted;
    if (length == 0)
        return strdup(text);
    quoted = (char *)malloc(length*2 + 1);
    if (mysql_real_escape_string(mysql, quoted, text, length) == 0)
    {
        g_free(quoted);
        return NULL;
    }
    return quoted;
}    

char* build_insert_request(
        MYSQL *ld, connection_t *element,
        tcp_state_t state,
        char *auth_oob_prefix,
        char *unauth_oob_prefix,
        struct log_mysql_params *params)
{
    char request_fields[INSERT_REQUEST_FIEDLS_SIZE];
    char request_values[INSERT_REQUEST_VALUES_SIZE];
    char tmp_buffer[REQUEST_TMP_BUFFER];
    gboolean ok;

    /* Write common informations */
    ok = secure_snprintf(request_fields, sizeof(request_fields),
            "INSERT INTO %s (state, oob_time_sec, ip_protocol, ip_saddr, ip_daddr, ",
            params->mysql_table_name);
    if (!ok) {
        return NULL;
    }
    ok = secure_snprintf(request_values, sizeof(request_values),
            "VALUES ('%hu', '%lu', '%hu', '%lu', '%lu', ",
            (short unsigned int)state,
            (long unsigned int)element->timestamp,
            (short unsigned int)element->tracking.protocol,
            (long unsigned int)element->tracking.saddr,
            (long unsigned int)element->tracking.daddr);
    if (!ok) {
        return NULL;
    }

    /* Add user informations */ 
    if (element->username) {        
        /* Get OS and application names */
        char *osname = generate_osname(
                element->os_sysname,
                element->os_version,
                element->os_release);
        char *appname = generate_appname(element->app_name); /*Just a size check actually*/

        /* Quote strings send to MySQL */
        char *quoted_username = quote_string(ld, element->username);
        char *quoted_osname = quote_string(ld, osname);
        char *quoted_appname = quote_string(ld, appname);
        g_free(osname);
        g_free(appname);

        ok = (quoted_username != NULL) && (quoted_osname != NULL) && (quoted_appname != NULL);
        if (ok)
        {
            /* Add oob prefix, informations about user, OS an application */
            g_strlcat(
                    request_fields, 
                    "oob_prefix, user_id, username, client_os, client_app", 
                    sizeof(request_fields));
            ok = secure_snprintf(tmp_buffer, sizeof(tmp_buffer),
                    "'%s', '%lu', '%s', '%s', '%s'",
                    auth_oob_prefix,
                    (long unsigned int)element->user_id,
                    quoted_username,
                    quoted_osname,
                    quoted_appname);
        }
        g_free(quoted_username);
        g_free(quoted_osname);
        g_free(quoted_appname);
        if (!ok) {
            return NULL;
        }
        g_strlcat(request_values, tmp_buffer, sizeof(request_values));
    } else {
        /* Add oob prefix */
        g_strlcat(
                request_fields, 
                "oob_prefix", 
                sizeof(request_fields));
        ok = secure_snprintf(tmp_buffer, sizeof(tmp_buffer),
                "'%s'",
                unauth_oob_prefix);        
        if (!ok) {
            return NULL;
        }
        g_strlcat(request_values, tmp_buffer, sizeof(request_values));
    }

    /* Add TCP/UDP parameters */
    if ((element->tracking.protocol == IPPROTO_TCP) 
            || (element->tracking.protocol == IPPROTO_UDP))
    {
        if (element->tracking.protocol == IPPROTO_TCP)
        {
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
                ", '%hu', '%hu')", 
                element->tracking.source,
                element->tracking.dest);
        if (!ok) {
            return NULL;
        }
        g_strlcat(request_values, tmp_buffer, sizeof(request_values));
    } else {
        g_strlcat(request_fields, ")", sizeof(request_fields));
        g_strlcat(request_values, ")", sizeof(request_values));
    }

    /* Check overflow */
    if (( (sizeof(request_fields)-1) <= strlen(request_fields) )
            ||
            ( (sizeof(request_values)-1) <= strlen(request_values) ))
    {
        return NULL;
    }

    /* do the mysql request */
    return g_strconcat(request_fields, "\n", request_values, NULL);
}    

inline int log_state_open(MYSQL *ld, connection_t *element,struct log_mysql_params* params)
{
    char *request;
    int mysql_ret;

    if (element->tracking.protocol == IPPROTO_TCP
            && nuauthconf->log_users_strict)
    {
        gboolean ok;
        char request[SHORT_REQUEST_SIZE];

        ok = secure_snprintf(request, sizeof(request),
                "UPDATE %s SET state=%hu, end_timestamp=FROM_UNIXTIME(%lu) "
                "WHERE (ip_saddr=%lu AND tcp_sport=%u AND (state=1 OR state=2))",
                params->mysql_table_name,
                TCP_STATE_CLOSE,
                element->timestamp,
                (long unsigned int)element->tracking.daddr,
                (element->tracking).source);

        /* need to update table to suppress double field */
        if (!ok)
        {
            log_message (SERIOUS_WARNING, AREA_MAIN,
                    "Building mysql update query, the SHORT_REQUEST_SIZE limit was reached!");
            return -1;
        }

        mysql_ret = mysql_real_query(ld, request, strlen(request));
        if (mysql_ret != 0){
            log_message (SERIOUS_WARNING, AREA_MAIN,
                    "Can not update Data: %s\n", mysql_error(ld));
            return -1;
        }
    }

    /* build sql request */
    request = build_insert_request(
            ld, element,
            TCP_STATE_OPEN, "ACCEPT", "ACCEPT",params);
    if (request == NULL)
    {
        log_message (SERIOUS_WARNING, AREA_MAIN,
                "Error while building MySQL insert query (state OPEN)!");
        return -1;
    }

    /* do query */ 
    mysql_ret = mysql_real_query(ld, request, strlen(request));
    g_free(request);


    /* check request error code */
    if (mysql_ret != 0)
    {
        log_message (SERIOUS_WARNING, AREA_MAIN,
                "Error when inserting data in MySQL: %s\n",
                mysql_error(ld));
        return -1;
    }
    return 0;
}    

inline int log_state_established(MYSQL *ld, connection_t *element,struct log_mysql_params* params)
{
    char request[LONG_REQUEST_SIZE];
    int Result;
    int update_status = 0;
    gboolean ok;

    while (update_status < 2){
        update_status++;

        ok = secure_snprintf(request, sizeof(request),
                "UPDATE %s SET state=%hu,start_timestamp=FROM_UNIXTIME(%lu) "
                "WHERE (ip_daddr=%lu AND ip_saddr=%lu "
                "AND tcp_dport=%u AND tcp_sport=%u AND state=%hu)",
                params->mysql_table_name,
                TCP_STATE_ESTABLISHED,
                element->timestamp,
                (long unsigned int)(element->tracking).saddr,
                (long unsigned int)(element->tracking).daddr,
                (element->tracking).source,
                (element->tracking).dest,
                TCP_STATE_OPEN);
        if (!ok) {
            log_message(SERIOUS_WARNING, AREA_MAIN, "Building mysql update query, the SHORT_REQUEST_SIZE limit was reached!\n");
            return -1;
        }
        Result = mysql_real_query(ld, request, strlen(request));
        if (Result != 0){
            log_message(SERIOUS_WARNING, AREA_MAIN, "Can not update Data : %s\n",mysql_error(ld));
            return -1;
        }
        if (mysql_affected_rows(ld) >= 1){
            return 0;
        }else{
            if (update_status <2){
                /* Sleep for 1/3 sec */
                struct timespec sleep;
                sleep.tv_sec = 0;
                sleep.tv_nsec = 333333333;
                nanosleep(&sleep, NULL);
            }else{
                debug_log_message(DEBUG, AREA_MAIN, "Tried to update MYSQL entry twice, looks like data to update wasn't inserted\n");
            }
        }
    }
    return 0;
}    

inline int log_state_close(MYSQL *ld, connection_t *element,struct log_mysql_params *params)
{
    char request[LONG_REQUEST_SIZE];
    int Result;
    int update_status = 0;
    gboolean ok;

    while (update_status < 2){
        update_status++;
        ok = secure_snprintf(request, sizeof(request),
                "UPDATE %s SET end_timestamp=FROM_UNIXTIME(%lu), state=%hu "
                "WHERE (ip_saddr=%lu AND ip_daddr=%lu "
                "AND tcp_sport=%u AND tcp_dport=%u AND state=%hu)",
                params->mysql_table_name,
                element->timestamp,
                TCP_STATE_CLOSE,
                (long unsigned int)(element->tracking).saddr,
                (long unsigned int)(element->tracking).daddr,
                (element->tracking).source,
                (element->tracking).dest,
                TCP_STATE_ESTABLISHED);
        if (!ok)
            log_message (SERIOUS_WARNING, AREA_MAIN,
                    "Building mysql update query, the SHORT_REQUEST_SIZE limit was reached!\n");
        return -1;
    }

    Result = mysql_real_query(ld, request, strlen(request));
    if (Result != 0){
        log_message(SERIOUS_WARNING, AREA_MAIN, "Can not update Data : %s\n",mysql_error(ld));
        return -1;
    }
    if (mysql_affected_rows(ld) >= 1){
        return 0;
    }else{
        if (update_status <2){
            /* Sleep for 2/3 sec */
            struct timespec sleep;
            sleep.tv_sec = 0;
            sleep.tv_nsec = 666666666;
            nanosleep(&sleep, NULL);
        }else{
            debug_log_message (WARNING, AREA_MAIN,
                "Tried to update MYSQL entry twice, "
                "looks like data to update wasn't inserted\n");
        }
    }
    return 0;
}    

int log_state_drop(MYSQL *ld, connection_t *element, struct log_mysql_params* params)
{
    int mysql_ret;

    /* build sql request */
    char *request = build_insert_request(
            ld, element, 
            TCP_STATE_DROP, "DROP", "UNAUTHENTICATED DROP",params);
    if (request == NULL)
    {
        log_message (SERIOUS_WARNING, AREA_MAIN,
                "Error while building MySQL insert query (state DROP)!");
        return -1;
    }

    /* do query */ 
    mysql_ret = mysql_real_query(ld, request, strlen(request));
    g_free(request);

    /* check request error code */
    if (mysql_ret != 0)
    {
        log_message (SERIOUS_WARNING, AREA_MAIN,
                "Error when inserting data in MySQL: %s\n",
                mysql_error(ld));
        return -1;
    }
    return 0;
}    

MYSQL* get_mysql_handler(struct log_mysql_params* params)
{
    MYSQL *ld = g_private_get (params->mysql_priv);
    if (ld != NULL) {
        return ld;
    }
    
    ld = mysql_conn_init(params);
    if (ld == NULL){
        log_message (SERIOUS_WARNING, AREA_MAIN,
            "Can not initiate MYSQL connection");
        return NULL;
    }
    g_private_set(params->mysql_priv,ld);
    return ld;

}    

G_MODULE_EXPORT gint user_packet_logs (connection_t* element, tcp_state_t state,gpointer params_p)
{
  struct log_mysql_params* params = (struct log_mysql_params*)params_p;
    MYSQL *ld = get_mysql_handler(params);
    if (ld == NULL) {
        return -1;
    }

    /* contruct request */
    switch (state) {
        case TCP_STATE_OPEN:
            return log_state_open(ld, element,params);

        case TCP_STATE_ESTABLISHED: 
            if ((element->tracking).protocol == IPPROTO_TCP){
                return log_state_established(ld, element,params);
            } else {
                return 0;
            }

        case TCP_STATE_CLOSE: 
            if ((element->tracking).protocol == IPPROTO_TCP){
                return log_state_close(ld, element, params);
            } else {
                return 0;
            }

        case TCP_STATE_DROP:
            return log_state_drop(ld, element, params);

        default:
			/* Ignore other states */
            return 0;
    }
}

G_MODULE_EXPORT int user_session_logs(user_session_t *c_session, session_state_t state,gpointer params_p)
{
  struct log_mysql_params* params = (struct log_mysql_params*)params_p;
    char request[LONG_REQUEST_SIZE];
    int mysql_ret;
    MYSQL *ld;
    gboolean ok;
    
    ld = get_mysql_handler(params);
    if (ld == NULL) {
        return -1;
    }

    switch (state) {
        case SESSION_OPEN:
            /* create new user session */
            ok = secure_snprintf(request, sizeof(request),
                    "INSERT INTO %s (user_id, username, ip_saddr, "
                    "os_sysname, os_release, os_version, first_time) "
                    "VALUES ('%lu', '%s', '%u', '%s', '%s', '%s', FROM_UNIXTIME(%lu))",
                    params->mysql_users_table_name,
                    c_session->user_id,
                    c_session->user_name,
                    c_session->addr,
                    c_session->sysname,
                    c_session->release,
                    c_session->version,
                    time(NULL));
            break;
            
        case SESSION_CLOSE:
            /* update existing user session */
            ok = secure_snprintf(request, sizeof(request),
                    "UPDATE %s SET last_time=FROM_UNIXTIME(%lu) "
                    "WHERE ip_saddr=%u",
                    params->mysql_users_table_name,
                    time(NULL),
                    c_session->addr);
            break;

        default:
            return -1;
    }
    if (!ok) {
        return -1;
    }

    /* execute query */
    mysql_ret = mysql_real_query(ld, request, strlen(request));
    if (mysql_ret != 0){
        log_message (SERIOUS_WARNING, AREA_MAIN,
            "Can execute request : %s\n", mysql_error(ld));
        return -1;
    }
    return 1;
}

/** @} */
