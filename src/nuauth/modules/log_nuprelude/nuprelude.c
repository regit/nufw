/*
 ** Copyright(C) 2006 INL
 **	written by Victor Stinner <victor.stinner AT haypocalc.com>
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

#include "log_prelude.h"
#include <prelude.h>
#include <prelude-log.h>
#include <idmef-tree-wrap.h>

confparams mysql_nuauth_vars[] = {
    /*    { "prelude_..." , G_TOKEN_STRING, 0 , PRELUDE_... }, */
};

GMutex *global_client_mutex;
prelude_client_t *global_client; /* private pointer for mysql database access */

G_MODULE_EXPORT gchar* module_params_unload(gpointer params_ptr)
{
    return NULL;
}

/**
 * Function called every second to update timer 
 */
void update_prelude_timer()
{
    prelude_timer_wake_up();
}

/**
 * Function called only once: when the module is unloaded.
 *
 * \return NULL
 */ 
G_MODULE_EXPORT void g_module_unload(GModule *module)
{
    log_message(SERIOUS_WARNING, AREA_MAIN, 
            "[+] Prelude log: Close client connection");
    prelude_client_destroy(global_client, PRELUDE_CLIENT_EXIT_STATUS_SUCCESS);
    g_mutex_free(global_client_mutex);

    cleanup_func_remove(update_prelude_timer);

    log_message(SERIOUS_WARNING, AREA_MAIN, 
            "[+] Prelude log: Deinit library");
    prelude_deinit();
}

/**
 * Destroy a private IDMEF message when a thread stops.
 */ 
void destroy_idmef (idmef_message_t *idmef)
{
    idmef_message_destroy(idmef);
}

G_MODULE_EXPORT gboolean init_module_from_conf(module_t *module)
{
    struct log_prelude_params* params=g_new0(struct log_prelude_params, 1);
#if 0
    char *configfile=DEFAULT_CONF_FILE;
    if (params == NULL)
        return FALSE;

    /* parse conf file */
    if (module->configfile){
        parse_conffile(module->configfile,sizeof(mysql_nuauth_vars)/sizeof(confparams),mysql_nuauth_vars);
    } else {
        parse_conffile(configfile,sizeof(mysql_nuauth_vars)/sizeof(confparams),mysql_nuauth_vars);
    }

    params->... = (char *)READ_CONF("prelude_...");
#endif
    params->packet_tpl = g_private_new((GDestroyNotify)destroy_idmef);
    params->session_tpl = g_private_new((GDestroyNotify)destroy_idmef);
    module->params=(gpointer)params;
    return TRUE;
}

static void del_idmef_object(idmef_message_t *message, const char *object)
{
    idmef_value_t *val;
    idmef_path_t *path;
    if ( idmef_path_new(&path, object) < 0) {
        return;
    }
    if (0< idmef_path_get(path, message, &val)) {
        idmef_value_destroy (val);
    }
    idmef_path_destroy(path);
    return;
}

static int add_idmef_object(idmef_message_t *message, const char *object, const char *value)
{
    int ret;
    idmef_value_t *val, *oldval;
    idmef_path_t *path;


    ret = idmef_path_new(&path, object);
    if ( ret < 0 ) {
        log_message(DEBUG, AREA_MAIN, 
                "Prelude: Fail to set attribute %s=%s: %s", 
                object, value,
                prelude_strerror(ret));
        return -1;
    }

    /* remove old value if it does exist */
    ret = idmef_path_get(path, message, &oldval);
    if (0< ret)
    {
        idmef_value_destroy (oldval);
    }

    /* set new value */
    ret = idmef_value_new_from_path(&val, path, value);
    if ( ret < 0 ) {
        log_message(DEBUG, AREA_MAIN, 
                "Prelude: Fail to set attribute %s=%s: %s", object, value,
                prelude_strerror(ret));
        idmef_path_destroy(path);
        return -1;
    }
    ret = idmef_path_set(path, message, val);
    idmef_value_destroy(val);
    idmef_path_destroy(path);
    return ret;
}

int feed_template(idmef_message_t *idmef)
{
#if 0    
    char buffer[50];

    /* analyzer */
    add_idmef_object(idmef, "alert.analyzer.name", "nuauth");
    add_idmef_object(idmef, "alert.analyzer.analyzer.name", "nuauth");
    add_idmef_object(idmef, "alert.analyzer.manufacturer", "http://www.nufw.org/");
    add_idmef_object(idmef, "alert.analyzer.model", "authentification server");
    add_idmef_object(idmef, "alert.analyzer.version", "2.0");
    add_idmef_object(idmef, "alert.analyzer.class", "server");
    add_idmef_object(idmef, "alert.analyzer.ostype", "Linux");
    add_idmef_object(idmef, "alert.analyzer.osversion", "2.6");
    add_idmef_object(idmef, "alert.analyzer.process.name", "nuauth");
    if (secure_snprintf(buffer, sizeof(buffer), "%lu", (unsigned long)getpid())) {
        add_idmef_object(idmef, "alert.analyzer.process.pid", buffer);
    }
#endif
    
    /* source address/service */    
    add_idmef_object(idmef, "alert.source(0).node.address(0).category", "ipv4-addr");
    add_idmef_object(idmef, "alert.source(0).service.ip_version", "4"); 

    /* target address/service */    
    add_idmef_object(idmef, "alert.target(0).node.address(0).category", "ipv4-addr");
    add_idmef_object(idmef, "alert.target(0).service.ip_version", "4"); 

    /* set assessment */
    add_idmef_object(idmef, "alert.assessment.impact.completion", "succeeded"); /* failed | succeeded */
    add_idmef_object(idmef, "alert.assessment.impact.type", "user"); /* admin | dos | file | recon | user | other */
    return 1;
}

idmef_message_t *create_alert_template()
{
    idmef_message_t *idmef;
    int ret;

    ret = idmef_message_new(&idmef);
    if ( ret < 0 ) {
        prelude_perror(ret, "unable to create IDMEF message");
        return NULL;
    }

    ret = feed_template(idmef);
    if (ret < 0) {
        prelude_perror(ret, "unable to create IDMEF message");
        idmef_message_destroy(idmef);
        return NULL;
    }
    return idmef;
}

idmef_message_t *create_packet_template()
{
    idmef_message_t *idmef = create_alert_template();
        
    return idmef;
}

idmef_message_t *create_session_template()
{
    char buffer[50];
    idmef_message_t *idmef = create_alert_template();

    add_idmef_object(idmef, "alert.target(0).process.name", "nuauth");
    if (secure_snprintf(buffer, sizeof(buffer), "%lu", (unsigned long)getpid())) {
        add_idmef_object(idmef, "alert.target(0).process.pid", buffer);
    }

    add_idmef_object(idmef, "alert.source(0).service.protocol", "tcp");
    add_idmef_object(idmef, "alert.source(0).service.name", "nufw-client");
    add_idmef_object(idmef, "alert.source(0).process.name", "nutcpc");

    /* TODO: Maybe write real IPv6 of nuauth :-) */
    add_idmef_object(idmef, "alert.target(0).node.address(0).address", "::1");
    add_idmef_object(idmef, "alert.target(0).service.protocol", "tcp"); 

    if (secure_snprintf(buffer, sizeof(buffer), "%hu", nuauthconf->userpckt_port)) {
        add_idmef_object(idmef, "alert.target(0).service.port", buffer); 
    }

    add_idmef_object(idmef, "alert.additional_data(0).type", "string");
    add_idmef_object(idmef, "alert.additional_data(0).meaning", "OS system name");
    add_idmef_object(idmef, "alert.additional_data(1).type", "string");
    add_idmef_object(idmef, "alert.additional_data(1).meaning", "OS release");
    add_idmef_object(idmef, "alert.additional_data(2).type", "string");
    add_idmef_object(idmef, "alert.additional_data(2).meaning", "OS full version");

    return idmef;
}

idmef_message_t *create_message_packet(
        idmef_message_t *tpl,
        tcp_state_t state, connection_t* conn, 
        char *state_text, char *impact,  char *severity)
{
    idmef_message_t *idmef;
    time_t stdlib_time;
    idmef_time_t *create_time;
    idmef_time_t *detect_time;
    idmef_alert_t *alert;
    int ret;
    char buffer[50];
    char ip_ascii[INET6_ADDRSTRLEN];
    char *tmp_buffer;
    unsigned short psrc, pdst;

    /* duplicate message */
    idmef = idmef_message_ref(tpl);

    ret = idmef_message_new_alert(idmef, &alert);
    if ( ret < 0 ) {
        idmef_message_destroy(idmef);
        return NULL;
    }

    /* set create time */
    ret = idmef_time_new_from_time(&create_time, &conn->timestamp);
    if (ret < 0) {
        idmef_message_destroy(idmef);
        return NULL;
    }
    idmef_alert_set_create_time(alert, create_time);

    /* set detect time */
    ret = idmef_alert_new_detect_time(alert, &detect_time);
    if (ret < 0) {
        idmef_message_destroy(idmef);
        return NULL;
    }
    stdlib_time = time(NULL);
    idmef_time_set_from_time (detect_time, &stdlib_time);

    add_idmef_object(idmef, "alert.classification.text", state_text);
    add_idmef_object(idmef, "alert.assessment.impact.severity", severity); /* info | low | medium | high */
    add_idmef_object(idmef, "alert.assessment.impact.description", impact);

    /* IP source/dest */
    if (inet_ntop(AF_INET6, &conn->tracking.saddr, ip_ascii, sizeof(ip_ascii)) != NULL)
        add_idmef_object(idmef, "alert.source(0).node.address(0).address", ip_ascii);
    if (inet_ntop(AF_INET6, &conn->tracking.saddr, ip_ascii, sizeof(ip_ascii)) != NULL)
        add_idmef_object(idmef, "alert.target(0).node.address(0).address", ip_ascii);
    
    /* IP protocol */
    if (secure_snprintf(buffer, sizeof(buffer), "%hu", conn->tracking.protocol)) {
        add_idmef_object(idmef, "alert.source(0).service.iana_protocol_number", buffer);
        add_idmef_object(idmef, "alert.target(0).service.iana_protocol_number", buffer);
    }
    
    /* TCP/UDP ports */
    if (conn->tracking.protocol == IPPROTO_TCP
            || conn->tracking.protocol == IPPROTO_UDP)
    {
        if ((state == TCP_STATE_ESTABLISHED)/* || (state == TCP_STATE_DROP)*/) {
            psrc = conn->tracking.dest;
            pdst = conn->tracking.source;
        } else {
            psrc = conn->tracking.source;
            pdst = conn->tracking.dest;
        }
        if (secure_snprintf(buffer, sizeof(buffer), "%hu", psrc)) {
            add_idmef_object(idmef, "alert.source(0).service.port", buffer); 
        }
        if (secure_snprintf(buffer, sizeof(buffer), "%hu", pdst)) {
            add_idmef_object(idmef, "alert.target(0).service.port", buffer); 
        }
    } else {
        del_idmef_object(idmef, "alert.source(0).service.port");
        del_idmef_object(idmef, "alert.target(0).service.port");
        if (conn->tracking.protocol == IPPROTO_ICMP) {
            add_idmef_object(idmef, "alert.source(0).service.name", "icmp"); 
            add_idmef_object(idmef, "alert.target(0).service.name", "icmp"); 
        }
    }

    /* user informations */
    if (conn->username != NULL) {
        add_idmef_object(idmef, "alert.source(0).user.user_id(0).type", "current-user");
        add_idmef_object(idmef, "alert.source(0).user.category", "application");  /* os-device */
        add_idmef_object(idmef, "alert.source(0).user.user_id(0).name", conn->username); 
        if (secure_snprintf(buffer, sizeof(buffer), "%lu", conn->user_id)) {
            add_idmef_object(idmef, "alert.source(0).user.user_id(0).number", buffer);
        }
    } else {
        del_idmef_object(idmef, "alert.source(0).user");
    }

    /* source process */
    if (conn->app_name != NULL) {
        tmp_buffer = g_path_get_basename(conn->app_name);
        add_idmef_object(idmef, "alert.source(0).process.name", tmp_buffer);
        g_free(tmp_buffer);
        add_idmef_object(idmef, "alert.source(0).process.path", conn->app_name);
    } else {
        del_idmef_object(idmef, "alert.source(0).process");
    }

    /* os informations */
    if (conn->os_sysname != NULL) {
        add_idmef_object(idmef, "alert.additional_data(0).type", "string");
        add_idmef_object(idmef, "alert.additional_data(0).meaning", "OS system name");
        add_idmef_object(idmef, "alert.additional_data(0).data", conn->os_sysname);
        add_idmef_object(idmef, "alert.additional_data(1).type", "string");
        add_idmef_object(idmef, "alert.additional_data(1).meaning", "OS release");
        add_idmef_object(idmef, "alert.additional_data(1).data", conn->os_release);
        add_idmef_object(idmef, "alert.additional_data(2).type", "string");
        add_idmef_object(idmef, "alert.additional_data(2).meaning", "OS full version");
        add_idmef_object(idmef, "alert.additional_data(2).data", conn->os_version);
    } else {
        del_idmef_object(idmef, "alert.additional_data(0)");
        del_idmef_object(idmef, "alert.additional_data(1)");
        del_idmef_object(idmef, "alert.additional_data(2)");
    }

    return idmef;
}

idmef_message_t *create_message_session(
        idmef_message_t *tpl,
        user_session_t *session,
        char *state_text, char *impact,  char *severity)
{
    idmef_message_t *idmef;
    time_t stdlib_time;
    idmef_time_t *create_time;
    idmef_time_t *detect_time;
    idmef_alert_t *alert;
    int ret;
    char buffer[50];
    char ip_ascii[INET6_ADDRSTRLEN];

    /* duplicate message */
    idmef = idmef_message_ref(tpl);

    ret = idmef_message_new_alert(idmef, &alert);
    if ( ret < 0 ) {
        idmef_message_destroy(idmef);
        return NULL;
    }

    /* set create time */
    stdlib_time = time(NULL);
    idmef_time_new_from_time (&create_time, &stdlib_time);
    if (ret < 0) {
        idmef_message_destroy(idmef);
        return NULL;
    }
    idmef_alert_set_create_time(alert, create_time);

    /* set detect time */
    ret = idmef_alert_new_detect_time(alert, &detect_time);
    if (ret < 0) {
        idmef_message_destroy(idmef);
        return NULL;
    }
    idmef_time_set_from_time (detect_time, &stdlib_time);


    add_idmef_object(idmef, "alert.classification.text", state_text);
    add_idmef_object(idmef, "alert.assessment.impact.severity", severity); /* info | low | medium | high */
    add_idmef_object(idmef, "alert.assessment.impact.description", impact);

    /* source address/service */    
    if (inet_ntop(AF_INET6, &session->addr, ip_ascii, sizeof(ip_ascii)) != NULL)
    {
        add_idmef_object(idmef, "alert.source(0).node.address(0).address", ip_ascii);
    }

    /* set user informations */
    if (session->user_name != NULL) {
        add_idmef_object(idmef, "alert.source(0).user.user_id(0).type", "current-user");
        add_idmef_object(idmef, "alert.source(0).user.category", "application");  /* os-device */
        add_idmef_object(idmef, "alert.source(0).user.user_id(0).name", session->user_name); 
        if (secure_snprintf(buffer, sizeof(buffer), "%lu", session->user_id)) {
            add_idmef_object(idmef, "alert.source(0).user.user_id(0).number", buffer);
        }
    } else {
        del_idmef_object(idmef, "alert.source(0).user");
    }

    /* os informations */
    add_idmef_object(idmef, "alert.additional_data(0).data", session->sysname);
    add_idmef_object(idmef, "alert.additional_data(1).data", session->release);
    add_idmef_object(idmef, "alert.additional_data(2).data", session->version);
    return idmef;
}

G_MODULE_EXPORT gint user_packet_logs (connection_t* element, tcp_state_t state, gpointer params_ptr)
{
    struct log_prelude_params *params = params_ptr;
    idmef_message_t *tpl;
    idmef_message_t *message;
    char *impact;
    char *state_text;
    char *severity;

    impact = "notify connection state change";
    switch (state) {
        case TCP_STATE_OPEN:
            state_text = "Open connection";
            severity = "low";
            break;
        case TCP_STATE_ESTABLISHED: 
            state_text = "Connection established";
            severity = "info";
            break;
        case TCP_STATE_CLOSE: 
            state_text = "Close connection";
            severity = "low";
            break;
        case TCP_STATE_DROP:
            if (element->username != NULL) {
                state_text = "Drop auth connection";
                severity = "high";
            } else {
                state_text = "Drop unauth connection (auth timeout)";
                severity = "medium";
            }
            break;
        default:
            return -1;
            break;
    }

    /* get message template (or create it if needed) */
    tpl = g_private_get(params->packet_tpl);
    if (tpl == NULL) {
        tpl = create_packet_template(); 
        g_private_set(params->packet_tpl, tpl);
    }

    /* feed message fields */
    message = create_message_packet(tpl, state, element, state_text, impact, severity);
    if (message == NULL) {
        return -1;
    }

    /* send message */
    g_mutex_lock(global_client_mutex);
    prelude_client_send_idmef(global_client, message);
    g_mutex_unlock(global_client_mutex);
    idmef_message_destroy(message);
    return 0;
}

G_MODULE_EXPORT int user_session_logs(user_session_t *c_session, session_state_t state,gpointer params_ptr)
{
    struct log_prelude_params *params = params_ptr;
    idmef_message_t *tpl;
    idmef_message_t *message;
    char *impact;
    char *severity;
    char *state_text;

    severity = "low";
    switch (state) {
        case SESSION_OPEN:
            state_text = "user log in";
            impact = "user log in";
            break;
        case SESSION_CLOSE:
            state_text = "user log out";
            impact = "user log out";
            break;
        default:
            return -1;
    }

    /* get message template (or create it if needed) */
    tpl = g_private_get(params->session_tpl);
    if (tpl == NULL) {
        tpl = create_session_template(); 
        g_private_set(params->session_tpl, tpl);
    }

    /* feed message fields */
    message = create_message_session(tpl, c_session, state_text, impact, severity);    
    if (message == NULL) {
        return -1;
    }

    /* send message */
    g_mutex_lock(global_client_mutex);
    prelude_client_send_idmef(global_client, message);
    g_mutex_unlock(global_client_mutex);
    idmef_message_destroy(message);
    return 0;
}

/**
 * Function called only once: when the module is loaded.
 *
 * \return NULL
 */ 
G_MODULE_EXPORT gchar* g_module_check_init()
{
    const char *version;
    int argc;
    char **argv = NULL; 
    int ret;

    log_message(SERIOUS_WARNING, AREA_MAIN, 
            "[+] Prelude log: Init Prelude library");

    version = prelude_check_version (PRELUDE_VERSION_REQUIRE);
    if (version == NULL) {
        log_message(CRITICAL, AREA_MAIN,
                "Fatal error: Prelude module needs prelude version %s (installed version is %s)!", 
                PRELUDE_VERSION_REQUIRE,
                prelude_check_version(NULL));
        exit(EXIT_FAILURE);
    }

    ret = prelude_init(&argc, argv);
    if ( ret < 0 ) {
        log_message(CRITICAL, AREA_MAIN,
                "Fatal error: Fail to init Prelude module: %s!",
                prelude_strerror(ret));
        exit(EXIT_FAILURE);
    }


    log_message(SERIOUS_WARNING, AREA_MAIN, 
            "[+] Prelude log: Open client connection");

    /* Ask Prelude to don't log anything */
    prelude_log_set_flags(PRELUDE_LOG_FLAGS_QUIET);

    /* create a new client */
    global_client_mutex = g_mutex_new();
    ret = prelude_client_new(&global_client, "nufw");
    if ( ! global_client ) {
        log_message(CRITICAL, AREA_MAIN,
                "Fatal error: Unable to create a prelude client object: %s!",
                prelude_strerror(ret));
        exit(EXIT_FAILURE);
    }

    ret = prelude_client_start(global_client);
    if ( ret < 0 ) {
        log_message(CRITICAL, AREA_MAIN,
                "Fatal error: Unable to start prelude client: %s!",
                prelude_strerror(ret));
        exit(EXIT_FAILURE);
    }

    cleanup_func_push(update_prelude_timer);

#if 0
    /* set flags */
    ret = prelude_client_set_flags(global_client, 
            PRELUDE_CLIENT_FLAGS_ASYNC_SEND|PRELUDE_CLIENT_FLAGS_ASYNC_TIMER);
    if ( ret < 0 ) {
        log_message(WARNING, AREA_MAIN,
                "Prelude: Warning, unnable to set asynchronous send and timer: %s",
                prelude_strerror(ret));
    }
#endif

    return NULL;
}

