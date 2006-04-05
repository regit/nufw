/*
 ** Copyright(C) 2003-2006 Victor Stinner <victor.stinner AT haypocalc.com>
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
#include <idmef-tree-wrap.h>

confparams mysql_nuauth_vars[] = {
/*    { "prelude_..." , G_TOKEN_STRING, 0 , PRELUDE_... }, */
};

/**
 * Get the client handler. If this function is called for the first time, 
 * init Prelude library and then create the client connection.
 */
prelude_client_t *get_client(struct log_prelude_params* params)
{
    const char *version;
    int argc;
    char **argv = NULL; 
    int ret;

    prelude_client_t *client = g_private_get (params->client);
    if (client != NULL) {
        return client;
    }

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
                "Fatal error: Fail to init Prelude module!");
        exit(EXIT_FAILURE);
    }

    log_message(SERIOUS_WARNING, AREA_MAIN, 
            "[+] Prelude log: Open client connection to Prelude manager");

    ret = prelude_client_new(&client, "nufw");
    if ( ! client ) {
        log_message(CRITICAL, AREA_MAIN,
                "Fatal error: Unable to create a prelude client object!");
        exit(EXIT_FAILURE);
    }

    ret = prelude_client_start(client);
    if ( ret < 0 ) {
        log_message(CRITICAL, AREA_MAIN,
                "Fatal error: Unable to start prelude client!");
        prelude_deinit();
        exit(EXIT_FAILURE);
    }

    g_private_set(params->client, client);
    return client;
}    

void close_prelude_client(void *data)
{
    prelude_client_t *client = (prelude_client_t *)data;
    log_message(SERIOUS_WARNING, AREA_MAIN, 
            "[+] Prelude log: close client connection and deinit library");
    prelude_client_destroy(client, PRELUDE_CLIENT_EXIT_STATUS_SUCCESS);
    prelude_deinit();
}

G_MODULE_EXPORT gchar* module_params_unload(gpointer params_ptr)
{
    struct log_prelude_params* params = (struct log_prelude_params*)params_ptr;

    if (params == NULL) {
        return NULL;
    }
    
    prelude_client_t *client = g_private_get (params->client);
    if (client != NULL)
    {
        close_prelude_client(client);
        g_private_set(params->client, NULL);
    }
    g_free(params);
    return NULL;
}

G_MODULE_EXPORT gboolean 
init_module_from_conf(module_t *module)
{
    char *configfile=DEFAULT_CONF_FILE;
    struct log_prelude_params* params=g_new0(struct log_prelude_params, 1);
    if (params == NULL)
        return FALSE;
    params->client = g_private_new(close_prelude_client);

    /* parse conf file */
    if (module->configfile){
        parse_conffile(module->configfile,sizeof(mysql_nuauth_vars)/sizeof(confparams),mysql_nuauth_vars);
    } else {
        parse_conffile(configfile,sizeof(mysql_nuauth_vars)/sizeof(confparams),mysql_nuauth_vars);
    }
    
/*    params->... = (char *)READ_CONF("prelude_..."); */
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
                    "Prelude: Fail to set attribute %s=%s", object, value);
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
                    "Prelude: Fail to set attribute %s=%s", object, value);
            idmef_path_destroy(path);
            return -1;
        }
        ret = idmef_path_set(path, message, val);
        idmef_value_destroy(val);
        idmef_path_destroy(path);
        return ret;
}

int feed_message(idmef_message_t *idmef)
{
    /* source address/service */    
    add_idmef_object(idmef, "alert.source(0).node.address(0).category", "ipv4-addr");
    add_idmef_object(idmef, "alert.source(0).service.ip_version", "4"); 

    /* target address/service */    
    add_idmef_object(idmef, "alert.target(0).node.address(0).category", "ipv4-addr");
    add_idmef_object(idmef, "alert.target(0).service.ip_version", "4"); 
    add_idmef_object(idmef, "alert.target(0).process.name", "nuauth");

    /* set assessment */
    add_idmef_object(idmef, "alert.assessment.impact.completion", "succeeded"); /* failed | succeeded */
    add_idmef_object(idmef, "alert.assessment.impact.type", "user"); /* admin | dos | file | recon | user | other */
/*    add_idmef_object(idmef, "alert.assessment.action.category", "block-installed"); */ /* block-installed | notification-sent | taken-offline | other */

    /* user */
/*    add_idmef_object(idmef, "alert.source(0).user.UserId(0).name", "haypo"); 
    add_idmef_object(idmef, "alert.source(0).user.UserId(0).number", "1000");  */
    return 1;
}

idmef_message_t *create_message_template()
{
    idmef_message_t *idmef;
    int ret;

    ret = idmef_message_new(&idmef);
    if ( ret < 0 ) {
        prelude_perror(ret, "unable to create IDMEF message");
        return NULL;
    }

    ret = feed_message(idmef);
    if (ret < 0) {
        prelude_perror(ret, "unable to create IDMEF message");
        idmef_message_destroy(idmef);
        return NULL;
    }
    return idmef;
}

idmef_message_t *create_message_packet(idmef_message_t *template,
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
    struct in_addr ipaddr;
    char *tmp_buffer;
    unsigned short psrc, pdst;

/*     idmef_data_copy_ref and idmef_data_copy_dup should help you */
/*    idmef_stuff_ref() */

    /* duplicate message */
    if (template == NULL) {
        return template;
    }
    idmef = idmef_message_ref(template);

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
    
    if ((state == TCP_STATE_ESTABLISHED) || (state == TCP_STATE_DROP)) {
        psrc = conn->tracking.dest;
        pdst = conn->tracking.source;
    } else {
        psrc = conn->tracking.source;
        pdst = conn->tracking.dest;
    }

    /* source address/service */    
    ipaddr.s_addr = ntohl(conn->tracking.saddr);
    add_idmef_object(idmef, "alert.source(0).node.address(0).address", inet_ntoa(ipaddr));
    if (secure_snprintf(buffer, sizeof(buffer), "%hu", conn->tracking.protocol)) {
        add_idmef_object(idmef, "alert.source(0).service.iana_protocol_number", buffer);
    }
    if (secure_snprintf(buffer, sizeof(buffer), "%hu", psrc))
            add_idmef_object(idmef, "alert.source(0).service.port", buffer); 

    /* target address/service */    
    ipaddr.s_addr = ntohl(conn->tracking.daddr);
    add_idmef_object(idmef, "alert.target(0).node.address(0).address", inet_ntoa(ipaddr));
    add_idmef_object(idmef, "alert.target(0).service.protocol", "tcp"); 
    if (secure_snprintf(buffer, sizeof(buffer), "%hu", pdst))
        add_idmef_object(idmef, "alert.target(0).service.port", buffer); 

    /* source process */
    if (conn->app_name != NULL) {
        tmp_buffer = g_path_get_basename(conn->app_name);
        add_idmef_object(idmef, "alert.source(0).process.name", tmp_buffer);
        g_free(tmp_buffer);
        add_idmef_object(idmef, "alert.source(0).process.path", conn->app_name);
    } else {
        del_idmef_object(idmef, "alert.source(0).process.name");
        del_idmef_object(idmef, "alert.source(0).process.path");
    }
    return idmef;
}

idmef_message_t *create_message_session(idmef_message_t *template,
        user_session *session,
        char *state_text, char *impact,  char *severity)
{
    idmef_message_t *idmef;
    time_t stdlib_time;
    idmef_time_t *create_time;
    idmef_time_t *detect_time;
    idmef_alert_t *alert;
    int ret;
    char buffer[50];
    struct in_addr ipaddr;

/*     idmef_data_copy_ref and idmef_data_copy_dup should help you */
/*    idmef_stuff_ref() */

    /* duplicate message */
    if (template == NULL) {
        return template;
    }
    idmef = idmef_message_ref(template);

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
    ipaddr.s_addr = session->addr;
    add_idmef_object(idmef, "alert.source(0).node.address(0).address", inet_ntoa(ipaddr));
    add_idmef_object(idmef, "alert.source(0).service.protocol", "tcp");
    add_idmef_object(idmef, "alert.source(0).process.name", "nutcpc");

    /* target address/service */    
    inet_aton("127.0.0.1", &ipaddr);
    add_idmef_object(idmef, "alert.target(0).node.address(0).address", inet_ntoa(ipaddr));
    add_idmef_object(idmef, "alert.target(0).service.protocol", "tcp"); 
    if (secure_snprintf(buffer, sizeof(buffer), "%hu", nuauthconf->userpckt_port))
        add_idmef_object(idmef, "alert.target(0).service.port", buffer); 

    return idmef;
}

G_MODULE_EXPORT gint user_packet_logs (connection_t* element, tcp_state_t state, gpointer params_p)
{
    prelude_client_t *client = get_client(params_p);
    idmef_message_t *message;
    idmef_message_t *tpl;
    char *impact;
    char *state_text;
    char *severity;

    if (client == NULL)
        return -1;

    tpl = create_message_template();
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
            state_text = "Drop connection";
            severity = "medium";
            break;
        default:
            return -1;
            break;
    }

    message = create_message_packet(tpl, state, element, state_text, impact, severity);
    if (message == NULL) {
        return -1;
    }

    prelude_client_send_idmef(client, message);
    idmef_message_destroy(message);
    idmef_message_destroy(tpl);

    return 0;
}

G_MODULE_EXPORT int user_session_logs(user_session *c_session, session_state_t state,gpointer params_p)
{
    idmef_message_t *message;
    idmef_message_t *tpl;
    char *impact;
    char *severity;
    char *state_text;

    prelude_client_t *client = get_client(params_p);
    if (client == NULL)
        return -1;

    tpl = create_message_template();
   
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
/*                    c_session->user_id,
                    c_session->user_name,
                    c_session->addr,
                    c_session->sysname,
                    c_session->release,
                    c_session->version, */
    }
    
    message = create_message_session(tpl, c_session, state_text, impact, severity);    
    if (message == NULL) {
        return -1;
    }
    prelude_client_send_idmef(client, message);
    idmef_message_destroy(message);
    idmef_message_destroy(tpl);
    return 0;
}

