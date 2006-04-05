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

    version = prelude_check_version (PRELUDE_VERSION_REQUIRE);
    if (version == NULL) {
        printf("need prelude version %s (installed version is %s).\n", 
                PRELUDE_VERSION_REQUIRE,
                prelude_check_version(NULL));
        return NULL;
    }
    
    ret = prelude_init(&argc, argv);
    if ( ret < 0 ) {
        prelude_perror(ret, "unable to initialize the prelude library");
        return NULL;
    }


    ret = prelude_client_new(&client, "nufw");
    if ( ! client ) {
        prelude_perror(ret, "Unable to create a prelude client object");
        return NULL;
    }

    ret = prelude_client_start(client);
    if ( ret < 0 ) {
        prelude_perror(ret, "Unable to start prelude client");
        prelude_deinit();
        return NULL;
    }

    g_private_set(params->client, client);
    return client;
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
        prelude_client_destroy(client, PRELUDE_CLIENT_EXIT_STATUS_SUCCESS);
        prelude_deinit();
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

static int add_idmef_object(idmef_message_t *message, const char *object, const char *value)
{
        int ret;
        idmef_value_t *val, *oldval;
        idmef_path_t *path;
        
        
        ret = idmef_path_new(&path, object);
        if ( ret < 0 ) {
            printf("FAIL %s=%s\n", object, value);
            return -1;
        }

        ret = idmef_value_new_from_path(&val, path, value);
        if ( ret < 0 ) {
            printf("Fails to set %s message attribute to %s!\n", object, value);
            idmef_path_destroy(path);
            return -1;
        }

        ret = idmef_path_get(path, message, &oldval);
        if (0< ret)
        {
            idmef_value_destroy (oldval);
        }
        ret = idmef_path_set(path, message, val);

        idmef_value_destroy(val);
        idmef_path_destroy(path);
        
        return ret;
}

int feed_message(idmef_message_t *idmef)
{
    /* classification */
    add_idmef_object(idmef, "alert.classification.text", "Reject connection");
    add_idmef_object(idmef, "alert.classification.reference(0).origin", "user-specific"); 
    add_idmef_object(idmef, "alert.classification.reference(0).name", "NuFW-U001");
    add_idmef_object(idmef, "alert.classification.reference(0).url", "http://www.nufw.org/attack.php?code=U001");

    /* source address/service */    
    add_idmef_object(idmef, "alert.source(0).interface", "eth0");
    add_idmef_object(idmef, "alert.source(0).node.address(0).category", "ipv4-addr");
    add_idmef_object(idmef, "alert.source(0).service.ip_version", "4"); 

    /* target address/service */    
    add_idmef_object(idmef, "alert.target(0).interface", "eth1");
    add_idmef_object(idmef, "alert.target(0).node.address(0).category", "ipv4-addr");
    add_idmef_object(idmef, "alert.target(0).service.ip_version", "4"); 

    /* target process */
    add_idmef_object(idmef, "alert.target(0).process.name", "ssh");
    add_idmef_object(idmef, "alert.target(0).process.path", "/usr/bin/ssh");
    add_idmef_object(idmef, "alert.target(0).process.pid", "34");
   
    /* set assessment */
    add_idmef_object(idmef, "alert.assessment.impact.severity", "high"); /* info | low | medium | high */
    add_idmef_object(idmef, "alert.assessment.impact.completion", "succeeded"); /* failed | succeeded */
    add_idmef_object(idmef, "alert.assessment.impact.type", "user"); /* admin | dos | file | recon | user | other */
    add_idmef_object(idmef, "alert.assessment.impact.description", "nufw description of impact");
    add_idmef_object(idmef, "alert.assessment.action.category", "block-installed"); /* block-installed | notification-sent | taken-offline | other */

    /* set additionnal data */
    add_idmef_object(idmef, "alert.additional_data(0).data", "My name is Bond");
    add_idmef_object(idmef, "alert.additional_data(1).data", "James Bond");

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

idmef_message_t *create_message(idmef_message_t *template, connection_t* conn)
{
    idmef_message_t *idmef;
    time_t stdlib_time;
    idmef_time_t *create_time;
    idmef_time_t *detect_time;
    idmef_alert_t *alert;
    int ret;
    char buffer[50];
    static int time_diff = 0;
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
    stdlib_time -= 5;
    stdlib_time += time_diff;
    time_diff += 5;
    ret = idmef_time_new_from_time(&create_time, &stdlib_time);
    if (ret < 0) {
        idmef_message_destroy(idmef);
        return NULL;
    }
    idmef_alert_set_create_time(alert, create_time);

    /* set detect time */
    stdlib_time += 5;    
    ret = idmef_alert_new_detect_time(alert, &detect_time);
    if (ret < 0) {
        idmef_message_destroy(idmef);
        return NULL;
    }
    idmef_time_set_from_time (detect_time, &stdlib_time);

    /* source address/service */    
    ipaddr.s_addr = ntohl(conn->tracking.saddr);
    add_idmef_object(idmef, "alert.source(0).node.address(0).address", inet_ntoa(ipaddr));
    add_idmef_object(idmef, "alert.source(0).service.protocol", "tcp");
    if (secure_snprintf(buffer, sizeof(buffer), "%hu", conn->tracking.source))
            add_idmef_object(idmef, "alert.source(0).service.port", buffer); 

    /* target address/service */    
    ipaddr.s_addr = ntohl(conn->tracking.daddr);
    add_idmef_object(idmef, "alert.target(0).node.address(0).address", inet_ntoa(ipaddr));
    add_idmef_object(idmef, "alert.target(0).service.protocol", "tcp"); 
    if (secure_snprintf(buffer, sizeof(buffer), "%hu", conn->tracking.dest))
        add_idmef_object(idmef, "alert.target(0).service.port", buffer); 

    /* source process */
    add_idmef_object(idmef, "alert.source(0).process.name", "ssh");
    add_idmef_object(idmef, "alert.source(0).process.path", "/usr/bin/ssh");
    add_idmef_object(idmef, "alert.source(0).process.pid", "7874");
    return idmef;
}

G_MODULE_EXPORT gint user_packet_logs (connection_t* element, tcp_state_t state, gpointer params_p)
{
    prelude_client_t *client = get_client(params_p);
    idmef_message_t *message;
    idmef_message_t *tpl;

    if (client == NULL)
        return -1;

    tpl = create_message_template();
    message = create_message(tpl, element);
    if (message == NULL) {
        return -1;
    }

    switch (state) {
        case TCP_STATE_OPEN:
        case TCP_STATE_ESTABLISHED: 
        case TCP_STATE_CLOSE: 
        case TCP_STATE_DROP:
        default:
            /*
               element->timestamp,
               (long unsigned int)(element->tracking).saddr,
               (long unsigned int)(element->tracking).daddr,
               (element->tracking).source,
               (element->tracking).dest,
               */
            break;
    }

    prelude_client_send_idmef(client, message);
    idmef_message_destroy(message);
    idmef_message_destroy(tpl);

    return 0;
}

G_MODULE_EXPORT int user_session_logs(user_session *c_session, session_state_t state,gpointer params_p)
{
#if 0    
    idmef_message_t *message;
    idmef_message_t *tpl;
    prelude_client_t *client = get_client(params_p);
    if (client == NULL)
        return -1;

    tpl = create_message_template();
    message = create_message_session(tpl, c_session);
    if (message == NULL) {
        return -1;
    }
    
    switch (state) {
        case SESSION_OPEN:
        case SESSION_CLOSE:
        default:
/*                    c_session->user_id,
                    c_session->user_name,
                    c_session->addr,
                    c_session->sysname,
                    c_session->release,
                    c_session->version, */
            break;
    }

    prelude_client_send_idmef(client, message);
    idmef_message_destroy(message);
    idmef_message_destroy(tpl);
#endif    
    return 0;
}

