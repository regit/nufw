#include <prelude.h>
#include <idmef-tree-wrap.h>
#include <stdio.h>

#define PRELUDE_VERSION_REQUIRE "0.9.0"

#if 0
static int add_idmef_object(idmef_message_t *message, const char *object, const char *value)
{
        int ret;
        idmef_value_t *val;
        idmef_path_t *path;
        
        ret = idmef_path_new(&path, object);
        if ( ret < 0 )
                return -1;

        ret = idmef_value_new_from_path(&val, path, value);
        if ( ret < 0 ) {
                idmef_path_destroy(path);
                return -1;
        }

        ret = idmef_path_set(path, message, val);

        idmef_value_destroy(val);
        idmef_path_destroy(path);
        
        return ret;
}

    add_idmef_object(idmef, "alert.classification.text", "My classification text");
    add_idmef_object(idmef, "alert.classification.reference(0).name", "OSVDB-XXXX");
    add_idmef_object(idmef, "alert.classification.reference(0).origin", "osvdb");
    add_idmef_object(idmef, "alert.classification.reference(0).url", "http://my.url/");
#endif

idmef_message_t *create_message()
{
    idmef_message_t *idmef;
    idmef_alert_t *alert;
    idmef_classification_t *class;
    prelude_string_t *str;
    int ret;

    ret = idmef_message_new(&idmef);
    if ( ret < 0 ) {
        prelude_perror(ret, "unable to create IDMEF message");
        idmef_alert_destroy (alert);
        return NULL;
    }

    ret = idmef_message_new_alert(idmef, &alert);
    if ( ret < 0 ) {
        prelude_perror(ret, "unable to create IDMEF alert");
        idmef_message_destroy(idmef);
        return NULL;
    }

    ret = idmef_alert_new_classification(alert, &class);
    if ( ret < 0 ) {
        prelude_perror(ret, "unable to create IDMEF classification");
        idmef_message_destroy(idmef);
        return NULL;
    }

    ret = idmef_classification_new_text(class, &str);
    if ( ret < 0 ) {
        prelude_perror(ret, "unable to create classification text");
        idmef_message_destroy(idmef);
        return NULL;
    }

    prelude_string_set_constant(str, "My classification");

    return idmef;
}

int main(int argc, char **argv)
{
    int ret;
    prelude_client_t *client;
    idmef_message_t *message;
    const char *version;

    version = prelude_check_version (PRELUDE_VERSION_REQUIRE);
    if (version == NULL) {
        printf("need prelude version %s (installed version is %s).\n", 
                PRELUDE_VERSION_REQUIRE,
                prelude_check_version(NULL));
        return -1;
    }
    
    ret = prelude_init(&argc, argv);
    if ( ret < 0 ) {
        prelude_perror(ret, "unable to initialize the prelude library");
        return -1;
    }


    ret = prelude_client_new(&client, "nufw");
    if ( ! client ) {
        prelude_perror(ret, "Unable to create a prelude client object");
        return -1;
    }

    ret = prelude_client_start(client);
    if ( ret < 0 ) {
        prelude_perror(ret, "Unable to start prelude client");
        prelude_deinit();
        return -1;
    }

    ret = prelude_client_set_flags(client, PRELUDE_CLIENT_FLAGS_ASYNC_SEND|PRELUDE_CLIENT_FLAGS_ASYNC_TIMER);
    if ( ret < 0 ) {
        fprintf(stderr, "Unable to set asynchronous send and timer.\n");
        prelude_deinit();
        return -1;
    }

    message = create_message();
    if (message != NULL) {
        printf("Send message\n");
        prelude_client_send_idmef(client, message);
        idmef_message_destroy(message);
    } else {
        printf("Fail to gen. message\n");
    }

    prelude_client_destroy(client, PRELUDE_CLIENT_EXIT_STATUS_SUCCESS);
    
    prelude_deinit();
    
    printf("ok\n");
    return 0;
}
