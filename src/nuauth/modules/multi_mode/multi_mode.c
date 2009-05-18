/*
 ** Copyright(C) 2009 INL
 ** written by Eric Leblond <eleblond@inl.fr>
 **            Pierre Chifflier <chifflier@inl.fr>
 **
  */
#include <auth_srv.h>

#include <nussl.h>

#include <proto.h>
#include <emc_proto.h>

#include "nuauthconf.h"

extern struct nuauth_tls_t nuauth_tls;

/**
 * \ingroup NuauthModules
 */

#define EMC_NODE "127.0.0.1"
#define NUAUTH_EMC_CONNINFO "192.168.33.184 4129"

#define MULTI_EXT_NAME "MULTI"
#define MULTI_CONNECT_CMD "CONNECT"
#define MULTI_CONNLIST_CMD "CONNLIST"
#define MULTI_CONNECTED_CMD "CONNECTED"
#define MULTI_DISCONNECTED_CMD "DISCONNECTED"

static int connect_info(char **buf, int bufsize, void *data);
static int disconnect_info(char **buf, int bufsize, void *data);

struct proto_ext_t _multi_ext = {
	.name = MULTI_EXT_NAME,
	.ncmd = 2,
	.cmd = {
		{
		.cmdname = MULTI_CONNECTED_CMD,
		.nargs = 1,
		.callback = &connect_info,
		},
		{
		.cmdname = MULTI_DISCONNECTED_CMD,
		.nargs = 1,
		.callback = &disconnect_info,
		},

	}
};



#define NUAUTH_EMC_KEYFILE CONFIG_DIR "/nuauth-emc-key.pem"
#define NUAUTH_EMC_CERTFILE CONFIG_DIR "/nuauth-emc-cert.pem"
#define NUAUTH_EMC_CAFILE CONFIG_DIR "/NuFW-cacert.pem"
#define MULTI_INACTIVITY_DELAY 30

struct multi_mode_params {
	/* FIXME switch to list */
	gchar *emc_node;
	struct nuauth_thread_t emc_thread;
	/* session to EMC */
	nussl_session *nussl;
	/* multi capability index */
	unsigned int capa_index;
	unsigned int secondary_index;
	char * tls_key;
	char * tls_cert;
	char * tls_ca;
	char * conninfo;

	int is_connected;
};

unsigned int secondary_index;

static int connect_to_emc(struct multi_mode_params *params);
static void *emc_thread(struct nuauth_thread_t *data);

/*
 * Returns version of nuauth API
 */
G_MODULE_EXPORT uint32_t get_api_version()
{
	return NUAUTH_API_VERSION;
}

static gboolean is_inactive_client(gpointer key,
			   gpointer value, gpointer user_data)
{
	if (! (((user_session_t *) value)->capa_flags & (1 << secondary_index))) {
		return FALSE;
	}

	if (((user_session_t *) value)->last_request <
			(*(time_t *) user_data - MULTI_INACTIVITY_DELAY)) {
		return TRUE;
	}
	return FALSE;
}

static void clean_inactive_session()
{
	time_t current_time = time(NULL);
	clean_client_session_bycallback(is_inactive_client, &current_time);
}



G_MODULE_EXPORT gchar *unload_module_with_params(gpointer params_p)
{
	struct multi_mode_params *params =
	    (struct multi_mode_params *) params_p;

	thread_stop(&(params->emc_thread));
	nussl_session_destroy(params->nussl);
	g_free(params->emc_node);
	g_free(params);

	cleanup_func_remove(&clean_inactive_session);

	if (unregister_protocol_extension(&_multi_ext) != NU_EXIT_OK) {
		log_message(WARNING, DEBUG_AREA_MAIN,
			    "Unable to unregister protocol extension for MULTI");
		return NULL;
	}

	return NULL;
}

G_MODULE_EXPORT gboolean init_module_from_conf(module_t * module)
{
	struct multi_mode_params *params =
	    g_new0(struct multi_mode_params, 1);

	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
		    "multi_mode module ($Revision$)");

	params->emc_node = nuauth_config_table_get_or_default("multi_mode_emc_node", EMC_NODE);
	params->tls_key = nuauth_config_table_get_or_default("nuauth_emc_tls_key", NUAUTH_EMC_KEYFILE);
	params->tls_cert = nuauth_config_table_get_or_default("nuauth_emc_tls_cert", NUAUTH_EMC_CERTFILE);
	params->tls_ca = nuauth_config_table_get_or_default("nuauth_emc_tls_cacert", NUAUTH_EMC_CAFILE);
	params->conninfo = nuauth_config_table_get_or_default("nuauth_emc_conninfo", NUAUTH_EMC_CONNINFO);


	if (register_client_capa("MULTI", &(params->capa_index)) != NU_EXIT_OK) {
		log_message(WARNING, DEBUG_AREA_MAIN,
			    "Unable to register capability MULTI");
		return FALSE;
	}
	if (register_client_capa("SECONDARY", &secondary_index) != NU_EXIT_OK) {
		log_message(WARNING, DEBUG_AREA_MAIN,
			    "Unable to register capability SECONDARY");
		return FALSE;
	}

	module->params = (gpointer) params;

	if (register_protocol_extension(nuauthdatas, &_multi_ext) != NU_EXIT_OK) {
		log_message(WARNING, DEBUG_AREA_MAIN,
			    "Unable to register protocol extension for MULTI");
		return FALSE;
	}

	cleanup_func_push(&clean_inactive_session);

	/* start EMC connected thread */
	thread_new_wdata(&(params->emc_thread), "multi_mode EMC thread", params, &emc_thread);

	return TRUE;
}

static int connect_to_emc(struct multi_mode_params *params)
{
	int ret;
	int port = 4140; // XXX hardcoded value
	int suppress_cert_verif = 1; // XXX hardcoded value

	if (params->nussl) {
		return -1;
	}

	params->nussl = nussl_session_create(NUSSL_SSL_CTX_CLIENT);

	ret = nussl_ssl_set_keypair(params->nussl, params->tls_cert, params->tls_key);

	if (ret != NUSSL_OK) {
		log_message(FATAL, DEBUG_AREA_MAIN,
				"Warning: Failed to load default certificate and key.\n");
		nussl_session_destroy(params->nussl);
		params->nussl = NULL;
		return -1;
	}
	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
			"multi_mode Using certificate: %s key %s",
			params->tls_cert, params->tls_key);

	if (params->tls_ca != NULL) {
		ret = nussl_ssl_trust_cert_file(params->nussl, params->tls_ca);
		if (ret != NUSSL_OK) {
			log_message(FATAL, DEBUG_AREA_MAIN,
					"multi_mode Unable to load certificate authority, aborting");
			return -1;
		}
	} else {
		log_message(WARNING, DEBUG_AREA_MAIN,
				"\nWARNING: you have not provided any certificate authority.\n"
				"multi_mode will *NOT* verify server certificate trust.\n"
				"Use the -A <cafile> option to set up CA.\n\n"
		       );
		//session->suppress_fqdn_verif = 1;
		nussl_set_session_flag(params->nussl, NUSSL_SESSFLAG_IGNORE_ID_MISMATCH, 1);
	}
	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
			"multi_mode Using CA: %s",
			params->tls_ca);


	if (nuauth_tls.crl_file != NULL) {
		ret = nussl_ssl_set_crl_file(params->nussl, nuauth_tls.crl_file, nuauth_tls.ca);
		if (ret != NUSSL_OK) {
			log_message(FATAL, DEBUG_AREA_MAIN,
					"TLS error with CRL: %s", nussl_get_error(params->nussl));
			return -1;
		}
		log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
				"multi_mode Using crl: %s", nuauth_tls.crl_file);
	}




	if (suppress_cert_verif)
		nussl_ssl_disable_certificate_check(params->nussl,1);

#if 0
	if (session->suppress_fqdn_verif)
		nussl_set_session_flag(session->nussl, NUSSL_SESSFLAG_IGNORE_ID_MISMATCH, 1);

	if (session->pkcs12_file) {
		if (!nu_client_load_pkcs12(session, session->pkcs12_file, session->pkcs12_password, err))
			return 0;
	} else {
		if (!nu_client_load_key(session, session->pem_key, session->pem_cert, err))
			return 0;
	}

	if (!nu_client_load_ca(session, session->pem_ca, err))
		return 0;

	if (session->pem_crl) {
		if (!nu_client_load_crl(session, session->pem_crl, session->pem_ca, err))
			return 0;
	}
#endif

	nussl_set_hostinfo(params->nussl, params->emc_node, port);

	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
		    "multi_mode connecting to EMC node %s:%d", params->emc_node, port);

	ret = nussl_open_connection(params->nussl);
	if (ret != NUSSL_OK) {
		nussl_close_connection(params->nussl);
		params->nussl = NULL;
		log_message(WARNING, DEBUG_AREA_MAIN,
				"Could not open connection to EMC node %s:%d", params->emc_node, port);
		return -1;
	}

	{
		char text[] = "Hello from multi_mode";
		struct nu_header msg;

		msg.proto = PROTO_VERSION_EMC_V1;
		msg.msg_type = EMC_HELLO;
		msg.option = 0;
		msg.length = htons(strlen(text));

		nussl_write(params->nussl, (char*)&msg, sizeof(msg));
		nussl_write(params->nussl, text, strlen(text));
	}

	params->is_connected = 1;

	log_message(INFO, DEBUG_AREA_MAIN,
		    "multi_mode connected to EMC node %s:%d", params->emc_node, port);

	return 1;
}

static gboolean capa_check(user_session_t *session, gpointer data)
{
	struct multi_mode_params *params =
	    (struct multi_mode_params *) data;
	if (session->capa_flags & (1 << params->capa_index)) {
		return TRUE;
	}
	return FALSE;
}

static void multi_warn_clients(struct in6_addr *saddr,
			      const char *connect_string,
			      struct multi_mode_params *params
			      )
{
	char buf[1024];
	struct nu_header * header = (struct nu_header *) buf;
	char * enc_field = buf + sizeof(* header);
	struct msg_addr_set global_msg;
	int ret;

	header->proto = PROTO_VERSION;
	header->msg_type = EXTENDED_PROTO;
	header->option = 0;

	ret = snprintf(enc_field, sizeof(buf) - sizeof(*header),
				"BEGIN\n" MULTI_EXT_NAME "\n" MULTI_CONNECT_CMD " %s\nEND\n",
				connect_string);

	header->length = sizeof(struct nu_header) + ret;
	header->length = htons(header->length);

	global_msg.msg = (struct nu_srv_message *) header;
	global_msg.addr = *saddr;
	global_msg.found = FALSE;

	warn_clients(&global_msg, &capa_check, params);
}


static void* emc_thread(struct nuauth_thread_t *thread)
{
	struct multi_mode_params *params =
	    (struct multi_mode_params *) thread->data;
	fd_set wk_set;		/* working set */
	int mx = 0;
	int bufsize;
	int ret;
	char buf[1024];
	char data[1024];
	int len;
	struct nu_header *msg = (struct nu_header *) buf;
	struct in6_addr saddr;
	struct in_addr paddr;
	char *conninfo;
	char client_addr[1024];

	/* "endless" loop */
	while (g_mutex_trylock(thread->mutex)) {
		g_mutex_unlock(thread->mutex);

		if (params->nussl == NULL) {
			do {
				ret = connect_to_emc(params);
				if (ret < 0) {
					params->nussl = NULL;
					sleep(2);
				}
			} while (ret < 0);
			mx = nussl_session_get_fd(params->nussl);

		}
		FD_ZERO(&wk_set);
		FD_SET(mx, &wk_set);
		ret = select(mx + 1, &wk_set, NULL, NULL, NULL);
		if (ret == -1) {
			nussl_close_connection(params->nussl);
			params->nussl = NULL;
			params->is_connected = 0;
			continue;
		}
		/* get data */
		bufsize = nussl_read(params->nussl, buf, sizeof(buf));
		if (bufsize <= 0) {
			nussl_close_connection(params->nussl);
			params->nussl = NULL;
			params->is_connected = 0;
			continue;
		}

		log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
				"msg: proto=%d, type=%d, option=%d, length=%d",
				msg->proto, msg->msg_type, msg->option, ntohs(msg->length));
		len = nussl_read(params->nussl, data, ntohs(msg->length));
		if (bufsize <= 0) {
			nussl_close_connection(params->nussl);
			params->nussl = NULL;
			params->is_connected = 0;
			continue;
		}

		data[len] = '\0';
		log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
				"msg: data=%s",
				data);

		/* parse message */
		if (msg->msg_type != EMC_CLIENT_CONNECTION_REQUEST) {
			log_message(WARNING, DEBUG_AREA_MAIN,
					"multi: invalid message type %d", msg->msg_type);
			continue;
		}

		/* build saddr */
		sscanf(data, "%s", client_addr);
		inet_aton(client_addr, &paddr);
		uint32_to_ipv6(paddr.s_addr, &saddr);

		/* build conninfo */
		conninfo = data + strlen(client_addr) + 1;;

		multi_warn_clients(&saddr, conninfo, params);
	/*	else forget packet */
	}
	return NULL;
}


static int connect_info(char **buf, int bufsize, void *data)
{
	struct tls_buffer_read * tdata = (struct tls_buffer_read *) data;

	/* TODO handle connection list to be able to work nice
	 * on multiuser systems */

	log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
		    "Secondary session for user \"%s\" to %s", tdata->user_name, *buf);
	*buf = *buf + strlen(*buf);

	return SASL_OK;
}

static int disconnect_info(char **buf, int bufsize, void *data)
{
	struct tls_buffer_read * tdata = (struct tls_buffer_read *) data;

	/* TODO handle connection list to be able to work nice
	 * on multiuser systems */

	log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
		    "End of secondary session for user \"%s\" to %s", tdata->user_name, *buf);
	*buf = *buf + strlen(*buf);

	return SASL_OK;
}



/**
 * @{ */

G_MODULE_EXPORT gchar *ip_authentication(auth_pckt_t * pckt,
					 struct multi_mode_params *
					 params)
{
	char buf[1024];
	struct nu_header *msg = (struct nu_header *) buf;
	tracking_t * header = & pckt->header;
	char connbuffer[1024];

	/* TODO test if source is not a direct net */

	/* if not in direct net send packet to EMC */
	format_ipv6(&header->saddr, connbuffer, sizeof(connbuffer), NULL);
	connbuffer[strlen(connbuffer)] = ' ';
	connbuffer[strlen(connbuffer) + 1] = '\0';
	strcat(connbuffer, params->conninfo);

	log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
		"connbuffer: [%s]", connbuffer);

	msg->proto = PROTO_VERSION_EMC_V1;
	msg->msg_type = EMC_CLIENT_CONNECTION_REQUEST;
	msg->option = 0;
	msg->length = htons(strlen(connbuffer));

	nussl_write(params->nussl, (char*)msg, sizeof(struct nu_header));
	nussl_write(params->nussl, connbuffer, strlen(connbuffer));


	return NULL;
}

/** @} */
