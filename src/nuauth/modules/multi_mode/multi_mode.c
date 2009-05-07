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

#define MULTI_EXT_NAME "MULTI"
#define MULTI_CONNECT_CMD "CONNECT"
#define MULTI_CONNLIST_CMD "CONNLIST"
#define MULTI_CONNECTED_CMD "CONNECTED"

struct multi_mode_params {
	/* FIXME switch to list */
	gchar *emc_node;
	/* session to EMC */
	nussl_session *nussl;
	/* multi capability index */
	unsigned char capa_index;

	int is_connected;
};

static int connect_to_emc(struct multi_mode_params *params);

/*
 * Returns version of nuauth API
 */
G_MODULE_EXPORT uint32_t get_api_version()
{
	return NUAUTH_API_VERSION;
}


G_MODULE_EXPORT gchar *unload_module_with_params(gpointer params_p)
{
	struct multi_mode_params *params =
	    (struct multi_mode_params *) params_p;

	/* FIXME close EMC thread */
	g_free(params->emc_node);
	g_free(params);

	return NULL;
}

G_MODULE_EXPORT gboolean init_module_from_conf(module_t * module)
{
	struct multi_mode_params *params =
	    g_new0(struct multi_mode_params, 1);

	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
		    "multi_mode module ($Revision$)");

	params->emc_node = nuauth_config_table_get_or_default("multi_mode_emc_node", EMC_NODE);

	if (register_client_capa("MULTI", &(params->capa_index)) != NU_EXIT_OK) {
		log_message(WARNING, DEBUG_AREA_MAIN,
			    "Unable to register capability MULTI");
		return FALSE;
	}

	module->params = (gpointer) params;

	/* register protocol function */

	/* start EMC connected thread */
	/* XXX use a thread */
	connect_to_emc(params);

	return TRUE;
}

static int connect_to_emc(struct multi_mode_params *params)
{
	int ret;
	int exit_on_error = 0;
	int port = 4140; // XXX hardcoded value
	int suppress_cert_verif = 1; // XXX hardcoded value

	if (params->nussl) {
		return -1;
	}

	params->nussl = nussl_session_create(NUSSL_SSL_CTX_CLIENT);

	if (nuauth_tls.cert != NULL || nuauth_tls.key != NULL) {
		ret = nussl_ssl_set_keypair(params->nussl, nuauth_tls.cert, nuauth_tls.key);

		if (ret != NUSSL_OK) {
				printf("Warning: Failed to load default certificate and key.\n");
		}
	}
	if (nuauth_tls.ca != NULL) {
		ret = nussl_ssl_trust_cert_file(params->nussl, nuauth_tls.ca);
		if (ret != NUSSL_OK) {
			if (exit_on_error) {
				log_message(FATAL, DEBUG_AREA_MAIN,
						"Unable to set CA");
				return -1;
			}
			else {
				fprintf(stderr,"\nWARNING: you have not provided any certificate authority.\n"
						"multi_mode will *NOT* verify server certificate trust.\n"
						"Use the -A <cafile> option to set up CA.\n\n"
				       );
				//session->suppress_fqdn_verif = 1;
				nussl_set_session_flag(params->nussl, NUSSL_SESSFLAG_IGNORE_ID_MISMATCH, 1);
			}
		}
	}

	if (nuauth_tls.crl_file != NULL) {
		ret = nussl_ssl_set_crl_file(params->nussl, nuauth_tls.crl_file, nuauth_tls.ca);
		if (ret != NUSSL_OK) {
			fprintf(stderr,"TLS error with CRL: %s",
				nussl_get_error(params->nussl));
			return 0;
		}
		printf("Using crl: %s\n", nuauth_tls.crl_file);
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

	ret = nussl_open_connection(params->nussl);
	if (ret != NUSSL_OK) {
		nussl_session_destroy(params->nussl);
		params->nussl = NULL;
		log_message(FATAL, DEBUG_AREA_MAIN,
				"Could not open connection");
		return -1;
	}

	{
		const char text[] = "Hello from multi_mode";
		struct nu_header msg;

		msg.proto = PROTO_VERSION_EMC_V1;
		msg.msg_type = EMC_HELLO;
		msg.option = 0;
		msg.length = strlen(text);

		nussl_write(params->nussl, (char*)&msg, sizeof(msg));
		nussl_write(params->nussl, text, sizeof(text));
	}

	params->is_connected = 1;

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
				"BEGIN\n" MULTI_EXT_NAME "\n" MULTI_CONNECTED_CMD " %s\nEND\n",
				connect_string);

	header->length = sizeof(struct nu_header) + ret;
	header->length = htons(header->length);

	global_msg.msg = (struct nu_srv_message *) header;
	global_msg.addr = *saddr;
	global_msg.found = FALSE;

	warn_clients(&global_msg, capa_check, params);
}


void emc_thread(void *params_p )
{
	struct multi_mode_params *params =
	    (struct multi_mode_params *) params_p;
	/* connect to EMC via nussl */
	connect_to_emc(params);
	/* "endless" loop */

#if 0
	while ( ) {
	/* get data */
		bufsize = nussl_read(session->nussl, buf, sizeof(buf));
		if (bufsize <= 0) {
			/* error */
			connect_to_emc(params);
		}
		switch (message->type) {
	/* if connection asked */
			case SRV_REQUIRED_INFO:
	/*	test if there is a user at IP */

	/*	send connection request if necessary */
	multi_warn_clients(saddr, conninfo, params);


	/*	else forget packet */
	}
#endif
}


/**
 * @{ */

G_MODULE_EXPORT gchar *ip_authentication(tracking_t * header,
					 struct multi_mode_params *
					 params)
{
	/* test if source is not a direct net */

	/* if not in direct net send packet to EMC */

	return NULL;
}

/** @} */
