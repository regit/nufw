/*
 ** Copyright(C) 2009 INL
 ** written by Eric Leblond <eleblond@inl.fr>
 **            Pierre Chifflier <chifflier@inl.fr>
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation, version 3 of the License.
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

#include <nussl.h>

#include <emc_proto.h>

#include "nuauthconf.h"

extern struct nuauth_tls_t nuauth_tls;

/**
 * \ingroup NuauthModules
 */

#define EMC_NODE "127.0.0.1"

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
		struct emc_message_header_t msg;

		msg.command = EMC_HELLO;
		msg.length = strlen(text);

		nussl_write(params->nussl, (char*)&msg, sizeof(msg));
		nussl_write(params->nussl, text, sizeof(text));
	}

	params->is_connected = 1;

	return 1;
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
	global_msg->addr =
		((tracking_t *) message->datas)->saddr;
	global_msg->found = FALSE;
	/* search in client array */
	ask_clients_connection(global_msg, params);


	/*	else forget packet */
	}
#endif
}

/**
 * Ask each client of global_msg address set to send their new connections
 * (connections in stage "SYN SENT").
 *
 * \param global_msg Address set of clients
 * \return Returns 0 on error, 1 otherwise
 */
char ask_clients_connection(struct msg_addr_set *global_msg, gpointer params_p)
{
	struct multi_mode_params *params =
	    (struct multi_mode_params *) params_p;
#if 0
	ip_sessions_t *ipsessions = NULL;
	GSList *ipsockets = NULL;
	GSList *badsockets = NULL;
	struct timeval timestamp;
	struct timeval interval;
#if DEBUG_ENABLE
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG, DEBUG_AREA_USER)) {
		char addr_ascii[INET6_ADDRSTRLEN];
		format_ipv6(&global_msg->addr, addr_ascii, INET6_ADDRSTRLEN, NULL);
		g_message("Warn client(s) on IP %s", addr_ascii);
	}
#endif

	g_mutex_lock(client_mutex);
	ipsessions = g_hash_table_lookup(client_ip_hash, &global_msg->addr);
	if (ipsessions) {
		global_msg->found = TRUE;
		gettimeofday(&timestamp, NULL);

		if (ipsessions->proto_version >= PROTO_VERSION_V22_1) {
			timeval_substract(&interval, &timestamp, &(ipsessions->last_message));
			if (interval.tv_sec || (interval.tv_usec < nuauthconf->push_delay)) {
				g_mutex_unlock(client_mutex);
				return 1;
			} else {
				ipsessions->last_message.tv_sec = timestamp.tv_sec;
				ipsessions->last_message.tv_usec = timestamp.tv_usec;
			}
		}

		for (ipsockets = ipsessions->sessions; ipsockets; ipsockets = ipsockets->next) {
			user_session_t *session = (user_session_t *)ipsockets->data;
			/* check if client has MULTI capability */
			if (session->capa_flags & (1 << params->capa_index)) {
				int ret;
				ret = nussl_write(session->nussl,
						(char*)global_msg->msg,
						ntohs(global_msg->msg->length));
				if (ret < 0) {
					log_message(WARNING, DEBUG_AREA_USER,
							"Failed to send warning to client(s): %s", nussl_get_error(session->nussl));
					badsockets = g_slist_prepend(badsockets, GINT_TO_POINTER(ipsockets->data));
				}
			}
		}
		if (badsockets) {
			for (; badsockets; badsockets = badsockets->next) {
				int sockno = GPOINTER_TO_INT(badsockets->data);
				nu_error_t ret = delete_client_by_socket_ext(sockno, 0);
				if (ret != NU_EXIT_OK) {
					log_message(WARNING, DEBUG_AREA_USER,
						"Fails to destroy socket in hash.");
				}
			}
			g_slist_free(badsockets);
		}
		g_mutex_unlock(client_mutex);
		return 1;
	} else {
		global_msg->found = FALSE;
		g_mutex_unlock(client_mutex);
		return 0;
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
