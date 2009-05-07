/*
 ** Copyright(C) 2009 INL
 ** Written by Eric Leblond <eleblond@inl.fr>
 **
 */

#include <libnuclient.h>
#include <nuclient.h>
#include <nuclient_plugins.h>
#include "nubase.h"
#include "proto.h"

#define MULTI_EXT_NAME "MULTI"
#define MULTI_CONNECT_CMD "CONNECT"
#define MULTI_CONNLIST_CMD "CONNLIST"
#define MULTI_CONNECTED_CMD "CONNECTED"
#define MULTI_DISCONNECTED_CMD "DISCONNECTED"

int multi_connect(char **dbuf, int dbufsize, void *data);
int multi_connlist(char **dbuf, int dbufsize, void *data);

struct proto_ext_t multi_ext = {
	.name = MULTI_EXT_NAME,
	.ncmd = 2,
	.cmd = {
		{
		.cmdname = MULTI_CONNECT_CMD,
		.nargs = 3,
		.callback = &multi_connect,
		},
		{
		.cmdname = MULTI_CONNECTED_CMD,
		.nargs = 0,
		.callback = &multi_connlist,
		},
	}
};

struct llist_head _sec_session_list;

typedef struct _sec_nuauth_session_t {
	struct llist_head list;
	nuauth_session_t *session;
	nuauth_session_t *orig_session;
	conn_t *auth[CONN_MAX];
	/* TODO use define */
	char hostname[128];
	char port[64];
	char net[64];
	int count;
	int retry;
} sec_nuauth_session_t;

static int send_connected(nuauth_session_t *session, sec_nuauth_session_t * ssession, char * state);

static int multi_dispatch(struct nuclient_plugin_t *plugin, unsigned int event_id, nuauth_session_t * session, const char *arg);

int NUCLIENT_PLUGIN_INIT(unsigned int api_num, struct nuclient_plugin_t *plugin)
{
	printf("***********************\n");
	printf("Hello from plugin\n");
	printf("Server API version: 0x%lx\n", (long)api_num);
	printf("Internal API version: 0x%lx\n", (long)PLUGIN_API_NUM);
	printf("Instance name: %s\n", plugin->instance_name);
	printf("***********************\n");

	if (PLUGIN_API_NUM != api_num)
		return -1;

	plugin->dispatch = multi_dispatch;
	plugin->close = NULL;
	//plugin->close = test_close;
	//
	nu_client_set_capability(MULTI_EXT_NAME);
	/* register cruise  protocol extension */
	INIT_LLIST_HEAD(&(multi_ext.list));
	llist_add(&nu_cruise_extproto_l, &(multi_ext.list));

	INIT_LLIST_HEAD(&_sec_session_list);

	return 0;
}

static void clean_ssession(sec_nuauth_session_t *ssession)
{
	/* TODO need to lock to avoid writing on dead session */
	send_connected(ssession->orig_session, ssession, MULTI_DISCONNECTED_CMD);
	nu_client_delete(ssession->session);
	llist_del(&ssession->list);
}

static int multi_send_packet(struct nuclient_plugin_t * plugin, conn_t * arg)
{
	sec_nuauth_session_t *ssession;

	/* iter on secondary session */
	llist_for_each_entry(ssession, &_sec_session_list, list) {
		/* TODO check if net match */
#if 0
		if (net_not_match)
			continue;
#endif
		if (add_packet_to_send
				(ssession->session, (ssession->auth), &(ssession->count),
				 arg) == -1) {
			clean_ssession(ssession);
		}
		/* */
	}
	return 0;
}

static int multi_dispatch(struct nuclient_plugin_t *plugin, unsigned int event_id, nuauth_session_t * session, const char *arg)
{
	sec_nuauth_session_t *ssession;
	switch (event_id) {
		case NUCLIENT_EVENT_NEW_CONNECTION:
		case NUCLIENT_EVENT_RETRANSMIT_CONNECTION:
			/* send bucket to all existing session */
			multi_send_packet(plugin, (conn_t *)arg);
			break;
		case NUCLIENT_EVENT_END_CHECK:
			llist_for_each_entry(ssession, &_sec_session_list, list) {
				if (ssession->count > 0) {
					if (ssession->count < CONN_MAX) {
						ssession->auth[ssession->count] = NULL;
					}
					if (send_user_pckt(ssession->session, ssession->auth) != 1) {
						/* error sending */
						clean_ssession(ssession);
						return 0;
					}
					ssession->count = 0;
					ssession->auth[0] = NULL;
					ssession->retry = 0;
				} else {
					if (ssession->retry++ > 5) {
						if (! send_hello_pckt(ssession->session)) {
							clean_ssession(ssession);
							return 0;
						}
						ssession->retry = 0;
					}
				}

			}
		break;
		default:
			/* simply ignoring event */
			break;
	}
	return 0;
}

static int send_connected(nuauth_session_t *session, sec_nuauth_session_t * ssession, char * state)
{
	char buf[1024];
	struct nu_header * header = (struct nu_header *) buf;
	char * enc_field = buf + sizeof(* header);
	int ret;

	header->proto = PROTO_VERSION;
	header->msg_type = EXTENDED_PROTO;
	header->option = 0;

	ret = snprintf(enc_field, sizeof(buf) - sizeof(*header),
				"BEGIN\n" MULTI_EXT_NAME "\n%s %s\nEND\n",
				state,
				ssession->hostname);

	header->length = htons(sizeof(*header) + ret);

	ret = nussl_write(session->nussl, buf, ntohs(header->length));
	if (ret < 0) {
		if (session->verbose)
			printf("Error sending tls data: ...");
		clean_ssession(ssession);
		return 0;
	}
	return 1;
}


static int authenticate_all_conn(nuauth_session_t *session,
				 sec_nuauth_session_t * ssession)
{
	int i;
	int count = 0;
	conn_t *auth[CONN_MAX];
	for (i = 0; i < CONNTABLE_BUCKETS; i++) {
		conn_t *bucket;

		bucket = session->ct->buckets[i];
		while (bucket != NULL) {
			if (add_packet_to_send(session, auth, &count,
					 bucket) == -1) {
				/* problem when sending we exit */
				clean_ssession(ssession);
				return -1;
			}

		}
	}

	if (count > 0) {
		if (count < CONN_MAX) {
			auth[count] = NULL;
		}
		if (send_user_pckt(session, auth) != 1) {
			/* error sending */
			clean_ssession(ssession);
			return -1;
		}
	}

	return 0;

}

/**
 * Create the username information packet and send it to nuauth.
 * Packet is in format ::nuv2_authfield.
 *
 * \param session Pointer to client session
 * \param err Pointer to a nuclient_error_t: which contains the error
 */

int multi_connect(char **dbuf,int dbufsize, void *data)
{
	nuauth_session_t * session = (nuauth_session_t *) data;
	sec_nuauth_session_t * ssession;
	sec_nuauth_session_t * psession;

	ssession = calloc(1, sizeof(*ssession));
	/* get IP from command */
	sscanf(*dbuf, "%s", ssession->hostname);
	*dbuf += strlen(ssession->hostname);
	sscanf(*dbuf, "%s", ssession->port);
	/* try to get optional net */
	if (dbuf[strlen(ssession->port)] != 0) {
		*dbuf += strlen(ssession->port);
		sscanf(*dbuf, "%s", ssession->net);
	} else {
		ssession->net[0] = 0;
	}
	/* initiate connection to IP if needed */
	llist_for_each_entry(psession, &_sec_session_list, list) {
		if (!strcmp(psession->hostname, ssession->hostname)) {
			if (!strcmp(psession->port, ssession->port)) {
				free(ssession);
				return 0;
			}
		}
	}

	ssession->orig_session = session;
	ssession->session = nu_client_new(session->username, session->password, 0, NULL);
	/* TLS setup */
	nu_client_set_key(ssession->session, session->pem_key, session->pem_cert, NULL);
	nu_client_set_ca(ssession->session, session->pem_ca, NULL);
	ssession->session->suppress_fqdn_verif = session->suppress_fqdn_verif;
	/* connection */
	nu_client_connect(ssession->session, ssession->hostname, ssession->port, NULL);
	/* initiate list entry */
	INIT_LLIST_HEAD(&(ssession->list));
	/* add entry to the list */
	llist_add(&_sec_session_list, &(ssession->list));
	/* send connected message in reply */
	send_connected(session, ssession, MULTI_CONNECTED_CMD);

	/* authenticate all needed connection at start */
	authenticate_all_conn(session, ssession);

	return 0;
}

int multi_connlist(char **dbuf,int dbufsize, void *data)
{
	nuauth_session_t * session = (nuauth_session_t *) data;
	sec_nuauth_session_t * ssession;
	int ret;

	llist_for_each_entry(ssession, &_sec_session_list, list) {
		if ((ret = send_connected(session, ssession, MULTI_CONNECTED_CMD)) != 1) {
			return ret;
		}
	}

	return 1;
}
