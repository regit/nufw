/*
 ** Copyright(C) 2009 INL
 ** Written by Eric Leblond <eleblond@inl.fr>
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
 **
 */

#include <libnuclient.h>
#include <nuclient.h>
#include <nuclient_plugins.h>
#include "nubase.h"
#include "proto.h"

#define LUSER_EXT_NAME "LUSER"
#define LUSER_USER_CMD "LOCALUSER"

int send_username(char **dbuf, int dbufsize, void *data);
int send_username_cruise(char **dbuf, int dbufsize, void *data);

struct proto_ext_t localuser_ext = {
	.name = LUSER_EXT_NAME,
	.ncmd = 1,
	.cmd = {
		{
		.cmdname = LUSER_USER_CMD,
		.nargs = 0,
		.callback = &send_username,
		},
	}
};

struct proto_ext_t cr_localuser_ext = {
	.name = LUSER_EXT_NAME,
	.ncmd = 1,
	.cmd = {
		{
		.cmdname = LUSER_USER_CMD,
		.nargs = 0,
		.callback = &send_username_cruise,
		},
	}
};

static int test_dispatch(struct nuclient_plugin_t *plugin, unsigned int event_id, nuauth_session_t * session, const char *arg);

int NUCLIENT_PLUGIN_INIT(unsigned int api_num, struct nuclient_plugin_t *plugin)
{
	printf("***********************\n");
	printf("Hello from plugin\n");
	printf("Server API version: 0x%lx\n", api_num);
	printf("Internal API version: 0x%lx\n", PLUGIN_API_NUM);
	printf("Instance name: %s\n", plugin->instance_name);
	printf("***********************\n");

	if (PLUGIN_API_NUM != api_num)
		return -1;

	plugin->dispatch = test_dispatch;
	plugin->close = NULL;
	//plugin->close = test_close;
	//
	nu_client_set_capability(LUSER_EXT_NAME);
	/* register postauth protocol extension */
	INIT_LLIST_HEAD(&(localuser_ext.list));
	llist_add(&nu_postauth_extproto_l, &(localuser_ext.list));

	/* register cruise protocol extension */
	INIT_LLIST_HEAD(&(cr_localuser_ext.list));
	llist_add(&nu_cruise_extproto_l, &(cr_localuser_ext.list));

	return 0;
}

static int test_dispatch(struct nuclient_plugin_t *plugin, unsigned int event_id, nuauth_session_t * session, const char *arg)
{
	printf("plugin dispatch function called, event %d\n", event_id);
	return 0;
}

/**
 * Create the username information packet and send it to nuauth.
 * Packet is in format ::nuv2_authfield.
 *
 * \param session Pointer to client session
 * \param err Pointer to a nuclient_error_t: which contains the error
 */

int send_username(char **dbuf,int dbufsize, void *data)
{
	nuauth_session_t * session = (nuauth_session_t *) data;
	char buf[1024];
	struct nu_authfield *vfield = (struct nu_authfield *) buf;
	char *enc_capa = buf + sizeof(struct nu_authfield);
	char buffer[512];
	struct passwd result_buf;
	struct passwd *result_bufp = NULL;
	int ret;

	ret = getpwuid_r(getuid(), &result_buf, buffer, sizeof(buffer),
		       &result_bufp);
	if (ret != 0) {
		/*
		SET_ERROR(err, NUSSL_ERR, ret);
		*/
		return 0;
	}
	ret = snprintf(enc_capa, sizeof(buf) - sizeof(*vfield),
				"BEGIN\n" LUSER_EXT_NAME "\n" LUSER_USER_CMD " %s\nEND\n",
				result_bufp->pw_name);

	/* build packet header */
	vfield->type = EXTENDED_PROTO_FIELD;
	vfield->option = 0;
	vfield->length = sizeof(struct nu_authfield) + ret;

	/* add packet body */
	vfield->length = htons(vfield->length);

	/* Send capabilities field over network */
	ret = nussl_write(session->nussl, buf, ntohs(vfield->length));
	if (ret < 0) {
		if (session->verbose)
			printf("Error sending tls data: ...");
		/*
		SET_ERROR(err, NUSSL_ERR, ret);
		*/
		return 0;
	}

	return 1;
}

int send_username_cruise(char **dbuf,int dbufsize, void *data)
{
	nuauth_session_t * session = (nuauth_session_t *) data;
	char buf[1024];
	struct nu_header *header;
	char *enc_capa = buf + sizeof(struct nu_header);
	char buffer[512];
	struct passwd result_buf;
	struct passwd *result_bufp = NULL;
	int ret;

	header = (struct nu_header *) buf;
	header->proto = PROTO_VERSION;
	header->msg_type = EXTENDED_PROTO;
	header->option = 0;

	ret = getpwuid_r(getuid(), &result_buf, buffer, sizeof(buffer),
		       &result_bufp);
	if (ret != 0) {
		/*
		SET_ERROR(err, NUSSL_ERR, ret);
		*/
		return 0;
	}
	ret = snprintf(enc_capa, sizeof(buf) - sizeof(*header),
				"BEGIN\n" LUSER_EXT_NAME "\n" LUSER_USER_CMD " %s\nEND\n",
				result_bufp->pw_name);

	header->length = sizeof(struct nu_header) + ret;

	/* add packet body */
	header->length = htons(header->length);

	/* Send capabilities field over network */
	ret = nussl_write(session->nussl, buf, ntohs(header->length));
	if (ret < 0) {
		if (session->verbose)
			printf("Error sending tls data: ...");
		/*
		SET_ERROR(err, NUSSL_ERR, ret);
		*/
		return 0;
	}

	return 1;
}
