/*
 ** Copyright(C) 2004-2008 INL
 ** Written by  Eric Leblond <regit@inl.fr>
 **             Vincent Deffontaines <gryzor@inl.fr>
 **
 ** $Id$
 ** tls.c: Common functions for TLS nufw and user management
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

#include "auth_srv.h"
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <nubase.h>
#include <nussl.h>

/**
 * \addtogroup TLS
 * @{
 */

/* } <- Added to avoid false positive
 * with check_log introduced by the
 * comment just above ;-) */

/**
 * \file nuauth/tls.c
 * \brief Functions use to create/destroy a TLS connection
 *
 * Contain common functions tor TLS handling
 */


/* These are global */
extern struct nuauth_tls_t nuauth_tls;

struct tls_nufw_context_t {
	char *addr;
	char *port;
	int mx;
	int sck_inet;
	fd_set tls_rx_set;	/* read set */
	GMutex *mutex;

	nussl_session *server;
};

void tls_common_init(void)
{

	struct stat stats;

	nuauth_tls.key = nubase_config_table_get_or_default("nuauth_tls_key", NUAUTH_KEYFILE);
	nuauth_tls.cert = nubase_config_table_get_or_default("nuauth_tls_cert", NUAUTH_CERTFILE);
	nuauth_tls.ca = nubase_config_table_get_or_default("nuauth_tls_cacert", NUAUTH_CACERTFILE);
	nuauth_tls.crl_file = nubase_config_table_get("nuauth_tls_crl");
	nuauth_tls.crl_refresh = nubase_config_table_get_or_default_int("nuauth_tls_crl_refresh", DEFAULT_REFRESH_CRL_INTERVAL);
	/* {"nuauth_tls_key_passwd", G_TOKEN_STRING, 0, NULL}, */

	if ( nuauth_tls.crl_file ) {
		log_message(VERBOSE_DEBUG, DEBUG_AREA_GW | DEBUG_AREA_USER,
			"Certificate revocation list: %s",
			nuauth_tls.crl_file);

		if (access(nuauth_tls.crl_file, R_OK)) {
			log_message(WARNING, DEBUG_AREA_MAIN,
				    "TLS : can not access crl file %s",
				    nuauth_tls.crl_file);
			nuauth_ask_exit();
		}

		stat(nuauth_tls.crl_file, &stats);
		nuauth_tls.crl_file_mtime = stats.st_mtime;
	}

}

/*
 * This function is called
 * when NuAuth traps a signal.
 * Which is always the case when the
 * application terminates (since we send it anyway).
 */
void tls_common_deinit(void)
{
#if 0
/* XXX: Of course we must deallocate, but considering the new config API */
	g_free(nuauth_tls.key);
	g_free(nuauth_tls.cert);
	g_free(nuauth_tls.ca);
	g_free(nuauth_tls.crl_file);
#endif
}


void tls_crl_update_each_session(GSList *session)
{

	GSList *listrunner = session;
	int ret;

	while ( listrunner ) {
		struct nuauth_thread_t *nuauth_thread = listrunner->data;
		struct tls_nufw_context_t *context = nuauth_thread->data;

		ret = nussl_ssl_set_crl_file(context->server, nuauth_tls.crl_file);

		if(ret < 0)
		{
			log_area_printf(DEBUG_AREA_GW, DEBUG_LEVEL_CRITICAL,
					"[%i] NuFW TLS: CRL file reloading failed (%s)",
					getpid(), nussl_get_error(context->server));
		}

		listrunner = g_slist_next(listrunner);

	} g_slist_free(listrunner);

}

/**
 * Refresh crl file
 *
 * This function is run periodically because it is pushed with
 * cleanup_func_push() to the list of nuauth periodically run
 * function.
 */
void refresh_crl_file(void)
{
	struct stat stats;

	nuauth_tls.crl_refresh_counter++;
	if (nuauth_tls.crl_refresh == nuauth_tls.crl_refresh_counter) {
		stat(nuauth_tls.crl_file, &stats);

		if (nuauth_tls.crl_file_mtime < stats.st_mtime) {

			tls_crl_update_each_session(nuauthdatas->tls_nufw_servers);
			tls_crl_update_each_session(nuauthdatas->tls_auth_servers);
		}
		nuauth_tls.crl_refresh_counter = 0;
	}

}

/**@}*/
