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

	confparams_t nuauth_tls_vars[] = {
		{"nuauth_tls_key", G_TOKEN_STRING, 0,
		 g_strdup(NUAUTH_KEYFILE)},
		{"nuauth_tls_cert", G_TOKEN_STRING, 0,
		 g_strdup(NUAUTH_CERTFILE)},
		{"nuauth_tls_cacert", G_TOKEN_STRING, 0,
		 g_strdup(NUAUTH_CACERTFILE)},
		{"nuauth_tls_crl", G_TOKEN_STRING, 0, NULL},
		{"nuauth_tls_crl_refresh", G_TOKEN_INT,
		 DEFAULT_REFRESH_CRL_INTERVAL, NULL},
		{"nuauth_tls_key_passwd", G_TOKEN_STRING, 0, NULL},
	};
	const unsigned int nb_params = sizeof(nuauth_tls_vars) / sizeof(confparams_t);

	if(!parse_conffile(DEFAULT_CONF_FILE, nb_params, nuauth_tls_vars))
	{
	        log_message(FATAL, DEBUG_AREA_MAIN, "Failed to load config file %s", DEFAULT_CONF_FILE);
		return;
	}

#define READ_CONF(KEY) \
	get_confvar_value(nuauth_tls_vars, nb_params, KEY)

	nuauth_tls.key = (char *) READ_CONF("nuauth_tls_key");
	nuauth_tls.cert = (char *) READ_CONF("nuauth_tls_cert");
	nuauth_tls.ca = (char *) READ_CONF("nuauth_tls_cacert");
	nuauth_tls.crl_file = (char *) READ_CONF("nuauth_tls_crl");
	nuauth_tls.crl_refresh = *(int *) READ_CONF("nuauth_tls_crl_refresh");

#undef READ_CONF

	if ( nuauth_tls.crl_file ) {
		log_message(VERBOSE_DEBUG, DEBUG_AREA_GW | DEBUG_AREA_USER,
			"Certificate revocation list: %s",
			nuauth_tls.crl_file);

		if (access(nuauth_tls.crl_file, R_OK)) {
			g_warning("[%i] TLS : can not access crl file %s",
			getpid(), nuauth_tls.crl_file);
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
	g_free(nuauth_tls.key);
	g_free(nuauth_tls.cert);
	g_free(nuauth_tls.ca);
	g_free(nuauth_tls.crl_file);
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
	GSList *listrunner = nuauthdatas->tls_nufw_servers;

	nuauth_tls.crl_refresh_counter++;
	if (nuauth_tls.crl_refresh == nuauth_tls.crl_refresh_counter) {
		while (listrunner) {
			struct stat stats;
			stat(nuauth_tls.crl_file, &stats);

			if (nuauth_tls.crl_file_mtime < stats.st_mtime) {
				struct nuauth_thread_t *nuauth_thread = listrunner->data;
				struct tls_nufw_context_t *context = nuauth_thread->data;
				int ret;
			//	printf("server addr: %s\n", context->addr);
				ret = nussl_ssl_set_crl_file(context->server, nuauth_tls.crl_file);

				if(ret < 0)
				{
					log_area_printf(DEBUG_AREA_GW, DEBUG_LEVEL_CRITICAL,
							"[%i] NuFW TLS: CRL file reloading failed (%s)",
							getpid(), nussl_get_error(context->server));
				}

			}

			listrunner = g_slist_next(listrunner);
		}
		nuauth_tls.crl_refresh_counter = 0;
	}
	g_slist_free(listrunner);

}

/**@}*/
