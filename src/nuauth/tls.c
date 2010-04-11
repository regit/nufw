/*
 ** Copyright(C) 2004-2009 INL
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

#include "nuauthconf.h"

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

void tls_common_init(void)
{

	struct stat stats;

	nuauth_tls.key = nuauth_config_table_get_or_default("nuauth_tls_key", NUAUTH_KEYFILE);
	nuauth_tls.cert = nuauth_config_table_get_or_default("nuauth_tls_cert", NUAUTH_CERTFILE);
	nuauth_tls.ca = nuauth_config_table_get_or_default("nuauth_tls_cacert", NUAUTH_CACERTFILE);
	nuauth_tls.capath = nuauth_config_table_get("nuauth_tls_ca_path");
	nuauth_tls.crl_file = nuauth_config_table_get("nuauth_tls_crl");
	nuauth_tls.crl_refresh = nuauth_config_table_get_or_default_int("nuauth_tls_crl_refresh", DEFAULT_REFRESH_CRL_INTERVAL);
	nuauth_tls.ciphers = nuauth_config_table_get("nuauth_tls_ciphers");
	/* {"nuauth_tls_key_passwd", G_TOKEN_STRING, 0, NULL}, */

	log_message(VERBOSE_DEBUG, DEBUG_AREA_GW | DEBUG_AREA_USER,
			"Certificate authority: %s", nuauth_tls.ca);
	log_message(VERBOSE_DEBUG, DEBUG_AREA_GW | DEBUG_AREA_USER,
			"Server certificate: %s", nuauth_tls.cert);
	log_message(VERBOSE_DEBUG, DEBUG_AREA_GW | DEBUG_AREA_USER,
			"Server certificate key: %s", nuauth_tls.key);

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
	} else {
		g_warning ("[%i] nuauth: no revocation list configured.\n",
			getpid());
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

/**
 * Refresh crl file
 *
 * This function is run periodically because it is pushed with
 * cleanup_func_push() to the list of nuauth periodically run
 * function.
 */
void refresh_crl_file(void)
{
	nuauth_tls.crl_refresh_counter++;
	if (nuauth_tls.crl_refresh == nuauth_tls.crl_refresh_counter) {
		force_refresh_crl_file();
	}

}

void force_refresh_crl_file(void)
{
	struct stat stats;

	if (nuauth_tls.crl_file == NULL)
		return;
	if (stat(nuauth_tls.crl_file, &stats) < 0)
		return;

	if (nuauth_tls.crl_file_mtime < stats.st_mtime) {
		tls_crl_update_nufw_session(nuauthdatas->tls_nufw_servers);
		tls_crl_update_user_session(nuauthdatas->tls_auth_servers);
		nuauth_tls.crl_file_mtime = stats.st_mtime;
	}
	nuauth_tls.crl_refresh_counter = 0;
}

/**@}*/
