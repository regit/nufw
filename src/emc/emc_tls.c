/*
 ** Copyright(C) 2009 INL
 ** Written by Pierre Chifflier <chifflier@inl.fr>
 **     INL : http://www.inl.fr/
 **
 ** $Id$
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

#include <config.h>

#include <unistd.h>
#include <string.h>

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif

#include <nussl.h>

#include <nubase.h>
#include <config-parser.h>

#include "emc_server.h"
#include "emc_config.h"
#include "emc_tls.h"

int emc_init_tls(struct emc_server_context *ctx)
{
	char *tls_cert;
	char *tls_key;
	char *tls_ca;
	char *tls_capath;
	char *tls_crl;
	char *tls_ciphers;
	int request_cert = 1; /* XXX hardcoded value, should be 2 (request cert) */
	int ret;

	tls_cert    = emc_config_table_get_or_default("emc_tls_cert",NULL);
	tls_key     = emc_config_table_get_or_default("emc_tls_key",NULL);
	tls_ca      = emc_config_table_get_or_default("emc_tls_ca",NULL);
	tls_capath  = emc_config_table_get("emc_tls_capath");
	tls_crl     = emc_config_table_get("emc_tls_crl");
	tls_ciphers = emc_config_table_get("emc_tls_ciphers");

	ctx->nussl = nussl_session_create_with_fd(ctx->server_sock, request_cert);

	if (nussl_session_set_dh_bits(ctx->nussl, DH_BITS) != NUSSL_OK) {
		fprintf(stderr, "ERROR Unable to initialize Diffie Hellman params.\n");
		return -1;
	}

	ret = nussl_ssl_set_keypair(ctx->nussl, tls_cert, tls_key);
	if (ret != NUSSL_OK) {
		fprintf(stderr, "ERROR Failed to load user key/certificate: %s\n",
			    nussl_get_error(ctx->nussl));
		return -1;
	}

	ret = nussl_ssl_trust_cert_file(ctx->nussl, tls_ca);
	if (ret != NUSSL_OK) {
		fprintf(stderr, "ERROR Failed to load user certificate authority: %s\n",
			    nussl_get_error(ctx->nussl));
		return -1;
	}

	if (tls_capath) {
		ret = nussl_ssl_trust_dir(ctx->nussl, tls_capath);
		if (ret != NUSSL_OK) {
			fprintf(stderr,
					"ERROR Failed to load user certificate authority directory: %s\n",
					nussl_get_error(ctx->nussl));
			return -1;
		}
	}

	if (tls_crl) {
		ret = nussl_ssl_set_crl_file(ctx->nussl, tls_crl, tls_ca);
		if (ret != NUSSL_OK) {
			fprintf(stderr,
					"ERROR Failed to load certificate revocation list (CRL): %s\n",
					nussl_get_error(ctx->nussl));
			return -1;
		}
	}

	if (tls_ciphers) {
		nussl_session_set_ciphers(ctx->nussl, tls_ciphers);
	}

	return 0;
}

