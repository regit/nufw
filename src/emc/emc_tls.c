/*
 ** Copyright(C) 2009 INL
 ** Written by Pierre Chifflier <chifflier@inl.fr>
 **     INL : http://www.inl.fr/
 **
 ** All rights reserved.
 **
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

int emc_init_tls(struct emc_tls_server_context *ctx)
{
	char *tls_cert;
	char *tls_key;
	char *tls_ca;
	char *tls_capath;
	char *tls_crl;
	char *tls_ciphers;
	int request_cert = 1; /* XXX hardcoded value, should be 2 (request cert) */
	int ret;
	char *tls_dh_file;

	tls_cert    = emc_config_table_get_or_default("emc_tls_cert",NULL);
	tls_key     = emc_config_table_get_or_default("emc_tls_key",NULL);
	tls_ca      = emc_config_table_get_or_default("emc_tls_ca",NULL);
	tls_capath  = emc_config_table_get("emc_tls_capath");
	tls_crl     = emc_config_table_get("emc_tls_crl");
	tls_ciphers = emc_config_table_get("emc_tls_ciphers");
	tls_dh_file = emc_config_table_get("emc_tls_dh_file");

	ctx->nussl = nussl_session_create_with_fd(ctx->server_sock, request_cert);

	ret = nussl_ssl_set_keypair(ctx->nussl, tls_cert, tls_key);
	if (ret != NUSSL_OK) {
		log_printf(DEBUG_LEVEL_FATAL, "ERROR Failed to load user key/certificate: %s",
			    nussl_get_error(ctx->nussl));
		return -1;
	}

	ret = nussl_ssl_trust_cert_file(ctx->nussl, tls_ca);
	if (ret != NUSSL_OK) {
		log_printf(DEBUG_LEVEL_FATAL, "ERROR Failed to load user certificate authority: %s",
			    nussl_get_error(ctx->nussl));
		return -1;
	}

	if (tls_capath) {
		ret = nussl_ssl_trust_dir(ctx->nussl, tls_capath);
		if (ret != NUSSL_OK) {
			log_printf(DEBUG_LEVEL_FATAL,
					"ERROR Failed to load user certificate authority directory: %s",
					nussl_get_error(ctx->nussl));
			return -1;
		}
	}

	if (tls_crl) {
		ret = nussl_ssl_set_crl_file(ctx->nussl, tls_crl, tls_ca);
		if (ret != NUSSL_OK) {
			log_printf(DEBUG_LEVEL_FATAL,
					"ERROR Failed to load certificate revocation list (CRL): %s",
					nussl_get_error(ctx->nussl));
			return -1;
		}
	}

	if (tls_ciphers) {
		nussl_session_set_ciphers(ctx->nussl, tls_ciphers);
	}

	if (tls_dh_file == NULL || nussl_session_set_dh_file(ctx->nussl, tls_dh_file) != NUSSL_OK) {
		log_printf(DEBUG_LEVEL_WARNING, "WARNING Unable to read Diffie Hellman params file.");
		if (nussl_session_set_dh_bits(ctx->nussl, DH_BITS) != NUSSL_OK) {
			log_printf(DEBUG_LEVEL_FATAL, "ERROR Unable to generate Diffie Hellman params.");
			return -1;
		}
	}

	return 0;
}

