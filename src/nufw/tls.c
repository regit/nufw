/*
 ** Copyright (C) 2002-2005 INL
 ** Written by Éric Leblond <eric@regit.org>
 **            Vincent Deffontaines <vincent@gryzor.com>
 ** INL http://www.inl.fr/
 **
 ** $Id$
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
 */


#include "nufw.h"
#include <gnutls/x509.h>

/**
 * \file nufw/tls.c
 * \brief Create a TLS connection to NuAuth
 *
 * Create a TLS connection to NuAuth using tls_connect().
 */

/**
 * Check nuauth certification domain name (DN).
 *
 * Returns 1 on error, 0 if the domain name is valid.
 */
unsigned int check_nuauth_cert_dn(gnutls_session *tls_session)
{
	/* we check that dn provided in nuauth certificate is valid */
	char dn[128];
	size_t size;
	int ret;

#if 0
	unsigned int algo, bits;
	time_t expiration_time,
	       activation_time;
#endif
	const gnutls_datum *cert_list;
	unsigned int cert_list_size = 0;
	gnutls_x509_crt cert;

	/* This function only works for X.509 certificates.
	*/
	if (gnutls_certificate_type_get(*tls_session) != GNUTLS_CRT_X509)
		return 0;

	cert_list = gnutls_certificate_get_peers(*tls_session, &cert_list_size);
	if (cert_list_size == 0) {
		return 1;
	}

	/* we only print information about the first certificate */
	ret = gnutls_x509_crt_init(&cert);
	if (ret != 0) {
		log_area_printf	(DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING,
				"TLS: cannot init x509 cert: %s",
				gnutls_strerror(ret));
		return 0;
	}

	ret = gnutls_x509_crt_import(cert, &cert_list[0], GNUTLS_X509_FMT_DER);
	if (ret != 0) {
		log_area_printf
			(DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING,
			 "TLS: cannot import x509 cert: %s",
			 gnutls_strerror(ret));
		return 0;
	}

	/* TODO: verify date */
#if 0
	expiration_time = gnutls_x509_crt_get_expiration_time(cert);
	activation_time = gnutls_x509_crt_get_activation_time(cert);

	/* Extract some of the public key algorithm's parameters */
	algo = gnutls_x509_crt_get_pk_algorithm(cert, &bits);
#endif
	size = sizeof(dn);
	ret = gnutls_x509_crt_get_dn(cert, dn, &size);
	if (ret != 0) {
		log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING,
			 "TLS: cannot copy x509 cert name into buffer: %s",
			 gnutls_strerror(ret));
		return 0;
	}
	dn[sizeof(dn)-1] = 0;
	if (strcmp(dn, nuauth_cert_dn)) {
		log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING,
			 "TLS: bad certificate DN received from nuauth server: %s",
			 dn);
		return 0;
	}
	return 1;
}

/**
 * Create a TLS connection to NuAuth: create a TCP socket and connect
 * to NuAuth using ::adr_srv.
 *
 * If x509 is enable (USE_X509 equals to 1), create credentials and check
 * NuAuth's one.
 *
 * \return Pointer to a gnutls_session session, or NULL if an error occurs.
 */
gnutls_session *tls_connect()
{
	gnutls_session *tls_session;
	int tls_socket, ret;
#if USE_X509
	const int cert_type_priority[3] = { GNUTLS_CRT_X509, 0 };

	/* compute patch key_file */
	if (!key_file) {
		key_file =
		    (char *) calloc(strlen(CONFIG_DIR) + strlen(KEYFILE) +
				    2, sizeof(char));
		if (!key_file) {
			log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
					"Couldn't malloc for key_file!");
			return NULL;
		}
		strcat(key_file, CONFIG_DIR);
		strcat(key_file, "/");
		strcat(key_file, KEYFILE);
	}
	if (!cert_file) {
		cert_file =
		    (char *) calloc(strlen(CONFIG_DIR) + strlen(CERTFILE) +
				    2, sizeof(char));
		if (!cert_file) {
			log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
					"Couldn't malloc for cert_file!");
			return NULL;
		}
		strcat(cert_file, CONFIG_DIR);
		strcat(cert_file, "/");
		strcat(cert_file, CERTFILE);
	}

	/* test if key exists */
	if (access(key_file, R_OK)) {
		log_area_printf(DEBUG_AREA_GW, DEBUG_LEVEL_WARNING,
				"TLS: can not access key file \"%s\"!",
				key_file);
		return NULL;
	}
	if (access(cert_file, R_OK)) {
		log_area_printf(DEBUG_AREA_GW, DEBUG_LEVEL_WARNING,
				"TLS: can not access cert file \"%s\"!",
				cert_file);
		return NULL;
	}

	/* X509 stuff */
	ret = gnutls_certificate_allocate_credentials(&tls.xcred);
	if (ret != 0) {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING,
				"TLS: can not allocate gnutls credentials: %s",
				gnutls_strerror(ret));
		return NULL;
	}

	/* sets the trusted cas file */
	if (ca_file) {
		ret =
		    gnutls_certificate_set_x509_trust_file(tls.xcred,
							   ca_file,
							   GNUTLS_X509_FMT_PEM);
		if (ret < 0) {
			log_area_printf(DEBUG_AREA_MAIN,
					DEBUG_LEVEL_FATAL,
					"TLS: can not set gnutls trust file: %s",
					gnutls_strerror(ret));
			return NULL;
		}
	}
	ret =
	    gnutls_certificate_set_x509_key_file(tls.xcred, cert_file,
						 key_file,
						 GNUTLS_X509_FMT_PEM);
	if (ret < 0) {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING,
				"TLS: can not set cert/key file: %s",
				gnutls_strerror(ret));
		return NULL;

	}
#endif

	/* Initialize TLS session */
	tls_session = (gnutls_session *) calloc(1, sizeof(gnutls_session));
	if (tls_session == NULL) {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING,
				"TLS: can not calloc!");
		return NULL;
	}
	ret = gnutls_init(tls_session, GNUTLS_CLIENT);
	if (ret != 0) {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING,
				"TLS: init failed: %s",
				gnutls_strerror(ret));
		return NULL;
	}
	tls_socket =
	    socket(adr_srv->ai_family, adr_srv->ai_socktype,
		   adr_srv->ai_protocol);

	/* connect */
	if (tls_socket <= 0)
		return NULL;
	if (connect(tls_socket, adr_srv->ai_addr, adr_srv->ai_addrlen) ==
	    -1) {
		return NULL;
	}

	ret = gnutls_set_default_priority(*(tls_session));
	if (ret < 0) {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING,
				"TLS: priority setting failed: %s",
				gnutls_strerror(ret));
		return NULL;
	}
#if USE_X509
	ret =
	    gnutls_certificate_type_set_priority(*(tls_session),
						 cert_type_priority);
	if (ret < 0) {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING,
				"TLS: gnutls_certificate_type_set_priority() failed: %s",
				gnutls_strerror(ret));
		return NULL;
	}

	/* put the x509 credentials to the current session */
	ret =
	    gnutls_credentials_set(*(tls_session), GNUTLS_CRD_CERTIFICATE,
				   tls.xcred);
	if (ret < 0) {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING,
				"TLS: Failed to configure credentials: %s",
				gnutls_strerror(ret));
		return NULL;
	}
#endif

	/* This function returns void */
	gnutls_transport_set_ptr(*(tls_session),
				 (gnutls_transport_ptr) tls_socket);

	/* Perform the TLS handshake */
	ret = 0;
	do {
		if (ret != 0) {
			log_area_printf(DEBUG_AREA_GW, DEBUG_LEVEL_INFO,
					"TLS: gnutls_handshake() ... (last error: %i)",
					ret);
		}
		ret = gnutls_handshake(*(tls_session));
	} while (ret < 0 && !gnutls_error_is_fatal(ret));

	if (ret < 0) {
		gnutls_perror(ret);
		return NULL;
	}
#if USE_X509
	if (ca_file) {
		unsigned int status = 0;
		/* we need to verify received certificates */
		ret = gnutls_certificate_verify_peers2(*tls_session, &status);
		if (ret < 0) {
			log_area_printf(DEBUG_AREA_GW,
					DEBUG_LEVEL_WARNING,
					"TLS: Certificate authority verification failed: %s",
					gnutls_strerror(ret));
			return NULL;
		}
		if (status) {
			char buffer[200];
			buffer[0] = 0;
			if (status & GNUTLS_CERT_INVALID)
				SECURE_STRNCAT(buffer, " invalid", sizeof(buffer));
			if (status & GNUTLS_CERT_REVOKED)
				SECURE_STRNCAT(buffer, ", revoked", sizeof(buffer));
			if (status & GNUTLS_CERT_SIGNER_NOT_FOUND)
				SECURE_STRNCAT(buffer, ", signer not found", sizeof(buffer));
			if (status & GNUTLS_CERT_SIGNER_NOT_CA)
				SECURE_STRNCAT(buffer, ", signer not a CA", sizeof(buffer));
			log_area_printf(DEBUG_AREA_GW, DEBUG_LEVEL_WARNING,
					"TLS: Invalid certificates received from nuauth server:%s",
					buffer);
			return NULL;
		}
		if (nuauth_cert_dn) {
			if (!check_nuauth_cert_dn(tls_session)) {
				return NULL;
			}
		}
	}
#endif
	return tls_session;
}
