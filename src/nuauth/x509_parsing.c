/**
 ** Copyright(C) 2006-2007 INL
 ** Written by Eric Leblond <regit@inl.fr>
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


#include <auth_srv.h>
#include <gnutls/x509.h>

/**
 * \addtogroup TLSUser
 * @{
 */


gint get_first_x509_cert_from_tls_session(gnutls_session session,
					  gnutls_x509_crt * cert)
{
	const gnutls_datum *cert_list;
	unsigned int cert_list_size = 0;

	if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509)
		return SASL_BADPARAM;

	cert_list = gnutls_certificate_get_peers(session, &cert_list_size);

	log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
		    "Peer provided %d certificates.", cert_list_size);

	if (cert_list_size > 0) {
		/* we only print information about the first certificate. */
		gnutls_x509_crt_init(cert);
		if (gnutls_x509_crt_import(*cert, &cert_list[0],
				       GNUTLS_X509_FMT_DER) != 0)
			return SASL_BADPARAM;
	} else {
		return SASL_BADPARAM;
	}
	return SASL_OK;
}


#if 0
/**
 * Given a pointer to a x509 certificate, it checks
 * the validity :
 * - expiration time
 * - activation time
 * - issuer DN against authority
 */
gint check_x509_certificate_validity(gnutls_session session)
{
	gnutls_x509_crt cert;
	int ret;

	if (get_first_x509_cert_from_tls_session(session, &cert) !=
	    SASL_OK) {
		log_message(DEBUG, DEBUG_AREA_USER,
			    "Can't get first cert from session");
		return SASL_BADPARAM;
	}

	/* Check certificat hook */
	ret = modules_check_certificate(session, cert);
	gnutls_x509_crt_deinit(cert);

	return ret;
}
#endif

/**
 *  This function parse information about this session's peer
 * certificate and return username of peer.
 *
 *  return NULL if certificate is not valid
 */

#if 0
gchar *get_username_from_x509_certificate(gnutls_session session)
{
	gnutls_x509_crt cert;
	char *username = NULL;

	if (get_first_x509_cert_from_tls_session(session, &cert) !=
	    SASL_OK) {
		return NULL;
	}
	username = modules_certificate_to_uid(session, cert);
	gnutls_x509_crt_deinit(cert);
	log_message(VERBOSE_DEBUG, DEBUG_AREA_USER, "\tCN: %s", username);
	return username;
}
#endif

/** @} */
