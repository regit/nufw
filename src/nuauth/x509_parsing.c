#include <auth_srv.h>
#include <gnutls/x509.h>

#define DN_LENGTH 256

/**
 * Given a pointer to a x509 certificate, it checks 
 * the validity :
 * - expiration time
 * - activation time
 */
gint check_x509_certificate_validity(gnutls_x509_crt* cert)
{
	time_t expiration_time, activation_time;

	expiration_time = gnutls_x509_crt_get_expiration_time(*cert);
	activation_time = gnutls_x509_crt_get_activation_time(*cert);

	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
		g_message("Certificate validity starts at: %s", ctime(&activation_time));
		g_message("Certificate expires: %s", ctime(&expiration_time));
	}
	/* verify date */
	if (expiration_time<time(NULL)){
	        if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN)){
		        g_message("Certificate expired at: %s", ctime(&expiration_time));
                }
		return SASL_EXPIRED;
	}

	if (activation_time>time(NULL)){
	        if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN)){
		        g_message("Certificate only activates at: %s", ctime(&activation_time));
                }
		return SASL_DISABLED;
	}

	return SASL_OK;
}

/**
 *  This function parse information about this session's peer
 * certificate and return username of peer.
 *
 *  return NULL if certificate is not valid
 */
gchar* parse_x509_certificate_info(gnutls_session session)
{
	char dn[DN_LENGTH];
	size_t size;
	const gnutls_datum *cert_list;
	unsigned int cert_list_size = 0;
	gnutls_x509_crt cert;
	char* username=NULL;
	char* pointer=NULL;
	int ret;

	/* This function only works for X.509 certificates.
	*/
	if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509)
		return NULL;

	cert_list = gnutls_certificate_get_peers(session, &cert_list_size);

	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
		g_message("Peer provided %d certificates.\n", cert_list_size);
	}

	if (cert_list_size > 0) {
		/* we only print information about the first certificate. */
		gnutls_x509_crt_init( &cert);

		gnutls_x509_crt_import( cert, &cert_list[0],GNUTLS_X509_FMT_DER);

		/* checking validity first */
		ret = check_x509_certificate_validity(&cert);
		if (ret != SASL_OK){
			/* we can't accept an unvalid certificate to authenticate */
			return NULL;
		}

		/* Extract some of the public key algorithm's parameters
		*/

		size = sizeof(dn);
		gnutls_x509_crt_get_issuer_dn( cert, dn, &size);
		if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER)){
			g_message("\tIssuer's DN: %s\n", dn);
		}
		/* test if we trust this Issuer */

		size = sizeof(dn);
		gnutls_x509_crt_get_dn( cert, dn, &size);
		if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER)){
			g_message("\tDN: %s\n", dn);
		}

		/* parse DN and extract username is there is one */
		pointer=g_strrstr_len(dn,DN_LENGTH-1,",CN=");
		if (pointer){
			char* string_end=NULL;
			pointer+=4;
			string_end=g_strrstr_len(pointer,dn-pointer,",");
			if (string_end) {
				*string_end=0;
				username=g_strdup(pointer);
			}
		}

		gnutls_x509_crt_deinit( cert);
		if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER)){
			g_message("\tCN: %s\n", username);
		}
		return username;
	}
	return NULL;
}


