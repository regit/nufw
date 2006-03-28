#include <auth_srv.h>
#include <gnutls/x509.h>

#define DN_LENGTH 256

gint get_first_x509_cert_from_tls_session(gnutls_session session,gnutls_x509_crt* cert)
{
	const gnutls_datum *cert_list;
	unsigned int cert_list_size = 0;
	
	if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509)
		return SASL_BADPARAM;

	cert_list = gnutls_certificate_get_peers(session, &cert_list_size);

	log_message(VERBOSE_DEBUG, AREA_MAIN, "Peer provided %d certificates.", cert_list_size);

	if (cert_list_size > 0) {
		/* we only print information about the first certificate. */
		gnutls_x509_crt_init( cert);
		gnutls_x509_crt_import( *cert, &cert_list[0],GNUTLS_X509_FMT_DER);
	} else {
		return SASL_BADPARAM;
	}
	return SASL_OK;
}



/**
 * Given a pointer to a x509 certificate, it checks 
 * the validity :
 * - expiration time
 * - activation time
 * - issuer DN against authority
 */
gint check_x509_certificate_validity(gnutls_session session)
{
	time_t expiration_time, activation_time;
	char dn[DN_LENGTH];
	size_t size;
	gnutls_x509_crt cert;

	if (get_first_x509_cert_from_tls_session(session,&cert) == SASL_OK){
		return SASL_BADPARAM;
	}
	expiration_time = gnutls_x509_crt_get_expiration_time(cert);
	activation_time = gnutls_x509_crt_get_activation_time(cert);

	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
		g_message("Certificate validity starts at: %s", ctime(&activation_time));
		g_message("Certificate expires: %s", ctime(&expiration_time));
	}
	/* verify date */
	if (expiration_time<time(NULL)){
	        if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN)){
		        g_message("Certificate expired at: %s", ctime(&expiration_time));
                }
		gnutls_x509_crt_deinit( cert);
		return SASL_EXPIRED;
	}

	if (activation_time>time(NULL)){
	        if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN)){
		        g_message("Certificate only activates at: %s", ctime(&activation_time));
                }
		gnutls_x509_crt_deinit( cert);
		return SASL_DISABLED;
	}
	
	size = sizeof(dn);
	gnutls_x509_crt_get_issuer_dn( cert, dn, &size);
	log_message(VERBOSE_DEBUG, AREA_USER, "\tIssuer's DN: %s", dn);
	/* TODO  test if we trust this Issuer */
	gnutls_x509_crt_deinit( cert);
	return SASL_OK;
}

/**
 *  This function parse information about this session's peer
 * certificate and return username of peer.
 *
 *  return NULL if certificate is not valid
 */

gchar *	get_username_from_x509_certificate(gnutls_session session)
{
	size_t size;
	gnutls_x509_crt cert;
	char* username=NULL;
	char* pointer=NULL;
	char dn[DN_LENGTH];

	if ( get_first_x509_cert_from_tls_session(session,&cert) != SASL_OK){
		return NULL;
	}
	
	size = sizeof(dn);
	gnutls_x509_crt_get_dn( cert, dn, &size);
	log_message(VERBOSE_DEBUG, AREA_USER, "\tDN: %s", dn);
	
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
	log_message(VERBOSE_DEBUG, AREA_USER, "\tCN: %s", username);
	return username;
}


