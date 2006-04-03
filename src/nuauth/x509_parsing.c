#include <auth_srv.h>
#include <gnutls/x509.h>


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
    gnutls_x509_crt cert;
    int ret;

    if (get_first_x509_cert_from_tls_session(session,&cert) == SASL_OK){
        return SASL_BADPARAM;
    }

    /* Check certificat hook */
    ret = modules_check_certificate(session,cert);
    gnutls_x509_crt_deinit( cert);

    return ret;
}

/**
 *  This function parse information about this session's peer
 * certificate and return username of peer.
 *
 *  return NULL if certificate is not valid
 */

gchar *	get_username_from_x509_certificate(gnutls_session session)
{
    gnutls_x509_crt cert;
    char* username=NULL;

    if ( get_first_x509_cert_from_tls_session(session,&cert) != SASL_OK){
        return NULL;
    }
    username = modules_certificate_to_uid(&session,&cert);
    gnutls_x509_crt_deinit( cert);
    log_message(VERBOSE_DEBUG, AREA_USER, "\tCN: %s", username);
    return username;
}


