#include <auth_srv.h>
#include <gnutls/x509.h>

/**
 *  This function parse information about this session's peer
 * certificate and return username of peer.
 */
gchar* parse_x509_certificate_info(gnutls_session session)
{
   char dn[128];
   size_t size;
   unsigned int algo, bits;
   time_t expiration_time, activation_time;
   const gnutls_datum *cert_list;
   int cert_list_size = 0;
   gnutls_x509_crt cert;
   char* username=NULL;
   char* pointer=NULL;

   /* This function only works for X.509 certificates.
    */
   if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509)
      return NULL;

   cert_list = gnutls_certificate_get_peers(session, &cert_list_size);

        if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
   g_message("Peer provided %d certificates.\n", cert_list_size);
	}

   if (cert_list_size > 0) {

      /* we only print information about the first certificate.
       */
      gnutls_x509_crt_init( &cert);

      gnutls_x509_crt_import( cert, &cert_list[0],GNUTLS_X509_FMT_DER);

        if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
      g_message("Certificate info:\n");
	}

      expiration_time = gnutls_x509_crt_get_expiration_time( cert);
      activation_time = gnutls_x509_crt_get_activation_time( cert);

        if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
      g_message("\tCertificate is valid since: %s", ctime(&activation_time));
      g_message("\tCertificate expires: %s", ctime(&expiration_time));
	}
      /* verify date */

      /* Extract some of the public key algorithm's parameters
       */
      algo =
          gnutls_x509_crt_get_pk_algorithm(cert, &bits);

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
      pointer=g_strrstr_len(dn,127,",CN=");
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

