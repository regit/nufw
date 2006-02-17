/*
 ** Copyright (C) 2002-2005, Éric Leblond <eric@regit.org>
 **		       Vincent Deffontaines <vincent@gryzor.com>
 **                      INL http://www.inl.fr/
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

/** \file tls.c
 * \brief Create a TLS connection to NuAuth
 * 
 * Create a TLS connection to NuAuth using tls_connect().
 */

/**
 * Create a TLS connection to NuAuth: create a TCP socket and connect to ::adr_srv.
 *
 * If x509 is enable (USE_X509 equals to 1), create credentials and check
 * NuAuth's one.
 *
 * \return Pointer to a gnutls_session session, or NULL if an error occurs.
 */
gnutls_session* tls_connect()
{
    gnutls_session* tls_session;
    gnutls_certificate_credentials xcred;
    int tls_socket,ret;
#if USE_X509
    const int cert_type_priority[3] = { GNUTLS_CRT_X509, 0 };

    /* compute patch key_file */
    if (!key_file) {
        key_file=(char*)calloc(strlen(CONFIG_DIR)+strlen(KEYFILE)+2,sizeof(char));
        if (!key_file)
        {
            log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG, "Couldn't malloc for key_file!");
            return NULL;
        }
        strcat(key_file,CONFIG_DIR);
        strcat(key_file,"/");
        strcat(key_file,KEYFILE);
    }
    if (!cert_file) {
        cert_file=(char*)calloc(strlen(CONFIG_DIR)+strlen(CERTFILE)+2,sizeof(char));
        if (!cert_file)
        {
            log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG, 
                    "Couldn't malloc for cert_file!");
            return NULL;
        }
        strcat(cert_file,CONFIG_DIR);
        strcat(cert_file,"/");
        strcat(cert_file,CERTFILE);
    }
    
    /* test if key exists */
    if (access(key_file,R_OK)){
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG, 
                "TLS: can not access key file \"%s\"!", key_file);
        return NULL;
    }
    if (access(cert_file,R_OK)){
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING,
                "TLS: can not access cert file \"%s\"!", cert_file);
        return NULL;
    }

    /* X509 stuff */
    gnutls_certificate_allocate_credentials(&xcred);

    /* sets the trusted cas file */
    if (ca_file){
        gnutls_certificate_set_x509_trust_file(xcred, ca_file, GNUTLS_X509_FMT_PEM);
    }
    gnutls_certificate_set_x509_key_file(xcred,cert_file,key_file,GNUTLS_X509_FMT_PEM);
#endif

    /* Initialize TLS session */
    tls_session=(gnutls_session*)calloc(1,sizeof(gnutls_session));
    gnutls_init(tls_session, GNUTLS_CLIENT);
    tls_socket = socket (AF_INET,SOCK_STREAM,0);

    /* connect */
    if (tls_socket <= 0)
        return NULL;
    if ( connect(tls_socket,(struct sockaddr *)(&adr_srv),sizeof(adr_srv)) == -1){
        return NULL;
    }

    gnutls_set_default_priority(*(tls_session));
#if USE_X509
    gnutls_certificate_type_set_priority(*(tls_session), cert_type_priority);

    /* put the x509 credentials to the current session */
    gnutls_credentials_set(*(tls_session), GNUTLS_CRD_CERTIFICATE, xcred);
#endif

    gnutls_transport_set_ptr( *(tls_session), (gnutls_transport_ptr)tls_socket);

    /* Perform the TLS handshake */
    ret = gnutls_handshake( *(tls_session));

    if (ret < 0) {
        gnutls_perror(ret);
        return NULL;
    } else {
#if USE_X509
        if (ca_file){
            /* we need to verify received certificates */
            if( gnutls_certificate_verify_peers(*tls_session) !=0){
                log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING, "TLS: invalid certificates received from nuauth server");
                return NULL;
            } else {
                if (nuauth_cert_dn){
                    /* we check that dn provided in nuauth certificate is valid */
                    char dn[128];
                    size_t size;
#if 0
                    unsigned int algo, bits;
                    time_t expiration_time, activation_time;
#endif
                    const gnutls_datum *cert_list;
                    unsigned int cert_list_size = 0;
                    gnutls_x509_crt cert;

                    /* This function only works for X.509 certificates.
                    */
                    if (gnutls_certificate_type_get(*tls_session) != GNUTLS_CRT_X509)
                        return NULL;

                    cert_list = gnutls_certificate_get_peers(*tls_session, &cert_list_size);

                    if (cert_list_size > 0) {

                        /* we only print information about the first certificate.
                        */
                        gnutls_x509_crt_init( &cert);

                        gnutls_x509_crt_import( cert, &cert_list[0],GNUTLS_X509_FMT_DER);
#if 0
                        expiration_time = gnutls_x509_crt_get_expiration_time( cert);
                        activation_time = gnutls_x509_crt_get_activation_time( cert);

                        /* TODO: verify date */

                        /* Extract some of the public key algorithm's parameters
                        */
                        algo = gnutls_x509_crt_get_pk_algorithm(cert, &bits);
#endif 
                        size = sizeof(dn);
                        gnutls_x509_crt_get_dn( cert, dn, &size);
                        if (strcmp(dn,nuauth_cert_dn)){
                            log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING,
                                    "TLS : bad certificate DN received from nuauth server: %s", dn);
                            return NULL;
                        }
                    }
                }
            }
        }
#endif
        return tls_session;
    }
}

