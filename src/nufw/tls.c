#include "nufw.h"

gnutls_session * tls_connect()
{
  gnutls_session* tls_session;
  gnutls_certificate_credentials xcred;
#if USE_X509
  const int cert_type_priority[3] = { GNUTLS_CRT_X509, 
      GNUTLS_CRT_OPENPGP, 0 };
#endif
  int tls_socket,ret;
  /* compute patch key_file */
  if (!key_file)
  {
      //snprintf(key_file,FILENAME_SIZE,CONFIG_DIR "/" KEYFILE);
      key_file=(char *)malloc(strlen(CONFIG_DIR)+strlen(KEYFILE)+2);
      if (!key_file)
      {
          if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN)){
              if (log_engine == LOG_TO_SYSLOG) {
                  syslog(SYSLOG_FACILITY(DEBUG_LEVEL_DEBUG),"Couldn't malloc for key_file!");
              }else {
                  printf("[%i] Couldn't malloc for key_file!\n",getpid());
              }
          }

          return NULL;
      }
      strcat(key_file,CONFIG_DIR);
      strcat(key_file,"/");
      strcat(key_file,KEYFILE);
  }
  if (!cert_file)
  {
      //snprintf(cert_file,FILENAME_SIZE,CONFIG_DIR "/" CERTFILE);
      cert_file=(char *)malloc(strlen(CONFIG_DIR)+strlen(CERTFILE)+2);
      if (!cert_file)
      {
          if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN)){
              if (log_engine == LOG_TO_SYSLOG) {
                  syslog(SYSLOG_FACILITY(DEBUG_LEVEL_DEBUG),"Couldn't malloc for cert_file!");
              }else {
                  printf("[%i] Couldn't malloc for cert_file!\n",getpid());
              }
          }
          return NULL;
      }
      strcat(cert_file,CONFIG_DIR);
      strcat(cert_file,"/");
      strcat(cert_file,CERTFILE);
  }
  /* test if key exists */
  if (access(key_file,R_OK)){
      if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN)){
          if (log_engine == LOG_TO_SYSLOG) {
              syslog(SYSLOG_FACILITY(DEBUG_LEVEL_DEBUG),"TLS : can not access key file %s",key_file);
          }else {
              printf("[%i] TLS : can not access key file %s\n",getpid(),key_file);
          }
      }
      return NULL;
  }
  if (access(cert_file,R_OK)){
      if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN)){
          if (log_engine == LOG_TO_SYSLOG) {
              syslog(SYSLOG_FACILITY(DEBUG_LEVEL_DEBUG),"TLS : can not access cert file %s",cert_file);
          }else {
              printf("[%i] TLS : can not access cert file %s\n",getpid(),cert_file);
          }
      }
      return NULL;
  }
#if USE_X509
  /* X509 stuff */
  gnutls_certificate_allocate_credentials(&xcred);

  /* sets the trusted cas file */
  if (ca_file){
      gnutls_certificate_set_x509_trust_file(xcred, ca_file, GNUTLS_X509_FMT_PEM);
  }
  gnutls_certificate_set_x509_key_file(xcred,cert_file,key_file,GNUTLS_X509_FMT_PEM);

#endif
  /* Initialize TLS session 
   */
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


  /* put the x509 credentials to the current session
   */
  gnutls_credentials_set(*(tls_session), GNUTLS_CRD_CERTIFICATE, xcred);

#endif
  gnutls_transport_set_ptr( *(tls_session), (gnutls_transport_ptr)tls_socket);

  /* Perform the TLS handshake
   */
  ret = gnutls_handshake( *(tls_session));

  if (ret < 0) {
      gnutls_perror(ret);
      return NULL;
  } else {
      if (ca_file){
          /* we need to verify received certificates */
          if( gnutls_certificate_verify_peers(*tls_session) !=0){
              if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN)){
                  if (log_engine == LOG_TO_SYSLOG) {
                      syslog(SYSLOG_FACILITY(DEBUG_LEVEL_DEBUG),"TLS : invalid certificates received from nuauth server");
                  }else {
                      printf("[%i] TLS : invalid certificates received from nuauth server\n",getpid());
                  }
              }
              return NULL;
          }
      }
      return tls_session;
  }
}

