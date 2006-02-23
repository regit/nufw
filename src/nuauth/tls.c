/*
 ** Copyright(C) 2004,2005 INL
 ** written by  Eric Leblond <regit@inl.fr>
 **             Vincent Deffontaines <gryzor@inl.fr>
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
 **
 */

#include "auth_srv.h"
#include <sys/time.h>
#include <time.h>

struct tls_insert_data { 
	int socket;
	gpointer data;
};

/* These are global */
gnutls_certificate_credentials x509_cred;
int nuauth_tls_request_cert;
int nuauth_tls_auth_by_cert;

/**
 * strictly close a tls session
 * nothing to care about client
 */
int close_tls_session(int c,gnutls_session* session) {
	if (close(c))
		if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
			g_message("close_tls_session : close() failed!");
	gnutls_deinit(*session); /* TODO check output */
#ifdef DEBUG_ENABLE
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
		g_message("gnutls_deinit() was called");
#endif
	if (session){
		g_free(session);
	}
	return 1;
}

/** 
 * cleanly end a tls session 
 */
int cleanly_close_tls_session(int c,gnutls_session* session) {
	gnutls_bye(*session,GNUTLS_SHUT_RDWR);
#ifdef DEBUG_ENABLE
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
		g_message("gnutls_bye() was called");
#endif
	return close_tls_session(c,session);
}

/**
 * verify certs for a session
 */
gint check_certs_for_tls_session(gnutls_session session) {
	unsigned int status;
	int ret;
	/* This verification function uses the trusted CAs in the credentials
	 * structure. So you must have installed one or more CA certificates.
	 */
	ret = gnutls_certificate_verify_peers2 (session, &status);

	if (ret < 0){
		g_warning ("Certificate verification failed\n");
		return SASL_BADPARAM;
	}

	if (status & GNUTLS_CERT_INVALID){
		g_message("The certificate is not trusted.\n");
		return SASL_FAIL;
	}

	if (status & GNUTLS_CERT_SIGNER_NOT_FOUND){
		g_message("The certificate hasn't got a known issuer.\n");
		return SASL_NOVERIFY;
	}

	if (status & GNUTLS_CERT_REVOKED){
		g_message("The certificate has been revoked.\n");
		return SASL_EXPIRED;
	}

	if (gnutls_certificate_type_get(session) == GNUTLS_CRT_X509){
 		return check_x509_certificate_validity(session);
	} else {
		/* we only support X509 for now */
		return SASL_BADPARAM;
	}
	return SASL_OK;
}

/**
 * get username from a tls session
 *
 * Extract the username from the provided certificate
 */
gchar* get_username_from_tls_session(gnutls_session session) {
	if (gnutls_certificate_type_get(session) == GNUTLS_CRT_X509){
 		return get_username_from_x509_certificate(session);
	} else {
		return NULL;
	}
}

/**
 * complete all user initation phase.
 */
void tls_sasl_connect(gpointer userdata, gpointer data) {
	gnutls_session * session;
	user_session* c_session;
	int ret;
    unsigned int size=1;
	int c = ((struct client_connection*)userdata)->socket;

	if (tls_connect(c,&session) != SASL_BADPARAM) {
		c_session=g_new0(user_session,1);
		c_session->tls=session;
		c_session->addr=((struct client_connection*)userdata)->addr.sin_addr.s_addr;
		c_session->groups=NULL;
		c_session->last_req.tv_sec=0;
		c_session->last_req.tv_usec=0;
		c_session->req_needed=TRUE;
		c_session->userid=NULL;
		c_session->uid=0;
		g_free(userdata);
		if ((nuauth_tls_auth_by_cert == TRUE)   
				&& gnutls_certificate_get_peers(*session,&size) 
		   ) {
			ret = check_certs_for_tls_session(*session);

			if (ret != SASL_OK){
				if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN)){
					g_message("Certificate verification failed : %s",gnutls_strerror(ret));
				}
			} else {
				gchar* username=NULL;
				/* need to parse the certificate to see if it is a sufficient credential */
				username=get_username_from_tls_session(*session);
				/* parsing complete */ 
				if (username){
#ifdef DEBUG_ENABLE
					if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
						g_message("Using username %s from certificate",username);
#endif
					if(  user_check(username, NULL, 0,
								&(c_session->uid), &(c_session->groups)
						       )!=SASL_OK) {
#ifdef DEBUG_ENABLE
						if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)){
							g_message("error when searching user groups");	
						}
#endif
						c_session->groups=NULL;
						c_session->uid=0;
						/* we free username as it is not a good one */
						g_free(username);
					} else {
						c_session->userid=username;
					}
				}
			}
		}
		ret = sasl_user_check(c_session);
		switch (ret){
			case SASL_OK:
				{
					struct nuv2_srv_message msg;
					/* Success place */
					/* remove socket from the list of pre auth socket */
					remove_socket_from_pre_client_list(c);

					/* checking policy on multiuser usage */
					switch (nuauthconf->connect_policy){
						case POLICY_MULTIPLE_LOGIN:
							break;
						case POLICY_ONE_LOGIN:
							g_static_mutex_lock (&client_mutex);
							if (! look_for_username(c_session->userid)){
								g_static_mutex_unlock (&client_mutex);
								break;
							}
							g_static_mutex_unlock (&client_mutex);
						case POLICY_PER_IP_ONE_LOGIN:
							g_static_mutex_lock (&client_mutex);
							if (! get_client_sockets_by_ip(c_session->addr) ){
								g_static_mutex_unlock (&client_mutex);
								break;
							}
							g_static_mutex_unlock (&client_mutex);
						default:
#ifdef DEBUG_ENABLE
							if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
								g_message("User %s already connected, closing socket",c_session->userid);
#endif
							/* get rid of client */
							close_tls_session(c,c_session->tls);
							c_session->tls=NULL;
							clean_session(c_session);
							return;
					}
					if (nuauthconf->push) {
						struct internal_message* message=g_new0(struct internal_message,1);
						struct tls_insert_data * datas=g_new0(struct tls_insert_data,1);
						if ((message == NULL) || (datas == NULL )){
							close_tls_session(c,c_session->tls);
							c_session->tls=NULL;
							clean_session(c_session);
							break;
						}
						datas->socket=c;
						datas->data=c_session;
						message->datas=datas;
						message->type=INSERT_MESSAGE;
						g_async_queue_push(nuauthdatas->tls_push_queue,message);
					} else {
						g_static_mutex_lock (&client_mutex);
						add_client(c,c_session);
						g_static_mutex_unlock (&client_mutex);
					}
					/* unlock hash client */
					msg.type=SRV_TYPE;
					if (nuauthconf->push){
						msg.option = SRV_TYPE_PUSH ;
					} else {
						msg.option = SRV_TYPE_POLL ;
					}
					msg.length=0;
					/* send mode to client */
					if (gnutls_record_send(*(c_session->tls),&msg,sizeof(msg)) < 0){ 
#ifdef DEBUG_ENABLE
						if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_USER))
							g_message("gnutls_record_send() failure at %s:%d",__FILE__,__LINE__);
#endif
						if (nuauthconf->push){
							close_tls_session(c,c_session->tls);
							//                                            close(c);
							c_session->tls=NULL;
							clean_session(c_session);
							break;
						} else {
							g_static_mutex_lock (&client_mutex);
							delete_client_by_socket(c);
							g_static_mutex_unlock (&client_mutex);
							break;
						}
					}

					log_user_session(c_session,SESSION_OPEN);
#ifdef DEBUG_ENABLE
					if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
						g_message("Says we need to work on %d\n",c);
#endif
					g_async_queue_push(mx_queue,GINT_TO_POINTER(c));
					break;
				} 
			case SASL_FAIL:
				{
#ifdef DEBUG_ENABLE
					if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
						g_message("Crash on user side, closing socket");
#endif

					remove_socket_from_pre_client_list(c);
					close_tls_session(c,c_session->tls);
					c_session->tls=NULL;
					clean_session(c_session);
					break;
				}
			default:
				{
#ifdef DEBUG_ENABLE
					if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
						g_message("Problem with user, closing socket");
#endif
					/* get rid of client */
					close_tls_session(c,c_session->tls);
					c_session->tls=NULL;
					clean_session(c_session);
				}
		}
	} else {
		g_free(userdata);
	}
	remove_socket_from_pre_client_list(c);
}

gnutls_session* initialize_tls_session() {
	gnutls_session* session;
#if 0
	const int cert_type_priority[2] = { GNUTLS_CRT_X509, 0 };
#endif

	session = g_new0(gnutls_session,1);
	if (session == NULL)
		return NULL;

	if (gnutls_init(session, GNUTLS_SERVER) != 0)
	{
		g_free(session);
		return NULL;
	}

	/* avoid calling all the priority functions, since the defaults
	 * are adequate.
	 */
	if (gnutls_set_default_priority( *session)<0)
	{
		g_free(session);
		return NULL;
	}

#if 0
	if (gnutls_certificate_type_set_priority(*session, cert_type_priority)<0)
		return NULL;
#endif

	if (gnutls_credentials_set(*session, GNUTLS_CRD_CERTIFICATE, x509_cred)<0)
	{
		g_free(session);
		return NULL;
	}
	/* request client certificate if any.  */ 
	gnutls_certificate_server_set_request( *session,nuauth_tls_request_cert);

	gnutls_dh_set_prime_bits( *session, DH_BITS);

	return session;
}

static gnutls_dh_params dh_params;

static int generate_dh_params(void)  {
	/* Generate Diffie Hellman parameters - for use with DHE
	 * kx algorithms. These should be discarded and regenerated
	 * once a day, once a week or once a month. Depending on the
	 * security requirements.
	 */
	if (gnutls_dh_params_init( &dh_params)<0)
		return -1;
	if (gnutls_dh_params_generate2( dh_params, DH_BITS)<0)
		return -1;

	return 0;
}

/**
 * realize tls connection.
 */
int tls_connect(int c,gnutls_session** session_ptr) {
	int ret;
	int count=0;
	gnutls_session* session;
	*(session_ptr) = initialize_tls_session();
	session=*(session_ptr);
	if ((session_ptr==NULL) || (session==NULL))
	{
		close(c);
		return SASL_BADPARAM;
	}
#ifdef DEBUG_ENABLE
	if (session_ptr == NULL)
		if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN))
			g_message("NuFW TLS Init failure (session_ptr is NULL)\n");

	if (session==NULL)
		if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN))
			g_message("NuFW TLS Init failure (initialize_tls_session())\n");
#endif
	gnutls_transport_set_ptr( *session, (gnutls_transport_ptr) c);

#ifdef DEBUG_ENABLE
	if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)){
		g_message("NuFW TLS Handshaking\n");
	}
#endif
	ret = gnutls_handshake( *session);

#ifdef DEBUG_ENABLE
	if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)){
		g_message("NuFW TLS Handshaked\n");
	}
#endif
	while ((ret == GNUTLS_E_AGAIN) || (ret == GNUTLS_E_INTERRUPTED))
	{
		ret = gnutls_handshake( *session);
		count++;
		if (count>10)
			break;
	}
	if ((count>1) && ((ret == GNUTLS_E_GOT_APPLICATION_DATA) || (ret == GNUTLS_E_WARNING_ALERT_RECEIVED)))
	{
#ifdef DEBUG_ENABLE
		if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)){
			g_message("NuFW TLS Handshake : needed several calls and returned a nonfatal error. Trying to continue..");
		}
#endif
	}else
		if (ret < 0) {
			close_tls_session(c,session);
			if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)){
				g_message("NuFW TLS Handshake has failed (%s)\n\n",
						gnutls_strerror(ret)) ; 
			}
			return SASL_BADPARAM;
		}

#ifdef DEBUG_ENABLE
	if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)){
		g_message("NuFW TLS Handshake was completed\n");
	}
#endif

	if (nuauth_tls_request_cert==GNUTLS_CERT_REQUIRE){
		/* certicate verification */
		ret = check_certs_for_tls_session(*session);
		if (ret != 0){
			if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN)){
				g_message("Certificate verification failed : %s",gnutls_strerror(ret));
			}
			close_tls_session(c,session);
			return SASL_BADPARAM;
		}
	}
	return SASL_OK;
}

/**
 * Read conf file and allocate x509 credentials
 */
void create_x509_credentials() {
	char* nuauth_tls_key=NULL;
	char* nuauth_tls_cert=NULL;
	char* nuauth_tls_cacert=NULL;
	char* nuauth_tls_key_passwd=NULL;
	char* nuauth_tls_crl=NULL;
	char *configfile=DEFAULT_CONF_FILE;
	gpointer vpointer;
	int ret;
	//gnutls_dh_params dh_params;
	int int_dh_params;
	confparams nuauth_tls_vars[] = {
		{ "nuauth_tls_key" , G_TOKEN_STRING , 0, g_strdup(NUAUTH_KEYFILE) },
		{ "nuauth_tls_cert" , G_TOKEN_STRING , 0, g_strdup(NUAUTH_CERTFILE) },
		{ "nuauth_tls_cacert" , G_TOKEN_STRING , 0, g_strdup(NUAUTH_CACERTFILE) },
		{ "nuauth_tls_crl" , G_TOKEN_STRING , 0, NULL },
		{ "nuauth_tls_key_passwd" , G_TOKEN_STRING , 0, NULL },
		{ "nuauth_tls_request_cert" , G_TOKEN_INT ,FALSE, NULL },
		{ "nuauth_tls_auth_by_cert" , G_TOKEN_INT ,FALSE, NULL }
	};
	parse_conffile(configfile,sizeof(nuauth_tls_vars)/sizeof(confparams),nuauth_tls_vars);
	/* set variable value from config file */
	vpointer=get_confvar_value(nuauth_tls_vars,sizeof(nuauth_tls_vars)/sizeof(confparams),"nuauth_tls_key");
	nuauth_tls_key=(char*)(vpointer);

	vpointer=get_confvar_value(nuauth_tls_vars,sizeof(nuauth_tls_vars)/sizeof(confparams),"nuauth_tls_cert");
	nuauth_tls_cert=(char*)(vpointer);

	vpointer=get_confvar_value(nuauth_tls_vars,sizeof(nuauth_tls_vars)/sizeof(confparams),"nuauth_tls_cacert");
	nuauth_tls_cacert=(char*)(vpointer);

	vpointer=get_confvar_value(nuauth_tls_vars,sizeof(nuauth_tls_vars)/sizeof(confparams),"nuauth_tls_crl");
	nuauth_tls_crl=(char*)(vpointer);

	vpointer=get_confvar_value(nuauth_tls_vars,sizeof(nuauth_tls_vars)/sizeof(confparams),"nuauth_tls_key_passwd");
	nuauth_tls_key_passwd=(char*)(vpointer);

	vpointer=get_confvar_value(nuauth_tls_vars,sizeof(nuauth_tls_vars)/sizeof(confparams),"nuauth_tls_request_cert");
	nuauth_tls_request_cert=*(int*)(vpointer);

	vpointer=get_confvar_value(nuauth_tls_vars,sizeof(nuauth_tls_vars)/sizeof(confparams),"nuauth_tls_auth_by_cert");
	nuauth_tls_auth_by_cert=*(int*)(vpointer);

	gnutls_certificate_allocate_credentials(&x509_cred);
	ret = gnutls_certificate_set_x509_trust_file(x509_cred,  nuauth_tls_cacert , 
			GNUTLS_X509_FMT_PEM);
	if(ret<=0){
		if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_USER)){
			g_message("Problem with certificate trust file : %s",
					gnutls_strerror(ret) 	);
		}
	}
	ret = gnutls_certificate_set_x509_key_file(x509_cred, nuauth_tls_cert,nuauth_tls_key, 
			GNUTLS_X509_FMT_PEM);
	if (ret <0){
		if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_USER)){
			g_message("Problem with certificate key file : %s",
					gnutls_strerror(ret) );
		}
	}

#ifdef DEBUG_ENABLE
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER)){
		g_message("TLS using key %s and cert %s",nuauth_tls_key,nuauth_tls_cert);
		if (nuauth_tls_request_cert == GNUTLS_CERT_REQUIRE)
			g_message("TLS require cert from client");
	}
#endif
	if (nuauth_tls_key){
		g_free(nuauth_tls_key);
	}

	if (nuauth_tls_cert){
		g_free(nuauth_tls_cert);
	}

	if (nuauth_tls_crl){
		if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
			g_message("certificate revocation list : %s\n",nuauth_tls_crl);
		gnutls_certificate_set_x509_crl_file(x509_cred, nuauth_tls_crl, 
				GNUTLS_X509_FMT_PEM);
		g_free(nuauth_tls_crl);
	}
	int_dh_params = generate_dh_params();
#ifdef DEBUG_ENABLE
	if (int_dh_params < 0)
		if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_USER))
			g_message("generate_dh_params() failed\n");
#endif


	//Gryzor doesnt understand wht dh_params is passed as 2nd argument, where a gnutls_dh_params_t structure is awaited
	//	gnutls_certificate_set_dh_params( x509_cred, 0);
	gnutls_certificate_set_dh_params( x509_cred, dh_params);
}

/**
 * dequeue addr that need to do a check.
 * 
 * lock is only needed when modifications are done
 * because when this thread work (push mode) it's the only one
 * who can modify the hash
 */
void push_worker() {
	struct msg_addr_set *global_msg=g_new0(struct msg_addr_set,1);
	struct nuv2_srv_message *msg=g_new0(struct nuv2_srv_message,1);
	struct internal_message * message;

	global_msg->msg=msg;
	msg->type=SRV_REQUIRED_PACKET;
	msg->option=0;
	msg->length=htons(4);

	g_async_queue_ref (nuauthdatas->tls_push_queue);

	/* wait for message */
	while ( ( message = g_async_queue_pop(nuauthdatas->tls_push_queue))  ) {
		switch (message->type) {
			case WARN_MESSAGE:
				{
					global_msg->addr=((tracking_t *)message->datas)->saddr;
					global_msg->found = FALSE;
					/* search in client array */
					g_static_mutex_lock (&client_mutex);
					warn_clients(global_msg);
					g_static_mutex_unlock (&client_mutex);
					/* do we have found something */
					if (global_msg->addr != INADDR_ANY){
						if (global_msg->found == FALSE ){
							/* if we do ip authentication send request to pool */
							if (nuauthconf->do_ip_authentication){
								g_thread_pool_push (nuauthdatas->ip_authentication_workers,
										message->datas,
										NULL);
							} else {
								g_free(message->datas);
							}
						} else {
							/* free header */
							g_free(message->datas);
						}
					}
				}
				break;
			case FREE_MESSAGE:
				{
					g_static_mutex_lock (&client_mutex);
					delete_client_by_socket(GPOINTER_TO_INT(message->datas));
					g_static_mutex_unlock (&client_mutex);
				}
				break;
			case INSERT_MESSAGE:
				{
					struct tls_insert_data* datas=message->datas;
					if (datas->data){
						g_static_mutex_lock (&client_mutex);
						add_client(datas->socket,datas->data);
						g_static_mutex_unlock (&client_mutex);
					}
				}
				break;
			default:
				g_message("lost");
		}
		g_free(message);
	}
}

void end_tls(int signal) {
	gnutls_global_deinit();
}
