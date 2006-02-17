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

#include <auth_srv.h>
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


GSList* pre_client_list;
GStaticMutex pre_client_list_mutex;


struct pre_client_elt {
	int socket;
	time_t validity;
};

gboolean remove_socket_from_pre_client_list(int c)
{
	GSList * client_runner=NULL;
	g_static_mutex_lock (&pre_client_list_mutex);
	for(client_runner=pre_client_list;client_runner;client_runner=client_runner->next){
		/* if entry older than delay then close socket */
		if (client_runner->data){
			if ( ((struct pre_client_elt*)(client_runner->data))->socket == c){
				g_free(client_runner->data);
				client_runner->data=NULL;
				pre_client_list=g_slist_remove_all(pre_client_list,NULL);
				g_static_mutex_unlock (&pre_client_list_mutex);
				return TRUE;
			} 
		}
	}
	g_static_mutex_unlock (&pre_client_list_mutex);
	return FALSE;
}

/**
 * Check pre client list to disconnect connection
 * that are open since too long
 */

void  pre_client_check()
{
	GSList * client_runner=NULL;
	time_t current_timestamp;
	for(;;){
		current_timestamp=time(NULL);

		/* lock client list */
		g_static_mutex_lock (&pre_client_list_mutex);
		/* iter on pre_client_list */
		for(client_runner=pre_client_list;client_runner;client_runner=client_runner->next){
			/* if entry older than delay then close socket */
			if (client_runner->data){
				if ( ((struct pre_client_elt*)(client_runner->data))->validity < current_timestamp){

#ifdef DEBUG_ENABLE
					if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER)){
						g_message("closing socket %d due to timeout\n",((struct pre_client_elt*)(client_runner->data))->socket);
					}
#endif
					shutdown(((struct pre_client_elt*)(client_runner->data))->socket,SHUT_RDWR);
					close(((struct pre_client_elt*)(client_runner->data))->socket);
					g_free(client_runner->data);
					client_runner->data=NULL;
				} 
			}
		}
		pre_client_list=g_slist_remove_all(pre_client_list,NULL);
		/* unlock client list */
		g_static_mutex_unlock (&pre_client_list_mutex);
		/* sleep */
		sleep(1);
	}
}

/**
 * strictly close a tls session
 * nothing to care about client */
int close_tls_session(int c,gnutls_session* session)
{
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
int cleanly_close_tls_session(int c,gnutls_session* session){
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

gint check_certs_for_tls_session(gnutls_session session)
{
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
gchar* get_username_from_tls_session(gnutls_session session)
{
	if (gnutls_certificate_type_get(session) == GNUTLS_CRT_X509){
 		return get_username_from_x509_certificate(session);
	} else {
		return NULL;
	}
}

gnutls_session* initialize_tls_session()
{
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

static int generate_dh_params(void) 
{

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
 * get RX paquet from a TLS client connection and send it to user authentication threads.
 *
 * - Argument : SSL RX packet
 * - Return : 1 if read done, EOF if read complete, -1 on error
 */
static int treat_user_request (user_session * c_session)
{
	struct buffer_read * datas;
	int read_size=0;

	if (c_session != NULL){
		datas=g_new0(struct buffer_read,1);
		if (datas==NULL)
			return -1;
		datas->socket=0;
		datas->buf=NULL;
		datas->tls=c_session->tls;
		datas->addr=c_session->addr;
#ifdef DEBUG_ENABLE
		if (!c_session->multiusers) {
			if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
				g_message("Packet from user %s\n",c_session->userid);
		}
#endif
		/* copy packet datas */
		datas->buf=g_new0(char,BUFSIZE);
		if (datas->buf == NULL){
			g_free(datas);
			return -1;
		}
		read_size = gnutls_record_recv(*(c_session->tls),datas->buf,BUFSIZE);
		if ( read_size> 0 ){
			struct nuv2_header* pbuf=(struct nuv2_header* )datas->buf;
			/* get header to check if we need to get more datas */
#ifdef DEBUG_ENABLE
			if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
				g_message("(%s:%d) Packet size is %d\n",__FILE__,__LINE__,pbuf->length );
			}
#endif

			if (pbuf->proto==2 && pbuf->msg_type == USER_HELLO){
#ifdef DEBUG_ENABLE
				if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
					g_message("(%s:%d) user HELLO",__FILE__,__LINE__);
				}
#endif
				g_free(datas->buf);
				g_free(datas);
				return 1;
			}
			if (pbuf->proto==2 && pbuf->length> read_size && pbuf->length<1800 ){
				/* we realloc and get what we miss */
				datas->buf=g_realloc(datas->buf,pbuf->length);
				if (gnutls_record_recv(*(c_session->tls),datas->buf+BUFSIZE,read_size-pbuf->length)<0){
					free_buffer_read(datas);
					return -1;
				}
			}
			/* check message type because USER_HELLO has to be ignored */
			if ( pbuf->msg_type == USER_HELLO){
				return 1;
			}
			/* check authorization if we're facing a multi user packet */ 
			if ( (pbuf->option == 0x0) ||
					((pbuf->option == 0x1) && c_session->multiusers)) {
				/* this is an authorized packet we fill the buffer_read structure */
				if (c_session->multiusers) {
					datas->userid=NULL;
					datas->uid=0;
					datas->groups=NULL;
				} else {
					datas->userid = g_strdup(c_session->userid);
					datas->uid = c_session->uid;
					datas->groups = g_slist_copy (c_session->groups);
				}
				if (c_session->sysname){
					datas->sysname=g_strdup(c_session->sysname);
					if (datas->sysname == NULL){
						free_buffer_read(datas);
						return -1;
					}
				}
				if (c_session->release){
					datas->release=g_strdup(c_session->release);
					if (datas->release == NULL){
						free_buffer_read(datas);
						return -1;
					}
				}
				if (c_session->version){
					datas->version=g_strdup(c_session->version);
					if (datas->version == NULL){
						free_buffer_read(datas);
						return -1;
					}
				}

#ifdef DEBUG_ENABLE
				if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
					g_message("Pushing packet to user_checker");
#endif
				g_thread_pool_push (nuauthdatas->user_checkers,
						datas,	
						NULL
						);
			} else {
				if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN)){
					g_message("Bad packet, option of header is not set or unauthorized option");
				}
				free_buffer_read(datas);
				return EOF;
			}
		} else {
#ifdef DEBUG_ENABLE
			if (read_size <0) 
				if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN))
					g_message("Received error from user %s\n",datas->userid );
#endif

			free_buffer_read(datas);
			return EOF;
		}
	}
	return 1;
}


/**
 * realize tls connection.
 */
int tls_connect(int c,gnutls_session** session_ptr){
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
 * complete all user initation phase.
 */
void  tls_sasl_connect(gpointer userdata, gpointer data)
{
	gnutls_session * session;
	user_session* c_session;
	int ret,size=1;
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

/**
 * Read conf file and allocate x509 credentials
 *
 */

void create_x509_credentials(){
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
 * TLS user packet server. 
 * Thread function serving user connection.
 * 
 * - Argument : None
 * - Return : None
 */

void* tls_user_authsrv()
{
	int z;
	struct sockaddr_in addr_inet,addr_clnt;
	GThreadPool* tls_sasl_worker;
	unsigned int len_inet;
	int sck_inet;
	int n,c;
	int mx;
	fd_set tls_rx_set; /* read set */
	fd_set wk_set; /* working set */
	struct timeval tv;
	gpointer vpointer;
	char *configfile=DEFAULT_CONF_FILE;
	gpointer c_pop;
	gint option_value;
	GThread * pre_client_thread;
	confparams nuauth_tls_vars[] = {
		{ "nuauth_tls_max_clients" , G_TOKEN_INT ,NUAUTH_SSL_MAX_CLIENTS, NULL },
		{ "nuauth_number_authcheckers" , G_TOKEN_INT ,NB_AUTHCHECK, NULL },
		{ "nuauth_auth_nego_timeout" , G_TOKEN_INT ,AUTH_NEGO_TIMEOUT, NULL }
	};
	int nuauth_tls_max_clients=NUAUTH_TLS_MAX_CLIENTS;
	int nuauth_number_authcheckers=NB_AUTHCHECK;
	int nuauth_auth_nego_timeout=AUTH_NEGO_TIMEOUT;
	/* get config file setup */
	/* parse conf file */
	parse_conffile(configfile,sizeof(nuauth_tls_vars)/sizeof(confparams),nuauth_tls_vars);
	vpointer=get_confvar_value(nuauth_tls_vars,sizeof(nuauth_tls_vars)/sizeof(confparams),"nuauth_tls_max_clients");
	nuauth_tls_max_clients=*(int*)(vpointer); 
	vpointer=get_confvar_value(nuauth_tls_vars,sizeof(nuauth_tls_vars)/sizeof(confparams),"nuauth_number_authcheckers");
	nuauth_number_authcheckers=*(int*)(vpointer);
	vpointer=get_confvar_value(nuauth_tls_vars,sizeof(nuauth_tls_vars)/sizeof(confparams),"nuauth_auth_nego_timeout");
	nuauth_auth_nego_timeout=*(int*)(vpointer);

	/* init sasl stuff */	
	my_sasl_init();

	init_client_struct();

#if 0
	/* intercept SIGTERM */
	action.sa_handler = tls_nuauth_cleanup;
	sigemptyset( & (action.sa_mask));
	action.sa_flags = 0;
	if ( sigaction( SIGTERM, & action , NULL ) != 0) {
		printf("Error\n");
		exit(1);
	}
#endif

	pre_client_list=NULL;
	pre_client_thread = g_thread_create ( (GThreadFunc) pre_client_check,
			NULL,
			FALSE,
			NULL);
	if (! pre_client_thread )
		exit(1);


	tls_sasl_worker = g_thread_pool_new  ((GFunc) tls_sasl_connect,
			NULL,
			nuauth_number_authcheckers,
			TRUE,
			NULL);
	/* open the socket */
	sck_inet = socket (AF_INET,SOCK_STREAM,0);

	if (sck_inet == -1)
	{
		g_warning("socket() failed, exiting");
		exit(-1);
	}

	option_value=1;
	/* set socket reuse and keep alive option */
	setsockopt (
			sck_inet,
			SOL_SOCKET,
			SO_REUSEADDR,
			&option_value,
			sizeof(option_value));

	setsockopt (
			sck_inet,
			SOL_SOCKET,
			SO_KEEPALIVE,
			&option_value,
			sizeof(option_value));

	memset(&addr_inet,0,sizeof addr_inet);

	addr_inet.sin_family= AF_INET;
	addr_inet.sin_port=htons(nuauthconf->userpckt_port);
	addr_inet.sin_addr.s_addr=nuauthconf->client_srv->s_addr;

	len_inet = sizeof addr_inet;

	z = bind (sck_inet,
			(struct sockaddr *)&addr_inet,
			len_inet);
	if (z == -1)
	{
		g_warning ("user bind() failed to %s:%d at %s:%d, exiting",inet_ntoa(addr_inet.sin_addr),nuauthconf->userpckt_port,__FILE__,__LINE__);
		exit(-1);
	}

	/* Listen ! */
	z = listen(sck_inet,20);
	if (z == -1)
	{
		g_warning ("user listen() failed, exiting");
		exit(-1);
	}

	/* init fd_set */
	FD_ZERO(&tls_rx_set);
	FD_ZERO(&wk_set);
	FD_SET(sck_inet,&tls_rx_set);
	mx=sck_inet+1;
	mx_queue=g_async_queue_new ();

	for(;;){
		/* try to get new file descriptor to update set */
		c_pop=g_async_queue_try_pop (mx_queue);

		while (c_pop) {
			c=GPOINTER_TO_INT(c_pop);

#ifdef DEBUG_ENABLE
			if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
				g_message("checking mx against %d\n",c);
#endif
			if ( c+1 > mx )
				mx = c + 1;
			/*
			 * change FD_SET
			 */
			FD_SET(c,&tls_rx_set);
			c_pop=g_async_queue_try_pop (mx_queue);
		}


		/*
		 * copy rx set to working set 
		 */

		FD_ZERO(&wk_set);
		for (z=0;z<mx;++z){
			if (FD_ISSET(z,&tls_rx_set))
				FD_SET(z,&wk_set);
		}

		/*
		 * define timeout 
		 */

		tv.tv_sec=2;
		tv.tv_usec=30000;

		n=select(mx,&wk_set,NULL,NULL,&tv);

		if (n == -1) {
			g_warning("select() failed, exiting\n");
			exit(EXIT_FAILURE);
		} else if (!n) {
			continue;
		}

		/*
		 * Check if a connect has occured
		 */

		if (FD_ISSET(sck_inet,&wk_set) ){
			/*
			 * Wait for a connect
			 */
			len_inet = sizeof addr_clnt;
			c = accept (sck_inet,
					(struct sockaddr *)&addr_clnt,
					&len_inet);
			if (c == -1){
				if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN)){
					g_warning("accept");
				}
			}

			if ( get_number_of_clients() >= nuauth_tls_max_clients -1 ) {

				if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN)){
					g_warning("too many clients (%d configured)\n",nuauth_tls_max_clients);
				}
				close(c);
				continue;
			} else {
				/* if system is not in reload */
				if (! (nuauthdatas->need_reload)){
					struct client_connection* current_client_conn=g_new0(struct client_connection,1);
					struct pre_client_elt* new_pre_client;
					current_client_conn->socket=c;
					memcpy(&current_client_conn->addr,&addr_clnt,sizeof(struct sockaddr_in));

					if ( c+1 > mx )
						mx = c + 1;
					/* Set KEEP ALIVE on connection */
					setsockopt ( c,
							SOL_SOCKET,
							SO_KEEPALIVE,
							&option_value,
							sizeof(option_value));
					/* give the connection to a separate thread */
					/*  add element to pre_client 
					    create pre_client_elt */
					new_pre_client = g_new0(struct pre_client_elt,1);
					new_pre_client->socket = c;
					new_pre_client->validity = time(NULL) + nuauth_auth_nego_timeout;

					g_static_mutex_lock (&pre_client_list_mutex);
					pre_client_list=g_slist_prepend(pre_client_list,new_pre_client);
					g_static_mutex_unlock (&pre_client_list_mutex);
					g_thread_pool_push (tls_sasl_worker,
							current_client_conn,	
							NULL
							);
				} else {
					shutdown(c,SHUT_RDWR);
					close(c);
				}
			}
		}

		/*
		 * check for client activity
		 */
		for ( c=0; c<mx; ++c) {
			if ( c == sck_inet )
				continue;
			if ( FD_ISSET(c,&wk_set) ) {
				user_session * c_session;
				int u_request;
#ifdef DEBUG_ENABLE
				if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
					g_message("activity on %d\n",c);
#endif

				/* we lock here but can do other thing on hash as it is not destructive 
				 * in push mode modification of hash are done in push_worker */
				g_static_mutex_lock (&client_mutex);
				c_session = get_client_datas_by_socket(c);
				g_static_mutex_unlock (&client_mutex);
				if (nuauthconf->session_duration && c_session->expire < time(NULL)){
					FD_CLR(c,&tls_rx_set);
					g_static_mutex_lock (&client_mutex);
					delete_client_by_socket(c);
					g_static_mutex_unlock (&client_mutex);
				} else {
					u_request = treat_user_request( c_session );
					if (u_request == EOF) {
						log_user_session(c_session,SESSION_CLOSE);
#ifdef DEBUG_ENABLE
						if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
							g_message("client disconnect on %d\n",c);
#endif
						FD_CLR(c,&tls_rx_set);
						/* clean client structure */
						if (nuauthconf->push){
							struct internal_message* message=g_new0(struct internal_message,1);
							message->type = FREE_MESSAGE;
							message->datas = GINT_TO_POINTER(c);
							g_async_queue_push(nuauthdatas->tls_push_queue,message);
						} else {
							g_static_mutex_lock (&client_mutex);
							delete_client_by_socket(c);
							g_static_mutex_unlock (&client_mutex);
						}
					}else if (u_request < 0) {
#ifdef DEBUG_ENABLE
						if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
							g_message("treat_user_request() failure\n");
#endif
					}
				}
			}
		}

		for ( c = mx - 1;
				c >= 0 && !FD_ISSET(c,&tls_rx_set);
				c = mx -1 ){
#ifdef DEBUG_ENABLE
			if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
				g_message("setting mx to %d\n",c);
#endif
			mx = c;
		}
	}


	close(sck_inet);

	return NULL;

}

/** 
 * get RX paquet from a TLS client connection and send it to user authentication threads.
 *
 * - Argument : SSL RX packet
 * - Return : 1 if read done, EOF if read complete
 */
	static int
treat_nufw_request (nufw_session * c_session)
{
	char * dgram=NULL;
	int dgram_size;

	if (c_session != NULL){
		/* copy packet datas */
		dgram=g_new0(char,BUFSIZE);
		dgram_size =  gnutls_record_recv(*(c_session->tls),dgram,BUFSIZE) ;
		if (  dgram_size > 0 ){
			connection * current_conn;
			current_conn = authpckt_decode(dgram , dgram_size );
			if (current_conn == NULL){
				if ( *(dgram+1) != AUTH_CONTROL && *(dgram+1) != AUTH_CONN_DESTROY  )
					if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_PACKET)){
						g_warning("Can't parse packet, this IS bad !\n");
					}
			} else {

				current_conn->socket=0;
				current_conn->tls=c_session;
				/* gonna feed the birds */

				if (current_conn->state == STATE_HELLOMODE){
					struct internal_message *message = g_new0(struct internal_message,1);
					message->type=INSERT_MESSAGE;
					message->datas=current_conn;
					current_conn->state = STATE_AUTHREQ;
					g_async_queue_push (nuauthdatas->localid_auth_queue,message);
				}else {
					current_conn->state = STATE_AUTHREQ;
					g_async_queue_push (nuauthdatas->connexions_queue,
							current_conn,
							NULL);
				}
			}
		} else {
			g_free(dgram);
			g_atomic_int_dec_and_test(&(c_session->usage));
			return EOF;
		}
	}
	g_free(dgram);
	return 1;
}

void clean_nufw_session(nufw_session * c_session){

	gnutls_transport_ptr socket_tls;
	socket_tls=gnutls_transport_get_ptr(*(c_session->tls));
	close((int)socket_tls);
#ifdef DEBUG_ENABLE
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
		g_message("close nufw session calling");
#endif
	if (c_session->tls ){
		gnutls_bye(
				*(c_session->tls)	
				, GNUTLS_SHUT_RDWR);
		gnutls_deinit(
				*(c_session->tls)	
			     );
		g_free(c_session->tls);
	} else {


#ifdef DEBUG_ENABLE
		if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
			g_warning("close nufw session was called but NULL");
#endif

	}

#ifdef DEBUG_ENABLE
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
		g_message("close nufw session calling");
#endif
}


/**
 * TLS nufw packet server.
 *
 * - Argument : None
 * - Return : None
 */

void* tls_nufw_authsrv()
{
	int z;
	//struct sigaction action;
	struct sockaddr_in addr_inet,addr_clnt;
	unsigned int len_inet;
	int sck_inet;
	int n,c;
	int mx;
	gint option_value;
	fd_set tls_rx_set; /* read set */
	fd_set wk_set; /* working set */
	struct timeval tv;
	nufw_session * nu_session;
#if 0
	char *configfile=DEFAULT_CONF_FILE;
	gpointer vpointer;
	confparams nuauth_tls_vars[] = {
		{ "nuauth_tls_max_servers" , G_TOKEN_INT ,NUAUTH_TLS_MAX_SERVERS, NULL }
	};
	int nuauth_tls_max_servers=NUAUTH_TLS_MAX_SERVERS;
	/* get config file setup */
	/* parse conf file */
	parse_conffile(configfile,sizeof(nuauth_tls_vars)/sizeof(confparams),nuauth_tls_vars);
	/* set variable value from config file */
	vpointer=get_confvar_value(nuauth_tls_vars,sizeof(nuauth_tls_vars)/sizeof(confparams),"nuauth_tls_max_servers");
	nuauth_tls_max_servers=*(int*)(vpointer?vpointer:&nuauth_tls_max_servers);
#endif

	/* build servers hash */
	nufw_servers = g_hash_table_new_full(
			NULL,
			NULL,
			NULL,
			(GDestroyNotify)	clean_nufw_session
			);
	nufw_servers_mutex = g_mutex_new();

	/* this must be called once in the program
	*/
#if 0
	/* intercept SIGTERM */
	action.sa_handler = tls_nuauth_cleanup;
	sigemptyset( & (action.sa_mask));
	action.sa_flags = 0;
	if ( sigaction( SIGTERM, & action , NULL ) != 0) {
		printf("Error\n");
		exit(1);
	}
#endif

	/* open the socket */
	sck_inet = socket (AF_INET,SOCK_STREAM,0);

	if (sck_inet == -1)
	{
		g_warning("socket() failed, exiting");
		exit(-1);
	}

	option_value=1;
	setsockopt (
			sck_inet,
			SOL_SOCKET,
			SO_REUSEADDR,
			&option_value,
			sizeof(option_value));


	memset(&addr_inet,0,sizeof addr_inet);

	addr_inet.sin_family= AF_INET;
	addr_inet.sin_port=htons(nuauthconf->authreq_port);
	addr_inet.sin_addr.s_addr=nuauthconf->nufw_srv->s_addr;

	z = bind (sck_inet,
			(struct sockaddr *)&addr_inet,
			sizeof addr_inet);
	if (z == -1)
	{
		g_warning ("nufw bind() failed to %s:%d, exiting",inet_ntoa(addr_inet.sin_addr),nuauthconf->authreq_port);
		exit(-1);
	}

	/* Listen ! */
	z = listen(sck_inet,20);
	if (z == -1)
	{
		g_warning ("nufw listen() failed, exiting");
		exit(-1);
	}

	/* init fd_set */
	FD_ZERO(&tls_rx_set);
	FD_ZERO(&wk_set);
	FD_SET(sck_inet,&tls_rx_set);
	mx=sck_inet+1;
	mx_nufw_queue=g_async_queue_new ();

	for(;;){

		/*
		 * copy rx set to working set 
		 */
		FD_ZERO(&wk_set);
		for (z=0;z<mx;++z){
			if (FD_ISSET(z,&tls_rx_set))
				FD_SET(z,&wk_set);
		}

		/*
		 * define timeout 
		 */

		tv.tv_sec=2;
		tv.tv_usec=30000;

		n=select(mx,&wk_set,NULL,NULL,&tv);

		if (n == -1) {
			g_warning("select() failed, exiting\n");
			exit(EXIT_FAILURE);
		} else if (!n) {
			continue;
		}

		/*
		 * Check if a connect has occured
		 */

		if (FD_ISSET(sck_inet,&wk_set) ){
			/*
			 * Wait for a connect
			 */
			len_inet = sizeof addr_clnt;
			c = accept (sck_inet,
					(struct sockaddr *)&addr_clnt,
					&len_inet);
			if (c == -1){
				if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN)){
					g_warning("accept");
				}
			}

			/* test if server is in the list of authorized servers */
			if (! check_inaddr_in_array(addr_clnt.sin_addr,nuauthconf->authorized_servers)){
				if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN)){
					g_warning("unwanted server (%s)\n",inet_ntoa(addr_clnt.sin_addr));
				}
				close(c);
				continue;
			}
#if 0
			if ( c >= nuauth_tls_max_servers) {
				if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN)){
					g_warning("too much servers (%d configured)\n",nuauth_tls_max_servers);
				}
				close(c);
				continue;
			}
#endif

			/* initialize TLS */
			nu_session=g_new0(nufw_session,1);
			nu_session->usage=0;
			nu_session->alive=TRUE;
			nu_session->peername.s_addr=addr_clnt.sin_addr.s_addr;
			if (tls_connect(c,&(nu_session->tls)) == SASL_OK){
				g_mutex_lock(nufw_servers_mutex);
				g_hash_table_insert(nufw_servers,GINT_TO_POINTER(c),nu_session);
				g_mutex_unlock(nufw_servers_mutex);
				FD_SET(c,&tls_rx_set);
				if ( c+1 > mx )
					mx = c + 1;
			}
		}

		/*
		 * check for server activity
		 */
		for ( c=0; c<mx; ++c) {
			if ( c == sck_inet )
				continue;
			if ( FD_ISSET(c,&wk_set) ) {
				nufw_session * c_session;
#ifdef DEBUG_ENABLE
				if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
					g_message("activity on %d\n",c);
#endif
				c_session=g_hash_table_lookup( nufw_servers , GINT_TO_POINTER(c));
				g_atomic_int_inc(&(c_session->usage));
				if (treat_nufw_request(c_session) == EOF) {
					/* get session link with c */
#ifdef DEBUG_ENABLE
					if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_USER))
						g_message("nufw server disconnect on %d\n",c);
#endif
					FD_CLR(c,&tls_rx_set);
					g_mutex_lock(nufw_servers_mutex);
					if (g_atomic_int_get(&(c_session->usage)) == 0) {
						/* clean client structure */
						g_hash_table_remove(nufw_servers,GINT_TO_POINTER(c));
					} else {
						g_hash_table_steal(nufw_servers,GINT_TO_POINTER(c));
						c_session->alive=FALSE;
					}
					g_mutex_unlock(nufw_servers_mutex);
					close(c);
				}
			}
		}

		for ( c = mx - 1;
				c >= 0 && !FD_ISSET(c,&tls_rx_set);
				c = mx -1 ){
			mx = c;
		}
	}


	close(sck_inet);
	return NULL;

}

void  refresh_client (gpointer key, gpointer value, gpointer user_data)
{
	/* first check if a request is needed */
	if ( ((user_session *)value)->req_needed){
		struct timeval current_time;
		gettimeofday(&current_time,NULL);
		current_time.tv_sec=current_time.tv_sec -((user_session  *)value)->last_req.tv_sec;
		current_time.tv_usec=current_time.tv_usec -((user_session  *)value)->last_req.tv_usec;

#ifdef DEBUG_ENABLE
		if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER)){
			g_message("request needed");
		}
#endif

		/* check if timeout is reached */
		if ( 
				( current_time.tv_sec	 > 1 ) ||			
				(  abs(current_time.tv_usec) > TLS_CLIENT_MIN_DELAY ) 

		   ) {
#ifdef DEBUG_ENABLE
			if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER)){
				g_message("request now sent");
			}
#endif
			gnutls_record_send(*((user_session*)value)->tls,
					&((struct msg_addr_set *)user_data)->msg,
					sizeof(struct nuv2_srv_message)
					);
			((user_session  *)value)->req_needed=FALSE; 
			((user_session *)value)->last_req.tv_sec=current_time.tv_sec;
			((user_session  *)value)->last_req.tv_usec=current_time.tv_usec;
		}
	} 
}
/**
 * dequeue addr that need to do a check.
 * 
 * lock is only needed when modifications are done
 * because when this thread work (push mode) it's the only one
 * who can modify the hash
 */
void push_worker () 
{
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
					global_msg->addr=((tracking *)message->datas)->saddr;
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


void close_servers(int signal)
{
	g_mutex_lock(nufw_servers_mutex);
	g_hash_table_destroy(nufw_servers);
	nufw_servers=NULL;
	g_mutex_unlock(nufw_servers_mutex);
}

void end_tls(int signal)
{
	gnutls_global_deinit();
}
