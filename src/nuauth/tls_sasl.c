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

extern int nuauth_tls_auth_by_cert;

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

