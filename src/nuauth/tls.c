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
 ** In addition, as a special exception, the copyright holders give
 ** permission to link the code of portions of this program with the
 ** Cyrus SASL library under certain conditions as described in each
 ** individual source file, and distribute linked combinations
 ** including the two.
 ** You must obey the GNU General Public License in all respects
 ** for all of the code used other than Cyrus SASL.  If you modify
 ** file(s) with this exception, you may extend this exception to your
 ** version of the file(s), but you are not obligated to do so.  If you
 ** do not wish to do so, delete this exception statement from your
 ** version.  If you delete this exception statement from all source
 ** files in the program, then also delete it here.
 **
 ** This product includes software developed by Computing Services
 ** at Carnegie Mellon University (http://www.cmu.edu/computing/).
 **
 */


#include <auth_srv.h>

#include <sasl/saslutil.h>

#include <sys/time.h>
#include <time.h>


#include "tls.h"

struct tls_insert_data { 
	int socket;
	gpointer data;
};

/* These are global */
gnutls_certificate_credentials x509_cred;
int nuauth_tls_request_cert;

#if FAIT_BEAU
static const char *group_prop[]={SASL_USER_GROUPS,NULL};
#endif

GPrivate* group_priv;
GPrivate* user_priv;

int external_get_opt(void *context, const char *plugin_name,
		const char *option,
		const char **result, unsigned *len)
{
	if (! strcmp(option,"mech_list")){
		*result=strdup("external");
	}
	return SASL_OK;
}

int internal_get_opt(void *context, const char *plugin_name,
		const char *option,
		const char **result, unsigned *len)
{
	if (! strcmp(option,"mech_list")){
		*result=strdup("plain");
	}
	return SASL_OK;
}

int userdb_checkpass(sasl_conn_t *conn,
		void *context,
		const char *user,
		const char *pass,
		unsigned passlen,
		struct propctx *propctx)
{
	GSList *groups=NULL;
	uint16_t uid=0;

	/*
	 * call module to get password 
	 *	 and additional properties
	 */

	/* pass can not be null */
	if (pass==NULL || passlen==0){
		if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN))
			g_message("password sent by user %s is NULL",user);
		return SASL_BADAUTH;
	}

	if ((* module_user_check)(user,pass,passlen,&uid,&groups)==SASL_OK){
		guint tuid=uid;
		g_private_set(group_priv,groups);
		g_private_set(user_priv,GUINT_TO_POINTER(tuid));
		/* we're done */
		return SASL_OK;    
	}
	/* return to fallback */
	return SASL_NOAUTHZ;
}

static sasl_callback_t callbacks[] = {
	{ SASL_CB_GETOPT, &internal_get_opt, NULL },
	{ SASL_CB_SERVER_USERDB_CHECKPASS, &userdb_checkpass,NULL}, 
	{ SASL_CB_LIST_END, NULL, NULL }
};

static sasl_callback_t external_callbacks[] = {
	{ SASL_CB_GETOPT, &external_get_opt, NULL },
	{ SASL_CB_SERVER_USERDB_CHECKPASS, &userdb_checkpass,NULL}, 
	{ SASL_CB_LIST_END, NULL, NULL }
};

void clean_session(user_session * c_session){
#if TRY_DEBUG
	gnutls_bye(
			*(c_session->tls)	
			, GNUTLS_SHUT_RDWR);
#endif
	gnutls_deinit(
			*(c_session->tls)	
		     );
	g_free(c_session->tls);
	if (c_session->userid){
		g_free(c_session->userid);
	}
	g_slist_free(c_session->groups);
	g_free(c_session);
}

/* strictly close a tls session
 * nothing to care about client */

int close_tls_session(int c,gnutls_session* session){
	close(c);
	gnutls_deinit(*session);
#ifdef DEBUG_ENABLE
				if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
					g_message("gnutls_deinit() was called");
#endif
	g_free(session);
}
/** cleanly end a tls session */
int cleanly_close_tls_session(int c,gnutls_session* session){
	gnutls_bye(*session,GNUTLS_SHUT_WR);
#ifdef DEBUG_ENABLE
				if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
					g_message("gnutls_bye() was called");
#endif
	return close_tls_session(c,session);
}



gnutls_session* initialize_tls_session()
{
	gnutls_session* session;
	const int cert_type_priority[3] = { GNUTLS_CRT_X509, 0 };

	session = g_new0(gnutls_session,1);
        if (session == NULL)
            return NULL;

	if (gnutls_init(session, GNUTLS_SERVER) != 0)
            return NULL;

	/* avoid calling all the priority functions, since the defaults
	 * are adequate.
	 */
	if (gnutls_set_default_priority( *session)<0)
            return NULL;

	if (gnutls_certificate_type_set_priority(*session, cert_type_priority)<0)
            return NULL;

	if (gnutls_credentials_set(*session, GNUTLS_CRD_CERTIFICATE, x509_cred)<0)
            return NULL;
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
	static int
treat_user_request (user_session * c_session)
{
	struct buffer_read * datas;
	int read_size=0;

	if (c_session != NULL){
		datas=g_new0(struct buffer_read,1);
                if (datas==NULL)
                  return -1;
		datas->socket=0;
		datas->tls=c_session->tls;
		if (c_session->multiusers) {
			datas->userid=NULL;
			datas->uid=0;
			datas->groups=NULL;
		} else {
			datas->userid = g_strdup(c_session->userid);
#ifdef DEBUG_ENABLE
			if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
				g_message("Packet from user %s\n",datas->userid );
#endif
			datas->uid = c_session->uid;
			datas->groups = g_slist_copy (c_session->groups);
		}
		if (c_session->sysname){
			datas->sysname=g_strdup(c_session->sysname);
                        if (datas->sysname == NULL)
                            return -1;
                }
		if (c_session->release){
			datas->release=g_strdup(c_session->release);
                        if (datas->release == NULL)
                            return -1;
                }
		if (c_session->version){
			datas->version=g_strdup(c_session->version);
                        if (datas->version == NULL)
                            return -1;
                }
		/* copy packet datas */
		datas->buf=g_new0(char,BUFSIZE);
                if (datas->buf == NULL)
                    return -1;
		read_size = gnutls_record_recv(*(c_session->tls),datas->buf,BUFSIZE);
		if ( read_size> 0 ){
			struct nuv2_header* pbuf=(struct nuv2_header* )datas->buf;
			/* get header to check if we need to get more datas */
#ifdef DEBUG_ENABLE
			if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
				g_message("Packet size is %d\n",pbuf->length );
#endif

			if (pbuf->proto==2 && pbuf->length> read_size && pbuf->length<1800 ){
				/* we realloc and get what we miss */
				datas->buf=g_realloc(datas->buf,pbuf->length);
				if (gnutls_record_recv(*(c_session->tls),datas->buf+BUFSIZE,read_size-pbuf->length)<0)
                                    return -1;
			}
			/* check authorization if we're facing a multi user packet */ 
			if ( (pbuf->option == 0x0) ||
					((pbuf->option == 0x1) && c_session->multiusers)) {

#ifdef DEBUG_ENABLE
				if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
					g_message("Pushing packet to user_checker");
#endif
				g_thread_pool_push (user_checkers,
						datas,	
						NULL
						);
			} else {
#ifdef DEBUG_ENABLE
				if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
					g_message("Bad packet, option of header is not set");
#endif
			}
		} else {
#ifdef DEBUG_ENABLE
                        if (read_size <0) //FIXME : Gryzor added this test, but is unsure
			  if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
				g_message("Receive error from user %s\n",datas->userid );
#endif

			if (datas->sysname)
				g_free(datas->sysname);
			if (datas->release)
				g_free(datas->release);
			if (datas->version)
				g_free(datas->version);
			g_free(datas->buf);
			g_free(datas->userid);
			g_slist_free(datas->groups);
			g_free(datas);
			return EOF;
		}
	}
	return 1;
}


/**
 * do the sasl negotiation.
 *
 * return -1 if it fails
 */
int mysasl_negotiate(user_session * c_session , sasl_conn_t *conn)
{
	char buf[8192];
	char chosenmech[128];
	const char *data=NULL;
	unsigned len=0;
	int r = SASL_FAIL;
	int count;
	int ret=0;
	gnutls_session session=*(c_session->tls);
	gboolean external_auth=FALSE;
	struct in_addr remote_inaddr;
	ssize_t record_send;
        char addresse[INET_ADDRSTRLEN+1];

	remote_inaddr.s_addr=c_session->addr;

	r = sasl_listmech(conn, NULL, "(",",",")",
			&data, &len, &count);
	if (r != SASL_OK) {
		if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN)){
			g_warning("generating mechanism list");
		}
		return SASL_BADPARAM;
	}
#ifdef DEBUG_ENABLE
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
		g_message("%d mechanisms : %s\n", count,data);
#endif
	/* send capability list to client */
	record_send = gnutls_record_send(session, data, len);
	if (( record_send == GNUTLS_E_INTERRUPTED ) || ( record_send == GNUTLS_E_AGAIN)){
#ifdef DEBUG_ENABLE
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
		g_message("sasl nego : need to resent packet");
	}
#endif
		record_send = gnutls_record_send(session, data, len);
	}
	if (record_send<0) 
	{
		return SASL_FAIL;
	}

	memset(chosenmech,0,sizeof chosenmech);
	len = gnutls_record_recv(session, chosenmech, sizeof chosenmech);
	if (len <= 0) {
		if (len==0){
			if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN)){
				g_message("client didn't choose mechanism\n");
			}
			if (gnutls_record_send(session,"N", 1) <= 0) /* send NO to client */
                            return SASL_FAIL;
			return SASL_BADPARAM;
		} else {

			if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN)){
				g_message("ssal nego : tls crash");
			}
			return SASL_FAIL; 
		}
	} 
#ifdef DEBUG_ENABLE
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
		g_message("client chose mechanism %s\n",chosenmech);
#endif

	memset(buf,0,sizeof buf);
	len = gnutls_record_recv(session, buf, sizeof(buf));
	if(len != 1) {
		if (len<0){
			return SASL_FAIL;
		}
#ifdef DEBUG_ENABLE
		if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN))
			g_message("didn't receive first-sent parameter correctly");
#endif
		if (gnutls_record_send(session,"N", 1) <= 0) /* send NO to client */
                    return SASL_FAIL;
		return SASL_BADPARAM;
	}

	if(buf[0] == 'Y') {
		/* receive initial response (if any) */


		memset(buf,0,sizeof(buf));
		len = gnutls_record_recv(session, buf, sizeof(buf));
		if (len<0){
			return SASL_FAIL;
		}
		/* start libsasl negotiation */
		r = sasl_server_start(conn, 
				chosenmech, 
				buf, 
				len,
				&data,
				&len);
	} else {
#ifdef DEBUG_ENABLE
		if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN))
			g_message("start with no msg");
#endif
		r = sasl_server_start(conn, 
				chosenmech, 
				NULL, 
				0,
				&data, 
				&len);

	}



	if (r != SASL_OK && r != SASL_CONTINUE) {

		if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN)){
			g_warning("sasl negotiation error: %d",r);
		}
		ret = sasl_getprop(conn, SASL_USERNAME, (const void **)	&(c_session->userid));
		if (ret == SASL_OK){
			if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN)){
                                inet_ntop( AF_INET, &remote_inaddr, addresse, INET_ADDRSTRLEN);
				g_warning("%s at %s is a badguy",c_session->userid,addresse);
                        }
		}else{
			if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN)){
                                inet_ntop( AF_INET, &remote_inaddr, addresse, INET_ADDRSTRLEN);
				g_warning("unidentified badguy(?) from %s",addresse);
                        }
		}
		if (gnutls_record_send(session,"N", 1)<=0) /* send NO to client */
			return SASL_FAIL;
		return SASL_BADPARAM;
	}



	while (r == SASL_CONTINUE) {

		if (data) {
			if (gnutls_record_send(session,"C", 1)<=0) /* send CONTINUE to client */
				return SASL_FAIL;
			if (gnutls_record_send(session, data, len)<0)
				return SASL_FAIL;
		} else {
			if (gnutls_record_send(session,"C", 1)<=0) /* send CONTINUE to client */
				return SASL_FAIL;
			if (gnutls_record_send(session, "", 0)<0)
				return SASL_FAIL;
		}


		memset(buf,0,sizeof buf);
		len = gnutls_record_recv(session, buf, sizeof buf);
		if (len <= 0) {
#ifdef DEBUG_ENABLE
			if (!len){
				if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
					g_message("Client disconnected during sasl negotiation\n");
				}
			} else {
				if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
					g_message("TLS error during sasl negotiation\n");
				}
			}
#endif
			return SASL_FAIL;
		}

		r = sasl_server_step(conn, buf, len, &data, &len);
		if (r != SASL_OK && r != SASL_CONTINUE) {
#ifdef DEBUG_ENABLE
			if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
				g_message("error performing SASL negotiation");
				g_message("\n%s\n", sasl_errdetail(conn));
			}
#endif
			if (gnutls_record_send(session,"N", 1) <= 0) /* send NO to client */
				return SASL_FAIL;
			return SASL_BADPARAM;
		}
	} // while continue

		
	if (r != SASL_OK) {
#ifdef DEBUG_ENABLE
		if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
			g_warning("incorrect authentication");
		}
#endif
		if (gnutls_record_send(session,"N", 1) <= 0) /* send NO to client */
			return SASL_FAIL;
		return SASL_BADAUTH;
	}


	if (c_session->userid)
		external_auth=TRUE;

	if (external_auth == FALSE){
		char * tempname=NULL;
		ret = sasl_getprop(conn, SASL_USERNAME, (const void **)	&(tempname));
		if (ret != SASL_OK){
			g_warning("get user failed");
			return SASL_FAIL;
		}else{
			c_session->userid=g_strdup(tempname);
		}
	}
	//	if (ret != SASL_OK)
	//		g_warning("get user failed");

	/* check on multi user capability */
	if ( check_inaddr_in_array(remote_inaddr,nuauth_multi_servers_array)){
		gchar* stripped_user=get_rid_of_domain(c_session->userid);
		if (check_string_in_array(stripped_user,nuauth_multi_users_array)) {
			c_session->multiusers=TRUE;
		} else {
#ifdef DEBUG_ENABLE
			if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
                              inet_ntop( AF_INET, &remote_inaddr, addresse, INET_ADDRSTRLEN);
			      g_message("%s users on multi server %s\n", c_session->userid,addresse);
			      //g_message("%s users on multi server %s\n", c_session->userid,inet_ntoa(remote_inaddr));
                        }
#endif
			if (gnutls_record_send(session,"N", 1) <= 0) /* send NO to client */
				return SASL_FAIL;
		}
		g_free(stripped_user);
	} else {
		c_session->multiusers=FALSE;
	}

	/* in case no call to user_checkdb has been done we need to fill the group */

	if (external_auth == FALSE){
		c_session->groups=g_private_get(group_priv);
		c_session->uid=GPOINTER_TO_UINT(g_private_get(user_priv));
		if (c_session->uid == 0) 
		{
			if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN))
				g_message("Couldn't get user ID!");	
		}
		if (c_session->groups == NULL){
			if((*module_user_check)(c_session->userid,NULL,0,&(c_session->uid),&(c_session->groups))!=SASL_OK){
#ifdef DEBUG_ENABLE
				if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)){
					g_message("error when searching user groups");	
				}
#endif
				if (gnutls_record_send(session,"N", 1) <= 0) /* send NO to client */
                                    return SASL_FAIL;
				return SASL_BADAUTH;
			}
		}
	}

	if (gnutls_record_send(session,"O", 1) <= 0) /* send YES to client */
		return SASL_FAIL;
	//g_message( "negotiation complete\n");

	return SASL_OK;

}



/**
 * realize user negotiation from after TLS to the end. 
 */

int sasl_user_check(user_session* c_session)
{
	char *service="nufw";
	char *myhostname="nuserver";
	char *myrealm="nufw";
	sasl_conn_t * conn=NULL;
	sasl_security_properties_t secprops;
	gboolean external_auth=FALSE;
	char buf[1024];
        char addresse[INET_ADDRSTRLEN+1];
#if FAIT_BEAU
	char *groups=NULL;
#endif
	int ret;
	if (c_session->userid) {
		external_auth=TRUE;
	} 

	if (external_auth){
		ret = sasl_server_new(service, myhostname, myrealm, NULL, NULL,
				external_callbacks, 0, &conn);
	} else {
		ret = sasl_server_new(service, myhostname, myrealm, NULL, NULL,
				callbacks, 0, &conn);
	}
	if (ret != SASL_OK) {
		g_warning("allocating connection state - failure at sasl_server_new()");
	}

	secprops.min_ssf = 0;
	secprops.max_ssf = 0;
	secprops.property_names = NULL;
	secprops.property_values = NULL;
	secprops.security_flags = SASL_SEC_NOANONYMOUS; /* as appropriate */

	sasl_setprop(conn, SASL_SEC_PROPS, &secprops);

	if (external_auth){
		sasl_ssf_t extssf = 0;

#ifdef DEBUG_ENABLE
		if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
			g_message("setting params for external");
		if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
			g_message("TLS gives user %s, trying EXTERNAL",c_session->userid);	
		}
#endif
		ret = sasl_setprop(conn, SASL_AUTH_EXTERNAL,c_session->userid);
		if (ret != SASL_OK){
			if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN))
				g_warning("Error setting external auth");
		}
		ret = sasl_setprop(conn,SASL_SSF_EXTERNAL,&extssf);
		if (ret != SASL_OK){
			if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN))
				g_warning("Error setting external SSF");
		}
		ret = mysasl_negotiate(c_session, conn);
	} else {
		ret = mysasl_negotiate(c_session, conn);
	}
	if ( ret == SASL_OK ) {
		//char *remoteip=NULL;
		struct in_addr remote_inaddr;
		remote_inaddr.s_addr=c_session->addr;
                inet_ntop( AF_INET, &remote_inaddr, addresse, INET_ADDRSTRLEN);
//		remoteip=inet_ntoa(remote_inaddr); //FIXME Gryzor : this function is NOT thread safe ??? See inet_ntop(3)
		log_new_user(c_session->userid,addresse);
#ifdef DEBUG_ENABLE
		if (c_session->multiusers){
			if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)){
				g_message("multi user client");	
			}
		}
#endif

		/* recv OS datas from client */
		ret  = gnutls_record_recv(*(c_session->tls),buf,sizeof buf) ;
		if (ret  <= 0){
			/* allo houston */
#ifdef DEBUG_ENABLE
			if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)){
				g_message("error when receiving user OS");	
			}
#endif
			sasl_dispose(&conn);
			return SASL_FAIL;
		} else {
			int len;
			int decode;
			struct nuv2_authfield* osfield;
			gchar*	dec_buf=NULL;
			gchar** os_strings;
			osfield=(struct nuv2_authfield*)buf;
			if (osfield->type == OS_FIELD) {
				int dec_buf_size = osfield->length *8 - 32;
				if ( dec_buf_size > 1024 ) {
					/* it's a joke it's far too long */
					if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN)){
						g_warning("error osfield is too long, announced %d",osfield->length);	
					}
					sasl_dispose(&conn);
					return SASL_BADAUTH;
				}
				dec_buf = g_new0( gchar ,dec_buf_size);
				decode = sasl_decode64(buf+4,osfield->length -4,dec_buf, dec_buf_size,&len);
				switch (decode){
					case SASL_BUFOVER:
						{
								  if (len > 1024)
								  {
									  sasl_dispose(&conn);
									  g_free(dec_buf);
									  return SASL_BADAUTH;
								  }
								  dec_buf=g_try_realloc(dec_buf,len);
								  if (dec_buf){
									  if (sasl_decode64(buf+4,osfield->length -4,
												  dec_buf,len,&len) != SASL_OK){
										  sasl_dispose(&conn);
										  g_free(dec_buf);
										  return SASL_BADAUTH;
									  }

								  }else{
									  sasl_dispose(&conn);
									  g_free(dec_buf);
									  return SASL_BADAUTH;
								  }
								  break;
						  }
					case SASL_OK:
						{
							     break;
					     }
					default:
						{
							sasl_dispose(&conn);
							g_free(dec_buf);
							return SASL_BADAUTH;
						}
				}


				/* should always be true for the moment */
				if (osfield->option == OS_SRV){
					os_strings=g_strsplit(dec_buf,";",3);
					if (os_strings[0] && (strlen(os_strings[1]) < 128) ){
						c_session->sysname=string_escape(os_strings[0]);
						if (c_session->sysname==NULL){
							if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_USER))
								g_warning("received sysname contains invalid characters");	
							sasl_dispose(&conn);
							g_free(dec_buf);
							return SASL_BADAUTH;
						}
					} else {
						c_session->sysname=g_strdup(UNKNOWN_STRING);
					}
					if (os_strings[1] && (strlen(os_strings[1]) < 128) )   {
						c_session->release=string_escape(os_strings[1]);
						if (c_session->release==NULL){
							if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_USER))
								g_warning("received release contains invalid characters");	
							sasl_dispose(&conn);
							g_free(dec_buf);
							return SASL_BADAUTH;
						}
					} else {
						c_session->release=g_strdup(UNKNOWN_STRING);
					}
					if (os_strings[2] && (strlen(os_strings[2]) < 128) )  {
						c_session->version=string_escape(os_strings[2]);
						if (c_session->version==NULL){
							if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_USER))
								g_warning("received version contains invalid characters");	
							sasl_dispose(&conn);
							g_free(dec_buf);
							return SASL_BADAUTH;
						}
					} else {
						c_session->version=g_strdup(UNKNOWN_STRING);
					}
					/* print information */
					if (c_session->sysname && c_session->release && 
							c_session->version){

#ifdef DEBUG_ENABLE
						if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)){
							g_message("user %s uses OS %s ,%s, %s",c_session->userid,
									c_session->sysname , c_session->release , c_session->version);

						}
#endif
					}
					g_strfreev(os_strings);
				}
				g_free(dec_buf);
			}
		}
		/* sasl connection is not used anymore */
		sasl_dispose(&conn);
		return SASL_OK;
	} else {
		sasl_dispose(&conn);
		return ret;
	}
}

void socket_close(gpointer data)
{
	close(GPOINTER_TO_INT(data));
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
#ifdef DEBUG_ENABLE
        if (session==NULL)
            if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN))
                g_message("NuFW TLS Init failure (initialize_tls_session())\n");
#endif
	gnutls_transport_set_ptr( *session, (gnutls_transport_ptr)c);

#ifdef DEBUG_ENABLE
	if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)){
		g_message("NuFW TLS Handshaking\n");
	}
#endif
	ret = gnutls_handshake( *session);
#ifdef DEBUG_ENABLE
	if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)){
		g_message("gnutls_handshake() was just called\n");
	}
#endif
        while ((ret == GNUTLS_E_AGAIN) || (ret == GNUTLS_E_INTERRUPTED))
        {
#ifdef DEBUG_ENABLE
	    if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)){
		  g_message("gnutls_handshake() was just called again\n");
	    }
#endif
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
		if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN)){
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
		ret = gnutls_certificate_verify_peers(*session);
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
	int ret;
	int c = ((struct client_connection*)userdata)->socket;

	if (tls_connect(c,&session) != SASL_BADPARAM){
		c_session=g_new0(user_session,1);
		c_session->tls=session;
		c_session->addr=((struct client_connection*)userdata)->addr.sin_addr.s_addr;
		c_session->groups=NULL;
		c_session->last_req.tv_sec=0;
		c_session->last_req.tv_usec=0;
		c_session->req_needed=TRUE;
		c_session->userid=NULL;
		g_free(userdata);
		if (nuauth_tls_request_cert == GNUTLS_CERT_REQUIRE) 
		{
			gchar* username=NULL;
			/* need to parse the certificate to see if it is a sufficient credential */
			username=parse_x509_certificate_info(*session);
			/* parsing complete */ 
			if (username){
#ifdef DEBUG_ENABLE
				if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
					g_message("Using username %s from X509 certificate",username);
#endif
				if( (* module_user_check)(username, NULL, 0,
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
		ret = sasl_user_check(c_session);
		switch (ret){
			case SASL_OK:
				{
					struct nuv2_srv_message msg;
					if (nuauth_push) {
						struct tls_message* message=g_new0(struct tls_message,1);
						struct tls_insert_data * datas=g_new0(struct tls_insert_data,1);
						datas->socket=c;
						datas->data=c_session;
						message->datas=datas;
						message->type=INSERT_CLIENT;
						g_async_queue_push(tls_push,message);
					} else {
						g_static_mutex_lock (&client_mutex);
						g_hash_table_insert(client,GINT_TO_POINTER(c),c_session);
						g_static_mutex_unlock (&client_mutex);
					}
					/* unlock hash client */
					msg.type=SRV_TYPE;
					if (nuauth_push){
						msg.option = SRV_TYPE_PUSH ;
					} else {
						msg.option = SRV_TYPE_POLL ;
					}
					msg.length=0;
					/* send mode to client */
					if (gnutls_record_send(*(c_session->tls),&msg,sizeof(msg)) < 0){ //FIXME : gryzor added this if() which must be checked
#ifdef DEBUG_ENABLE
                                            if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_USER))
                                              g_message("Argh. gnutls_record_send() failure");
#endif
					    close_tls_session(c,c_session->tls);
                                            g_free(c_session);
                                            break;
                                        }

#ifdef DEBUG_ENABLE
					if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
						g_message("Tell we need to work on %d\n",c);
#endif
					g_async_queue_push(mx_queue,GINT_TO_POINTER(c));
				} 
				break;
			case SASL_FAIL:
#ifdef DEBUG_ENABLE
				if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
					g_message("Crash on user side, closing socket");
#endif

				close_tls_session(c,c_session->tls);
				g_free(c_session);
				break;
			default:
#ifdef DEBUG_ENABLE
				if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
					g_message("Problem with user, closing socket");
#endif
				/* get rid of client */
				cleanly_close_tls_session(c,c_session->tls);
				g_free(c_session);
		}
	}
}

/**
 * Read conf file and allocate x509 credentials
 *
 */

void create_x509_credentials(){
	char* nuauth_tls_key=NUAUTH_KEYFILE;
	char* nuauth_tls_cert=NUAUTH_KEYFILE;
	char* nuauth_tls_cacert=NUAUTH_KEYFILE;
	char* nuauth_tls_key_passwd=NUAUTH_KEY_PASSWD;
	char* nuauth_tls_crl=NULL;
	char *configfile=DEFAULT_CONF_FILE;
	gpointer vpointer;
	int ret;
        int dh_params;
	confparams nuauth_tls_vars[] = {
		{ "nuauth_tls_key" , G_TOKEN_STRING , 0, NUAUTH_KEYFILE },
		{ "nuauth_tls_cert" , G_TOKEN_STRING , 0, NUAUTH_KEYFILE },
		{ "nuauth_tls_cacert" , G_TOKEN_STRING , 0, NUAUTH_KEYFILE },
		{ "nuauth_tls_crl" , G_TOKEN_STRING , 0, NULL },
		{ "nuauth_tls_key_passwd" , G_TOKEN_STRING , 0, NUAUTH_KEY_PASSWD },
		{ "nuauth_tls_request_cert" , G_TOKEN_INT ,TRUE, NULL }
	};
	parse_conffile(configfile,sizeof(nuauth_tls_vars)/sizeof(confparams),nuauth_tls_vars);
	/* set variable value from config file */
	vpointer=get_confvar_value(nuauth_tls_vars,sizeof(nuauth_tls_vars)/sizeof(confparams),"nuauth_tls_key");
	nuauth_tls_key=(char*)(vpointer?vpointer:nuauth_tls_key);

	vpointer=get_confvar_value(nuauth_tls_vars,sizeof(nuauth_tls_vars)/sizeof(confparams),"nuauth_tls_cert");
	nuauth_tls_cert=(char*)(vpointer?vpointer:nuauth_tls_cert);

	vpointer=get_confvar_value(nuauth_tls_vars,sizeof(nuauth_tls_vars)/sizeof(confparams),"nuauth_tls_cacert");
	nuauth_tls_cacert=(char*)(vpointer?vpointer:nuauth_tls_cacert);

	vpointer=get_confvar_value(nuauth_tls_vars,sizeof(nuauth_tls_vars)/sizeof(confparams),"nuauth_tls_crl");
	nuauth_tls_crl=(char*)(vpointer?vpointer:nuauth_tls_crl);

	vpointer=get_confvar_value(nuauth_tls_vars,sizeof(nuauth_tls_vars)/sizeof(confparams),"nuauth_tls_key_passwd");
	nuauth_tls_key_passwd=(char*)(vpointer?vpointer:nuauth_tls_key_passwd);

	nuauth_tls_request_cert=TRUE;
	vpointer=get_confvar_value(nuauth_tls_vars,sizeof(nuauth_tls_vars)/sizeof(confparams),"nuauth_tls_request_cert");
	nuauth_tls_request_cert=*(int*)(vpointer?vpointer:&nuauth_tls_request_cert);
	if (nuauth_tls_request_cert == TRUE){
		nuauth_tls_request_cert=GNUTLS_CERT_REQUIRE;
	} else {
		nuauth_tls_request_cert=GNUTLS_CERT_REQUEST;
	}

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
		if (	nuauth_tls_request_cert == GNUTLS_CERT_REQUIRE)
			g_message("TLS require cert from client");
	}
#endif

	if (nuauth_tls_crl){
		if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
			g_message("certificate revocation list : %s\n",nuauth_tls_crl);
		gnutls_certificate_set_x509_crl_file(x509_cred, nuauth_tls_crl, 
				GNUTLS_X509_FMT_PEM);
	}
	dh_params = generate_dh_params();
#ifdef DEBUG_ENABLE
        if (dh_params < 0)
            if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_USER))
                g_message("generate_dh_params() failed\n");
#endif


	gnutls_certificate_set_dh_params( x509_cred, dh_params);
}

/**
 * TLS user packet server.
 * 
 * - Argument : None
 * - Return : None
 */

void* tls_user_authsrv()
{
	int z;
	//struct sigaction action;
	struct sockaddr_in addr_inet,addr_clnt;
	GThreadPool* tls_sasl_worker;
	int len_inet;
	int sck_inet;
	int n,c,ret;
	int mx;
	fd_set tls_rx_set; /* read set */
	fd_set wk_set; /* working set */
	struct timeval tv;
	gpointer vpointer;
	char *configfile=DEFAULT_CONF_FILE;
	gpointer c_pop;

	confparams nuauth_tls_vars[] = {
		{ "nuauth_tls_max_clients" , G_TOKEN_INT ,NUAUTH_SSL_MAX_CLIENTS, NULL },
		{ "nuauth_number_authcheckers" , G_TOKEN_INT ,NB_AUTHCHECK, NULL }
	};
	int nuauth_tls_max_clients=NUAUTH_TLS_MAX_CLIENTS;
	int nuauth_number_authcheckers=NB_AUTHCHECK;
	/* get config file setup */
	/* parse conf file */
	parse_conffile(configfile,sizeof(nuauth_tls_vars)/sizeof(confparams),nuauth_tls_vars);
	vpointer=get_confvar_value(nuauth_tls_vars,sizeof(nuauth_tls_vars)/sizeof(confparams),"nuauth_tls_max_clients");
	nuauth_tls_max_clients=*(int*)(vpointer?vpointer:&nuauth_tls_max_clients);
	vpointer=get_confvar_value(nuauth_tls_vars,sizeof(nuauth_tls_vars)/sizeof(confparams),"nuauth_number_authcheckers");
	nuauth_number_authcheckers=*(int*)(vpointer?vpointer:&nuauth_number_authcheckers);

	/* build client hash */
	client = g_hash_table_new_full(
			NULL,
			NULL,
			(GDestroyNotify) socket_close,
			(GDestroyNotify) clean_session
			);


	/* initialize SASL */
	ret = sasl_server_init(callbacks, "nuauth");
	if (ret != SASL_OK){
		exit(EXIT_FAILURE);
	}
	/* end SASL */


	/* init private stuff, here to be made only once */
	group_priv = g_private_new(g_free);
	user_priv = g_private_new(g_free);
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

	memset(&addr_inet,0,sizeof addr_inet);

	addr_inet.sin_family= AF_INET;
	addr_inet.sin_port=htons(userpckt_port);
	addr_inet.sin_addr.s_addr=client_srv.sin_addr.s_addr;

	len_inet = sizeof addr_inet;

	z = bind (sck_inet,
			(struct sockaddr *)&addr_inet,
			len_inet);
	if (z == -1)
	{
		g_warning ("user bind() failed on port %d, exiting",userpckt_port);
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

#ifdef DEBUG_ENABLE
		if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
			g_message("mx is %d\n",mx);
#endif
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

#ifdef DEBUG_ENABLE
		if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
			g_message("copy rx set");
#endif
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

			if ( c >= nuauth_tls_max_clients) {

				if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN)){
					g_warning("too many clients (%d configured)\n",nuauth_tls_max_clients);
				}
				close(c);
				continue;
			} else {
				struct client_connection* current_conn=g_new0(struct client_connection,1);
				current_conn->socket=c;
				memcpy(&current_conn->addr,&addr_clnt,sizeof(struct sockaddr_in));

				if ( c+1 > mx )
					mx = c + 1;
				/* give the connection to a separate thread */

				g_thread_pool_push (tls_sasl_worker,
						current_conn,	
						NULL
						);
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
				c_session = g_hash_table_lookup(client ,GINT_TO_POINTER(c));
                                u_request = treat_user_request( c_session );
				if (u_request == EOF) {
#ifdef DEBUG_ENABLE
					if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
						g_message("client disconnect on %d\n",c);
#endif
					FD_CLR(c,&tls_rx_set);
					/* clean client structure */
					if (nuauth_push){
						struct tls_message* message=g_new0(struct tls_message,1);
						message->type = FREE_CLIENT;
						message->datas = GINT_TO_POINTER(c);
						g_async_queue_push(tls_push,message);
					} else {
						g_static_mutex_lock (&client_mutex);
						g_hash_table_remove(client,GINT_TO_POINTER(c));
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

		for ( c = mx - 1;
				c >= 0 && !FD_ISSET(c,&tls_rx_set);
				c = mx -1 ){
#ifdef DEBUG_ENABLE
			if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
				g_message("setting mx to %d\n",c);
#endif
			mx = c;
		}
#ifdef DEBUG_ENABLE
		if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
			g_message("mx set to %d\n",mx);
#endif
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
				if ( *(dgram+1) != AUTH_CONTROL )
					if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_PACKET)){
						g_warning("Can't parse packet, this IS bad !\n");
					}
			} else {

				current_conn->socket=0;
				current_conn->tls=c_session;
				/* gonna feed the birds */
				current_conn->state = STATE_AUTHREQ;
				/* put gateway addr in struct */
				g_thread_pool_push (acl_checkers,
						current_conn,
						NULL);
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
	gnutls_bye(
			*(c_session->tls)	
			, GNUTLS_SHUT_RDWR);
	gnutls_deinit(
			*(c_session->tls)	
		     );
	g_free(c_session->tls);
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
	int len_inet;
	int sck_inet;
	int n,c;
	int mx;
	fd_set tls_rx_set; /* read set */
	fd_set wk_set; /* working set */
	struct timeval tv;
	gpointer vpointer;
	char *configfile=DEFAULT_CONF_FILE;
	nufw_session * nu_session;
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

	/* build servers hash */
	nufw_servers = g_hash_table_new_full(
			NULL,
			NULL,
			(GDestroyNotify)socket_close,
			(GDestroyNotify)	clean_nufw_session
			);


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

	memset(&addr_inet,0,sizeof addr_inet);

	addr_inet.sin_family= AF_INET;
	addr_inet.sin_port=htons(authreq_port);
	addr_inet.sin_addr.s_addr=nufw_srv.sin_addr.s_addr;

	len_inet = sizeof addr_inet;

	z = bind (sck_inet,
			(struct sockaddr *)&addr_inet,
			len_inet);
	if (z == -1)
	{
		g_warning ("nufw bind() failed on port %d, exiting",authreq_port);
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
			if (c == -1)
				if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN)){
					g_warning("accept");
				}

			/* test if server is in the list of authorized servers */
			if (! check_inaddr_in_array(addr_clnt.sin_addr,authorized_servers)){
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
			if (tls_connect(c,&(nu_session->tls)) == SASL_OK){
				g_hash_table_insert(nufw_servers,GINT_TO_POINTER(c),nu_session);
				FD_SET(c,&tls_rx_set);
				if ( c+1 > mx )
					mx = c + 1;
			} else {
				close(c);
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
					if (g_atomic_int_get(&(c_session->usage)) == 0) {
						/* clean client structure */
						g_hash_table_remove(nufw_servers,GINT_TO_POINTER(c));
					} else {
						g_hash_table_steal(nufw_servers,GINT_TO_POINTER(c));
						c_session->alive=FALSE;
					}
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

struct msg_addr_set {
	struct nuv2_srv_message msg;
	uint32_t addr;
	uint16_t delay;
	gboolean found;
};

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
 * warn client that it need to check about new connection.
 * 
 */

void  warn_client (gpointer key, gpointer value, gpointer user_data)
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
		if ( ((struct msg_addr_set *)user_data)->addr == htonl(((user_session*)value)->addr) ) {
			((struct msg_addr_set *)user_data)->found = TRUE;
		}
	} else {
		if ( ((struct msg_addr_set *)user_data)->addr == htonl(((user_session*)value)->addr) ) {
			((struct msg_addr_set *)user_data)->found = TRUE;
			struct timeval current_time;
			gettimeofday(&current_time,NULL);
			current_time.tv_sec=current_time.tv_sec -((user_session  *)value)->last_req.tv_sec;
			current_time.tv_usec=current_time.tv_usec -((user_session  *)value)->last_req.tv_usec;
			if ( 
					( current_time.tv_sec	 > 1 ) ||			
					(  abs(current_time.tv_usec) > TLS_CLIENT_MIN_DELAY ) 

			   ) {

#ifdef DEBUG_ENABLE
				if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER)){
					g_message("sending request");
				}
#endif
				gnutls_record_send(*((user_session*)value)->tls,
						&((struct msg_addr_set *)user_data)->msg,
						sizeof(struct nuv2_srv_message)
						);

				((user_session  *)value)->req_needed=FALSE; 
				((user_session *)value)->last_req.tv_sec=current_time.tv_sec;
				((user_session  *)value)->last_req.tv_usec=current_time.tv_usec;
			} else {
				((user_session  *)value)->req_needed=TRUE; 
			}
		}
	}
}

/**
 * dequeue addr that need to do a check.
 */
void push_worker () 
{
	struct msg_addr_set *global_msg=g_new0(struct msg_addr_set,1);
	struct tls_message * message;

	global_msg->msg.type=SRV_REQUIRED_PACKET;
	global_msg->msg.option=0;
	global_msg->msg.length=4;
	tls_push = g_async_queue_new ();
	if (!tls_push)
		exit(1);

	g_async_queue_ref (tls_push);

	/* wait for message */
	while ( ( message = g_async_queue_pop(tls_push))  ) {
		switch (message->type) {
			case WARN_CLIENTS:
				{
					global_msg->addr=((tracking *)message->datas)->saddr;
					global_msg->found = FALSE;
					/* search in client array */
					g_hash_table_foreach (client, warn_client, global_msg);
					/* do we have found something */
					if (global_msg->addr != INADDR_ANY){
						if (global_msg->found == FALSE ){
							/* if we do ip authentication send request to pool */
							if (nuauth_do_ip_authentication){
								g_thread_pool_push (ip_authentication_workers,
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
			case FREE_CLIENT:
				{
					g_static_mutex_lock (&client_mutex);
					g_hash_table_remove(client,message->datas);
					g_static_mutex_unlock (&client_mutex);
				}
				break;
			case INSERT_CLIENT:
				{
					struct tls_insert_data* datas=message->datas;
					/* FIXME regarde si pas bizarre */
					g_hash_table_insert(client,GINT_TO_POINTER(datas->socket),datas->data);
				}
				break;
			case REFRESH_CLIENTS:
				g_hash_table_foreach (client, refresh_client, NULL);
				break;
			default:
				g_message("lost");
		}
		g_free(message);
	}
}
