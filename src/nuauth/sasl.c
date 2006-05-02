/*
 ** Copyright(C) 2005-2006 INL
 ** Written by Eric Leblond <regit@inl.fr>
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
#include "security.h"

gchar * mech_string_internal;
gchar * mech_string_external;

GPrivate* group_priv;
GPrivate* user_priv;

/*sasl init function*/
void *sasl_gthread_mutex_init(void)
{
	GMutex* lock = g_mutex_new();
	if (!lock)								      
		return NULL;							      
	return lock;
}

int sasl_gthread_mutex_lock(void *lock)
{
	g_mutex_lock(lock);
	return 0;
}

int sasl_gthread_mutex_unlock(void *lock)
{
	g_mutex_unlock(lock);
	return 0;
}

void sasl_gthread_mutex_free(void *lock)
{
	g_mutex_free(lock);
}

/* where using private datas to avoid over allocating */

static int external_get_opt(void *context, const char *plugin_name,
		const char *option,
		const char **result, unsigned *len)
{
	if (! strcmp(option,"mech_list")){
		*result=mech_string_external;
	}
	return SASL_OK;
}

static int internal_get_opt(void *context, const char *plugin_name,
		const char *option,
		const char **result, unsigned *len)
{
	if (! strcmp(option,"mech_list")){
		*result=mech_string_internal;
	}
	return SASL_OK;
}

static int userdb_checkpass(sasl_conn_t *conn,
		void *context,
		const char *user,
		const char *pass,
		unsigned passlen,
		struct propctx *propctx)
{
	GSList *groups=NULL;
	uint32_t uid=0;
	char *dec_user=NULL;

	/*
	 * call module to get password 
	 *	 and additional properties
	 */

	/* pass can not be null */
	if (pass==NULL || passlen==0){
		log_message(INFO, AREA_AUTH, "Password sent by user %s is NULL",user);
		return SASL_BADAUTH;
	}

	/* convert username from utf-8 to locale */
	if (nuauthconf->uses_utf8){
		size_t bwritten;
		dec_user = g_locale_from_utf8  (user,
				-1,
				NULL,
				&bwritten,
				NULL);
		if ( ! dec_user ) {
			log_message(WARNING, AREA_AUTH, "Can not convert username at %s:%d",__FILE__,__LINE__);

			/* return to fallback */
			return SASL_NOAUTHZ;
		}
	} else {
		dec_user=(char*)user;
	}


	if ( modules_user_check(dec_user,pass,passlen,&uid,&groups) == SASL_OK){
		g_private_set(group_priv,groups);
		g_private_set(user_priv,GUINT_TO_POINTER(uid));
		/* we're done */
		if (nuauthconf->uses_utf8) g_free(dec_user);
		return SASL_OK;
	}
	if (nuauthconf->uses_utf8) g_free(dec_user);
	/* return to fallback */
	log_message(INFO, AREA_AUTH, "Bad auth from user at %s:%d",__FILE__,__LINE__);
	return SASL_NOAUTHZ;
}


/* called in tls_user_init */
void my_sasl_init()
{
	int ret;

	sasl_set_mutex(sasl_gthread_mutex_init, 
			sasl_gthread_mutex_lock, 
			sasl_gthread_mutex_unlock, 
			sasl_gthread_mutex_free);
	/* initialize SASL */
    ret = sasl_server_init(NULL, "nuauth");
    if (ret != SASL_OK){
        log_message(CRITICAL, AREA_AUTH, "Fail to init SASL library!");
        exit(EXIT_FAILURE);
    }

	mech_string_internal=g_strdup("plain");
	mech_string_external=g_strdup("external");

	/* init private stuff, here to be made only once */
	group_priv = g_private_new(g_free);
	user_priv = g_private_new(g_free);
}


/**
 * do the sasl negotiation.
 *
 * return -1 if it fails
 */
static int mysasl_negotiate(user_session_t * c_session , sasl_conn_t *conn)
{
	char buf[8192];
	char chosenmech[128];
	const char *data=NULL;
	int tls_len=0;
    unsigned sasl_len=0;
	int r = SASL_FAIL;
	int count;
	int ret=0;
	gnutls_session session=*(c_session->tls);
	gboolean external_auth=FALSE;
	struct in_addr remote_inaddr;
	ssize_t record_send;
	char address[INET_ADDRSTRLEN+1];

	remote_inaddr.s_addr=c_session->addr;

	r = sasl_listmech(conn, NULL, "(", ",", ")", &data,&sasl_len, &count);
	if (r != SASL_OK) {
		log_message(WARNING, AREA_AUTH, "generating mechanism list");
		return SASL_BADPARAM;
	}
	debug_log_message(VERBOSE_DEBUG, AREA_AUTH, "%d mechanisms : %s", count,data);
	tls_len=sasl_len;
	/* send capability list to client */
	record_send = gnutls_record_send(session, data, tls_len);
	if (( record_send == GNUTLS_E_INTERRUPTED ) || ( record_send == GNUTLS_E_AGAIN)){
		debug_log_message(VERBOSE_DEBUG, AREA_AUTH, "sasl nego : need to resend packet");
		record_send = gnutls_record_send(session, data, tls_len);
	}
	if (record_send<0) 
	{
		return SASL_FAIL;
	}
	debug_log_message(VERBOSE_DEBUG, AREA_AUTH, "Now we know record_send >= 0");

	memset(chosenmech,0,sizeof chosenmech);
	tls_len = gnutls_record_recv(session, chosenmech, sizeof chosenmech);
	if (tls_len <= 0) {
		if (tls_len==0){
			log_message(INFO, AREA_AUTH, "client didn't choose mechanism");
			if (gnutls_record_send(session,"N", 1) <= 0) /* send NO to client */
				return SASL_FAIL;
			return SASL_BADPARAM;
		} else {
			log_message(INFO, AREA_AUTH, "sasl nego : tls crash");
			return SASL_FAIL; 
		}
	} 
	debug_log_message(VERBOSE_DEBUG, AREA_AUTH, "client chose mechanism %s",chosenmech);

	memset(buf,0,sizeof buf);
	tls_len = gnutls_record_recv(session, buf, sizeof(buf));
	if(tls_len != 1) {
		if (tls_len<0){
			return SASL_FAIL;
		}
		debug_log_message(DEBUG, AREA_AUTH, "didn't receive first-sent parameter correctly");
		if (gnutls_record_send(session,"N", 1) <= 0) /* send NO to client */
			return SASL_FAIL;
		return SASL_BADPARAM;
	}

	if(buf[0] == 'Y') {
		/* receive initial response (if any) */


		memset(buf,0,sizeof(buf));
		tls_len = gnutls_record_recv(session, buf, sizeof(buf));
		if (tls_len<0){
			return SASL_FAIL;
		}
		/* start libsasl negotiation */
		r = sasl_server_start(conn, chosenmech, buf, tls_len, &data, &sasl_len);
	} else {
		debug_log_message(DEBUG, AREA_AUTH, "start with no msg");
		r = sasl_server_start(conn, chosenmech, NULL, 0, &data, &sasl_len);
	}

	if (r != SASL_OK && r != SASL_CONTINUE) {
		gchar * user_name;

		log_message(INFO, AREA_AUTH, "sasl negotiation error: %d",r);
		ret = sasl_getprop(conn, SASL_USERNAME, (const void **)	&(user_name));
		c_session->user_name = g_strdup(user_name);
		/*		ret = sasl_getprop(conn, SASL_USERNAME, (const void **)	&(c_session->user_name)); */
		if (ret == SASL_OK){
			if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_AUTH)){
				const char *err = inet_ntop( AF_INET, &remote_inaddr, address, sizeof(address));
                if (err == NULL)
                    SECURE_STRNCPY(address, "<inet_ntop error>", sizeof(address));
				g_warning("%s at %s is a badguy",c_session->user_name,address);
			}
		}else{
			if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_AUTH)){
				const char *err = inet_ntop( AF_INET, &remote_inaddr, address, sizeof(address));
                if (err == NULL)
                    SECURE_STRNCPY(address, "<inet_ntop error>", sizeof(address));
				g_warning("unidentified badguy(?) from %s",address);
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
			if (gnutls_record_send(session, data, tls_len)<0)
				return SASL_FAIL;
		} else {
			if (gnutls_record_send(session,"C", 1)<=0) /* send CONTINUE to client */
				return SASL_FAIL;
			if (gnutls_record_send(session, "", 0)<0)
				return SASL_FAIL;
		}


		memset(buf,0,sizeof buf);
		tls_len = gnutls_record_recv(session, buf, sizeof buf);
		if (tls_len <= 0) {
#ifdef DEBUG_ENABLE
			if (!tls_len){
				log_message(VERBOSE_DEBUG, AREA_AUTH, "Client disconnected during sasl negotiation");
			} else {
				log_message(VERBOSE_DEBUG, AREA_AUTH, "TLS error during sasl negotiation");
			}
#endif
			return SASL_FAIL;
		}

		r = sasl_server_step(conn, buf, tls_len, &data, &sasl_len);
		if (r != SASL_OK && r != SASL_CONTINUE) {
#ifdef DEBUG_ENABLE
			log_message(VERBOSE_DEBUG, AREA_AUTH, "error performing SASL negotiation: %s", sasl_errdetail(conn));
#endif
			if (gnutls_record_send(session,"N", 1) <= 0) /* send NO to client */
				return SASL_FAIL;
			return SASL_BADPARAM;
		}
	} /* while continue */


	if (r != SASL_OK) {
		debug_log_message(VERBOSE_DEBUG, AREA_AUTH, "incorrect authentication");
		if (gnutls_record_send(session,"N", 1) <= 0) /* send NO to client */
			return SASL_FAIL;
		return SASL_BADAUTH;
	}


	if (c_session->user_name)
		external_auth=TRUE;

	if (external_auth == FALSE){
		char * tempname=NULL;
		ret = sasl_getprop(conn, SASL_USERNAME, (const void **)	&(tempname));
		if (ret != SASL_OK){
			g_warning("get user failed");
			return SASL_FAIL;
		}else{
			c_session->user_name=g_strdup(tempname);
		}
	}

	/* check on multi user capability */
	if ( check_inaddr_in_array(remote_inaddr,nuauthconf->multi_servers_array)){
		gchar* stripped_user=get_rid_of_domain(c_session->user_name);
		if (check_string_in_array(stripped_user,nuauthconf->multi_users_array)) {
			c_session->multiusers=TRUE;
		} else {
#ifdef DEBUG_ENABLE
			if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_AUTH)){
				const char *err = inet_ntop( AF_INET, &remote_inaddr, address, sizeof(address));
                if (err == NULL)
                    SECURE_STRNCPY(address, "<inet_ntop error>", sizeof(address));
				g_message("%s users on multi server %s", c_session->user_name,address);
			}
#endif
			if (gnutls_record_send(session,"N", 1) <= 0){ /* send NO to client */
                g_free(stripped_user);
				return SASL_FAIL;
            }
		}
		g_free(stripped_user);
	} else {
		c_session->multiusers=FALSE;
	}

	/* in case no call to user_checkdb has been done we need to fill the group */

	if (external_auth == FALSE){
		c_session->groups=g_private_get(group_priv);
		c_session->user_id=GPOINTER_TO_UINT(g_private_get(user_priv));
		if (c_session->user_id == 0) 
		{
			log_message(INFO, AREA_AUTH, "Couldn't get user ID!");
		}
		if (c_session->groups == NULL){
			if(modules_user_check(c_session->user_name,NULL,0,&(c_session->user_id),&(c_session->groups))!=SASL_OK){
				debug_log_message(DEBUG, AREA_AUTH, "error when searching user groups");
				if (gnutls_record_send(session,"N", 1) <= 0) /* send NO to client */
					return SASL_FAIL;
				return SASL_BADAUTH;
			}
		}
	}

	if (gnutls_record_send(session,"O", 1) <= 0) /* send YES to client */
		return SASL_FAIL;

	/* negotiation complete */
	return SASL_OK;
}

int sasl_parse_user_os(user_session_t* c_session, char *buf, int buf_size)
{
    unsigned int len;
    int decode;
    struct nuv2_authfield* osfield;
    gchar*	dec_buf=NULL;
    gchar** os_strings;
    int dec_buf_size;
	
    struct in_addr remote_inaddr;
    char address[INET_ADDRSTRLEN+1];
    remote_inaddr.s_addr=c_session->addr;
    
    osfield=(struct nuv2_authfield*)buf;

    /* check buffer underflow */
    if (buf_size < (int)sizeof(struct nuv2_authfield)) {
        const char *err = inet_ntop( AF_INET, &remote_inaddr, address, sizeof(address));
        if (err == NULL)
            SECURE_STRNCPY(address, "<inet_ntop error>", sizeof(address));
        g_message("%s sent a too small osfield",address);
        return SASL_FAIL;
    }
    
    if (osfield->type != OS_FIELD) {
#ifdef DEBUG_ENABLE
        log_message(DEBUG, AREA_USER, "osfield received %d,%d,%d from %s",osfield->type,osfield->option,ntohs(osfield->length),address);
#endif
        return SASL_FAIL;
    }
    
    dec_buf_size = ntohs(osfield->length);
    if ( dec_buf_size > 1024 || (ntohs(osfield->length) <= 4)) {
        const char *err = inet_ntop( AF_INET, &remote_inaddr, address, sizeof(address));
        if (err == NULL)
            SECURE_STRNCPY(address, "<inet_ntop error>", sizeof(address));
        log_message(WARNING, AREA_USER, "error osfield from %s is uncorrect, announced %d",address,ntohs(osfield->length));
        /* One more gryzor hack*/
        if ( dec_buf_size > 4096 ) 
          log_message(WARNING, AREA_USER, "   Is %s running a 1.0 client?",address);
#ifdef DEBUG_ENABLE
        log_message(DEBUG, AREA_USER, "%s:%d osfield received %d,%d,%d ",__FILE__,__LINE__,osfield->type,osfield->option,ntohs(osfield->length));
#endif
        return SASL_BADAUTH;
    }
    dec_buf = g_new0( gchar ,dec_buf_size);
    decode = sasl_decode64(buf+4,ntohs(osfield->length) -4,dec_buf, dec_buf_size,&len);
    if (decode != SASL_OK)
    {
        g_free(dec_buf);
        return SASL_BADAUTH;
    }

    /* should always be true for the moment */
    if (osfield->option == OS_SRV){
        os_strings=g_strsplit(dec_buf,";",3);
        if (os_strings[0] == NULL || os_strings[1] == NULL || os_strings[2] == NULL)
        {
            g_strfreev(os_strings);
            g_free(dec_buf);
            return SASL_BADAUTH;
        }
        if (strlen(os_strings[0]) < 128) {
            c_session->sysname=string_escape(os_strings[0]);
            if (c_session->sysname==NULL){
                const char *err = inet_ntop( AF_INET, &remote_inaddr, address, sizeof(address));
                if (err == NULL)
                    SECURE_STRNCPY(address, "<inet_ntop error>", sizeof(address));
                log_message(WARNING, AREA_USER, "received sysname with invalid characters from %s",address);
                g_free(dec_buf);
                return SASL_BADAUTH;
            }
        } else {
            c_session->sysname=g_strdup(UNKNOWN_STRING);
        }
        if (strlen(os_strings[1]) < 128) {
            c_session->release=string_escape(os_strings[1]);
            if (c_session->release==NULL){
                const char *err = inet_ntop( AF_INET, &remote_inaddr, address, sizeof(address));
                if (err == NULL)
                    SECURE_STRNCPY(address, "<inet_ntop error>", sizeof(address));
                log_message(WARNING, AREA_USER, "received release with invalid characters from %s",address);
                g_free(dec_buf);
                return SASL_BADAUTH;
            }
        } else {
            c_session->release=g_strdup(UNKNOWN_STRING);
        }
        if (strlen(os_strings[2]) < 128) {
            c_session->version=string_escape(os_strings[2]);
            if (c_session->version==NULL){
                const char *err = inet_ntop( AF_INET, &remote_inaddr, address, sizeof(address));
                if (err == NULL)
                    SECURE_STRNCPY(address, "<inet_ntop error>", sizeof(address));
                log_message(WARNING, AREA_USER, "received version with invalid characters from %s",address);
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
            if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_USER)){
                const char *err = inet_ntop( AF_INET, &remote_inaddr, address, sizeof(address));
                if (err == NULL)
                    SECURE_STRNCPY(address, "<inet_ntop error>", sizeof(address));
                g_message("user %s at %s uses OS %s ,%s, %s",c_session->user_name, address,
                        c_session->sysname , c_session->release , c_session->version);

            }
#endif
        }
        g_strfreev(os_strings);
    }else{
        const char *err = inet_ntop( AF_INET, &remote_inaddr, address, sizeof(address));
        if (err == NULL)
           SECURE_STRNCPY(address, "<inet_ntop error>", sizeof(address));
        log_message(DEBUG, AREA_AUTH, "from %s : osfield->option is not OS_SRV ?!",address);

        g_free(dec_buf);
        return SASL_FAIL;

    }
    g_free(dec_buf);
    return SASL_OK;
}

/**
 * realize user negotiation from after TLS to the end. 
 */

int sasl_user_check(user_session_t* c_session)
{
	char *service="nufw";
	char *myhostname="nuserver";
	char *myrealm="nufw";
	sasl_conn_t * conn=NULL;
	sasl_security_properties_t secprops;
	gboolean external_auth=FALSE;
	char buf[1024];
	int ret, buf_size;
	sasl_callback_t internal_callbacks[] = {
		{ SASL_CB_GETOPT, &internal_get_opt, NULL },
		{ SASL_CB_SERVER_USERDB_CHECKPASS, &userdb_checkpass,NULL}, 
		{ SASL_CB_LIST_END, NULL, NULL }
	};
	sasl_callback_t external_callbacks[] = {
		{ SASL_CB_GETOPT, &external_get_opt, NULL },
		{ SASL_CB_SERVER_USERDB_CHECKPASS, &userdb_checkpass,NULL}, 
		{ SASL_CB_LIST_END, NULL, NULL }
	};
    sasl_callback_t *callbacks;

	if (c_session->user_name) {
		external_auth=TRUE;
        callbacks = external_callbacks;
	} else { 
        callbacks = internal_callbacks;
	}
    
    ret = sasl_server_new(service, myhostname, myrealm, NULL, NULL, callbacks, 0, &conn);
	if (ret != SASL_OK) {
		g_warning("allocating connection state - failure at sasl_server_new()");
	}

	secprops.min_ssf = 0;
	secprops.max_ssf = 0;
	secprops.property_names = NULL;
	secprops.property_values = NULL;
	secprops.security_flags = SASL_SEC_NOANONYMOUS; /* as appropriate */
	secprops.maxbufsize = 65536;
	sasl_setprop(conn, SASL_SEC_PROPS, &secprops);

	if (external_auth){
		sasl_ssf_t extssf = 0;

#ifdef DEBUG_ENABLE
		log_message(VERBOSE_DEBUG, AREA_AUTH, "setting params for external");
		log_message(VERBOSE_DEBUG, AREA_AUTH, "TLS gives user %s, trying EXTERNAL",c_session->user_name);
#endif
		ret = sasl_setprop(conn, SASL_AUTH_EXTERNAL,c_session->user_name);
		if (ret != SASL_OK){
			log_message(INFO, AREA_AUTH, "Error setting external auth");
		}
		ret = sasl_setprop(conn,SASL_SSF_EXTERNAL,&extssf);
		if (ret != SASL_OK){
			log_message(INFO, AREA_AUTH, "Error setting external SSF");
		}
		ret = mysasl_negotiate(c_session, conn);
	} else {
		ret = mysasl_negotiate(c_session, conn);
	}
	sasl_dispose(&conn);
	if ( ret != SASL_OK )
		return ret;
#ifdef DEBUG_ENABLE
    if (c_session->multiusers){
        log_message(DEBUG, AREA_USER, "multi user client");
    }
#endif

    /* recv OS datas from client */
    buf_size = gnutls_record_recv(*(c_session->tls), buf, sizeof buf) ;
    if (buf_size <= 0){
        /* allo houston */
        debug_log_message(DEBUG, AREA_USER, "error when receiving user OS");
        return SASL_FAIL;
    }

    ret = sasl_parse_user_os(c_session, buf, buf_size);
    if (ret != SASL_OK)
        return ret;

    if (nuauthconf->session_duration){
        c_session->expire=time(NULL)+nuauthconf->session_duration;
    } else {
        c_session->expire=-1;
    }

    /* sasl connection is not used anymore */
    return SASL_OK;
}

