/*
 ** Copyright(C) 2003 Eric Leblond <eric@regit.org>
 **		      Vincent Deffontaines <vincent@gryzor.com>
 **                   INL http://www.inl.fr/
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

#include <auth_srv.h>
#include <time.h>

//#define CAPTIVE_PORTAL 1


/**
 * print log message about new user on IP.
 * 
 * Argument 1 : user id
 * Argument 2 : ip
 * Return : None
 */

void log_new_user(char *username,char* remoteip)
{
	if ( nuauth_log_users & 1 ){
#ifdef CAPTIVE_PORTAL
		char cmdbuffer[128];
#endif
		g_message("User %s on %s",username,remoteip);
#ifdef CAPTIVE_PORTAL
		snprintf(cmdbuffer,128,"/etc/nufw/user-up.sh %s %s",username,remoteip);
		system(cmdbuffer);
#endif
	}
}

/**
 * print log message about user disconnect.
 * 
 * Argument 1 : user id
 * Argument 2 : ip
 * Return : None
 */

void log_user_disconnect(char *username,char* remoteip)
{
	if ( nuauth_log_users & 1 ){
#ifdef CAPTIVE_PORTAL
		char cmdbuffer[128];
#endif
		g_message("User %s disconnect on %s",username,remoteip);
#ifdef CAPTIVE_PORTAL
		snprintf(cmdbuffer,128,"/etc/nufw/user-down.sh %s %s",username,remoteip);
		system(cmdbuffer);
#endif
	}
	/* TODO : branch user-down script here */
}



struct Conn_State { 
	connection conn;
	int state;};

/**
 * log user packet or by a direct call to log module or by sending log 
 * message to logger thread pool.
 * 
 * Argument 1 : connection
 * Argument 2 : state of the connection
 */

void log_user_packet (connection element,int state){
	struct Conn_State conn_state= { element, state};
	struct Conn_State * conn_state_copy;

	if ((nuauth_log_users_sync) && (state == STATE_OPEN) ){
            if ( nuauth_log_users &  8 ){
                   if (nuauth_log_users_without_realm){
                       element.username = get_rid_of_domain(element.username);
                    }
                   user_logs (
				     element, 
				     state
				    );
                   g_free(element.username);
            }
	} else {
            if (
                ((nuauth_log_users & 2) && (state == STATE_DROP)) 
                || 
                ((nuauth_log_users & 4) && (state == STATE_OPEN)) 
                || 
                (nuauth_log_users & 8) 
               ) {
		/* feed thread pool */
                conn_state_copy=g_memdup(&conn_state,sizeof(conn_state));
                if ( conn_state.conn.username ){
                    if (nuauth_log_users_without_realm){
                        conn_state_copy->conn.username = get_rid_of_domain(conn_state.conn.username);
                    } else {
                        conn_state_copy->conn.username = g_strdup(conn_state.conn.username);
                    }
                }
		g_thread_pool_push(user_loggers,
				conn_state_copy,
				NULL);
            }
	}
	/* end */
}


/**
 * interface to logging module function for thread pool worker.
 * 
 * Argument 1 : struct Conn_State
 * Argument 2 : unused 
 * Return : None
 */

void real_log_user_packet (gpointer userdata, gpointer data){
	user_logs (
			     ((struct Conn_State *)userdata)->conn, 
			     ((struct Conn_State *)userdata)->state
			    );
	/* free userdata */
	g_free(((struct Conn_State*)userdata)->conn.username);
	g_free(userdata);
}
