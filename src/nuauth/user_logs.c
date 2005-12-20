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

	if ((nuauthconf->log_users_sync) && (state == STATE_OPEN) ){
            if ( nuauthconf->log_users &  8 ){
                   if (nuauthconf->log_users_without_realm){
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
                ((nuauthconf->log_users & 2) && (state == STATE_DROP)) 
                || 
                ((nuauthconf->log_users & 4) && (state == STATE_OPEN)) 
                || 
                (nuauthconf->log_users & 8) 
               ) {
		/* feed thread pool */
                conn_state_copy=g_memdup(&conn_state,sizeof(conn_state));
                if ( conn_state.conn.username ){
                    if (nuauthconf->log_users_without_realm){
                        conn_state_copy->conn.username = get_rid_of_domain(conn_state.conn.username);
                    } else {
                        conn_state_copy->conn.username = g_strdup(conn_state.conn.username);
                    }
                }
		g_thread_pool_push(nuauthdatas->user_loggers,
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
        block_on_conf_reload();
	user_logs (
			     ((struct Conn_State *)userdata)->conn, 
			     ((struct Conn_State *)userdata)->state
			    );
	/* free userdata */
	g_free(((struct Conn_State*)userdata)->conn.username);
	g_free(userdata);
}
