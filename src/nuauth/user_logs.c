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
	connection_t conn;
	tcp_state_t state;
};

/**
 * log user packet or by a direct call to log module or by sending log 
 * message to logger thread pool.
 * 
 * \param element A connection
 * \param state TCP state of the connection
 */

void log_user_packet (connection_t element, tcp_state_t state)
{
	struct Conn_State conn_state= { element, state};
	struct Conn_State * conn_state_copy;

	if ((nuauthconf->log_users_sync) && (state == TCP_STATE_OPEN) ){
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
                ((nuauthconf->log_users & 2) && (state == TCP_STATE_DROP)) 
                || 
                ((nuauthconf->log_users & 4) && (state == TCP_STATE_OPEN)) 
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

void real_log_user_packet (gpointer userdata, gpointer data)
{
        block_on_conf_reload();
	user_logs (
			     ((struct Conn_State *)userdata)->conn, 
			     ((struct Conn_State *)userdata)->state
			    );
	/* free userdata */
	g_free(((struct Conn_State*)userdata)->conn.username);
	g_free(userdata);
}

gboolean log_user_session(user_session* usession, session_state_t state)
{
	struct session_event* sessevent=g_new0(struct session_event,1);
	/* feed thread pool */
	if (nuauthconf->log_users & 1){
		sessevent->session=g_memdup(usession,sizeof(usession));
		sessevent->state=state;
		if ( sessevent->session->userid ){
			if (nuauthconf->log_users_without_realm){
				sessevent->session->userid = get_rid_of_domain(usession->userid);
			} else {
				sessevent->session->userid  = g_strdup(usession->userid);
			}
		}
		g_thread_pool_push(nuauthdatas->user_session_loggers,
				sessevent,
				NULL);
	}
	return TRUE;
}

void log_user_session_thread (gpointer element,gpointer data)
{
        block_on_conf_reload();
	user_session_logs(((struct session_event*)element)->session,((struct session_event*)element)->state);
	g_free(((struct session_event*)element)->session->userid);
	g_free(((struct session_event*)element)->session);
	g_free(element);
}
