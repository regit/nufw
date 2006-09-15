/*
 ** Copyright(C) 2003-2006 INL
 **         written by
 **             Eric Leblond <eric@regit.org>
 **		        Vincent Deffontaines <vincent@gryzor.com>
 **         INL http://www.inl.fr/
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
	void* conn;
	tcp_state_t state;
};

/**
 * log user packet or by a direct call to log module or by sending log
 * message to logger thread pool.
 *
 * \param element A connection
 * \param state TCP state of the connection
 */

void log_user_packet (connection_t* element, tcp_state_t state)
{
	if ((nuauthconf->log_users_sync) && (state == TCP_STATE_OPEN) ){
            if ( nuauthconf->log_users &  8 ){
                modules_user_logs ( element, state);
            }
	} else {
        if (
                ((nuauthconf->log_users & 2) && (state == TCP_STATE_DROP))
                ||
                ((nuauthconf->log_users & 4) && (state == TCP_STATE_OPEN))
                ||
                (nuauthconf->log_users & 8)
           ) {
            struct Conn_State * conn_state_copy;
            conn_state_copy=g_new0(struct Conn_State,1);
            conn_state_copy->conn=(void*)duplicate_connection(element);
            if (! conn_state_copy->conn){
                g_free(conn_state_copy);
                return;
            }
            conn_state_copy->state=state;

            g_thread_pool_push(nuauthdatas->user_loggers,
                    conn_state_copy,
                    NULL);
        }
	}
	/* end */
}

/**
 * \brief log user packet from a single ::accounted_connection
 *
 * This is always asynchronous and we directly push the ::accounted_connection to the
 * user_loggers pool.
 */
void log_user_packet_from_accounted_connection(struct accounted_connection* datas,tcp_state_t state)
{
	struct Conn_State * conn_state_copy;
	conn_state_copy=g_new0(struct Conn_State,1);
	conn_state_copy->conn=g_memdup(datas,sizeof(*datas));
	if (! conn_state_copy->conn){
		g_free(conn_state_copy);
		return;
	}
	conn_state_copy->state=state;

	g_thread_pool_push(nuauthdatas->user_loggers,
			conn_state_copy,
			NULL);

}



/**
 * interface to logging module function for thread pool worker.
 *
 * \param userdata A ::Conn_State
 * \param data Unused
 * \return None
 */

void real_log_user_packet (gpointer userdata, gpointer data)
{
  block_on_conf_reload();
  modules_user_logs (
          ((struct Conn_State *)userdata)->conn,
          ((struct Conn_State *)userdata)->state
          );
  /* free userdata */
  if ((((struct Conn_State *)userdata)->state == TCP_STATE_OPEN) ||
		  (((struct Conn_State *)userdata)->state == TCP_STATE_DROP )){
	  ((connection_t*)((struct Conn_State *)userdata)->conn)->state=AUTH_STATE_DONE;
	  free_connection((connection_t*)((struct Conn_State *)userdata)->conn);
  }
  g_free(userdata);
}

/**
 * High level function used to log an user session (connect / disconnect).
 *
 * It duplicate the user session and push it in
 * nuauthdatas->user_session_loggers thread pool: it will call
 * log_user_session_thread().
 */
void log_user_session(user_session_t* usession, session_state_t state)
{
    struct session_event* sessevent;

    if (state == SESSION_OPEN)
        log_message(MESSAGE, AREA_USER,
                "[+] User \"%s\" connected.", usession->user_name);
    else
        log_message(MESSAGE, AREA_USER,
                "[+] User \"%s\" disconnected.", usession->user_name);

    if ((nuauthconf->log_users & 1) == 0){
        if (state == SESSION_CLOSE){
                clean_session(usession);
        }
        return;
    }

    /* copy interresting informations of the session */
    sessevent=g_new0(struct session_event,1);
    if (sessevent == NULL) {
        /* no more memory :-( */
        return;
    }
    if (state == SESSION_OPEN) {
        sessevent->session=g_memdup(usession, sizeof(*usession));
        sessevent->session->user_name  = g_strdup(usession->user_name);
        sessevent->session->tls = NULL;
        sessevent->session->socket = usession->socket;
        sessevent->session->groups = NULL;
        sessevent->session->sysname = g_strdup(usession->sysname);
        sessevent->session->version = g_strdup(usession->version);
        sessevent->session->release = g_strdup(usession->release);
    } else {
        /* closing we do not need to duplicate */
        sessevent->session = usession;
    }
    sessevent->state=state;
     /* feed thread pool */
    g_thread_pool_push(nuauthdatas->user_session_loggers,
            sessevent,
            NULL);
}

/**
 * Thread of nuauthdatas->user_session_loggers thread pool:
 * call modules_user_session_logs() and the free memory.
 *
 * Don't use this function directly! Use log_user_session().
 */
void log_user_session_thread (gpointer event_ptr, gpointer unused_optional)
{
    struct session_event *event = (struct session_event*)event_ptr;
    user_session_t* session = event->session;
    block_on_conf_reload();
    modules_user_session_logs(session, event->state);
    g_free(session->user_name);
    g_free(session->sysname);
    g_free(session->version);
    g_free(session->release);
    g_free(session);
    g_free(event);
}

