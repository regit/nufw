/*
 ** Copyright(C) 2003-2008 INL
 ** Written by Eric Leblond <eric@regit.org>
 **            Vincent Deffontaines <vincent@gryzor.com>
 ** INL http://www.inl.fr/
 **
 ** $Id$
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

struct conn_state {
	void *conn;
	tcp_state_t state;
};

/**
 * \brief Log user packet via modules
 *
 * Log user packet or by a direct call to log module or by sending log
 * message to logger thread pool.
 *
 * If nuauth_params::log_user_sync is set to 1, we log synchronously
 * to be sure that the packet is logged by all the modules before
 * the decision leaves nuauth and reach nufw. This is only done for
 * packet which initiate a connection (in Netfilter meaning).
 *
 * If nuauth_params::log_user_sync is set to 0, log_user_packet() directly
 * sends packet to the pool of threads waiting for logging.
 *
 * \param element A connection
 * \param state A ::tcp_state_t, TCP state of the connection
 */

nu_error_t log_user_packet(connection_t * element, tcp_state_t state)
{
	if (element->flags & ACL_FLAGS_NOLOG) {
		RETURN_NO_LOG NU_EXIT_OK;
	}

	if (nuauthdatas->loggers_pool_full == TRUE) {
		log_message(INFO, DEBUG_AREA_USER, "No packet logging to avoid logger DOS");
		return NU_EXIT_ERROR;
	}

	if (nuauthconf->drop_if_no_logging ||
			((nuauthconf->log_users_sync) && (state == TCP_STATE_OPEN)
			 && (!(element->flags & ACL_FLAGS_ASYNC)))
	   ) {
		if (nuauthconf->log_users & 8) {
			return modules_user_logs(element, state);
		}
	} else {
		if (((nuauthconf->log_users & 2)
		     && (state == TCP_STATE_DROP))
		    || ((nuauthconf->log_users & 4)
			&& (state == TCP_STATE_OPEN))
		    || (nuauthconf->log_users & 8)
		    ) {
			struct conn_state *conn_state_copy;
			conn_state_copy = g_new0(struct conn_state, 1);
			conn_state_copy->conn =
			    (void *) duplicate_connection(element);
			if (!conn_state_copy->conn) {
				g_free(conn_state_copy);
				log_message(MESSAGE, DEBUG_AREA_MAIN,
					    "Unable to duplicate connection");
				return NU_EXIT_ERROR;
			}
			conn_state_copy->state = state;

			thread_pool_push(nuauthdatas->user_loggers,
					   conn_state_copy, NULL);
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
void log_user_packet_from_accounted_connection(struct accounted_connection
					       *datas, tcp_state_t state)
{
	struct conn_state *conn_state_copy;
	conn_state_copy = g_new0(struct conn_state, 1);
	conn_state_copy->conn = g_memdup(datas, sizeof(*datas));
	if (!conn_state_copy->conn) {
		g_free(conn_state_copy);
		log_message(MESSAGE, DEBUG_AREA_MAIN,
			    "Unable to duplicate connection");
		return;
	}
	conn_state_copy->state = state;

	thread_pool_push(nuauthdatas->user_loggers,
			   conn_state_copy, NULL);

}



/**
 * \brief Interface to logging module function for thread pool worker.
 *
 * This function is used in nuauthdatas->user_loggers thread pool.
 *
 * \param userdata A ::conn_state
 * \param data Unused
 * \return None
 */
void real_log_user_packet(gpointer userdata, gpointer data)
{
	modules_user_logs(((struct conn_state *) userdata)->conn,
			  ((struct conn_state *) userdata)->state);
	/* free userdata */
	if ((((struct conn_state *) userdata)->state == TCP_STATE_OPEN) ||
	    (((struct conn_state *) userdata)->state == TCP_STATE_DROP)) {
		((connection_t *) ((struct conn_state *) userdata)->conn)->
		    state = AUTH_STATE_DONE;
		free_connection((connection_t *) ((struct conn_state *)
						  userdata)->conn);
	}
	g_free(userdata);
}

static void print_group(gpointer group, gpointer userdata)
{
	char ** str_groups = (char **) userdata;
	char * userdata_p = *(char **) userdata;
	if (userdata_p) {
		*str_groups = g_strdup_printf("%s,%d",
				userdata_p,
				GPOINTER_TO_INT(group));
	} else {
		*str_groups = g_strdup_printf("%d",
				GPOINTER_TO_INT(group));
	}
	g_free(userdata_p);
}

/**
 * \brief High level function used to log an user session
 *
 * It logs connection and disconnection of user.
 *
 * It duplicates the user session and push it in
 * nuauthdatas->user_session_loggers thread pool.
 * This calls log_user_session_thread() on the session.
 */
void log_user_session(user_session_t * usession, session_state_t state)
{
	struct session_event *sessevent;
	char * str_groups = NULL;

	if (nuauthdatas->session_loggers_pool_full == TRUE) {
		log_message(INFO, DEBUG_AREA_USER, "No session logging to avoid logger DOS");
		return;
	}

	if (state == SESSION_OPEN) {
		if (usession->groups) {
			g_slist_foreach(usession->groups, print_group,
					&str_groups);
		}
		log_message(MESSAGE, DEBUG_AREA_USER,
			    "[+] User \"%s\" connected, groups: %s",
			    usession->user_name, str_groups);
		g_free(str_groups);
	} else
		log_message(MESSAGE, DEBUG_AREA_USER,
			    "[+] User \"%s\" disconnected.",
			    usession->user_name);

	if ((nuauthconf->log_users & 1) == 0) {
		RETURN_NO_LOG;
	}

	/* copy interesting informations of the session */
	sessevent = g_new0(struct session_event, 1);
	if (sessevent == NULL) {
		/* no more memory :-( */
		log_message(WARNING, DEBUG_AREA_MAIN, "No more memory");
		return;
	}
	sessevent->session = g_memdup(usession, sizeof(*usession));
	sessevent->session->user_name =
		g_strdup(usession->user_name);
	sessevent->session->nussl = NULL;
	sessevent->session->socket = usession->socket;
	sessevent->session->groups = NULL;
	sessevent->session->sysname = g_strdup(usession->sysname);
	sessevent->session->version = g_strdup(usession->version);
	sessevent->session->release = g_strdup(usession->release);
	sessevent->state = state;
	/* feed thread pool */
	thread_pool_push(nuauthdatas->user_session_loggers,
			   sessevent, NULL);
}

/**
 * \brief Function of session loggers thread pool
 *
 * Thread of nuauthdatas->user_session_loggers thread pool:
 *  - block during nuauth reload
 *  - call modules_user_session_logs()
 *  - free memory
 *
 * \attention Don't use this function directly! Use log_user_session().
 */
void log_user_session_thread(gpointer event_ptr, gpointer unused_optional)
{
	struct session_event *event = (struct session_event *) event_ptr;
	user_session_t *session = event->session;

	modules_user_session_logs(session, event->state);
	g_free(session->user_name);
	g_free(session->sysname);
	g_free(session->version);
	g_free(session->release);
	g_free(session);
	g_free(event);
}

/** If there is too much unhandled messages modify
 * switch to enable action in other nuauth part.*/
void act_on_loggers_processing()
{
	if (g_thread_pool_unprocessed(nuauthdatas->user_loggers) >
			nuauthconf->max_unassigned_messages) {
		nuauthdatas->loggers_pool_full = TRUE;
	} else {
		nuauthdatas->loggers_pool_full = FALSE;
	}
	if (g_thread_pool_unprocessed(nuauthdatas->user_session_loggers) > 
			nuauthconf->max_unassigned_messages) {
		nuauthdatas->session_loggers_pool_full = TRUE;
	} else {
		nuauthdatas->session_loggers_pool_full = FALSE;
	}
}
