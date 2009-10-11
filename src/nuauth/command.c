/*
 ** Copyright(C) 2007,2008 INL
 ** Written by Victor Stinner <victor.stinner@inl.fr>
 **	       Eric Leblond <eric@inl.fr>
 **
 ** $Id$
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation, version 3 of the License.
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


#include "command.h"

#ifdef BUILD_NUAUTH_COMMAND
#include "auth_srv.h"
#include "command_enc.h"
#include "security.h"

#include <errno.h>
#include <sys/un.h>		/* unix socket */
#include <sys/stat.h>		/* fchmod() */
#include <sys/types.h>		/* mode_t */

#include <ev.h>

#include <nubase.h>

#include "nuauthconf.h"

#define SOCKET_PATH LOCAL_STATE_DIR "/run/nuauth/"
#define SOCKET_FILENAME "nuauth-command.socket"
#define SOCKET_TARGET SOCKET_PATH SOCKET_FILENAME

GHashTable *client_conn_hash;

const char* COMMAND_HELP =
"version: display nuauth version\n"
"confdump: dump configuration\n"
"users: list connected users\n"
"firewalls: list connected nufw firewalls\n"
"packets count: display number of decision waiting packets\n"
"user count: display number of connected clients\n"
"refresh cache: refresh all caches\n"
"refresh crl: refresh the TLS crl file\n"
"disconnect ID: disconnect an user with his session identifier\n"
"disconnect all: disconnect all users\n"
"uptime: display nuauth starting time and uptime\n"
"reload: reload nuauth configuration\n"
"reload periods: reload the time periods\n"
"display debug_level\n"
"display debug_areas\n"
"debug_level LEVEL\n"
"debug_areas AREAS\n"
"help: display this help\n"
"quit: disconnect";

const char* PYTHON_PROTO_VERSION = "NuFW 0.1";

static void command_activity_cb(struct ev_loop *loop, ev_io *w, int revents);
static void command_client_activity_cb(struct ev_loop *loop, ev_io *w, int revents);

typedef struct {
	time_t start_timestamp;
	int socket;
	struct sockaddr_un client_addr;
	struct ev_loop *loop;
	ev_io command_watcher;
} command_t;

typedef struct {
	int fd;
	ev_io watcher;
	command_t *master_command;
} command_client_t;


int command_new(command_t * this)
{
	struct sockaddr_un addr;
	int len;
	int ret;
	int on = 1;

	this->start_timestamp = time(NULL);
	this->socket = -1;
	this->loop = NULL;

	/* Create socket dir */
	ret = mkdir(SOCKET_PATH, S_IRWXU);
	if ( ret != 0 && errno != EEXIST ) {
		log_area_printf(DEBUG_AREA_AUTH, DEBUG_LEVEL_FATAL,
				"Cannot create socket directory %s: %s", SOCKET_PATH, strerror(errno));
	}

	/* Remove socket file */
	(void) unlink(SOCKET_TARGET);

	/* set address */
	addr.sun_family = AF_UNIX;
	SECURE_STRNCPY(addr.sun_path, SOCKET_TARGET, sizeof(addr.sun_path));
	addr.sun_path[sizeof(addr.sun_path) - 1] = 0;
	len = strlen(addr.sun_path) + sizeof(addr.sun_family);

	/* create socket */
	this->socket = socket(AF_UNIX, SOCK_STREAM, 0);
	if (this->socket == -1) {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL, "Command server: unable to create UNIX socket %s: %s",
			    getpid(), addr.sun_path, g_strerror(errno));
		return 0;
	}

	/* Set file mode */
	(void)fchmod(this->socket, 0600);

	/* set reuse option */
	ret = setsockopt(this->socket, SOL_SOCKET, SO_REUSEADDR,
		       (char *) &on, sizeof(on));
	if ( ret != 0 ) {
		log_area_printf(DEBUG_AREA_AUTH, DEBUG_LEVEL_FATAL,
				"Cannot set sockets options: %s.",  strerror(errno));
	}

	/* bind socket */
	ret = bind(this->socket, (struct sockaddr *) &addr, len);
	if (ret == -1) {
		g_warning("[%i] Command server: UNIX socket bind(%s) error: %s",
			    getpid(), SOCKET_TARGET, g_strerror(errno));
		return 0;
	}

	/* listen */
	if (listen(this->socket, 1) == -1) {
		g_warning("[%i] Command server: UNIX socket listen() error: %s",
			    getpid(), g_strerror(errno));
		return 0;
	}

	this->loop = ev_loop_new(0);
	if ( this->loop == NULL ) {
		log_area_printf(DEBUG_AREA_AUTH, DEBUG_LEVEL_FATAL,
				"Command server: could not create ev loop");
	}

	ev_io_init(&this->command_watcher, command_activity_cb, this->socket, EV_READ);
	this->command_watcher.data = this;
	ev_io_start(this->loop, &this->command_watcher);

	return 1;
}

void command_client_close(command_client_t * this)
{
	log_message(WARNING, DEBUG_AREA_MAIN,
		    "Command server: close client connection");
	close(this->fd);
	this->fd = -1;

	ev_io_stop(this->master_command->loop, &this->watcher);
	ev_unloop(this->master_command->loop, EVUNLOOP_ONE);
}

int command_client_accept(command_t * this)
{
	char buffer[9];
	int ret;
	command_client_t *client;
	int clientfd;

	/* accept client socket */
	socklen_t len = sizeof(this->client_addr);
	clientfd = accept(this->socket, (struct sockaddr *) &this->client_addr, &len);
	if (clientfd < 0) {
		log_message(CRITICAL, DEBUG_AREA_MAIN,
			    "Command server: accept() error: %s",
			    g_strerror(errno));
		return 0;
	}
	log_message(WARNING, DEBUG_AREA_MAIN,
		    "Command server: client connection");

	/* read client version */
	buffer[sizeof(buffer)-1] = 0;
	ret = recv(clientfd, buffer, sizeof(buffer)-1, 0);
	if (ret < 0) {
		log_message(CRITICAL, DEBUG_AREA_MAIN,
			    "Command server: client doesn't send version");
		close(clientfd);
		return 0;
	}
	buffer[ret] = 0;

	/* send server version */
	send(clientfd, PYTHON_PROTO_VERSION, 8, 0);

	/* check client version */
	if (strcmp(buffer, PYTHON_PROTO_VERSION) != 0) {
		log_message(CRITICAL, DEBUG_AREA_MAIN,
			    "Command server: invalid client version: \"%s\"",
			    buffer);
		close(clientfd);
		return 0;
	}

	client = g_new(command_client_t, 1);
	client->fd = clientfd;
	client->master_command = this;

	ev_io_init(&client->watcher, command_client_activity_cb, client->fd, EV_READ);
	client->watcher.data = client;
	ev_io_start(this->loop, &client->watcher);

	/* client connected */
	log_message(WARNING, DEBUG_AREA_MAIN,
		    "Command server: client connected");

	return 1;
}

void command_uptime(encoder_t* encoder, command_client_t *this)
{
	time_t diff = time(NULL) - this->master_command->start_timestamp;
	return encoder_add_uptime(encoder, this->master_command->start_timestamp, diff);
}

void command_users_callback(int sock, user_session_t *session, GSList **users)
{
	encoder_t *encoder = encode_user(session);
	*users = g_slist_prepend(*users, encoder);
}

void command_users(command_client_t *this, encoder_t *encoder)
{
	/* read user list */
	GSList *users = NULL;
	foreach_session((GHFunc)command_users_callback, &users);

	/* encode user list */
	encoder_add_tuple_from_slist(encoder, users);
	encoder_slist_destroy(users);
}

void command_server_callback(int sock, nufw_session_t *session, GSList **servers)
{
	encoder_t *encoder = encode_nufw(session);
	*servers = g_slist_prepend(*servers, encoder);
}

void command_servers(command_client_t *this, encoder_t *encoder)
{
	/* read user list */
	GSList *servers = NULL;
	foreach_nufw_server((GHFunc)command_server_callback, &servers);

	/* encode user list */
	encoder_add_tuple_from_slist(encoder, servers);
	encoder_slist_destroy(servers);
}

/**
 * Internal function do disconnect a client
 */
int command_do_disconnect(int sock)
{
	int ok = 1;
	GSList *thread_p;

	/* iter on each server thread */
	for (thread_p=nuauthdatas->tls_auth_servers; thread_p; thread_p = thread_p->next) {
		struct tls_user_context_t *this =
			((struct nuauth_thread_t *)thread_p->data)->data;
		/* send query to disconnect all users */
		disconnect_user_msg_t *msg = g_new(disconnect_user_msg_t, 1);
		msg->socket = sock;
		msg->mutex = g_mutex_new();

		g_async_queue_push(this->cmd_queue, msg);
		ev_async_send(this->loop,
			      &this->client_destructor_signal);
		/* wait until clients are disconnected */
		g_mutex_lock(msg->mutex);
		g_mutex_lock(msg->mutex);
		g_mutex_unlock(msg->mutex);
		g_mutex_free(msg->mutex);

		/* write answer */
		if (msg->result == NU_EXIT_OK) {
			ok = 1;
			g_free(msg);
			break;
		} else {
			ok = 0;
		}
		/* return in case we've just send a global disconnect message */
		if (sock == -1) {
			break;
		}
	}
	return ok;
}

/**
 * Disconnect all client
 **/
int command_disconnect_all(command_client_t *this, encoder_t *encoder)
{
	if (command_do_disconnect(-1)) {
		encoder_add_string(encoder, "users disconnected");
		return 1;
	} else {
		encoder_add_string(encoder, "no user connected");
		return 0;
	}
}

/**
 * Disconnect a client
 */
int command_disconnect(command_client_t *this, encoder_t *encoder, char *command)
{
	int sock;

	/* convert socket number to integer and create mutex */
	if (!str_to_int(command, &sock)) {
		return 0;
	}

	if (command_do_disconnect(sock)) {
		encoder_add_string(encoder, "users disconnected");
		return 1;
	} else {
		encoder_add_string(encoder, "no user connected");
		return 0;
	}
}

char* FORTUNES[] = {
	"<haypo> gryzor: c'est pratique subversion hein ? " \
	"surtout les lendemains de fete",
	"<Regit> J'ai un cerveau de mulot en bas age",
	"<misc> c'est debian, c'est credible",
	"<lodesi> naotemp_home: windows me fait pas peur :P\n" \
	"<naotemp_home> lodesi: bon ben on t envoie au kosovo",
	"<acatout> C'est pas un veterinaire, qu'il faut, pour un troll ?",
	"\"impossible\" (c) gryzor",
};

const int NB_FORTUNE = sizeof(FORTUNES) / sizeof(FORTUNES[0]);

const char* fortune()
{
	double index = (double)random() * NB_FORTUNE / RAND_MAX;
	return FORTUNES[(int)index];
}

static void conf_server_side_print(void *encoder, char *buffer)
{
	encoder_add_string(encoder, buffer);
}

void command_execute(command_client_t * this, char *command)
{
	encoder_t *encoder, *answer;
	int ret;
	int ok;

	/* process command */
	ok = 1;
	encoder = encoder_new();
	if (strcmp(command, "quit") == 0) {
		/* nothing */
	} else if (strcmp(command, "help") == 0) {
		encoder_add_string(encoder, COMMAND_HELP);
	} else if (strcmp(command, "uptime") == 0) {
		command_uptime(encoder, this);
	} else if (strcmp(command, "nupik!") == 0) {
		encoder_add_string(encoder, fortune());
	} else if (strcmp(command, "users") == 0) {
		command_users(this, encoder);
	} else if (strcmp(command, "firewalls") == 0) {
		command_servers(this, encoder);
	} else if (strcmp(command, "version") == 0) {
		encoder_add_string(encoder, NUAUTH_FULL_VERSION);
	} else if (strcmp(command, "confdump") == 0) {
		nuauth_config_table_print(encoder, conf_server_side_print);
	} else if (strcmp(command, "disconnect all") == 0) {
		ok = command_disconnect_all(this, encoder);
		force_refresh_crl_file();
	} else if (strncmp(command, "disconnect ", 10) == 0) {
		ok = command_disconnect(this, encoder, command+10);
		force_refresh_crl_file();
	} else if (strcmp(command, "reload") == 0) {
		gboolean restart = nuauth_reload(0);
		if (restart) {
			encoder_add_string(encoder, "Configuration change requires Nuauth restart");
		} else {
			encoder_add_string(encoder, "Configuration reloaded");
		}
	} else if (strcmp(command, "reload periods") == 0) {
		reload_periods(&nuauthconf->periods);
		encoder_add_string(encoder, "Periods reloaded");
	} else if (strcmp(command, "refresh cache") == 0) {
		if (nuauthconf->acl_cache) {
			cache_reset(nuauthdatas->acl_cache);
			encoder_add_string(encoder, "Cache refreshed");
		} else {
			encoder_add_string(encoder, "Cache disabled");
		}
	} else if (strcmp(command, "refresh crl") == 0) {
		force_refresh_crl_file();
		encoder_add_string(encoder, "Refresh of CRL file done");
	} else if (strncmp(command, "debug_level ", 12) == 0) {
		int debug_level = atoi(command+12);
		if ((0 < debug_level) && (debug_level <= 9)) {
			nuauthconf->debug_level = debug_level;
			log_message(INFO, DEBUG_AREA_MAIN,
			    "Debug level set to %d",
			    debug_level);
			encoder_add_string(encoder,"Debug level changed");
		} else {
			encoder_add_string(encoder,"Improper debug level (not in 1..9)");
			ok = 0;
		}
	}  else if (strncmp(command, "debug_areas ", 12) == 0) {
		int debug_areas = atoi(command+12);
		if (debug_areas > 0) {
			nuauthconf->debug_areas = debug_areas;
			log_message(INFO, DEBUG_AREA_MAIN,
			    "Debug areas set to %d",
			    debug_areas);
			encoder_add_string(encoder,"Debug areas changed");
		} else {
			encoder_add_string(encoder,"Improper debug areas");
			ok = 0;
		}
	} else if (strcmp(command, "display debug_level") == 0) {
		encoder_add_int32(encoder, nuauthconf->debug_level);
	} else if (strcmp(command, "display debug_areas") == 0) {
		encoder_add_int32(encoder, nuauthconf->debug_areas);
	} else if (strcmp(command, "packets count") == 0) {
		encoder_add_int32(encoder, g_hash_table_size(conn_list));
	} else if (strcmp(command, "user count") == 0) {
		encoder_add_int32(encoder, g_hash_table_size(client_conn_hash));
	} else {
		/* unknown command => disconnect */
	}

	/* on error (invalid input): disconnect client */
	if (encoder->size == 0) {
		command_client_close(this);
		encoder_destroy(encoder);
		return;
	}

	/* create answer */
	answer = encode_answer(ok, encoder);
	encoder_destroy(encoder);

	/* send answer */
	ret = send(this->fd, answer->data, answer->size, 0);
	if (ret < 0) {
		log_message(WARNING, DEBUG_AREA_MAIN,
			    "Command server: client send() error: %s",
			    g_strerror(errno));
		command_client_close(this);
	}
	encoder_destroy(answer);
}

void command_client_run(command_client_t * this)
{
	char buffer[40];
	int ret;
	ret = recv(this->fd, buffer, sizeof(buffer) - 1, 0);
	if (ret <= 0) {
		if (ret == 0) {
			log_message(WARNING, DEBUG_AREA_MAIN, "Command server: "
				    "lost connection with client");
		} else {
			log_message(WARNING, DEBUG_AREA_MAIN, "Command server: "
				    "error on recv() from client: %s",
				    g_strerror(errno));
		}
		command_client_close(this);
		return;
	}
	if (ret == (sizeof(buffer)-1))
	{
		log_message(WARNING, DEBUG_AREA_MAIN,
			    "Command server: client command is too long, "
			    "disconnect him.");
		command_client_close(this);
	}
	buffer[ret] = 0;
	command_execute(this, buffer);
}

static void command_client_activity_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	if (w && w->data)
		command_client_run(w->data);
}

static void command_activity_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	if (w && w->data)
		command_client_accept(w->data);
}

int command_main(command_t * this)
{
	ev_loop(this->loop, 0);

	return 1;
}

void *command_server(GMutex * mutex)
{
	command_t command;

	if (!command_new(&command)) {
		nuauth_ask_exit();
		return NULL;
	}

	while (g_mutex_trylock(mutex)) {
		g_mutex_unlock(mutex);

		command_main(&command);
	}
	return NULL;
}

#endif

