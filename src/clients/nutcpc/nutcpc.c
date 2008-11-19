/*
 ** Copyright 2004-2008 - INL
 ** Written by Eric Leblond <eric.leblond@inl.fr>
 **            Vincent Deffontaines <vincent@inl.fr>
 ** INL http://www.inl.fr/
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

/* Enable GNU extensions: getline() from stdio.h */
#include "nufw_source.h"

#include <config.h>
#include "../lib/nuclient.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <locale.h>
#include <sys/resource.h>	/* setrlimit() */
#include <langinfo.h>
#include <stdarg.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/stat.h>	/* mkdir() */
#include <sys/types.h>	/* mkdir() */
#include <termios.h>	/* tcgetattr() */
#include "proto.h"
#include "security.h"
#include "debug.h"
#define NUTCPC_VERSION PACKAGE_VERSION " $Revision$"

#ifdef FREEBSD
#include <sys/syslimits.h>	/* PATH_MAX */
#include <readpassphrase.h>
#endif

#define MAX_RETRY_TIME 30

#include <nubase.h>
#include <nussl.h>

struct termios orig;
nuauth_session_t *session = NULL;
nuclient_error_t *err = NULL;
struct sigaction old_sigterm;
struct sigaction old_sigint;
int forced_reconnect = 0;
static int suppress_ca_warning = 0;
static int suppress_fqdn_verif = 0;

void panic(const char *fmt, ...)
#ifdef __GNUC__
	__attribute__((__format__(printf,1,2)))
#endif
;

typedef struct {
	char port[10];		/*!< Port (service) number / name */
	unsigned long interval;	/*!< Number of millisecond for sleep in main loop (default value: 100ms) */
	unsigned char donotuselock;	/*!< Do not user lock */
	char srv_addr[512];	/*!< Nuauth server hostname */
	char password[100];
	char nuauthdn[512];
	unsigned char debug_mode;	/*!< Debug mode enabled if different than zero */
	int tempo;		/*!< Number of second between each connection retry */
	char *certfile;
	char *keyfile;
	char *cafile;
	char *crlfile;
	char *pkcs12file;
	char *pkcs12password;
	char *krb5_service;
} nutcpc_context_t;

/**
 * Panic: function called on fatal error.
 * Display error message and then exit client (using exit()).
 */
void panic(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	printf("\n");
	printf("Fatal error: ");
	vprintf(fmt, args);
	printf("\n");
	fflush(stdout);
	exit(EXIT_FAILURE);
	va_end(args);
}

/**
 * Compure run pid filename: "$HOME/.nufw/nutcpc"
 */
char *compute_run_pid()
{
	char path_dir[254];
	char *home = nu_get_home_dir();
	if (home == NULL)
		return NULL;
	secure_snprintf(path_dir, sizeof(path_dir), "%s/.nufw", home);
	if (access(path_dir, R_OK) != 0) {
		printf("Creating directory \"%s\"\n", path_dir);
		if (mkdir(path_dir, S_IRWXU) != 0) {
			printf("Could not create directory \"%s\" (%s)\n", path_dir, strerror(errno));
		}
	}
	secure_snprintf(path_dir, sizeof(path_dir), "%s/.nufw/nutcpc", home);
	free(home);
	return strdup(path_dir);
}

/**
 * Test if a nutcpc is currently running
 */
int test_nutcpc(pid_t *pid)
{
	FILE *fd;
	int ok = EXIT_FAILURE;
	char *runpid = compute_run_pid();

	if (runpid) {
		fd = fopen(runpid, "r");
		if (fd) {
			fscanf(fd, "%d", pid);
			fclose(fd);
			/* FIXME test if process pid is running */
			ok = EXIT_SUCCESS;
		}
		free(runpid);
	}
	return ok;
}

/**
 * Kill existing instance of nutcpc: read pid file,
 * and then send SIGTERM to the process.
 *
 * Exit the program at the end of this function.
 */
void kill_nutcpc()
{
	pid_t pid;

	if (test_nutcpc(&pid) == EXIT_SUCCESS) {
		int ret;
		char *runpid = compute_run_pid();
		ret = kill(pid, SIGTERM);
		if (ret == 0) {
			printf("nutcpc process killed (pid %lu)\n",
					(unsigned long) pid);
			unlink(runpid);
			free(runpid);
			exit(EXIT_SUCCESS);
		} else {
			switch (errno) {
				case ESRCH:
					printf("Process does not exist: removing pid file\n");
					unlink(runpid);
					break;
				case EINVAL:
				case EPERM:
				default:
					printf("Bad return from kill\n");
			}
			free(runpid);
			exit(EXIT_FAILURE);
		}
	} else {
		printf("No nutcpc seems to be running\n");
		exit(EXIT_FAILURE);
	}
	exit(EXIT_SUCCESS);
}

/**
 * Leave the client:
 *   - Restore ECHO mode ;
 *   - Free memory of the library ;
 *   - Unlink pid file ;
 *   - deinit. library ;
 *   - free memory.
 */
void leave_client()
{
	char *runpid;
	struct termios term;

	/* restore ECHO mode */
	if (tcgetattr(fileno(stdin), &term) == 0) {
		term.c_lflag |= ECHO;
		(void) tcsetattr(fileno(stdin), TCSAFLUSH, &term);
	}

	if (session) {
		nu_client_delete(session);
	}

	runpid = compute_run_pid();
	if (runpid != NULL) {
		unlink(runpid);
		free(runpid);
	}
	nu_client_global_deinit();
	nu_client_error_destroy(err);
}

/**
 * Signal handler: catch SIGINT or SIGTERM. This function will exit nutcpc:
 * deinit libnuclient, free memory, and then exit the process.
 *
 * The function will first reinstall old handlers.
 */
void exit_clean()
{
	/* reinstall old signal handlers */
	(void) sigaction(SIGINT, &old_sigint, NULL);
	(void) sigaction(SIGTERM, &old_sigterm, NULL);

	/* quit nutcpc */
	printf("\nQuit client\n");
	leave_client();
	exit(EXIT_SUCCESS);
}

#ifdef FREEBSD
ssize_t getline(char **lineptr, size_t * n, FILE * stream)
{
	char *line;
	size_t len;

	/* call fgetln(): read line from stdin */
	line = fgetln(stream, &len);
	if (!line)
		return -1;

	/* buffer need to grow up? */
	if (len >= *n) {
		char *tmp = realloc(*lineptr, len + 1);
		if (tmp == NULL) {
			printf("Not enough memory\n");
			return -1;
		}
		*lineptr = tmp;
		*n = len + 1;
	}
	memcpy(*lineptr, line, len);
	(*lineptr)[len] = 0;
	return len;
}
#endif

#ifndef FREEBSD
/**
 * Read a password on terminal. Given buffer may grow up (resized by realloc).
 *
 * \param lineptr Pointer to buffer
 * \param linelen Initial length (including nul byte) of the buffer
 * \return Number of characters of the password,
 *         or -1 if fails
 */
ssize_t my_getpass(char **lineptr, size_t * linelen)
{
	struct termios new;
	int nread;

	/* Turn echoing off and fail if we can't. */
	if (tcgetattr(fileno(stdin), &orig) != 0)
		return -1;
	new = orig;
	new.c_lflag &= ~ECHO;
	if (tcsetattr(fileno(stdin), TCSAFLUSH, &new) != 0)
		return -1;

	/* Read the password. */
	nread = getline(lineptr, linelen, stdin);

	/* Restore terminal. */
	(void) tcsetattr(fileno(stdin), TCSAFLUSH, &orig);

	/* remove new line if needed */
	if (0 < nread) {
		char *line = *lineptr;
		if (line[nread - 1] == '\n') {
			line[nread - 1] = '\0';
			nread--;
		}
	}
	printf("\n");
	return nread;
}
#endif

/**
 * Callback used in nu_client_connect() call: read password
 *
 * \return New allocated buffer containing the password,
 *         or NULL if it fails
 */
char *get_password()
{
	size_t password_size = 32;
	char *new_pass;
	char *question = "Enter password: ";
#ifdef FREEBSD
	char *ret;
#else
	int ret;
#endif

	new_pass = (char *) calloc(password_size, sizeof(char));
#ifdef FREEBSD
	ret =
	    readpassphrase(question, new_pass, password_size,
			   RPP_REQUIRE_TTY);
	if (ret == NULL) {
		fprintf(stderr, "unable to read passphrase");
	}
#else
	printf("%s", question);
	ret = my_getpass(&new_pass, &password_size);
	if (ret < 0) {
		free(new_pass);
		printf("Problem when getting password\n");
		return NULL;
	}
#endif
	return new_pass;
}

/**
 * Callback used in nu_client_connect() call: read user name
 *
 * \return New allocated buffer containing the name,
 *         or NULL if it fails
 */
char *get_username()
{
	char *username;
	int nread;
	size_t username_size = 32;

	printf("Enter username: ");
	username = (char *) calloc(username_size, sizeof(char));
	nread = getline(&username, &username_size, stdin);
	if (nread < 0) {
		free(username);
		printf("Problem when reading username\n");
		return NULL;
	}
	if (0 < nread && username[nread - 1] == '\n') {
		username[nread - 1] = 0;
	}
	return username;
}

/**
 * Print client usage.
 */
static void usage(void)
{
	fprintf(stderr, "usage: nutcpc -U username -H host\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -k: kill active client\n");
	fprintf(stderr, "  -c: check if there is an active client\n");
	fprintf(stderr, "  -l: don't create lock file\n");
	fprintf(stderr, "  -V: display version\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Certificate options:\n");
	fprintf(stderr, "  -C CERTFILE: PEM certificate filename\n");
	fprintf(stderr, "  -A AUTHFILE: PEM authority certificate filename\n");
	fprintf(stderr, "  -K KEYFILE:  PEM RSA private key filename\n");
	fprintf(stderr, "  -S PKCS12FILE: PKCS12 key/certificate filename\n");
	fprintf(stderr, "  -W PKCS12PASS: PKCS12 password\n");
	fprintf(stderr, "  -R CRLFILE: crl filename\n");
	fprintf(stderr, "  -Q: suppress warning if no certificate authority is configured\n");
	fprintf(stderr, "  -N: suppress error if server FQDN does not match certificate CN.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "SASL options:\n");
	fprintf(stderr, "  -Z SERVICE: Kerberos service name (nuauth)\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Other options:\n");
	fprintf(stderr, "  -p PORT: nuauth port number\n");
	fprintf(stderr, "  -a AUTH_DN: authentication domain name\n");
	fprintf(stderr, "  -I INTERVAL: check interval in milliseconds\n");
	fprintf(stderr, "  -q: do not display running nutcpc options on \"ps\"\n");
	fprintf(stderr, "  -P PASSWORD: specify password (only for debug purpose)\n");
	fprintf(stderr, "  -d: debug mode (don't go to foreground, daemon)\n");
	fprintf(stderr, "\n");
	exit(EXIT_FAILURE);
}

void process_hup(int signum)
{
	forced_reconnect = 1;
}

/**
 * Install signal handlers:
 *   - SIGINT: call exit_clean() ;
 *   - SIGTERM: call exit_clean().
 */
void install_signals()
{
	struct sigaction action;
	action.sa_handler = exit_clean;
	sigemptyset(&(action.sa_mask));
	action.sa_flags = 0;

	/* install handlers */
	if (sigaction(SIGINT, &action, &old_sigint) != 0) {
		fprintf(stderr, "Unable to install SIGINT signal handler!\n");
		exit(EXIT_FAILURE);
	}
	if (sigaction(SIGTERM, &action, &old_sigterm) != 0) {
		fprintf(stderr, "Unable to install SIGTERM signal handler!\n");
		exit(EXIT_FAILURE);
	}
	memset(&action, 0, sizeof(action));
	action.sa_handler = &process_hup;
	action.sa_flags = SIGHUP;

	if (sigaction(SIGHUP, &action, NULL) != 0)
	{
		fprintf(stderr, "Warning : Unable to install SIGHUP signal handler!\n");
	}
}

/**
 * Daemonize the process
 */
void daemonize_process(nutcpc_context_t * context, char *runpid)
{
	pid_t p;

	/* 1st fork */
	p = fork();
	if (p < 0) {
		fprintf(stderr, "nutcpc: fork failure: %s\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* kill 1st process (keep 2nd) */
	if (p != 0) {
		exit(0);
	}

	/* 2nd fork */
	p = fork();
	if (p < 0) {
		fprintf(stderr, "nutcpc: fork falure: %s\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* kill 2nd process (keep 3rd) */
	if (p != 0) {
		fprintf(stderr, "nutcpc started (pid %d)\n", (int) p);
		if (context->donotuselock == 0) {
			FILE *RunD;
			RunD = fopen(runpid, "w");
			free(runpid);
			fprintf(RunD, "%d", p);
			fclose(RunD);
		}
		exit(EXIT_SUCCESS);
	}

	/* Fix process user identifier, close stdin, stdout, stderr,
	 * set currente directory to root directory */
	setsid();
	(void) chdir("/");
	ioctl(STDIN_FILENO, TIOCNOTTY, NULL);
	(void) close(STDIN_FILENO);
	(void) close(STDOUT_FILENO);
	(void) close(STDERR_FILENO);
	setpgid(0, 0);
}

void wipe(void *data, size_t datalen)
{
	memset(data, 0, datalen);
}

/**
 * Display informations about the user certificate
 *
 */
void display_cert(nuauth_session_t* session)
{
	char* infos = nu_client_get_cert_infos(session);
	printf("User certificate:\n%s\n", infos ? infos : "None");
	free(infos);
	infos = nu_client_get_server_cert_infos(session);
	printf("Server certificate:\n%s\n", infos ? infos : "None");
	free(infos);
}


/**
 * Try to connect to nuauth.
 *
 * \return The client session, or NULL on error (get description from ::err)
 */
nuauth_session_t *do_connect(nutcpc_context_t * context, char *username)
{
	nuauth_session_t *session;

	session = nu_client_new_callback(get_username, get_password, 1, err);
	if (session == NULL) {
		printf("Problem during session callback init\n");
		return NULL;
	}

	if (username) {
		nu_client_set_username(session, username);
		free(username);
	}
	if (context->password[0] != 0) {
		nu_client_set_password(session, context->password);
	}

	nu_client_set_debug(session, context->debug_mode);

	/* Set hostname from libnuclient if it wasn't specified by the user */
	if(*context->port == '\0')
	{
		if(nu_client_default_port())
			SECURE_STRNCPY(context->port, nu_client_default_port(),
			       sizeof(context->port));
		else
			SECURE_STRNCPY(context->port, USERPCKT_SERVICE,
				       sizeof(context->port));
	}

	if(*context->srv_addr == '\0')
	{
		if(nu_client_default_hostname())
			SECURE_STRNCPY(context->srv_addr, nu_client_default_hostname(),
			       sizeof(context->srv_addr));
		else
			SECURE_STRNCPY(context->srv_addr, NUAUTH_IP,
				       sizeof(context->srv_addr));
	}

	if (context->pkcs12file) {
		if (!nu_client_set_pkcs12(session, context->pkcs12file, context->pkcs12password, err)) {
			goto init_failed;
		}
	}
	else {
		if (!nu_client_set_key(session, context->keyfile, context->certfile, err)) {
			goto init_failed;
		}
	}

	if (!nu_client_set_ca(session, context->cafile, err)) {
		goto init_failed;
	}

	nu_client_set_ca_suppress_warning(session,suppress_ca_warning);
	if (suppress_fqdn_verif)
		nu_client_set_fqdn_suppress_verif(session, 1);

	if (context->nuauthdn) {
		if (!nu_client_set_nuauth_cert_dn(session,
						  context->nuauthdn,
						  err)) {
			goto init_failed;
		}
	}

	if (context->crlfile) {
		if (!nu_client_set_crlfile(session, context->crlfile, err)) {
			goto init_failed;
		}
	}

	if (context->krb5_service) {
		if (!nu_client_set_krb5_service(session, context->krb5_service)) {
			nu_client_delete(session);
			fprintf(stderr, "Unable to setup Kerberos5 service\n");
			return NULL;
		}
	}

	if (!nu_client_connect(session, context->srv_addr, context->port, err)) {
		goto init_failed;
	}
	return session;
init_failed:

	printf("Initialization error: %s\n", nu_client_strerror(session, err));
	nu_client_delete(session);
	return NULL;
}

/**
 * Main loop: program stay in this loop until it stops.
 */
void main_loop(nutcpc_context_t * context)
{
	int connected = 1;
	int ret;
	for (;;) {
		if (!connected) {
			if (forced_reconnect == 0) {
				usleep((unsigned long) context->tempo * 1000000);
			} else {
				context->tempo = 1;
				forced_reconnect = 0;
			}
			if (context->tempo < MAX_RETRY_TIME) {
				context->tempo *= 2;
			}

			/* try to reconnect to nuauth */
			if (nu_client_connect
					(session, context->srv_addr, context->port,
					 err) != 0) {
				connected = 1;
				context->tempo = 1;	/* second */
			} else {
				printf("Reconnection error: %s\n",
						nu_client_strerror(session, err));
				nu_client_reset(session);
			}
		} else {
			forced_reconnect = 0;
			ret = nu_client_check(session, err);
			if (ret < 0) {
				/* on error: reset the session */
				nu_client_reset(session);
				connected = 0;
				printf("%s\n", nu_client_strerror(session, err));
			}
		}
	}
}

/**
 * Copy a filename given on the command line.
 * If it doesn't start with '/', add current directory as prefix.
 *
 * Returns NULL on error, new allocated string otherwise.
 */
char* copy_filename(char* name)
{
	char cwd[PATH_MAX];
	char buffer[PATH_MAX];
	int ok;
	char* ret;
	if (name[0] != '/') {
		ret = getcwd(cwd, sizeof(cwd));
		if (!ret) {
			printf("Unable to get current working directory\n");
			return NULL;
		}
		ok = secure_snprintf(buffer, sizeof(buffer), "%s/%s", cwd, name);
		if (!ok) {
			printf("Unable to copy filename\n");
			return NULL;
		}
		RETURN_NO_LOG strdup(buffer);
	} else {
		RETURN_NO_LOG strdup(name);
	}
}

/**
 * Parse command line options
 */
void parse_cmdline_options(int argc, char **argv,
			   nutcpc_context_t * context, char **username)
{
	int ch;
	int index;
	int stealth = 0;

	/* set default values */
	context->interval = 100;
	context->donotuselock = 0;
	context->debug_mode = 0;
	context->tempo = 1;

	/* Parse all command line arguments */
	opterr = 0;
	while ((ch = getopt(argc, argv, "kcldqNQVu:H:I:U:p:P:a:K:C:A:R:W:S:Z:")) != -1) {
		switch (ch) {
		case 'H':
			SECURE_STRNCPY(context->srv_addr, optarg,
				       sizeof(context->srv_addr));
			break;
		case 'P':
			SECURE_STRNCPY(context->password, optarg,
				       sizeof(context->password));
			stealth = 1;
			break;
		case 'd':
			context->debug_mode = 1;
			break;
		case 'I':
			context->interval = atoi(optarg);
			if (context->interval == 0) {
				fprintf(stderr, "nutcpc: bad interval\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 'l':
			context->donotuselock = 1;
			break;
		case 'U':
			*username = strdup(optarg);
			break;
		case 'c': {
				  pid_t pid;
				  if (test_nutcpc(&pid) == EXIT_SUCCESS) {
					  printf("nutcpc already running (pid %u)\n",
						 pid);
					  exit(EXIT_SUCCESS);
				  }
				  printf("No running nutcpc\n");
				  exit(EXIT_FAILURE);
			  }
			break;
		case 'k':
			kill_nutcpc();
			break;
		case 'V':
			printf("nutcpc (version " NUTCPC_VERSION ")\n");
			exit(0);
		case 'p':
			SECURE_STRNCPY(context->port, optarg,
				       sizeof(context->port));
			break;
		case 'q':
			stealth = 1;
			break;
		case 'N':
			suppress_fqdn_verif = 1;
			break;
		case 'Q':
			suppress_ca_warning = 1;
			break;
		case 'a':
			SECURE_STRNCPY(context->nuauthdn, optarg,
				       sizeof(context->nuauthdn));
			break;
		case 'C':
			context->certfile = copy_filename(optarg);
			break;
		case 'K':
			context->keyfile = copy_filename(optarg);
			break;
		case 'A':
			context->cafile = copy_filename(optarg);
			break;
		case 'R':
			context->crlfile = copy_filename(optarg);
			break;
		case 'S':
			context->pkcs12file = copy_filename(optarg);
			break;
		case 'W':
			context->pkcs12password = strdup(optarg);
			break;
		case 'Z':
			context->krb5_service = strdup(optarg);
			break;
		default:
			usage();
		}
	}
	if (context->password[0] != 0 && !context->debug_mode) {
		fprintf(stderr,
			"Don't use -P option outside debugging, it's not safe!\n");
		exit(EXIT_FAILURE);
	}

	if ((context->keyfile || context->certfile) && (context->pkcs12file || context->pkcs12password))
	{
		fprintf(stderr, "Don't mix PKCS12 options with X509/RSA options.\n");
		exit(EXIT_FAILURE);
	}

	/* fill argument with nul byte */
	if (stealth == 1) {
		for (index = argc; 1 < index; index--) {
			memset(argv[index - 1], '\0',
			       strlen(argv[index - 1]));
		}
	}
}

/**
 * Initialize nuclient library
 */
void init_library(nutcpc_context_t * context, char *username)
{
	struct rlimit core_limit;

	/* Avoid creation of core file which may contains username and password */
	if (!context->debug_mode && getrlimit(RLIMIT_CORE, &core_limit) == 0) {
		core_limit.rlim_cur = 0;
		setrlimit(RLIMIT_CORE, &core_limit);
	}

	/* Prepare error structure */
	if (nu_client_error_init(&err) != 0) {
		printf("Cannot init error structure!\n");
		exit(EXIT_FAILURE);
	}

	/* global libnuclient init */
	if (!nu_client_global_init(err)) {
		printf("Unable to initiate nuclient library!\n");
		printf("Problem: %s\n", nu_client_strerror(session, err));
		exit(EXIT_FAILURE);
	}

	/* options specificied on command line are taken prior
	 * to options from configuration file
	 */
	suppress_fqdn_verif |= nu_client_default_suppress_fqdn_verif();
	if (!context->cafile)
		context->cafile = (char *)nu_client_default_tls_ca();
	if (!context->certfile)
		context->certfile = (char *)nu_client_default_tls_cert();
	if (!context->keyfile)
		context->keyfile = (char *)nu_client_default_tls_key();

	/* Init. library */
	printf("Connecting to NuFW gateway (%s)\n", context->srv_addr);
	session = do_connect(context, username);

	if (session) {
		display_cert(session);
	}

	/* Library failure? */
	if (session == NULL) {
		printf("Unable to initiate connection to NuFW gateway\n");
		printf("Problem: %s\n", nu_client_strerror(session, err));
		printf("Authentication failed (check parameters)\n");
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char **argv)
{
	char *runpid = compute_run_pid();
	char *username = NULL;
	char *default_username = NULL;
	nutcpc_context_t context;
	memset(&context, 0, sizeof(context));

	default_username = nu_get_user_name();

	/* needed by iconv */
	setlocale(LC_ALL, "");

	if (!nu_check_version(NUCLIENT_VERSION)) {
		fprintf(stderr,
			"Wrong version of libnuclient (%s instead of %s)\n",
			nu_get_version(), NUCLIENT_VERSION);
		exit(EXIT_FAILURE);
	}

	if (runpid == NULL) {
		fprintf(stderr, "Can not determine runpid, leaving\n");
		exit(EXIT_FAILURE);
	}



	/* parse command line options */
	parse_cmdline_options(argc, argv, &context, &username);

	if (!context.debug_mode) {
		if (context.donotuselock == 0) {
			if (!access(runpid, R_OK)) {
				FILE *fd;
				printf("Lock file found: %s\n", runpid);
				if ((fd = fopen(runpid, "r"))) {
					char line[20];
					if (fgets(line, 19, fd)) {
						pid_t pid =
						    (pid_t) atoi(line);
						fclose(fd);
						if (kill(pid, 0)) {
							printf
							    ("No running process, starting anyway (deleting lockfile)\n");
							unlink(runpid);
						} else {
							printf
							    ("Kill existing process with \"-k\" or ignore it with \"-l\" option\n");
							exit(EXIT_FAILURE);
						}
					}
				}
			}
		}
	}

	install_signals();

	if (!username)
		username = default_username;

	init_library(&context, username);

	/*
	 * Become a daemon by double-forking and detaching completely from
	 * the terminal.
	 */

	if (!context.debug_mode) {
		daemonize_process(&context, runpid);
	} else {
		fprintf(stderr,
			"nutcpc " NUTCPC_VERSION " started (debug)\n");
	}
	free(runpid);

	main_loop(&context);
	leave_client();
	exit(EXIT_SUCCESS);
}
