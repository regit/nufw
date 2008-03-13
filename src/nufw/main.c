/*
 ** Copyright (C) 2002-2007 INL
 ** Written by Eric Leblond <regit@inl.fr>
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

/**
 *  \defgroup Nufw Nufw
 *  \file main.c
 *  \brief Function main()
 *
 * See function main().
 */

#include "nufw.h"

#include <linux/netfilter.h>
#include <unistd.h>
#include <pthread.h>
#include <netdb.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>
#include <sys/types.h>

#include <nubase.h>

GCRY_THREAD_OPTION_PTHREAD_IMPL;

char *key_file = NULL;
char *cert_file = NULL;

/* packet server thread */
struct nufw_threadtype thread;

/* packet server thread */
struct nufw_signals signals;

/*! Name of pid file prefixed by LOCAL_STATE_DIR (variable defined
 * during compilation/installation) */
#define NUFW_PID_FILE  LOCAL_STATE_DIR "/run/nufw.pid"

/**
 * Stop threads and then wait until threads exit.
 */
void nufw_stop_thread()
{
	/* ask threads to stop */
	pthread_mutex_lock(&tls.auth_server_mutex);
	pthread_mutex_lock(&thread.mutex);

	/* wait for thread end */
	log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_MESSAGE,
			"Wait threads end");
	if (tls.auth_server_running) {
		pthread_join(tls.auth_server, NULL);
	}
	pthread_mutex_unlock(&tls.auth_server_mutex);
	pthread_join(thread.thread, NULL);
	pthread_mutex_unlock(&thread.mutex);
}

/**
 * Clean mutex, memory, etc. before exiting NuFW
 */
void nufw_prepare_quit()
{
	/* clear packet list: use trylock() instead of lock() because the
	 * mutex may already be locked */
	clear_packet_list();
	pthread_mutex_destroy(&packets_list.mutex);

	/* close tls session */
	close_tls_session();
	pthread_mutex_destroy(&tls.mutex);

	/* destroy conntrack handle */
#ifdef HAVE_LIBCONNTRACK
	nfct_close(cth);
#endif

	/* free memory */
	free(key_file);
	free(cert_file);
	free(ca_file);
	freeaddrinfo(adr_srv);

	/* destroy pid file */
	unlink(NUFW_PID_FILE);
}

/**
 * "Hard" cleanup before leaving: called when SIGINT/SIGTERM is called twice.
 * Don't wait for thread end.
 */
void nufw_hard_cleanup(int signal)
{
	/* reinstall old handlers */
	(void) sigaction(SIGTERM, &signals.old_sigterm_hdl, NULL);
	(void) sigaction(SIGINT, &signals.old_sigint_hdl, NULL);

	log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_FATAL,
			"[+] NuFW \"hard\" cleanup (catch double signal)");
	nufw_prepare_quit();
	log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_FATAL,
			"[+] Exit NuFW");
	exit(EXIT_SUCCESS);
}

/**
 * Cleanup before leaving:
 *   - Destroy netfilter queue/handler
 *   - Close conntrack
 *   - Unlink pid file
 *   - Call exit(EXIT_SUCCESS)
 */
void nufw_cleanup(int signal)
{
	struct sigaction action;

	/* install "hard cleanup" for SIGTERM */
	memset(&action, 0, sizeof(action));
	action.sa_handler = nufw_hard_cleanup;
	sigemptyset(&(action.sa_mask));
	action.sa_flags = 0;
	sigaction(SIGTERM, &action, NULL);

	/* install "hard cleanup" for SIGINT */
	memset(&action, 0, sizeof(action));
	action.sa_handler = nufw_hard_cleanup;
	sigemptyset(&(action.sa_mask));
	action.sa_flags = 0;
	sigaction(SIGINT, &action, NULL);

	log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_FATAL,
			"[+] Stop NuFW (catch signal)");
	nufw_stop_thread();
	nufw_prepare_quit();
	log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_FATAL,
			"[+] Exit NuFW");
	exit(EXIT_SUCCESS);
}

/**
 * Create packet server thread: init mutex and create thread
 * with packetsrv() function. Send pointer to ::thread to
 * the function.
 */
void create_thread()
{
	/* should be static because thread may read data after this function exits */
	static struct nufw_threadargument arg;
	arg.thread = &thread;
	arg.parent_pid = getpid();

	/* set attribute to "joinable thread" */
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	/* create mutex */
	pthread_mutex_init(&thread.mutex, NULL);

	/* try to create the thread */
	if (pthread_create(&thread.thread, &attr, packetsrv, &arg) != 0) {
		pthread_mutex_destroy(&thread.mutex);
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_FATAL,
				"Fail to create thread!");
		exit(EXIT_FAILURE);
	}
#ifdef HAVE_LIBCONNTRACK
	if (handle_conntrack_event) {
		if (pthread_create
		    (&(tls.conntrack_event_handler), NULL,
		     conntrack_event_handler, NULL) == EAGAIN) {
			exit(EXIT_FAILURE);
		}
	}
#endif

}

/**
 * Install signals:
 *   - Set SIGTERM handler to nufw_cleanup()
 *   - Set SIGINT handler to nufw_cleanup()
 *   - Ignore SIGPIPE
 *   - Set SIGUSR1 handler to process_usr1()
 *   - Set SIGUSR2 handler to process_usr2()
 *   - Set SIGPOLL handler to process_poll()
 */
void install_signals()
{
	struct sigaction action;

	/* intercept SIGTERM */
	memset(&action, 0, sizeof(action));
	action.sa_handler = nufw_cleanup;
	sigemptyset(&(action.sa_mask));
	action.sa_flags = 0;
	if (sigaction(SIGTERM, &action, &signals.old_sigterm_hdl) != 0) {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_FATAL,
				"Fail to install SIGTERM handler: %d \n",
				errno);
		exit(EXIT_FAILURE);
	}

	/* intercept SIGINT */
	memset(&action, 0, sizeof(action));
	action.sa_handler = nufw_cleanup;
	sigemptyset(&(action.sa_mask));
	action.sa_flags = 0;
	if (sigaction(SIGINT, &action, &signals.old_sigint_hdl) != 0) {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_FATAL,
				"Fail to install SIGINT handler: %d \n",
				errno);
		exit(EXIT_FAILURE);
	}

	/* ignore "broken pipe" signal */
	signal(SIGPIPE, SIG_IGN);

	/* intercpet SIGUSR1 */
	memset(&action, 0, sizeof(action));
	action.sa_handler = &process_usr1;
	action.sa_flags = SIGUSR1;
	if (sigaction(SIGUSR1, &action, NULL) == -1) {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING,
				"Warning: Could not set signal USR1");
	}

	/* intercpet SIGUSR2 */
	memset(&action, 0, sizeof(action));
	action.sa_handler = &process_usr2;
	action.sa_flags = SIGUSR2;
	if (sigaction(SIGUSR2, &action, NULL) == -1) {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING,
				"Warning: Could not set signal USR2");
	}

	/* intercpet SIGPOLL */
	memset(&action, 0, sizeof(action));
	action.sa_handler = &process_poll;
	action.sa_flags = SIGPOLL;
	if (sigaction(SIGPOLL, &action, NULL) == -1) {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING,
				"Warning: Could not set signal POLL");
	}

#ifdef HAVE_LIBCONNTRACK
	/* intercpet SIGSYS */
	memset(&action, 0, sizeof(action));
	action.sa_handler = &process_sys;
	action.sa_flags = SIGSYS;
	if (sigaction(SIGSYS, &action, NULL) == -1) {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING,
				"Warning: Could not set signal SYS");
	}

	/* intercpet SIGWINCH */
	memset(&action, 0, sizeof(action));
	action.sa_handler = &process_winch;
	action.sa_flags = SIGWINCH;
	if (sigaction(SIGWINCH, &action, NULL) == -1) {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING,
				"Warning: Could not set signal WINCH");
	}
#endif
}

/**
 * Daemonize current process.
 */
void nufw_daemonize()
{
	FILE *pf;
	pid_t pidf;

	if (access(NUFW_PID_FILE, R_OK) == 0) {
		/* Check if the existing process is still alive. */
		pid_t pidv;

		pf = fopen(NUFW_PID_FILE, "r");
		if (pf != NULL &&
		    fscanf(pf, "%d", &pidv) == 1 && kill(pidv, 0) == 0) {
			fclose(pf);
			printf
			    ("pid file exists. Is nufw already running? Aborting!\n");
			exit(EXIT_FAILURE);
		}

		if (pf != NULL)
			fclose(pf);
	}

	pidf = fork();
	if (pidf < 0) {
		log_printf(DEBUG_LEVEL_FATAL, "Unable to fork. Aborting!");
		exit(-1);
	} else {
		/* parent */
		if (pidf > 0) {
			if ((pf = fopen(NUFW_PID_FILE, "w")) != NULL) {
				fprintf(pf, "%d\n", (int) pidf);
				fclose(pf);
			} else {
				printf("Dying, can not create PID file : "
				       NUFW_PID_FILE "\n");
				exit(EXIT_FAILURE);
			}
			exit(EXIT_SUCCESS);
		}
	}

	chdir("/");

	setsid();

	/* set log engine */
	log_engine = LOG_TO_SYSLOG;

	/* Close stdin, stdout, stderr. */
	(void) close(0);
	(void) close(1);
	(void) close(2);
}


/**
 * Initialization checks
 *  - check key and cert files
 */
int init_checks()
{
#if USE_X509
	if (!init_x509_filenames()) {
		printf("ERROR: Unable to allocate memory for "
				"key or cert filename!\n");
		return 0;
	}
	if (access(key_file, R_OK)) {
		printf("ERROR: Unable to read key file: %s\n", key_file);
		return 0;
	}
	if (access(cert_file, R_OK)) {
		printf("ERROR: Unable to read key file: %s\n", cert_file);
		return 0;
	}
#endif
	return 1;
}


/**
 * Main function of NuFW:
 *   - Initialize variables
 *   - Parse command line options
 *   - Dameonize it if nequired
 *   - Initialize log engine (see init_log_engine()).
 *   - Initialiaze mutex
 *   - Create TLS tunnel
 *   - Install signal handlers:
 *      - Ignore SIGPIPE
 *      - SIGTERM quit the program (see nufw_cleanup())
 *      - SIGUSR1 increase debug verbosity (see process_usr1())
 *      - SIGUSR2 decrease debug verbosity (see process_usr2())
 *      - SIGPOLL display statistics (see process_poll())
 *   - Open conntrack
 *   - Create packet server thread: packetsrv()
 *   - Run main loop
 *
 * When NuFW is running, main loop and two threads (packetsrv() and
 * authsrv()) and  are running.
 *
 * The most interresting things are done in the packet server (thread
 * packetsrv()). The main loop just clean up old packets and display
 * statistics.
 */
int main(int argc, char *argv[])
{
	/* option */
#if USE_NFQUEUE
	char *options_list = "DhVvmq:"
#ifdef HAVE_NFQ_SET_QUEUE_MAXLEN
	    "L:"
#endif
	    "c:k:a:n:d:p:t:T:A:"
#ifdef HAVE_LIBCONNTRACK
	    "CM"
#endif
	    ;
#else
	char *options_list = "DhVvmc:k:a:n:d:p:t:T:A:";
#endif
	int option, daemonize = 0;
	char *version = PACKAGE_VERSION;

	/* initialize variables */

	log_engine = LOG_TO_STD;	/* default is to send debug messages to stdout + stderr */
	authreq_port = AUTHREQ_PORT;
	packet_timeout = PACKET_TIMEOUT;
	track_size = TRACK_SIZE;
	cert_file = NULL;
	key_file = NULL;
	ca_file = NULL;
	nuauth_cert_dn = NULL;
	SECURE_STRNCPY(authreq_addr, AUTHREQ_ADDR, sizeof authreq_addr);
	debug_level = DEFAULT_DEBUG_LEVEL;
	debug_areas = DEFAULT_DEBUG_AREAS;
#if USE_NFQUEUE
	nfqueue_num = DEFAULT_NFQUEUE;
#ifdef HAVE_LIBCONNTRACK
	handle_conntrack_event = CONNTRACK_HANDLE_DEFAULT;
	nufw_conntrack_uses_mark = 0;
#endif
#ifdef HAVE_NFQ_SET_QUEUE_MAXLEN

	queue_maxlen = QUEUE_MAXLEN;
#endif
#endif
	nufw_set_mark = 0;


	log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_VERBOSE_DEBUG,
			"[+] Start NuFW");

	/*parse options */
	while ((option = getopt(argc, argv, options_list)) != -1) {
		switch (option) {
		case 'k':
			key_file = strdup(optarg);
			if (key_file == NULL) {
				fprintf(stderr,
					"Couldn't malloc! Exiting");
				exit(EXIT_FAILURE);
			}
			break;
		case 'c':
			cert_file = strdup(optarg);
			if (cert_file == NULL) {
				fprintf(stderr,
					"Couldn't malloc! Exiting");
				exit(EXIT_FAILURE);
			}
			break;
		case 'a':
			ca_file = strdup(optarg);
			if (ca_file == NULL) {
				fprintf(stderr,
					"Couldn't malloc! Exiting");
				exit(EXIT_FAILURE);
			}
			break;
		case 'n':
			nuauth_cert_dn = strdup(optarg);
			if (nuauth_cert_dn == NULL) {
				fprintf(stderr,
					"Couldn't malloc! Exiting");
				exit(EXIT_FAILURE);
			}
			break;
		case 'V':
			fprintf(stdout, "%s (version %s)\n", PACKAGE_NAME,
				version);
			return 1;
		case 'D':
			daemonize = 1;
			break;
		case 'v':
			/*fprintf (stdout, "Debug should be On\n"); */
			debug_level += 1;
			break;
		case 'p':
			authreq_port = atoi(optarg);
			break;
			/* destination IP */
		case 'd':
			SECURE_STRNCPY(authreq_addr, optarg,
				       sizeof authreq_addr);
			printf("Sending Auth request to %s\n",
			       authreq_addr);
			break;
			/* packet timeout */
		case 't':
			sscanf(optarg, "%d", &packet_timeout);
			break;
			/* max size of packet list */
		case 'T':
			sscanf(optarg, "%d", &track_size);
			break;
		case 'A':
			sscanf(optarg, "%d", &debug_areas);
			break;
		case 'm':
			nufw_set_mark = 1;
			break;
#if USE_NFQUEUE
		case 'q':
			sscanf(optarg, "%hu", &nfqueue_num);
			break;
		case 'C':
#if HAVE_LIBCONNTRACK
			handle_conntrack_event = 1;
			break;
		case 'M':
			nufw_conntrack_uses_mark = 1;
			/* this implies -C */
			handle_conntrack_event = 1;
			/* and -m */
			nufw_set_mark = 1;
			break;
#endif				/* HAVE_LIBCONNTRACK */
#ifdef HAVE_NFQ_SET_QUEUE_MAXLEN
		case 'L':
			sscanf(optarg, "%u", &queue_maxlen);
			break;
#endif
#endif				/* USE_NFQUEUE */

		case 'h':
			fprintf(stdout, "%s [-hVc"
#ifdef HAVE_LIBCONNTRACK
				"CM"
#endif
				"v[v[v[v[v[v[v[v[v[v]]]]]]]]]] [-d remote_addr] [-p remote_port]  [-t packet_timeout] [-T track_size]"
#ifdef USE_NFQUEUE
				" [-q queue_num]"
#ifdef HAVE_NFQ_SET_QUEUE_MAXLEN
				" [-L queue_maxlen]"
#endif
#endif
				"\n\
\t-h: display this help and exit\n\
\t-V: display version and exit\n\
\t-D: daemonize\n\
\t-k: use specified file as key file\n\
\t-c: use specified file as cert file\n\
\t-a: use specified file as ca file (strict checking is done if selected) (default: none)\n\
\t-n: use specified string as the needed DN of nuauth (inforce certificate checking) (default: none)\n\
\t-v: increase debug level (+1 for each 'v') (max useful number: 10)\n\
\t-A: debug areas (see man page for details)\n\
\t-m: mark packet with nuauth provided mark\n"
#ifdef HAVE_LIBCONNTRACK
				"\t-C: listen to conntrack events (needed for connection expiration)\n\
\t-M: only report event on marked connections to nuauth (implies -C and -m)\n"
#endif
				"\t-d: remote address we send auth requests to (address of the nuauth server) (default: 127.0.0.1)\n\
\t-p: remote port we send auth requests to (TCP port nuauth server listens on) (default: 4128)\n"
#if USE_NFQUEUE
				"\t-q: use nfqueue number (default: 0)\n"
#ifdef HAVE_NFQ_SET_QUEUE_MAXLEN
				"\t-L : set queue max len (default : 1024)\n"
#endif
#endif
				"\t-t : timeout to forget about packets when they don't match (default : 15 s)\n\
\t-T : track size (default : 1000)\n",
				PACKAGE_TARNAME);

			exit(EXIT_SUCCESS);
		}
	}

	if (getuid()) {
		printf("nufw must be run as root! Sorry\n");
		exit(EXIT_FAILURE);
	}

	if (!init_checks()) {
		exit(EXIT_FAILURE);
	}

	/* Nice nufw to increase performance of nfnetlink layer */
	nice(-1);

	/* Daemon code */
	if (daemonize == 1) {
		nufw_daemonize();
	}

	install_signals();

	init_log_engine("nufw");

	/* open ICMP (IPv4) socket */
	raw_sock4 = socket(PF_INET, SOCK_RAW, 1);	/* 1: ICMP protocol */
	if (raw_sock4 == -1) {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL,
				"Fail to create socket for ICMP!");
		exit(EXIT_FAILURE);
	}

	/* open ICMPv6 socket */
	raw_sock6 = socket(PF_INET6, SOCK_RAW, 58);	/* 58: ICMPv6 protocol */
	if (raw_sock6 == -1) {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL,
				"Fail to create socket for ICMPv6!");
	}

	/* create packet list */
	packets_list.start = NULL;
	packets_list.end = NULL;
	packets_list.length = 0;
	pthread_mutex_init(&packets_list.mutex, NULL);

	/* init. tls */
	tls.session = NULL;
	tls.auth_server_running = 0;
	pthread_mutex_init(&tls.mutex, NULL);

	/* start GNU TLS library */
	gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
	if (nussl_init() != NUSSL_OK) {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_FATAL,
				"Unable to initialize NuSSL library.");

	}

#ifdef HAVE_LIBCONNTRACK
	cth = nfct_open(CONNTRACK, 0);
#endif


	/* create packet server thread */
	create_thread();
	log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_FATAL,
			"[+] NuFW " VERSION " started");

	/* control stuff */
	pckt_tx = pckt_rx = 0;
	while (1 == 1) {
		int stat = pckt_tx;
		const int seconds = 5;

		sleep(seconds);

		stat = pckt_tx - stat;

		/* clean old packets */
		pthread_mutex_lock(&packets_list.mutex);
		clean_old_packets();
		pthread_mutex_unlock(&packets_list.mutex);
#ifdef DEBUG_ENABLE
		/* display stats */
		process_poll(0);
		printf("Average: %u\n", stat / seconds);
#endif
	}

	nufw_stop_thread();
	nufw_prepare_quit();
	return EXIT_SUCCESS;
}
