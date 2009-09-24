/*
 ** Copyright (C) 2002-2009 INL
 ** Written by Eric Leblond <regit@inl.fr>
 **            Vincent Deffontaines <vincent@gryzor.com>
 **            Pierre Chifflier <chifflier@inl.fr>
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

/**
 *  \defgroup Nufw Nufw
 *  \file main.c
 *  \brief Function main()
 *
 * See function main().
 */

#include "nufw.h"

#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif

#include <linux/netfilter.h>
#include <unistd.h>
#include <netdb.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>
#include <sys/types.h>

#include <nubase.h>

#include "nufwconf.h"

char *key_file = NULL;
char *cert_file = NULL;

/* packet server thread */
struct nufw_threadtype thread;

/* packet server thread */
struct nufw_signals signals;

/*! Name of pid file prefixed by LOCAL_STATE_DIR (variable defined
 * during compilation/installation) */
#define NUFW_PID_FILE  LOCAL_STATE_DIR "/run/nufw.pid"

char * nufw_config_file = DEFAULT_NUFW_CONF_FILE;

/**
 * Clean mutex, memory, etc. before exiting NuFW
 */
void nufw_prepare_quit()
{
	/* clear packet list: use trylock() instead of lock() because the
	 * mutex may already be locked */
	clear_packet_list();

	/* close tls session */
	close_tls_session();

	/* destroy conntrack handle */
#ifdef HAVE_LIBCONNTRACK
	nfct_close(cth);
#endif

	/* free memory */
	free(key_file);
	free(cert_file);
	free(ca_file);
	free(crl_file);
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
	nufw_prepare_quit();
	log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_FATAL,
			"[+] Exit NuFW");
	exit(EXIT_SUCCESS);
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

	/* intercept SIGUSR1 */
	memset(&action, 0, sizeof(action));
	action.sa_handler = &process_usr1;
	action.sa_flags = SIGUSR1;
	if (sigaction(SIGUSR1, &action, NULL) == -1) {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING,
				"Warning: Could not set signal USR1");
	}

	/* intercept SIGUSR2 */
	memset(&action, 0, sizeof(action));
	action.sa_handler = &process_usr2;
	action.sa_flags = SIGUSR2;
	if (sigaction(SIGUSR2, &action, NULL) == -1) {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING,
				"Warning: Could not set signal USR2");
	}

	/* intercept SIGPOLL */
	memset(&action, 0, sizeof(action));
	action.sa_handler = &process_poll;
	action.sa_flags = SIGPOLL;
	if (sigaction(SIGPOLL, &action, NULL) == -1) {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING,
				"Warning: Could not set signal POLL");
	}

	/* intercept SIGHUP */
	memset(&action, 0, sizeof(action));
	action.sa_handler = &process_hup;
	action.sa_flags = SIGHUP;
	if (sigaction(SIGHUP, &action, NULL) == -1) {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING,
				"Warning: Could not set signal HUP");
	}
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
 * Parse configuration values and set variables
 */
int nufw_use_config()
{
	char * value;

	value = nufw_config_table_get("nufw_tls_cacert");
	if (value != NULL && ca_file == NULL) {
		ca_file = strdup(value);
	}

	value = nufw_config_table_get_or_default("nufw_tls_cert",DEFAULT_NUFW_CERT);
	if (value != NULL && cert_file == NULL) {
		cert_file = strdup(value);
	}

	value = nufw_config_table_get_or_default("nufw_tls_key",DEFAULT_NUFW_KEY);
	if (value != NULL && key_file == NULL) {
		key_file = strdup(value);
	}

	value = nufw_config_table_get("nufw_tls_crl");
	if (value != NULL && crl_file == NULL) {
		crl_file = strdup(value);
	}

	value = nufw_config_table_get_or_default("nufw_destination", AUTHREQ_ADDR);
	if (value != NULL && strlen(authreq_addr) == 0) {
		SECURE_STRNCPY(authreq_addr, value, sizeof authreq_addr);
		printf("Sending Auth request to %s\n", authreq_addr);
	}

	return 0;
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

static struct option long_options[] = {
	{"help", 0, NULL, 'h'},
	{"version", 0, NULL, 'V'},
	{"daemon", 0, NULL, 'D'},
	{"no-strict", 0, NULL, 's'},
	{"strict", 0, NULL, 'S'},
	{"no-fqdn", 0, NULL, 'N'},
	{"key", 1, NULL, 'k'},
	{"cert", 1, NULL, 'c'},
	{"ca", 1, NULL, 'a'},
	{"crl", 1, NULL, 'r'},
	{"check-dn", 1, NULL, 'n'},
	{"verbose", 0, NULL, 'v'},
	{"debug-area", 1, NULL, 'A'},
	{"ipv4", 0, NULL, '4'},
	{"mark", 0, NULL, 'm'},
	{"conntrack", 0, NULL, 'C'},
	{"marked-only", 0, NULL, 'M'},
	{"destination", 1, NULL, 'd'},
	{"port", 1, NULL, 'p'},
	{"queue", 1, NULL, 'q'},
	{"queue-len", 1, NULL, 'L'},
	{"timeout", 1, NULL, 't'},
	{"track-size", 1, NULL, 'T'},

	{0, 0, 0, 0}
};


void display_usage(void)
{
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
\t-h (--help       ): display this help and exit\n\
\t-V (--version    ): display version and exit\n\
\t-D (--daemon     ): daemonize\n\
\t-f (--config     ): use specific config file\n\
\t-s (--no-strict  ): do not enforce strict checking of TLS certificates\n\
\t-S (--strict     ): this option does nothing, it is here for backward compatibility\n\
\t-N (--no-fqdn    ): do not check nuauth fqdn (-d params) against provided certificate\n\
\t-k (--key        ): certificate key file\n\
\t-c (--cert       ): certificate file\n\
\t-a (--ca         ): certificate authority file (strict checking is done if selected) (default: none)\n\
\t-r (--crl        ): use specified file as crl file (default: none)\n\
\t-n (--check-dn   ): use specified string as the needed DN of nuauth (enforce certificate checking) (default is to)\n\
\t\tcheck the DN against nuauth FQDN specified using the -d option)\n\
\t-v (--verbose    ): increase debug level (+1 for each 'v') (max useful number: 10)\n\
\t-A (--debug-area ): debug areas (see man page for details)\n\
\t-4 (--ipv4       ): use this flag if your system does not have IPv6 support for nfnetlink\n\
\t-m (--mark       ): mark packet with nuauth provided mark\n"
#ifdef HAVE_LIBCONNTRACK
"\t-C (--conntrack  ): listen to conntrack events (needed for connection expiration)\n\
\t-M (--marked-only): only report event on marked connections to nuauth (implies -C and -m)\n"
#endif
"\t-d (--destination): remote address we send auth requests to (address of the nuauth server) (default: 127.0.0.1)\n\
\t-p (--port       ): remote port we send auth requests to (TCP port nuauth server listens on) (default: 4128)\n"
#if USE_NFQUEUE
"\t-q (--queue      ): use nfqueue number (default: 0)\n"
#ifdef HAVE_NFQ_SET_QUEUE_MAXLEN
"\t-L (--queue-len  ): set queue max len (default: 1024)\n"
#endif
#endif
"\t-t (--timeout    ): timeout to forget about packets when they don't match (default: 15 s)\n\
\t-T (--track-size ): track size (default : 1000)\n",
				PACKAGE_TARNAME);
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
	char *options_list = "4sSNDf:hVvmq:"
#ifdef HAVE_NFQ_SET_QUEUE_MAXLEN
	    "L:"
#endif
	    "c:k:a:n:r:d:p:t:T:A:"
#ifdef HAVE_LIBCONNTRACK
	    "CM"
#endif
	    ;
#else
	char *options_list = "4sSNDf:hVvmc:k:a:n:r:d:p:t:T:A:";
#endif
	int option, daemonize = 0;
	char *version = PACKAGE_VERSION;
	nufw_no_ipv6 = 0;

	/* initialize variables */

	log_engine = LOG_TO_STD;	/* default is to send debug messages to stdout + stderr */
	authreq_port = AUTHREQ_PORT;
	packet_timeout = PACKET_TIMEOUT;
	track_size = TRACK_SIZE;
	cert_file = NULL;
	key_file = NULL;
	ca_file = NULL;
	crl_file = NULL;
	nuauth_cert_dn = NULL;
	authreq_addr[0] = '\0';
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
	nufw_strict_tls = 1;
	nufw_fqdn_check = 1;


	log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_VERBOSE_DEBUG,
			"[+] Start NuFW");

	/*parse options */
	while ((option = getopt_long(argc, argv, options_list, long_options, NULL)) != -1) {
		switch (option) {
		case 'f':
			nufw_config_file = strdup(optarg);
			if (nufw_config_file == NULL) {
				fprintf(stderr,
					"Couldn't malloc! Exiting");
				exit(EXIT_FAILURE);
			}
			break;
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
		case 'r':
			crl_file = strdup(optarg);
			if (crl_file == NULL) {
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
		case 's':
			nufw_strict_tls = 0;
			nufw_fqdn_check = 0;
			break;
		case 'S':
			break;
		case 'N':
			nufw_fqdn_check = 0;
			break;
		case '4':
			nufw_no_ipv6 = 1;
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
			display_usage();
			exit(EXIT_SUCCESS);
		}
	}

	if (nufw_parse_configuration(nufw_config_file) != 0) {
		printf("Error while parsing configuration file\n");
		exit(EXIT_FAILURE);
	}

	if (nufw_use_config() != 0) {
		printf("Error while setting configuration values from file\n");
		exit(EXIT_FAILURE);
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

	if (!nufw_no_ipv6) {
		/* open ICMPv6 socket */
		raw_sock6 = socket(PF_INET6, SOCK_RAW, 58);	/* 58: ICMPv6 protocol */
		if (raw_sock6 == -1) {
			log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL,
					"Fail to create socket for ICMPv6!");
		}
	}

	/* create packet list */
	packets_list.start = NULL;
	packets_list.end = NULL;
	packets_list.length = 0;

	/* init. tls */
	tls.session = NULL;
	tls.auth_server_running = 0;

	/* start GNU TLS library */
	if (nussl_init() != NUSSL_OK) {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_FATAL,
				"Unable to initialize NuSSL library.");

	}

#ifdef HAVE_LIBCONNTRACK
	cth = nfct_open(CONNTRACK, 0);
#endif

	log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_INFO,
			"[+] NuFW server starting");


	/* do initial connect */
	tls_connect();
	if (tls.session) {
		char buf[256];
		buf[0] = '\0';
		nussl_session_get_cipher(tls.session, buf, sizeof(buf));
		log_area_printf(DEBUG_AREA_GW,
				DEBUG_LEVEL_WARNING,
				"[+] TLS connection to nuauth established (%s:%d), cipher is %s",
				authreq_addr, authreq_port,
				(buf[0] != '\0') ? buf : "none" );
	} else {
		log_area_printf(DEBUG_AREA_GW,
				DEBUG_LEVEL_CRITICAL,
				"[!] TLS connection to nuauth can NOT be established (%s:%d)",
				authreq_addr, authreq_port);
	}

	log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_FATAL,
			"[+] NuFW " VERSION " started");

	if (daemonize == 0) {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL,
				"NuFW launched in foreground (without -D option), "
				"logging to stdout and stderr only (no syslog).");
	}

	/* control stuff */
	pckt_tx = pckt_rx = 0;

	/* create packet server */
	packetsrv(NULL);

	nufw_prepare_quit();
	return EXIT_SUCCESS;
}
