/*
 ** Copyright(C) 2009 INL
 ** Written by Pierre Chifflier <chifflier@inl.fr>
 **     INL : http://www.inl.fr/
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

#include <config.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <signal.h>

#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#include <nubase.h>

#include "emc_server.h"
#include "emc_config.h"

/*! Name of pid file prefixed by LOCAL_STATE_DIR (variable defined
 * during compilation/installation) */
#define EMC_PID_FILE  LOCAL_STATE_DIR "/run/emc/emc.pid"

struct emc_server_context *server_ctx;

static struct option long_options[] = {
	{"help", 0, NULL, 'h'},
	{"version", 0, NULL, 'V'},
	{"daemon", 0, NULL, 'D'},
	{"verbose", 0, NULL, 'v'},
	{"config", 0, NULL, 'f'},

	{0, 0, 0, 0}
};

void display_usage(void)
{
	fprintf(stdout, "emc [-hVDv ]"
				"\n\
\t-h (--help       ): display this help and exit\n\
\t-V (--version    ): display version and exit\n\
\t-D (--daemon     ): daemonize\n\
\t-v (--verbose    ): increase debug level (+1 for each 'v') (max useful number: 10)\n\
\t-f (--config     ): use specific config file\n\
"
	);
}

/**
 * Daemonize current process.
 */
void emc_daemonize()
{
	FILE *pf;
	pid_t pidf;

	if (access(EMC_PID_FILE, R_OK) == 0) {
		/* Check if the existing process is still alive. */
		pid_t pidv;

		pf = fopen(EMC_PID_FILE, "r");
		if (pf != NULL &&
		    fscanf(pf, "%d", &pidv) == 1 && kill(pidv, 0) == 0) {
			fclose(pf);
			printf
			    ("pid file exists. Is emc already running? Aborting!\n");
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
			if ((pf = fopen(EMC_PID_FILE, "w")) != NULL) {
				fprintf(pf, "%d\n", (int) pidf);
				fclose(pf);
			} else {
				printf("Dying, can not create PID file : "
				       EMC_PID_FILE "\n");
				exit(EXIT_FAILURE);
			}
			exit(EXIT_SUCCESS);
		}
	}

	chdir("/");

	setsid();

	/* set log engine */
	log_engine = LOG_TO_SYSLOG;

	{
		/* warning: do not close fd (0 1 2), or this will create problems when trying
		 * to create child process with a pipe (dup2 fails with error EBADF)
		 */
		int fd = open("/dev/null",O_RDWR);
		dup2(fd,0);
		dup2(fd,1);
		dup2(fd,2);
		close(fd);
	}
}



int main(int argc, char **argv)
{
	const char options_list[] = "hVDvf:";
	int option, daemonize = 0;
	const char *version = PACKAGE_VERSION;
	char *conf_file = EMC_DEFAULT_CONF;

	debug_level = DEBUG_LEVEL_INFO;

	/*parse options */
	while ((option = getopt_long(argc, argv, options_list, long_options, NULL)) != -1) {
		switch (option) {
		case 'V':
			fprintf(stdout, "emc (version %s)\n",
				version);
			return 1;
		case 'D':
			daemonize = 1;
			break;
		case 'v':
			debug_level += 1;
			break;
		case 'h':
			display_usage();
			exit(EXIT_SUCCESS);
		case 'f':
			conf_file = strdup(optarg);
			if (conf_file == NULL) {
				fprintf(stderr,
					"Couldn't malloc! Exiting");
				exit(EXIT_FAILURE);
			}
			break;
		}
	}



	server_ctx = g_malloc0(sizeof(struct emc_server_context));
	nussl_init();

	init_log_engine("emc");

	log_printf(DEBUG_LEVEL_INFO, "INFO EMC server starting (version %s)", version);

	/* ignore SIGPIPE */
	signal(SIGPIPE, SIG_IGN);

	if (emc_init_config(conf_file) != 0) {
		log_printf(DEBUG_LEVEL_FATAL, "ERROR could not load config, aborting\n");

		exit(-1);
	}

	if (emc_init_server(server_ctx) != 0) {
		log_printf(DEBUG_LEVEL_FATAL, "ERROR server initialization failed\n");

		exit(-1);
	}

	/* Daemon code */
	if (daemonize == 1) {
		emc_daemonize();
		init_log_engine("emc");
	}

	emc_start_server(server_ctx);

	g_free(server_ctx);

	unlink(EMC_PID_FILE);

	return 0;
}

