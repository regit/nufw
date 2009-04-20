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

#include <signal.h>

#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif

#include <nubase.h>

#include "emc_server.h"
#include "emc_config.h"

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

	emc_start_server(server_ctx);

	g_free(server_ctx);

	return 0;
}

