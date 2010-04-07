/*
 ** Copyright(C) 2010 EdenWall Technologies
 ** Written by  Pierre Chifflier <chifflier@edenwall.com>
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
 **
 */

#include <config.h>
#include "nussl_config.h"

#include <stdlib.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <string.h>

#include "nussl.h"

#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif

static struct option long_options[] = {
	{"help", 0, NULL, 'h'},
	{"version", 0, NULL, 'V'},

	{"ca-file", 0, NULL, 'A'},

	{0, 0, 0, 0}
};

void display_usage(void)
{
	fprintf(stdout, "nussl_tool [-hVAPCLv]\n"
"\t-h (--help       ): display this help and exit\n\
\t-V (--version    ): display version and exit\n\
\t-A (--ca-file    ): CA file\n\
\t-P (--ca-path    ): CA path\n\
\t-C (--cert       ): Certificate file\n\
\t-L (--crl        ): CRL file\n\
\n\
\t-v (--verify     ): verify certificate\n\
\n");
}

enum nussl_tool_command {
	COMMAND_NONE = 0,
	COMMAND_VERIFY,
};

int main(int argc, char **argv)
{
	const char *options_list = "hVA:P:C:L:v";
	int option;
	const char *cert = NULL;
	const char *ca_cert = NULL;
	const char *ca_path = NULL;
	const char *crl = NULL;
	int command = 0;
	char ret_message[4096];
	size_t message_sz = sizeof(ret_message);
	int rc;

	while ((option = getopt_long(argc, argv, options_list, long_options, NULL)) != -1) {
		switch (option) {
		case 'h':
			display_usage();
			return 0;
		case 'V':
			fprintf(stdout, "ssl_tool for nussl version %s\n", PACKAGE_VERSION);
			return 0;
		case 'A':
			ca_cert = strdup(optarg);
			break;
		case 'P':
			ca_path = strdup(optarg);
			break;
		case 'C':
			cert = strdup(optarg);
			break;
		case 'L':
			crl = strdup(optarg);
			break;
		case 'v':
			command = COMMAND_VERIFY;
			break;
		}
	}

	nussl_init();

	switch (command) {
	case COMMAND_VERIFY:
		rc = nussl_local_check_certificate(cert, ca_cert, ca_path, crl,
				ret_message, message_sz);
		fprintf(stdout, "nussl_local_check_certificate: %d\n"
				"message: %s\n",
				rc, ret_message);
		break;
	default:
		fprintf(stderr, "no command provided\n");
		display_usage();
		return 0;
	}

	return 0;
}

